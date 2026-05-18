#include "source/extensions/filters/listener/qosmos_dpi/qosmos_engine.h"

#include <sys/time.h>

#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <utility>

#include "absl/strings/str_format.h"

extern "C" {
#include "dpi/protodef.h"  // Q_PROTO_IP, Q_PROTO_IP6, Q_PROTO_TCP
}

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace QosmosDpi {

QosmosWorker::QosmosWorker(qmdpi_engine* engine) {
  worker_ = qmdpi_worker_create(engine);
  if (worker_ == nullptr) {
    // Per qmdpi.h: NULL on error with errno set.
    ENVOY_LOG(error, "qosmos_dpi: qmdpi_worker_create failed (errno={}: {})",
              errno, std::strerror(errno));
    // We don't throw here — a worker thread without a Qosmos worker is a
    // hard failure but it's manageable: the filter's onData will detect
    // worker_ == nullptr and short-circuit to non-web with engine_error
    // stat incremented. Throwing inside ThreadLocal initialisation would
    // crash the Envoy worker thread, which is worse.
  }
}

QosmosWorker::~QosmosWorker() {
  if (worker_ != nullptr) {
    int rc = qmdpi_worker_destroy(worker_);
    if (rc != 0) {
      ENVOY_LOG(warn, "qosmos_dpi: qmdpi_worker_destroy returned {}", rc);
    }
    worker_ = nullptr;
  }
}

std::string QosmosEngine::resolveEngineConfig(const std::string& user_supplied,
                                               uint32_t nb_workers) {
  if (!user_supplied.empty()) {
    return user_supplied;
  }
  // Stream-mode default. Mirrors dataplane/libs/qosmos_dpi/src/QosmosDpi.cpp:52.
  // first_header=0 (handled per-PDU in the filter, not at engine create) +
  // injection_mode=stream + nb_workers must match the Envoy worker count
  // so the Qosmos engine's internal lock-free fan-out has the right shape.
  return absl::StrFormat("injection_mode=stream;nb_workers=%u", nb_workers);
}

QosmosEngine::QosmosEngine(const std::string& engine_config,
                           const std::string& bundle_path,
                           const std::string& table_path,
                           uint32_t nb_workers,
                           ThreadLocal::SlotAllocator& tls) {
  // 1. Engine.
  const std::string config = resolveEngineConfig(engine_config, nb_workers);
  ENVOY_LOG(info, "qosmos_dpi: creating engine (config='{}')", config);
  engine_ = qmdpi_engine_create(config.c_str());
  if (engine_ == nullptr) {
    throw EnvoyException(
        absl::StrFormat("qosmos_dpi: qmdpi_engine_create failed (errno=%d: %s)",
                        errno, std::strerror(errno)));
  }

  // 2. Bundle.
  // Per qmdpi.h: passing NULL as filename uses the bundle library linked
  // *into* the user application. envoy-static statically links
  // libqmbundle.fpic.a (see ns-envoy/WORKSPACE qosmos_sdk entry), so the
  // bundle code is already in this process — there's nothing to dlopen.
  // The proto config field `protocol_bundle_path` can:
  //   - be empty   ⇒ use the linked-in bundle (NULL filename)
  //   - be a path  ⇒ dynamic load (kept for future flexibility, e.g. if
  //                  we ever switch to a shared-library bundle)
  const char* bundle_filename =
      bundle_path.empty() ? nullptr : bundle_path.c_str();
  ENVOY_LOG(info, "qosmos_dpi: loading protocol bundle ({})",
            bundle_path.empty() ? "from statically-linked libqmbundle"
                                 : absl::StrCat("from ", bundle_path));
  bundle_ = qmdpi_bundle_create_from_file(engine_, bundle_filename);
  if (bundle_ == nullptr) {
    qmdpi_engine_destroy(engine_);
    engine_ = nullptr;
    throw EnvoyException(absl::StrFormat(
        "qosmos_dpi: qmdpi_bundle_create_from_file(%s) failed (errno=%d: %s)",
        bundle_path.empty() ? "NULL" : ("'" + bundle_path + "'"),
        errno, std::strerror(errno)));
  }
  if (int rc = qmdpi_bundle_activate(bundle_); rc != 0) {
    qmdpi_bundle_destroy(bundle_);
    qmdpi_engine_destroy(engine_);
    bundle_ = nullptr;
    engine_ = nullptr;
    throw EnvoyException(
        absl::StrFormat("qosmos_dpi: qmdpi_bundle_activate failed (rc=%d)", rc));
  }

  // Enable all signatures. Without this, every protocol is disabled — the
  // engine produces empty paths and qmdpi_bundle_attr_register fails with
  // -1. Mirrors the licensed-SDK example
  // (src/examples/attribute_extraction/main.c:161). Reference:
  // qosmos-poc pcap-analyzer also calls this.
  if (int rc = qmdpi_bundle_signature_enable_all(bundle_); rc != 0) {
    qmdpi_bundle_destroy(bundle_);
    qmdpi_engine_destroy(engine_);
    bundle_ = nullptr;
    engine_ = nullptr;
    throw EnvoyException(absl::StrFormat(
        "qosmos_dpi: qmdpi_bundle_signature_enable_all failed (rc=%d)", rc));
  }

  // Register ssl:alpn for extraction. Cascade rules 0 (non-web ALPN
  // beats everything) and 1 (transport-token + HTTP ALPN ⇒ web) consume
  // it. Failure here is non-fatal — we log and proceed with ssl_proto_id_
  // staying at -1, which makes the per-classify hook extraction a no-op.
  // Cascade then runs with no ALPN signal: conservative — more flows go
  // to non-web/CFW, but no incorrect web verdicts.
  if (int rc = qmdpi_bundle_attr_register(bundle_, "ssl", "alpn"); rc != 0) {
    ENVOY_LOG(warn, "qosmos_dpi: qmdpi_bundle_attr_register(ssl, alpn) "
                     "returned {} — ALPN cascade rules will not fire", rc);
  } else {
    // Cache the integer (proto_id, attr_id) pair for fast match in the
    // per-classify result iterator.
    qmdpi_signature* ssl_sig = qmdpi_bundle_signature_get_byname(bundle_, "ssl");
    qmdpi_attr* alpn_attr =
        qmdpi_bundle_attr_get_byname(bundle_, "ssl", "alpn");
    if (ssl_sig != nullptr && alpn_attr != nullptr) {
      ssl_proto_id_ = qmdpi_signature_id_get(ssl_sig);
      alpn_attr_id_ = qmdpi_attr_id_get(alpn_attr);
      ENVOY_LOG(info, "qosmos_dpi: registered ssl:alpn extraction "
                       "(proto_id={}, attr_id={})", ssl_proto_id_, alpn_attr_id_);
    } else {
      ENVOY_LOG(warn, "qosmos_dpi: could not resolve ssl:alpn ids "
                       "(ssl_sig={}, alpn_attr={}) — ALPN cascade rules "
                       "will not fire",
                fmt::ptr(ssl_sig), fmt::ptr(alpn_attr));
    }
  }

  // 3. Protocol table (CSV-derived JSON). Loaded right after bundle activate
  //    so that any hot-path lookup never has to NULL-check it.
  ENVOY_LOG(info, "qosmos_dpi: loading protocol table from '{}'", table_path);
  auto table_or = ProtocolTable::loadJson(table_path);
  if (!table_or.ok()) {
    qmdpi_bundle_destroy(bundle_);
    qmdpi_engine_destroy(engine_);
    bundle_ = nullptr;
    engine_ = nullptr;
    throw EnvoyException(
        absl::StrFormat("qosmos_dpi: %s", std::string(table_or.status().message())));
  }
  table_ = std::move(*table_or);
  ENVOY_LOG(info, "qosmos_dpi: loaded {} protocols (bundle version={})",
            table_->numProtocols(), table_->version());

  // 4. Per-worker handles via ThreadLocal::TypedSlot. Each Envoy worker
  //    thread independently calls qmdpi_worker_create(engine_) inside its
  //    own thread context.
  worker_slot_ = ThreadLocal::TypedSlot<QosmosWorker>::makeUnique(tls);
  qmdpi_engine* engine_ptr = engine_;
  worker_slot_->set([engine_ptr](Event::Dispatcher&) {
    return std::make_shared<QosmosWorker>(engine_ptr);
  });
}

QosmosEngine::~QosmosEngine() {
  // Order: workers (per-thread) → bundle → engine. workers go away when
  // worker_slot_ resets — that triggers ~QosmosWorker on each worker thread.
  worker_slot_.reset();

  if (bundle_ != nullptr) {
    int rc = qmdpi_bundle_destroy(bundle_);
    if (rc != 0) {
      ENVOY_LOG(warn, "qosmos_dpi: qmdpi_bundle_destroy returned {}", rc);
    }
    bundle_ = nullptr;
  }
  if (engine_ != nullptr) {
    int rc = qmdpi_engine_destroy(engine_);
    if (rc != 0) {
      ENVOY_LOG(warn, "qosmos_dpi: qmdpi_engine_destroy returned {}", rc);
    }
    engine_ = nullptr;
  }
  // table_ unique_ptr cleans itself up.
}

QosmosWorker& QosmosEngine::workerForThisThread() {
  // TypedSlot<>::get() returns OptRef<T>; we asserted set() ran on every
  // worker thread before the first onAccept, so this is always populated
  // on a worker thread. Calling from the main thread (e.g. tests) without
  // a runOnAllThreads() will trip the underlying assert — that's the
  // intended Envoy contract for ThreadLocal.
  return worker_slot_->get().ref();
}

// ─────────── Real Qosmos classifier implementation ───────────
//
// Owns a qmdpi_flow* via RAII. classifyFirstPdu consumes it; ~RealClassifier
// destroys it if classify never ran (silence-timeout / on-close path).
namespace {

// Render the qmdpi_path object as a dotted string. Mirrors
// dataplane/libs/qosmos_dpi/src/QosmosDpi.cpp:372 (qmdpi_data_path_to_buffer).
std::string pathToString(qmdpi_bundle* bundle, const qmdpi_path* path) {
  if (path == nullptr || bundle == nullptr) return {};
  char buffer[512];
  int rc = qmdpi_data_path_to_buffer(bundle, buffer, sizeof(buffer), path);
  if (rc != 0) return {};
  return std::string(buffer);
}

class RealQosmosClassifier : public QosmosClassifier,
                              Logger::Loggable<Logger::Id::filter> {
public:
  // ssl_proto_id / alpn_attr_id of -1 disable hook extraction (cascade
  // runs with empty Hooks; rules 0/1 don't fire). See QosmosEngine ctor
  // for why those might be -1.
  RealQosmosClassifier(qmdpi_worker* worker, qmdpi_bundle* bundle,
                        qmdpi_flow* flow, int ssl_proto_id, int alpn_attr_id)
      : worker_(worker), bundle_(bundle), flow_(flow),
        ssl_proto_id_(ssl_proto_id), alpn_attr_id_(alpn_attr_id) {}

  ~RealQosmosClassifier() override {
    // RAII: if classifyFirstPdu never ran (e.g. silence timeout, early
    // close), destroy the flow here. qmdpi_flow_destroy is the only way
    // to release engine-side per-flow state in stream mode.
    if (flow_ != nullptr) {
      qmdpi_result* sink = nullptr;
      int rc = qmdpi_flow_destroy(worker_, flow_, &sink);
      if (rc != 0) {
        ENVOY_LOG(debug, "qosmos_dpi: ~RealQosmosClassifier: "
                          "qmdpi_flow_destroy returned {}", rc);
      }
      flow_ = nullptr;
    }
  }

  bool flowAlive() const override { return flow_ != nullptr; }

  ClassifyResult classifyFirstPdu(const void* bytes, int len, int direction,
                                   int tenant_id) override {
    ClassifyResult result;
    if (flow_ == nullptr || worker_ == nullptr) {
      result.engine_error = true;
      return result;
    }

    struct timeval tv;
    gettimeofday(&tv, nullptr);

    int rc = qmdpi_worker_pdu_set(worker_, bytes, len, &tv,
                                   /*first_header=*/0, direction, tenant_id);
    if (rc != 0) {
      ENVOY_LOG(debug, "qosmos_dpi: qmdpi_worker_pdu_set returned {}", rc);
      result.engine_error = true;
      // Continue — flow_destroy below may still produce a useful final.
    }

    qmdpi_result* intermediate = nullptr;
    rc = qmdpi_worker_process(worker_, /*flow=*/nullptr, &intermediate);
    if (rc != 0) {
      ENVOY_LOG(debug, "qosmos_dpi: qmdpi_worker_process returned {}", rc);
      result.engine_error = true;
    }
    if (intermediate != nullptr) {
      qmdpi_path* p = qmdpi_result_path_get(intermediate);
      result.intermediate_path = pathToString(bundle_, p);
      // Extract ssl:alpn from intermediate result. The TLS ClientHello
      // is the very first client byte stream, so ALPN is typically
      // available on the intermediate path already — before flow_destroy.
      extractAlpn(intermediate, result.hooks);
    }

    // ALWAYS qmdpi_flow_destroy — see plan §1, §7.4. Whether the
    // intermediate was conclusive or not, the per-flow state is no
    // longer needed (we will not feed more bytes). The destroy out-param
    // is the engine's best-guess final result.
    qmdpi_result* final_result = nullptr;
    rc = qmdpi_flow_destroy(worker_, flow_, &final_result);
    if (rc != 0) {
      ENVOY_LOG(debug, "qosmos_dpi: qmdpi_flow_destroy returned {}", rc);
    }
    flow_ = nullptr;
    if (final_result != nullptr) {
      qmdpi_path* p = qmdpi_result_path_get(final_result);
      result.final_path = pathToString(bundle_, p);
      // Re-extract ssl:alpn from final result IF the intermediate didn't
      // produce one (e.g. flow that pinned to ssl only after destroy).
      // We don't overwrite — first-seen wins.
      if (result.hooks.find("ssl:alpn") == result.hooks.end()) {
        extractAlpn(final_result, result.hooks);
      }
    }

    return result;
  }

private:
  // Walk qmdpi_result_attr_getnext on `result` and pluck out any
  // ssl:alpn values, comma-joined into hooks["ssl:alpn"]. ALPN can have
  // multiple registered values per flow (the client's full preference
  // list); we join them with ", " to match the qosmos-poc cascade
  // (run_tests.py:340 splits on ',' and trims).
  void extractAlpn(qmdpi_result* result, Hooks& hooks) const {
    if (result == nullptr || ssl_proto_id_ < 0 || alpn_attr_id_ < 0) {
      return;
    }
    int proto_id = 0, attr_id = 0, attr_flags = 0;
    int attr_len = 0;
    const char* attr_value = nullptr;
    std::string joined;
    while (qmdpi_result_attr_getnext(result, &proto_id, &attr_id,
                                      &attr_value, &attr_len,
                                      &attr_flags) == 0) {
      if (proto_id != ssl_proto_id_ || attr_id != alpn_attr_id_) {
        continue;
      }
      if (attr_value == nullptr || attr_len <= 0) {
        continue;
      }
      if (!joined.empty()) joined.append(", ");
      joined.append(attr_value, static_cast<size_t>(attr_len));
    }
    if (!joined.empty()) {
      hooks["ssl:alpn"] = std::move(joined);
    }
  }

  qmdpi_worker* worker_;
  qmdpi_bundle* bundle_;
  qmdpi_flow* flow_;
  int ssl_proto_id_;
  int alpn_attr_id_;
};

}  // namespace

QosmosClassifierPtr QosmosEngine::makeClassifier(bool is_v6, const void* src_ip,
                                                  uint16_t src_port_nbo,
                                                  const void* dst_ip,
                                                  uint16_t dst_port_nbo) {
  if (engine_ == nullptr || bundle_ == nullptr) {
    return nullptr;
  }
  auto& worker_obj = workerForThisThread();
  qmdpi_worker* worker = worker_obj.raw();
  if (worker == nullptr) {
    return nullptr;
  }

  const int l3 = is_v6 ? Q_PROTO_IP6 : Q_PROTO_IP;
  qmdpi_flow* flow = qmdpi_flow_create(worker, l3, Q_PROTO_TCP,
                                        src_ip, &src_port_nbo,
                                        dst_ip, &dst_port_nbo);
  if (flow == nullptr) {
    ENVOY_LOG(warn, "qosmos_dpi: qmdpi_flow_create returned NULL (errno={}: {})",
              errno, std::strerror(errno));
    return nullptr;
  }
  return std::make_unique<RealQosmosClassifier>(worker, bundle_, flow,
                                                  ssl_proto_id_, alpn_attr_id_);
}

}  // namespace QosmosDpi
}  // namespace ListenerFilters
}  // namespace Extensions
}  // namespace Envoy
