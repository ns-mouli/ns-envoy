#include "source/extensions/common/qosmos_dpi/qosmos_engine.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/time.h>

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <utility>

#include "absl/strings/str_format.h"

#include "source/extensions/common/qosmos_dpi/verdict_cache.h"

extern "C" {
#include "dpi/protodef.h"  // Q_PROTO_IP, Q_PROTO_IP6, Q_PROTO_TCP
}

namespace Envoy {
namespace Extensions {
namespace Common {
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
                                               uint32_t nb_workers,
                                               uint32_t total_nb_flows) {
  if (!user_supplied.empty()) {
    return user_supplied;
  }
  // Stream-mode default. Mirrors dataplane/libs/qosmos_dpi/src/QosmosDpi.cpp:52
  // and the licensed-SDK example
  // (src/examples/attribute_extraction/main.c:131):
  //   injection_mode=stream
  //   nb_workers=N+1 — Envoy worker count plus one slack slot. Empirically
  //                    qmdpi_worker_create returns NULL when the count
  //                    matches exactly (one slot may be reserved for the
  //                    engine's own use); bumping by 1 avoids the race.
  //   nb_flows        — the SDK documents this as "maximum number of flow
  //                    contexts PER WORKER" (see SDK examples
  //                    napatech_integration/main.c:96,
  //                    afp_integration/main.c and pcap_analyzer defaults).
  //                    We honour a process-wide budget by dividing:
  //                    per-worker = ceil(total_nb_flows / (nb_workers + 1)).
  //                    Default total is 300000 (~600 MB engine-side flow-
  //                    store; SDK's own pcap_analyzer defaults to 200000
  //                    for reference).
  const uint32_t total = total_nb_flows == 0 ? 300000U : total_nb_flows;
  const uint32_t effective_workers = nb_workers + 1;
  const uint32_t per_worker =
      (total + effective_workers - 1) / effective_workers;   // ceil-divide
  return absl::StrFormat("injection_mode=stream;nb_workers=%u;nb_flows=%u",
                          effective_workers, per_worker);
}

QosmosEngine::QosmosEngine(const std::string& engine_config,
                           const std::string& bundle_path,
                           const std::string& table_path,
                           uint32_t nb_workers,
                           ThreadLocal::SlotAllocator& tls,
                           uint32_t verdict_cache_max_entries,
                           uint32_t total_nb_flows) {
  // 1. Engine.
  const std::string config =
      resolveEngineConfig(engine_config, nb_workers, total_nb_flows);
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

  // Register discriminator hooks for extraction. Failure of any one is
  // non-fatal — the corresponding attr_id stays at -1 and the extractor
  // simply skips it. Downstream behaviour degrades gracefully:
  //   ssl:alpn missing  ⇒ cascade rules 0/1 don't fire (conservative,
  //                       more flows to non-web).
  //   ssl:server_name /
  //   ssl:ja4          ⇒ TLS cache-key falls back to next-priority hint
  //                       or Plain {dst-ip, dst-port} — cache still works,
  //                       just with more collisions across shared IPs.
  //   http:host        ⇒ cleartext HTTP cache-key falls back to Plain.
  auto register_attr = [this](const char* proto, const char* attr,
                              int& proto_id_out, int& attr_id_out,
                              const char* extra_hint = nullptr) {
    if (int rc = qmdpi_bundle_attr_register(bundle_, proto, attr); rc != 0) {
      ENVOY_LOG(warn, "qosmos_dpi: qmdpi_bundle_attr_register({}, {}) "
                       "returned {}{}",
                proto, attr, rc,
                extra_hint == nullptr ? "" : extra_hint);
      return;
    }
    qmdpi_signature* sig = qmdpi_bundle_signature_get_byname(bundle_, proto);
    qmdpi_attr* a = qmdpi_bundle_attr_get_byname(bundle_, proto, attr);
    if (sig != nullptr && a != nullptr) {
      proto_id_out = qmdpi_signature_id_get(sig);
      attr_id_out = qmdpi_attr_id_get(a);
      ENVOY_LOG(info, "qosmos_dpi: registered {}:{} extraction "
                       "(proto_id={}, attr_id={})",
                proto, attr, proto_id_out, attr_id_out);
    } else {
      ENVOY_LOG(warn, "qosmos_dpi: could not resolve {}:{} ids "
                       "(sig={}, attr={})",
                proto, attr, fmt::ptr(sig), fmt::ptr(a));
    }
  };

  // ssl:alpn — cascade rules 0/1 (see ProtocolTable::isWebWithRule).
  register_attr("ssl", "alpn", ssl_proto_id_, alpn_attr_id_,
                 " — ALPN cascade rules will not fire");
  // ssl:server_name — TLS SNI (primary cache-key discriminator).
  {
    int discard_proto = -1;
    register_attr("ssl", "server_name", discard_proto, sni_attr_id_,
                   " — cache-key SNI discriminator disabled for TLS flows");
    // ssl_proto_id_ was populated by the alpn call above; if that failed
    // and this one succeeded, backfill from `discard_proto`.
    if (ssl_proto_id_ < 0 && discard_proto >= 0) ssl_proto_id_ = discard_proto;
  }
  // ssl:ja4 — TLS fingerprint fallback when SNI is absent (ECH etc).
  // The Qosmos SDK's underlying enum is Q_SSL_FINGERPRINT_JA4, so the
  // attribute-name string used with qmdpi_bundle_attr_register is
  // "fingerprint_ja4" (the SDK follows the lower-cased enum-suffix-after-
  // Q_SSL_ convention). Verified against the SDK's own examples on
  // 2026-07-28 — a plain "ja4" register returns -1.
  {
    int discard_proto = -1;
    register_attr("ssl", "fingerprint_ja4", discard_proto, ja4_attr_id_,
                   " — cache-key JA4 discriminator disabled for TLS flows");
    if (ssl_proto_id_ < 0 && discard_proto >= 0) ssl_proto_id_ = discard_proto;
  }
  // http:host — HTTP Host header / HTTP/2 :authority.
  register_attr("http", "host", http_proto_id_, host_attr_id_,
                 " — cache-key Host discriminator disabled for cleartext HTTP");

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

  // 5. Per-worker verdict cache. Only allocated when
  //    verdict_cache_max_entries > 0; a null cache_slot_ acts as the
  //    "cache disabled" signal for verdictCacheEnabled() /
  //    cacheForThisThread() callers.
  if (verdict_cache_max_entries > 0) {
    const uint32_t effective_max =
        verdict_cache_max_entries == 0 ? 100000U : verdict_cache_max_entries;
    cache_slot_ = ThreadLocal::TypedSlot<VerdictCache>::makeUnique(tls);
    cache_slot_->set([effective_max](Event::Dispatcher&) {
      return std::make_shared<VerdictCache>(effective_max);
    });
    ENVOY_LOG(info,
              "qosmos_dpi: verdict cache enabled (per-worker, max_entries={})",
              effective_max);
  }
}

QosmosEngine::~QosmosEngine() {
  // Order: caches (per-thread) → workers (per-thread) → bundle → engine.
  // cache_slot_ is fine to reset before worker_slot_ — cache entries are
  // owned by the cache, not the worker.
  cache_slot_.reset();
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

VerdictCache& QosmosEngine::cacheForThisThread() {
  // Callers must check verdictCacheEnabled() first — this method
  // dereferences cache_slot_ unconditionally.
  return cache_slot_->get().ref();
}

// ─────────── Real Qosmos classifier implementation ───────────
//
// Owns a qmdpi_flow* via RAII. classifyFirstPdu consumes it; ~RealClassifier
// destroys it if classify never ran (silence-timeout / on-close path).
namespace {

// Render the qmdpi_path object as a dotted string. Mirrors
// dataplane/libs/qosmos_dpi/src/QosmosDpi.cpp:372 (qmdpi_data_path_to_buffer).
//
// API contract (qmdpi.h:2778-2780): the function returns the *written
// length* (a positive int) on success, 0 if the path is not applicable
// (empty path), and a negative error code on failure. Treating any
// non-zero return as an error was an early bug — it discarded every
// successfully rendered path.
std::string pathToString(qmdpi_bundle* bundle, const qmdpi_path* path) {
  if (path == nullptr || bundle == nullptr) return {};
  char buffer[512] = {0};
  int rc = qmdpi_data_path_to_buffer(bundle, buffer, sizeof(buffer), path);
  if (rc < 0) return {};
  // rc may be 0 (no path) or > 0 (length written). Either way the buffer
  // is NUL-terminated by the engine; an empty buffer ⇒ empty string.
  return std::string(buffer);
}

// L3/L4 header POD layouts the Qosmos engine consumes via
// qmdpi_worker_pdu_header_set (stream mode). Layouts mirror the licensed
// SDK's src/include/packet_helper.h (qm_ip_hdr / qm_tcp_hdr) — the engine
// reads these structs by absolute offset, so the on-the-wire shape (IPv4
// / TCP fixed headers) must match exactly. We synthesise only the fields
// the engine actually inspects: addresses + ports + next-protocol (TCP).
// Sequence numbers, checksums, IDs, ttl, etc. are zero — stream-mode
// protocol pinning isn't checksum-aware.
//
// IPv6 is intentionally not handled here: the listener can accept v6
// flows, but pdu_header_set is skipped for them in stream mode (engine
// continues to receive bytes; classification may still be empty — that
// path was already fail-safe before this change). Phase-1 traffic is
// IPv4 only.
#pragma pack(push, 1)
struct SynthIp4Hdr {
  uint8_t  ihl_version;     // ihl=5, version=4 → 0x45
  uint8_t  tos;
  uint16_t tot_len_nbo;
  uint16_t id;
  uint16_t frag_off;
  uint8_t  ttl;
  uint8_t  protocol;        // IPPROTO_TCP = 6
  uint16_t check;
  uint32_t saddr_nbo;
  uint32_t daddr_nbo;
};
static_assert(sizeof(SynthIp4Hdr) == 20, "IPv4 header must be 20 bytes");

struct SynthTcpHdr {
  uint16_t source_nbo;
  uint16_t dest_nbo;
  uint32_t seq;
  uint32_t ack_seq;
  uint16_t doff_flags;      // doff=5 (header length in 32-bit words)
  uint16_t window;
  uint16_t check;
  uint16_t urg_ptr;
};
static_assert(sizeof(SynthTcpHdr) == 20, "TCP header must be 20 bytes");
#pragma pack(pop)

// Cached attribute (proto_id, attr_id) pairs for the hooks we extract on
// every classify. -1 in any field means that attribute wasn't registered
// successfully at engine init; the extractor treats it as "skip".
struct AttrIds {
  int ssl_proto{-1};    // shared across alpn/sni/ja4 (they all live on ssl)
  int alpn_attr{-1};
  int sni_attr{-1};
  int ja4_attr{-1};
  int http_proto{-1};
  int host_attr{-1};
};

class RealQosmosClassifier : public QosmosClassifier,
                              Logger::Loggable<Logger::Id::filter> {
public:
  // Any negative id in `attr_ids` disables extraction of that specific
  // hook — the classifier still runs and other hooks still work. See
  // QosmosEngine ctor for why an id might be -1.
  RealQosmosClassifier(qmdpi_worker* worker, qmdpi_bundle* bundle,
                        qmdpi_flow* flow, const AttrIds& attr_ids,
                        bool is_v6, const void* src_ip,
                        uint16_t src_port_nbo, const void* dst_ip,
                        uint16_t dst_port_nbo)
      : worker_(worker), bundle_(bundle), flow_(flow),
        attr_ids_(attr_ids),
        is_v4_(!is_v6) {
    // Cache the 5-tuple into pre-baked L3/L4 header buffers so the hot
    // path just hands their addresses to qmdpi_worker_pdu_header_set.
    // Phase-1 only synthesises IPv4 headers (is_v4_ == false ⇒ skip
    // header_set; behaviour reverts to the pre-hypothesis-1 path).
    std::memset(&ip4_, 0, sizeof(ip4_));
    std::memset(&tcp_, 0, sizeof(tcp_));
    if (is_v4_) {
      // version=4, ihl=5 → 0x45.
      ip4_.ihl_version = 0x45;
      ip4_.ttl = 64;
      ip4_.protocol = IPPROTO_TCP;
      // src_ip/dst_ip point at in_addr.s_addr (NBO uint32).
      std::memcpy(&ip4_.saddr_nbo, src_ip, sizeof(ip4_.saddr_nbo));
      std::memcpy(&ip4_.daddr_nbo, dst_ip, sizeof(ip4_.daddr_nbo));
    }
    (void)dst_ip;  // silence unused warning when !is_v4_
    tcp_.source_nbo = src_port_nbo;
    tcp_.dest_nbo = dst_port_nbo;
    // doff=5 (20-byte header, no options). Standard TCP wire format:
    // byte 12 = (doff<<4)|reserved = 0x50; byte 13 = flags = 0. As a
    // little-endian uint16_t at byte offset 12, in-memory bytes
    // [0x50, 0x00] correspond to the integer value 0x0050. The SDK
    // qm_tcp_hdr's LE bitfield (res1:4, doff:4, ...) reads the same
    // bytes the same way.
    tcp_.doff_flags = 0x0050;
  }

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

  // Feed one PDU. NO flow_destroy — the flow stays alive for a subsequent
  // call. Populates result.intermediate_path, result.hooks (ssl:alpn), and
  // result.final_state (from QMDPI_RESULT_FLAGS_CLASSIFIED_FINAL_STATE).
  ClassifyResult classifyPdu(const void* bytes, int len, int direction,
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

    // Stream-mode: hand the engine the (synthesised) inner-most L3/L4
    // headers built from the 5-tuple cached at flow_create time. Empirically
    // verified 2026-05-18 NOT required for plain TCP/HTTP/SSL pinning —
    // qmdpi_flow_create already told the engine the L3/L4 protocol IDs
    // (Q_PROTO_IP + Q_PROTO_TCP) and the 5-tuple. But qmdpi.h:735 lists
    // it as REQUIRED for protocols whose disambiguation needs L3/L4
    // header bytes (IPSEC-over-UDP, Skype-over-TCP). Cheap to keep wired
    // up so the engine has them available if a flow ever needs them.
    //
    // IPv4 only in phase-1; IPv6 connections skip header_set (the listener
    // accepts v6 flows, but their classification path predated this call
    // and was already correct for HTTP/SSL).
    if (is_v4_) {
      void* l3 = static_cast<void*>(&ip4_);
      void* l4 = static_cast<void*>(&tcp_);
      rc = qmdpi_worker_pdu_header_set(worker_, l3, l4);
      if (rc != 0) {
        ENVOY_LOG(debug, "qosmos_dpi: qmdpi_worker_pdu_header_set returned {}",
                  rc);
        result.engine_error = true;
      }
    }

    qmdpi_result* intermediate = nullptr;
    // STREAM mode: the flow handle MUST be passed to qmdpi_worker_process
    // (see SDK src/examples/stream_injection/main.c:788). Passing NULL is
    // for packet mode where the engine looks up the flow from the L3/L4
    // headers we don't supply. We did supply a flow via qmdpi_flow_create,
    // so it goes here. Without this the engine returns -1 with no errno.
    rc = qmdpi_worker_process(worker_, flow_, &intermediate);
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
      extractDiscriminatorHooks(intermediate, result.hooks);
      // Finality signal: set iff the engine has decided nothing new will
      // change the classification given more bytes. Only meaningful on
      // this (pre-destroy) path.
      const qmdpi_result_flags* flags = qmdpi_result_flags_get(intermediate);
      if (flags != nullptr) {
        result.final_state =
            QMDPI_RESULT_FLAGS_CLASSIFIED_FINAL_STATE(flags) != 0;
      }
      ENVOY_LOG(debug, "qosmos_dpi: post-process result={} path_ptr={} "
                        "rendered_path='{}' final_state={} rc={}",
                fmt::ptr(intermediate), fmt::ptr(p),
                result.intermediate_path, result.final_state, rc);
    } else {
      ENVOY_LOG(debug, "qosmos_dpi: post-process result is NULL (rc={})", rc);
    }
    return result;
  }

  // qmdpi_flow_destroy: releases per-flow engine state and returns the
  // engine's best-guess final path via the out-param. Idempotent.
  ClassifyResult finalize() override {
    ClassifyResult result;
    if (flow_ == nullptr) {
      // Already finalized (or never had a flow). Return an empty result
      // with engine_error=false — a repeat finalize() is not an error.
      return result;
    }
    qmdpi_result* final_result = nullptr;
    int rc = qmdpi_flow_destroy(worker_, flow_, &final_result);
    if (rc != 0) {
      ENVOY_LOG(debug, "qosmos_dpi: qmdpi_flow_destroy returned {}", rc);
      result.engine_error = true;
    }
    flow_ = nullptr;
    if (final_result != nullptr) {
      qmdpi_path* p = qmdpi_result_path_get(final_result);
      result.final_path = pathToString(bundle_, p);
      extractDiscriminatorHooks(final_result, result.hooks);
    }
    return result;
  }

  // qmdpi_worker_process_fqdn: derive a classification path from an FQDN (the
  // SNI) alone — no flow interaction. qmdpi_path is a fixed-size struct
  // (qmdpi_struct.h: {uint32_t qp_len; uint32_t qp_value[16]}), so we can
  // stack-allocate it. Returns the rendered path or "" on error/empty.
  std::string classifyFqdn(const std::string& fqdn) override {
    if (worker_ == nullptr || bundle_ == nullptr || fqdn.empty()) {
      return {};
    }
    qmdpi_path path;
    std::memset(&path, 0, sizeof(path));
    int rc = qmdpi_worker_process_fqdn(worker_, bundle_, fqdn.c_str(), &path);
    if (rc < 0) {
      ENVOY_LOG(debug, "qosmos_dpi: qmdpi_worker_process_fqdn('{}') rc={}", fqdn, rc);
      return {};
    }
    return pathToString(bundle_, &path);
  }

private:
  // Walk qmdpi_result_attr_getnext ONCE and pluck out every registered
  // discriminator hook into `hooks`. Keys:
  //   "ssl:alpn"         — cascade rules 0/1 consume this (may be multi-
  //                        value; joined with ", " to match qosmos-poc's
  //                        run_tests.py:340 splitter).
  //   "ssl:server_name"  — TLS SNI, primary cache-key discriminator.
  //   "ssl:ja4"          — TLS JA4 client fingerprint (SNI fallback).
  //   "http:host"        — HTTP Host / HTTP2 :authority (cleartext HTTP
  //                        cache discriminator).
  //
  // Attributes with alpn-style multi-value semantics (currently only ALPN)
  // get comma-joined; single-value attributes (SNI/JA4/Host) are
  // first-writer-wins — the first attr_getnext hit wins.
  void extractDiscriminatorHooks(qmdpi_result* result, Hooks& hooks) const {
    if (result == nullptr) return;
    int proto_id = 0, attr_id = 0, attr_flags = 0;
    int attr_len = 0;
    const char* attr_value = nullptr;
    std::string alpn_joined;
    while (qmdpi_result_attr_getnext(result, &proto_id, &attr_id,
                                      &attr_value, &attr_len,
                                      &attr_flags) == 0) {
      if (attr_value == nullptr || attr_len <= 0) continue;
      const size_t len = static_cast<size_t>(attr_len);

      // Attributes on the ssl protocol: alpn (multi-value), sni, ja4.
      if (proto_id == attr_ids_.ssl_proto && attr_ids_.ssl_proto >= 0) {
        if (attr_id == attr_ids_.alpn_attr && attr_ids_.alpn_attr >= 0) {
          if (!alpn_joined.empty()) alpn_joined.append(", ");
          alpn_joined.append(attr_value, len);
          continue;
        }
        if (attr_id == attr_ids_.sni_attr && attr_ids_.sni_attr >= 0) {
          hooks.try_emplace("ssl:server_name", std::string(attr_value, len));
          continue;
        }
        if (attr_id == attr_ids_.ja4_attr && attr_ids_.ja4_attr >= 0) {
          hooks.try_emplace("ssl:ja4", std::string(attr_value, len));
          continue;
        }
      }
      // Attribute on the http protocol: host.
      if (proto_id == attr_ids_.http_proto && attr_ids_.http_proto >= 0 &&
          attr_id == attr_ids_.host_attr && attr_ids_.host_attr >= 0) {
        hooks.try_emplace("http:host", std::string(attr_value, len));
        continue;
      }
    }
    if (!alpn_joined.empty()) {
      hooks["ssl:alpn"] = std::move(alpn_joined);
    }
  }

  qmdpi_worker* worker_;
  qmdpi_bundle* bundle_;
  qmdpi_flow* flow_;
  AttrIds attr_ids_;
  bool is_v4_;
  // Pre-baked synthesised inner-most headers, addresses fed to
  // qmdpi_worker_pdu_header_set on every classify call.
  SynthIp4Hdr ip4_{};
  SynthTcpHdr tcp_{};
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
  AttrIds attr_ids;
  attr_ids.ssl_proto = ssl_proto_id_;
  attr_ids.alpn_attr = alpn_attr_id_;
  attr_ids.sni_attr = sni_attr_id_;
  attr_ids.ja4_attr = ja4_attr_id_;
  attr_ids.http_proto = http_proto_id_;
  attr_ids.host_attr = host_attr_id_;
  return std::make_unique<RealQosmosClassifier>(worker, bundle_, flow,
                                                  attr_ids,
                                                  is_v6, src_ip, src_port_nbo,
                                                  dst_ip, dst_port_nbo);
}

}  // namespace QosmosDpi
}  // namespace Common
}  // namespace Extensions
}  // namespace Envoy
