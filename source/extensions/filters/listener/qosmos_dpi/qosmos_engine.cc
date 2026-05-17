#include "source/extensions/filters/listener/qosmos_dpi/qosmos_engine.h"

#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <utility>

#include "absl/strings/str_format.h"

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
  ENVOY_LOG(info, "qosmos_dpi: loading protocol bundle from '{}'", bundle_path);
  bundle_ = qmdpi_bundle_create_from_file(engine_, bundle_path.c_str());
  if (bundle_ == nullptr) {
    qmdpi_engine_destroy(engine_);
    engine_ = nullptr;
    throw EnvoyException(absl::StrFormat(
        "qosmos_dpi: qmdpi_bundle_create_from_file('%s') failed (errno=%d: %s)",
        bundle_path, errno, std::strerror(errno)));
  }
  if (int rc = qmdpi_bundle_activate(bundle_); rc != 0) {
    qmdpi_bundle_destroy(bundle_);
    qmdpi_engine_destroy(engine_);
    bundle_ = nullptr;
    engine_ = nullptr;
    throw EnvoyException(
        absl::StrFormat("qosmos_dpi: qmdpi_bundle_activate failed (rc=%d)", rc));
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

}  // namespace QosmosDpi
}  // namespace ListenerFilters
}  // namespace Extensions
}  // namespace Envoy
