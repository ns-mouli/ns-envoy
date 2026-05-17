#pragma once

#include <memory>
#include <string>

#include "envoy/singleton/instance.h"
#include "envoy/thread_local/thread_local.h"

#include "source/common/common/logger.h"
#include "source/extensions/filters/listener/qosmos_dpi/protocol_table.h"

extern "C" {
#include "qmdpi.h"
}

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace QosmosDpi {

// Per-Envoy-worker Qosmos handle. Holds a `qmdpi_worker*` whose lifetime
// matches its enclosing Envoy worker thread (one ThreadLocal slot entry per
// worker). Created via `qmdpi_worker_create(engine)` on each worker thread,
// destroyed via `qmdpi_worker_destroy(worker)` when the engine shuts down.
//
// Reference impl call order: dataplane/libs/cfw/vpp_plugins/firewall_plugin/
// src/ns_appfw_dpi.c:840-863.
class QosmosWorker : public ThreadLocal::ThreadLocalObject,
                     Logger::Loggable<Logger::Id::filter> {
public:
  explicit QosmosWorker(qmdpi_engine* engine);
  ~QosmosWorker() override;

  // The C handle the filter feeds bytes to via qmdpi_worker_pdu_set /
  // qmdpi_worker_process / qmdpi_flow_create / qmdpi_flow_destroy.
  qmdpi_worker* raw() const { return worker_; }

  // Diagnostics for tests.
  bool isValid() const { return worker_ != nullptr; }

private:
  qmdpi_worker* worker_{};
};

// Process-wide Qosmos engine + protocol bundle + cascade table. Held in
// Envoy's Singleton::Manager (one instance per process). Created on first
// listener-filter config load; destroyed on Envoy shutdown.
//
// Lifetime contract:
//   - Constructor: qmdpi_engine_create(stream-mode config string) +
//                  qmdpi_bundle_create_from_file + qmdpi_bundle_activate +
//                  ProtocolTable::loadJson, all exactly once.
//   - Destructor:  qmdpi_bundle_destroy + qmdpi_engine_destroy.
//   - workerSlot(): hands out per-worker QosmosWorker handles via
//                   ThreadLocal::TypedSlot<QosmosWorker>. Each Envoy worker
//                   thread gets its own qmdpi_worker* via qmdpi_worker_create.
class QosmosEngine : public Singleton::Instance,
                     Logger::Loggable<Logger::Id::filter> {
public:
  // Args:
  //   engine_config: Qosmos engine config string. Empty ⇒ synthesised
  //                  default ("injection_mode=stream;nb_workers=N").
  //   bundle_path:   path to .qmdb protocol bundle.
  //   table_path:    path to qosmos_protocols.json.
  //   nb_workers:    number of Envoy worker threads (used to size the
  //                  Qosmos engine's internal worker pool when synthesising
  //                  the config string).
  //   tls:           Envoy's ThreadLocal::SlotAllocator. We allocate a
  //                  TypedSlot<QosmosWorker> here and populate it from the
  //                  main thread; each worker thread will deep-copy the
  //                  per-worker entry.
  QosmosEngine(const std::string& engine_config,
               const std::string& bundle_path,
               const std::string& table_path,
               uint32_t nb_workers,
               ThreadLocal::SlotAllocator& tls);

  ~QosmosEngine() override;

  qmdpi_engine* rawEngine() const { return engine_; }
  qmdpi_bundle* rawBundle() const { return bundle_; }
  const ProtocolTable& table() const { return *table_; }

  // Returns the QosmosWorker bound to the calling Envoy worker thread.
  // Must be called from a worker thread (i.e. inside an Envoy filter
  // callback) — the underlying TypedSlot<>::get() asserts this.
  QosmosWorker& workerForThisThread();

private:
  // Build the engine_config string that gets passed to qmdpi_engine_create.
  // If `user_supplied` is non-empty, returns it verbatim; otherwise
  // synthesises the default stream-mode config.
  static std::string resolveEngineConfig(const std::string& user_supplied,
                                          uint32_t nb_workers);

  qmdpi_engine* engine_{};
  qmdpi_bundle* bundle_{};
  std::unique_ptr<ProtocolTable> table_;
  ThreadLocal::TypedSlotPtr<QosmosWorker> worker_slot_;
};

using QosmosEngineSharedPtr = std::shared_ptr<QosmosEngine>;

}  // namespace QosmosDpi
}  // namespace ListenerFilters
}  // namespace Extensions
}  // namespace Envoy
