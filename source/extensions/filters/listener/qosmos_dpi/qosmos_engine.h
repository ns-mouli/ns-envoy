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

// Result of a single first-PDU classification round: the engine's
// intermediate path (from qmdpi_worker_process) and the final path
// (from qmdpi_flow_destroy out-param). Either may be empty.
//
// hooks carries any extracted attributes the cascade consults. As of
// 2026-05-18 we extract only ssl:alpn; future extensions can populate
// additional keys without changing the cascade interface.
struct ClassifyResult {
  std::string intermediate_path;
  std::string final_path;
  Hooks hooks;
  bool engine_error{false};   // true if qmdpi_worker_pdu_set or
                              // qmdpi_worker_process returned non-zero.
};

// Per-connection classification transaction. Owns a qmdpi_flow* via
// RAII: created at construction time (or nullptr on failure), destroyed
// either by `classifyFirstPdu()` (the verdict path) or by `~QosmosClassifier`
// (the silence-timeout / on-close path). Either way, qmdpi_flow_destroy
// is called exactly once per successfully-created flow.
//
// Filter holds a `std::unique_ptr<QosmosClassifier>` per accepted
// connection. Tests substitute a MockQosmosClassifier that returns
// canned ClassifyResult instances without touching the real Qosmos engine.
class QosmosClassifier {
public:
  virtual ~QosmosClassifier() = default;

  // Whether the underlying qmdpi_flow* was created successfully and is
  // still alive (i.e. classifyFirstPdu hasn't been called yet AND the
  // constructor didn't fail). False ⇒ the connection should fail-safe
  // to non-web.
  virtual bool flowAlive() const PURE;

  // Single-shot classify. Feeds `bytes`/`len` to qmdpi_worker_pdu_set,
  // runs qmdpi_worker_process to get the intermediate path, then
  // UNCONDITIONALLY calls qmdpi_flow_destroy to get the final path
  // and release engine-side state. After this returns, flowAlive()
  // returns false and subsequent calls are no-ops returning empty
  // ClassifyResult{}.
  virtual ClassifyResult classifyFirstPdu(const void* bytes, int len,
                                          int direction,
                                          int tenant_id) PURE;
};

using QosmosClassifierPtr = std::unique_ptr<QosmosClassifier>;

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

  const ProtocolTable& table() const { return *table_; }

  // Returns the QosmosWorker bound to the calling Envoy worker thread.
  // Must be called from a worker thread (i.e. inside an Envoy filter
  // callback) — the underlying TypedSlot<>::get() asserts this.
  QosmosWorker& workerForThisThread();

  // Factory: build a QosmosClassifier for one connection. The classifier
  // calls qmdpi_flow_create internally during construction. Returns nullptr
  // if the engine isn't ready (e.g. construction failed earlier and we're
  // operating in fail-safe mode); the caller treats nullptr as engine_error.
  //
  // src/dst args are network-byte-order. `is_v6` selects between IPv4 (uses
  // the lower 4 bytes of `src`/`dst`) and IPv6 (uses all 16 bytes).
  QosmosClassifierPtr makeClassifier(bool is_v6, const void* src_ip,
                                      uint16_t src_port_nbo,
                                      const void* dst_ip,
                                      uint16_t dst_port_nbo);

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

  // Cascade rules 0/1 consume `ssl:alpn`. We register that attribute at
  // init time and cache its (proto_id, attr_id) integer pair so the
  // per-classify result-iteration can match it without string lookups.
  // Negative values ⇒ registration failed (cascade will run without ALPN
  // hooks; rules 0/1 won't fire; behaviour is conservative).
  int ssl_proto_id_{-1};
  int alpn_attr_id_{-1};
};

using QosmosEngineSharedPtr = std::shared_ptr<QosmosEngine>;

}  // namespace QosmosDpi
}  // namespace ListenerFilters
}  // namespace Extensions
}  // namespace Envoy
