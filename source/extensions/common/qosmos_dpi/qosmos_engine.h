#pragma once

#include <memory>
#include <string>

#include "envoy/singleton/instance.h"
#include "envoy/thread_local/thread_local.h"

#include "source/common/common/logger.h"
#include "source/extensions/common/qosmos_dpi/protocol_table.h"

extern "C" {
#include "qmdpi.h"
}

namespace Envoy {
namespace Extensions {
namespace Common {
namespace QosmosDpi {

class VerdictCache;

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
  // True iff the engine set QMDPI_RESULT_FLAGS_CLASSIFIED_FINAL_STATE on this
  // classify. Only ever set by classifyPdu() (which does not destroy the
  // flow); classifyFirstPdu() and finalize() always leave this false because
  // the finality signal is only meaningful before the destroy call.
  bool final_state{false};
};

// Per-connection classification transaction. Owns a qmdpi_flow* via
// RAII: created at construction time (or nullptr on failure), destroyed
// either by `classifyFirstPdu()` / `finalize()` (the verdict paths) or by
// `~QosmosClassifier` (the silence-timeout / on-close path). Either way,
// qmdpi_flow_destroy is called exactly once per successfully-created flow.
//
// Filter holds a `std::unique_ptr<QosmosClassifier>` per accepted
// connection. Tests substitute a MockQosmosClassifier that returns
// canned ClassifyResult instances without touching the real Qosmos engine.
class QosmosClassifier {
public:
  virtual ~QosmosClassifier() = default;

  // Whether the underlying qmdpi_flow* was created successfully and is
  // still alive (i.e. finalize() hasn't been called yet AND the
  // constructor didn't fail). False ⇒ the connection should fail-safe
  // to non-web.
  virtual bool flowAlive() const PURE;

  // Feed one PDU to the engine. Does NOT destroy the flow — the flow stays
  // alive (flowAlive() remains true) for a subsequent call. Sets
  // result.final_state from QMDPI_RESULT_FLAGS_CLASSIFIED_FINAL_STATE and
  // populates result.intermediate_path + result.hooks. result.final_path
  // is always empty on this path (the final path is a qmdpi_flow_destroy
  // out-param, and destroy hasn't happened).
  //
  // The listener filter calls this at most once (for the initial verdict);
  // the correction network filter calls it repeatedly afterward on the
  // SAME classifier instance.
  virtual ClassifyResult classifyPdu(const void* bytes, int len, int direction,
                                     int tenant_id) PURE;

  // Idempotent teardown: qmdpi_flow_destroy, flow_ = nullptr. Extracts the
  // final path + hooks from the destroy out-param and returns them via
  // ClassifyResult (intermediate_path always empty on this path).
  // After this returns, flowAlive() returns false and further classifyPdu
  // calls are no-ops returning ClassifyResult{engine_error=true}.
  virtual ClassifyResult finalize() PURE;

  // Convenience wrapper: classifyPdu + finalize, merged. This is the
  // pre-cache single-shot path — the listener filter uses it when
  // verdict_cache_correction_enabled is false (default), preserving today's
  // "destroy on first PDU" behaviour byte-for-byte. It also lets tests /
  // mocks that only cared about the merged shape keep working unchanged.
  // Non-virtual by design — implementations override the two primitives.
  ClassifyResult classifyFirstPdu(const void* bytes, int len, int direction,
                                   int tenant_id) {
    ClassifyResult cr = classifyPdu(bytes, len, direction, tenant_id);
    ClassifyResult final_cr = finalize();
    cr.final_path = std::move(final_cr.final_path);
    for (auto& kv : final_cr.hooks) {
      cr.hooks.try_emplace(kv.first, std::move(kv.second));
    }
    if (final_cr.engine_error) cr.engine_error = true;
    cr.final_state = false;   // finality-signal is meaningless post-destroy.
    return cr;
  }
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
               ThreadLocal::SlotAllocator& tls,
               uint32_t verdict_cache_max_entries = 0,
               uint32_t total_nb_flows = 0);

  ~QosmosEngine() override;

  const ProtocolTable& table() const { return *table_; }

  // Returns the QosmosWorker bound to the calling Envoy worker thread.
  // Must be called from a worker thread (i.e. inside an Envoy filter
  // callback) — the underlying TypedSlot<>::get() asserts this.
  QosmosWorker& workerForThisThread();

  // Returns the VerdictCache bound to the calling Envoy worker thread.
  // Same call-site restriction as workerForThisThread(). Non-null iff
  // verdict_cache_max_entries was non-zero at construction; callers must
  // check via verdictCacheEnabled() before dereferencing.
  bool verdictCacheEnabled() const { return cache_slot_ != nullptr; }
  VerdictCache& cacheForThisThread();

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
  // synthesises the default stream-mode config. `total_nb_flows` is the
  // process-wide flow-context budget; the per-worker `nb_flows` argument
  // is derived as ceil(total_nb_flows / (nb_workers + 1)). 0 ⇒ use
  // built-in default (300000).
  static std::string resolveEngineConfig(const std::string& user_supplied,
                                          uint32_t nb_workers,
                                          uint32_t total_nb_flows);

  qmdpi_engine* engine_{};
  qmdpi_bundle* bundle_{};
  std::unique_ptr<ProtocolTable> table_;
  ThreadLocal::TypedSlotPtr<QosmosWorker> worker_slot_;
  // Non-null iff the verdict cache is enabled (max_entries > 0). Kept as a
  // TypedSlotPtr rather than a TypedSlot so a null cache_slot_ is a
  // zero-cost signal that the cache is off; the correction filter's
  // per-worker cacheForThisThread() calls flow through this same slot.
  ThreadLocal::TypedSlotPtr<VerdictCache> cache_slot_;

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
}  // namespace Common
}  // namespace Extensions
}  // namespace Envoy
