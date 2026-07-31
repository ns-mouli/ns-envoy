#pragma once

#include <chrono>
#include <functional>
#include <memory>
#include <string>

#include "envoy/event/timer.h"
#include "envoy/network/filter.h"
#include "envoy/stats/scope.h"
#include "envoy/stats/stats_macros.h"

#include "source/common/common/logger.h"
#include "source/extensions/common/qosmos_dpi/qosmos_engine.h"
#include "source/extensions/common/qosmos_dpi/verdict_cache.h"

#include "envoy/extensions/filters/listener/qosmos_dpi/v3/qosmos_dpi.pb.h"

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace QosmosDpi {

// Shared plumbing moved to source/extensions/common/qosmos_dpi/. Import
// the symbols this filter references so the existing unqualified names
// (QosmosEngine, QosmosClassifier, ClassifyResult, Hooks, ProtocolTable,
// ...) still resolve. Adding new imports here is cheaper than touching
// every reference site.
using ::Envoy::Extensions::Common::QosmosDpi::ClassifyResult;
using ::Envoy::Extensions::Common::QosmosDpi::Hooks;
using ::Envoy::Extensions::Common::QosmosDpi::ProtocolTable;
using ::Envoy::Extensions::Common::QosmosDpi::QosmosClassifier;
using ::Envoy::Extensions::Common::QosmosDpi::QosmosClassifierPtr;
using ::Envoy::Extensions::Common::QosmosDpi::QosmosEngine;
using ::Envoy::Extensions::Common::QosmosDpi::QosmosEngineSharedPtr;
using ::Envoy::Extensions::Common::QosmosDpi::QosmosWorker;

// Factory function the Filter uses to obtain a per-connection classifier.
// In production this delegates to QosmosEngine::makeClassifier(). Tests
// substitute a lambda that returns a MockQosmosClassifier.
//
// is_v6 selects IPv4 vs IPv6 layout. src_ip/dst_ip point to the address
// bytes (4 or 16 depending on is_v6). Ports are network byte order.
using ClassifierFactory =
    std::function<QosmosClassifierPtr(bool is_v6, const void* src_ip,
                                       uint16_t src_port_nbo,
                                       const void* dst_ip,
                                       uint16_t dst_port_nbo)>;

// All counter / histogram stats for the qosmos_dpi listener filter.
//
// Naming follows the {ALL_QOSMOS_DPI_STATS,GENERATE_*} macro convention
// used by every listener filter (see tls_inspector.h:37).
//
//   web_classified            verdict was web (intermediate or post-destroy)
//   non_web_classified        verdict was non-web (intermediate or post-destroy
//                             or fail-safe)
//   silence_timeout           silence timer fired before any client byte
//   inconclusive_forced_cfw   both intermediate AND post-destroy paths null;
//                             defaulted to non-web/CFW
//   engine_error              qmdpi_* returned error during classification
//   flows_released_at_verdict releaseFlow() called from a verdict path
//   flows_released_at_close   releaseFlow() called from ~Filter belt-and-braces
//                             (rare — client disconnected before any verdict)
//   bytes_processed           histogram of bytes_inspected per connection
//   verdict_cache_hit         onAccept lookup found an existing entry; DPI
//                             skipped entirely for this connection
//   verdict_cache_miss        onAccept lookup found nothing; DPI proceeded
//   verdict_cache_reject_full  put() attempted on a new key when the cache
//                             is at max_entries (no eviction — new key
//                             dropped); rare, indicates a capacity bump is
//                             needed
//   handed_off_to_correction  onData/onSilenceTimeout parked a QosmosFlowHandoff
//                             in FilterState for the correction network filter
//                             to claim
//   verdict_cache_size        current per-worker cache entry count (gauge)
#define ALL_QOSMOS_DPI_STATS(COUNTER, GAUGE, HISTOGRAM)                       \
  COUNTER(web_classified)                                                     \
  COUNTER(non_web_classified)                                                 \
  COUNTER(silence_timeout)                                                    \
  COUNTER(inconclusive_forced_cfw)                                            \
  COUNTER(engine_error)                                                       \
  COUNTER(flows_released_at_verdict)                                          \
  COUNTER(flows_released_at_close)                                            \
  COUNTER(verdict_cache_hit)                                                  \
  COUNTER(verdict_cache_miss)                                                 \
  COUNTER(verdict_cache_reject_full)                                          \
  COUNTER(verdict_cache_disagreement)                                         \
  COUNTER(handed_off_to_correction)                                           \
  GAUGE(flows_active, NeverImport)                                            \
  GAUGE(verdict_cache_size, NeverImport)                                      \
  HISTOGRAM(bytes_processed, Bytes)

struct QosmosDpiStats {
  ALL_QOSMOS_DPI_STATS(GENERATE_COUNTER_STRUCT, GENERATE_GAUGE_STRUCT,
                       GENERATE_HISTOGRAM_STRUCT)
};

// Snapshot of the accepted connection's destination — captured in onAccept
// so onData / onSilenceTimeout can compose the verdict cache key (adding
// a hooks-derived SNI/JA4/Host discriminator, or Plain when no name hint
// is available). An empty `.ip` signals "no cache key computable"; the
// filter treats that as fail-safe and skips the cache path.
struct DstAddrSnapshot {
  std::string ip;
  uint16_t port{0};
};

// Config for the qosmos_dpi listener filter. One Config per listener; the
// filter Factory clones it per-connection. Holds:
//   - a shared_ptr to the process-wide QosmosEngine (Singleton::Instance)
//   - the protocol-table reference (cascade lookup table)
//   - the classifier factory (production: QosmosEngine::makeClassifier;
//     tests: lambda returning MockQosmosClassifier)
//   - resolved proto-config knobs
//   - the stats handle (shared by all filter instances on this listener)
class Config {
public:
  using ProtoConfig =
      envoy::extensions::filters::listener::qosmos_dpi::v3::QosmosDpi;

  Config(const ProtoConfig& proto, QosmosEngineSharedPtr engine,
         Stats::Scope& scope);

  // Test-only constructor: inject a mock classifier factory and bypass
  // QosmosEngine entirely. The protocol table is provided directly. An
  // optional VerdictCache can be attached; when non-null the filter's
  // cache/handoff branches fire as if a real engine were behind them.
  // Owned by the caller — must outlive this Config.
  Config(const ProtoConfig& proto, ClassifierFactory factory,
         std::shared_ptr<ProtocolTable> table, Stats::Scope& scope,
         Extensions::Common::QosmosDpi::VerdictCache* test_verdict_cache = nullptr);

  // The cascade lookup table. In production the engine owns it; in tests
  // we override via the second constructor. Always non-null after Config
  // construction (the constructors enforce this).
  const ProtocolTable& table() const;
  const ClassifierFactory& classifierFactory() const { return classifier_factory_; }

  const std::string& webCluster() const { return web_cluster_; }
  const std::string& nonWebCluster() const { return non_web_cluster_; }
  std::chrono::milliseconds silenceTimeout() const { return silence_timeout_; }
  uint32_t defaultTenantId() const { return default_tenant_id_; }
  uint32_t maxInspectBytes() const { return max_inspect_bytes_; }
  bool closeOnEngineError() const { return close_on_engine_error_; }

  // Verdict-cache + correction knobs (proto fields 10 + 11). Off by default;
  // the filter's onAccept/onData/onSilenceTimeout branches are byte-for-byte
  // identical to today's behaviour when this returns false.
  bool verdictCacheCorrectionEnabled() const {
    return verdict_cache_correction_enabled_;
  }

  // Non-null in production iff verdictCacheCorrectionEnabled() is true.
  // Null in the test constructor (tests exercising the correction path use
  // dedicated fixtures — see plan Part I). Kept as a raw pointer because
  // Config already owns the QosmosEngine shared_ptr.
  QosmosEngine* engine() const { return engine_.get(); }

  // Returns the VerdictCache the filter should use for THIS worker thread
  // (production: engine_->cacheForThisThread() when the engine has the
  // cache enabled; tests: the test_verdict_cache passed to the test-only
  // ctor). Returns nullptr when the cache is disabled or the config is
  // production without a live engine cache — callers must null-check.
  Extensions::Common::QosmosDpi::VerdictCache* verdictCacheForThisThread() const;

  QosmosDpiStats& stats() { return stats_; }

private:
  // engine_ is non-null in production; null in tests (when the second
  // constructor is used). Owning the shared_ptr keeps the engine alive
  // for as long as any Config (and therefore listener) references it.
  QosmosEngineSharedPtr engine_;
  std::shared_ptr<ProtocolTable> table_;
  ClassifierFactory classifier_factory_;

  std::string web_cluster_;
  std::string non_web_cluster_;
  std::chrono::milliseconds silence_timeout_;
  uint32_t default_tenant_id_;
  uint32_t max_inspect_bytes_;
  bool close_on_engine_error_;
  bool verdict_cache_correction_enabled_{false};
  Extensions::Common::QosmosDpi::VerdictCache* test_verdict_cache_{nullptr};
  QosmosDpiStats stats_;
};

using ConfigSharedPtr = std::shared_ptr<Config>;

// The listener filter itself. One instance per accepted connection.
//
// Lifecycle (matches docs/qosmos-dpi-integration-plan.md §1, §7.4):
//   onAccept   →  config_->classifierFactory()(...) → owns qmdpi_flow*
//                 + arm 200ms silence timer
//   onData     →  classifier_->classifyFirstPdu() returns
//                 {intermediate_path, final_path}; classifier internally
//                 ALWAYS calls qmdpi_flow_destroy.
//                 cascade(intermediate) || cascade(final) || non_web
//                 setVerdict() via PerConnectionCluster
//                 return Continue (filter is done)
//   silence    →  setVerdict(non_web), continueFilterChain(true).
//                 ~classifier_ destroys the unused flow.
//   ~Filter    →  ~classifier_ destroys the flow if still alive
//                 (belt-and-braces; rare — connection closed before
//                 first byte AND before silence_timeout fired). v1.32.4's
//                 Network::ListenerFilter has no onClose() hook (only
//                 onAccept/onData/maxReadBytes), so this cleanup — silence
//                 timer disarm + classifier teardown — lives entirely in
//                 the destructor.
//
// Default verdict on any inconclusive / null / error path is non-web (CFW).
class Filter : public Network::ListenerFilter,
               Logger::Loggable<Logger::Id::filter> {
public:
  explicit Filter(ConfigSharedPtr config);
  ~Filter() override;

  // Network::ListenerFilter
  Network::FilterStatus onAccept(Network::ListenerFilterCallbacks& cb) override;
  Network::FilterStatus onData(Network::ListenerFilterBuffer& buffer) override;
  size_t maxReadBytes() const override { return config_->maxInspectBytes(); }

private:
  // Silence-timer callback. Invoked when no client bytes arrived within
  // silence_timeout. Defaults verdict to non_web and releases the chain.
  void onSilenceTimeout();

  // Write PerConnectionCluster into FilterState. Called exactly once per
  // connection from a verdict-finalising path.
  void setVerdict(absl::string_view cluster_name, bool is_web);

  // Increment the appropriate flow-released-* counter based on whether
  // the classifier was destroyed via the verdict path (classifyFirstPdu
  // ran) or the on-close belt-and-braces path. Called from ~Filter.
  void recordClassifierDestruction();

  ConfigSharedPtr config_;
  Network::ListenerFilterCallbacks* cb_{};
  QosmosClassifierPtr classifier_;
  Event::TimerPtr silence_timer_;
  bool verdict_set_{false};
  bool classify_invoked_{false};   // true once classifyFirstPdu has run.
  bool handed_off_{false};         // true once classifier_ was moved into
                                    // a QosmosFlowHandoff in FilterState.
  // Only populated when verdictCacheCorrectionEnabled(). Cached from
  // onAccept and consumed in onData / onSilenceTimeout: destination
  // {ip, port} — the discriminator part of the key comes from post-
  // classifyPdu hooks (SNI/JA4/Host) and is folded in there. Empty
  // dst_addr_.ip signals "no key computed" (fail-safe: skip cache
  // lookup / populate for this connection). DstAddrSnapshot type
  // declared at namespace scope below the class.
  DstAddrSnapshot dst_addr_;
  // Full cache key: dst_addr_ + hooks-derived discriminator. Populated in
  // onData right after classifyPdu (so it can be handed to the correction
  // filter via QosmosFlowHandoff), or in onSilenceTimeout using
  // dst_addr_ + Plain discriminator (no hooks available yet).
  Extensions::Common::QosmosDpi::VerdictCacheKey cache_key_;
  size_t bytes_peeked_this_pdu_{0};   // set in onData right before
                                       // classifyPdu; consumed when a
                                       // handoff is constructed.
};

}  // namespace QosmosDpi
}  // namespace ListenerFilters
}  // namespace Extensions
}  // namespace Envoy
