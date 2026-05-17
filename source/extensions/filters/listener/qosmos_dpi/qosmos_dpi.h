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
#include "source/extensions/filters/listener/qosmos_dpi/qosmos_engine.h"

#include "envoy/extensions/filters/listener/qosmos_dpi/v3/qosmos_dpi.pb.h"

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace QosmosDpi {

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
//   flows_released_at_close   releaseFlow() called from onClose belt-and-braces
//                             (rare — client disconnected before any verdict)
//   bytes_processed           histogram of bytes_inspected per connection
#define ALL_QOSMOS_DPI_STATS(COUNTER, GAUGE, HISTOGRAM)                       \
  COUNTER(web_classified)                                                     \
  COUNTER(non_web_classified)                                                 \
  COUNTER(silence_timeout)                                                    \
  COUNTER(inconclusive_forced_cfw)                                            \
  COUNTER(engine_error)                                                       \
  COUNTER(flows_released_at_verdict)                                          \
  COUNTER(flows_released_at_close)                                            \
  GAUGE(flows_active, NeverImport)                                            \
  HISTOGRAM(bytes_processed, Bytes)

struct QosmosDpiStats {
  ALL_QOSMOS_DPI_STATS(GENERATE_COUNTER_STRUCT, GENERATE_GAUGE_STRUCT,
                       GENERATE_HISTOGRAM_STRUCT)
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
  // QosmosEngine entirely. The protocol table is provided directly.
  Config(const ProtoConfig& proto, ClassifierFactory factory,
         std::shared_ptr<ProtocolTable> table, Stats::Scope& scope);

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
//   onClose    →  ~classifier_ destroys the flow if still alive
//                 (belt-and-braces; rare — connection closed before
//                 first byte AND before silence_timeout fired).
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
  void onClose() override;

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
};

}  // namespace QosmosDpi
}  // namespace ListenerFilters
}  // namespace Extensions
}  // namespace Envoy
