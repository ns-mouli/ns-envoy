#pragma once

#include <chrono>
#include <memory>
#include <string>

#include "envoy/event/timer.h"
#include "envoy/network/filter.h"
#include "envoy/stats/scope.h"
#include "envoy/stats/stats_macros.h"

#include "source/common/common/logger.h"
#include "source/extensions/filters/listener/qosmos_dpi/qosmos_engine.h"

#include "envoy/extensions/filters/listener/qosmos_dpi/v3/qosmos_dpi.pb.h"

extern "C" {
#include "qmdpi.h"
}

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace QosmosDpi {

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
//   - resolved proto-config knobs: cluster names, silence_timeout,
//     max_inspect_bytes, default_tenant_id, close_on_engine_error
//   - the stats handle (shared by all filter instances on this listener)
class Config {
public:
  using ProtoConfig =
      envoy::extensions::filters::listener::qosmos_dpi::v3::QosmosDpi;

  Config(const ProtoConfig& proto, QosmosEngineSharedPtr engine,
         Stats::Scope& scope);

  QosmosEngine& engine() { return *engine_; }

  const std::string& webCluster() const { return web_cluster_; }
  const std::string& nonWebCluster() const { return non_web_cluster_; }
  std::chrono::milliseconds silenceTimeout() const { return silence_timeout_; }
  uint32_t defaultTenantId() const { return default_tenant_id_; }
  uint32_t maxInspectBytes() const { return max_inspect_bytes_; }
  bool closeOnEngineError() const { return close_on_engine_error_; }

  QosmosDpiStats& stats() { return stats_; }

private:
  QosmosEngineSharedPtr engine_;
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
//   onAccept   →  qmdpi_flow_create(5-tuple) + arm 200ms silence timer
//   onData     →  qmdpi_worker_pdu_set + qmdpi_worker_process(intermediate)
//                 →  ALWAYS qmdpi_flow_destroy(&final_result)   (releaseFlow)
//                 →  setVerdict(web | non-web)  via PerConnectionCluster
//                 →  return Continue   (filter is done)
//   silence    →  setVerdict(non_web)  + continueFilterChain(true)
//                 (server-greets-first FTP/SMTP)
//   onClose    →  releaseFlow() if still alive (belt-and-braces)
//
// Default verdict on any inconclusive / null / error path is non-web.
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
  // Called from onData once we have at least one PDU. Runs:
  //   qmdpi_worker_pdu_set + qmdpi_worker_process → cascade → if no verdict yet,
  //   qmdpi_flow_destroy → cascade(final_result) → setVerdict.
  // Returns Continue when verdict is finalised, StopIteration when waiting
  // for more bytes (only when we haven't reached max_inspect_bytes yet).
  Network::FilterStatus classifyOnFirstPdu(
      const Buffer::ConstRawSlice& slice);

  // Silence-timer callback. Invoked from the dispatcher when no client
  // bytes arrived within the silence_timeout window. Defaults verdict
  // to non_web (CFW for FTP/SMTP server-greets-first) and releases the
  // filter chain.
  void onSilenceTimeout();

  // Write PerConnectionCluster into FilterState. Called exactly once per
  // connection from a verdict-finalising path. After this, tcp_proxy will
  // pick `cluster_name` as the upstream when the filter chain continues.
  void setVerdict(absl::string_view cluster_name, bool is_web);

  // Destroy the qmdpi_flow* and release engine-side state. Idempotent —
  // sets flow_ = nullptr after destruction. Called from every verdict
  // path AND from onClose belt-and-braces. The two paths increment
  // different counters so we can verify the invariant
  // `flows_released_at_verdict + flows_released_at_close == flows_created`.
  // `from_verdict_path` true ⇒ increment flows_released_at_verdict.
  // false ⇒ increment flows_released_at_close.
  void releaseFlow(bool from_verdict_path, qmdpi_result** out_result = nullptr);

  ConfigSharedPtr config_;
  Network::ListenerFilterCallbacks* cb_{};
  qmdpi_flow* flow_{};
  Event::TimerPtr silence_timer_;
  size_t bytes_inspected_{0};
  bool verdict_set_{false};
};

}  // namespace QosmosDpi
}  // namespace ListenerFilters
}  // namespace Extensions
}  // namespace Envoy
