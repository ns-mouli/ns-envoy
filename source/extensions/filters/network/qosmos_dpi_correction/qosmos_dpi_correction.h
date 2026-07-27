#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

#include "envoy/event/timer.h"
#include "envoy/network/filter.h"
#include "envoy/stats/scope.h"
#include "envoy/stats/stats_macros.h"

#include "source/common/common/logger.h"
#include "source/extensions/common/qosmos_dpi/qosmos_engine.h"
#include "source/extensions/common/qosmos_dpi/qosmos_flow_handoff.h"
#include "source/extensions/common/qosmos_dpi/verdict_cache.h"

#include "envoy/extensions/filters/network/qosmos_dpi_correction/v3/qosmos_dpi_correction.pb.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace QosmosDpiCorrection {

using ::Envoy::Extensions::Common::QosmosDpi::ClassifyResult;
using ::Envoy::Extensions::Common::QosmosDpi::QosmosClassifierPtr;
using ::Envoy::Extensions::Common::QosmosDpi::QosmosEngine;
using ::Envoy::Extensions::Common::QosmosDpi::QosmosFlowHandoff;
using ::Envoy::Extensions::Common::QosmosDpi::VerdictCacheKey;

// Stats for the correction filter's own scope
// (`qosmos_dpi_correction.<counter>`), separate from the listener filter's
// `qosmos_dpi.<counter>` set. See plan Part H.
//
//   correction_flows_claimed          Filter::onNewConnection found a
//                                     QosmosFlowHandoff and released the
//                                     classifier out of it.
//   correction_flow_destroyed         Filter::finalize called (either the
//                                     engine reached final_state or a
//                                     resource bound tripped).
//   correction_flips                  A2.2 signal: the corrected verdict
//                                     disagreed with the 4-pkt initial
//                                     verdict. Never incremented on the
//                                     silence-timeout hand-off (nullopt
//                                     initial verdict).
//   correction_bound_hit              A resource bound (timeout OR bytes
//                                     OR pdus) tripped before final_state.
//   correction_populated_from_silence  Silence-timeout hand-off
//                                     (initial_verdict_is_web == nullopt)
//                                     reached a real classification later
//                                     and populated the cache — a
//                                     first-time populate rather than a
//                                     correction. Distinct from flips.
//   correction_flows_active           Gauge: currently claimed classifiers.
//   correction_bytes_processed        Histogram: bytes fed post-hand-off.
#define ALL_QOSMOS_DPI_CORRECTION_STATS(COUNTER, GAUGE, HISTOGRAM)             \
  COUNTER(correction_flows_claimed)                                            \
  COUNTER(correction_flow_destroyed)                                           \
  COUNTER(correction_flips)                                                    \
  COUNTER(correction_bound_hit)                                                \
  COUNTER(correction_populated_from_silence)                                   \
  GAUGE(correction_flows_active, NeverImport)                                  \
  HISTOGRAM(correction_bytes_processed, Bytes)

struct QosmosDpiCorrectionStats {
  ALL_QOSMOS_DPI_CORRECTION_STATS(GENERATE_COUNTER_STRUCT,
                                   GENERATE_GAUGE_STRUCT,
                                   GENERATE_HISTOGRAM_STRUCT)
};

class Config {
public:
  using ProtoConfig = envoy::extensions::filters::network::qosmos_dpi_correction::v3::QosmosDpiCorrection;

  Config(const ProtoConfig& proto, Stats::Scope& scope);

  std::chrono::milliseconds correctionTimeout() const { return correction_timeout_; }
  uint32_t maxCorrectionBytes() const { return max_correction_bytes_; }
  uint32_t maxCorrectionPdus() const { return max_correction_pdus_; }

  QosmosDpiCorrectionStats& stats() { return stats_; }

private:
  std::chrono::milliseconds correction_timeout_;
  uint32_t max_correction_bytes_;
  uint32_t max_correction_pdus_;
  QosmosDpiCorrectionStats stats_;
};

using ConfigSharedPtr = std::shared_ptr<Config>;

// Read + Write network filter. Claims the handed-off classifier in
// `onNewConnection()`; feeds subsequent CTS bytes via `onData` (after
// skipping the leading bytes the listener filter already peeked) and STC
// bytes via `onWrite` into the SAME flow via `classifyPdu`; on final_state
// or a resource bound, calls `finalize()`, re-runs the cascade, corrects
// the per-worker cache if the verdict flipped, and goes permanently
// passthrough for the rest of the connection.
class Filter : public Network::Filter,
               Logger::Loggable<Logger::Id::filter> {
public:
  explicit Filter(ConfigSharedPtr config);
  ~Filter() override;

  // Network::ReadFilter
  Network::FilterStatus onNewConnection() override;
  Network::FilterStatus onData(Buffer::Instance& data, bool end_stream) override;
  void initializeReadFilterCallbacks(Network::ReadFilterCallbacks& cb) override {
    read_cb_ = &cb;
  }

  // Network::WriteFilter
  Network::FilterStatus onWrite(Buffer::Instance& data, bool end_stream) override;
  void initializeWriteFilterCallbacks(Network::WriteFilterCallbacks& cb) override {
    write_cb_ = &cb;
  }

private:
  // Called from onData / onWrite once the per-connection state (classifier,
  // key, engine) has been claimed. Skips any CTS bytes already peeked by
  // the listener filter, forwards a slice to classifyPdu, checks the
  // final_state flag and the resource bounds, and finalizes when either
  // trips. `data` is never mutated — the correction filter is a passive
  // observer; all bytes still reach the next filter / tcp_proxy /
  // upstream unchanged.
  Network::FilterStatus feed(Buffer::Instance& data, int direction);

  // Force-finalize the flow. If final_state was reached, re-run the
  // cascade and correct the cache. If a resource bound tripped, only
  // update the cache when there was a real prior verdict — silence-
  // timeout hand-offs that never reached a real classification leave the
  // cache alone (better an uncached destination than a synthetic guess).
  void finalizeAndMaybeCorrect(bool final_state_reached);

  ConfigSharedPtr config_;
  Network::ReadFilterCallbacks* read_cb_{};
  Network::WriteFilterCallbacks* write_cb_{};

  // Claimed state (only populated after a successful onNewConnection).
  QosmosClassifierPtr classifier_;
  VerdictCacheKey key_;
  absl::optional<bool> initial_verdict_is_web_;
  QosmosEngine* engine_{};
  size_t cts_bytes_to_skip_{0};

  // Resource-bound counters.
  size_t bytes_fed_{0};
  uint32_t pdus_fed_{0};
  Event::TimerPtr correction_timer_;

  // Set once onNewConnection decides this connection has no handoff (or
  // the handoff has already been finalized). Every subsequent onData /
  // onWrite is a zero-cost pass-through. Also set after finalize().
  bool passthrough_{true};
};

}  // namespace QosmosDpiCorrection
}  // namespace NetworkFilters
}  // namespace Extensions
}  // namespace Envoy
