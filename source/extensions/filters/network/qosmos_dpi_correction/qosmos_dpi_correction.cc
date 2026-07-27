#include "source/extensions/filters/network/qosmos_dpi_correction/qosmos_dpi_correction.h"

#include <cstdint>
#include <utility>

#include "envoy/network/connection.h"

#include "source/common/protobuf/utility.h"

extern "C" {
#include "qmdpi_const.h"  // QMDPI_DIR_CTS / QMDPI_DIR_STC
}

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace QosmosDpiCorrection {

namespace {

QosmosDpiCorrectionStats generateStats(Stats::Scope& scope) {
  const std::string prefix = "qosmos_dpi_correction.";
  return QosmosDpiCorrectionStats{ALL_QOSMOS_DPI_CORRECTION_STATS(
      POOL_COUNTER_PREFIX(scope, prefix), POOL_GAUGE_PREFIX(scope, prefix),
      POOL_HISTOGRAM_PREFIX(scope, prefix))};
}

}  // namespace

Config::Config(const ProtoConfig& proto, Stats::Scope& scope)
    : correction_timeout_(
          PROTOBUF_GET_MS_OR_DEFAULT(proto, correction_timeout, 5000)),
      max_correction_bytes_(proto.max_correction_bytes() == 0
                                ? 65536U
                                : proto.max_correction_bytes()),
      max_correction_pdus_(proto.max_correction_pdus() == 0
                               ? 64U
                               : proto.max_correction_pdus()),
      stats_(generateStats(scope)) {}

Filter::Filter(ConfigSharedPtr config) : config_(std::move(config)) {}

Filter::~Filter() {
  // If we still hold a classifier (e.g. the connection closed before
  // final_state was reached AND before a bound tripped), tear it down
  // now. This keeps the cache alone — a synthetic post-close guess
  // would poison future connections.
  if (classifier_ != nullptr) {
    classifier_->finalize();
    classifier_.reset();
    config_->stats().correction_flows_active_.dec();
    config_->stats().correction_flow_destroyed_.inc();
  }
}

Network::FilterStatus Filter::onNewConnection() {
  if (read_cb_ == nullptr) {
    // Extremely defensive: filter manager didn't wire us up as a read
    // filter. Nothing we can do — go passthrough.
    passthrough_ = true;
    return Network::FilterStatus::Continue;
  }

  auto* handoff =
      read_cb_->connection().streamInfo().filterState()->getDataMutable<QosmosFlowHandoff>(
          QosmosFlowHandoff::filterStateKey());
  if (handoff == nullptr) {
    // No hand-off object for this connection — either the listener
    // filter didn't produce one (cache disabled, cache hit, or listener
    // filter not in the chain) or another network filter already claimed
    // it. Either way: passthrough for the rest of the connection.
    passthrough_ = true;
    return Network::FilterStatus::Continue;
  }

  classifier_ = handoff->release();
  key_ = handoff->cacheKey();
  initial_verdict_is_web_ = handoff->initialVerdictIsWeb();
  engine_ = &handoff->engine();
  cts_bytes_to_skip_ = handoff->bytesAlreadyConsumed();
  if (classifier_ == nullptr) {
    // Another filter already released it, or the listener never populated
    // it. Passthrough.
    passthrough_ = true;
    return Network::FilterStatus::Continue;
  }
  passthrough_ = false;

  config_->stats().correction_flows_claimed_.inc();
  config_->stats().correction_flows_active_.inc();

  correction_timer_ = read_cb_->connection().dispatcher().createTimer([this]() {
    if (passthrough_) return;   // finalize already ran on another path.
    ENVOY_LOG(debug, "qosmos_dpi_correction: correction timer fired "
                      "(bytes_fed={}, pdus_fed={})",
              bytes_fed_, pdus_fed_);
    config_->stats().correction_bound_hit_.inc();
    finalizeAndMaybeCorrect(/*final_state_reached=*/false);
  });
  correction_timer_->enableTimer(config_->correctionTimeout());

  ENVOY_LOG(debug,
            "qosmos_dpi_correction: claimed handoff (initial_verdict={}, "
            "cts_bytes_to_skip={})",
            initial_verdict_is_web_.has_value()
                ? (*initial_verdict_is_web_ ? "web" : "non-web")
                : "none",
            cts_bytes_to_skip_);
  return Network::FilterStatus::Continue;
}

Network::FilterStatus Filter::onData(Buffer::Instance& data, bool /*end_stream*/) {
  return feed(data, QMDPI_DIR_CTS);
}

Network::FilterStatus Filter::onWrite(Buffer::Instance& data, bool /*end_stream*/) {
  return feed(data, QMDPI_DIR_STC);
}

Network::FilterStatus Filter::feed(Buffer::Instance& data, int direction) {
  if (passthrough_ || classifier_ == nullptr) {
    return Network::FilterStatus::Continue;
  }

  // CTS-only skip: the listener filter peeked (MSG_PEEK) these bytes and
  // fed them to classifyPdu already. The network filter chain's first
  // read re-delivers them. Skip so we don't resubmit already-processed
  // bytes to the same stream-mode flow. See envoy-qosmos-cache.md Part B
  // "Peek semantics".
  const uint64_t total = data.length();
  uint64_t offset = 0;
  if (direction == QMDPI_DIR_CTS && cts_bytes_to_skip_ > 0) {
    if (total <= cts_bytes_to_skip_) {
      cts_bytes_to_skip_ -= static_cast<size_t>(total);
      return Network::FilterStatus::Continue;   // every byte was a dup.
    }
    offset = cts_bytes_to_skip_;
    cts_bytes_to_skip_ = 0;
  }
  if (total == offset) return Network::FilterStatus::Continue;

  // Linearize the tail of the buffer past the skip. Buffer::linearize()
  // returns a pointer into the buffer's contiguous storage; we PROMISE
  // not to drain — this filter is a passive observer, every byte must
  // still reach tcp_proxy / upstream unchanged.
  const size_t feed_len = static_cast<size_t>(total - offset);
  void* linear = data.linearize(static_cast<uint32_t>(total));
  const void* feed_bytes =
      static_cast<const void*>(static_cast<const uint8_t*>(linear) + offset);

  ClassifyResult cr =
      classifier_->classifyPdu(feed_bytes, static_cast<int>(feed_len),
                                direction, /*tenant_id=*/1);
  bytes_fed_ += feed_len;
  pdus_fed_++;
  config_->stats().correction_bytes_processed_.recordValue(feed_len);

  ENVOY_LOG(debug,
            "qosmos_dpi_correction: fed {} bytes dir={} pdus={} final_state={} "
            "intermediate='{}'",
            feed_len, direction == QMDPI_DIR_CTS ? "CTS" : "STC", pdus_fed_,
            cr.final_state, cr.intermediate_path);

  if (cr.final_state) {
    finalizeAndMaybeCorrect(/*final_state_reached=*/true);
    return Network::FilterStatus::Continue;
  }

  // Resource bounds: bytes and pdus tracked here, time by the dispatcher
  // timer set in onNewConnection.
  if (bytes_fed_ >= config_->maxCorrectionBytes() ||
      pdus_fed_ >= config_->maxCorrectionPdus()) {
    ENVOY_LOG(debug, "qosmos_dpi_correction: resource bound tripped "
                      "(bytes={}, pdus={})",
              bytes_fed_, pdus_fed_);
    config_->stats().correction_bound_hit_.inc();
    finalizeAndMaybeCorrect(/*final_state_reached=*/false);
  }
  return Network::FilterStatus::Continue;
}

void Filter::finalizeAndMaybeCorrect(bool final_state_reached) {
  if (classifier_ == nullptr) return;
  if (correction_timer_ != nullptr) {
    correction_timer_->disableTimer();
  }
  ClassifyResult final_cr = classifier_->finalize();
  classifier_.reset();
  config_->stats().correction_flows_active_.dec();
  config_->stats().correction_flow_destroyed_.inc();
  passthrough_ = true;

  // Only touch the cache when there's something authoritative to say:
  //   (a) final_state was reached — re-run the cascade to derive the
  //       corrected verdict from either final_cr.final_path (post-destroy
  //       path from finalize) or the intermediate path we already saw.
  //   (b) a resource bound tripped WITH a prior real verdict — we can
  //       repopulate the cache with what finalize's final_path says (best
  //       effort at bound-hit time).
  //   (c) a resource bound tripped WITHOUT a prior real verdict (silence-
  //       timeout hand-off) — DO NOTHING. The plan explicitly says a
  //       synthetic guess here would poison future connections; better to
  //       leave the destination uncached and give the next connection a
  //       fresh attempt.
  if (!final_state_reached && !initial_verdict_is_web_.has_value()) {
    ENVOY_LOG(debug, "qosmos_dpi_correction: bound-hit on silence-timeout "
                      "hand-off with no real classification — cache untouched");
    return;
  }
  if (engine_ == nullptr) return;

  const std::string& path =
      !final_cr.final_path.empty() ? final_cr.final_path
                                    : std::string{};   // no signal at all
  if (path.empty()) {
    // Nothing to derive a verdict from. Same treatment as (c): leave the
    // cache alone rather than lock in a guess.
    return;
  }
  const auto verdict = engine_->table().isWeb(path, final_cr.hooks);
  if (!verdict.has_value()) return;
  const bool new_is_web = *verdict;

  auto& cache = engine_->cacheForThisThread();
  if (initial_verdict_is_web_.has_value()) {
    if (new_is_web != *initial_verdict_is_web_) {
      cache.correct(key_, new_is_web);
      config_->stats().correction_flips_.inc();
      ENVOY_LOG(info,
                "qosmos_dpi_correction: verdict flip {} -> {} (path='{}')",
                *initial_verdict_is_web_ ? "web" : "non-web",
                new_is_web ? "web" : "non-web", path);
    }
    // No-op if the verdict agrees: the "4pkt" entry the listener filter
    // put is already correct.
  } else {
    // Silence-timeout hand-off. First-time populate. Distinct stat from
    // correction_flips_ because there was no prior verdict to disagree
    // with.
    cache.put(key_, new_is_web, "post_silence_final");
    config_->stats().correction_populated_from_silence_.inc();
    ENVOY_LOG(info,
              "qosmos_dpi_correction: post-silence populate verdict={} "
              "(path='{}')",
              new_is_web ? "web" : "non-web", path);
  }
}

}  // namespace QosmosDpiCorrection
}  // namespace NetworkFilters
}  // namespace Extensions
}  // namespace Envoy
