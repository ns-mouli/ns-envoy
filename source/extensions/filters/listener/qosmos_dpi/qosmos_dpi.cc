#include "source/extensions/filters/listener/qosmos_dpi/qosmos_dpi.h"

#include <arpa/inet.h>
#include <netinet/in.h>

#include <chrono>
#include <cstdint>

#include "envoy/network/address.h"

#include "source/common/protobuf/utility.h"
#include "source/common/tcp_proxy/tcp_proxy.h"
#include "source/extensions/common/qosmos_dpi/qosmos_flow_handoff.h"
#include "source/extensions/common/qosmos_dpi/verdict_cache.h"

#include "absl/strings/string_view.h"

extern "C" {
#include "qmdpi_const.h"  // QMDPI_DIR_CTS
}

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace QosmosDpi {

namespace {

// Stat-prefix scope: all stats land under "qosmos_dpi.<counter>" per the
// existing extension convention.
QosmosDpiStats generateStats(Stats::Scope& scope) {
  const std::string prefix = "qosmos_dpi.";
  return QosmosDpiStats{ALL_QOSMOS_DPI_STATS(POOL_COUNTER_PREFIX(scope, prefix),
                                              POOL_GAUGE_PREFIX(scope, prefix),
                                              POOL_HISTOGRAM_PREFIX(scope, prefix))};
}

// Read the 5-tuple from the accepted socket. remoteAddress() = client (CTS src),
// directLocalAddress() = original destination (CTS dst, populated by the
// kernel via SO_ORIGINAL_DST when iptables REDIRECT/TPROXY is in front of
// envoy — see Topology A/B docs).
struct FiveTuple {
  in_addr  v4_src{};
  in_addr  v4_dst{};
  in6_addr v6_src{};
  in6_addr v6_dst{};
  uint16_t src_port_nbo{};
  uint16_t dst_port_nbo{};
  bool is_v6{false};
};

// Build a VerdictCacheKey from the connection's destination address +
// requested server name (populated by tls_inspector when present). Returns
// a key with empty dst_ip iff there is no usable v4/v6 destination — the
// caller should treat that as "skip cache lookup and populate" for this
// connection.
Extensions::Common::QosmosDpi::VerdictCacheKey
computeCacheKey(const Network::ConnectionInfoProvider& info) {
  Extensions::Common::QosmosDpi::VerdictCacheKey key;
  const auto& local = info.directLocalAddress();
  if (local == nullptr || local->ip() == nullptr) return key;
  key.dst_ip = local->ip()->addressAsString();
  key.dst_port = local->ip()->port();
  const absl::string_view sni = info.requestedServerName();
  if (!sni.empty()) {
    key.kind = Extensions::Common::QosmosDpi::DiscriminatorKind::Sni;
    key.discriminator_value.assign(sni.data(), sni.size());
  } else {
    key.kind = Extensions::Common::QosmosDpi::DiscriminatorKind::Plain;
  }
  return key;
}

FiveTuple readFiveTuple(const Network::ConnectionInfoProvider& info) {
  FiveTuple t{};
  const auto& remote = info.remoteAddress();
  const auto& local = info.directLocalAddress();
  if (remote != nullptr && remote->ip() != nullptr && remote->ip()->ipv4() != nullptr &&
      local != nullptr && local->ip() != nullptr && local->ip()->ipv4() != nullptr) {
    t.v4_src.s_addr = htonl(remote->ip()->ipv4()->address());
    t.v4_dst.s_addr = htonl(local->ip()->ipv4()->address());
    t.src_port_nbo = htons(remote->ip()->port());
    t.dst_port_nbo = htons(local->ip()->port());
    return t;
  }
  t.is_v6 = true;
  if (remote != nullptr && remote->ip() != nullptr && remote->ip()->ipv6() != nullptr) {
    auto a = remote->ip()->ipv6()->address();
    auto* dst = reinterpret_cast<uint8_t*>(&t.v6_src);
    for (int i = 0; i < 16; ++i) dst[15 - i] = static_cast<uint8_t>(a >> (i * 8));
    t.src_port_nbo = htons(remote->ip()->port());
  }
  if (local != nullptr && local->ip() != nullptr && local->ip()->ipv6() != nullptr) {
    auto a = local->ip()->ipv6()->address();
    auto* dst = reinterpret_cast<uint8_t*>(&t.v6_dst);
    for (int i = 0; i < 16; ++i) dst[15 - i] = static_cast<uint8_t>(a >> (i * 8));
    t.dst_port_nbo = htons(local->ip()->port());
  }
  return t;
}

}  // namespace

// ──────────────── Config ────────────────

Config::Config(const ProtoConfig& proto, QosmosEngineSharedPtr engine,
               Stats::Scope& scope)
    : engine_(std::move(engine)),
      table_(nullptr),  // not owned — engine holds it; table() returns engine_->table().
      web_cluster_(proto.web_cluster()),
      non_web_cluster_(proto.non_web_cluster()),
      silence_timeout_(
          PROTOBUF_GET_MS_OR_DEFAULT(proto, silence_timeout, 200)),
      default_tenant_id_(proto.default_tenant_id() == 0 ? 1
                                                        : proto.default_tenant_id()),
      max_inspect_bytes_(proto.max_inspect_bytes() == 0 ? 1024
                                                        : proto.max_inspect_bytes()),
      close_on_engine_error_(proto.close_on_engine_error()),
      verdict_cache_correction_enabled_(proto.verdict_cache_correction_enabled()),
      stats_(generateStats(scope)) {
  // Production path: classifier factory delegates to the singleton engine.
  // Capture engine_ by raw pointer (the shared_ptr is held in this Config).
  QosmosEngine* engine_ptr = engine_.get();
  classifier_factory_ = [engine_ptr](bool is_v6, const void* src_ip,
                                      uint16_t src_port_nbo, const void* dst_ip,
                                      uint16_t dst_port_nbo) {
    return engine_ptr->makeClassifier(is_v6, src_ip, src_port_nbo, dst_ip,
                                       dst_port_nbo);
  };
}

const ProtocolTable& Config::table() const {
  // Production: engine owns the table (table_ is null). Tests: table_
  // was provided directly. We assert at least one is set — the
  // constructors enforce this.
  return table_ != nullptr ? *table_ : engine_->table();
}

Config::Config(const ProtoConfig& proto, ClassifierFactory factory,
               std::shared_ptr<ProtocolTable> table, Stats::Scope& scope)
    : engine_(nullptr),
      table_(std::move(table)),
      classifier_factory_(std::move(factory)),
      web_cluster_(proto.web_cluster()),
      non_web_cluster_(proto.non_web_cluster()),
      silence_timeout_(
          PROTOBUF_GET_MS_OR_DEFAULT(proto, silence_timeout, 200)),
      default_tenant_id_(proto.default_tenant_id() == 0 ? 1
                                                        : proto.default_tenant_id()),
      max_inspect_bytes_(proto.max_inspect_bytes() == 0 ? 1024
                                                        : proto.max_inspect_bytes()),
      close_on_engine_error_(proto.close_on_engine_error()),
      verdict_cache_correction_enabled_(proto.verdict_cache_correction_enabled()),
      stats_(generateStats(scope)) {}

// ──────────────── Filter ────────────────

Filter::Filter(ConfigSharedPtr config) : config_(std::move(config)) {}

Filter::~Filter() {
  recordClassifierDestruction();
}

void Filter::recordClassifierDestruction() {
  // Called from ~Filter. classifier_ may already be empty for two reasons:
  //   (a) we never accepted a flow (engine error in onAccept), or
  //   (b) the flow was handed off to the correction network filter via
  //       QosmosFlowHandoff (handed_off_ tracks this).
  // In case (b) the QosmosFlowHandoff (owned by FilterState) still counts
  // as an active flow — the correction filter is the one that will
  // eventually destroy it. We nonetheless decrement flows_active_ here
  // because that gauge tracks flows held by THIS listener filter; the
  // correction filter maintains its own correction_flows_active gauge.
  //
  // If classifier_ has a still-alive flow at destructor time, that means
  // classifyFirstPdu / classifyPdu / finalize never ran (early close, or
  // silence timeout without correction enabled). verdict_set_ is the
  // discriminator between silence-timeout (verdict was set) and early
  // close (verdict was not set).
  if (handed_off_) {
    config_->stats().flows_active_.dec();
    return;
  }
  if (classifier_ == nullptr) return;
  const bool was_alive = classifier_->flowAlive();
  classifier_.reset();   // RAII destroy — qmdpi_flow_destroy if needed
  if (!was_alive) return;
  if (verdict_set_) {
    config_->stats().flows_released_at_verdict_.inc();
  } else {
    config_->stats().flows_released_at_close_.inc();
  }
  config_->stats().flows_active_.dec();
}

Network::FilterStatus Filter::onAccept(Network::ListenerFilterCallbacks& cb) {
  cb_ = &cb;

  const auto& info = cb.socket().connectionInfoProvider();

  // Verdict-cache lookup, when enabled. On hit: set the verdict directly
  // from the cached entry and Continue without touching Qosmos. On miss:
  // stash the key on the filter so onData/onSilenceTimeout can populate
  // the cache and hand off the flow to the correction filter.
  //
  // When disabled, cache_key_ stays empty and every branch below (which
  // gates on !cache_key_.dst_ip.empty() && config_->verdictCacheCorrectionEnabled())
  // behaves exactly as today.
  if (config_->verdictCacheCorrectionEnabled() && config_->engine() != nullptr &&
      config_->engine()->verdictCacheEnabled()) {
    cache_key_ = computeCacheKey(info);
    if (!cache_key_.dst_ip.empty()) {
      auto& cache = config_->engine()->cacheForThisThread();
      auto hit = cache.lookup(cache_key_);
      if (hit.has_value()) {
        config_->stats().verdict_cache_hit_.inc();
        const auto& cluster = hit->verdict_is_web ? config_->webCluster()
                                                  : config_->nonWebCluster();
        setVerdict(cluster, hit->verdict_is_web);
        return Network::FilterStatus::Continue;
      }
      config_->stats().verdict_cache_miss_.inc();
    }
  }

  const FiveTuple t = readFiveTuple(info);
  classifier_ = config_->classifierFactory()(
      t.is_v6,
      t.is_v6 ? static_cast<const void*>(&t.v6_src)
              : static_cast<const void*>(&t.v4_src),
      t.src_port_nbo,
      t.is_v6 ? static_cast<const void*>(&t.v6_dst)
              : static_cast<const void*>(&t.v4_dst),
      t.dst_port_nbo);

  if (classifier_ == nullptr || !classifier_->flowAlive()) {
    // Engine couldn't allocate a flow (engine init failed earlier, worker
    // missing, or qmdpi_flow_create returned NULL). Fail-safe: route to
    // non-web (or refuse if so configured).
    config_->stats().engine_error_.inc();
    if (config_->closeOnEngineError()) {
      cb.socket().ioHandle().close();
      return Network::FilterStatus::StopIteration;
    }
    setVerdict(config_->nonWebCluster(), /*is_web=*/false);
    return Network::FilterStatus::Continue;
  }
  config_->stats().flows_active_.inc();

  // Arm silence timer for server-greets-first protocols.
  silence_timer_ = cb.dispatcher().createTimer([this]() { onSilenceTimeout(); });
  silence_timer_->enableTimer(config_->silenceTimeout());

  return Network::FilterStatus::StopIteration;
}

Network::FilterStatus Filter::onData(Network::ListenerFilterBuffer& buffer) {
  if (verdict_set_) {
    return Network::FilterStatus::Continue;
  }
  if (silence_timer_ != nullptr) {
    silence_timer_->disableTimer();
  }
  if (classifier_ == nullptr || !classifier_->flowAlive()) {
    // Should not happen — onAccept fail-safed already if classifier was
    // bad. Defensive.
    config_->stats().engine_error_.inc();
    setVerdict(config_->nonWebCluster(), /*is_web=*/false);
    return Network::FilterStatus::Continue;
  }

  const auto slice = buffer.rawSlice();
  config_->stats().bytes_processed_.recordValue(static_cast<uint64_t>(slice.len_));

  const bool correction_enabled =
      config_->verdictCacheCorrectionEnabled() && config_->engine() != nullptr &&
      config_->engine()->verdictCacheEnabled() && !cache_key_.dst_ip.empty();

  // When correction is enabled we call classifyPdu (no flow_destroy) so
  // the correction network filter can keep feeding the same flow past the
  // 4-packet boundary. Otherwise, preserve today's classifyFirstPdu shape
  // (single-shot, immediate flow_destroy).
  ClassifyResult cr;
  if (correction_enabled) {
    cr = classifier_->classifyPdu(
        slice.mem_, static_cast<int>(slice.len_), QMDPI_DIR_CTS,
        static_cast<int>(config_->defaultTenantId()));
    bytes_peeked_this_pdu_ = slice.len_;
  } else {
    cr = classifier_->classifyFirstPdu(
        slice.mem_, static_cast<int>(slice.len_), QMDPI_DIR_CTS,
        static_cast<int>(config_->defaultTenantId()));
  }
  classify_invoked_ = true;

  if (cr.engine_error) {
    config_->stats().engine_error_.inc();
    if (config_->closeOnEngineError() && cb_ != nullptr) {
      cb_->socket().ioHandle().close();
      return Network::FilterStatus::StopIteration;
    }
    // Fall through — we may still have a usable path despite the error.
  }

  // Run the cascade: intermediate first, then final on inconclusive.
  // The classifier extracts ssl:alpn from qmdpi_result for us so cascade
  // rules 0 (non-web ALPN beats everything) and 1 (transport-token +
  // HTTP ALPN ⇒ web) can fire.
  std::optional<bool> verdict;
  const auto alpn_it = cr.hooks.find("ssl:alpn");
  const std::string alpn_str =
      alpn_it != cr.hooks.end() ? alpn_it->second : std::string{};
  if (!cr.intermediate_path.empty()) {
    verdict = config_->table().isWeb(cr.intermediate_path, cr.hooks);
    ENVOY_LOG(debug, "qosmos_dpi: intermediate path='{}' alpn='{}' verdict={}",
              cr.intermediate_path, alpn_str,
              verdict.has_value() ? (*verdict ? "web" : "non-web") : "null");
  }
  if (!verdict.has_value() && !cr.final_path.empty()) {
    verdict = config_->table().isWeb(cr.final_path, cr.hooks);
    ENVOY_LOG(debug, "qosmos_dpi: final-after-destroy path='{}' alpn='{}' verdict={}",
              cr.final_path, alpn_str,
              verdict.has_value() ? (*verdict ? "web" : "non-web") : "null");
  }

  bool verdict_is_web = false;
  if (verdict.has_value() && *verdict) {
    verdict_is_web = true;
    setVerdict(config_->webCluster(), /*is_web=*/true);
  } else if (verdict.has_value() && !*verdict) {
    setVerdict(config_->nonWebCluster(), /*is_web=*/false);
  } else {
    config_->stats().inconclusive_forced_cfw_.inc();
    setVerdict(config_->nonWebCluster(), /*is_web=*/false);
  }

  // Cache-populate + optional hand-off. Only when correction is enabled
  // AND we reached a real verdict (not the inconclusive default) — caching
  // "we had no signal, defaulted to non-web" would poison the cache and
  // suppress every future connection's DPI on that destination.
  if (correction_enabled && verdict.has_value() && cb_ != nullptr) {
    auto& cache = config_->engine()->cacheForThisThread();
    if (!cache.put(cache_key_, verdict_is_web, "4pkt")) {
      config_->stats().verdict_cache_reject_full_.inc();
    }
    config_->stats().verdict_cache_size_.set(cache.size());

    if (cr.final_state) {
      // Rare: the engine already reached a final classification on this
      // very first PDU. Nothing to correct — finalize the flow here and
      // don't burden the correction filter with a hand-off.
      classifier_->finalize();
    } else {
      // Park the live classifier in FilterState for the correction filter
      // to pick up on the network-filter side. If no correction filter is
      // present in filter_chains, ~QosmosFlowHandoff will RAII-destroy the
      // flow at connection close — no leak.
      auto handoff = std::make_unique<
          Extensions::Common::QosmosDpi::QosmosFlowHandoff>(
          std::move(classifier_), cache_key_,
          absl::optional<bool>(verdict_is_web), config_->engine(),
          bytes_peeked_this_pdu_);
      cb_->filterState().setData(
          Extensions::Common::QosmosDpi::QosmosFlowHandoff::key(),
          std::move(handoff),
          StreamInfo::FilterState::StateType::Mutable,
          StreamInfo::FilterState::LifeSpan::Connection);
      config_->stats().handed_off_to_correction_.inc();
      handed_off_ = true;
      // classifier_ is now empty; recordClassifierDestruction() will
      // decrement flows_active_ via the handed_off_ branch.
    }
  }

  return Network::FilterStatus::Continue;
}

void Filter::onSilenceTimeout() {
  ENVOY_LOG(debug, "qosmos_dpi: silence timeout fired (server-greets-first?), "
                    "defaulting to {}", config_->nonWebCluster());
  config_->stats().silence_timeout_.inc();

  const bool correction_enabled =
      config_->verdictCacheCorrectionEnabled() && config_->engine() != nullptr &&
      config_->engine()->verdictCacheEnabled() && !cache_key_.dst_ip.empty() &&
      classifier_ != nullptr && classifier_->flowAlive() && cb_ != nullptr;

  // When correction is enabled, hand off the live-but-fed-nothing classifier
  // before setting the fallback verdict. The correction filter will see
  // initial_verdict_is_web == nullopt and treat any later real
  // classification as a first-time cache populate rather than a correction.
  // Do NOT cache the fallback here — a wrongly-guessed destination would
  // never get re-DPI'd on the next connection. See plan Part B (silence-
  // timeout hand-off) for the rationale.
  if (correction_enabled) {
    auto handoff = std::make_unique<
        Extensions::Common::QosmosDpi::QosmosFlowHandoff>(
        std::move(classifier_), cache_key_,
        absl::optional<bool>(),          // no prior verdict
        config_->engine(),
        0 /* no bytes peeked — classifyPdu never ran */);
    cb_->filterState().setData(
        Extensions::Common::QosmosDpi::QosmosFlowHandoff::key(),
        std::move(handoff),
        StreamInfo::FilterState::StateType::Mutable,
        StreamInfo::FilterState::LifeSpan::Connection);
    config_->stats().handed_off_to_correction_.inc();
    handed_off_ = true;
  }

  setVerdict(config_->nonWebCluster(), /*is_web=*/false);
  if (cb_ != nullptr) {
    cb_->continueFilterChain(true);
  }
}

void Filter::setVerdict(absl::string_view cluster_name, bool is_web) {
  if (verdict_set_) return;
  verdict_set_ = true;

  if (is_web) {
    config_->stats().web_classified_.inc();
  } else {
    config_->stats().non_web_classified_.inc();
  }

  if (cb_ == nullptr) return;
  cb_->filterState().setData(
      TcpProxy::PerConnectionCluster::key(),
      std::make_unique<TcpProxy::PerConnectionCluster>(cluster_name),
      StreamInfo::FilterState::StateType::Mutable,
      StreamInfo::FilterState::LifeSpan::Connection);
}

void Filter::onClose() {
  if (silence_timer_ != nullptr) {
    silence_timer_->disableTimer();
  }
  // ~classifier_ in ~Filter handles the actual qmdpi_flow_destroy via RAII.
  // Nothing else to do here; recordClassifierDestruction in ~Filter
  // updates the released-at-close stat.
}

}  // namespace QosmosDpi
}  // namespace ListenerFilters
}  // namespace Extensions
}  // namespace Envoy
