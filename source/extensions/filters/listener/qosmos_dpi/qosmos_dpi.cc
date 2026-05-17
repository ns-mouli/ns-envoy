#include "source/extensions/filters/listener/qosmos_dpi/qosmos_dpi.h"

#include <arpa/inet.h>
#include <netinet/in.h>

#include <chrono>
#include <cstdint>

#include "envoy/network/address.h"

#include "source/common/protobuf/utility.h"
#include "source/common/tcp_proxy/tcp_proxy.h"

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
      stats_(generateStats(scope)) {}

// ──────────────── Filter ────────────────

Filter::Filter(ConfigSharedPtr config) : config_(std::move(config)) {}

Filter::~Filter() {
  recordClassifierDestruction();
}

void Filter::recordClassifierDestruction() {
  // Called from ~Filter. classifier_ may already be empty (if we never
  // accepted a flow due to engine error in onAccept). If it has a flow
  // still alive, that means classifyFirstPdu never ran — either silence
  // timeout fired (already counted via flows_released_at_verdict in
  // onSilenceTimeout) or the connection closed early (count as
  // flows_released_at_close).
  //
  // We can't tell the two apart from inside the destructor; the
  // verdict_set_ flag is the discriminator. silence-timeout calls
  // setVerdict so verdict_set_ is true; early-close hasn't.
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

  const FiveTuple t = readFiveTuple(cb.socket().connectionInfoProvider());
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

  ClassifyResult cr = classifier_->classifyFirstPdu(
      slice.mem_, static_cast<int>(slice.len_), QMDPI_DIR_CTS,
      static_cast<int>(config_->defaultTenantId()));
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
  // Without ssl:alpn hooks, rules 0/1 don't fire (TODO: wire hook
  // extraction in a follow-up; cascade falls back to rule 2/3/4).
  Hooks empty_hooks;
  std::optional<bool> verdict;
  if (!cr.intermediate_path.empty()) {
    verdict = config_->table().isWeb(cr.intermediate_path, empty_hooks);
    ENVOY_LOG(debug, "qosmos_dpi: intermediate path='{}' verdict={}",
              cr.intermediate_path,
              verdict.has_value() ? (*verdict ? "web" : "non-web") : "null");
  }
  if (!verdict.has_value() && !cr.final_path.empty()) {
    verdict = config_->table().isWeb(cr.final_path, empty_hooks);
    ENVOY_LOG(debug, "qosmos_dpi: final-after-destroy path='{}' verdict={}",
              cr.final_path,
              verdict.has_value() ? (*verdict ? "web" : "non-web") : "null");
  }

  if (verdict.has_value() && *verdict) {
    setVerdict(config_->webCluster(), /*is_web=*/true);
  } else if (verdict.has_value() && !*verdict) {
    setVerdict(config_->nonWebCluster(), /*is_web=*/false);
  } else {
    config_->stats().inconclusive_forced_cfw_.inc();
    setVerdict(config_->nonWebCluster(), /*is_web=*/false);
  }
  return Network::FilterStatus::Continue;
}

void Filter::onSilenceTimeout() {
  ENVOY_LOG(debug, "qosmos_dpi: silence timeout fired (server-greets-first?), "
                    "defaulting to {}", config_->nonWebCluster());
  config_->stats().silence_timeout_.inc();
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
