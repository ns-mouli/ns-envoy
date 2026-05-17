#include "source/extensions/filters/listener/qosmos_dpi/qosmos_dpi.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/time.h>

#include <chrono>
#include <cstdint>
#include <cstring>

#include "envoy/network/address.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/common/protobuf/utility.h"
#include "source/common/tcp_proxy/tcp_proxy.h"

#include "absl/strings/string_view.h"

extern "C" {
#include "dpi/protodef.h"  // Q_PROTO_IP, Q_PROTO_IP6, Q_PROTO_TCP
}

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace QosmosDpi {

namespace {

// Stat-prefix scope: all stats land under "qosmos_dpi.<counter>" per the
// existing extension convention (tls_inspector.tls_inspector.* etc.).
QosmosDpiStats generateStats(Stats::Scope& scope) {
  const std::string prefix = "qosmos_dpi.";
  return QosmosDpiStats{ALL_QOSMOS_DPI_STATS(POOL_COUNTER_PREFIX(scope, prefix),
                                              POOL_GAUGE_PREFIX(scope, prefix),
                                              POOL_HISTOGRAM_PREFIX(scope, prefix))};
}

// Render the qmdpi_path object as a dotted string. Uses
// qmdpi_data_path_to_buffer (mirrors dataplane/libs/qosmos_dpi/src/QosmosDpi.cpp:372).
// Returns empty string if path is null or rendering fails.
std::string pathToString(qmdpi_bundle* bundle, const qmdpi_path* path) {
  if (path == nullptr || bundle == nullptr) return {};
  char buffer[512];
  int rc = qmdpi_data_path_to_buffer(bundle, buffer, sizeof(buffer), path);
  if (rc != 0) return {};
  return std::string(buffer);
}

// Read the 5-tuple from the accepted socket. Stream-mode Qosmos doesn't
// strictly need accurate src/dst (the engine uses them as a flow key only
// — classification is purely byte-driven), but we feed real values so the
// engine's per-flow logging matches reality.
struct FiveTuple {
  int l3proto;        // Q_PROTO_IP or Q_PROTO_IP6
  int l4proto;        // Q_PROTO_TCP
  in_addr  v4_src{};  // network byte order
  in_addr  v4_dst{};
  in6_addr v6_src{};
  in6_addr v6_dst{};
  uint16_t src_port{};  // network byte order
  uint16_t dst_port{};
  bool is_v6{false};
};

// Extract a 5-tuple from the Envoy socket. remoteAddress() = client (CTS src),
// directLocalAddress() = original destination (CTS dst, populated by the
// kernel via SO_ORIGINAL_DST when iptables REDIRECT/TPROXY is in front of
// envoy — see Topology A/B docs).
FiveTuple readFiveTuple(const Network::ConnectionInfoProvider& info) {
  FiveTuple t{};
  const auto& remote = info.remoteAddress();
  const auto& local = info.directLocalAddress();
  if (remote != nullptr && remote->ip() != nullptr && remote->ip()->ipv4() != nullptr &&
      local != nullptr && local->ip() != nullptr && local->ip()->ipv4() != nullptr) {
    t.l3proto = Q_PROTO_IP;
    t.l4proto = Q_PROTO_TCP;
    t.v4_src.s_addr = htonl(remote->ip()->ipv4()->address());
    t.v4_dst.s_addr = htonl(local->ip()->ipv4()->address());
    t.src_port = htons(remote->ip()->port());
    t.dst_port = htons(local->ip()->port());
    return t;
  }
  // Fall through: IPv6 (or partial info — caller still tries flow_create
  // and will log if it fails).
  t.l3proto = Q_PROTO_IP6;
  t.l4proto = Q_PROTO_TCP;
  if (remote != nullptr && remote->ip() != nullptr && remote->ip()->ipv6() != nullptr) {
    auto a = remote->ip()->ipv6()->address();  // absl::uint128
    auto* dst = reinterpret_cast<uint8_t*>(&t.v6_src);
    for (int i = 0; i < 16; ++i) {
      dst[15 - i] = static_cast<uint8_t>(a >> (i * 8));
    }
    t.src_port = htons(remote->ip()->port());
  }
  if (local != nullptr && local->ip() != nullptr && local->ip()->ipv6() != nullptr) {
    auto a = local->ip()->ipv6()->address();
    auto* dst = reinterpret_cast<uint8_t*>(&t.v6_dst);
    for (int i = 0; i < 16; ++i) {
      dst[15 - i] = static_cast<uint8_t>(a >> (i * 8));
    }
    t.dst_port = htons(local->ip()->port());
  }
  t.is_v6 = true;
  return t;
}

}  // namespace

// ──────────────── Config ────────────────

Config::Config(const ProtoConfig& proto, QosmosEngineSharedPtr engine,
               Stats::Scope& scope)
    : engine_(std::move(engine)),
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
  // Defensive: should already be destroyed by onData / onSilenceTimeout /
  // onClose. If not, we leak engine state if we don't destroy here. The
  // gauge accounting catches this bug at runtime.
  if (flow_ != nullptr) {
    releaseFlow(/*from_verdict_path=*/false);
  }
}

Network::FilterStatus Filter::onAccept(Network::ListenerFilterCallbacks& cb) {
  cb_ = &cb;

  auto& worker_obj = config_->engine().workerForThisThread();
  if (!worker_obj.isValid()) {
    // Engine startup must have been broken — can't create a flow without
    // a worker. Fail-safe to non-web (or refuse if so configured).
    config_->stats().engine_error_.inc();
    if (config_->closeOnEngineError()) {
      cb.socket().ioHandle().close();
      return Network::FilterStatus::StopIteration;
    }
    setVerdict(config_->nonWebCluster(), /*is_web=*/false);
    return Network::FilterStatus::Continue;
  }

  const FiveTuple t = readFiveTuple(cb.socket().connectionInfoProvider());
  if (t.is_v6) {
    flow_ = qmdpi_flow_create(worker_obj.raw(), t.l3proto, t.l4proto,
                              static_cast<const void*>(&t.v6_src),
                              static_cast<const void*>(&t.src_port),
                              static_cast<const void*>(&t.v6_dst),
                              static_cast<const void*>(&t.dst_port));
  } else {
    flow_ = qmdpi_flow_create(worker_obj.raw(), t.l3proto, t.l4proto,
                              static_cast<const void*>(&t.v4_src),
                              static_cast<const void*>(&t.src_port),
                              static_cast<const void*>(&t.v4_dst),
                              static_cast<const void*>(&t.dst_port));
  }
  if (flow_ == nullptr) {
    ENVOY_LOG(warn, "qosmos_dpi: qmdpi_flow_create returned NULL; defaulting to non-web");
    config_->stats().engine_error_.inc();
    if (config_->closeOnEngineError()) {
      cb.socket().ioHandle().close();
      return Network::FilterStatus::StopIteration;
    }
    setVerdict(config_->nonWebCluster(), /*is_web=*/false);
    return Network::FilterStatus::Continue;
  }
  config_->stats().flows_active_.inc();

  // Arm the silence timer. For server-greets-first protocols (FTP, SMTP)
  // the client may stay silent until the server's banner; we default to
  // CFW after silence_timeout if no client bytes arrive. The phase-1
  // mandate is "verdict on first client bytes" — silence is a verdict
  // too (= non-web), and we cannot wait forever.
  silence_timer_ = cb.dispatcher().createTimer([this]() { onSilenceTimeout(); });
  silence_timer_->enableTimer(config_->silenceTimeout());

  return Network::FilterStatus::StopIteration;
}

Network::FilterStatus Filter::onData(Network::ListenerFilterBuffer& buffer) {
  if (verdict_set_) {
    // Should not happen — once we Continue, Envoy stops calling us. Defensive
    // no-op so we never re-enter classifyOnFirstPdu after the flow is dead.
    return Network::FilterStatus::Continue;
  }

  if (silence_timer_ != nullptr) {
    silence_timer_->disableTimer();
  }

  const auto slice = buffer.rawSlice();
  bytes_inspected_ = slice.len_;
  config_->stats().bytes_processed_.recordValue(static_cast<uint64_t>(bytes_inspected_));

  return classifyOnFirstPdu(slice);
}

Network::FilterStatus Filter::classifyOnFirstPdu(
    const Buffer::ConstRawSlice& slice) {
  auto& worker_obj = config_->engine().workerForThisThread();
  qmdpi_worker* worker = worker_obj.raw();
  if (worker == nullptr || flow_ == nullptr) {
    config_->stats().engine_error_.inc();
    if (config_->closeOnEngineError() && cb_ != nullptr) {
      cb_->socket().ioHandle().close();
      return Network::FilterStatus::StopIteration;
    }
    setVerdict(config_->nonWebCluster(), /*is_web=*/false);
    return Network::FilterStatus::Continue;
  }

  // Stream-mode PDU set: first_header=0 (no L3/L4 parsing — we only feed
  // payload bytes), QMDPI_DIR_CTS (client→server is the only direction
  // the listener filter ever sees). Tenant id from proto config.
  struct timeval tv;
  gettimeofday(&tv, nullptr);
  int rc = qmdpi_worker_pdu_set(
      worker, slice.mem_, static_cast<int>(slice.len_), &tv,
      /*first_header=*/0, QMDPI_DIR_CTS,
      static_cast<int>(config_->defaultTenantId()));
  if (rc != 0) {
    ENVOY_LOG(debug, "qosmos_dpi: qmdpi_worker_pdu_set returned {}", rc);
    // Don't bail here — process can still produce a useful intermediate;
    // and even if it can't, the unconditional flow_destroy below extracts
    // whatever the engine has. Increment engine_error so the failure is
    // observable.
    config_->stats().engine_error_.inc();
  }

  qmdpi_result* intermediate = nullptr;
  rc = qmdpi_worker_process(worker, /*flow=*/nullptr, &intermediate);
  if (rc != 0) {
    ENVOY_LOG(debug, "qosmos_dpi: qmdpi_worker_process returned {}", rc);
    config_->stats().engine_error_.inc();
  }

  // Cascade against the intermediate path FIRST. Hooks-extraction (ssl:alpn
  // etc.) is a follow-up — see qosmos-dpi-integration-plan.md §11. Without
  // hooks, rules 0 and 1 don't fire; flows fall through to rule 2 (CSV) or
  // rule 4 (default non-web). Conservative behaviour until ALPN extraction
  // lands.
  Hooks empty_hooks;  // TODO: populate ssl:alpn from qmdpi_result_attr_getnext.
  std::optional<bool> verdict;

  qmdpi_bundle* bundle = config_->engine().rawBundle();
  if (intermediate != nullptr) {
    qmdpi_path* path = qmdpi_result_path_get(intermediate);
    const std::string path_str = pathToString(bundle, path);
    if (!path_str.empty()) {
      verdict = config_->engine().table().isWeb(path_str, empty_hooks);
      ENVOY_LOG(debug, "qosmos_dpi: intermediate path='{}' verdict={}",
                path_str, verdict.has_value()
                              ? (*verdict ? "web" : "non-web") : "null");
    }
  }

  // ALWAYS qmdpi_flow_destroy() — see plan §1 & §7.4. Whether the verdict
  // is conclusive or not, the per-flow engine state is no longer needed
  // (we will not feed more bytes). Destroy returns the engine's final
  // best-guess result; if the intermediate cascade was inconclusive, we
  // re-run the cascade against this final result.
  qmdpi_result* final_result = nullptr;
  releaseFlow(/*from_verdict_path=*/true, &final_result);

  if (!verdict.has_value() && final_result != nullptr) {
    qmdpi_path* fpath = qmdpi_result_path_get(final_result);
    const std::string final_str = pathToString(bundle, fpath);
    if (!final_str.empty()) {
      verdict = config_->engine().table().isWeb(final_str, empty_hooks);
      ENVOY_LOG(debug, "qosmos_dpi: post-destroy path='{}' verdict={}",
                final_str, verdict.has_value()
                               ? (*verdict ? "web" : "non-web") : "null");
    }
  }

  // Apply the verdict. Default is non-web (CFW). Anything that doesn't
  // POSITIVELY classify as web stays non-web.
  if (verdict.has_value() && *verdict) {
    setVerdict(config_->webCluster(), /*is_web=*/true);
  } else if (verdict.has_value() && !*verdict) {
    setVerdict(config_->nonWebCluster(), /*is_web=*/false);
  } else {
    // Both intermediate and post-destroy paths were null/inconclusive.
    config_->stats().inconclusive_forced_cfw_.inc();
    setVerdict(config_->nonWebCluster(), /*is_web=*/false);
  }
  return Network::FilterStatus::Continue;
}

void Filter::onSilenceTimeout() {
  ENVOY_LOG(debug, "qosmos_dpi: silence timeout fired (server-greets-first?), defaulting to {}",
            config_->nonWebCluster());
  config_->stats().silence_timeout_.inc();
  // Destroy the flow even though we never fed any bytes. The engine still
  // allocated per-flow state in qmdpi_flow_create(); this releases it.
  if (flow_ != nullptr) {
    releaseFlow(/*from_verdict_path=*/true);
  }
  setVerdict(config_->nonWebCluster(), /*is_web=*/false);
  if (cb_ != nullptr) {
    cb_->continueFilterChain(true);
  }
}

void Filter::setVerdict(absl::string_view cluster_name, bool is_web) {
  if (verdict_set_) return;  // Idempotent; defensive against double-fire.
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

void Filter::releaseFlow(bool from_verdict_path, qmdpi_result** out_result) {
  if (flow_ == nullptr) return;
  auto& worker_obj = config_->engine().workerForThisThread();
  qmdpi_worker* worker = worker_obj.raw();
  if (worker == nullptr) {
    // Worker is gone (engine teardown raced) — leak the flow rather than
    // call into a dead engine. Increment engine_error for visibility.
    config_->stats().engine_error_.inc();
    flow_ = nullptr;
    config_->stats().flows_active_.dec();
    return;
  }
  qmdpi_result* sink = nullptr;
  qmdpi_result** target = (out_result != nullptr) ? out_result : &sink;
  int rc = qmdpi_flow_destroy(worker, flow_, target);
  if (rc != 0) {
    // Per qmdpi.h: "QMDPI_PROCESS_MORE if one or more TCP Segments of the
    // flow are still present in the reassembly queue". Phase 1 doesn't feed
    // more bytes anyway, so QMDPI_PROCESS_MORE is harmless — log at debug.
    ENVOY_LOG(debug, "qosmos_dpi: qmdpi_flow_destroy returned {}", rc);
  }
  flow_ = nullptr;
  config_->stats().flows_active_.dec();
  if (from_verdict_path) {
    config_->stats().flows_released_at_verdict_.inc();
  } else {
    config_->stats().flows_released_at_close_.inc();
  }
}

void Filter::onClose() {
  // Belt-and-braces: if the connection closed before any verdict path ran
  // (e.g. client SYN-then-RST), destroy the flow now. In the happy path
  // this is a no-op because flow_ was already nulled by classifyOnFirstPdu
  // or onSilenceTimeout.
  if (silence_timer_ != nullptr) {
    silence_timer_->disableTimer();
  }
  if (flow_ != nullptr) {
    releaseFlow(/*from_verdict_path=*/false);
  }
}

}  // namespace QosmosDpi
}  // namespace ListenerFilters
}  // namespace Extensions
}  // namespace Envoy
