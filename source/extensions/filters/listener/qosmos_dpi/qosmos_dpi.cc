#include "source/extensions/filters/listener/qosmos_dpi/qosmos_dpi.h"

#include <arpa/inet.h>
#include <netinet/in.h>

#include <chrono>
#include <cstdint>
#include <cstring>

#include "envoy/network/address.h"

#include "source/common/protobuf/utility.h"
#include "source/common/tcp_proxy/tcp_proxy.h"
#include "source/extensions/common/qosmos_dpi/qosmos_flow_handoff.h"
#include "source/extensions/common/qosmos_dpi/verdict_cache.h"

#include "absl/strings/string_view.h"

extern "C" {
#include "qmdpi_const.h"  // QMDPI_DIR_CTS
}

// Forward declaration — VCL verdict push is defined after the namespace close
// to avoid vcl_io_handle.h namespace pollution (it introduces Envoy::Extensions::Network
// which would shadow Envoy::Network::FilterStatus inside the QosmosDpi namespace).
namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace QosmosDpi {
void qosmos_dpi_push_verdict(::Envoy::Network::IoHandle& io, bool is_web);
}
}
}
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
// localAddress() = original destination (CTS dst).
//
// MUST be localAddress(), NOT directLocalAddress(). Envoy's contract
// (envoy/network/socket.h:225) is that directLocalAddress() is "the listener
// address and it can not be modified by listener filters" — original_dst
// restores the SO_ORIGINAL_DST destination via restoreLocalAddress(), which
// writes local_address_ and deliberately leaves direct_local_address_ alone
// (source/common/network/socket_impl.h:44-47).
//
// Under TPROXY/IP_TRANSPARENT the socket is bound to the original destination,
// so the two agree and the distinction is invisible. Under iptables REDIRECT
// they do NOT: directLocalAddress() is the listener's own ip:port for every
// connection, which silently (a) collapsed the verdict-cache key to its
// discriminator alone and (b) fed Qosmos a constant flow signature, disabling
// its IP-classification and internal-cache mechanisms. See design.md §13.15.
//
// ORDERING REQUIREMENT: qosmos_dpi must be listed AFTER original_dst in
// listener_filters, so original_dst's onAccept has already restored the
// address by the time ours runs. topology-c-qosmos.yaml orders it correctly.
// If original_dst is absent, localAddress() == directLocalAddress() and this
// degrades to the previous behaviour rather than breaking.
struct FiveTuple {
  in_addr  v4_src{};
  in_addr  v4_dst{};
  in6_addr v6_src{};
  in6_addr v6_dst{};
  uint16_t src_port_nbo{};
  uint16_t dst_port_nbo{};
  bool is_v6{false};
};

// Extract {dst-ip, dst-port} from the accepted socket. Returns an empty
// .ip string on failure (no usable v4/v6 destination); callers should
// skip the cache path in that case. Result matches the header's
// Filter::DstAddrSnapshot shape so the two can be assigned directly.
DstAddrSnapshot readDstAddr(const Network::ConnectionInfoProvider& info) {
  const auto& local = info.localAddress();   // NOT directLocalAddress() — see above
  if (local == nullptr || local->ip() == nullptr) return {};
  return {local->ip()->addressAsString(),
          static_cast<uint16_t>(local->ip()->port())};
}

// Build a VerdictCacheKey from a destination + the discriminator hooks
// extracted by the classifier on the first PDU. Priority hierarchy:
//   1. ssl:server_name  (TLS SNI — primary)
//   2. ssl:ja4          (TLS w/o SNI — fingerprint fallback)
//   3. http:host        (cleartext HTTP Host / HTTP/2 :authority)
//   4. Plain            (no name hint — {dst-ip, dst-port} alone)
//
// Verified attribute-name mapping matches qosmos-cache-poc's hook labels
// (inspect_pcap4.sh + run_cache_poc.py). The classifier's extractor
// (RealQosmosClassifier::extractDiscriminatorHooks) is responsible for
// populating these into `hooks` if the corresponding Qosmos attribute
// registered successfully at engine init.
Extensions::Common::QosmosDpi::VerdictCacheKey
computeCacheKeyFromHooks(const DstAddrSnapshot& dst,
                          const Extensions::Common::QosmosDpi::Hooks& hooks) {
  Extensions::Common::QosmosDpi::VerdictCacheKey key;
  if (dst.ip.empty()) return key;
  key.dst_ip = dst.ip;
  key.dst_port = dst.port;
  auto assign = [&](Extensions::Common::QosmosDpi::DiscriminatorKind kind,
                    const std::string& value) {
    key.kind = kind;
    key.discriminator_value = value;
  };
  if (auto it = hooks.find("ssl:server_name");
      it != hooks.end() && !it->second.empty()) {
    assign(Extensions::Common::QosmosDpi::DiscriminatorKind::Sni, it->second);
    return key;
  }
  if (auto it = hooks.find("ssl:ja4");
      it != hooks.end() && !it->second.empty()) {
    assign(Extensions::Common::QosmosDpi::DiscriminatorKind::Ja4, it->second);
    return key;
  }
  if (auto it = hooks.find("http:host");
      it != hooks.end() && !it->second.empty()) {
    assign(Extensions::Common::QosmosDpi::DiscriminatorKind::HttpHost,
           it->second);
    return key;
  }
  key.kind = Extensions::Common::QosmosDpi::DiscriminatorKind::Plain;
  return key;
}

FiveTuple readFiveTuple(const Network::ConnectionInfoProvider& info) {
  FiveTuple t{};
  const auto& remote = info.remoteAddress();
  const auto& local = info.localAddress();   // NOT directLocalAddress() — see above
  if (remote != nullptr && remote->ip() != nullptr && remote->ip()->ipv4() != nullptr &&
      local != nullptr && local->ip() != nullptr && local->ip()->ipv4() != nullptr) {
    // NO htonl(): Ipv4::address() is documented (envoy/network/address.h:38)
    // as already being "the 32-bit IPv4 address in network byte order", and
    // the impl returns sockaddr_in::sin_addr.s_addr verbatim
    // (address_impl.h:180). Byte-swapping it here reversed every address we
    // handed Qosmos — 10.10.2.2 arrived as 2.2.10.10. Ports DO need htons:
    // Ip::port() returns host byte order. See design.md §13.15.
    t.v4_src.s_addr = remote->ip()->ipv4()->address();
    t.v4_dst.s_addr = local->ip()->ipv4()->address();
    t.src_port_nbo = htons(remote->ip()->port());
    t.dst_port_nbo = htons(local->ip()->port());
    return t;
  }
  t.is_v6 = true;
  // Same correction for v6. Ipv6Helper::address() memcpy's the 16 network-order
  // bytes of sin6_addr straight into the uint128 (address_impl.cc:239-244), so
  // its memory already holds them in wire order. The previous loop wrote byte i
  // to position 15-i, reversing them.
  if (remote != nullptr && remote->ip() != nullptr && remote->ip()->ipv6() != nullptr) {
    const absl::uint128 a = remote->ip()->ipv6()->address();
    static_assert(sizeof(a) == sizeof(t.v6_src), "uint128 must be 16 bytes");
    std::memcpy(&t.v6_src, &a, sizeof(t.v6_src));
    t.src_port_nbo = htons(remote->ip()->port());
  }
  if (local != nullptr && local->ip() != nullptr && local->ip()->ipv6() != nullptr) {
    const absl::uint128 a = local->ip()->ipv6()->address();
    std::memcpy(&t.v6_dst, &a, sizeof(t.v6_dst));
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
               std::shared_ptr<ProtocolTable> table, Stats::Scope& scope,
               Extensions::Common::QosmosDpi::VerdictCache* test_verdict_cache)
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
      test_verdict_cache_(test_verdict_cache),
      stats_(generateStats(scope)) {}

Extensions::Common::QosmosDpi::VerdictCache*
Config::verdictCacheForThisThread() const {
  if (!verdict_cache_correction_enabled_) return nullptr;
  if (test_verdict_cache_ != nullptr) return test_verdict_cache_;
  if (engine_ == nullptr || !engine_->verdictCacheEnabled()) return nullptr;
  return &engine_->cacheForThisThread();
}

// ──────────────── Filter ────────────────

Filter::Filter(ConfigSharedPtr config) : config_(std::move(config)) {}

Filter::~Filter() {
  // v1.32.4's Network::ListenerFilter has no onClose() hook, so the
  // silence-timer disarm that used to happen there now happens here too.
  if (silence_timer_ != nullptr) {
    silence_timer_->disableTimer();
  }
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

  // Snapshot the destination for later cache-key building. No cache
  // lookup yet — the key discriminator (SNI/JA4/Host) comes from
  // classifyPdu hooks, which run in onData. See
  // envoy-qosmos/docs/verdict-cache-onData-plan.md for rationale.
  //
  // dst_addr_ stays empty when the socket has no usable v4/v6 local
  // address (should never happen with original_dst upstream, but the
  // rest of the filter treats an empty dst_ip as "skip cache path").
  if (config_->verdictCacheForThisThread() != nullptr) {
    dst_addr_ = readDstAddr(info);
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

  // Skip inline_conn_info metadata prepended by prior service (socksproxy/ctap).
  // Format: [4-byte hdr: m_msgLen(u16) + m_version(u16=3)] [TLVs...] [EOD]
  // Without skipping, Qosmos sees the metadata instead of HTTP/TLS and
  // returns base.ip.tcp (can't identify the protocol).
  // We only skip for classification — the buffer and TCP seq/ack are NOT
  // modified. tcp_proxy still forwards the full stream; downstream services
  // (iproxy/appfwl) handle inline_conn_info in their own adapters.
  const uint8_t* data = static_cast<const uint8_t*>(slice.mem_);
  int data_len = static_cast<int>(slice.len_);
  if (data_len >= 4) {
    uint16_t meta_version = (data[2] << 8) | data[3];
    if (meta_version == 3) {  // INLINE_CONN_INFO_VERSION_3
      uint16_t meta_len = (data[0] << 8) | data[1];
      if (meta_len > 0 && meta_len < data_len) {
        ENVOY_LOG(debug, "qosmos_dpi: skipping inline_conn_info len={}", meta_len);
        data += meta_len;
        data_len -= meta_len;
      }
    }
  }

  auto* cache = config_->verdictCacheForThisThread();
  const bool cache_available = cache != nullptr && !dst_addr_.ip.empty();

  // When the cache is available we call classifyPdu (no flow_destroy) so
  // the correction network filter — or this filter's own short-circuit
  // branch below — controls the flow's fate. Otherwise, preserve today's
  // classifyFirstPdu shape (single-shot, immediate flow_destroy).
  ClassifyResult cr;
  if (cache_available) {
    cr = classifier_->classifyPdu(
        data, data_len, QMDPI_DIR_CTS,
        static_cast<int>(config_->defaultTenantId()));
    bytes_peeked_this_pdu_ = slice.len_;
  } else {
    cr = classifier_->classifyFirstPdu(
        data, data_len, QMDPI_DIR_CTS,
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
  // The classifier extracts ssl:alpn, ssl:server_name, ssl:ja4, http:host
  // from qmdpi_result for us — see RealQosmosClassifier::extractDiscriminatorHooks.
  // Cascade rules 0/1 consume alpn; the cache key builder below consumes
  // the other three.
  std::optional<bool> verdict;
  ProtocolTable::Rule initial_rule = ProtocolTable::Rule::kNone;
  const auto alpn_it = cr.hooks.find("ssl:alpn");
  const std::string alpn_str =
      alpn_it != cr.hooks.end() ? alpn_it->second : std::string{};
  if (!cr.intermediate_path.empty()) {
    verdict = config_->table().isWebWithRule(cr.intermediate_path, cr.hooks, initial_rule);
    ENVOY_LOG(debug, "qosmos_dpi: intermediate path='{}' alpn='{}' verdict={}",
              cr.intermediate_path, alpn_str,
              verdict.has_value() ? (*verdict ? "web" : "non-web") : "null");
  }
  if (!verdict.has_value() && !cr.final_path.empty()) {
    verdict = config_->table().isWebWithRule(cr.final_path, cr.hooks, initial_rule);
    ENVOY_LOG(debug, "qosmos_dpi: final-after-destroy path='{}' alpn='{}' verdict={}",
              cr.final_path, alpn_str,
              verdict.has_value() ? (*verdict ? "web" : "non-web") : "null");
  }

  // ── FQDN-first refinement (SNI for TLS, Host for cleartext HTTP) ──
  //
  // On the first PDU Qosmos often hasn't committed the app into the path yet:
  // a TLS ClientHello yields the coarse provisional `base.ip.tcp.ssl` scored on
  // ALPN alone (rule 0/1 → web-biased), and cleartext HTTP can yield a generic
  // `base.ip.tcp.http`. But the discriminator the engine DID extract as a hook
  // — SNI (`ssl:server_name`) for TLS, Host (`http:host`) for HTTP — already
  // names the destination. Resolve the app from it via qmdpi_worker_process_fqdn
  // (a standalone domain classification that feeds no PDU and does NOT destroy
  // the flow) and route on that more-resolved verdict, while still handing the
  // live flow to correction below for bidirectional confirmation.
  //
  // Applied only when the cascade did NOT already pin an app (rule !=
  // kRule2CsvLookup): an app-pinned intermediate path is at least as specific
  // as the domain, so overriding it could only lose information.
  //
  // NOTE the guard deliberately does NOT exclude kRule2CsvLookupTransport.
  // Transport tokens (`ssl`, `tcp`, `quic`, `unknown`, …) have CSV rows too,
  // so rule 2 fires for a bare `base.ip.tcp.ssl` — but that is the cascade
  // reporting "I only got as far as TLS", not an app pin, and suppressing the
  // refine there threw away an SNI the engine had already handed us. That was
  // the root cause of the residual non-web→web flips (52 of 60 in the
  // 2026-07-30 full-corpus run): a no-ALPN ClientHello scores
  // `base.ip.tcp.ssl` → rule 2 on the `ssl` row → non-web, refine skipped,
  // and correction later pins the real app → flip. Hosting tokens are
  // unaffected: rule 2 is skipped for them entirely, so they already reach
  // this refine via rule 3/4. This keeps the
  // refinement strictly accuracy-improving (see docs/real-envoy-corpus-vs-poc.md
  // §"Remediation validated": 100% of resolvable-SNI flips resolve to the
  // corrected verdict from the discriminator alone). No config gate — the rule
  // guard already scopes it to the coarse-verdict case. `final_state` cases and
  // flows with no SNI/Host (ECH, old ClientHellos) fall back to the cascade.
  if (!cr.final_state && classifier_ != nullptr &&
      initial_rule != ProtocolTable::Rule::kRule2CsvLookup) {
    absl::string_view fqdn_src;
    std::string fqdn;
    if (const auto it = cr.hooks.find("ssl:server_name");
        it != cr.hooks.end() && !it->second.empty()) {
      fqdn = it->second;
      fqdn_src = "sni";
    } else if (const auto it2 = cr.hooks.find("http:host");
               it2 != cr.hooks.end() && !it2->second.empty()) {
      fqdn = it2->second;
      fqdn_src = "host";
    }
    if (!fqdn.empty()) {
      const std::string fqdn_path = classifier_->classifyFqdn(fqdn);
      if (!fqdn_path.empty()) {
        ProtocolTable::Rule fqdn_rule = ProtocolTable::Rule::kNone;
        if (auto fqdn_verdict =
                config_->table().isWebWithRule(fqdn_path, cr.hooks, fqdn_rule);
            fqdn_verdict.has_value()) {
          ENVOY_LOG(debug, "qosmos_dpi: fqdn-refine src={} fqdn='{}' path='{}' "
                            "verdict={} (was intermediate verdict={})",
                    fqdn_src, fqdn, fqdn_path,
                    *fqdn_verdict ? "web" : "non-web",
                    verdict.has_value() ? (*verdict ? "web" : "non-web") : "null");
          verdict = fqdn_verdict;
        }
      }
    }
  }

  // Build the cache key now that we have hooks. This key is what the
  // correction filter will later use to populate `final_seen=true`, and
  // it's what we look up right now to see whether some earlier flow to
  // the same discriminator has already been promoted to final.
  if (cache_available) {
    cache_key_ = computeCacheKeyFromHooks(dst_addr_, cr.hooks);
    // Log the discriminator KIND. Sni/HttpHost name the destination, so a
    // shared key there is mostly benign; Ja4 fingerprints the CLIENT's TLS
    // stack and Plain has an empty discriminator by construction, so those
    // two are the kinds that can conflate unrelated destinations if the
    // dst component is ever weak (see §13.15). Without this the corpus runs
    // can only infer the blast radius from an owners shortfall.
    ENVOY_LOG(debug, "qosmos_dpi: cache-key kind={} dst={}:{} discriminator='{}'",
              discriminatorKindName(cache_key_.kind), cache_key_.dst_ip,
              cache_key_.dst_port, cache_key_.discriminator_value);
  }

  // ── Cache short-circuit: hit with final_seen=true ──
  //
  // A prior flow to the same {dst-ip, dst-port, SNI/JA4/Host} has already
  // gone through correction and reached a terminal verdict. Use it,
  // destroy the flow here, skip the hand-off to correction. If this
  // flow's own initial cascade produced a different verdict, count it as
  // a disagreement (per plan §7 option b — trust cache, log for
  // observability, never override).
  if (cache_available) {
    if (auto hit = cache->lookup(cache_key_);
        hit.has_value() && hit->final_seen) {
      config_->stats().verdict_cache_hit_.inc();
      if (verdict.has_value() && *verdict != hit->verdict_is_web) {
        config_->stats().verdict_cache_disagreement_.inc();
        ENVOY_LOG(debug, "qosmos_dpi: verdict_cache_disagreement "
                          "(cached={} initial={} path='{}' alpn='{}')",
                  hit->verdict_is_web ? "web" : "non-web",
                  *verdict ? "web" : "non-web",
                  cr.intermediate_path, alpn_str);
      }
      // Destroy the qmdpi_flow — no correction extension needed for this
      // flow, we already have the terminal verdict.
      classifier_->finalize();
      const auto& cluster = hit->verdict_is_web ? config_->webCluster()
                                                : config_->nonWebCluster();
      setVerdict(cluster, hit->verdict_is_web);
      return Network::FilterStatus::Continue;
    }
  }

  // ── Fall-through: not a terminal hit ──
  // Either the cache was disabled, no entry existed (miss), or the entry
  // was still initial (final_seen=false — some other flow is currently
  // running its correction extension for this key). All three cases route
  // by our own initial verdict below and, when cache is available,
  // populate/hand off so THIS flow contributes to (or races with) the
  // correction observation.
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

  // Cache-populate + optional hand-off. Only when the cache is available
  // AND we reached a real verdict (not the inconclusive default) — caching
  // "we had no signal, defaulted to non-web" would poison the cache and
  // suppress every future connection's DPI on that destination.
  if (cache_available && verdict.has_value() && cb_ != nullptr) {
    // Stat the outcome. A hit with final_seen=false is a "reinforcement"
    // — folded into handed_off_to_correction so we keep one counter (per
    // plan §Q2). The miss/hit distinction is bumped for observability but
    // both paths hand off.
    const auto pre_hit = cache->lookup(cache_key_);
    if (pre_hit.has_value()) {
      // Hit with final_seen=false (final_seen=true was handled above).
      config_->stats().verdict_cache_hit_.inc();
    } else {
      config_->stats().verdict_cache_miss_.inc();
    }
    if (!cache->put(cache_key_, verdict_is_web, "4pkt")) {
      config_->stats().verdict_cache_reject_full_.inc();
    }
    config_->stats().verdict_cache_size_.set(cache->size());

    if (cr.final_state) {
      // Rare: the engine already reached a final classification on this
      // very first PDU. Nothing to correct — finalize the flow here and
      // don't burden the correction filter with a hand-off. Also promote
      // the cache entry to final immediately.
      cache->put(cache_key_, verdict_is_web, "final");
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
          Extensions::Common::QosmosDpi::QosmosFlowHandoff::filterStateKey(),
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
      config_->verdictCacheForThisThread() != nullptr &&
      !dst_addr_.ip.empty() && classifier_ != nullptr &&
      classifier_->flowAlive() && cb_ != nullptr;

  // On the silence-timeout path we have no hooks (classifyPdu never ran),
  // so the cache key is Plain — {dst-ip, dst-port} alone. The correction
  // filter, if it later reaches a real classification from STC bytes,
  // populates the cache under this Plain key. Not perfect for shared
  // {IP,port} destinations, but the alternative (skip the cache) would
  // mean every future connection to the same IP:port re-arms silence
  // and never gets the correction signal.
  if (correction_enabled) {
    cache_key_ =
        computeCacheKeyFromHooks(dst_addr_,
                                  Extensions::Common::QosmosDpi::Hooks{});
  }

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
        Extensions::Common::QosmosDpi::QosmosFlowHandoff::filterStateKey(),
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

  // Push verdict to VPP via VCL ctrl_mq so ns-envoy-adapter can set
  // fctx->is_web for iproxy skip/keep routing in the NSH service chain.
  if (cb_ != nullptr) {
    qosmos_dpi_push_verdict(cb_->socket().ioHandle(), is_web);
  }

  if (cb_ == nullptr) return;
  cb_->filterState().setData(
      TcpProxy::PerConnectionCluster::key(),
      std::make_unique<TcpProxy::PerConnectionCluster>(cluster_name),
      StreamInfo::FilterState::StateType::Mutable,
      StreamInfo::FilterState::LifeSpan::Connection);
}

}  // namespace QosmosDpi
}  // namespace ListenerFilters
}  // namespace Extensions
}  // namespace Envoy

// VCL verdict push implementation — outside all namespaces to avoid
// vcl_io_handle.h namespace pollution. The VCL header introduces
// Envoy::Extensions::Network which would shadow Envoy::Network inside
// the QosmosDpi namespace (causing Network::FilterStatus lookup failures).
#include "contrib/vcl/source/vcl_io_handle.h"

extern "C" {
// vppcom_set_verdict is added by Netskope VPP patches — not in upstream
// vppcom.h. Declare it here since the prebuilt /opt/vpp23 header may not
// have it.
extern int vppcom_set_verdict(int fd, uint8_t is_web);
}

void Envoy::Extensions::ListenerFilters::QosmosDpi::qosmos_dpi_push_verdict(
    ::Envoy::Network::IoHandle& io, bool is_web) {
  auto* vcl_io = dynamic_cast<Envoy::Extensions::Network::Vcl::VclIoHandle*>(&io);
  if (vcl_io) {
    vppcom_set_verdict(vcl_io->sh(), is_web ? 1 : 0);
  }
}
