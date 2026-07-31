#include <arpa/inet.h>

#include <fstream>
#include <memory>
#include <string>

#include "envoy/extensions/filters/listener/qosmos_dpi/v3/qosmos_dpi.pb.h"
#include "envoy/network/filter.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/common/network/utility.h"
#include "source/common/stream_info/filter_state_impl.h"
#include "source/common/tcp_proxy/tcp_proxy.h"
#include "source/extensions/filters/listener/qosmos_dpi/qosmos_dpi.h"
#include "source/extensions/common/qosmos_dpi/qosmos_engine.h"
#include "source/extensions/common/qosmos_dpi/qosmos_flow_handoff.h"
#include "source/extensions/common/qosmos_dpi/verdict_cache.h"

#include "test/mocks/event/mocks.h"
#include "test/mocks/network/mocks.h"
#include "test/test_common/environment.h"
#include "test/test_common/utility.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

using ::testing::NiceMock;
using ::testing::Return;
using ::testing::ReturnRef;

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace QosmosDpi {
namespace {

// ─────────── Mock classifier ───────────
//
// Filter holds QosmosClassifierPtr and calls flowAlive() / classifyFirstPdu()
// on it. Tests inject a MockQosmosClassifier with per-test canned
// ClassifyResult values plus assertions on the lifecycle.
class MockQosmosClassifier : public QosmosClassifier {
public:
  ~MockQosmosClassifier() override {
    destroyed_at_alive_ = flow_alive_;
    if (external_destroyed_flag_ != nullptr) {
      *external_destroyed_flag_ = true;
    }
  }

  bool flowAlive() const override { return flow_alive_; }

  // The interface split classifyFirstPdu into classifyPdu (no destroy) +
  // finalize (destroy). The base class provides a non-virtual
  // classifyFirstPdu that composes the two — which is exactly the shape
  // the pre-cache listener filter path exercises. Override the primitives.
  ClassifyResult classifyPdu(const void* bytes, int len, int direction,
                              int tenant_id) override {
    classify_called_ = true;
    classify_bytes_.assign(static_cast<const char*>(bytes), len);
    classify_direction_ = direction;
    classify_tenant_ = tenant_id;
    // result_ carries the intermediate_path / hooks / final_state that
    // the pre-cache tests set up. final_path stays owned by finalize().
    ClassifyResult r;
    r.intermediate_path = result_.intermediate_path;
    r.hooks = result_.hooks;
    r.engine_error = result_.engine_error;
    r.final_state = result_.final_state;
    return r;
  }

  ClassifyResult finalize() override {
    // Mirror RealQosmosClassifier semantics: flow goes away, subsequent
    // finalize() calls are no-ops.
    if (!flow_alive_) return ClassifyResult{};
    flow_alive_ = false;
    ClassifyResult r;
    r.final_path = result_.final_path;
    // ssl:alpn stays where the caller put it in result_.hooks; the merge
    // logic in QosmosClassifier::classifyFirstPdu handles first-write-wins.
    return r;
  }

  // Test inputs.
  ClassifyResult result_;
  bool flow_alive_{true};
  bool* external_destroyed_flag_{nullptr};

  // Test outputs.
  bool classify_called_{false};
  bool destroyed_at_alive_{false};
  std::string classify_bytes_;
  int classify_direction_{0};
  int classify_tenant_{0};
};

// In-test fake ListenerFilterBuffer. Minimal — just enough to hand a
// rawSlice() back. drain() is a no-op (the qosmos_dpi filter doesn't
// drain — tcp_proxy gets the bytes after we Continue).
class FakeListenerFilterBuffer : public Network::ListenerFilterBuffer {
public:
  explicit FakeListenerFilterBuffer(absl::string_view bytes)
      : bytes_(bytes) {}
  const Buffer::ConstRawSlice rawSlice() const override {
    return Buffer::ConstRawSlice{const_cast<char*>(bytes_.data()), bytes_.size()};
  }
  bool drain(uint64_t /*length*/) override { return true; }

private:
  std::string bytes_;
};

// Default proto: web_cluster=web_cluster, non_web_cluster=cfw_cluster.
envoy::extensions::filters::listener::qosmos_dpi::v3::QosmosDpi defaultProto() {
  envoy::extensions::filters::listener::qosmos_dpi::v3::QosmosDpi p;
  p.set_web_cluster("web_cluster");
  p.set_non_web_cluster("cfw_cluster");
  return p;
}

constexpr absl::string_view kFixtureJson = R"json({
  "version": "test-fixture",
  "transport_tokens":      ["base", "ip", "tcp", "ssl", "tls", "unknown"],
  "hosting_tokens":        ["amazon_aws", "gcp"],
  "http_alpn_prefixes":    ["h2", "h3", "http/1.1"],
  "non_web_alpn_prefixes": ["ftp", "smtp"],
  "web_substring_tokens":  ["http", "websocket"],
  "protocols": [
    { "name": "http",   "web": true  },
    { "name": "ssl",    "web": false },
    { "name": "ftp",    "web": false },
    { "name": "smtp",   "web": false }
  ]
})json";

std::shared_ptr<ProtocolTable> loadFixtureTable() {
  const std::string path =
      TestEnvironment::temporaryPath("qosmos_protocols_filter_fixture.json");
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  out << kFixtureJson;
  out.close();
  auto t_or = ProtocolTable::loadJson(path);
  EXPECT_TRUE(t_or.ok()) << t_or.status().message();
  return std::shared_ptr<ProtocolTable>(std::move(*t_or));
}

// ─────────── Test fixture ───────────

class QosmosDpiFilterTest : public testing::Test {
protected:
  void SetUp() override {
    table_ = loadFixtureTable();

    // Wire socket addresses on the built-in mock callbacks.socket_.
    // socket(), filterState(), streamInfo() are already wired via the
    // MockListenerFilterCallbacks constructor.
    auto remote_or = Network::Utility::resolveUrl("tcp://192.168.10.2:54321");
    auto local_or = Network::Utility::resolveUrl("tcp://10.10.2.2:80");
    ASSERT_TRUE(remote_or.ok());
    ASSERT_TRUE(local_or.ok());
    callbacks_.socket_.connection_info_provider_->setRemoteAddress(*remote_or);
    // localAddress = real destination, restored by original_dst (ordered
    // before us) via restoreLocalAddress(). v1.32.4's ConnectionInfoProvider
    // has no directLocalAddress() concept at all (no getter, no setter) —
    // unlike main, where the distinct accessor made a same-vs-different-value
    // regression test meaningful. Here, reverting to a nonexistent
    // directLocalAddress() simply fails to compile, so the compiler is the
    // regression guard; see §13.15 / readFiveTuple.
    callbacks_.socket_.connection_info_provider_->setLocalAddress(*local_or);

    // Filter calls dispatcher() to arm the silence timer; return our mock.
    ON_CALL(callbacks_, dispatcher()).WillByDefault(ReturnRef(dispatcher_));

    // Build the classifier factory that captures whatever knobs the test
    // set on next_factory_*.
    auto factory = [this](bool is_v6, const void* /*src_ip*/,
                           uint16_t /*src_port*/, const void* dst_ip,
                           uint16_t dst_port_nbo) -> QosmosClassifierPtr {
      // Record the destination the filter derived, so a test can assert the
      // Qosmos flow signature carries the REAL destination and not the
      // listener address.
      captured_dst_is_v6_ = is_v6;
      captured_dst_port_ = ntohs(dst_port_nbo);
      if (!is_v6 && dst_ip != nullptr) {
        char buf[INET_ADDRSTRLEN] = {};
        ::inet_ntop(AF_INET, dst_ip, buf, sizeof(buf));
        captured_dst_ip_ = buf;
      }
      if (next_factory_returns_null_) {
        return nullptr;
      }
      auto m = std::make_unique<MockQosmosClassifier>();
      m->flow_alive_ = next_factory_alive_;
      m->result_ = next_factory_result_;
      m->external_destroyed_flag_ = &saw_destruction_;
      captured_mock_ = m.get();
      return m;
    };

    config_ = std::make_shared<Config>(defaultProto(), factory, table_,
                                        *stats_store_.rootScope());
  }

  // Drive Filter::onAccept + Filter::onData with a single canned PDU.
  void runCycle(absl::string_view pdu_bytes) {
    filter_ = std::make_unique<Filter>(config_);
    EXPECT_EQ(filter_->onAccept(callbacks_),
              Network::FilterStatus::StopIteration);

    FakeListenerFilterBuffer fb(pdu_bytes);
    EXPECT_EQ(filter_->onData(fb), Network::FilterStatus::Continue);
  }

  // Pull verdict cluster name out of FilterState. Empty if not set.
  std::string verdictCluster() {
    auto* obj = callbacks_.filter_state_
        .getDataReadOnly<TcpProxy::PerConnectionCluster>(
            TcpProxy::PerConnectionCluster::key());
    return obj == nullptr ? std::string{} : obj->value();
  }

  // Members.
  std::shared_ptr<ProtocolTable> table_;
  ConfigSharedPtr config_;
  Stats::IsolatedStoreImpl stats_store_;

  std::string captured_dst_ip_;
  uint16_t captured_dst_port_{0};
  bool captured_dst_is_v6_{false};
  bool next_factory_alive_{true};
  bool next_factory_returns_null_{false};
  ClassifyResult next_factory_result_{};

  MockQosmosClassifier* captured_mock_{nullptr};
  bool saw_destruction_{false};

  NiceMock<Event::MockDispatcher> dispatcher_;
  NiceMock<Network::MockListenerFilterCallbacks> callbacks_;
  std::unique_ptr<Filter> filter_;
};

// ─────────── Verdict tests ───────────

// §13.15 regression. The Qosmos flow signature must carry the destination
// original_dst restored via localAddress() — 10.10.2.2:80 in this fixture.
// v1.32.4 has no directLocalAddress() at all, so a revert to it fails to
// compile rather than failing this assertion; this test still pins the
// correct value flows into the Qosmos signature.
//
// It matters because the tuple is the flow SIGNATURE: qmdpi.h documents that
// "all mechanisms related to cache or IP classification obtain addresses and
// ports directly in the flow sig". Feeding the listener address disables
// Qosmos's IP classification and poisons its internal cache. (It does NOT
// merge flows — qmdpi_flow_create allocates a fresh context per call.)
TEST_F(QosmosDpiFilterTest, Regression_FiveTupleUsesRestoredDestination) {
  next_factory_result_.intermediate_path = "base.ip.tcp.http";
  runCycle("GET / HTTP/1.1\r\n\r\n");

  EXPECT_FALSE(captured_dst_is_v6_);
  EXPECT_EQ(captured_dst_ip_, "10.10.2.2");   // NOT 10.10.0.1
  EXPECT_EQ(captured_dst_port_, 80);          // NOT 8443
}

TEST_F(QosmosDpiFilterTest, IntermediateHttpRoutesToWebCluster) {
  next_factory_result_.intermediate_path = "base.ip.tcp.http";
  runCycle("GET / HTTP/1.1\r\n\r\n");

  EXPECT_EQ(verdictCluster(), "web_cluster");
  EXPECT_EQ(config_->stats().web_classified_.value(), 1);
  EXPECT_EQ(config_->stats().non_web_classified_.value(), 0);
  EXPECT_EQ(config_->stats().inconclusive_forced_cfw_.value(), 0);
  ASSERT_NE(captured_mock_, nullptr);
  EXPECT_TRUE(captured_mock_->classify_called_);
  EXPECT_EQ(captured_mock_->classify_direction_, 1);   // QMDPI_DIR_CTS
  EXPECT_EQ(captured_mock_->classify_tenant_, 1);      // default
}

TEST_F(QosmosDpiFilterTest, IntermediateFtpRoutesToCfwCluster) {
  next_factory_result_.intermediate_path = "base.ip.tcp.ftp";
  runCycle("USER anonymous\r\n");
  EXPECT_EQ(verdictCluster(), "cfw_cluster");
  EXPECT_EQ(config_->stats().non_web_classified_.value(), 1);
  EXPECT_EQ(config_->stats().web_classified_.value(), 0);
}

TEST_F(QosmosDpiFilterTest, IntermediateInconclusiveFinalConclusiveUsesFinal) {
  next_factory_result_.intermediate_path = "";
  next_factory_result_.final_path = "base.ip.tcp.smtp";
  runCycle("EHLO example.com\r\n");
  EXPECT_EQ(verdictCluster(), "cfw_cluster");
  EXPECT_EQ(config_->stats().non_web_classified_.value(), 1);
  EXPECT_EQ(config_->stats().inconclusive_forced_cfw_.value(), 0);
}

TEST_F(QosmosDpiFilterTest, BothPathsEmptyForcesCfw) {
  next_factory_result_.intermediate_path = "";
  next_factory_result_.final_path = "";
  runCycle("\x00\x01\x02\x03");
  EXPECT_EQ(verdictCluster(), "cfw_cluster");
  EXPECT_EQ(config_->stats().non_web_classified_.value(), 1);
  EXPECT_EQ(config_->stats().inconclusive_forced_cfw_.value(), 1);
}

// ─────────── ssl:alpn hook-driven verdicts ───────────
//
// Cascade rules 0 and 1 require the classifier to populate
// ClassifyResult.hooks["ssl:alpn"]. Rule 0 (non-web ALPN beats
// everything) and rule 1 (transport-token + HTTP ALPN ⇒ web) only fire
// when ALPN is present.

TEST_F(QosmosDpiFilterTest, AlpnFtpForcesNonWebViaRule0) {
  next_factory_result_.intermediate_path = "base.ip.tcp.ssl.unknown";
  next_factory_result_.hooks["ssl:alpn"] = "ftp";
  runCycle("\x16\x03\x01...");
  EXPECT_EQ(verdictCluster(), "cfw_cluster");
  EXPECT_EQ(config_->stats().non_web_classified_.value(), 1);
  EXPECT_EQ(config_->stats().web_classified_.value(), 0);
}

TEST_F(QosmosDpiFilterTest, AlpnH2OnSslUnknownTriggersRule1Web) {
  next_factory_result_.intermediate_path = "base.ip.tcp.ssl.unknown";
  next_factory_result_.hooks["ssl:alpn"] = "h2";
  runCycle("\x16\x03\x01...");
  EXPECT_EQ(verdictCluster(), "web_cluster");
  EXPECT_EQ(config_->stats().web_classified_.value(), 1);
}

TEST_F(QosmosDpiFilterTest, AlpnHttp1OnAmazonAwsTriggersRule1Web) {
  // Hosting-token last segment: rule 2 deliberately skips (CSV
  // amazon_aws=true is aggregate, individual flows may be non-web).
  // Rule 1 with HTTP ALPN promotes to web on positive client evidence.
  next_factory_result_.intermediate_path = "base.ip.tcp.ssl.amazon_aws";
  next_factory_result_.hooks["ssl:alpn"] = "http/1.1";
  runCycle("\x16\x03\x01...");
  EXPECT_EQ(verdictCluster(), "web_cluster");
  EXPECT_EQ(config_->stats().web_classified_.value(), 1);
}

TEST_F(QosmosDpiFilterTest, AlpnFtpDataMatchesNonWebPrefix) {
  // Non-web ALPN matching is prefix+dash (so ftp-data matches ftp).
  next_factory_result_.intermediate_path = "base.ip.tcp.ssl.unknown";
  next_factory_result_.hooks["ssl:alpn"] = "ftp-data";
  runCycle("\x16\x03\x01...");
  EXPECT_EQ(verdictCluster(), "cfw_cluster");
  EXPECT_EQ(config_->stats().non_web_classified_.value(), 1);
}

TEST_F(QosmosDpiFilterTest, AlpnListWithFtpEntryStillTriggersRule0) {
  // ALPN can be a comma-separated list (client preference order).
  // Any non-web entry beats everything.
  next_factory_result_.intermediate_path = "base.ip.tcp.ssl.amazon_aws";
  next_factory_result_.hooks["ssl:alpn"] = "h2, ftp";
  runCycle("\x16\x03\x01...");
  EXPECT_EQ(verdictCluster(), "cfw_cluster");
  EXPECT_EQ(config_->stats().non_web_classified_.value(), 1);
}

// ─────────── Lifecycle invariants ───────────

TEST_F(QosmosDpiFilterTest, ClassifyFirstPduIsCalledExactlyOnce) {
  next_factory_result_.intermediate_path = "base.ip.tcp.http";
  runCycle("GET / HTTP/1.1\r\n\r\n");
  ASSERT_NE(captured_mock_, nullptr);
  EXPECT_TRUE(captured_mock_->classify_called_);
  // After classify, mock's flow_alive_ flipped to false. ~Filter then
  // destroys the mock — saw_destruction_ flips true.
  filter_.reset();
  EXPECT_TRUE(saw_destruction_);
}

TEST_F(QosmosDpiFilterTest, EarlyCloseDestroysAliveFlow_BumpsClosedStat) {
  // Connection accepted but no bytes ever fed AND no silence timeout
  // (we never advance simulated time). ~Filter destroys the still-alive
  // mock; recordClassifierDestruction sees verdict_set_=false and
  // increments flows_released_at_close_.
  filter_ = std::make_unique<Filter>(config_);
  EXPECT_EQ(filter_->onAccept(callbacks_),
            Network::FilterStatus::StopIteration);
  ASSERT_NE(captured_mock_, nullptr);
  EXPECT_FALSE(captured_mock_->classify_called_);

  filter_.reset();   // simulates early connection close.

  EXPECT_TRUE(saw_destruction_);
  EXPECT_TRUE(captured_mock_ == nullptr ? false : true);   // captured_mock_ is now dangling but flag is set.
  EXPECT_EQ(config_->stats().flows_released_at_close_.value(), 1);
  EXPECT_EQ(config_->stats().flows_released_at_verdict_.value(), 0);
  EXPECT_EQ(config_->stats().flows_active_.value(), 0);
}

TEST_F(QosmosDpiFilterTest, FactoryReturnsNullFailsSafeNonWeb) {
  next_factory_returns_null_ = true;

  filter_ = std::make_unique<Filter>(config_);
  EXPECT_EQ(filter_->onAccept(callbacks_),
            Network::FilterStatus::Continue);

  EXPECT_EQ(verdictCluster(), "cfw_cluster");
  EXPECT_EQ(config_->stats().engine_error_.value(), 1);
  EXPECT_EQ(config_->stats().non_web_classified_.value(), 1);
  EXPECT_FALSE(saw_destruction_);   // no classifier was ever created.
}

TEST_F(QosmosDpiFilterTest, ClassifierEngineErrorStillFailsSafeNonWeb) {
  next_factory_result_.engine_error = true;
  next_factory_result_.intermediate_path = "";
  next_factory_result_.final_path = "";
  runCycle("garbage");
  EXPECT_EQ(verdictCluster(), "cfw_cluster");
  EXPECT_GE(config_->stats().engine_error_.value(), 1);
  EXPECT_EQ(config_->stats().non_web_classified_.value(), 1);
}

// ─────────── Silence-timer behaviour ───────────
//
// onAccept arms a timer via dispatcher.createTimer(callback). We capture
// the callback at create-timer time, then invoke it manually to simulate
// the 200ms expiry. Asserts: silence_timeout stat increments, verdict =
// non_web (CFW), continueFilterChain(true) is called.

TEST_F(QosmosDpiFilterTest, SilenceTimeoutDefaultsToCfw) {
  // Capture the timer callback that Filter::onAccept registers.
  Event::TimerCb captured_cb;
  auto* timer = new NiceMock<Event::MockTimer>();   // NiceMock so default
                                                    // enableTimer() is a no-op.
  EXPECT_CALL(dispatcher_, createTimer_(_))
      .WillOnce([&captured_cb, timer](Event::TimerCb cb) {
        captured_cb = std::move(cb);
        return timer;
      });

  bool continue_called = false;
  EXPECT_CALL(callbacks_, continueFilterChain(true))
      .WillOnce([&continue_called](bool) { continue_called = true; });

  filter_ = std::make_unique<Filter>(config_);
  EXPECT_EQ(filter_->onAccept(callbacks_),
            Network::FilterStatus::StopIteration);
  ASSERT_NE(captured_mock_, nullptr);
  EXPECT_FALSE(captured_mock_->classify_called_);
  ASSERT_TRUE(captured_cb != nullptr);

  // Fire the timer.
  captured_cb();

  EXPECT_EQ(verdictCluster(), "cfw_cluster");
  EXPECT_EQ(config_->stats().silence_timeout_.value(), 1);
  EXPECT_EQ(config_->stats().non_web_classified_.value(), 1);
  EXPECT_TRUE(continue_called);
  EXPECT_FALSE(captured_mock_->classify_called_);   // classify never ran.
}

// ─────────── Verdict-cache + hand-off (Part I) ───────────
//
// Separate fixture: a real VerdictCache is injected via Config's test-only
// ctor. verdict_cache_correction_enabled must be true on the proto for
// verdictCacheForThisThread() to return the injected cache. The listener
// filter's cache/handoff branches are unit-testable end-to-end this way
// without a running QosmosEngine.

class QosmosDpiCacheFilterTest : public testing::Test {
protected:
  void SetUp() override {
    table_ = loadFixtureTable();
    cache_ = std::make_unique<
        Extensions::Common::QosmosDpi::VerdictCache>(/*max_entries=*/100);

    auto remote_or = Network::Utility::resolveUrl("tcp://192.168.10.2:54321");
    auto local_or = Network::Utility::resolveUrl("tcp://10.10.2.2:80");
    ASSERT_TRUE(remote_or.ok());
    ASSERT_TRUE(local_or.ok());
    callbacks_.socket_.connection_info_provider_->setRemoteAddress(*remote_or);
    // localAddress is the real destination restored by original_dst, which
    // runs before us. v1.32.4 has no directLocalAddress() concept at all
    // (see the SetUp() comment in QosmosDpiFilterTest above), so unlike
    // main there is no second accessor to accidentally read — a revert
    // fails to compile. See Regression_CacheKeyUsesRestoredDestination.
    callbacks_.socket_.connection_info_provider_->setLocalAddress(*local_or);

    ON_CALL(callbacks_, dispatcher()).WillByDefault(ReturnRef(dispatcher_));

    factory_ = [this](bool, const void*, uint16_t, const void*, uint16_t)
        -> QosmosClassifierPtr {
      if (skip_factory_) return nullptr;
      factory_invoked_++;
      auto m = std::make_unique<MockQosmosClassifier>();
      m->flow_alive_ = true;
      m->result_ = next_result_;
      m->external_destroyed_flag_ = &saw_destruction_;
      captured_mock_ = m.get();
      return m;
    };

    envoy::extensions::filters::listener::qosmos_dpi::v3::QosmosDpi proto =
        defaultProto();
    proto.set_verdict_cache_correction_enabled(true);
    proto.set_verdict_cache_total_entries(100);
    config_ = std::make_shared<Config>(proto, factory_, table_,
                                        *stats_store_.rootScope(),
                                        cache_.get());
  }

  Extensions::Common::QosmosDpi::VerdictCacheKey expectedKey() const {
    Extensions::Common::QosmosDpi::VerdictCacheKey k;
    k.dst_ip = "10.10.2.2";
    k.dst_port = 80;
    k.kind = Extensions::Common::QosmosDpi::DiscriminatorKind::Plain;
    return k;
  }

  std::string verdictCluster() {
    auto* obj = callbacks_.filter_state_
        .getDataReadOnly<TcpProxy::PerConnectionCluster>(
            TcpProxy::PerConnectionCluster::key());
    return obj == nullptr ? std::string{} : obj->value();
  }

  Extensions::Common::QosmosDpi::QosmosFlowHandoff* getHandoff() {
    return callbacks_.filter_state_
        .getDataMutable<Extensions::Common::QosmosDpi::QosmosFlowHandoff>(
            Extensions::Common::QosmosDpi::QosmosFlowHandoff::filterStateKey());
  }

  std::shared_ptr<ProtocolTable> table_;
  std::unique_ptr<Extensions::Common::QosmosDpi::VerdictCache> cache_;
  ConfigSharedPtr config_;
  Stats::IsolatedStoreImpl stats_store_;

  ClassifierFactory factory_;
  ClassifyResult next_result_{};
  bool skip_factory_{false};
  int factory_invoked_{0};
  MockQosmosClassifier* captured_mock_{nullptr};
  bool saw_destruction_{false};

  NiceMock<Event::MockDispatcher> dispatcher_;
  NiceMock<Network::MockListenerFilterCallbacks> callbacks_;
  std::unique_ptr<Filter> filter_;
};

TEST_F(QosmosDpiCacheFilterTest, OnAcceptAlwaysRunsClassifier) {
  // Post-2026-07-28 semantics: cache lookup is deferred to onData (until
  // classifyPdu emits the discriminator hooks). onAccept always creates a
  // classifier and arms the silence timer — the cache never short-circuits
  // at accept time.
  ASSERT_TRUE(cache_->put(expectedKey(), /*verdict_is_web=*/true, "final"));

  filter_ = std::make_unique<Filter>(config_);
  EXPECT_EQ(filter_->onAccept(callbacks_),
            Network::FilterStatus::StopIteration);
  // No cache stats bumped at accept time — that's all onData's job now.
  EXPECT_EQ(config_->stats().verdict_cache_hit_.value(), 0);
  EXPECT_EQ(config_->stats().verdict_cache_miss_.value(), 0);
  EXPECT_EQ(config_->stats().web_classified_.value(), 0);
  EXPECT_EQ(factory_invoked_, 1);
  EXPECT_NE(captured_mock_, nullptr);
}

TEST_F(QosmosDpiCacheFilterTest, OnDataCacheHitFinalSeenShortCircuitsHandoff) {
  // Pre-populate the cache with a terminal (final_seen=true) entry for
  // {10.10.2.2, 80, Plain}. First PDU arrives, classifier runs, key is
  // built from hooks (no SNI/Host in this fixture → Plain), lookup hits
  // final. Verdict served from cache; classifier finalized; no hand-off.
  ASSERT_TRUE(cache_->put(expectedKey(), /*verdict_is_web=*/true, "final"));
  next_result_.intermediate_path = "base.ip.tcp.http";

  filter_ = std::make_unique<Filter>(config_);
  ASSERT_EQ(filter_->onAccept(callbacks_),
            Network::FilterStatus::StopIteration);
  FakeListenerFilterBuffer fb("GET / HTTP/1.1\r\n\r\n");
  ASSERT_EQ(filter_->onData(fb), Network::FilterStatus::Continue);

  EXPECT_EQ(verdictCluster(), "web_cluster");
  EXPECT_EQ(config_->stats().verdict_cache_hit_.value(), 1);
  EXPECT_EQ(config_->stats().verdict_cache_miss_.value(), 0);
  EXPECT_EQ(config_->stats().web_classified_.value(), 1);
  // No hand-off — the terminal cache entry short-circuited the flow.
  EXPECT_EQ(config_->stats().handed_off_to_correction_.value(), 0);
  EXPECT_EQ(getHandoff(), nullptr);
  ASSERT_NE(captured_mock_, nullptr);
  EXPECT_FALSE(captured_mock_->flow_alive_);   // finalize() ran.
}

TEST_F(QosmosDpiCacheFilterTest, OnDataCacheDisagreementCountedNotOverridden) {
  // Cached final verdict is web, but the current flow's initial cascade
  // resolves to non-web. Trust the cache (§3 option b), bump the
  // disagreement stat, don't override.
  ASSERT_TRUE(cache_->put(expectedKey(), /*verdict_is_web=*/true, "final"));
  next_result_.intermediate_path = "base.ip.tcp.ftp";   // Rule 2 → non-web.

  filter_ = std::make_unique<Filter>(config_);
  ASSERT_EQ(filter_->onAccept(callbacks_),
            Network::FilterStatus::StopIteration);
  FakeListenerFilterBuffer fb("USER anonymous\r\n");
  ASSERT_EQ(filter_->onData(fb), Network::FilterStatus::Continue);

  EXPECT_EQ(verdictCluster(), "web_cluster");   // cache wins.
  EXPECT_EQ(config_->stats().verdict_cache_disagreement_.value(), 1);
  EXPECT_EQ(config_->stats().verdict_cache_hit_.value(), 1);
  EXPECT_EQ(config_->stats().web_classified_.value(), 1);
  EXPECT_EQ(config_->stats().handed_off_to_correction_.value(), 0);
}

TEST_F(QosmosDpiCacheFilterTest, OnDataCacheHitInitialOnlyHandsOff) {
  // Cache has an entry, but final_seen=false — another flow is still on
  // its correction extension. Current flow "reinforces" by running its
  // own classify + hand-off (folded into handed_off_to_correction stat).
  ASSERT_TRUE(cache_->put(expectedKey(), /*verdict_is_web=*/true, "4pkt"));
  next_result_.intermediate_path = "base.ip.tcp.http";

  filter_ = std::make_unique<Filter>(config_);
  ASSERT_EQ(filter_->onAccept(callbacks_),
            Network::FilterStatus::StopIteration);
  FakeListenerFilterBuffer fb("GET / HTTP/1.1\r\n\r\n");
  ASSERT_EQ(filter_->onData(fb), Network::FilterStatus::Continue);

  EXPECT_EQ(verdictCluster(), "web_cluster");
  // hit stat bumped, but hand-off ALSO happened (reinforcement).
  EXPECT_EQ(config_->stats().verdict_cache_hit_.value(), 1);
  EXPECT_EQ(config_->stats().verdict_cache_miss_.value(), 0);
  EXPECT_EQ(config_->stats().handed_off_to_correction_.value(), 1);
  EXPECT_NE(getHandoff(), nullptr);
}

TEST_F(QosmosDpiCacheFilterTest, OnDataCacheMissPopulatesAndHandsOff) {
  // Classic miss path: fresh key, classifyPdu emits an initial verdict,
  // cache populated with source="4pkt", hand-off parked in FilterState.
  next_result_.intermediate_path = "base.ip.tcp.http";

  filter_ = std::make_unique<Filter>(config_);
  ASSERT_EQ(filter_->onAccept(callbacks_),
            Network::FilterStatus::StopIteration);
  FakeListenerFilterBuffer fb("GET / HTTP/1.1\r\n\r\n");
  ASSERT_EQ(filter_->onData(fb), Network::FilterStatus::Continue);

  EXPECT_EQ(config_->stats().verdict_cache_miss_.value(), 1);
  EXPECT_EQ(config_->stats().verdict_cache_hit_.value(), 0);
  EXPECT_EQ(config_->stats().handed_off_to_correction_.value(), 1);
  auto hit = cache_->lookup(expectedKey());
  ASSERT_TRUE(hit.has_value());
  EXPECT_FALSE(hit->final_seen);
  EXPECT_EQ(hit->source, "4pkt");
}

TEST_F(QosmosDpiCacheFilterTest, OnDataPopulatesCacheAndHandsOff) {
  next_result_.intermediate_path = "base.ip.tcp.http";
  next_result_.final_state = false;   // NOT final_state — expect hand-off.

  filter_ = std::make_unique<Filter>(config_);
  ASSERT_EQ(filter_->onAccept(callbacks_),
            Network::FilterStatus::StopIteration);

  FakeListenerFilterBuffer fb("GET / HTTP/1.1\r\n\r\n");
  ASSERT_EQ(filter_->onData(fb), Network::FilterStatus::Continue);

  // Verdict: web, cache populated.
  EXPECT_EQ(verdictCluster(), "web_cluster");
  EXPECT_EQ(config_->stats().web_classified_.value(), 1);
  auto hit = cache_->lookup(expectedKey());
  ASSERT_TRUE(hit.has_value());
  EXPECT_TRUE(hit->verdict_is_web);
  EXPECT_EQ(hit->source, "4pkt");
  // Hand-off: FilterState has the object, and it holds the moved-out
  // classifier (not the listener filter).
  auto* handoff = getHandoff();
  ASSERT_NE(handoff, nullptr);
  ASSERT_TRUE(handoff->initialVerdictIsWeb().has_value());
  EXPECT_TRUE(*handoff->initialVerdictIsWeb());
  EXPECT_EQ(handoff->bytesAlreadyConsumed(),
            std::string("GET / HTTP/1.1\r\n\r\n").size());
  EXPECT_EQ(config_->stats().handed_off_to_correction_.value(), 1);
}

TEST_F(QosmosDpiCacheFilterTest, OnDataFinalStateFinalizesWithoutHandoff) {
  next_result_.intermediate_path = "base.ip.tcp.http";
  next_result_.final_state = true;   // First PDU already conclusive.

  filter_ = std::make_unique<Filter>(config_);
  ASSERT_EQ(filter_->onAccept(callbacks_),
            Network::FilterStatus::StopIteration);
  FakeListenerFilterBuffer fb("GET / HTTP/1.1\r\n\r\n");
  ASSERT_EQ(filter_->onData(fb), Network::FilterStatus::Continue);

  // Verdict + cache populate happen as usual...
  EXPECT_EQ(verdictCluster(), "web_cluster");
  ASSERT_TRUE(cache_->lookup(expectedKey()).has_value());
  // ...but NO hand-off (final_state short-circuits the hand-off path).
  EXPECT_EQ(config_->stats().handed_off_to_correction_.value(), 0);
  EXPECT_EQ(getHandoff(), nullptr);
  ASSERT_NE(captured_mock_, nullptr);
  // finalize() was called on the mock, so flow_alive_ flipped off.
  EXPECT_FALSE(captured_mock_->flow_alive_);
}

TEST_F(QosmosDpiCacheFilterTest, InconclusiveVerdictIsNotCached) {
  // Both paths empty → the filter defaults to non-web (CFW) BUT MUST NOT
  // cache that guess. Caching an inconclusive default would suppress DPI
  // on every future connection to the destination.
  next_result_.intermediate_path = "";
  next_result_.final_path = "";

  filter_ = std::make_unique<Filter>(config_);
  ASSERT_EQ(filter_->onAccept(callbacks_),
            Network::FilterStatus::StopIteration);
  FakeListenerFilterBuffer fb("\x00\x01\x02\x03");
  ASSERT_EQ(filter_->onData(fb), Network::FilterStatus::Continue);

  EXPECT_EQ(verdictCluster(), "cfw_cluster");
  EXPECT_EQ(config_->stats().inconclusive_forced_cfw_.value(), 1);
  // Cache SHOULD stay empty.
  EXPECT_EQ(cache_->size(), 0U);
  EXPECT_FALSE(cache_->lookup(expectedKey()).has_value());
  // No hand-off either — we have no verdict to correct against.
  EXPECT_EQ(config_->stats().handed_off_to_correction_.value(), 0);
  EXPECT_EQ(getHandoff(), nullptr);
}

TEST_F(QosmosDpiCacheFilterTest, SilenceTimeoutHandsOffWithNulloptVerdict) {
  // Silence-timeout path: no bytes ever fed, classifier still alive. The
  // filter must park a QosmosFlowHandoff with initialVerdictIsWeb=nullopt
  // (no verdict yet) so the correction filter can populate the cache
  // later if it reaches a real classification.
  Event::TimerCb captured_cb;
  auto* timer = new NiceMock<Event::MockTimer>();
  EXPECT_CALL(dispatcher_, createTimer_(_))
      .WillOnce([&captured_cb, timer](Event::TimerCb cb) {
        captured_cb = std::move(cb);
        return timer;
      });
  bool continue_called = false;
  EXPECT_CALL(callbacks_, continueFilterChain(true))
      .WillOnce([&continue_called](bool) { continue_called = true; });

  filter_ = std::make_unique<Filter>(config_);
  ASSERT_EQ(filter_->onAccept(callbacks_),
            Network::FilterStatus::StopIteration);
  ASSERT_TRUE(captured_cb != nullptr);
  captured_cb();   // fire silence timer.

  // Fallback verdict is non-web.
  EXPECT_EQ(verdictCluster(), "cfw_cluster");
  EXPECT_EQ(config_->stats().silence_timeout_.value(), 1);
  EXPECT_TRUE(continue_called);

  // Hand-off happened WITH nullopt verdict.
  auto* handoff = getHandoff();
  ASSERT_NE(handoff, nullptr);
  EXPECT_FALSE(handoff->initialVerdictIsWeb().has_value());
  EXPECT_EQ(handoff->bytesAlreadyConsumed(), 0U);
  EXPECT_EQ(config_->stats().handed_off_to_correction_.value(), 1);
  // Cache stays empty on the silence path — we don't cache the guess.
  EXPECT_EQ(cache_->size(), 0U);
}

TEST_F(QosmosDpiCacheFilterTest, DisabledCorrectionByteForByteIdentical) {
  // Regression: when verdictCacheForThisThread() is null (e.g. proto flag
  // off), the filter must behave exactly like the pre-cache implementation
  // — no cache lookup, no populate, no hand-off, cache untouched. Prove
  // that by rebuilding Config with a proto that leaves the flag off.
  envoy::extensions::filters::listener::qosmos_dpi::v3::QosmosDpi proto =
      defaultProto();
  // No set_verdict_cache_correction_enabled — defaults to false.
  auto disabled_config = std::make_shared<Config>(
      proto, factory_, table_, *stats_store_.rootScope(), cache_.get());
  ASSERT_EQ(disabled_config->verdictCacheForThisThread(), nullptr);

  next_result_.intermediate_path = "base.ip.tcp.http";
  filter_ = std::make_unique<Filter>(disabled_config);
  ASSERT_EQ(filter_->onAccept(callbacks_),
            Network::FilterStatus::StopIteration);
  FakeListenerFilterBuffer fb("GET / HTTP/1.1\r\n\r\n");
  ASSERT_EQ(filter_->onData(fb), Network::FilterStatus::Continue);

  EXPECT_EQ(verdictCluster(), "web_cluster");
  // ZERO cache activity.
  EXPECT_EQ(disabled_config->stats().verdict_cache_hit_.value(), 0);
  EXPECT_EQ(disabled_config->stats().verdict_cache_miss_.value(), 0);
  EXPECT_EQ(disabled_config->stats().handed_off_to_correction_.value(), 0);
  EXPECT_EQ(cache_->size(), 0U);
  EXPECT_EQ(getHandoff(), nullptr);
}

}  // namespace
}  // namespace QosmosDpi
}  // namespace ListenerFilters
}  // namespace Extensions
}  // namespace Envoy
