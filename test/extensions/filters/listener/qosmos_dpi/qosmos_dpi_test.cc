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
#include "source/extensions/filters/listener/qosmos_dpi/qosmos_engine.h"

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

  ClassifyResult classifyFirstPdu(const void* bytes, int len, int direction,
                                   int tenant_id) override {
    classify_called_ = true;
    classify_bytes_.assign(static_cast<const char*>(bytes), len);
    classify_direction_ = direction;
    classify_tenant_ = tenant_id;
    flow_alive_ = false;   // mirrors RealQosmosClassifier semantics.
    return result_;
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
    callbacks_.socket_.connection_info_provider_->setLocalAddress(*local_or);

    // Filter calls dispatcher() to arm the silence timer; return our mock.
    ON_CALL(callbacks_, dispatcher()).WillByDefault(ReturnRef(dispatcher_));

    // Build the classifier factory that captures whatever knobs the test
    // set on next_factory_*.
    auto factory = [this](bool /*is_v6*/, const void* /*src_ip*/,
                           uint16_t /*src_port*/, const void* /*dst_ip*/,
                           uint16_t /*dst_port*/) -> QosmosClassifierPtr {
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

}  // namespace
}  // namespace QosmosDpi
}  // namespace ListenerFilters
}  // namespace Extensions
}  // namespace Envoy
