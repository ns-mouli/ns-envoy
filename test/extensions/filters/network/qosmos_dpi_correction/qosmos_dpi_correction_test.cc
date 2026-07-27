#include <memory>
#include <string>
#include <vector>

#include "envoy/extensions/filters/network/qosmos_dpi_correction/v3/qosmos_dpi_correction.pb.h"
#include "envoy/network/filter.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/common/stream_info/filter_state_impl.h"
#include "source/extensions/common/qosmos_dpi/qosmos_engine.h"
#include "source/extensions/common/qosmos_dpi/qosmos_flow_handoff.h"
#include "source/extensions/common/qosmos_dpi/verdict_cache.h"
#include "source/extensions/filters/network/qosmos_dpi_correction/qosmos_dpi_correction.h"

#include "test/mocks/event/mocks.h"
#include "test/mocks/network/mocks.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

using ::testing::NiceMock;
using ::testing::Return;
using ::testing::ReturnRef;

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace QosmosDpiCorrection {
namespace {

using ::Envoy::Extensions::Common::QosmosDpi::ClassifyResult;
using ::Envoy::Extensions::Common::QosmosDpi::DiscriminatorKind;
using ::Envoy::Extensions::Common::QosmosDpi::QosmosClassifier;
using ::Envoy::Extensions::Common::QosmosDpi::QosmosClassifierPtr;
using ::Envoy::Extensions::Common::QosmosDpi::QosmosFlowHandoff;
using ::Envoy::Extensions::Common::QosmosDpi::VerdictCacheKey;

// A scripted classifier: caller pushes ClassifyResults; each classifyPdu call
// pops the next scripted result. finalize() flips flow_alive_ and returns
// a result with an optional final_path.
class FakeQosmosClassifier : public QosmosClassifier {
public:
  bool flowAlive() const override { return flow_alive_; }

  ClassifyResult classifyPdu(const void* bytes, int len, int direction,
                              int /*tenant_id*/) override {
    classify_calls_++;
    total_bytes_fed_ += len;
    directions_.push_back(direction);
    bytes_snapshots_.emplace_back(static_cast<const char*>(bytes), len);
    if (scripted_.empty()) return ClassifyResult{};
    ClassifyResult r = scripted_.front();
    scripted_.erase(scripted_.begin());
    return r;
  }

  ClassifyResult finalize() override {
    finalize_calls_++;
    flow_alive_ = false;
    ClassifyResult r;
    r.final_path = final_path_;
    return r;
  }

  // Test inputs.
  std::vector<ClassifyResult> scripted_;
  std::string final_path_;
  bool flow_alive_{true};

  // Test outputs.
  int classify_calls_{0};
  int finalize_calls_{0};
  size_t total_bytes_fed_{0};
  std::vector<int> directions_;
  std::vector<std::string> bytes_snapshots_;
};

// Note on coverage scope: the correction filter's finalizeAndMaybeCorrect
// path reads QosmosEngine::table() + cacheForThisThread(), which are
// non-virtual on the shipped engine. Faking them would need either
// virtualization of the engine (a wider refactor) or dependency-injection
// changes. For now, this suite covers the non-engine paths:
//   - passthrough (no handoff), skip-bytes accounting on CTS + STC,
//     resource-bound triggers, destructor-driven finalize, claim stat.
// The engine-touching paths (verdict-flip correction, populate-from-
// silence) are exercised end-to-end via the topology-C run in
// cfw-demux-svc/envoy-qosmos — see envoy-qosmos-cache.md Verification.

VerdictCacheKey plainKey(absl::string_view ip, uint16_t port) {
  VerdictCacheKey k;
  k.dst_ip.assign(ip.data(), ip.size());
  k.dst_port = port;
  k.kind = DiscriminatorKind::Plain;
  return k;
}

class QosmosDpiCorrectionTest : public testing::Test {
protected:
  void SetUp() override {
    proto_.mutable_correction_timeout()->set_seconds(5);
    proto_.set_max_correction_bytes(65536);
    proto_.set_max_correction_pdus(64);
    config_ = std::make_shared<Config>(proto_, *stats_store_.rootScope());

    // Wire the filter to the mock read + write callbacks so
    // read_cb_->connection() reaches our mock connection with its
    // filter_state_.
    ON_CALL(read_cb_.connection_, streamInfo())
        .WillByDefault(ReturnRef(read_cb_.connection_.stream_info_));
    ON_CALL(read_cb_.connection_, dispatcher())
        .WillByDefault(ReturnRef(dispatcher_));
    ON_CALL(read_cb_.connection_.stream_info_, filterState())
        .WillByDefault(ReturnRef(filter_state_shared_));
  }

  void makeFilter() {
    filter_ = std::make_unique<Filter>(config_);
    filter_->initializeReadFilterCallbacks(read_cb_);
    filter_->initializeWriteFilterCallbacks(write_cb_);
  }

  void parkHandoff(QosmosClassifierPtr classifier,
                   const VerdictCacheKey& key,
                   absl::optional<bool> initial_verdict_is_web,
                   size_t bytes_already_consumed) {
    auto handoff = std::make_unique<QosmosFlowHandoff>(
        std::move(classifier), key, initial_verdict_is_web,
        /*engine=*/nullptr, bytes_already_consumed);
    filter_state_shared_->setData(
        QosmosFlowHandoff::filterStateKey(), std::move(handoff),
        StreamInfo::FilterState::StateType::Mutable,
        StreamInfo::FilterState::LifeSpan::Connection);
  }

  envoy::extensions::filters::network::qosmos_dpi_correction::v3::QosmosDpiCorrection
      proto_;
  Stats::IsolatedStoreImpl stats_store_;
  ConfigSharedPtr config_;

  NiceMock<Event::MockDispatcher> dispatcher_;
  NiceMock<Network::MockReadFilterCallbacks> read_cb_;
  NiceMock<Network::MockWriteFilterCallbacks> write_cb_;
  StreamInfo::FilterStateSharedPtr filter_state_shared_ =
      std::make_shared<StreamInfo::FilterStateImpl>(
          StreamInfo::FilterState::LifeSpan::Connection);
  std::unique_ptr<Filter> filter_;
};

TEST_F(QosmosDpiCorrectionTest, NoHandoffIsPassthrough) {
  // No handoff object → onNewConnection Continues; onData/onWrite are
  // zero-cost passthroughs regardless of what's in the buffer.
  makeFilter();
  EXPECT_EQ(filter_->onNewConnection(), Network::FilterStatus::Continue);
  EXPECT_EQ(config_->stats().correction_flows_claimed_.value(), 0);

  Buffer::OwnedImpl data("random bytes");
  const auto before = data.length();
  EXPECT_EQ(filter_->onData(data, false), Network::FilterStatus::Continue);
  EXPECT_EQ(data.length(), before);   // buffer unchanged.

  Buffer::OwnedImpl resp("server data");
  const auto before2 = resp.length();
  EXPECT_EQ(filter_->onWrite(resp, false), Network::FilterStatus::Continue);
  EXPECT_EQ(resp.length(), before2);
}

TEST_F(QosmosDpiCorrectionTest, ClaimsHandoffAndIncrementsClaimStat) {
  QosmosClassifierPtr classifier = std::make_unique<FakeQosmosClassifier>();
  parkHandoff(std::move(classifier), plainKey("1.2.3.4", 443),
              absl::optional<bool>(true), /*bytes_already_consumed=*/0);
  makeFilter();
  EXPECT_EQ(filter_->onNewConnection(), Network::FilterStatus::Continue);
  EXPECT_EQ(config_->stats().correction_flows_claimed_.value(), 1);
  EXPECT_EQ(config_->stats().correction_flows_active_.value(), 1);
}

TEST_F(QosmosDpiCorrectionTest, SkipsAlreadyPeekedCtsBytesExactly) {
  // Bytes-already-consumed = 10. First onData delivers exactly 10 bytes
  // → filter must NOT call classifyPdu (every byte is a duplicate).
  // Second onData with 5 new bytes → classifyPdu called with just those 5.
  auto* fake = new FakeQosmosClassifier();
  parkHandoff(QosmosClassifierPtr(fake), plainKey("1.2.3.4", 443),
              absl::optional<bool>(true), /*bytes_already_consumed=*/10);
  makeFilter();
  ASSERT_EQ(filter_->onNewConnection(), Network::FilterStatus::Continue);

  Buffer::OwnedImpl dup_data("0123456789");   // exactly 10 bytes.
  const auto before = dup_data.length();
  ASSERT_EQ(filter_->onData(dup_data, false), Network::FilterStatus::Continue);
  EXPECT_EQ(fake->classify_calls_, 0);
  EXPECT_EQ(dup_data.length(), before);   // buffer untouched.

  Buffer::OwnedImpl new_data("hello");
  const auto before2 = new_data.length();
  ASSERT_EQ(filter_->onData(new_data, false), Network::FilterStatus::Continue);
  EXPECT_EQ(fake->classify_calls_, 1);
  EXPECT_EQ(fake->total_bytes_fed_, 5U);
  EXPECT_EQ(fake->bytes_snapshots_.back(), "hello");
  EXPECT_EQ(new_data.length(), before2);   // still passive-observer.
}

TEST_F(QosmosDpiCorrectionTest, SkipSpansMultipleOnDataCalls) {
  auto* fake = new FakeQosmosClassifier();
  parkHandoff(QosmosClassifierPtr(fake), plainKey("1.2.3.4", 443),
              absl::optional<bool>(true), /*bytes_already_consumed=*/12);
  makeFilter();
  ASSERT_EQ(filter_->onNewConnection(), Network::FilterStatus::Continue);

  // First chunk = 5 bytes → all duplicates, skip counter still has 7.
  Buffer::OwnedImpl first("aaaaa");
  ASSERT_EQ(filter_->onData(first, false), Network::FilterStatus::Continue);
  EXPECT_EQ(fake->classify_calls_, 0);

  // Second chunk = 4 bytes → still all duplicates, skip counter has 3.
  Buffer::OwnedImpl second("bbbb");
  ASSERT_EQ(filter_->onData(second, false), Network::FilterStatus::Continue);
  EXPECT_EQ(fake->classify_calls_, 0);

  // Third chunk = 10 bytes → first 3 duplicates, last 7 fed.
  Buffer::OwnedImpl third("cccdddeeeff");   // 11 bytes total.
  ASSERT_EQ(filter_->onData(third, false), Network::FilterStatus::Continue);
  EXPECT_EQ(fake->classify_calls_, 1);
  EXPECT_EQ(fake->total_bytes_fed_, 8U);   // 11 - 3 = 8 new bytes.
  EXPECT_EQ(fake->bytes_snapshots_.back(), "dddeeeff");
}

TEST_F(QosmosDpiCorrectionTest, OnWriteNeverSkips) {
  // The STC direction never has any prior-peeked bytes to skip (the
  // listener filter only ever saw CTS). Even with bytes_already_consumed
  // non-zero, onWrite must feed every byte immediately.
  auto* fake = new FakeQosmosClassifier();
  parkHandoff(QosmosClassifierPtr(fake), plainKey("1.2.3.4", 443),
              absl::optional<bool>(true), /*bytes_already_consumed=*/50);
  makeFilter();
  ASSERT_EQ(filter_->onNewConnection(), Network::FilterStatus::Continue);

  Buffer::OwnedImpl stc("server greeting");
  ASSERT_EQ(filter_->onWrite(stc, false), Network::FilterStatus::Continue);
  EXPECT_EQ(fake->classify_calls_, 1);
  EXPECT_EQ(fake->total_bytes_fed_, std::string("server greeting").size());
  ASSERT_EQ(fake->directions_.size(), 1U);
  // 2 == QMDPI_DIR_STC in the vendored qmdpi_const.h.
  EXPECT_EQ(fake->directions_[0], 2);
}

TEST_F(QosmosDpiCorrectionTest, ResourceBoundByteCapForcesFinalize) {
  auto* fake = new FakeQosmosClassifier();
  parkHandoff(QosmosClassifierPtr(fake), plainKey("1.2.3.4", 443),
              absl::optional<bool>(true), /*bytes_already_consumed=*/0);
  // Shrink the byte cap so it trips on the first PDU.
  proto_.set_max_correction_bytes(4);
  config_ = std::make_shared<Config>(proto_, *stats_store_.rootScope());
  makeFilter();
  ASSERT_EQ(filter_->onNewConnection(), Network::FilterStatus::Continue);

  Buffer::OwnedImpl stc("more than four bytes");
  ASSERT_EQ(filter_->onWrite(stc, false), Network::FilterStatus::Continue);
  EXPECT_EQ(fake->classify_calls_, 1);
  EXPECT_EQ(fake->finalize_calls_, 1);   // bound tripped → finalize.
  EXPECT_EQ(config_->stats().correction_bound_hit_.value(), 1);
  EXPECT_EQ(config_->stats().correction_flow_destroyed_.value(), 1);
  EXPECT_EQ(config_->stats().correction_flows_active_.value(), 0);

  // Subsequent writes are pure passthrough.
  Buffer::OwnedImpl stc2("more data");
  ASSERT_EQ(filter_->onWrite(stc2, false), Network::FilterStatus::Continue);
  EXPECT_EQ(fake->classify_calls_, 1);   // no additional classify.
}

TEST_F(QosmosDpiCorrectionTest, ResourceBoundPduCapForcesFinalize) {
  auto* fake = new FakeQosmosClassifier();
  parkHandoff(QosmosClassifierPtr(fake), plainKey("1.2.3.4", 443),
              absl::optional<bool>(true), /*bytes_already_consumed=*/0);
  proto_.set_max_correction_pdus(2);
  config_ = std::make_shared<Config>(proto_, *stats_store_.rootScope());
  makeFilter();
  ASSERT_EQ(filter_->onNewConnection(), Network::FilterStatus::Continue);

  Buffer::OwnedImpl a("abc");
  Buffer::OwnedImpl b("def");
  ASSERT_EQ(filter_->onWrite(a, false), Network::FilterStatus::Continue);
  EXPECT_EQ(fake->finalize_calls_, 0);
  ASSERT_EQ(filter_->onWrite(b, false), Network::FilterStatus::Continue);
  EXPECT_EQ(fake->finalize_calls_, 1);
  EXPECT_EQ(config_->stats().correction_bound_hit_.value(), 1);
}

TEST_F(QosmosDpiCorrectionTest, FinalStateBeforeBoundTriggersFinalize) {
  // First classifyPdu returns final_state=true → finalize should fire
  // without waiting for the byte/pdu bound. Bound stat should NOT
  // increment because this is a "clean" finalize, not a bound-hit.
  auto* fake = new FakeQosmosClassifier();
  fake->scripted_.push_back(ClassifyResult{});
  fake->scripted_.back().final_state = true;
  parkHandoff(QosmosClassifierPtr(fake), plainKey("1.2.3.4", 443),
              absl::optional<bool>(true), /*bytes_already_consumed=*/0);
  makeFilter();
  ASSERT_EQ(filter_->onNewConnection(), Network::FilterStatus::Continue);

  Buffer::OwnedImpl stc("server hello");
  ASSERT_EQ(filter_->onWrite(stc, false), Network::FilterStatus::Continue);
  EXPECT_EQ(fake->classify_calls_, 1);
  EXPECT_EQ(fake->finalize_calls_, 1);
  EXPECT_EQ(config_->stats().correction_bound_hit_.value(), 0);   // NOT bound.
  EXPECT_EQ(config_->stats().correction_flow_destroyed_.value(), 1);
}

TEST_F(QosmosDpiCorrectionTest, DestructorFinalizesUnclaimedFlow) {
  // Connection closes with the classifier still active (no final_state,
  // no bound). ~Filter must finalize it so the flow doesn't leak.
  auto* fake = new FakeQosmosClassifier();
  parkHandoff(QosmosClassifierPtr(fake), plainKey("1.2.3.4", 443),
              absl::optional<bool>(true), /*bytes_already_consumed=*/0);
  makeFilter();
  ASSERT_EQ(filter_->onNewConnection(), Network::FilterStatus::Continue);
  EXPECT_EQ(config_->stats().correction_flows_active_.value(), 1);

  filter_.reset();   // simulate connection close.
  EXPECT_EQ(fake->finalize_calls_, 1);
  EXPECT_EQ(config_->stats().correction_flow_destroyed_.value(), 1);
  EXPECT_EQ(config_->stats().correction_flows_active_.value(), 0);
}

}  // namespace
}  // namespace QosmosDpiCorrection
}  // namespace NetworkFilters
}  // namespace Extensions
}  // namespace Envoy
