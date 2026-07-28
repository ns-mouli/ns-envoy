#include "source/extensions/common/qosmos_dpi/verdict_cache.h"

#include "gtest/gtest.h"

namespace Envoy {
namespace Extensions {
namespace Common {
namespace QosmosDpi {
namespace {

VerdictCacheKey plainKey(absl::string_view ip, uint16_t port) {
  VerdictCacheKey k;
  k.dst_ip.assign(ip.data(), ip.size());
  k.dst_port = port;
  k.kind = DiscriminatorKind::Plain;
  return k;
}

VerdictCacheKey sniKey(absl::string_view ip, uint16_t port,
                       absl::string_view sni) {
  VerdictCacheKey k;
  k.dst_ip.assign(ip.data(), ip.size());
  k.dst_port = port;
  k.kind = DiscriminatorKind::Sni;
  k.discriminator_value.assign(sni.data(), sni.size());
  return k;
}

TEST(VerdictCacheTest, PutThenLookupHits) {
  VerdictCache cache(10);
  const auto k = plainKey("1.2.3.4", 443);
  EXPECT_FALSE(cache.lookup(k).has_value());
  EXPECT_TRUE(cache.put(k, /*verdict_is_web=*/true, "4pkt"));
  auto hit = cache.lookup(k);
  ASSERT_TRUE(hit.has_value());
  EXPECT_TRUE(hit->verdict_is_web);
  EXPECT_EQ(hit->source, "4pkt");
  EXPECT_FALSE(hit->final_seen);   // "4pkt" ⇒ initial
  EXPECT_EQ(cache.size(), 1U);
}

TEST(VerdictCacheTest, LookupMissReturnsNullopt) {
  VerdictCache cache(10);
  EXPECT_FALSE(cache.lookup(plainKey("9.9.9.9", 22)).has_value());
  EXPECT_EQ(cache.size(), 0U);
}

TEST(VerdictCacheTest, CorrectOverwritesEntry) {
  VerdictCache cache(10);
  const auto k = plainKey("1.2.3.4", 443);
  ASSERT_TRUE(cache.put(k, /*verdict_is_web=*/false, "4pkt"));
  // Right after put with "4pkt", the entry is not yet final.
  {
    auto pre = cache.lookup(k);
    ASSERT_TRUE(pre.has_value());
    EXPECT_FALSE(pre->final_seen);
  }
  ASSERT_TRUE(cache.correct(k, /*verdict_is_web=*/true));
  auto hit = cache.lookup(k);
  ASSERT_TRUE(hit.has_value());
  EXPECT_TRUE(hit->verdict_is_web);
  EXPECT_EQ(hit->source, "final");
  EXPECT_TRUE(hit->final_seen);    // correct() promotes to terminal.
  EXPECT_EQ(cache.size(), 1U);     // corrected in-place, no growth.
}

TEST(VerdictCacheTest, PostSilenceFinalIsAlsoFinalSeen) {
  // The correction filter's silence-hand-off path writes source =
  // "post_silence_final" when a silence-timeout flow eventually reached a
  // real classification. Same terminal semantics as "final".
  VerdictCache cache(10);
  const auto k = plainKey("1.2.3.4", 25);
  ASSERT_TRUE(cache.put(k, /*verdict_is_web=*/false, "post_silence_final"));
  auto hit = cache.lookup(k);
  ASSERT_TRUE(hit.has_value());
  EXPECT_FALSE(hit->verdict_is_web);
  EXPECT_EQ(hit->source, "post_silence_final");
  EXPECT_TRUE(hit->final_seen);
}

TEST(VerdictCacheTest, PutFinalDirectlyBypassesInitialPhase) {
  // Some paths (silence-hand-off with an already-known final verdict) write
  // "final" without any prior "4pkt" put. Cache should reflect final_seen
  // immediately.
  VerdictCache cache(10);
  const auto k = plainKey("5.6.7.8", 8080);
  ASSERT_TRUE(cache.put(k, /*verdict_is_web=*/true, "final"));
  auto hit = cache.lookup(k);
  ASSERT_TRUE(hit.has_value());
  EXPECT_TRUE(hit->final_seen);
  EXPECT_EQ(hit->source, "final");
}

TEST(VerdictCacheTest, RewriteFromFinalBackToFourPktIsPermitted) {
  // Defensive: nothing enforces monotonic promotion at the cache layer —
  // it's a policy the callers keep. If a caller does put("4pkt") over an
  // already-final entry, the entry demotes. Documents the layer contract.
  VerdictCache cache(10);
  const auto k = plainKey("5.6.7.8", 8080);
  ASSERT_TRUE(cache.put(k, /*verdict_is_web=*/true, "final"));
  ASSERT_TRUE(cache.put(k, /*verdict_is_web=*/false, "4pkt"));
  auto hit = cache.lookup(k);
  ASSERT_TRUE(hit.has_value());
  EXPECT_FALSE(hit->final_seen);
  EXPECT_EQ(hit->source, "4pkt");
  EXPECT_FALSE(hit->verdict_is_web);
}

TEST(VerdictCacheTest, MaxEntriesCapRejectsNewKeyWhenFull) {
  VerdictCache cache(2);
  EXPECT_TRUE(cache.put(plainKey("1.1.1.1", 80), true, "4pkt"));
  EXPECT_TRUE(cache.put(plainKey("2.2.2.2", 80), false, "4pkt"));
  EXPECT_EQ(cache.size(), 2U);
  // Third distinct key when full → rejected.
  EXPECT_FALSE(cache.put(plainKey("3.3.3.3", 80), true, "4pkt"));
  EXPECT_EQ(cache.size(), 2U);
  // But updating an EXISTING key when full is fine.
  EXPECT_TRUE(cache.put(plainKey("1.1.1.1", 80), false, "final"));
  auto hit = cache.lookup(plainKey("1.1.1.1", 80));
  ASSERT_TRUE(hit.has_value());
  EXPECT_FALSE(hit->verdict_is_web);
  EXPECT_EQ(hit->source, "final");
}

TEST(VerdictCacheTest, SniDiscriminatorDistinguishesSameIpPort) {
  // Two flows to the same IP:port with different SNIs are DIFFERENT keys.
  VerdictCache cache(10);
  ASSERT_TRUE(cache.put(sniKey("104.20.23.154", 443, "example.com"),
                        /*verdict_is_web=*/true, "4pkt"));
  ASSERT_TRUE(cache.put(sniKey("104.20.23.154", 443, "corp.example.com"),
                        /*verdict_is_web=*/false, "4pkt"));
  EXPECT_EQ(cache.size(), 2U);

  auto a = cache.lookup(sniKey("104.20.23.154", 443, "example.com"));
  auto b = cache.lookup(sniKey("104.20.23.154", 443, "corp.example.com"));
  ASSERT_TRUE(a.has_value());
  ASSERT_TRUE(b.has_value());
  EXPECT_TRUE(a->verdict_is_web);
  EXPECT_FALSE(b->verdict_is_web);
}

TEST(VerdictCacheTest, PlainAndSniAreDistinctEvenWithEmptySni) {
  // A Plain-keyed lookup should NOT hit an Sni-keyed entry even when the
  // Sni entry's discriminator_value happens to be empty (should never
  // happen in practice — code should always use Plain in that case — but
  // defensively verify the DiscriminatorKind byte is part of the key).
  VerdictCache cache(10);
  VerdictCacheKey plain = plainKey("1.2.3.4", 80);
  VerdictCacheKey sni_empty = sniKey("1.2.3.4", 80, "");
  ASSERT_TRUE(cache.put(plain, true, "4pkt"));
  EXPECT_FALSE(cache.lookup(sni_empty).has_value());
  EXPECT_EQ(cache.size(), 1U);
}

TEST(VerdictCacheTest, MaxEntriesZeroRejectsEverything) {
  // Degenerate configuration (max_entries=0). Every put on a new key fails.
  VerdictCache cache(0);
  EXPECT_FALSE(cache.put(plainKey("1.2.3.4", 443), true, "4pkt"));
  EXPECT_EQ(cache.size(), 0U);
}

}  // namespace
}  // namespace QosmosDpi
}  // namespace Common
}  // namespace Extensions
}  // namespace Envoy
