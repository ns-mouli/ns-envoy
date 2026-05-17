#include <fstream>
#include <string>

#include "source/extensions/filters/listener/qosmos_dpi/protocol_table.h"

#include "test/test_common/environment.h"

#include "gtest/gtest.h"

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace QosmosDpi {
namespace {

// Minimal in-test JSON fixture: a few CSV-derived protocols plus the five
// token sets. Mirrors the shape produced by scripts/csv_to_json.py.
// We intentionally hand-craft the protocols list to make the cascade rules
// observable in isolation rather than depending on a 5K-entry generated
// JSON. The full data/qosmos_protocols.json is exercised by the integration
// test (see qosmos_dpi_integration_test.cc).
constexpr absl::string_view kFixtureJson = R"json({
  "version": "test-fixture",
  "transport_tokens":      ["base", "ip", "tcp", "udp", "ssl", "tls", "quic", "unknown"],
  "hosting_tokens":        ["amazon_aws", "gcp", "cloudflare"],
  "http_alpn_prefixes":    ["h2", "h3", "http/1.0", "http/1.1"],
  "non_web_alpn_prefixes": ["ftp", "imap", "smtp", "smb"],
  "web_substring_tokens":  ["http", "websocket"],
  "protocols": [
    { "name": "http",        "web": true  },
    { "name": "ssl",         "web": false },
    { "name": "ftp",         "web": false },
    { "name": "smtp",        "web": false },
    { "name": "websocket",   "web": true  },
    { "name": "http_proxy",  "web": true  },
    { "name": "amazon_aws",  "web": true  },
    { "name": "gcp",         "web": true  }
  ]
})json";

class ProtocolTableTest : public ::testing::Test {
protected:
  static std::unique_ptr<ProtocolTable> loadFixture() {
    const std::string path =
        TestEnvironment::temporaryPath("qosmos_protocols_fixture.json");
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out << kFixtureJson;
    out.close();
    auto status_or = ProtocolTable::loadJson(path);
    EXPECT_TRUE(status_or.ok()) << status_or.status().message();
    return std::move(status_or).value();
  }

  static Hooks alpn(absl::string_view value) {
    Hooks h;
    h["ssl:alpn"] = std::string(value);
    return h;
  }
};

// ── Loader sanity ──

TEST_F(ProtocolTableTest, LoadsExpectedShape) {
  auto t = loadFixture();
  EXPECT_EQ(t->version(), "test-fixture");
  EXPECT_EQ(t->numProtocols(), 8u);
}

TEST_F(ProtocolTableTest, EmptyPathReturnsNullopt) {
  auto t = loadFixture();
  EXPECT_FALSE(t->isWeb("", {}).has_value());
}

// ── Rule 0: Non-web ALPN beats everything ──

TEST_F(ProtocolTableTest, Rule0_NonWebAlpnFtpReturnsNonWeb) {
  auto t = loadFixture();
  // Even though path ends in "unknown" (transport) and ALPN h2 would
  // normally win rule 1 → web, the explicit ftp ALPN comes first.
  Hooks h;
  h["ssl:alpn"] = "ftp, h2";
  EXPECT_EQ(t->isWeb("base.ip.tcp.ssl.unknown", h), false);
}

TEST_F(ProtocolTableTest, Rule0_FtpDataDashSuffixMatch) {
  auto t = loadFixture();
  // alpnMatchesNonWeb special-cases prefix-with-dash so "ftp-data"
  // matches the "ftp" prefix.
  EXPECT_EQ(t->isWeb("base.ip.tcp.ssl.unknown", alpn("ftp-data")), false);
}

TEST_F(ProtocolTableTest, Rule0_SmtpAlpn) {
  auto t = loadFixture();
  EXPECT_EQ(t->isWeb("base.ip.tcp.ssl.amazon_aws", alpn("smtp")), false);
}

// ── Rule 1: transport/hosting last token + HTTP ALPN → web ──

TEST_F(ProtocolTableTest, Rule1_SslUnknownWithHttp2AlpnIsWeb) {
  auto t = loadFixture();
  EXPECT_EQ(t->isWeb("base.ip.tcp.ssl.unknown", alpn("h2")), true);
}

TEST_F(ProtocolTableTest, Rule1_SslAmazonAwsWithHttp1AlpnIsWeb) {
  auto t = loadFixture();
  EXPECT_EQ(t->isWeb("base.ip.tcp.ssl.amazon_aws", alpn("http/1.1")), true);
}

TEST_F(ProtocolTableTest, Rule1_AlpnListWithHttpEntryStillWeb) {
  auto t = loadFixture();
  // ALPN list "spdy, h2" — h2 entry should fire rule 1.
  EXPECT_EQ(t->isWeb("base.ip.tcp.ssl.unknown", alpn("spdy, h2")), true);
}

// ── Rule 2: CSV authoritative — but skipped for hosting tokens ──

TEST_F(ProtocolTableTest, Rule2_HttpPathIsWeb) {
  auto t = loadFixture();
  EXPECT_EQ(t->isWeb("base.ip.tcp.http", {}), true);
}

TEST_F(ProtocolTableTest, Rule2_FtpPathIsNonWeb) {
  auto t = loadFixture();
  EXPECT_EQ(t->isWeb("base.ip.tcp.ftp", {}), false);
}

TEST_F(ProtocolTableTest, Rule2_HttpProxyMatchesCsvNotSubstring) {
  auto t = loadFixture();
  // http_proxy is set web=true in the CSV. The substring rule 3 would
  // also fire for "http", but rule 2 runs first. The point of this
  // test is to confirm rule 2 short-circuits (we'd see the same answer
  // here, so it's mostly a documentation test for the precedence).
  EXPECT_EQ(t->isWeb("base.ip.tcp.http_proxy", {}), true);
}

TEST_F(ProtocolTableTest, Rule2_HostingTokenSkippedWithoutAlpn) {
  auto t = loadFixture();
  // amazon_aws is web=true in the CSV, but rule 2 SKIPS hosting tokens.
  // No HTTP ALPN ⇒ rule 1 doesn't fire either ⇒ rule 4 default non-web.
  EXPECT_EQ(t->isWeb("base.ip.tcp.ssl.amazon_aws", {}), false);
}

TEST_F(ProtocolTableTest, Rule2_HostingTokenWithHttpAlpnGoesWebViaRule1) {
  auto t = loadFixture();
  EXPECT_EQ(t->isWeb("base.ip.tcp.ssl.gcp", alpn("h3")), true);
}

// ── Rule 3: substring fallback ──

TEST_F(ProtocolTableTest, Rule3_PathWithUnknownAppContainingHttpIsWeb) {
  auto t = loadFixture();
  // Path token not in CSV (rule 2 misses) but contains "http" substring.
  EXPECT_EQ(t->isWeb("base.ip.tcp.something_http_thing", {}), true);
}

TEST_F(ProtocolTableTest, Rule3_PathContainingWebsocketIsWeb) {
  auto t = loadFixture();
  EXPECT_EQ(t->isWeb("base.ip.tcp.unknown_websocket", {}), true);
}

// ── Rule 4: default non-web ──

TEST_F(ProtocolTableTest, Rule4_UnclassifiedPathDefaultsNonWeb) {
  auto t = loadFixture();
  // CSV miss (no entry for "novelapp"), no substrings matched, no ALPN.
  // Should fall to rule 4 default → non-web.
  EXPECT_EQ(t->isWeb("base.ip.tcp.novelapp", {}), false);
}

TEST_F(ProtocolTableTest, Rule4_TransportLastTokenWithoutAlpnDefaultsNonWeb) {
  auto t = loadFixture();
  // ssl.unknown without ALPN — rule 1 needs HTTP ALPN, rule 2 skipped
  // (transport, then for "unknown" CSV miss), rule 3 no http/websocket
  // substring → rule 4 default non-web.
  EXPECT_EQ(t->isWeb("base.ip.tcp.ssl.unknown", {}), false);
}

// ── Loader error paths ──

TEST_F(ProtocolTableTest, MissingFileReturnsError) {
  auto status_or =
      ProtocolTable::loadJson("/this/path/does/not/exist.json");
  EXPECT_FALSE(status_or.ok());
}

TEST_F(ProtocolTableTest, MalformedJsonReturnsError) {
  const std::string path =
      TestEnvironment::temporaryPath("qosmos_bad.json");
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  out << "{ this is not json";
  out.close();
  auto status_or = ProtocolTable::loadJson(path);
  EXPECT_FALSE(status_or.ok());
}

TEST_F(ProtocolTableTest, MissingProtocolsArrayReturnsError) {
  const std::string path =
      TestEnvironment::temporaryPath("qosmos_no_protocols.json");
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  out << R"json({
    "version": "x",
    "transport_tokens": [],
    "hosting_tokens": [],
    "http_alpn_prefixes": [],
    "non_web_alpn_prefixes": [],
    "web_substring_tokens": []
  })json";
  out.close();
  auto status_or = ProtocolTable::loadJson(path);
  EXPECT_FALSE(status_or.ok());
}

}  // namespace
}  // namespace QosmosDpi
}  // namespace ListenerFilters
}  // namespace Extensions
}  // namespace Envoy
