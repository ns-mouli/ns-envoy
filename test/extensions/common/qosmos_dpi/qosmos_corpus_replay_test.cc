// Direct-inject corpus replay test.
//
// Reads pcaps from $QOSMOS_CORPUS_ROOT (default ~/qosmos-pcaps), iterates
// every TCP stream, feeds the payload through the real shipped
// QosmosEngine + ProtocolTable cascade, and emits per-stream and aggregate
// classification results to $QOSMOS_RESULTS_DIR (default
// ~/code/cfw-demux-svc/envoy-qosmos/results) as JSON.
//
// Tier selection via $QOSMOS_CORPUS_SAMPLE_SIZE:
//   "smoke"      → ~50 pcaps stratified per app dir
//   unset/"confidence" → ~500 pcaps stratified per app dir  (default)
//   "full"       → every pcap in the corpus
//   any integer  → that many pcaps stratified per app dir
//
// Sample seed via $QOSMOS_CORPUS_SAMPLE_SEED (default 42).
//
// Bundle-version guard: if $QOSMOS_EXPECTED_BUNDLE_VERSION is set and the
// engine reports a different table version, GTEST_SKIP with a clear delta.
// Unset by default (bundle version is captured in the output for offline
// review).

#include <arpa/inet.h>
#include <sys/stat.h>

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <random>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

// The Envoy dispatcher chain drags in protobuf's coded_stream.h → absl/log/*,
// which uses `absl_nonnull`/`absl_nullable` macros. The two abseil copies
// in this workspace (`com_google_absl` and `abseil-cpp`) differ in whether
// nullability.h defines those macros. Including the newer abseil-cpp's
// nullability.h explicitly here (via absolute path in the -iquote search
// order) ensures the macros are present when protobuf later references
// them.
#include "envoy/config/core/v3/base.pb.h"                 // IWYU pragma: keep

#include "source/extensions/common/qosmos_dpi/qosmos_engine.h"

extern "C" {
#include "qmdpi_const.h"   // QMDPI_DIR_CTS / QMDPI_DIR_STC
}

#include "test/extensions/common/qosmos_dpi/pcap_reader.h"
#include "test/mocks/event/mocks.h"
#include "test/mocks/thread_local/mocks.h"

#include "absl/strings/str_cat.h"
#include "absl/strings/str_replace.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace Envoy {
namespace Extensions {
namespace Common {
namespace QosmosDpi {
namespace {

using ::testing::NiceMock;

namespace fs = std::filesystem;
using TestSupport::Chunk;
using TestSupport::Direction;
using TestSupport::PcapReader;
using TestSupport::TcpStream;

// ─────────────────────────── config helpers ───────────────────────────

std::string envOr(const char* name, const std::string& fallback) {
  const char* v = std::getenv(name);
  return (v && *v) ? std::string(v) : fallback;
}

std::string expandTilde(const std::string& path) {
  if (path.empty() || path[0] != '~') return path;
  const char* home = std::getenv("HOME");
  if (!home) return path;
  return std::string(home) + path.substr(1);
}

struct Config {
  std::string corpus_root;
  std::string results_dir;
  std::string protocol_table_path;
  std::string tier_label;         // "smoke", "confidence", "full", or "custom"
  int sample_size;                // -1 for full
  uint64_t seed;
  std::string expected_bundle_version;
  int max_streams_per_pcap;       // cap to match POC's split_tcp_streams_capped.sh
};

Config loadConfig() {
  Config c;
  c.corpus_root = expandTilde(envOr("QOSMOS_CORPUS_ROOT", "~/qosmos-pcaps"));
  c.results_dir = expandTilde(envOr(
      "QOSMOS_RESULTS_DIR", "~/code/cfw-demux-svc/envoy-qosmos/results"));
  c.protocol_table_path = expandTilde(envOr(
      "QOSMOS_PROTOCOL_TABLE_PATH",
      "~/code/cfw-demux-svc/envoy-qosmos/data/qosmos_protocols.json"));
  const std::string tier = envOr("QOSMOS_CORPUS_SAMPLE_SIZE", "confidence");
  if (tier == "smoke") { c.tier_label = "smoke"; c.sample_size = 50; }
  else if (tier == "confidence") { c.tier_label = "confidence"; c.sample_size = 500; }
  else if (tier == "full") { c.tier_label = "full"; c.sample_size = -1; }
  else {
    c.tier_label = "custom";
    try { c.sample_size = std::stoi(tier); }
    catch (...) { c.sample_size = 500; c.tier_label = "confidence"; }
  }
  c.seed = static_cast<uint64_t>(
      std::stoull(envOr("QOSMOS_CORPUS_SAMPLE_SEED", "42")));
  c.expected_bundle_version = envOr("QOSMOS_EXPECTED_BUNDLE_VERSION", "");
  // POC's split_tcp_streams_capped.sh keeps stream indices 0/1/2 (3 streams)
  // per pcap, capping the multi-thousand-stream mobile-app captures. We
  // match that default so aggregates are apples-to-apples. Set to 0 to
  // iterate every stream (needed for the ALG/PASV case in Phase 2).
  c.max_streams_per_pcap = std::stoi(envOr("QOSMOS_MAX_STREAMS_PER_PCAP", "3"));
  return c;
}

// ────────────────────── pcap discovery + sampling ──────────────────────

// Returns { app_dir_name → sorted pcap paths } across the corpus root.
std::map<std::string, std::vector<fs::path>>
discoverPcapsByApp(const fs::path& root) {
  std::map<std::string, std::vector<fs::path>> by_app;
  if (!fs::exists(root)) return by_app;
  for (auto& entry : fs::recursive_directory_iterator(root)) {
    if (!entry.is_regular_file()) continue;
    const auto& p = entry.path();
    const auto ext = p.extension().string();
    if (ext != ".pcap" && ext != ".pcapng") continue;
    // Skip anything that's obviously not a raw capture (e.g. `pcap4/*`
    // trimmed pairs from the POC — those aren't present in ~/qosmos-pcaps
    // anyway, but this makes the discovery robust if the env-var points
    // somewhere else).
    if (p.parent_path().filename() == "pcap4") continue;
    // App dir = parent directory name.
    const std::string app = p.parent_path().filename().string();
    by_app[app].push_back(p);
  }
  for (auto& [_, paths] : by_app) std::sort(paths.begin(), paths.end());
  return by_app;
}

// Stratified sample: at least 1 pcap per app, then round-robin fill to
// `target`. If target <= 0, return everything.
std::vector<fs::path>
stratifiedSample(const std::map<std::string, std::vector<fs::path>>& by_app,
                  int target, uint64_t seed) {
  std::vector<fs::path> out;
  if (target <= 0) {
    for (auto& [_, paths] : by_app) out.insert(out.end(), paths.begin(), paths.end());
    std::sort(out.begin(), out.end());
    return out;
  }
  std::mt19937_64 rng(seed);
  // Shuffle each app's pcap list deterministically once so round-robin
  // picks are stable per seed.
  std::map<std::string, std::vector<fs::path>> shuffled = by_app;
  for (auto& [_, paths] : shuffled) {
    std::shuffle(paths.begin(), paths.end(), rng);
  }
  std::vector<std::string> apps;
  apps.reserve(shuffled.size());
  for (auto& [a, _] : shuffled) apps.push_back(a);
  std::shuffle(apps.begin(), apps.end(), rng);
  // Round-robin: pick paths[0], then paths[1], ... from each app in
  // shuffled order until we hit target.
  size_t layer = 0;
  while (static_cast<int>(out.size()) < target) {
    bool progressed = false;
    for (const auto& a : apps) {
      auto& paths = shuffled[a];
      if (layer < paths.size()) {
        out.push_back(paths[layer]);
        progressed = true;
        if (static_cast<int>(out.size()) >= target) break;
      }
    }
    if (!progressed) break;
    ++layer;
  }
  return out;
}

// ───────────────────────── verdict + rule label ─────────────────────────

const char* ruleLabel(ProtocolTable::Rule r) {
  switch (r) {
    case ProtocolTable::Rule::kRule0NonWebAlpn: return "rule0_non_web_alpn";
    case ProtocolTable::Rule::kRule1TransportHostingAlpn: return "rule1_transport_hosting_alpn";
    case ProtocolTable::Rule::kRule2CsvLookup: return "rule2_csv_lookup";
    case ProtocolTable::Rule::kRule3SubstringFallback: return "rule3_substring_fallback";
    case ProtocolTable::Rule::kRule4DefaultNonWeb: return "rule4_default_non_web";
    case ProtocolTable::Rule::kNone: return "none";
  }
  return "unknown";
}

const char* verdictLabel(std::optional<bool> v) {
  if (!v.has_value()) return "undecidable";
  return *v ? "web" : "non_web";
}

// ───────────────────────── per-stream classifier ─────────────────────────

struct StreamRecord {
  std::string pcap_relpath;
  uint32_t stream_id;
  std::string initial_path;
  std::string initial_verdict;
  std::string initial_rule;
  std::string final_path;
  std::string final_verdict;
  std::string final_rule;
  bool final_state_reached{false};
  std::string final_source;    // "qosmos_final" | "last_path_fallback"
  bool engine_error{false};
  bool flipped{false};
  bool app_only_change{false}; // paths differ but verdicts don't
};

StreamRecord classifyOneStream(QosmosEngine& engine, const ProtocolTable& table,
                                const fs::path& pcap_relpath,
                                const TcpStream& stream) {
  StreamRecord rec;
  rec.pcap_relpath = pcap_relpath.string();
  rec.stream_id = stream.stream_id;

  auto classifier = engine.makeClassifier(
      stream.is_v6, stream.src_ip.data(), stream.src_port_nbo,
      stream.dst_ip.data(), stream.dst_port_nbo);
  if (!classifier) {
    rec.engine_error = true;
    rec.initial_verdict = "undecidable";
    rec.final_verdict = "undecidable";
    rec.initial_rule = "none";
    rec.final_rule = "none";
    rec.final_source = "engine_error";
    return rec;
  }

  // ── Initial verdict: first 4 PAYLOAD-BEARING packets, either direction ──
  //
  // Matches POC's split_tcp_streams_capped.sh + editcap -r ... 1-4 semantics
  // as closely as possible: POC's pcap4/* holds the first 4 wire packets
  // (SYN + SYN-ACK + ACK + first data). Our reader already skips SYN/ACKs
  // with no payload, so "first 4 chunks" here is roughly the first 4
  // application-layer PDUs, not 4 CTS-only PDUs.
  //
  // Hook accumulation: Qosmos emits attributes (e.g. ssl:alpn from the
  // ClientHello) on the specific qmdpi_result* for the classify call that
  // parsed the containing PDU. Subsequent classify results in the same
  // 4-packet window don't re-emit the same attribute, so we must merge
  // hooks across all N ≤ 4 initial calls — otherwise the first_result
  // captured on chunk 4 loses the ALPN that was emitted on chunk 1.
  // (The final-verdict loop below merges by the same rule.)
  ClassifyResult first_result;
  Hooks initial_hooks;
  int packets_seen = 0;
  size_t chunk_idx = 0;
  for (; chunk_idx < stream.chunks.size(); ++chunk_idx) {
    const auto& ch = stream.chunks[chunk_idx];
    const int dir = (ch.direction == Direction::CTS) ? QMDPI_DIR_CTS : QMDPI_DIR_STC;
    ClassifyResult r = classifier->classifyPdu(
        ch.bytes.data(), static_cast<int>(ch.bytes.size()), dir, /*tenant=*/1);
    if (r.engine_error) rec.engine_error = true;
    for (auto& kv : r.hooks) initial_hooks.try_emplace(kv.first, kv.second);
    first_result = r;
    if (++packets_seen >= 4) { ++chunk_idx; break; }
  }
  const std::string initial_path = first_result.intermediate_path;
  ProtocolTable::Rule initial_rule = ProtocolTable::Rule::kNone;
  auto initial_verdict = table.isWebWithRule(initial_path, initial_hooks, initial_rule);
  rec.initial_path = initial_path;
  rec.initial_verdict = verdictLabel(initial_verdict);
  rec.initial_rule = ruleLabel(initial_rule);

  // ── Continue feeding remaining chunks until final_state or EOF ──
  ClassifyResult last_result = first_result;
  Hooks merged_hooks = initial_hooks;
  for (; chunk_idx < stream.chunks.size(); ++chunk_idx) {
    const auto& ch = stream.chunks[chunk_idx];
    const int dir = (ch.direction == Direction::CTS) ? QMDPI_DIR_CTS : QMDPI_DIR_STC;
    ClassifyResult r = classifier->classifyPdu(
        ch.bytes.data(), static_cast<int>(ch.bytes.size()), dir, /*tenant=*/1);
    if (r.engine_error) rec.engine_error = true;
    last_result = r;
    for (auto& kv : r.hooks) merged_hooks.try_emplace(kv.first, kv.second);
    if (r.final_state) break;
  }
  rec.final_state_reached = last_result.final_state;

  // ── Finalize: capture engine's own final path ──
  ClassifyResult finalize_result = classifier->finalize();
  if (finalize_result.engine_error) rec.engine_error = true;
  for (auto& kv : finalize_result.hooks) merged_hooks.try_emplace(kv.first, kv.second);
  std::string final_path;
  if (!finalize_result.final_path.empty()) {
    final_path = finalize_result.final_path;
    rec.final_source = "qosmos_final";
  } else {
    final_path = last_result.intermediate_path;
    rec.final_source = "last_path_fallback";
  }
  ProtocolTable::Rule final_rule = ProtocolTable::Rule::kNone;
  auto final_verdict = table.isWebWithRule(final_path, merged_hooks, final_rule);
  rec.final_path = final_path;
  rec.final_verdict = verdictLabel(final_verdict);
  rec.final_rule = ruleLabel(final_rule);
  rec.flipped = (rec.initial_verdict != rec.final_verdict);
  rec.app_only_change =
      (!rec.flipped && rec.initial_path != rec.final_path);
  return rec;
}

// ──────────────────────────── JSON emitter ────────────────────────────
// Small hand-rolled JSON writer — avoids pulling in a dependency for a
// single output file.

std::string jsonEscape(absl::string_view s) {
  std::string out;
  out.reserve(s.size() + 2);
  for (char c : s) {
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (static_cast<unsigned char>(c) < 0x20) {
          char buf[8];
          std::snprintf(buf, sizeof(buf), "\\u%04x", c);
          out += buf;
        } else {
          out += c;
        }
    }
  }
  return out;
}

std::string jsonString(absl::string_view s) {
  return absl::StrCat("\"", jsonEscape(s), "\"");
}

// ────────────────────────────── the test ──────────────────────────────

class QosmosCorpusReplayTest : public ::testing::Test {
protected:
  void SetUp() override {
    tls_.setDispatcher(&dispatcher_);
  }
  void TearDown() override {
    // Reset TLS-owned qosmos objects on the main thread before engine dtor.
    tls_.shutdownThread();
  }
  NiceMock<Event::MockDispatcher> dispatcher_{"main"};
  NiceMock<ThreadLocal::MockInstance> tls_;
};

TEST_F(QosmosCorpusReplayTest, ReplayCorpus) {
  const Config cfg = loadConfig();

  if (!fs::exists(cfg.corpus_root)) {
    GTEST_SKIP() << "QOSMOS_CORPUS_ROOT does not exist: " << cfg.corpus_root;
  }
  if (!fs::exists(cfg.protocol_table_path)) {
    GTEST_SKIP() << "protocol table not found: " << cfg.protocol_table_path;
  }
  fs::create_directories(cfg.results_dir);

  // Bring up the real engine — cache disabled, single worker.
  auto engine = std::make_shared<QosmosEngine>(
      /*engine_config=*/"",
      /*bundle_path=*/"",
      cfg.protocol_table_path,
      /*nb_workers=*/1,
      tls_,
      /*verdict_cache_max_entries=*/0,
      /*total_nb_flows=*/0);

  const ProtocolTable& table = engine->table();
  const std::string table_version = std::string(table.version());
  std::cerr << "[qosmos-corpus] protocol table version: " << table_version
            << " (" << table.numProtocols() << " protocols)" << std::endl;

  if (!cfg.expected_bundle_version.empty() &&
      cfg.expected_bundle_version != table_version) {
    GTEST_SKIP() << "bundle version mismatch: expected='"
                 << cfg.expected_bundle_version << "' got='"
                 << table_version << "'";
  }

  auto by_app = discoverPcapsByApp(cfg.corpus_root);
  ASSERT_FALSE(by_app.empty()) << "no pcaps found under " << cfg.corpus_root;
  const auto sampled =
      stratifiedSample(by_app, cfg.sample_size, cfg.seed);
  ASSERT_FALSE(sampled.empty());
  std::cerr << "[qosmos-corpus] tier='" << cfg.tier_label << "' target="
            << cfg.sample_size << " sampled=" << sampled.size()
            << " app_dirs=" << by_app.size() << std::endl;

  // Per-stream records.
  std::vector<StreamRecord> records;
  size_t unprocessable_pcaps = 0;
  size_t streams_total = 0, streams_with_error = 0;
  size_t flips_total = 0, flips_non_web_to_web = 0, flips_web_to_non_web = 0;
  size_t app_only_changes = 0;
  size_t final_state_count = 0, last_path_fallback_count = 0;
  std::map<std::string, size_t> rule_hits_initial, rule_hits_final;

  const auto corpus_root_abs = fs::absolute(cfg.corpus_root);
  size_t pcap_idx = 0;
  for (const auto& pcap_path : sampled) {
    ++pcap_idx;
    auto streams_or = PcapReader::readAllStreams(pcap_path.string());
    if (!streams_or.ok() || streams_or->empty()) {
      ++unprocessable_pcaps;
      if (pcap_idx <= 5 || pcap_idx % 100 == 0) {
        std::cerr << "[qosmos-corpus] " << pcap_idx << "/" << sampled.size()
                  << " unprocessable: " << pcap_path.string()
                  << (streams_or.ok() ? " (no streams)" : " (" + std::string(streams_or.status().message()) + ")")
                  << std::endl;
      }
      continue;
    }
    fs::path rel = fs::relative(pcap_path, corpus_root_abs);
    int streams_processed_this_pcap = 0;
    for (const auto& stream : *streams_or) {
      if (cfg.max_streams_per_pcap > 0 &&
          streams_processed_this_pcap >= cfg.max_streams_per_pcap) {
        break;
      }
      ++streams_processed_this_pcap;
      StreamRecord r = classifyOneStream(*engine, table, rel, stream);
      ++streams_total;
      if (r.engine_error) ++streams_with_error;
      if (r.flipped) {
        ++flips_total;
        if (r.initial_verdict == "non_web" && r.final_verdict == "web") ++flips_non_web_to_web;
        else if (r.initial_verdict == "web" && r.final_verdict == "non_web") ++flips_web_to_non_web;
      }
      if (r.app_only_change) ++app_only_changes;
      if (r.final_state_reached) ++final_state_count;
      else ++last_path_fallback_count;
      ++rule_hits_initial[r.initial_rule];
      ++rule_hits_final[r.final_rule];
      records.push_back(std::move(r));
    }
    if (pcap_idx % 25 == 0 || pcap_idx == sampled.size()) {
      std::cerr << "[qosmos-corpus] progress " << pcap_idx << "/"
                << sampled.size() << " streams=" << streams_total
                << " flips=" << flips_total << std::endl;
    }
  }

  // ── Write summary JSON ──
  const std::string out_path = cfg.results_dir + "/direct_inject_" +
                                cfg.tier_label + "_summary.json";
  std::ofstream out(out_path, std::ios::binary | std::ios::trunc);
  ASSERT_TRUE(out.is_open()) << "cannot open " << out_path;
  out << "{\n";
  out << "  \"tier\": " << jsonString(cfg.tier_label) << ",\n";
  out << "  \"corpus_root\": " << jsonString(cfg.corpus_root) << ",\n";
  out << "  \"protocol_table_path\": " << jsonString(cfg.protocol_table_path) << ",\n";
  out << "  \"protocol_table_version\": " << jsonString(table_version) << ",\n";
  out << "  \"sample_target\": " << cfg.sample_size << ",\n";
  out << "  \"sample_seed\": " << cfg.seed << ",\n";
  out << "  \"max_streams_per_pcap\": " << cfg.max_streams_per_pcap << ",\n";
  out << "  \"sampled_pcaps\": " << sampled.size() << ",\n";
  out << "  \"app_dirs\": " << by_app.size() << ",\n";
  out << "  \"aggregates\": {\n";
  out << "    \"pcaps_seen\": " << sampled.size() << ",\n";
  out << "    \"unprocessable_pcaps\": " << unprocessable_pcaps << ",\n";
  out << "    \"streams_total\": " << streams_total << ",\n";
  out << "    \"streams_with_engine_error\": " << streams_with_error << ",\n";
  out << "    \"flip_count\": " << flips_total << ",\n";
  out << "    \"flip_rate_percent\": " << (streams_total == 0 ? 0.0 :
       100.0 * static_cast<double>(flips_total) / static_cast<double>(streams_total)) << ",\n";
  out << "    \"non_web_to_web_flips\": " << flips_non_web_to_web << ",\n";
  out << "    \"web_to_non_web_flips\": " << flips_web_to_non_web << ",\n";
  out << "    \"app_only_changes\": " << app_only_changes << ",\n";
  out << "    \"final_state_reached\": " << final_state_count << ",\n";
  out << "    \"last_path_fallback\": " << last_path_fallback_count << ",\n";
  out << "    \"rule_hits_initial\": {";
  {
    bool first = true;
    for (const auto& [k, v] : rule_hits_initial) {
      out << (first ? "" : ", ") << jsonString(k) << ": " << v;
      first = false;
    }
  }
  out << "},\n";
  out << "    \"rule_hits_final\": {";
  {
    bool first = true;
    for (const auto& [k, v] : rule_hits_final) {
      out << (first ? "" : ", ") << jsonString(k) << ": " << v;
      first = false;
    }
  }
  out << "}\n";
  out << "  },\n";
  out << "  \"streams\": [\n";
  for (size_t i = 0; i < records.size(); ++i) {
    const auto& r = records[i];
    out << "    {"
        << "\"pcap\": " << jsonString(r.pcap_relpath)
        << ", \"stream_id\": " << r.stream_id
        << ", \"initial_path\": " << jsonString(r.initial_path)
        << ", \"initial_verdict\": " << jsonString(r.initial_verdict)
        << ", \"initial_rule\": " << jsonString(r.initial_rule)
        << ", \"final_path\": " << jsonString(r.final_path)
        << ", \"final_verdict\": " << jsonString(r.final_verdict)
        << ", \"final_rule\": " << jsonString(r.final_rule)
        << ", \"final_state_reached\": " << (r.final_state_reached ? "true" : "false")
        << ", \"final_source\": " << jsonString(r.final_source)
        << ", \"flipped\": " << (r.flipped ? "true" : "false")
        << ", \"app_only_change\": " << (r.app_only_change ? "true" : "false")
        << ", \"engine_error\": " << (r.engine_error ? "true" : "false")
        << "}" << (i + 1 == records.size() ? "" : ",") << "\n";
  }
  out << "  ]\n";
  out << "}\n";
  out.close();

  std::cerr << "[qosmos-corpus] wrote " << out_path << std::endl;
  std::cerr << "[qosmos-corpus] streams=" << streams_total
            << " flips=" << flips_total
            << " ntw=" << flips_non_web_to_web
            << " wtn=" << flips_web_to_non_web
            << " app_only=" << app_only_changes
            << " unprocessable_pcaps=" << unprocessable_pcaps
            << std::endl;

  // Non-fatal sanity: expect at least *some* streams to have classified.
  EXPECT_GT(streams_total, 0u);
  // Engine errors should be a small fraction — POC saw ~0.95% unprocessable.
  if (streams_total > 0) {
    const double err_rate = 100.0 *
        static_cast<double>(streams_with_error) / static_cast<double>(streams_total);
    EXPECT_LT(err_rate, 10.0) << "engine error rate too high: " << err_rate << "%";
  }
}

// Experiment: would classifying the SNI alone (qmdpi_worker_process_fqdn) on
// the first packet give the CORRECTED verdict — i.e. fix the ALPN-driven
// web-bias without destroying the flow? Reads a TSV from $QOSMOS_FQDN_INPUT:
//   name<TAB>sni<TAB>corrected_verdict     (corrected in {web, non-web})
// For each, resolves the FQDN path, scores it through the same cascade, and
// compares to `corrected`. Writes results to $QOSMOS_FQDN_OUT (default
// <results_dir>/fqdn_probe.tsv). GTEST_SKIP if no input provided.
TEST_F(QosmosCorpusReplayTest, FqdnProbe) {
  const Config cfg = loadConfig();
  const std::string input = envOr("QOSMOS_FQDN_INPUT", "");
  if (input.empty() || !fs::exists(input)) {
    GTEST_SKIP() << "set QOSMOS_FQDN_INPUT to a TSV (name<TAB>sni<TAB>corrected)";
  }
  if (!fs::exists(cfg.protocol_table_path)) {
    GTEST_SKIP() << "protocol table not found: " << cfg.protocol_table_path;
  }
  fs::create_directories(cfg.results_dir);

  auto engine = std::make_shared<QosmosEngine>(
      /*engine_config=*/"", /*bundle_path=*/"", cfg.protocol_table_path,
      /*nb_workers=*/1, tls_, /*verdict_cache_max_entries=*/0,
      /*total_nb_flows=*/0);
  const ProtocolTable& table = engine->table();
  std::cerr << "[fqdn-probe] table version: " << table.version() << std::endl;

  // One worker-backed classifier (dummy 5-tuple); classifyFqdn ignores the flow.
  const uint8_t sip[4] = {10, 0, 0, 2};
  const uint8_t dip[4] = {1, 1, 1, 1};
  auto classifier = engine->makeClassifier(/*is_v6=*/false, sip, htons(12345),
                                            dip, htons(443));
  ASSERT_TRUE(classifier != nullptr);

  const std::string out_path =
      envOr("QOSMOS_FQDN_OUT", cfg.results_dir + "/fqdn_probe.tsv");
  std::ofstream out(out_path);
  out << "name\tsni\tfqdn_path\tfqdn_verdict\tcorrected\tmatch\n";

  std::ifstream in(input);
  std::string line;
  size_t total = 0, resolved = 0, matched = 0, empty_sni = 0;
  while (std::getline(in, line)) {
    if (line.empty() || line[0] == '#') {
      continue;
    }
    const size_t t1 = line.find('\t');
    const size_t t2 = (t1 == std::string::npos) ? std::string::npos
                                                 : line.find('\t', t1 + 1);
    if (t1 == std::string::npos || t2 == std::string::npos) {
      continue;
    }
    const std::string name = line.substr(0, t1);
    const std::string sni = line.substr(t1 + 1, t2 - t1 - 1);
    std::string corrected = line.substr(t2 + 1);
    const size_t t3 = corrected.find('\t');  // ignore any trailing columns
    if (t3 != std::string::npos) {
      corrected = corrected.substr(0, t3);
    }
    ++total;
    if (sni.empty() || sni == "-") {
      ++empty_sni;
      out << name << "\t" << sni << "\t\t(no-sni)\t" << corrected << "\tNA\n";
      continue;
    }
    const std::string path = classifier->classifyFqdn(sni);
    ProtocolTable::Rule rule = ProtocolTable::Rule::kNone;
    const std::string verdict =
        path.empty() ? "unresolved"
                     : verdictLabel(table.isWebWithRule(path, Hooks{}, rule));
    if (!path.empty()) {
      ++resolved;
    }
    // verdictLabel() renders "non_web"; callers may pass "non-web" — compare
    // canonically so the hyphen/underscore spelling doesn't matter.
    auto canon = [](std::string v) {
      std::replace(v.begin(), v.end(), '-', '_');
      return v;
    };
    const bool match = (canon(verdict) == canon(corrected));
    if (match) {
      ++matched;
    }
    out << name << "\t" << sni << "\t" << path << "\t" << verdict << "\t"
        << corrected << "\t" << (match ? "YES" : "no") << "\n";
  }
  out.close();

  std::cerr << "[fqdn-probe] cases=" << total << " with_sni=" << (total - empty_sni)
            << " fqdn_resolved_path=" << resolved
            << " fqdn_verdict==corrected=" << matched << " -> "
            << (total ? 100.0 * matched / total : 0.0) << "% of all, "
            << ((total - empty_sni) ? 100.0 * matched / (total - empty_sni) : 0.0)
            << "% of with-sni" << std::endl;
  std::cerr << "[fqdn-probe] wrote " << out_path << std::endl;
  EXPECT_GT(total, 0u);
}

}  // namespace
}  // namespace QosmosDpi
}  // namespace Common
}  // namespace Extensions
}  // namespace Envoy
