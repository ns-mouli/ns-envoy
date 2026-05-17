#pragma once

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace QosmosDpi {

// Hooks captured per-flow by the Qosmos engine: e.g. {"ssl:alpn": "h2"}.
// Mirrors `flow.hooks` in cfw-demux-svc/qosmos-poc/scripts/run_tests.py.
using Hooks = absl::flat_hash_map<std::string, std::string>;

// Read-only catalog driving the web/non-web cascade. Constructed once at
// QosmosEngine init from the JSON file produced by csv_to_json.py and shared
// by all Envoy worker threads as `const ProtocolTable&` — no per-worker
// duplication. Thread-safe for concurrent isWeb() calls because all members
// are const after construction.
class ProtocolTable {
public:
  // Loads from a JSON file (see scripts/csv_to_json.py for the shape).
  // Returns InvalidArgumentError on file/parse/shape errors with details
  // suitable for the listener-config validator.
  static absl::StatusOr<std::unique_ptr<ProtocolTable>>
  loadJson(const std::string& path);

  // Implements the 5-rule cascade verbatim from
  // cfw-demux-svc/qosmos-poc/scripts/run_tests.py:280-368.
  //
  //   0. Non-web ALPN (ftp/imap/smtp/...) → non-web. Runs first.
  //   1. Last token in transport_tokens or hosting_tokens AND ALPN starts
  //      with one of http_alpn_prefixes → web.
  //   2. CSV authoritative: web_apps_[last] → web/non-web. SKIPPED for
  //      hosting tokens.
  //   3. Substring fallback: any of web_substring_tokens_ in path → web.
  //   4. Default → non-web.
  //
  // Returns std::nullopt iff `path` is empty. Caller defaults that to
  // non-web (CFW) per the phase-1 fail-safe.
  std::optional<bool> isWeb(absl::string_view path, const Hooks& hooks) const;

  // Diagnostic hooks for unit tests.
  size_t numProtocols() const { return web_apps_.size(); }
  const std::string& version() const { return version_; }

private:
  ProtocolTable() = default;   // Construct via loadJson().

  std::string version_;

  // Rule 2: lowercased CSV `Name` column → CSV `web` column boolean.
  // ~5,179 entries from the current Qosmos protocol bundle.
  absl::flat_hash_map<std::string, bool> web_apps_;

  // Rule 1 / 2 supporting sets — small (≤ ~30 entries each).
  absl::flat_hash_set<std::string> transport_tokens_;
  absl::flat_hash_set<std::string> hosting_tokens_;
  absl::flat_hash_set<std::string> non_web_alpn_prefixes_;

  // Rules 1 / 3 — prefix / substring matches need ordered iteration with
  // absl::StartsWith / absl::StrContains. Sets/maps don't help.
  std::vector<std::string> http_alpn_prefixes_;
  std::vector<std::string> web_substring_tokens_;
};

}  // namespace QosmosDpi
}  // namespace ListenerFilters
}  // namespace Extensions
}  // namespace Envoy
