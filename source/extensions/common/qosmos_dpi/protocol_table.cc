#include "source/extensions/common/qosmos_dpi/protocol_table.h"

#include <fstream>
#include <sstream>

#include "source/common/common/thread.h"
#include "source/common/json/json_loader.h"

#include "absl/strings/ascii.h"
#include "absl/strings/match.h"
#include "absl/strings/str_split.h"

namespace Envoy {
namespace Extensions {
namespace Common {
namespace QosmosDpi {

namespace {

// Read entire file into a std::string. We avoid pulling in
// Filesystem::Instance because ProtocolTable is constructed at filter init
// before any thread/dispatcher exists; std::ifstream is sufficient and keeps
// the dependency surface small.
absl::StatusOr<std::string> slurpFile(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return absl::InvalidArgumentError("qosmos_dpi: cannot open " + path);
  }
  std::ostringstream ss;
  ss << in.rdbuf();
  return ss.str();
}

// Helper: load a JSON top-level array of strings into a string container.
// v1.32.4's Json::Object getters throw Json::Exception on malformed input
// (no …NoThrow variants besides getObjectNoThrow) — this propagates up to
// the TRY_NEEDS_AUDIT/CATCH in loadJson() below, which is the only caller.
template <typename Container>
void loadStringArray(const Json::Object& root, const std::string& field,
                     Container& out) {
  for (const auto& s : root.getStringArray(field, /*allow_empty=*/true)) {
    out.insert(out.end(), absl::AsciiStrToLower(s));
  }
}

}  // namespace

absl::StatusOr<std::unique_ptr<ProtocolTable>>
ProtocolTable::loadJson(const std::string& path) {
  auto json_or = slurpFile(path);
  if (!json_or.ok()) return json_or.status();

  // v1.32.4's whole Json::Object getter surface (getString, getStringArray,
  // getObjectArray, getBoolean, getObject) throws Json::Exception rather
  // than returning StatusOr — unlike main, where it's all StatusOr-based.
  // Wrap the body in one TRY/CATCH instead of per-call status checks; every
  // Json::Exception funnels into the same absl::InvalidArgumentError.
  TRY_NEEDS_AUDIT {
    auto root_or = Json::Factory::loadFromStringNoThrow(*json_or);
    if (!root_or.ok()) {
      return absl::InvalidArgumentError(
          "qosmos_dpi: failed to parse " + path + ": " +
          std::string(root_or.status().message()));
    }
    const auto& root = **root_or;

    auto table = std::unique_ptr<ProtocolTable>(new ProtocolTable());

    // version is informational; tolerate absence.
    table->version_ = root.getString("version", "unknown");

    // Token sets / ordered lists.
    loadStringArray(root, "transport_tokens", table->transport_tokens_);
    loadStringArray(root, "hosting_tokens", table->hosting_tokens_);
    loadStringArray(root, "non_web_alpn_prefixes", table->non_web_alpn_prefixes_);
    loadStringArray(root, "http_alpn_prefixes", table->http_alpn_prefixes_);
    loadStringArray(root, "web_substring_tokens", table->web_substring_tokens_);

    // Per-protocol web_apps_ map.
    auto protos = root.getObjectArray("protocols", /*allow_empty=*/false);
    table->web_apps_.reserve(protos.size());
    for (const auto& proto : protos) {
      const std::string name = proto->getString("name");
      const bool web = proto->getBoolean("web", false);
      table->web_apps_[absl::AsciiStrToLower(name)] = web;
    }

    return table;
  }
  CATCH(const EnvoyException& e, {
    return absl::InvalidArgumentError(
        "qosmos_dpi: failed to parse " + path + ": " + std::string(e.what()));
  })
  END_TRY
}

namespace {

// Lower-case copy. The cascade compares everything in lower case to match
// the qosmos-poc reference (`tokens = path.lower().split(".")`).
std::string toLower(absl::string_view s) {
  return absl::AsciiStrToLower(s);
}

// Split path on '.' and return the lowercased last segment, or empty if path
// is empty. Mirrors run_tests.py:343 (`tokens = path.lower().split(".") ;
// last = tokens[-1] if tokens else ""`).
std::string lastTokenLower(absl::string_view path) {
  if (path.empty()) return {};
  std::string lower = toLower(path);
  auto dot = lower.find_last_of('.');
  if (dot == std::string::npos) return lower;
  return lower.substr(dot + 1);
}

// Split a comma-separated ALPN string into individual lowercased values
// with surrounding whitespace stripped. The Qosmos engine emits ALPN as
// the client's full preference order (e.g. "h2, http/1.1"); rules 0 and
// 1 must inspect each entry independently.
std::vector<std::string> splitAlpnLower(absl::string_view alpn_csv) {
  std::vector<std::string> out;
  for (auto piece : absl::StrSplit(alpn_csv, ',')) {
    auto trimmed = absl::StripAsciiWhitespace(piece);
    if (!trimmed.empty()) {
      out.emplace_back(toLower(trimmed));
    }
  }
  return out;
}

// Run-tests.py rule 0 helper: ALPN value v matches non-web prefix p iff
// v == p OR v starts with p + "-" (so "ftp-data" matches "ftp", "imap-foo"
// matches "imap"). Note this is `prefix + "-"` matching, NOT pure
// startsWith — must match the qosmos-poc semantics exactly.
bool alpnMatchesNonWeb(absl::string_view value, absl::string_view prefix) {
  if (value == prefix) return true;
  if (value.size() > prefix.size() && value[prefix.size()] == '-' &&
      value.substr(0, prefix.size()) == prefix) {
    return true;
  }
  return false;
}

}  // namespace

std::optional<bool> ProtocolTable::isWeb(absl::string_view path,
                                         const Hooks& hooks) const {
  Rule ignored = Rule::kNone;
  return isWebWithRule(path, hooks, ignored);
}

std::optional<bool> ProtocolTable::isWebWithRule(absl::string_view path,
                                                  const Hooks& hooks,
                                                  Rule& rule_out) const {
  rule_out = Rule::kNone;
  // The cascade is undecidable when we have no path at all; the caller
  // defaults to non-web (CFW) per phase-1 fail-safe.
  if (path.empty()) return std::nullopt;

  // ALPN can arrive as a comma-separated list; match each entry independently.
  std::vector<std::string> alpn_values;
  if (auto it = hooks.find("ssl:alpn"); it != hooks.end()) {
    alpn_values = splitAlpnLower(it->second);
  }

  // ── Rule 0: Non-web ALPN beats every other signal ──
  for (const auto& v : alpn_values) {
    for (const auto& p : non_web_alpn_prefixes_) {
      if (alpnMatchesNonWeb(v, p)) {
        rule_out = Rule::kRule0NonWebAlpn;
        return false;  // non-web
      }
    }
  }

  const std::string last = lastTokenLower(path);

  // ── Rule 1: transport/hosting last token + HTTP ALPN → web ──
  // Catches HTTPS-on-CDN (`ssl.amazon_aws`) and HTTPS-on-untyped-host
  // (`ssl.unknown`) where Qosmos didn't pin an inner app but the client's
  // ALPN says HTTP.
  const bool last_is_transport = transport_tokens_.contains(last);
  const bool last_is_hosting = hosting_tokens_.contains(last);
  if (last_is_transport || last_is_hosting) {
    for (const auto& v : alpn_values) {
      for (const auto& p : http_alpn_prefixes_) {
        if (absl::StartsWith(v, p)) {
          rule_out = Rule::kRule1TransportHostingAlpn;
          return true;  // web
        }
      }
    }
  }

  // ── Rule 2: CSV authoritative — SKIPPED for hosting tokens ──
  // The CSV marks hosting tokens (amazon_aws/gcp/cloudflare/...) as
  // web=true in aggregate, but individual flows can be non-web (FTPS-on-AWS).
  // Skipping rule 2 for them lets rule 4 default to non-web → CFW, which
  // is the safer error asymmetry.
  if (!last_is_hosting) {
    if (auto it = web_apps_.find(last); it != web_apps_.end()) {
      // Distinguish a real app pin from a CSV row that merely happens to
      // exist for a transport token (`ssl`, `tcp`, `quic`, `unknown`, …).
      // The VERDICT is unchanged either way — deliberately, so this stays
      // behaviour-neutral for every existing caller of isWeb(). Only the
      // reported rule differs, which lets the FQDN-refine guard tell "the
      // cascade identified the app" apart from "the cascade only got as far
      // as the transport".
      rule_out = last_is_transport ? Rule::kRule2CsvLookupTransport
                                    : Rule::kRule2CsvLookup;
      return it->second;  // CSV-authoritative web/non-web
    }
  }

  // ── Rule 3: Substring fallback ──
  // Fires when the CSV doesn't know the app (new bundle entries, or no
  // CSV on this host). E.g. `unknown_websocket` → web by virtue of
  // containing "websocket".
  const std::string lowered = toLower(path);
  for (const auto& token : web_substring_tokens_) {
    if (absl::StrContains(lowered, token)) {
      rule_out = Rule::kRule3SubstringFallback;
      return true;  // web
    }
  }

  // ── Rule 4: Default ──
  rule_out = Rule::kRule4DefaultNonWeb;
  return false;  // non-web
}

}  // namespace QosmosDpi
}  // namespace Common
}  // namespace Extensions
}  // namespace Envoy
