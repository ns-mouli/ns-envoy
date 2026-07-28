#pragma once

#include <cstdint>
#include <optional>
#include <string>

#include "envoy/thread_local/thread_local.h"

#include "absl/container/flat_hash_map.h"
#include "absl/hash/hash.h"
#include "absl/strings/string_view.h"

namespace Envoy {
namespace Extensions {
namespace Common {
namespace QosmosDpi {

// Discriminator kind attached to a cache key. All four are now sourced
// from post-classifyPdu Qosmos hooks (ssl:server_name, ssl:ja4,
// http:host), replacing the earlier pre-DPI tls_inspector-based SNI
// extraction. See envoy-qosmos/docs/verdict-cache-onData-plan.md.
//
// Priority in the discriminator hierarchy (first match wins when the
// listener filter builds a key from the classifier's hooks):
//   Sni      — TLS with server_name in ClientHello (dominant)
//   Ja4      — TLS w/o SNI (ECH, or client didn't advertise)
//   HttpHost — cleartext HTTP Host header / HTTP/2 :authority
//   Plain    — no name hint (server-first cleartext, custom TCP)
enum class DiscriminatorKind : uint8_t {
  Sni = 0,
  Ja4 = 1,
  HttpHost = 2,
  Plain = 3,
};

// Cache key: dst-ip + dst-port + optional discriminator (SNI when the
// TLS listener filter has one; otherwise Plain). Every field is const
// after construction so hashing is stable.
struct VerdictCacheKey {
  std::string dst_ip;
  uint16_t dst_port{0};
  DiscriminatorKind kind{DiscriminatorKind::Plain};
  std::string discriminator_value;   // empty when kind == Plain

  bool operator==(const VerdictCacheKey& other) const {
    return dst_port == other.dst_port && kind == other.kind &&
           dst_ip == other.dst_ip &&
           discriminator_value == other.discriminator_value;
  }

  template <typename H> friend H AbslHashValue(H h, const VerdictCacheKey& k) {
    return H::combine(std::move(h), k.dst_ip, k.dst_port,
                      static_cast<uint8_t>(k.kind), k.discriminator_value);
  }
};

// One entry in the cache.
//
// `final_seen` distinguishes the two lifecycle phases of a cache entry:
//   - false: initial verdict from the listener filter's 4-pkt cascade. An
//            owner flow is (or was) running its correction extension to
//            promote this entry. Subsequent flows that hit at this state
//            still hand off to correction to contribute an observation.
//   - true:  final verdict — the correction filter reached
//            QMDPI_RESULT_FLAGS_CLASSIFIED_FINAL_STATE (or a silence-
//            timeout hand-off reached a real classification later).
//            Subsequent flows that hit at this state short-circuit: use
//            the cached verdict, destroy the qmdpi_flow immediately,
//            skip hand-off to correction.
//
// `source` is a human-readable observability tag preserved for stats /
// debug: "4pkt" (final_seen=false), "final" (final_seen=true, standard
// path), or "post_silence_final" (final_seen=true, silence-hand-off path).
// The source→final_seen mapping is enforced by put()/correct() below —
// callers can rely on either field independently.
struct VerdictCacheEntry {
  bool verdict_is_web{false};
  bool final_seen{false};
  std::string source;
};

// Per-Envoy-worker, thread-local, unlocked cache. Bound to a QosmosEngine
// via ThreadLocal::TypedSlot<VerdictCache> (see QosmosEngine::cacheForThisThread).
// A connection's whole filter chain runs on one worker thread for its
// entire lifetime, so no locking is needed. Trade-off documented in the
// plan Part 4: destinations split across workers via SO_REUSEPORT don't
// share cache state, effective hit rate degrades roughly by 1/concurrency
// in the worst case.
//
// No TTL/expiry in this phase (deferred). max_entries_ is a simple
// reject-when-full cap: put() on a new key when at capacity returns false
// (caller records the verdict_cache_reject_full stat) rather than
// evicting. Existing keys are always updatable via put()/correct() —
// only new-key insertion is capped.
class VerdictCache : public ThreadLocal::ThreadLocalObject {
public:
  explicit VerdictCache(uint32_t max_entries) : max_entries_(max_entries) {}

  std::optional<VerdictCacheEntry> lookup(const VerdictCacheKey& key) const {
    auto it = entries_.find(key);
    if (it == entries_.end()) return std::nullopt;
    return it->second;
  }

  // Insert or update. Returns true if the entry was stored (either newly
  // inserted or an existing key updated), false iff the cache is at
  // max_entries_ and `key` is not already present.
  //
  // `final_seen` is set from `source`: the string "4pkt" implies initial
  // (final_seen=false); any other source ("final", "post_silence_final",
  // …) implies terminal (final_seen=true). This one-way mapping keeps the
  // observability tag and the hot-path bool in lock-step.
  bool put(const VerdictCacheKey& key, bool verdict_is_web,
           absl::string_view source) {
    const bool final_seen = (source != "4pkt");
    auto it = entries_.find(key);
    if (it != entries_.end()) {
      it->second.verdict_is_web = verdict_is_web;
      it->second.final_seen = final_seen;
      it->second.source.assign(source.data(), source.size());
      return true;
    }
    if (entries_.size() >= max_entries_) return false;
    entries_.emplace(key,
                     VerdictCacheEntry{
                         verdict_is_web, final_seen,
                         std::string(source.data(), source.size())});
    return true;
  }

  // Correction shorthand: put(..., "final") — implies final_seen=true.
  // Always succeeds if the key already exists (which it must — the initial
  // 4-pkt put() populated it).
  bool correct(const VerdictCacheKey& key, bool verdict_is_web) {
    return put(key, verdict_is_web, "final");
  }

  size_t size() const { return entries_.size(); }
  uint32_t maxEntries() const { return max_entries_; }

private:
  uint32_t max_entries_;
  absl::flat_hash_map<VerdictCacheKey, VerdictCacheEntry> entries_;
};

}  // namespace QosmosDpi
}  // namespace Common
}  // namespace Extensions
}  // namespace Envoy
