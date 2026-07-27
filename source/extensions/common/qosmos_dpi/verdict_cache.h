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

// Discriminator kind attached to a cache key. JA4 is not usable pre-DPI
// (it comes from Qosmos's own `ssl:ja4` hook), so phase-1 only distinguishes
// SNI-derived keys from plain 3-tuple keys. See
// ~/.claude/plans/envoy-qosmos-cache.md Part F.
enum class DiscriminatorKind : uint8_t { Sni = 0, Plain = 1 };

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

// One entry in the cache. `source` is either "4pkt" (initial verdict from
// the listener filter's cascade) or "final" (corrected verdict after the
// correction filter reached QMDPI_RESULT_FLAGS_CLASSIFIED_FINAL_STATE) or
// "post_silence_final" (a silence-timeout hand-off that reached a real
// classification later).
struct VerdictCacheEntry {
  bool verdict_is_web{false};
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
  bool put(const VerdictCacheKey& key, bool verdict_is_web,
           absl::string_view source) {
    auto it = entries_.find(key);
    if (it != entries_.end()) {
      it->second.verdict_is_web = verdict_is_web;
      it->second.source.assign(source.data(), source.size());
      return true;
    }
    if (entries_.size() >= max_entries_) return false;
    entries_.emplace(key, VerdictCacheEntry{
                              verdict_is_web,
                              std::string(source.data(), source.size())});
    return true;
  }

  // Correction shorthand: put(..., "final"). Always succeeds if the key
  // already exists (which it must — the initial 4-pkt put() populated it).
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
