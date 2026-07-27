#pragma once

#include <cstddef>
#include <memory>
#include <string>

#include "envoy/stream_info/filter_state.h"

#include "absl/types/optional.h"

#include "source/extensions/common/qosmos_dpi/qosmos_engine.h"
#include "source/extensions/common/qosmos_dpi/verdict_cache.h"

namespace Envoy {
namespace Extensions {
namespace Common {
namespace QosmosDpi {

// Payload the listener filter parks in StreamInfo::FilterState (LifeSpan::
// Connection) so the companion envoy.filters.network.qosmos_dpi_correction
// network filter can claim the live Qosmos flow after tcp_proxy takes over
// the connection.
//
// Same mechanism TcpProxy::PerConnectionCluster uses to cross from listener
// filter to tcp_proxy (source/common/tcp_proxy/tcp_proxy.h:451). No
// listener-filter-cycle risk: the correction filter is a NETWORK filter,
// and it depends on this header via source/extensions/common/qosmos_dpi.
//
// The handoff carries:
//   - the live classifier (moved out of the listener filter's `classifier_`)
//   - the cache key already computed for the connection's destination
//   - initial_verdict_is_web: the 4-packet cascade verdict that got cached
//     under `key`, so the correction filter can detect a flip. nullopt when
//     no real verdict exists (silence-timeout path, Part B of the plan);
//     the correction filter then treats a later real classification as a
//     first-time populate rather than a correction.
//   - engine: a pointer to the process-wide QosmosEngine so the correction
//     filter can reach the ProtocolTable + per-worker VerdictCache without
//     touching Envoy's SingletonManager itself. Kept as a raw pointer since
//     the engine's shared_ptr is held on the listener filter's Config which
//     outlives every connection it created.
//   - bytes_already_consumed: the exact byte count the listener filter
//     already peeked (via MSG_PEEK) and fed to classifyPdu on the CTS
//     direction. The correction filter's onData() will re-see those same
//     bytes on the network filter chain's first real read and MUST skip
//     that many leading CTS bytes before feeding new bytes to the
//     inherited flow, else the same bytes get resubmitted to the same
//     stream-mode flow. Always 0 on the silence-timeout path (classifyPdu
//     never ran). See envoy-qosmos-cache.md Part B "Peek semantics".
class QosmosFlowHandoff : public StreamInfo::FilterState::Object {
public:
  QosmosFlowHandoff(QosmosClassifierPtr classifier, VerdictCacheKey key,
                    absl::optional<bool> initial_verdict_is_web,
                    QosmosEngine* engine, size_t bytes_already_consumed)
      : classifier_(std::move(classifier)), key_(std::move(key)),
        initial_verdict_is_web_(initial_verdict_is_web), engine_(engine),
        bytes_already_consumed_(bytes_already_consumed) {}

  // Idempotent transfer of ownership to the correction filter. Called at
  // most once from Filter::onNewConnection; a second call returns nullptr.
  QosmosClassifierPtr release() { return std::move(classifier_); }

  const VerdictCacheKey& cacheKey() const { return key_; }
  absl::optional<bool> initialVerdictIsWeb() const {
    return initial_verdict_is_web_;
  }
  QosmosEngine& engine() const { return *engine_; }
  size_t bytesAlreadyConsumed() const { return bytes_already_consumed_; }

  // FilterState key. Static-storage duration string so its address is
  // stable across the lifetime of the process.
  static const std::string& filterStateKey() {
    static const std::string* k =
        new std::string("envoy.extensions.common.qosmos_dpi.flow_handoff");
    return *k;
  }

private:
  // If release() is never called (correction filter absent, misconfigured,
  // or the connection closes before onNewConnection runs on that side),
  // ~QosmosFlowHandoff destroys the classifier, which RAII-destroys the
  // flow via ~RealQosmosClassifier. No new cleanup code needed here.
  QosmosClassifierPtr classifier_;
  VerdictCacheKey key_;
  absl::optional<bool> initial_verdict_is_web_;
  QosmosEngine* engine_;
  size_t bytes_already_consumed_;
};

}  // namespace QosmosDpi
}  // namespace Common
}  // namespace Extensions
}  // namespace Envoy
