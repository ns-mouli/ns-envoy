#include <algorithm>
#include <cstdint>
#include <string>

#include "envoy/extensions/filters/listener/qosmos_dpi/v3/qosmos_dpi.pb.h"
#include "envoy/extensions/filters/listener/qosmos_dpi/v3/qosmos_dpi.pb.validate.h"
#include "envoy/registry/registry.h"
#include "envoy/server/filter_config.h"
#include "envoy/singleton/manager.h"

#include "source/common/protobuf/utility.h"
#include "source/extensions/filters/listener/qosmos_dpi/qosmos_dpi.h"
#include "source/extensions/common/qosmos_dpi/qosmos_engine.h"

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace QosmosDpi {

// One singleton per process — mirrors the http_connection_manager pattern
// at source/extensions/filters/network/http_connection_manager/config.cc:229.
SINGLETON_MANAGER_REGISTRATION(qosmos_engine);

class QosmosDpiConfigFactory
    : public Server::Configuration::NamedListenerFilterConfigFactory {
public:
  Network::ListenerFilterFactoryCb createListenerFilterFactoryFromProto(
      const Protobuf::Message& message,
      const Network::ListenerFilterMatcherSharedPtr& listener_filter_matcher,
      Server::Configuration::ListenerFactoryContext& context) override {

    const auto& proto_config = MessageUtil::downcastAndValidate<
        const envoy::extensions::filters::listener::qosmos_dpi::v3::QosmosDpi&>(
        message, context.messageValidationVisitor());

    auto& server_context = context.serverFactoryContext();

    // QosmosEngine is process-wide. The first listener filter that gets
    // configured triggers engine create + bundle activate + protocol-table
    // load. Subsequent listener-filter-config loads (e.g. multiple
    // listeners) reuse the same engine.
    // The verdict cache is a per-worker slot on the engine. It's allocated
    // when total_entries > 0 (regardless of correction_enabled). With
    // correction disabled (VCL pipeline), entries are promoted to final
    // immediately and classifyFirstPdu is used (no handoff delay).
    //
    // Sizing:
    //   proto.verdict_cache_total_entries == 0  ⇒ cache disabled
    //   proto.verdict_cache_total_entries == N (>0) ⇒
    //     per-worker = ceil(N / nb_workers)
    //     (total-across-workers accounting, matching total_nb_flows).
    uint32_t cache_max_entries = 0U;
    if (proto_config.verdict_cache_total_entries() > 0U) {
      const uint32_t total = proto_config.verdict_cache_total_entries();
      const uint32_t workers =
          std::max<uint32_t>(1U, server_context.options().concurrency());
      cache_max_entries = (total + workers - 1U) / workers;   // ceil-divide
    }
    // Process-wide flow-context budget. 0 in the proto ⇒ engine ctor
    // substitutes its built-in default (300000). Per-worker nb_flows
    // (which is what the SDK actually consumes) is derived by the engine
    // as ceil(total_nb_flows / (nb_workers + 1)).
    const uint32_t total_nb_flows = proto_config.total_nb_flows();
    QosmosEngineSharedPtr engine =
        server_context.singletonManager().getTyped<QosmosEngine>(
            SINGLETON_MANAGER_REGISTERED_NAME(qosmos_engine),
            [&server_context, &proto_config, cache_max_entries,
             total_nb_flows]() -> std::shared_ptr<QosmosEngine> {
              return std::make_shared<QosmosEngine>(
                  proto_config.engine_config_path(),
                  proto_config.protocol_bundle_path(),
                  proto_config.protocol_table_path(),
                  server_context.options().concurrency(),
                  server_context.threadLocal(),
                  cache_max_entries,
                  total_nb_flows);
            });

    ConfigSharedPtr config =
        std::make_shared<Config>(proto_config, std::move(engine), context.scope());

    return [listener_filter_matcher,
            config](Network::ListenerFilterManager& filter_manager) -> void {
      filter_manager.addAcceptFilter(listener_filter_matcher,
                                     std::make_unique<Filter>(config));
    };
  }

  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return std::make_unique<
        envoy::extensions::filters::listener::qosmos_dpi::v3::QosmosDpi>();
  }

  std::string name() const override { return "envoy.filters.listener.qosmos_dpi"; }
};

REGISTER_FACTORY(QosmosDpiConfigFactory,
                 Server::Configuration::NamedListenerFilterConfigFactory){
    "envoy.listener.qosmos_dpi"};

}  // namespace QosmosDpi
}  // namespace ListenerFilters
}  // namespace Extensions
}  // namespace Envoy
