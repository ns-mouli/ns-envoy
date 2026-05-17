#include <string>

#include "envoy/extensions/filters/listener/qosmos_dpi/v3/qosmos_dpi.pb.h"
#include "envoy/extensions/filters/listener/qosmos_dpi/v3/qosmos_dpi.pb.validate.h"
#include "envoy/registry/registry.h"
#include "envoy/server/filter_config.h"
#include "envoy/singleton/manager.h"

#include "source/common/protobuf/utility.h"
#include "source/extensions/filters/listener/qosmos_dpi/qosmos_dpi.h"
#include "source/extensions/filters/listener/qosmos_dpi/qosmos_engine.h"

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
    QosmosEngineSharedPtr engine =
        server_context.singletonManager().getTyped<QosmosEngine>(
            SINGLETON_MANAGER_REGISTERED_NAME(qosmos_engine),
            [&server_context, &proto_config]() -> std::shared_ptr<QosmosEngine> {
              return std::make_shared<QosmosEngine>(
                  proto_config.engine_config_path(),
                  proto_config.protocol_bundle_path(),
                  proto_config.protocol_table_path(),
                  server_context.options().concurrency(),
                  server_context.threadLocal());
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
