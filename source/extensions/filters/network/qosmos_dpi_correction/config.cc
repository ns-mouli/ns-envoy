#include <memory>

#include "envoy/extensions/filters/network/qosmos_dpi_correction/v3/qosmos_dpi_correction.pb.h"
#include "envoy/extensions/filters/network/qosmos_dpi_correction/v3/qosmos_dpi_correction.pb.validate.h"
#include "envoy/registry/registry.h"

#include "source/extensions/filters/network/common/factory_base.h"
#include "source/extensions/filters/network/qosmos_dpi_correction/qosmos_dpi_correction.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace QosmosDpiCorrection {

class QosmosDpiCorrectionConfigFactory
    : public Common::FactoryBase<
          envoy::extensions::filters::network::qosmos_dpi_correction::v3::QosmosDpiCorrection> {
public:
  QosmosDpiCorrectionConfigFactory()
      : FactoryBase("envoy.filters.network.qosmos_dpi_correction") {}

private:
  Network::FilterFactoryCb createFilterFactoryFromProtoTyped(
      const envoy::extensions::filters::network::qosmos_dpi_correction::v3::
          QosmosDpiCorrection& proto_config,
      Server::Configuration::FactoryContext& context) override {
    auto config = std::make_shared<Config>(proto_config, context.scope());
    return [config](Network::FilterManager& filter_manager) -> void {
      // Register as both a read AND write filter — the correction filter
      // observes CTS via onData and STC via onWrite.
      filter_manager.addFilter(std::make_shared<Filter>(config));
    };
  }
};

REGISTER_FACTORY(QosmosDpiCorrectionConfigFactory,
                 Server::Configuration::NamedNetworkFilterConfigFactory){
    "envoy.qosmos_dpi_correction"};

}  // namespace QosmosDpiCorrection
}  // namespace NetworkFilters
}  // namespace Extensions
}  // namespace Envoy
