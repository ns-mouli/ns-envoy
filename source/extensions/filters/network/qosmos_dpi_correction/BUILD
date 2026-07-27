load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_extension",
    "envoy_cc_library",
    "envoy_extension_package",
)

licenses(["notice"])  # Apache 2

# Companion network filter to envoy.filters.listener.qosmos_dpi. Claims
# the live qmdpi_flow the listener filter parked in FilterState
# (QosmosFlowHandoff, LifeSpan::Connection), keeps feeding bytes past the
# 4-packet boundary, and corrects the per-worker verdict cache when
# Qosmos reaches a fuller classification. See
# ~/.claude/plans/envoy-qosmos-cache.md Part E.

envoy_extension_package()

envoy_cc_library(
    name = "qosmos_dpi_correction_lib",
    srcs = ["qosmos_dpi_correction.cc"],
    hdrs = ["qosmos_dpi_correction.h"],
    deps = [
        "//envoy/event:dispatcher_interface",
        "//envoy/event:timer_interface",
        "//envoy/network:connection_interface",
        "//envoy/network:filter_interface",
        "//envoy/stats:stats_macros",
        "//source/common/common:logger_lib",
        "//source/common/common:minimal_logger_lib",
        "//source/common/protobuf:utility_lib",
        "//source/extensions/common/qosmos_dpi:qosmos_engine_lib",
        "//source/extensions/common/qosmos_dpi:qosmos_flow_handoff_lib",
        "//source/extensions/common/qosmos_dpi:verdict_cache_lib",
        "@com_google_absl//absl/types:optional",
        "@envoy_api//envoy/extensions/filters/network/qosmos_dpi_correction/v3:pkg_cc_proto",
        "@qosmos_sdk//:qmdpi",
    ],
)

envoy_cc_extension(
    name = "config",
    srcs = ["config.cc"],
    deps = [
        ":qosmos_dpi_correction_lib",
        "//envoy/registry",
        "//envoy/server:filter_config_interface",
        "//source/extensions/filters/network/common:factory_base_lib",
        "@envoy_api//envoy/extensions/filters/network/qosmos_dpi_correction/v3:pkg_cc_proto",
    ],
)
