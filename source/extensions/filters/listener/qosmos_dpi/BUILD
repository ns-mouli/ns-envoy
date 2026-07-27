load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_extension",
    "envoy_cc_library",
    "envoy_extension_package",
)

licenses(["notice"])  # Apache 2

# Qosmos DPI listener filter — classifies inbound TCP connections via
# Qosmos DPI (stream mode) on the first client data PDU and steers each
# connection to a web or non-web upstream cluster.
# Phase-1 design:
# cfw-demux-svc/design-docs/cfw-demux-svc-envoy-qosmos-detailed-design-phase-1.md

envoy_extension_package()

# ProtocolTable and QosmosEngine moved to source/extensions/common/qosmos_dpi/
# so the future envoy.filters.network.qosmos_dpi_correction filter (verdict-
# cache correction; see ~/.claude/plans/envoy-qosmos-cache.md) can depend on
# them without introducing a listener-filter cycle. Depend on the new
# targets rather than re-declaring them here.

# The listener filter itself. One instance per accepted connection.
# State machine + flow lifecycle per docs/qosmos-dpi-integration-plan.md
# §1, §7.4: qmdpi_flow_create on accept → first-PDU classify →
# UNCONDITIONAL qmdpi_flow_destroy → setVerdict via PerConnectionCluster.
envoy_cc_library(
    name = "qosmos_dpi_lib",
    srcs = ["qosmos_dpi.cc"],
    hdrs = ["qosmos_dpi.h"],
    deps = [
        "//source/extensions/common/qosmos_dpi:qosmos_engine_lib",
        "//envoy/event:dispatcher_interface",
        "//envoy/event:timer_interface",
        "//envoy/network:filter_interface",
        "//envoy/network:listen_socket_interface",
        "//envoy/stats:stats_macros",
        "//source/common/buffer:buffer_lib",
        "//source/common/common:logger_lib",
        "//source/common/common:minimal_logger_lib",
        "//source/common/protobuf:utility_lib",
        "//source/common/tcp_proxy",
        "@com_google_absl//absl/strings",
        "@envoy_api//envoy/extensions/filters/listener/qosmos_dpi/v3:pkg_cc_proto",
        "@qosmos_sdk//:qmdpi",
    ],
)

# Extension factory + REGISTER_FACTORY entry. This is the target wired into
# extensions_build_config.bzl (Step 6) so the filter shows up in
# envoy-static.
envoy_cc_extension(
    name = "config",
    srcs = ["config.cc"],
    deps = [
        ":qosmos_dpi_lib",
        "//source/extensions/common/qosmos_dpi:qosmos_engine_lib",
        "//envoy/registry",
        "//envoy/server:filter_config_interface",
        "//envoy/singleton:manager_interface",
        "//source/common/protobuf:utility_lib",
        "@envoy_api//envoy/extensions/filters/listener/qosmos_dpi/v3:pkg_cc_proto",
    ],
)
