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

# Read-only catalog driving the web/non-web cascade. Loaded once at engine
# init from qosmos_protocols.json (produced by csv_to_json.py). Shared by
# all worker threads as `const ProtocolTable&` — see protocol_table.h for
# the singleton vs per-worker rationale.
envoy_cc_library(
    name = "protocol_table_lib",
    srcs = ["protocol_table.cc"],
    hdrs = ["protocol_table.h"],
    deps = [
        "//source/common/json:json_loader_lib",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
    ],
)

# Process-wide Qosmos engine + bundle + cascade table held in
# Singleton::Manager. Plus per-worker QosmosWorker handles via
# ThreadLocal::TypedSlot. See qosmos_engine.h for the lifetime contract.
envoy_cc_library(
    name = "qosmos_engine_lib",
    srcs = ["qosmos_engine.cc"],
    hdrs = ["qosmos_engine.h"],
    deps = [
        ":protocol_table_lib",
        "//envoy/singleton:instance_interface",
        "//envoy/thread_local:thread_local_interface",
        "//source/common/common:logger_lib",
        "//source/common/common:minimal_logger_lib",
        "@com_google_absl//absl/strings",
        "@qosmos_sdk//:qmdpi",
    ],
)

# The listener filter itself. One instance per accepted connection.
# State machine + flow lifecycle per docs/qosmos-dpi-integration-plan.md
# §1, §7.4: qmdpi_flow_create on accept → first-PDU classify →
# UNCONDITIONAL qmdpi_flow_destroy → setVerdict via PerConnectionCluster.
envoy_cc_library(
    name = "qosmos_dpi_lib",
    srcs = ["qosmos_dpi.cc"],
    hdrs = ["qosmos_dpi.h"],
    deps = [
        ":qosmos_engine_lib",
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
        ":qosmos_engine_lib",
        "//envoy/registry",
        "//envoy/server:filter_config_interface",
        "//envoy/singleton:manager_interface",
        "//source/common/protobuf:utility_lib",
        "@envoy_api//envoy/extensions/filters/listener/qosmos_dpi/v3:pkg_cc_proto",
    ],
)
