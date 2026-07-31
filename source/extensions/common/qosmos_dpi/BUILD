load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
    "envoy_package",
)

licenses(["notice"])  # Apache 2

# Shared Qosmos DPI plumbing consumed by:
#   - source/extensions/filters/listener/qosmos_dpi   (the shipped filter)
#   - source/extensions/filters/network/qosmos_dpi_correction  (future,
#     verdict-cache correction; see ~/.claude/plans/envoy-qosmos-cache.md).
# Moved here from filters/listener/qosmos_dpi/ so the network correction
# filter can depend on the same engine + protocol table without a
# listener-filter cycle.

envoy_package()

# Read-only catalog driving the web/non-web cascade. Loaded once at engine
# init from qosmos_protocols.json (produced by csv_to_json.py). Shared by
# all worker threads as `const ProtocolTable&` — see protocol_table.h for
# the singleton vs per-worker rationale.
envoy_cc_library(
    name = "protocol_table_lib",
    srcs = ["protocol_table.cc"],
    hdrs = ["protocol_table.h"],
    deps = [
        "//source/common/common:thread_lib",
        "//source/common/json:json_loader_lib",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
    ],
)

# Per-Envoy-worker, thread-local verdict cache keyed on {dst-ip, dst-port,
# discriminator}. Header-only. Consumed by qosmos_engine (which owns the
# per-worker slot) and by the future qosmos_dpi_correction network filter.
envoy_cc_library(
    name = "verdict_cache_lib",
    hdrs = ["verdict_cache.h"],
    deps = [
        "//envoy/thread_local:thread_local_interface",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/hash",
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
        ":verdict_cache_lib",
        "//envoy/singleton:instance_interface",
        "//envoy/thread_local:thread_local_interface",
        "//source/common/common:logger_lib",
        "//source/common/common:minimal_logger_lib",
        "@com_google_absl//absl/strings",
        "@qosmos_sdk//:qmdpi",
    ],
)

# FilterState::Object payload the listener filter parks under
# LifeSpan::Connection so the correction network filter can claim the live
# Qosmos flow after tcp_proxy takes over. Header-only. Consumed by both
# the listener filter and the correction filter — kept in common/ to
# avoid a listener-filter dep cycle.
envoy_cc_library(
    name = "qosmos_flow_handoff_lib",
    hdrs = ["qosmos_flow_handoff.h"],
    deps = [
        ":qosmos_engine_lib",
        ":verdict_cache_lib",
        "//envoy/stream_info:filter_state_interface",
        "@com_google_absl//absl/types:optional",
    ],
)
