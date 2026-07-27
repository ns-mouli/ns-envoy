load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_test",
    "envoy_package",
)

licenses(["notice"])  # Apache 2

envoy_package()

envoy_cc_test(
    name = "qosmos_dpi_correction_test",
    srcs = ["qosmos_dpi_correction_test.cc"],
    rbe_pool = "6gig",
    deps = [
        "//source/common/buffer:buffer_lib",
        "//source/common/stream_info:filter_state_lib",
        "//source/extensions/common/qosmos_dpi:protocol_table_lib",
        "//source/extensions/common/qosmos_dpi:qosmos_engine_lib",
        "//source/extensions/common/qosmos_dpi:qosmos_flow_handoff_lib",
        "//source/extensions/common/qosmos_dpi:verdict_cache_lib",
        "//source/extensions/filters/network/qosmos_dpi_correction:qosmos_dpi_correction_lib",
        "//test/mocks/event:event_mocks",
        "//test/mocks/network:network_mocks",
        "//test/test_common:environment_lib",
        "@envoy_api//envoy/extensions/filters/network/qosmos_dpi_correction/v3:pkg_cc_proto",
    ],
)
