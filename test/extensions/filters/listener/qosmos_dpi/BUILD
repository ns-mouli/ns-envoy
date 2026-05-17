load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_test",
    "envoy_package",
)

licenses(["notice"])  # Apache 2

envoy_package()

envoy_cc_test(
    name = "protocol_table_test",
    srcs = ["protocol_table_test.cc"],
    rbe_pool = "6gig",
    deps = [
        "//source/extensions/filters/listener/qosmos_dpi:protocol_table_lib",
        "//test/test_common:environment_lib",
    ],
)

envoy_cc_test(
    name = "qosmos_dpi_test",
    srcs = ["qosmos_dpi_test.cc"],
    rbe_pool = "6gig",
    deps = [
        "//source/common/buffer:buffer_lib",
        "//source/common/stream_info:filter_state_lib",
        "//source/common/tcp_proxy",
        "//source/extensions/filters/listener/qosmos_dpi:qosmos_dpi_lib",
        "//test/mocks/event:event_mocks",
        "//test/mocks/network:network_mocks",
        "//test/test_common:environment_lib",
        "//test/test_common:simulated_time_system_lib",
        "//test/test_common:utility_lib",
        "@envoy_api//envoy/extensions/filters/listener/qosmos_dpi/v3:pkg_cc_proto",
    ],
)
