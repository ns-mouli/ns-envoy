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

