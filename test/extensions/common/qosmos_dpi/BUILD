load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_test",
    "envoy_package",
)

licenses(["notice"])  # Apache 2

envoy_package()

envoy_cc_test(
    name = "verdict_cache_test",
    srcs = ["verdict_cache_test.cc"],
    rbe_pool = "6gig",
    deps = [
        "//source/extensions/common/qosmos_dpi:verdict_cache_lib",
    ],
)
