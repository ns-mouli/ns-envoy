load("@rules_cc//cc:defs.bzl", "cc_library")
load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_contrib_extension",
    "envoy_cc_library",
    "envoy_contrib_package",
)

licenses(["notice"])  # Apache 2

# VPP Comms Lib (VCL) adaptor.

envoy_contrib_package()

# Copy only the VCL header from /opt/vpp23 — the VPP shared libs
# (libvppcom.so, libvppinfra.so, etc.) are linked dynamically via
# --linkopt flags in clang.bazelrc. The .so files are copied into
# the Docker image at packaging time.
genrule(
    name = "vppcom_header",
    srcs = [],
    outs = ["external/vppcom.h"],
    cmd = "mkdir -p $(RULEDIR)/external && " +
          "cp /opt/vpp23/include/vcl/vppcom.h $(RULEDIR)/external/",
)

cc_library(
    name = "vpp_vcl",
    hdrs = ["external/vppcom.h"],
    defines = ["VPP_VCL"],
    includes = ["external/"],
    tags = ["skip_on_windows"],
    visibility = ["//visibility:public"],
)

envoy_cc_library(
    name = "vcl_interface_lib",
    srcs = [
        "vcl_event.cc",
        "vcl_interface.cc",
        "vcl_io_handle.cc",
    ],
    hdrs = [
        "vcl_event.h",
        "vcl_interface.h",
        "vcl_io_handle.h",
    ],
    visibility = ["//visibility:public"],
    deps = [
        ":vpp_vcl",
        "//envoy/event:dispatcher_interface",
        "//envoy/network:socket_interface",
        "//source/common/common:minimal_logger_lib",
        "//source/common/event:dispatcher_includes",
        "//source/common/event:dispatcher_lib",
        "//source/common/event:libevent_scheduler_lib",
        "//source/common/network:address_lib",
        "//source/common/network:io_socket_error_lib",
        "//source/common/network:socket_interface_lib",
        "//source/common/network:socket_lib",
    ],
)

envoy_cc_contrib_extension(
    name = "config",
    srcs = ["config.cc"],
    hdrs = ["config.h"],
    visibility = ["//visibility:public"],
    deps = [
        ":vcl_interface_lib",
        "@envoy_api//contrib/envoy/extensions/vcl/v3alpha:pkg_cc_proto",
    ],
)
