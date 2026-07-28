load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_test",
    "envoy_cc_test_library",
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

# Minimal libpcap-based reader for the corpus replay test. Not a full
# packet library — just enough to extract per-TCP-stream payload chunks
# so we can feed them to the real Qosmos engine.
envoy_cc_test_library(
    name = "pcap_reader_lib",
    srcs = ["pcap_reader.cc"],
    hdrs = ["pcap_reader.h"],
    deps = [
        "@abseil-cpp//absl/container:flat_hash_map",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings",
        "@system_libpcap//:pcap",
    ],
)

# Direct-inject corpus replay. Reads pcaps from $QOSMOS_CORPUS_ROOT, feeds
# every TCP stream through the shipped QosmosEngine + ProtocolTable, and
# emits a per-stream + aggregate summary JSON. Not a hermetic Bazel test:
# GTEST_SKIP if the corpus/protocol-table paths aren't available.
envoy_cc_test(
    name = "qosmos_corpus_replay_test",
    srcs = ["qosmos_corpus_replay_test.cc"],
    # Reader depends on system libpcap.so. The Bazel toolchain uses
    # `--sysroot=external/sysroot_linux_amd64/`, whose /lib/x86_64-linux-gnu
    # does NOT contain libpcap. Explicitly point ld at the host's system
    # library directory. This test is opt-in (tags=["manual"]) and runs
    # only where /usr/lib/x86_64-linux-gnu/libpcap.so exists.
    linkopts = [
        "-L/usr/lib/x86_64-linux-gnu",
        "-lpcap",
    ],
    rbe_pool = "6gig",
    tags = ["manual"],   # requires corpus + real Qosmos SDK; opt-in only.
    deps = [
        ":pcap_reader_lib",
        "//source/common/buffer:buffer_lib",
        "//source/extensions/common/qosmos_dpi:protocol_table_lib",
        "//source/extensions/common/qosmos_dpi:qosmos_engine_lib",
        "//test/mocks/event:event_mocks",
        "//test/mocks/thread_local:thread_local_mocks",
        # Pin the newer abseil-cpp copy so protobuf's coded_stream.h chain
        # sees `absl_nonnull`/`absl_nullable` macros consistently across the
        # two Envoy abseil repos.
        "@abseil-cpp//absl/base:nullability",
        "@qosmos_sdk//:qmdpi",
    ],
)
