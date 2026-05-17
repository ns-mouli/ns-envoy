workspace(name = "envoy")

load("//bazel:api_binding.bzl", "envoy_api_binding")

envoy_api_binding()

load("//bazel:api_repositories.bzl", "envoy_api_dependencies")

envoy_api_dependencies()

load("//bazel:repositories.bzl", "envoy_dependencies")

envoy_dependencies()

load("//bazel:bazel_deps.bzl", "envoy_bazel_dependencies")

envoy_bazel_dependencies()

load("//bazel:repositories_extra.bzl", "envoy_dependencies_extra")

envoy_dependencies_extra()

load("//bazel:python_dependencies.bzl", "envoy_python_dependencies")

envoy_python_dependencies()

load("//bazel:dependency_imports.bzl", "envoy_dependency_imports")

envoy_dependency_imports()

load("//bazel:repo.bzl", "envoy_repo")

envoy_repo()

load("//bazel:toolchains.bzl", "envoy_toolchains")

envoy_toolchains()

load("//bazel:dependency_imports_extra.bzl", "envoy_dependency_imports_extra")

envoy_dependency_imports_extra()

# Qosmos ixEngine SDK — Netskope tooling install at /opt/3p/binary/ixe.
# Used by source/extensions/filters/listener/qosmos_dpi for phase-1 DPI
# integration. See cfw-demux-svc/envoy-qosmos/docs/qosmos-dpi-integration-plan.md
# §6 for rationale.
new_local_repository(
    name = "qosmos_sdk",
    path = "/opt/3p/binary/ixe",
    build_file_content = """
package(default_visibility = ["//visibility:public"])

# Public Qosmos C API headers.
cc_library(
    name = "qmdpi_headers",
    hdrs = glob([
        "include/*.h",
        "include/dpi/**/*.h",
    ]),
    includes = ["include"],
)

# Engine: linked statically. PIC variant required because envoy-static
# is built as a PIE — the non-fpic libqmengine.a fails with
# "requires unsupported dynamic reloc 11; recompile with -fPIC".
cc_import(
    name = "qmengine_static",
    static_library = "lib/libqmengine.fpic.a",
)

# Bundle reader: linked statically. PIC variant for the same reason
# as qmengine.
cc_import(
    name = "qmbundle_static",
    static_library = "lib/libqmbundle.fpic.a",
)

# Composite target the qosmos_dpi filter depends on.
cc_library(
    name = "qmdpi",
    deps = [
        ":qmdpi_headers",
        ":qmengine_static",
        ":qmbundle_static",
    ],
    linkopts = [
        "-lpthread",
        "-lm",
        "-ldl",
    ],
)
""",
)
