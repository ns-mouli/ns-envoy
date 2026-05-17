# Envoy + Qosmos DPI Integration — Phase 1 (Envoy source tree)

This `ns-envoy` checkout is the Envoy source tree where the new `envoy.filters.listener.qosmos_dpi` listener filter is built. The canonical project doc — design status, implementation plan, run results, layout — lives at:

```
${HOME}/code/cfw-demux-svc/envoy-qosmos/CLAUDE.md
```

Read that first.

## Build

Use `--config=ns-clang` (defined in `user.bazelrc`, gitignored). It pins clang-18 from `/opt/llvm-18` + libstdc++ from `/opt/gcc-15` + gold linker via the `~/bin/ns-clang` and `~/bin/ns-clang++` driver wrappers. Full toolchain rationale and gotchas: `${HOME}/code/cfw-demux-svc/envoy-qosmos/docs/envoy-build-toolchain.md`.

```bash
~/bin/bazel build --config=ns-clang //source/exe:envoy-static
```

The 8 GB swapfile (`/swapfile`) on this VM is required for the final link of `envoy-static` — without it the kernel OOM-kills clang during link.

## Where the new filter lives

```
source/extensions/filters/listener/qosmos_dpi/   (to be created)
api/envoy/extensions/filters/listener/qosmos_dpi/v3/   (to be created)
test/extensions/filters/listener/qosmos_dpi/   (to be created)
```

Wired into the build via `source/extensions/extensions_build_config.bzl` next to the listener filter block (~line 244).

## Skipped per user direction

- `${HOME}/code/cfw-demux-svc/envoy-poc/` and its `ENVOY_BUILD_NOTES.md`
- `${HOME}/code/envoy/` (older clone)
- `${HOME}/code/envoy-vpp/`
