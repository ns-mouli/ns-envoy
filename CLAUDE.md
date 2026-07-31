# Envoy + Qosmos DPI Integration — v1.32.4 port (Envoy source tree)

This `ns-envoy-v132` worktree is the Envoy v1.32.4 source tree the
`envoy.filters.listener.qosmos_dpi` listener filter (+ the
`envoy.filters.network.qosmos_dpi_correction` network filter) has been ported
onto, replaying the 20-commit change set developed on `ns-envoy` `main`
(Envoy v1.39.0-dev). The canonical project doc — design status, implementation
plan, run results, layout — lives at:

```
${HOME}/code/cfw-demux-svc/envoy-qosmos/CLAUDE.md
```

Read that first, and `~/.claude/plans/envoy-v1.39-to-envoy-v1.32.4-porting.md`
for the port-specific plan and its P0/P1 fix list.

## Build

Use `--config=ns-clang` (defined in `user.bazelrc`, gitignored, adapted for
v1.32.4's `.bazelrc` — no `clang-common` config or `//bazel:libc++`/`:libstdc++`
bool_flags on this branch). It pins clang-18 from `/opt/llvm-18` + libstdc++
from `/opt/gcc-15` + gold linker via the `~/bin/ns-clang` and `~/bin/ns-clang++`
driver wrappers. Full toolchain rationale and gotchas:
`${HOME}/code/cfw-demux-svc/envoy-qosmos/docs/envoy-build-toolchain.md`.

For a much faster iteration loop, use `--config=ns-clang-trim` (tracked in
`netskope.bazelrc`, auto-imported from the root `.bazelrc`) — it overrides
`envoy_build_config` with `netskope/build_config/extensions_build_config.bzl`,
which keeps only the ~20 extensions the qosmos_dpi topology-C config actually
references and cuts a clean build from ~12h to ~2-3h.

```bash
~/bin/bazel build --config=ns-clang-trim //source/exe:envoy-static
```

The 8 GB swapfile (`/swapfile`) on this VM is required for the final link of
`envoy-static` — without it the kernel OOM-kills clang during link.

## Where the filter lives

```
source/extensions/filters/listener/qosmos_dpi/
source/extensions/filters/network/qosmos_dpi_correction/
source/extensions/common/qosmos_dpi/            (shared engine, protocol table, verdict cache)
api/envoy/extensions/filters/listener/qosmos_dpi/v3/
api/envoy/extensions/filters/network/qosmos_dpi_correction/v3/
test/extensions/filters/listener/qosmos_dpi/
test/extensions/filters/network/qosmos_dpi_correction/
test/extensions/common/qosmos_dpi/
```

Wired into the build via `source/extensions/extensions_build_config.bzl`
(listener filter ~line 204, network filter ~line 222).

## Skipped per user direction

- `${HOME}/code/cfw-demux-svc/envoy-poc/` and its `ENVOY_BUILD_NOTES.md`
- `${HOME}/code/envoy/` (older clone)
- `${HOME}/code/envoy-vpp/`
