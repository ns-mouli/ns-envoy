# netskope/build_config — trimmed extension set

Netskope-scoped `extensions_build_config.bzl` used by `--config=ns-clang-trim`
(see [`../../netskope.bazelrc`](../../netskope.bazelrc)).

Only the extensions the phase-1 `qosmos_dpi` topology-C actually references
stay enabled here; the other ~180 extensions upstream ships are commented
out. All HTTP filters, tracers, WASM, QUIC extensions (core QUIC still
compiles regardless — it lives in `source/common/quic/`), UDP, thrift,
dubbo, mongo, redis, kafka, mysql, postgres, mcp, generic_proxy,
dynamic_modules, ext_authz, ext_proc, dynamic_forward_proxy,
health_checkers, stat sinks, compression codecs, cache backends,
matchers beyond core 5-tuple, cert validators/selectors, injected creds
are all off.

## Why

Reduces the phase-1 filter dev loop from ~12 h clean builds to ~2.5 h,
and shrinks the final link's peak RSS below 8 GB so `/swapfile`
activation is optional (was required for the full extension set). See
[`~/.claude/plans/happy-herding-sun.md`](../../../../.claude/plans/happy-herding-sun.md)
for the ramp-up context.

## How to build with this config

```bash
cd ~/code/ns-envoy
~/bin/bazel build --config=ns-clang-trim //source/exe:envoy-static
~/bin/bazel test  --config=ns-clang-trim //test/extensions/common/qosmos_dpi/... \
                                          //test/extensions/filters/listener/qosmos_dpi/... \
                                          //test/extensions/filters/network/qosmos_dpi_correction/...
```

`--config=ns-clang-trim` inherits `--config=ns-clang` (from the
gitignored `user.bazelrc`) and layers on
`--override_repository=envoy_build_config=%workspace%/netskope/build_config`.
This directory ships the `WORKSPACE`, `BUILD`, and trimmed
`extensions_build_config.bzl` files that make up the overriding
`@envoy_build_config` repo (per Envoy's
[`bazel/README.md`](../../bazel/README.md#customize-extension-build-config)
documented mechanism).

## What to do if bootstrap fails with "Didn't find a registered implementation for name: 'X'"

An extension referenced by the runtime topology config isn't enabled in
the trim. Two options:

- Add its target to `extensions_build_config.bzl` here (30-second
  rebuild, only the link + registry re-runs).
- Fall back to the untrimmed `--config=ns-clang` for that build (full
  extension set; ~12 h clean).

## When adding new phase-1 filters

If a new filter target (e.g. `envoy.filters.network.qosmos_dpi_correction`
became the second Netskope filter here) needs to ship in the trimmed
binary, add its `envoy_cc_extension` target to this file's `EXTENSIONS`
dict AND to the upstream `source/extensions/extensions_build_config.bzl`
(the one this file shadows). Keeping both in sync means a full
`--config=ns-clang` build produces a superset of what
`--config=ns-clang-trim` does, and nothing here shadows an upstream
addition by accident.
