# Yuzu Codex Guide

Use repo-local Codex skills first. Start with the narrowest matching skill and combine skills when a change crosses domains.

## Route By Task

- `yuzu-build`: configure, compile, test, choose suites, or recover a broken build directory.
- `yuzu-meson`: edit any `meson.build`, change source lists, adjust dependencies, or update build graph behavior.
- `yuzu-proto`: edit `.proto` files, `proto/gen_proto.py`, `proto/meson.build`, `proto/buf.yaml`, or `gateway/priv/proto/**`.
- `yuzu-plugin-abi`: change `sdk/include/yuzu/plugin.h`, `plugin.hpp`, plugin descriptors, `plugin_loader.cpp`, or plugin action contracts.
- `yuzu-windows-msvc`: handle Windows MSYS2 + MSVC builds, `setup_msvc_env.sh`, `triplets/x64-windows.cmake`, Windows CI, or the Windows-specific protobuf/grpc wiring in root `meson.build`.

## Repo Invariants

- Meson is the only project build system.
- Use `./scripts/setup.sh` for canonical setup. Default build directories are `build-linux`, `build-windows`, and `build-macos`.
- Treat `proto/yuzu/**` as the canonical wire contract.
- Treat `gateway/priv/proto/**` as a gateway mirror that must stay synced with canonical proto sources.
- Treat `sdk/include/yuzu/plugin.h` as the stable C ABI boundary.
- On Windows, use MSYS2 bash plus `source ./setup_msvc_env.sh`. If the build touches the gateway custom target, also `source scripts/ensure-erlang.sh`.
- Never use `vcvars64.bat`.
- Never switch Windows protobuf/grpc back to Meson's cmake dependency path without reviewing the Windows-specific rules in root `meson.build` and `docs/windows-build.md`.

## Validation Defaults

- Build graph or source-list change: `meson compile -C <builddir>`
- Proto change: `buf lint proto`, `buf breaking proto --against '.git#subdir=proto,ref=origin/main'` when history is available, then rebuild consumers
- ABI or descriptor change: run targeted agent/plugin tests, especially descriptor and loader coverage
- Prefer `meson test -C <builddir> --suite <suite> --print-errorlogs` over broad runs when the change is scoped

## Read On Demand

- Build entrypoint: `scripts/setup.sh`
- Windows flow: `docs/windows-build.md`, `setup_msvc_env.sh`
- Proto codegen: `proto/meson.build`, `proto/gen_proto.py`, `gateway/rebar.config`
- ABI boundary: `sdk/include/yuzu/plugin.h`, `sdk/include/yuzu/plugin.hpp`, `agents/core/src/plugin_loader.cpp`
- CI behavior: `.github/workflows/ci.yml`
