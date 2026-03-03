# CLAUDE.md — Yuzu Codebase Guide

This file provides context for AI assistants (Claude Code and similar tools) working on the Yuzu codebase.

---

## Project Overview

**Yuzu** is a multi-platform agent–server framework written in **C++23**. It enables real-time endpoint management via gRPC bidirectional streaming, with a language-agnostic plugin architecture built on a stable C ABI.

- **Language:** C++23 (`std::expected`, ranges, structured bindings)
- **Transport:** gRPC + Protocol Buffers with TLS built-in
- **Platforms:** Windows (x64), Linux (x64/ARM64), macOS (ARM64)
- **Version:** 0.1.0 — Initial Scaffold
- **License:** Apache 2.0

---

## Repository Layout

```
Yuzu/
├── agents/
│   ├── core/                       # Agent daemon (yuzu-agent binary)
│   │   ├── include/yuzu/agent/
│   │   │   ├── agent.hpp           # Agent class + Config
│   │   │   └── plugin_loader.hpp
│   │   ├── src/
│   │   │   ├── agent.cpp
│   │   │   ├── plugin_loader.cpp
│   │   │   └── main.cpp            # CLI entry point (CLI11)
│   │   ├── CMakeLists.txt
│   │   └── meson.build
│   └── plugins/
│       └── example/                # Reference plugin implementation
│           ├── src/example_plugin.cpp
│           ├── CMakeLists.txt
│           └── meson.build
├── cmake/
│   ├── modules/
│   │   ├── CompilerFlags.cmake     # yuzu_set_compiler_flags() helper
│   │   └── YuzuProto.cmake         # yuzu_proto_library() helper
│   └── toolchains/
│       └── aarch64-linux-gnu.cmake # ARM64 cross-compile toolchain
├── proto/
│   └── yuzu/
│       ├── agent/v1/agent.proto    # AgentService (Register, Heartbeat, ExecuteCommand…)
│       ├── common/v1/common.proto  # Shared types (Platform, PluginInfo, ErrorDetail…)
│       └── server/v1/management.proto  # ManagementService (ListAgents, SendCommand…)
│   ├── CMakeLists.txt
│   └── meson.build
├── sdk/
│   └── include/yuzu/
│       ├── plugin.h                # C ABI — stable binary interface for plugins
│       ├── plugin.hpp              # C++ CRTP wrapper (yuzu::Plugin, yuzu::Result<T>)
│       └── version.hpp             # Version constants (kVersionMajor, kVersionString…)
│   ├── CMakeLists.txt
│   └── meson.build
├── server/
│   ├── core/                       # Server daemon (yuzu-server binary)
│   │   ├── include/yuzu/server/
│   │   ├── src/
│   │   │   ├── server.cpp
│   │   │   └── main.cpp
│   │   ├── CMakeLists.txt
│   │   └── meson.build
│   └── gateway/                    # gRPC gateway (placeholder, TBD)
│       ├── CMakeLists.txt
│       └── meson.build             # placeholder only
├── tests/
│   └── unit/
│       └── test_plugin_loader.cpp  # Catch2 unit tests
│   ├── CMakeLists.txt
│   └── meson.build
├── CMakeLists.txt                  # Primary build system (root)
├── CMakePresets.json               # Preset configs for all platforms (version 6)
├── meson.build                     # Root Meson build (alternative to CMake)
├── meson.options                   # Meson option definitions
├── vcpkg.json                      # Dependency manifest (pinned baseline)
├── vcpkg-configuration.json
├── .github/workflows/ci.yml        # GitHub Actions CI (4 platforms × 2 build types)
└── README.md
```

---

## Build System

The project supports both **CMake** (primary) and **Meson** (alternative). CMake uses **vcpkg** in manifest mode; Meson resolves dependencies via `pkg-config` / system packages.

### Requirements

| Tool | Minimum Version |
|------|----------------|
| CMake | 3.28 |
| Meson | 1.3 |
| Ninja | any recent |
| GCC | 13+ |
| Clang | 17+ |
| MSVC | 19.38+ (VS 2022) |
| vcpkg | any (baseline pinned) |

### CMake — Recommended

```bash
# Configure with a preset (Ninja generator, vcpkg auto-wired)
cmake --preset linux-debug          # Debug, x64-linux
cmake --preset linux-release        # Release, x64-linux, LTO ON
cmake --preset windows-debug        # MSVC, x64-windows, MultiThreadedDebugDLL
cmake --preset windows-release      # MSVC, x64-windows, MultiThreadedDLL, LTO ON
cmake --preset macos-debug          # Apple Clang, arm64-osx
cmake --preset macos-release        # arm64-osx, LTO ON
cmake --preset arm64-linux-debug    # Cross-compile aarch64-linux-gnu
cmake --preset arm64-linux-release  # arm64-linux, LTO ON

# Build
cmake --build --preset linux-debug

# Manual configure (vcpkg path must be set)
cmake -B build \
  -G Ninja \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_TOOLCHAIN_FILE=$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake \
  -DVCPKG_TARGET_TRIPLET=x64-linux \
  -DYUZU_BUILD_TESTS=ON

cmake --build build --parallel $(nproc)
```

#### CMake Build Options

| Option | Default | Description |
|--------|---------|-------------|
| `YUZU_BUILD_AGENT` | ON | Build yuzu-agent daemon |
| `YUZU_BUILD_SERVER` | ON | Build yuzu-server daemon |
| `YUZU_BUILD_SDK` | ON | Build and install the public SDK |
| `YUZU_BUILD_TESTS` | OFF | Enable Catch2 unit tests |
| `YUZU_BUILD_EXAMPLES` | ON | Build example plugins (only when `YUZU_BUILD_AGENT=ON`) |
| `YUZU_ENABLE_LTO` | OFF | Link-time optimization (auto-ON in all release presets) |
| `YUZU_ENABLE_ASAN` | OFF | AddressSanitizer + UBSan |
| `YUZU_ENABLE_TSAN` | OFF | ThreadSanitizer |

#### CMake Compiler Flags (`cmake/modules/CompilerFlags.cmake`)

Applied per-target via `yuzu_set_compiler_flags(<target>)`. **Always call this on new targets.**

| Compiler | Flags |
|----------|-------|
| MSVC | `/W4 /WX- /permissive- /Zc:__cplusplus /utf-8 /wd4100 /wd4251` |
| GCC / Clang | `-Wall -Wextra -Wpedantic -Wno-unused-parameter -fvisibility=hidden` |
| Clang only | `-Wno-gnu-zero-variadic-macro-arguments` |

Sanitizer flags are appended when `YUZU_ENABLE_ASAN` or `YUZU_ENABLE_TSAN` are ON (GCC/Clang only). LTO is enabled via `INTERPROCEDURAL_OPTIMIZATION`.

#### Proto Code Generation (`cmake/modules/YuzuProto.cmake`)

```cmake
yuzu_proto_library(
  NAME   yuzu_proto
  PROTOS ${PROTO_FILES}   # globbed via GLOB_RECURSE from proto/**/*.proto
)
```

- Finds `protoc` and `grpc_cpp_plugin` programs.
- Generates `*.pb.{h,cc}` and `*.grpc.pb.{h,cc}` into `${CMAKE_BINARY_DIR}/generated/proto/`.
- Produces a static library `yuzu_proto` that other targets link against.
- New `.proto` files placed under `proto/yuzu/` are picked up automatically by `GLOB_RECURSE` — no manual registration needed in CMake.
- Include generated headers as `#include "<stem>.pb.h"` (the generated dir is on the include path).

### Meson — Alternative

```bash
meson setup builddir -Dbuildtype=debug
meson compile -C builddir

# With options
meson setup builddir \
  -Dbuildtype=release \
  -Dbuild_tests=true \
  -Denable_lto=true

meson test -C builddir
```

#### Meson Options (`meson.options`)

| Option | Default | Description |
|--------|---------|-------------|
| `build_agent` | `true` | Build the agent daemon |
| `build_server` | `true` | Build the server daemon |
| `build_examples` | `true` | Build example plugins |
| `build_tests` | `false` | Build unit and integration tests |
| `enable_lto` | `false` | Link-time optimisation |
| `enable_asan` | `false` | AddressSanitizer |
| `enable_tsan` | `false` | ThreadSanitizer |

> **Note:** Meson has no `build_sdk` option — the SDK is always included as a header-only `declare_dependency()` in `sdk/meson.build`.

#### Meson Project Defaults

From `meson.build` `default_options`:

```
cpp_std=c++23, warning_level=3, werror=false,
default_library=shared, b_pie=true
```

Shared libraries are the Meson default (unlike CMake which uses static for internal libs). PIE is enabled globally.

#### Meson Dependency Names

| `dependency()` name | Package |
|---------------------|---------|
| `grpc++` | gRPC C++ |
| `protobuf` | Protocol Buffers |
| `spdlog` | spdlog |
| `nlohmann_json` | nlohmann-json |
| `CLI11` | CLI11 |
| `catch2-with-main` | Catch2 (tests only, in `tests/meson.build`) |

#### Meson Proto Codegen (`proto/meson.build`)

```meson
proto_out_dir = meson.current_build_dir() / 'generated'

custom_target(name + '_proto',
  output: [name + '.pb.cc', name + '.pb.h',
           name + '.grpc.pb.cc', name + '.grpc.pb.h'],
  command: [protoc, '--cpp_out=' + proto_out_dir,
            '--grpc_out=' + proto_out_dir,
            '--plugin=protoc-gen-grpc=' + ..., '-I', proto_src_dir, '@INPUT@'],
)
```

Outputs go to `<builddir>/proto/generated/`. The `yuzu_proto` static library wraps all generated sources and is exposed via `yuzu_proto_dep`. To add a new `.proto` file under Meson, add it to the `proto_files` list in `proto/meson.build`.

#### Meson Target Summary

| `meson.build` | Target | Type | Notes |
|---------------|--------|------|-------|
| `agents/core` | `yuzu_agent_core` | `static_library` | |
| `agents/core` | `yuzu-agent` | `executable` | `install: true` |
| `agents/plugins/example` | `example` | `shared_library` | `name_prefix: ''` → `example.so`/`.dll` |
| `proto` | `yuzu_proto` | `static_library` | wraps generated sources |
| `sdk` | *(header-only)* | `declare_dependency` | no compiled library |
| `server/core` | `yuzu_server_core` | `static_library` | |
| `server/core` | `yuzu-server` | `executable` | `install: true` |
| `tests` | `yuzu_tests` | `executable` | registered via `test('unit tests', ...)` |

Plugin install path (Meson): `get_option('libdir') / 'yuzu' / 'plugins'`
(e.g., `/usr/lib/yuzu/plugins/example.so`)

### Build Outputs

| Artifact | CMake location | Meson location |
|----------|---------------|----------------|
| Binaries | `${build}/bin/` | `<builddir>/` |
| Libraries | `${build}/lib/` | `<builddir>/` |
| Generated protos | `${build}/generated/proto/` | `<builddir>/proto/generated/` |

> **Generated files are in `.gitignore`** — `*.pb.h`, `*.pb.cc`, `*.grpc.pb.*` are never committed.

---

## Running Tests

```bash
# CMake
cmake -B build -DYUZU_BUILD_TESTS=ON ...
cmake --build build
ctest --test-dir build --output-on-failure -j $(nproc)

# Via preset (uses testPresets in CMakePresets.json)
ctest --preset linux-debug

# Meson
meson setup builddir -Dbuild_tests=true
meson test -C builddir
```

- Tests live in `tests/unit/test_plugin_loader.cpp` and use **Catch2 3.x**.
- **CMake:** links `Catch2::Catch2WithMain`; tests discovered with `catch_discover_tests(yuzu_tests)`.
- **Meson:** `dependency('catch2-with-main')` in `tests/meson.build`; registered with `test('unit tests', test_exe)`.
- Both link against `yuzu_agent_core` and the SDK.

---

## Dependencies

Managed via `vcpkg.json` (manifest mode, baseline `a42af01b72c28a8e1d7b48107b3c26c8ac3aa0b6`).

| Package | Platform | Purpose |
|---------|----------|---------|
| `grpc` + `codegen` feature | all | RPC framework + protoc plugin |
| `protobuf` | all | Message serialization |
| `abseil` ≥ 20240116 | all | Foundation lib (required by gRPC) |
| `spdlog` | all | Structured logging |
| `nlohmann-json` | all | JSON config parsing |
| `cli11` | all | CLI argument parsing |
| `openssl` | `!windows` | TLS / cryptography |
| `schannel` | `windows` | Windows native TLS |
| `catch2` | `!(arm & !x64)` | Unit testing (excluded on pure ARM) |

---

## Code Conventions

### Naming

| Entity | Convention | Example |
|--------|-----------|---------|
| Namespaces | `snake_case` | `yuzu::agent`, `yuzu::server` |
| Classes / Structs | `PascalCase` | `AgentImpl`, `PluginHandle`, `Config` |
| Functions / Methods | `snake_case` | `create()`, `scan()`, `write_output()` |
| Constants | `kCamelCase` | `kVersionString`, `kVersionMajor` |
| Macros | `SCREAMING_SNAKE_CASE` | `YUZU_PLUGIN_EXPORT`, `YUZU_BUILD_AGENT` |
| Private members | trailing `_` | `cfg_`, `descriptor_`, `handle_` |

### C++ Style

- **Standard:** C++23; use `std::expected`, ranges, structured bindings, `std::make_unique`.
- **Error handling:** Prefer `std::expected<T, E>` (via `yuzu::Result<T>`) over exceptions.
- **Attributes:** `[[nodiscard]]` on all query methods; `noexcept` on leaf functions.
- **Ownership:** `std::unique_ptr`; no raw owning pointers.
- **Const-correctness:** Strictly observed throughout.
- **PIMPL:** Public headers expose an interface + `create()` factory; implementation lives in `*Impl` classes in `.cpp` files.
- **Visibility:** `-fvisibility=hidden` (GCC/Clang); explicitly mark exported symbols.
- **No broad imports:** Never `using namespace std;` or similar in headers.

### Design Patterns

- **Factory:** `Agent::create(cfg)`, `Server::create(cfg)`, `PluginHandle::load(path)`
- **CRTP base:** `yuzu::Plugin<Derived>` for compile-time polymorphism in the C++ SDK wrapper
- **RAII:** `PluginHandle` manages `dlopen`/`dlclose` lifecycle
- **Stable C ABI:** All plugin entry points in `sdk/include/yuzu/plugin.h` — never reorder or remove fields in `YuzuPluginDescriptor`; only append

### Logging

Uses **spdlog**. Levels: `trace`, `debug`, `info`, `warn`, `error`.

```
[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] [%t] %v
```

### Proto / gRPC Conventions

- All `.proto` files live under `proto/yuzu/<service>/v1/`.
- Package names follow the directory: `yuzu.agent.v1`, `yuzu.common.v1`, `yuzu.server.v1`.
- **Do not commit generated files.** They are in `.gitignore`.
- **CMake:** `GLOB_RECURSE` auto-discovers new files in `proto/` — no manual registration needed.
- **Meson:** Add new `.proto` files to the `proto_files` list in `proto/meson.build`.
- Generated headers are included as `#include "<stem>.pb.h"` (no subdirectory prefix).

### Plugin Development

Plugins implement the C ABI in `sdk/include/yuzu/plugin.h`. Use the C++ CRTP wrapper:

```cpp
#include <yuzu/plugin.hpp>

class MyPlugin : public yuzu::Plugin<MyPlugin> {
public:
    static constexpr auto name    = "my_plugin";
    static constexpr auto version = "1.0.0";

    yuzu::Result<void> execute(std::string_view action,
                               const yuzu::Params& params,
                               yuzu::CommandContext& ctx) {
        if (action == "ping") {
            ctx.write_output("pong");
            return {};
        }
        return std::unexpected(yuzu::PluginError::UnknownAction);
    }
};

YUZU_PLUGIN_EXPORT(MyPlugin)   // generates C export trampolines
```

Plugins are built as **shared libraries** with no `lib` prefix (Meson: `name_prefix: ''`). They are installed to `<libdir>/yuzu/plugins/`. See `agents/plugins/example/` for the full reference implementation.

---

## Architecture Summary

```
┌──────────────────────────────────┐
│         Yuzu Server              │
│  ┌─────────┐  ┌──────────────┐  │
│  │ Gateway │  │  AgentMgr    │  │
│  │ (TBD)   │  │  (sessions)  │  │
│  └─────────┘  └──────────────┘  │
│        ↕ ManagementService       │
└──────────────────────────────────┘
         ↕ AgentService (gRPC TLS)
┌──────────────────────────────────┐
│         Yuzu Agent               │
│  ┌────────────┐  ┌────────────┐  │
│  │ PluginHost │  │ Plugin A   │  │
│  │  (loader)  │  │ Plugin B   │  │
│  └────────────┘  └────────────┘  │
└──────────────────────────────────┘
```

- **AgentService** (`proto/yuzu/agent/v1/`) — bidirectional streaming: Register, Heartbeat, ExecuteCommand, Subscribe, ReportInventory
- **ManagementService** (`proto/yuzu/server/v1/`) — operator API: ListAgents, GetAgent, SendCommand, WatchEvents, QueryInventory

---

## CI/CD

GitHub Actions (`.github/workflows/ci.yml`) triggers on:
- Push to `main`, `feature/**`, `fix/**`
- Pull requests targeting `main`

Concurrency: cancels in-progress runs for the same workflow + ref.

| Job | Runner | Compiler | Triplet | Tests run |
|-----|--------|----------|---------|-----------|
| `linux` | ubuntu-24.04 | GCC 13 or Clang 17 | x64-linux | yes |
| `windows` | windows-2022 | MSVC (VS 17 2022) | x64-windows | yes |
| `macos` | macos-14 | Apple Clang | arm64-osx | yes |
| `arm64-cross` | ubuntu-24.04 | aarch64-linux-gnu | arm64-linux | **no** (build only) |

All jobs:
- Use `lukka/run-vcpkg@v11` with the pinned baseline commit
- Enable vcpkg binary caching (`VCPKG_BINARY_SOURCES: "clear;x-gha,readwrite"`)
- Build Debug and Release (`fail-fast: false`)
- Run `YUZU_BUILD_TESTS=ON` (except ARM64 cross-compile)
- Windows uses `"Visual Studio 17 2022" -A x64` generator (not Ninja)

---

## Common Tasks

### Add a new source file to the agent

1. Place the file in `agents/core/src/` (or `include/yuzu/agent/` for headers).
2. **CMake:** Add to `target_sources(yuzu_agent_core ...)` in `agents/core/CMakeLists.txt`. Call `yuzu_set_compiler_flags(yuzu_agent_core)` if not already present.
3. **Meson:** Add to the `files(...)` list in `agents/core/meson.build`.

### Add a new proto message or service

1. Create/edit the `.proto` file under `proto/yuzu/<service>/v1/`.
2. **CMake:** `GLOB_RECURSE` picks it up automatically — no change needed.
3. **Meson:** Add the path to the `proto_files` list in `proto/meson.build`.
4. Include generated headers as `#include "<stem>.pb.h"`.

### Add a new test

1. Add a `TEST_CASE` block in `tests/unit/` (new or existing `.cpp` file).
2. If creating a new `.cpp` file:
   - **CMake:** Add to `target_sources(yuzu_tests ...)` in `tests/CMakeLists.txt`.
   - **Meson:** Add to `files(...)` in `tests/meson.build`.
3. Run: `ctest --test-dir build -R <test_name> --output-on-failure`

### Add a new plugin

1. Create `agents/plugins/<name>/src/<name>_plugin.cpp` implementing `yuzu::Plugin<Derived>`.
2. **CMake:** Create `agents/plugins/<name>/CMakeLists.txt` (model on `example`); add `add_subdirectory` under the `YUZU_BUILD_EXAMPLES` guard in root `CMakeLists.txt`.
3. **Meson:** Create `agents/plugins/<name>/meson.build` (model on `agents/plugins/example/meson.build`); add `subdir(...)` under `build_examples` guard in root `meson.build`.

### Add a new vcpkg dependency

1. Add the package to `"dependencies"` in `vcpkg.json`.
2. Re-run `cmake` to trigger vcpkg install.
3. Add `find_package(...)` and `target_link_libraries(...)` in the relevant `CMakeLists.txt`.
4. Add the `dependency(...)` call in the relevant `meson.build`.

---

## What to Avoid

- **Do not commit generated protobuf files.** They are regenerated at build time and listed in `.gitignore`.
- **Do not break the C ABI.** `YuzuPluginDescriptor` and `YuzuCommandContext` in `sdk/include/yuzu/plugin.h` must remain binary-stable. Only append new fields — never reorder or remove existing ones.
- **Do not throw exceptions across plugin boundaries.** Plugins are shared libraries; use `yuzu::Result<T>` / `std::expected` for all error propagation.
- **Do not use raw owning pointers.** Use `std::unique_ptr` or `std::shared_ptr`.
- **Do not use `using namespace std;`** or other broad namespace imports in headers.
- **Do not skip `yuzu_set_compiler_flags()`** on new CMake targets — this applies `-fvisibility=hidden`, sanitizers, and LTO consistently.
