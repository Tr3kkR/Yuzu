# CLAUDE.md — Yuzu Codebase Guide

This file provides context for AI assistants (Claude Code and similar tools) working on the Yuzu codebase.

---

## Project Overview

**Yuzu** is a multi-platform agent–server framework written in **C++23**. It enables real-time endpoint management via gRPC bidirectional streaming, with a language-agnostic plugin architecture built on a stable C ABI.

- **Language:** C++23 (std::expected, ranges, structured bindings)
- **Transport:** gRPC + Protocol Buffers with TLS built-in
- **Platforms:** Windows (x64), Linux (x64/ARM64), macOS (ARM64)
- **Version:** 0.1.0 — Initial Scaffold
- **License:** Apache 2.0

---

## Repository Layout

```
Yuzu/
├── agents/
│   ├── core/                  # Agent daemon (yuzu-agent binary)
│   │   ├── include/yuzu/agent/
│   │   │   ├── agent.hpp      # Agent class + Config
│   │   │   └── plugin_loader.hpp
│   │   └── src/
│   │       ├── agent.cpp
│   │       ├── plugin_loader.cpp
│   │       └── main.cpp       # CLI entry point (CLI11)
│   └── plugins/
│       └── example/           # Reference plugin implementation
├── cmake/
│   ├── modules/               # CompilerFlags.cmake, YuzuProto.cmake
│   └── toolchains/            # Cross-compile toolchains (e.g., aarch64)
├── proto/
│   └── yuzu/
│       ├── agent/v1/          # AgentService proto (Register, Heartbeat, ExecuteCommand…)
│       ├── common/v1/         # Shared types (Platform, PluginInfo, ErrorDetail, Timestamp)
│       └── server/v1/         # ManagementService proto (ListAgents, SendCommand…)
├── sdk/
│   └── include/yuzu/
│       ├── plugin.h           # C ABI — stable binary interface for plugins
│       ├── plugin.hpp         # C++ CRTP wrapper (yuzu::Plugin, yuzu::Result<T>)
│       └── version.hpp        # Version constants
├── server/
│   ├── core/                  # Server daemon (yuzu-server binary)
│   └── gateway/               # gRPC gateway (placeholder, TBD)
├── tests/
│   └── unit/
│       └── test_plugin_loader.cpp  # Catch2 unit tests
├── CMakeLists.txt             # Primary build system
├── CMakePresets.json          # Preset configs for all platforms
├── meson.build                # Alternative Meson build
├── meson.options              # Meson option definitions
├── vcpkg.json                 # Dependency manifest (pinned baseline)
├── vcpkg-configuration.json
├── .github/workflows/ci.yml   # GitHub Actions CI (4 platforms)
└── README.md
```

---

## Build System

The project supports both **CMake** (primary) and **Meson** (alternative). All builds use **vcpkg** in manifest mode for dependency management.

### Requirements

| Tool | Minimum Version |
|------|----------------|
| CMake | 3.28 |
| Meson | 1.3 |
| Ninja | any recent |
| GCC | 13+ |
| Clang | 17+ |
| MSVC | 19.38+ (VS 2022) |
| vcpkg | any (pinned baseline) |

### CMake — Recommended

```bash
# Configure using a preset (see CMakePresets.json)
cmake --preset linux-debug        # Debug, x64, GCC/Clang
cmake --preset linux-release
cmake --preset windows-debug      # MSVC, x64
cmake --preset macos-debug        # Apple Clang, arm64
cmake --preset arm64-linux-debug  # Cross-compile aarch64

# Build
cmake --build --preset linux-debug

# Manual configure (with tests enabled)
cmake -B build \
  -G Ninja \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_TOOLCHAIN_FILE=$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake \
  -DVCPKG_TARGET_TRIPLET=x64-linux \
  -DYUZU_BUILD_TESTS=ON

cmake --build build --parallel $(nproc)
```

### CMake Build Options

| Option | Default | Description |
|--------|---------|-------------|
| `YUZU_BUILD_AGENT` | ON | Build yuzu-agent daemon |
| `YUZU_BUILD_SERVER` | ON | Build yuzu-server daemon |
| `YUZU_BUILD_SDK` | ON | Build public SDK |
| `YUZU_BUILD_TESTS` | OFF | Enable Catch2 unit tests |
| `YUZU_BUILD_EXAMPLES` | ON | Build example plugins |
| `YUZU_ENABLE_LTO` | OFF | Link-time optimization |
| `YUZU_ENABLE_ASAN` | OFF | AddressSanitizer + UBSan |
| `YUZU_ENABLE_TSAN` | OFF | ThreadSanitizer |

### Meson

```bash
meson setup builddir -Dbuildtype=debug
meson compile -C builddir
meson test -C builddir
```

Meson options mirror the CMake ones: `build_agent`, `build_server`, `build_examples`, `build_tests`, `enable_lto`, `enable_asan`, `enable_tsan`.

### Build Outputs

| Artifact | Location |
|----------|----------|
| Binaries | `${build}/bin/` (yuzu-agent, yuzu-server) |
| Libraries | `${build}/lib/` |
| Generated protos | `${build}/generated/proto/` |

> **Note:** Generated protobuf files (`*.pb.h`, `*.pb.cc`, `*.grpc.pb.*`) are in `.gitignore` — they are created at build time by `cmake/modules/YuzuProto.cmake`.

---

## Running Tests

```bash
# CMake
cmake -DYUZU_BUILD_TESTS=ON ... && cmake --build build
ctest --test-dir build --output-on-failure -j $(nproc)

# Meson
meson test -C builddir
```

Tests live in `tests/unit/` and use **Catch2 3.x**. Test targets link against `yuzu::agent_core` and `yuzu::sdk`.

---

## Dependencies

Managed via `vcpkg.json` (manifest mode). The baseline commit is pinned in `vcpkg-configuration.json` for reproducibility.

| Package | Purpose |
|---------|---------|
| `grpc` | RPC framework (+ codegen feature) |
| `protobuf` | Message serialization |
| `abseil` (≥20240116) | Foundation lib (required by gRPC) |
| `spdlog` | Structured logging |
| `nlohmann-json` | JSON config parsing |
| `cli11` | Command-line argument parsing |
| `openssl` (non-Windows) | TLS/cryptography |
| `schannel` (Windows) | Windows native TLS |
| `catch2` (non-ARM) | Unit testing |

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
- **Attributes:** Use `[[nodiscard]]` on all query methods; `noexcept` on leaf functions.
- **Ownership:** Prefer `std::unique_ptr`; avoid raw owning pointers.
- **Const-correctness:** Strictly observed throughout.
- **PIMPL:** Public headers expose an interface + `create()` factory; implementation lives in `*Impl` classes in `.cpp` files.
- **Visibility:** Compile with `-fvisibility=hidden`; explicitly mark exported symbols.

### Design Patterns

- **Factory:** `Agent::create(cfg)`, `Server::create(cfg)`, `PluginHandle::load(path)`
- **CRTP base:** `yuzu::Plugin<Derived>` for compile-time polymorphism in the C++ SDK wrapper
- **RAII:** `PluginHandle` manages `dlopen`/`dlclose` lifecycle
- **Stable C ABI:** All plugin entry points defined in `sdk/include/yuzu/plugin.h` — never change existing field offsets in `YuzuPluginDescriptor`

### Logging

Uses **spdlog**. Log levels: `trace`, `debug`, `info`, `warn`, `error`. Format pattern:

```
[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] [%t] %v
```

### Proto / gRPC Conventions

- All `.proto` files live under `proto/yuzu/<service>/v1/`.
- Package names follow the directory: `yuzu.agent.v1`, `yuzu.common.v1`, `yuzu.server.v1`.
- New proto messages get generated at build time via `cmake/modules/YuzuProto.cmake` — do not commit generated files.
- When adding a new proto file, register it with the `yuzu_proto_library()` CMake helper.

### Plugin Development

Plugins implement the C ABI defined in `sdk/include/yuzu/plugin.h`. The C++ CRTP wrapper simplifies this:

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

See `agents/plugins/example/` for the full reference implementation.

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

- **AgentService** (`proto/yuzu/agent/v1/`) — agent ↔ server bidirectional streaming (Register, Heartbeat, ExecuteCommand, Subscribe, ReportInventory)
- **ManagementService** (`proto/yuzu/server/v1/`) — operator API (ListAgents, GetAgent, SendCommand, WatchEvents, QueryInventory)

---

## CI/CD

GitHub Actions (`.github/workflows/ci.yml`) runs on every push and PR across four matrix targets:

| Runner | Compiler | Triplet |
|--------|----------|---------|
| ubuntu-24.04 | GCC 13 + Clang 17 | x64-linux |
| windows-2022 | MSVC (VS 17 2022) | x64-windows |
| macos-14 | Apple Clang | arm64-osx |
| ubuntu-24.04 | aarch64-linux-gnu | arm64-linux |

All CI jobs:
- Use vcpkg binary caching (`VCPKG_BINARY_SOURCES`)
- Build with `YUZU_BUILD_TESTS=ON`
- Run `ctest --output-on-failure`
- Run both Debug and Release configurations

---

## Common Tasks

### Add a new source file to the agent

1. Place the file in `agents/core/src/` (or `include/yuzu/agent/` for headers).
2. Add it to the `target_sources(yuzu_agent_core ...)` block in `agents/core/CMakeLists.txt`.

### Add a new proto message or service

1. Create/edit the `.proto` file under `proto/yuzu/<service>/v1/`.
2. Register any new `.proto` file with `yuzu_proto_library()` in the relevant `CMakeLists.txt`.
3. Include the generated headers via `#include <yuzu/<service>/v1/...pb.h>`.

### Add a new test

1. Add a `TEST_CASE` block in `tests/unit/` (new or existing `.cpp` file).
2. If adding a new `.cpp` file, add it to `target_sources(yuzu_tests ...)` in `tests/CMakeLists.txt`.
3. Run with `ctest --test-dir build -R <test_name> --output-on-failure`.

### Add a new vcpkg dependency

1. Add the package to the `"dependencies"` array in `vcpkg.json`.
2. Re-run `cmake` to let vcpkg install the new package.
3. Add the corresponding `find_package` and `target_link_libraries` in the relevant `CMakeLists.txt`.

---

## What to Avoid

- **Do not commit generated protobuf files.** They are regenerated at build time and are listed in `.gitignore`.
- **Do not break the C ABI.** `YuzuPluginDescriptor` and `YuzuCommandContext` in `sdk/include/yuzu/plugin.h` must remain binary-stable. Only append new fields, never reorder or remove existing ones.
- **Do not throw exceptions across plugin boundaries.** Plugins are loaded as shared libraries; use `yuzu::Result<T>` / `std::expected` for error propagation.
- **Do not use raw owning pointers.** Use `std::unique_ptr` or `std::shared_ptr`.
- **Do not use `using namespace std;`** or other broad namespace imports in headers.
