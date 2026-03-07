# Yuzu — Claude Code Guide

Multi-platform agent and server framework for real-time endpoint management. C++23, gRPC/Protobuf, vcpkg, CMake 3.28+.

## Build

### Prerequisites
- CMake 3.28+, Ninja
- C++23 compiler: GCC 13+, Clang 17+, MSVC 19.38+, or Apple Clang 15+
- vcpkg (set `VCPKG_ROOT` or pass `CMAKE_TOOLCHAIN_FILE` manually)

### Configure and build (CMake presets — preferred)
```bash
cmake --preset linux-debug          # configure
cmake --build --preset linux-debug  # build
ctest --preset linux-debug          # test
```

Available presets: `linux-debug`, `linux-release`, `windows-debug`, `windows-release`, `macos-debug`, `macos-release`, `arm64-linux-debug`, `arm64-linux-release`.

### Manual configure (no VCPKG_ROOT)
```bash
cmake -B build -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=/path/to/vcpkg/scripts/buildsystems/vcpkg.cmake \
  -DVCPKG_TARGET_TRIPLET=x64-linux \
  -DCMAKE_BUILD_TYPE=Debug \
  -DYUZU_BUILD_TESTS=ON
cmake --build build --parallel $(nproc)
```

### Build options
| Option | Default | Notes |
|---|---|---|
| `YUZU_BUILD_AGENT` | ON | Agent daemon |
| `YUZU_BUILD_SERVER` | ON | Server daemon |
| `YUZU_BUILD_SDK` | ON | SDK headers + static helper lib |
| `YUZU_BUILD_TESTS` | OFF | Catch2 test suite |
| `YUZU_BUILD_EXAMPLES` | ON | Example plugin |
| `YUZU_ENABLE_LTO` | OFF | Link-time optimisation (ON in Release presets) |
| `YUZU_ENABLE_ASAN` | OFF | AddressSanitizer + UBSan |
| `YUZU_ENABLE_TSAN` | OFF | ThreadSanitizer |

## Test
```bash
ctest --test-dir build --output-on-failure -j $(nproc)
```
Tests require `-DYUZU_BUILD_TESTS=ON`. The Catch2 dependency is only installed by vcpkg on `x64 | arm64` platforms. The ARM64 cross-compile CI job intentionally skips tests.

## Project layout
```
agents/core/              Agent daemon (gRPC client, plugin loader)
agents/plugins/example/   Reference plugin implementation
server/core/              Server daemon (session management)
server/gateway/           gRPC gateway / TLS termination (TBD)
sdk/                      Public SDK — stable C ABI (plugin.h) + C++23 wrapper (plugin.hpp)
proto/                    Protobuf definitions (source of truth for wire protocol)
  yuzu/agent/v1/          AgentService: Register, Heartbeat, ExecuteCommand
  yuzu/common/v1/         Shared types: Platform, Timestamp, ErrorDetail
  yuzu/server/v1/         Management API
cmake/modules/
  YuzuProto.cmake         yuzu_proto_library() — runs protoc + grpc_cpp_plugin
  CompilerFlags.cmake     Warning flags, sanitizers, LTO helper
cmake/toolchains/         aarch64-linux-gnu and armv7-linux-gnueabihf cross-compile files
tests/unit/               Catch2 unit tests
```

## Protobuf / gRPC code generation
`YuzuProto.cmake` provides `yuzu_proto_library(NAME <target> PROTOS <files>)`. It:
1. Invokes `protoc` with `-I ${CMAKE_SOURCE_DIR}/proto`, preserving the package subdirectory in the output path (e.g. `yuzu/agent/v1/agent.pb.cc` under `build/generated/proto/`).
2. Builds a static library linking `gRPC::grpc++` and `protobuf::libprotobuf`.
3. Exposes `build/generated/proto/` as a PUBLIC include directory.

**Important**: The `OUTPUT` paths in `add_custom_command` must mirror where protoc actually writes files (relative to the import root, not just the bare filename). This was a past bug — don't revert to `NAME_WE`.

## vcpkg
- Manifest: `vcpkg.json`. Pinned baseline: `c1f21baeaf7127c13ee141fe1bdaa49eed371c0c` (matches `vcpkgGitCommitId` in CI).
- `builtin-baseline` is required because of the `version>=` constraint on abseil. Without it vcpkg resolves against HEAD.
- OpenSSL is skipped on Windows (`"platform": "!windows"`) — gRPC uses the native Windows crypto stack.
- `catch2` is platform-filtered to `x64 | arm64` (not 32-bit ARM).
- `schannel` is NOT a vcpkg port — don't add it. It's a Windows system library.

## CI matrix (`.github/workflows/ci.yml`)
| Job | Runner | Compiler | Triplet |
|---|---|---|---|
| linux | ubuntu-24.04 | GCC 13, Clang 17 | x64-linux |
| windows | windows-2022 | MSVC (VS 17 2022) | x64-windows |
| macos | macos-14 (Apple Silicon) | Apple Clang | arm64-osx |
| arm64-cross | ubuntu-24.04 | aarch64-linux-gnu gcc | arm64-linux |

vcpkg binary cache: `VCPKG_BINARY_SOURCES=clear;x-gha,readwrite`.

## Coding conventions
- **C++ standard**: C++23 throughout. Use `std::expected<T, E>` for errors, `std::span`, `std::string_view`, `std::format`.
- **Namespaces**: `yuzu::`, `yuzu::agent::`, `yuzu::server::`.
- **Naming**: PascalCase classes, snake_case variables/functions, `k`-prefix constants, trailing `_` for private members.
- **Headers**: `#pragma once` only. Include order: STL → third-party → project.
- **Plugin ABI**: C API in `sdk/include/yuzu/plugin.h` must stay stable. C++ ergonomics live in `plugin.hpp` (CRTP + `YUZU_PLUGIN_EXPORT` macro). Don't break the C boundary.
- **Entry points**: Both agent and server use CLI11 for args, spdlog for logging, and a `Factory::create(config)->run()` pattern with SIGINT/SIGTERM handlers.
- **Visibility**: `-fvisibility=hidden` is set globally; use `YUZU_EXPORT` to expose symbols intentionally.

## Authentication & Authorization (in progress)

mTLS for agent ↔ server is implemented. Remaining work:

1. **Enrollment token** — Add `enrollment_token` field to `RegisterRequest` in `agent.proto`. Server validates against a configured secret and rejects agents with invalid/missing tokens. Agent reads token from config/CLI.
2. **API key guard on HTTP endpoints** — Protect `/api/*` and `/events` with a static API key (`Authorization: Bearer <key>` header). Config/env-driven. Dashboard should prompt or embed the key.
3. **Admin / read-only roles** — Two-role model tied to API keys. Read-only: view dashboard, list agents, query inventory. Admin: send commands. `management.proto` already notes auth policies differ between agent-facing and operator-facing services.

Certificate setup instructions: `scripts/Certificate Instructions.txt`.
