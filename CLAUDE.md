# Yuzu — Claude Code Guide

Multi-platform agent and server framework for real-time endpoint management. C++23, gRPC/Protobuf, vcpkg, Meson.

## Build

### Prerequisites
- Meson 1.9.2, Ninja
- CMake (required by Meson's cmake dependency method — not used as a build system)
- C++23 compiler: GCC 13+, Clang 17+, MSVC 19.38+, or Apple Clang 15+
- vcpkg (set `VCPKG_ROOT`)

### Quick start (setup script)
```bash
./scripts/setup.sh                              # debug build, default compiler
./scripts/setup.sh --buildtype release --lto    # release + LTO
./scripts/setup.sh --tests                      # enable tests
./scripts/setup.sh --native-file meson/native/linux-gcc13.ini
./scripts/setup.sh --cross-file meson/cross/aarch64-linux-gnu.ini
```
The script runs `vcpkg install` then `meson setup` automatically.

### Manual configure
```bash
# 1. Install vcpkg packages
vcpkg install --triplet x64-linux --x-manifest-root=.

# 2. Configure
meson setup builddir \
  --buildtype=debug \
  -Dcmake_prefix_path=$VCPKG_ROOT/installed/x64-linux \
  -Dbuild_tests=true

# 3. Build
meson compile -C builddir
```

### Build options
| Option | Default | Notes |
|---|---|---|
| `-Dbuild_agent` | true | Agent daemon |
| `-Dbuild_server` | true | Server daemon |
| `-Dbuild_tests` | false | Catch2 test suite |
| `-Dbuild_examples` | true | Example plugins |
| `-Db_lto` | false | Link-time optimisation |
| `-Db_sanitize=address,undefined` | none | AddressSanitizer + UBSan |
| `-Db_sanitize=thread` | none | ThreadSanitizer |

Sanitizers and LTO use Meson built-in options (`b_lto`, `b_sanitize`).

## Test
```bash
meson test -C builddir --print-errorlogs
```
Tests require `-Dbuild_tests=true`. The Catch2 dependency is only installed by vcpkg on `x64 | arm64` platforms. The ARM64 cross-compile CI job intentionally skips tests.

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
  gen_proto.py            Codegen script (invoked by meson.build)
meson/cross/              Cross-compilation files (aarch64, armv7)
meson/native/             Native files for CI compilers (gcc-13, clang-17, etc.)
scripts/setup.sh          vcpkg install + meson setup convenience wrapper
tests/unit/               Catch2 unit tests
```

## Protobuf / gRPC code generation
`proto/meson.build` uses a `custom_target` that invokes `proto/gen_proto.py`. The script:
1. Runs `protoc` with `--cpp_out` and `--grpc_out` for each `.proto` file.
2. Rewrites `#include` paths to flatten subdirectory prefixes (so generated headers can be included as `"common.pb.h"` rather than `"yuzu/common/v1/common.pb.h"`).
3. Moves all generated files to a flat output directory.

The result is the `yuzu_proto` static library, exposed via `yuzu_proto_dep`.

## vcpkg
- Manifest: `vcpkg.json`. Pinned baseline: `4b77da7fed37817f124936239197833469f1b9a8` (matches `vcpkgGitCommitId` in CI).
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

vcpkg binary cache: `actions/cache` on `vcpkg/installed`, keyed on `vcpkg.json` + `vcpkg-configuration.json` hash.

## Coding conventions
- **C++ standard**: C++23 throughout. Use `std::expected<T, E>` for errors, `std::span`, `std::string_view`, `std::format`.
- **Namespaces**: `yuzu::`, `yuzu::agent::`, `yuzu::server::`.
- **Naming**: PascalCase classes, snake_case variables/functions, `k`-prefix constants, trailing `_` for private members.
- **Headers**: `#pragma once` only. Include order: STL → third-party → project.
- **Plugin ABI**: C API in `sdk/include/yuzu/plugin.h` must stay stable. C++ ergonomics live in `plugin.hpp` (CRTP + `YUZU_PLUGIN_EXPORT` macro). Don't break the C boundary.
- **Entry points**: Both agent and server use CLI11 for args, spdlog for logging, and a `Factory::create(config)->run()` pattern with SIGINT/SIGTERM handlers.
- **Visibility**: `-fvisibility=hidden` is set globally; use `YUZU_EXPORT` to expose symbols intentionally.

## Build system — Meson only

Meson is the sole build system. **Every time you add, remove, or rename a source file, update `meson.build` in the affected directory.** Always verify the meson build compiles after any change.

### Windows build (from MSYS2 bash)
```bash
source ./setup_msvc_env.sh
meson compile -C builddir
```

**IMPORTANT — do NOT use vcvars64.bat.** It returns exit code 1 due to optional extension failures (Clang, bundled CMake, ConnectionManager) even though cl.exe is set up correctly. This causes `.bat` wrapper scripts to abort or misbehave. `setup_msvc_env.sh` sets all MSVC paths directly in MSYS2 bash and is the only supported build method.

### Cross-compilation
```bash
./scripts/setup.sh --cross-file meson/cross/aarch64-linux-gnu.ini
```
Cross files live in `meson/cross/`. Native files for CI compiler selection live in `meson/native/`.

### Windows toolchain requirements
All paths are configured by `setup_msvc_env.sh`. Do **not** use Clang (`C:\Program Files\LLVM\bin`) — must use cl.exe/MSVC.
| Tool | Path |
|---|---|
| cl.exe | `C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\cl.exe` |
| cmake.exe | `C:\Program Files\CMake\bin\cmake.exe` (needed by Meson's cmake dep method) |
| ninja.exe | Installed with CMake or VS BuildTools |
| meson | `pip install meson==1.9.2` (Python) |
| vcpkg | `C:\Users\natha\vcpkg` (`VCPKG_ROOT`) |
| protoc | `C:\Users\natha\vcpkg\installed\x64-windows\tools\protobuf\protoc.exe` |
| grpc_cpp_plugin | `C:\Users\natha\vcpkg\installed\x64-windows\tools\grpc\grpc_cpp_plugin.exe` |

## Authentication & Authorization

### Implemented
- **mTLS** for agent ↔ server gRPC connections.
- **RBAC login** — session-cookie auth with PBKDF2-hashed passwords in `yuzu-server.cfg`. Two roles: `admin` (full access) and `user` (read-only). First-run interactive setup prompts for credentials.
- **Login page** — dark-themed, with greyed-out OIDC SSO stub ("Coming soon").
- **Settings page** (admin-only) — TLS toggle, PEM cert upload, user management, enrollment tokens, pending agent approvals, greyed-out AD/Entra section.
- **Hamburger menu** — upper-right dropdown with Settings, About (popup), and Logout.
- **Auth middleware** — `set_pre_routing_handler` redirects unauthenticated requests to `/login`, returns 401 for API calls.
- **Tiered agent enrollment**:
  - **Tier 1 (manual approval)** — agents without a token enter a pending queue; admin approves/denies via Settings page. Agents retry and are accepted once approved.
  - **Tier 2 (pre-shared tokens)** — admin generates time/use-limited enrollment tokens via the dashboard; agents pass `--enrollment-token <token>` at startup for auto-enrollment.
  - **Tier 3 (platform trust)** — proto fields reserved (`machine_certificate`, `attestation_signature`, `attestation_provider`) for future Windows cert store / cloud attestation enrollment.
- **Enrollment token persistence** — tokens stored in `enrollment-tokens.cfg`, pending agents in `pending-agents.cfg` (same directory as `yuzu-server.cfg`).
- **Agent `--enrollment-token` CLI flag** — passes token in `RegisterRequest.enrollment_token`.
- **Windows certificate store integration** — agent can read mTLS client cert + private key from the Windows cert store instead of PEM files. Uses CryptoAPI/CNG (`CertOpenStore`, `CertFindCertificateInStore`, `NCryptExportKey`). Searches Local Machine first, falls back to Current User. Exports full certificate chain (leaf + intermediates) as PEM. CLI flags: `--cert-store MY --cert-subject "yuzu-agent"` or `--cert-thumbprint "AB12..."`.
- **HTMX paradigm** — Settings page uses HTMX for all server interactions; server renders HTML fragments. Vanilla JS reserved only for clipboard copy. Dominant UI pattern going forward.

### Remaining work
1. **Tier 3 platform trust server-side** — server validates machine certificates against enterprise CA for auto-enrollment (agent-side cert store reading is done; server-side validation is not).
2. **HTTPS for web dashboard** — currently HTTP only; add TLS termination.
3. **OIDC SSO** — replace the stub login button with real OIDC flow.
4. **AD/Entra directory integration** — inherit roles from domain groups.
5. **macOS Keychain / Linux PKCS#11** — cert store integration for non-Windows platforms.

Certificate setup instructions: `scripts/Certificate Instructions.txt`.
