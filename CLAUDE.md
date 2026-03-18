# Yuzu — Claude Code Guide

## What is Yuzu?

Yuzu is an enterprise endpoint management platform — a single control plane for querying, commanding, patching, and enforcing compliance on Windows, Linux, and macOS fleets in real time. Think of it as an open-source alternative to commercial endpoint management platforms, built from scratch in C++23.

The project's goal is to match the full capability set of mature enterprise platforms (see `docs/capability-map.md`) while using modern architecture: gRPC/Protobuf transport, Prometheus-native metrics, SQLite for embedded storage, and a plugin ABI that is stable across compiler versions.

## Target Architecture

```
Operators (browser, REST API, automation scripts)
    │
    ▼
Yuzu Server
    ├── REST API (v1) — versioned, JSON, token or session auth
    ├── HTMX Dashboard — server-rendered, dark theme
    ├── Instruction Engine — definitions, scheduling, approval workflows
    ├── Policy Engine (Guaranteed State) — desired-state rules + triggers + auto-remediation
    ├── Response Store (SQLite) — persistent, filterable, aggregatable
    ├── Scope Engine — expression-tree device targeting (AND/OR/NOT, tags, OS, groups)
    ├── RBAC — principals, roles, securable types, per-operation permissions
    ├── Audit Log — who did what, when, on which devices
    ├── Scheduler — cron-style recurring instructions
    ├── Metrics — Prometheus /metrics endpoint
    └── Management Groups — hierarchical device grouping for access scoping
         │
         │ gRPC / Protobuf / mTLS (bidirectional streaming)
         │
    Yuzu Agent (per endpoint)
    ├── Plugin Host — dynamic .so/.dll loading via stable C ABI
    ├── Trigger Engine — interval, file change, service status, event log, registry, startup
    ├── KV Storage — SQLite-backed persistent storage for cross-instruction state
    ├── Content Distribution — HTTP download with hash verification, stage-and-execute
    ├── User Interaction — desktop notifications, questions, surveys (Windows)
    └── Metrics — Prometheus-compatible, per-plugin counters
```

## Instruction Engine

The instruction engine is the content plane — everything flows through YAML-defined InstructionDefinitions with typed parameter/result schemas, executed via the existing `CommandRequest` wire protocol. The content model is:

```
ProductPack → InstructionSet → InstructionDefinition
                                 ├── Parameter Schema (JSON Schema subset)
                                 ├── Result Schema (typed columns)
                                 └── Execution Spec (plugin + action)
```

Key design documents:
- `docs/Instruction-Engine.md` — Full architecture blueprint
- `docs/yaml-dsl-spec.md` — YAML DSL formal specification (6 content kinds)
- `docs/getting-started.md` — Beginner's guide with tutorial

The YAML DSL uses `apiVersion: yuzu.io/v1alpha1` and supports 6 `kind` values: `InstructionDefinition`, `InstructionSet`, `PolicyFragment`, `Policy`, `TriggerTemplate`, `ProductPack`. Definitions are stored with `yaml_source` (verbatim YAML, source of truth) plus denormalized columns for queries.

## Development Roadmap

The full roadmap is in `docs/roadmap.md` with 56 issues across 7 phases. The capability map (`docs/capability-map.md`) tracks 139 capabilities. Current progress: 44/139 done (32%).

**Phase execution order:**
0. Foundation completion (HTTPS, OTA updates, SDK utilities) — **Done**
1. Server data infrastructure (response store, audit, tags, scope engine) — **Done**
2. Instruction system (definitions, sets, scheduling, approvals, workflows)
3. Security & RBAC (granular permissions, management groups, OIDC, REST API)
4. Agent infrastructure (KV storage, triggers, content distribution, user interaction)
5. Policy engine (rules, deployment, compliance dashboard)
6. Windows depth (registry, WMI, per-user operations)
7. Scale & integration (gateway, health monitoring, AD/Entra, patches, webhooks)

When working on any issue, check the roadmap for dependencies and the capability map for context on what we're building toward.

## Build

### Prerequisites
- Meson 1.9.2, Ninja
- CMake (required by Meson's cmake dependency method — not used as a build system)
- C++23 compiler: GCC 13+, Clang 18+, MSVC 19.38+, or Apple Clang 15+
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
agents/core/              Agent daemon (gRPC client, plugin loader, trigger engine)
agents/plugins/           29 plugins (hardware, network, security, filesystem, etc.)
server/core/              Server daemon (sessions, auth, dashboard, REST API, policy engine)
server/gateway/           gRPC gateway / TLS termination (proto defined, not yet implemented)
sdk/                      Public SDK — stable C ABI (plugin.h) + C++23 wrapper (plugin.hpp)
proto/                    Protobuf definitions (source of truth for wire protocol)
  yuzu/agent/v1/          AgentService: Register, Heartbeat, ExecuteCommand, Subscribe
  yuzu/common/v1/         Shared types: Platform, Timestamp, ErrorDetail
  yuzu/server/v1/         ManagementService API
  yuzu/gateway/v1/        GatewayUpstream: ProxyRegister, BatchHeartbeat
  gen_proto.py            Codegen script (invoked by meson.build)
docs/                     Architecture docs, roadmap, capability map
meson/cross/              Cross-compilation files (aarch64, armv7)
meson/native/             Native files for CI compilers (gcc-13, clang-18, etc.)
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
| linux | ubuntu-24.04 | GCC 13, Clang 18 | x64-linux |
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

## Observability conventions
- **Prometheus metrics**: All metrics use `yuzu_` prefix. Server: `yuzu_server_*`. Agent: `yuzu_agent_*`.
- **Labels**: Consistent label set — `agent_id`, `plugin`, `method`, `status`, `os`, `arch`.
- **Histograms**: Default buckets: 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0.
- **Response schemas**: All instruction response data must be typed (bool, int32, int64, string, datetime) for downstream consumption by ClickHouse, Splunk, or other analytics.
- **Audit events**: Structured JSON with `timestamp`, `principal`, `action`, `target`, `detail`. Suitable for Splunk HEC or webhook delivery.
- **Event format**: All events (lifecycle, compliance, audit) follow a common envelope: `{event_type, timestamp, source, payload}` for consistent downstream parsing.

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
| python | `C:\Python314\python.exe` (system-wide, installed via Chocolatey) |
| meson | `C:\Python314\Scripts\meson.exe` (`pip install meson==1.9.2`) |
| vcpkg | `C:\vcpkg` (`VCPKG_ROOT`) |
| protoc | `C:\vcpkg\installed\x64-windows\tools\protobuf\protoc.exe` |
| grpc_cpp_plugin | `C:\vcpkg\installed\x64-windows\tools\grpc\grpc_cpp_plugin.exe` |

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

### Planned (see roadmap)
- **Granular RBAC** — Principals, roles, securable types, per-operation permissions (Phase 3)
- **OIDC SSO** — Replace stub with real OIDC flow (Phase 3)
- **API tokens** — Bearer token auth for automation (Phase 3)
- **AD/Entra integration** — Import users/groups from directory (Phase 7)
- **HTTPS for dashboard** — TLS termination (Phase 0)

Certificate setup instructions: `scripts/Certificate Instructions.txt`.

## Data architecture for analytics integration

When building new features, design data schemas with downstream analytics in mind:

### Response data
- Every instruction definition declares a typed schema (column name + type)
- Types: `bool`, `int32`, `int64`, `string`, `datetime`, `guid`, `clob`
- This makes it trivial to create ClickHouse tables or Splunk sourcetypes
- Large text fields use `clob` type with configurable truncation

### Audit events
- Structured as `{timestamp, principal, action, target_type, target_id, detail}`
- Can be forwarded to Splunk HEC or external webhook
- Indexed by timestamp and principal for efficient querying

### Metrics
- Prometheus exposition format on `/metrics`
- Labels: `agent_id`, `plugin`, `method`, `status`, `os`, `arch`
- Grafana dashboard templates in `docs/grafana/`
- ClickHouse can ingest via `prometheus_remote_write` or by scraping

### Inventory data
- Per-plugin structured blobs stored server-side
- Queryable via REST API with filter expressions
- Schema is self-describing (plugin reports its schema)
