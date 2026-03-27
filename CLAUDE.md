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

## Agent Team

Yuzu uses specialized Claude Code agents for enterprise-quality development.
Agents live in `.claude/agents/` and are invoked by name.

| Agent | Role | Primary Concern |
|-------|------|-----------------|
| architect | System Architect | Module boundaries, proto compat, ABI stability |
| security-guardian | Security Engineer | Auth enforcement, crypto, input validation, audit |
| happy-path | Happy Path Reviewer | Normal-condition correctness, logic completeness |
| unhappy-path | Unhappy Path Reviewer | Failure-mode interrogation, risk register, chaos feeds |
| consistency-auditor | Consistency Auditor | Cross-component state/schema/contract consistency |
| chaos-injector | Chaos Injector | Controlled failure scenario generation from identified risks |
| quality-engineer | QA & Test Engineer | Test coverage, fuzz targets, coverage thresholds |
| cross-platform | Platform Compatibility | Win/Linux/macOS/ARM64 builds, OS-specific code |
| docs-writer | Technical Writer | User manual, YAML defs, API docs, roadmap |
| build-ci | Build & CI/CD | Meson, vcpkg, GitHub Actions, proto codegen |
| performance | Performance Engineer | SQLite optimization, load testing, gateway scaling |
| erlang-dev | Erlang Developer | Erlang idioms, process lifecycle, EXIT signals, EUnit isolation |
| gateway-erlang | Erlang/OTP Specialist | Gateway supervision, rebar3, EUnit/CT |
| plugin-developer | Plugin Dev & SDK | New plugins, ABI guard, InstructionDefinition YAML |
| release-deploy | Release & Deployment | Docker, systemd, installers, release workflow |
| dsl-engineer | DSL & Expression Language | Scope DSL, CEL, parameter interpolation, trigger expressions, workflow primitives |

**Workflow:** architect first (design) → feature agents (implement) → erlang-dev (review Erlang code) → cross-platform (compile) → security-guardian (review) → happy-path + unhappy-path + consistency-auditor (parallel analysis) → chaos-injector (failure scenarios) → quality-engineer (test) → docs-writer (document) → build-ci (CI green) → performance (if data-plane) → release-deploy (if packaging).

**DSL touchpoints:** dsl-engineer is invoked as a feature agent for scope targeting, policy conditions (CEL), trigger template expressions, parameter binding, workflow primitives, and any YAML DSL spec evolution.

**Correctness & resilience touchpoints:** happy-path, unhappy-path, and consistency-auditor are invoked for all changes during full governance. consistency-auditor is additionally invoked when changes touch protobuf schemas, database schemas, API contracts, or cross-component state. chaos-injector runs after all three complete, synthesizing risks into executable failure scenarios. Gate 5 (chaos analysis) is skipped if gate 4 produces no findings.

### Governance

**Better process makes better products.** Every code change follows mandatory governance gates — no shortcuts, no exceptions:

1. **Change Summary** — the producing agent writes a structured summary (files, what, why, interfaces affected, security surface, user-facing impact) shared with ALL agents.
2. **Mandatory deep-dive** — security-guardian and docs-writer read every modified file for every change. Security reviews block on CRITICAL/HIGH findings. Documentation blocks if user-facing changes lack doc updates.
3. **Domain-triggered review** — architect, quality-engineer, cross-platform, performance, build-ci, dsl-engineer, erlang-dev, gateway-erlang, plugin-developer, and release-deploy review when changes touch their domain.
4. **Correctness & resilience analysis** — happy-path, unhappy-path, and consistency-auditor run in parallel. happy-path validates normal-condition correctness. unhappy-path performs systematic failure-mode interrogation and produces a risk register. consistency-auditor checks cross-component state/schema/contract consistency. All three are mandatory during full governance; consistency-auditor also triggers on schema evolution and protocol changes.
5. **Chaos analysis** — chaos-injector ingests outputs from unhappy-path and consistency-auditor to generate controlled failure scenarios with success criteria and rollback procedures. Runs only after gate 4 completes. Skipped if gate 4 produces no findings.
6. **All findings addressed** before merge — CRITICAL/HIGH are blocking, MEDIUM should be fixed, LOW addressed.
7. **Iterate** — re-review after fixes until the team gives a clean bill. No commit until governance passes.

**Lesson learned:** Waves 1-4 shipped without governance and accumulated 4 CRITICAL command injection vulnerabilities, untested stores, stale docs, and performance bottlenecks. These were caught before production but should have been caught before commit.

## Darwin Compatibility

This Claude instance is the designated **macOS/Darwin compatibility guardian** for Yuzu. When Windows-originated changes land on `origin/dev`, the standing workflow is:

1. `git fetch origin && git status` — confirm branch state.
2. `git pull` — fast-forward to latest dev.
3. `git diff HEAD~N..HEAD --stat` — review what changed.
4. Identify which previous Darwin fixes are still present in the new tree.
5. `meson setup builddir --reconfigure ...` if `meson.build` changed.
6. `meson compile -C builddir` — fix any new compile errors.
7. `bash scripts/run-tests.sh all` — fix any new test failures.
8. Commit clean with a Darwin-fix commit message.

### Standing Darwin pitfalls

| Area | Issue |
|---|---|
| Path comparisons | macOS `/var` → `/private/var` symlink: always call `fs::canonical()` on both sides before comparing paths in tests. |
| SQLite concurrency | Any new store that emits from multiple threads needs a mutex protecting the `db_` handle. |
| Erlang rebar3 ct | Always pass `--dir apps/yuzu_gw/test` together with `--suite` flags. |
| `curl -f` in tests | Do **not** use `-f` where 4xx is an acceptable response — it causes `|| echo "000"` fallbacks to contaminate the status code variable. |
| `prometheus_httpd` | Use `start/0` with `application:set_env(prometheus, prometheus_http, [{port, P}, {path, "/metrics"}])` — `start/1` does not exist. Call `application:ensure_all_started(prometheus_httpd)` first so `prometheus_http_impl:setup/0` runs before the first scrape. |

After any cross-platform change, always run `bash scripts/run-tests.sh all` on Darwin before committing.

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

The full roadmap is in `docs/roadmap.md` with 72 issues across 7 phases (all complete). The capability map (`docs/capability-map.md`) tracks 184 capabilities. Current progress: 165/184 done (90%).

**Phase execution order (all complete):**
0. Foundation completion (HTTPS, OTA updates, SDK utilities) — **Done**
1. Server data infrastructure (response store, audit, tags, scope engine) — **Done**
2. Instruction system (definitions, sets, scheduling, approvals, workflows) — **Done**
3. Security & RBAC (granular permissions, management groups, OIDC, REST API) — **Done**
4. Agent infrastructure (KV storage, triggers, content distribution, user interaction) — **Done**
5. Policy engine (rules, deployment, compliance dashboard) — **Done**
6. Windows depth (registry, WMI, per-user operations) — **Done**
7. Scale & integration (gateway, health monitoring, AD/Entra, patches, webhooks) — **Done**

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
agents/plugins/           44 plugins (hardware, network, security, filesystem, etc.)
server/core/              Server daemon (sessions, auth, dashboard, REST API, policy engine)
gateway/                  Erlang/OTP gateway node (standalone rebar3 project, see docs/erlang-gateway-blueprint.md)
sdk/                      Public SDK — stable C ABI (plugin.h) + C++23 wrapper (plugin.hpp)
proto/                    Protobuf definitions (source of truth for wire protocol)
  yuzu/agent/v1/          AgentService: Register, Heartbeat, ExecuteCommand, Subscribe
  yuzu/common/v1/         Shared types: Platform, Timestamp, ErrorDetail
  yuzu/server/v1/         ManagementService API
  yuzu/gateway/v1/        GatewayUpstream — server-side RPCs the Erlang gateway calls into
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

## Documentation requirements

All new features must be documented for human usability. **After writing or modifying code, the user manual section covering that feature must be updated to reflect the current user experience.** Documentation lives in `docs/user-manual/` and is the primary reference for operators.

- **User manual updates** — after implementing or changing a feature, update the relevant `docs/user-manual/*.md` file to match the current behavior. If the feature spans a new area, create a new manual section and add it to `docs/user-manual/README.md`.
- **YAML instruction definitions** — every new plugin must have corresponding `InstructionDefinition` YAML files in `content/definitions/` following the `yuzu.io/v1alpha1` DSL spec (`docs/yaml-dsl-spec.md`).
- **Substrate primitive registration** — new plugin actions must be added to the Substrate Primitive Reference table in `docs/yaml-dsl-spec.md` (section 14).
- **REST API documentation** — new or changed REST API endpoints must be reflected in `docs/user-manual/rest-api.md` with method, path, permissions, request/response examples.
- **CLAUDE.md updates** — architectural decisions, new stores, new plugin patterns, and cross-cutting concerns should be reflected here so future Claude sessions understand the system.

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
- **HTTPS by default** — `https_enabled` defaults to `true`. Operators must provide `--https-cert` and `--https-key`, or use `--no-https` for development. The `--https` flag was replaced with `--no-https`.
- **Secure bind default** — Web UI binds to `127.0.0.1` by default (not `0.0.0.0`). A startup warning is logged if overridden to all interfaces.
- **Metrics auth** — `/metrics` allows unauthenticated access from localhost only. Remote access requires authentication. `--metrics-no-auth` overrides for monitoring infrastructure.
- **Private key permission validation** — Server refuses to start if TLS private key files are group/others-readable on Unix. Uses `std::filesystem::perms` check. Skipped on Windows.
- **CORS on all API endpoints** — CORS headers applied via `set_post_routing_handler` for all `/api/` paths.
- **JSON error envelope** — All error responses use structured `{"error":{"code":N,"message":"..."},"meta":{"api_version":"v1"}}` envelope. Health probes (`/livez`, `/readyz`) use `{"status":"..."}` contract.
- **Certificate hot-reload** — HTTPS cert/key PEM files are polled for changes (default 60s interval) and hot-swapped without server restart. Validates PEM parse, cert/key match, and key file permissions before applying. gRPC TLS reload not supported. CLI: `--no-cert-reload`, `--cert-reload-interval`. Audit action: `cert.reload`. Metrics: `yuzu_server_cert_reloads_total`, `yuzu_server_cert_reload_failures_total`.

### Also Implemented (Phase 3 + Phase 7)
- **Granular RBAC** — 6 roles, 14 securable types, per-operation permissions, deny-override logic.
- **OIDC SSO** — Full PKCE flow, Entra ID discovery, JWT validation, group-to-role mapping.
- **API tokens** — Bearer token and `X-Yuzu-Token` header auth for automation. MCP tokens with mandatory expiration.
- **AD/Entra integration** — Microsoft Graph API for user/group import.

## MCP (Model Context Protocol) Server

Yuzu embeds an MCP server at `POST /mcp/v1/` using JSON-RPC 2.0 transport. This allows AI models (e.g., Claude Desktop) to securely query fleet status, check compliance, investigate agents, and — with appropriate authorization — execute instructions on endpoints.

### Architecture
- **Embedded in existing server** — MCP runs inside the same cpp-httplib server as the REST API and dashboard. It reuses auth middleware, RBAC, rate limiting, CORS, and audit logging with zero duplication.
- **Module:** `server/core/src/mcp_server.hpp` / `mcp_server.cpp` — mirrors `RestApiV1` pattern (injected store pointers, same callback signatures).
- **JSON-RPC helpers:** `mcp_jsonrpc.hpp` (header-only) — parse/build JSON-RPC 2.0 envelopes.
- **Tier policy:** `mcp_policy.hpp` (header-only) — static allow-lists per tier, checked before RBAC.
- **Output serialization:** Uses local `JObj`/`JArr` string builders (same pattern as `rest_api_v1.cpp`) to avoid the 56GB nlohmann template bloat. `nlohmann::json` is used for parsing only.

### Security Model
- **Three authorization tiers** enforced *before* RBAC: `readonly` (read only), `operator` (+ tag writes, auto-approved executions), `supervised` (all ops via approval workflow).
- **MCP tokens** use the existing API token system (`api_token_store`) with a new `mcp_tier` column. MCP tokens require mandatory expiration (max 90 days).
- **Approval workflow** — Operations that `requires_approval(tier, type, op)` returns true for are routed to the `ApprovalManager`. Admins approve/reject via Settings UI or REST API. All admins see all pending approvals (both AI-initiated and human-initiated).
- **Kill switch:** `--mcp-disable` rejects all `/mcp/v1/` requests with `kMcpDisabled` JSON-RPC error. `--mcp-read-only` blocks non-read tools.
- **Audit:** Every MCP tool call logged with `action: "mcp.<tool_name>"` and `mcp_tool` field on `AuditEvent`.

### Phase 1 (Implemented)
- 22 read-only tools: `list_agents`, `get_agent_details`, `query_audit_log`, `list_definitions`, `get_definition`, `query_responses`, `aggregate_responses`, `query_inventory`, `list_inventory_tables`, `get_agent_inventory`, `get_tags`, `search_agents_by_tag`, `list_policies`, `get_compliance_summary`, `get_fleet_compliance`, `list_management_groups`, `get_execution_status`, `list_executions`, `list_schedules`, `validate_scope`, `preview_scope_targets`, `list_pending_approvals`
- 3 resources: `yuzu://server/health`, `yuzu://compliance/fleet`, `yuzu://audit/recent`
- 4 prompts: `fleet_overview`, `investigate_agent`, `compliance_report`, `audit_investigation`
- Settings UI section with enable/disable and read-only toggles

### Phase 2 (Planned)
- 6 write/execute tools: `set_tag`, `delete_tag`, `execute_instruction`, `approve_request`, `reject_request`, `quarantine_device`
- Approval workflow integration for destructive operations
- SSE streaming for execution progress

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
