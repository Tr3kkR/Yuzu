# Yuzu — Claude Code Guide

## What is Yuzu?

Yuzu is an agentic enterprise endpoint management platform — a single control plane where agentic colleagues can query, command, scan, patch, and enforce policy compliance on Windows, Linux, and macOS fleets in real time. Think of it as an open-source alternative to commercial endpoint management platforms, built from scratch in C++23.

Goal: match the capability set of mature enterprise platforms (`docs/capability-map.md`) with modern architecture — gRPC/Protobuf transport, Prometheus-native metrics, **PostgreSQL server substrate + SQLite on the agent** (ADR-0006; "Server storage substrate" row below), and a compiler-stable plugin ABI.

## Target Architecture

```
Operators (agentic AI, humans with a browser, REST API, automation scripts)
    │
    ▼
Yuzu Server
    ├── REST API (v1) — versioned, JSON, token or session auth
    ├── HTMX Dashboard — server-rendered, dark theme (light theme is not supported and I will not be discussing it further)
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

## Glossary — three meanings of "agent"

The word **agent** is overloaded; this file relies on these definitions — use the disambiguated form in commits, PRs, and new docs:

- **Agent daemon** — the C++ binary in `agents/core/` on each managed endpoint that executes plugins (what this codebase usually means by "agent").
- **Governance agent** — the `.claude/agents/*.md` review actors run during `/governance`.
- **Agentic worker** — an external LLM-driven client driving Yuzu through MCP, REST, or the dashboard (the agentic-first principle, `docs/agentic-first-principle.md`).

## Context discipline

Context is the scarce resource. Keep this thread lean; spend file-reading budget in subagents.

- **Search before reading.** Grep (it *is* ripgrep) skips everything in `.gitignore` (build dirs, `vcpkg_installed/`, generated `*.pb.*`, `*.beam`, `tests-build-*`). Then Read only the line ranges you need — not whole directories.
- **Read / Glob / `find` do NOT honor `.gitignore`** — keep them out of build, vendored, or generated trees (`*.pb.h/.cc`, `vcpkg_installed/`) unless explicitly required.
- **Delegate broad reads.** Unknown code locations or many-file sweeps → launch an `Explore` (or `general-purpose`) subagent that returns conclusions, not file dumps.
- **Summarise and hand off proactively** — when a thread gets long, record files touched, facts learned, open questions, next command; continue or spawn a fresh agent from that summary.
- **For code changes:** owning module → its tests → smallest coherent patch → targeted suite (`meson test -C build-<os> --suite <agent|server|tar>`) before the broad one.

## Agent Team & Governance

Specialized agents live in `.claude/agents/` (each declares its role, triggers, and reference docs). `workflow-orchestrator` owns the gate sequence; the `/governance` skill is the entry point for running the full pipeline on a commit range.

Pipeline (8 gates, convention-enforced): Change Summary + Resource Ledger → security-guardian + docs-writer deep-dive → domain-triggered review (`cpp-expert` + `cpp-safety` on any C++ change) → happy-path + unhappy-path + consistency-auditor → chaos-injector (skipped if no findings) → compliance-officer + sre + enterprise-readiness → findings addressed (CRITICAL/HIGH block merge) → iterate. Use `/governance <range>`, not hand-running — waves 1–4 shipped 4 CRITICAL command-injection vulns without it.

## Darwin Compatibility

This Claude instance is the designated **macOS/Darwin compatibility guardian**. The `cross-platform` agent loads `docs/darwin-compat.md` on any change that may affect macOS — that doc holds the standing reconciliation workflow and the standing pitfalls table.

## Erlang Gateway Build & Quality

Touching `gateway/` or any `*.erl` file? **Read `docs/erlang-gateway-build.md` first.** It holds the build/verify commands, toolchain activation (`source scripts/ensure-erlang.sh`), the always-run-dialyzer rule, the mandatory-`--dir`/#337 and eunit-isolation/#336 gotchas, and the standing pitfalls table. The `gateway-erlang` agent loads it on any `gateway/`/`.erl` change; use `/gateway-eunit` and `/gateway-dialyzer` for routine runs.

## UAT Environment (Server ↔ Gateway ↔ Agent)

Standing up or debugging the stack? **Read `docs/uat-environment.md` first.** It covers the three mutually-exclusive rigs (`scripts/start-UAT.sh` native; `scripts/start-viz-uat.sh` containerised viz; `scripts/start-demo.sh` release-pinned Cedar & Vale demo — runbook `docs/demo-environment.md`), the port table, and gateway command forwarding (`--gateway-upstream`/`--gateway-mode`/`--gateway-command-addr`, `--trusted-nat-cidr`, the `agent_registry.cpp` `send_to()` flow). All three rigs bind 8080 + 50051 — only one runs at a time. `release-deploy` loads the doc on any compose/UAT-script change.

## Pre-commit testing with /test

The `/test` skill (`.claude/skills/test/SKILL.md`) is the single-command pre-commit/pre-push gate — compiles HEAD, upgrades from the previous release image, runs the standard test surface, persists every gate result + sub-step timing to a SQLite DB at `~/.local/share/yuzu/test-runs.db` (survives `git clean`; override `YUZU_TEST_DB=path`). Modes: `--quick` (~10 min), default (~30–45 min), `--full` (~60–120 min — adds OTA, sanitizers, coverage enforcement, perf measure-only). History: `bash scripts/test/test-db-query.sh --latest|--last N|--diff A B|--trend|--flaky`. Coverage-baseline and perf-calibration details live in the skill.

## Instruction Engine

The content plane: YAML-defined `InstructionDefinition` → `InstructionSet` → `ProductPack`, executed via the `CommandRequest` wire protocol; `yaml_source` is authoritative, denormalized columns are for queries. Architecture: `docs/Instruction-Engine.md`; DSL spec: `docs/yaml-dsl-spec.md`; tutorial: `docs/getting-started.md`.

**Build-time gotcha:** PyYAML is a **hard build dependency** (`meson setup` fails without it). Shipped content is build-time embedded (`embed_content.py` → `bundled_content.cpp`, seeded into `instructions.db` on first boot); the runtime never reads YAML from disk — no `--content-dir` flag. See `docs/Instruction-Engine.md` "Build-time content embedding".

## Enterprise Readiness and SOC 2

The path to enterprise-deployable is scoped in `docs/enterprise-readiness-soc2-first-customer.md` across 7 workstreams (GRC, Identity, AppSec, Reliability, Data, Secure SDLC, Customer Assurance); the Gate 6 agents (compliance-officer, sre, enterprise-readiness) evaluate every change against it.

## Development Roadmap

Roadmap: `docs/roadmap.md`. Capability map: `docs/capability-map.md` — its headline progress figure is overstated, treat with skepticism (memory `project_capability_map_accuracy.md`). Check the roadmap for dependencies before starting an issue.

## Build

Meson is the sole build system. **Every time you add, remove, or rename a source file, update `meson.build` in the affected directory** and verify the build compiles.

### Prerequisites
- Meson 1.11.1, Ninja
- CMake (required by Meson's cmake dependency method — not used as a build system)
- C++23 compiler: GCC 13+, Clang 18+, MSVC 19.38+, or Apple Clang 15+
- vcpkg (set `VCPKG_ROOT`)
- For vcpkg's libpq port (Postgres substrate, ADR-0006; builds postgresql from source): **Linux** needs `bison flex` (apt); **macOS** needs `autoconf automake libtool` (brew); **Windows** none extra (vcpkg auto-acquires winflexbison)

### Quick start (setup script)
```bash
./scripts/setup.sh                              # debug build, default compiler
./scripts/setup.sh --buildtype release --lto    # release + LTO
./scripts/setup.sh --tests                      # enable tests
```
(`--native-file meson/native/*.ini` / `--cross-file meson/cross/*.ini` select compilers / cross targets.)
The script runs `vcpkg install` then `meson setup` automatically.

### Manual configure
```bash
vcpkg install --triplet x64-linux --x-manifest-root=.
meson setup build-linux --buildtype=debug -Dcmake_prefix_path=$VCPKG_ROOT/installed/x64-linux -Dbuild_tests=true
meson compile -C build-linux
```

### Build options
`-Dbuild_agent` / `-Dbuild_server` / `-Dbuild_examples` (default true), `-Dbuild_tests` (default false), and the Meson built-ins `-Db_lto`, `-Db_sanitize=address,undefined` (ASan+UBSan) or `-Db_sanitize=thread` (TSan).

### Per-OS build directory convention

Same source tree is built from multiple hosts (WSL2 + native Windows on one box, plus macOS); per-OS dirs prevent clobbering: `build-linux` / `build-windows` / `build-macos`. Use `scripts/setup.sh` (auto-picks) or pass `-C build-<os>`. If setup.sh finds a dir recorded for another host it refuses to reconfigure unless `--wipe` — prevents opaque ninja "dyndep is not an input"/Windows-path failures when a Windows builddir is reused under WSL2. `setup.sh` never auto-wipes; defaults to `--reconfigure`.

### Windows build

`docs/windows-build.md` is the source of truth — MSYS2 bash sequence, the `setup_msvc_env.sh` + `scripts/ensure-erlang.sh` activation pair, full path inventory, and the two hard rules: **never use `vcvars64.bat`** (extension exit-1 corrupts wrappers) and **never Clang from `C:\Program Files\LLVM\bin`** (must be cl.exe/MSVC). `cross-platform` and `build-ci` agents load this on any Windows-touching change.

**Provisioning a native Windows CI runner** is codified in `deploy/windows/` (provisioning spec, `toolchain-manifest.json`, runner self-test, CCD-pin wrapper); the gateway build resolves its toolchain from `YUZU_ESCRIPT`/`YUZU_REBAR3`, and the 4 runners share one vcpkg binary cache via `RUNNER_TOOL_CACHE`. See `deploy/windows/README.md`.

### Cross-compilation
`./scripts/setup.sh --cross-file meson/cross/aarch64-linux-gnu.ini`

## Test

Every test target carries a `suite:` label (`agent`, `tar`, `server`) so `--suite <name>` filters directly:

```bash
meson test -C build-linux --suite <server|agent|tar> --print-errorlogs   # omit --suite for everything
```

Tests require `-Dbuild_tests=true`. The Catch2 dependency is only installed by vcpkg on `x64 | arm64` platforms. The ARM64 cross-compile CI job intentionally skips tests.

### Direct binary invocation

For Catch2 tag filtering (`[rest][token]`, etc.) or raw output, call the test binary directly via the stable per-component symlinks maintained by `scripts/link-tests.sh`:

```bash
tests-build-server-linux_x64/yuzu_server_tests "[rest][token]"
tests-build-agent-linux_x64/yuzu_agent_tests "[metrics]"
```

`scripts/setup.sh` creates the symlinks; on a plain `meson setup` checkout run `bash scripts/link-tests.sh` once after the first `meson compile`. Triplet suffix derives from the host (`linux_x64`, `linux_arm64`, `macos_arm64`, `windows_x64`). Symlinks point at the real build output, so they stay live across rebuilds. `tests-build-*/` is gitignored.

### Third-party warning suppression

Every `dependency()` is marked `include_type: 'system'` so vcpkg/gRPC/abseil/protobuf/Catch2 warnings are `-isystem`-silenced while our code stays `warning_level=3`. **Do not remove `include_type: 'system'`** on new dependencies — load-bearing for build-log readability.

## Project layout

```
agents/core/      Agent daemon (gRPC client, plugin loader, trigger engine)
agents/plugins/   47 plugins
server/core/      Server daemon (sessions, auth, dashboard, REST API, policy engine)
gateway/          Erlang/OTP gateway (standalone rebar3 project)
sdk/              Public SDK — stable C ABI (plugin.h) + C++23 wrapper
proto/            Protobuf definitions (source of truth for wire protocol)
tests/unit/       Catch2 unit tests
docs/             Architecture docs, conventions, roadmap, capability map
```

`proto/meson.build` invokes `proto/gen_proto.py`, which runs `protoc` and flattens `#include` subdirectory prefixes (headers ship as `"common.pb.h"`). Result: the `yuzu_proto` static library via `yuzu_proto_dep`. `build-ci` owns this codegen flow.

## vcpkg
- Manifest: `vcpkg.json`. Pinned baseline: `4b77da7fed37817f124936239197833469f1b9a8` (matches `vcpkgGitCommitId` in CI).
- `builtin-baseline` is required because of the `version>=` constraint on abseil. Without it vcpkg resolves against HEAD.
- OpenSSL is **required on every platform including Windows** — vcpkg's gRPC port compiles its TLS/JWT/PEM paths against OpenSSL headers regardless of linkage mode, leaving `grpc.lib` with unresolveds only `libssl.lib`+`libcrypto.lib` satisfy. The old `!windows` filter ("gRPC will use schannel") was aspirational, disproven by the #375 option-D canary — openssl is an unconditional top-level dep.
- `catch2` is platform-filtered to `x64 | arm64` (not 32-bit ARM).
- **libpq (ADR-0006/0008): no cmake target carries static libpq's full closure.** `libpgcommon`/`libpgport` + OpenSSL live only in `libpq.pc`'s `Libs.private`, so meson's `libpq_dep` block wires them explicitly (unix: cmake `FindPostgreSQL` + `find_library`; Windows: hand-wired per the #375 pattern below). On Windows libpq is a **DLL** (the static override covers the grpc stack only), shipped via the release zip's vcpkg-DLL sweep (ADR-0008 Correction 2026-06-10). `libpq_dep` is gated on `build_server` (agent stays SQLite). Manifest pins `default-features: false, features: [openssl]`. Pure-C libpq has no MSVC `detect_mismatch` records — a wrong-CRT lib pick links silently, so the buildtype-conditional `_vcpkg_lib_win` selection is load-bearing.
- **Windows grpc/protobuf/abseil is load-bearing — both halves.** The `triplets/x64-windows.cmake` static-linkage override AND meson's Windows-specific hand-wired `protobuf_dep`/`grpcpp_dep` (`cxx.find_library()`) are the **only configuration found** that avoids both LNK2038 (meson cmake-dep bug) and LNK2005 (abseil DLL symbol conflicts). Don't simplify either half without reading `.claude/agents/build-ci.md` "Windows MSVC static-link history and #375" (full timeline + the #376 QUIC escape). Linux/macOS unaffected.

## CI architecture

Three-tier split: Tier 1 PR fast-path (`ci.yml`, one Linux + Windows + macOS + `proto-compat`, <10 min), Tier 2 push to dev/main (full matrix, no sanitizers/coverage, #410), Tier 3 nightly (`nightly.yml`, sanitizers + coverage — failure auto-opens `nightly-broken`; **no merge to main while it is open**). Full reference: `docs/ci-architecture.md`. `workflow_dispatch`/cron fire only once the workflow file is on `main` — new workflows on `dev` are dormant until merged. `build-ci` owns the matrix; `cross-platform` owns Windows/macOS specifics.

## Release workflow gates

The `release:` job (`.github/workflows/release.yml`) runs `scripts/check-compose-versions.sh` as its **first step**. It walks an explicit tracked list of compose files and rejects any `ghcr.io/<owner>/yuzu-{server,gateway,agent}(-chisel)?:X.Y.Z` reference that is a bare numeric tag, or a `${YUZU_VERSION:-...}` default ≠ the tag being released; floating tags are ignored. Explicit file args override the tracked list.

**Before tagging**, bump the `${YUZU_VERSION:-X.Y.Z}` default in every tracked compose file and verify locally: `bash scripts/check-compose-versions.sh 0.12.0`. Otherwise the job fails only after the full build matrix (~30–60 wasted runner-min, nothing published). New compose file ⇒ also add it to the `FILES` array in the script — auto-discovery is deliberately off.

## Changelog

**Never edit `CHANGELOG.md`** — add one fragment file `changelog.d/<PR#>-<slug>.<section>.md` (body = the finished `- ` bullet), assembled at release. A hook + the `Changelog fragments` CI job enforce this; see `changelog.d/README.md`.

## Routed concerns (read the doc, not this file)

| Concern | Doc | Loaded by |
|---|---|---|
| Authentication, RBAC, headers, tokens, self-target principal-destruction guard (#397/#403). Every new list/fan-out read of per-agent data MUST use the admit-then-filter `authorize_list_read` chokepoint (World A, ADR-0017) — never a bare global `require_permission` (inert for confined operators; fails open on a corrupt `rbac.db`). | `docs/auth-architecture.md` | `security-guardian` on auth/RBAC/crypto/header/token change |
| PKI / internal CA — `ca.db` (`CaStore`) holds cert metadata + CRL versions + the root key's opaque `key_ref` ONLY; the CA root **private key is never in the DB** (behind `KeyProvider`; treat `key_ref` as opaque). `sign_agent_csr` is the single shared signer for the direct `Register` AND gateway `ProxyRegister` paths — subject/SAN/EKU are server-chosen, the CSR's ignored. Revoke is serial-scoped — DENY an agent to stop re-issuance. Shipped composes stay plaintext until PR5b, so **do not internet-expose `:50051`** (fleet-RCE risk). Wired PR2–PR6; pending: the PR5b encrypted-by-default distribution flip. Full detail: `docs/pki-architecture.md`. | `docs/pki-architecture.md` | `security-guardian` + `cpp-safety` + `docs-writer` on `x509_ca.{hpp,cpp}` / `key_provider.{hpp,cpp}` / `secure_buffer.hpp` / `aes_gcm.hpp` / `pg/secret_codec.{hpp,cpp}` (ADR-0010 secrets seam — also on any new `KeyProvider`/`KekProvider` subclass) / `ca_store.{hpp,cpp}` / `agent_csr.{hpp,cpp}` / `ca_routes.{hpp,cpp}` / `/api/v1/ca/`; `gateway-erlang` on `gateway/config/sys.config*` / gateway `*_pb.erl` / `yuzu_gw_app.erl` TLS |
| AuthDB invariants — `auth.db` mode, migration, lifetime, seed-vs-live, role-field-ignored, gate audit, cleanup cadence, snapshot-and-release | `.claude/agents/authdb.md` | `authdb` agent on `auth_db.{hpp,cpp}` / `auth_routes.*` / `auth.{hpp,cpp}` change |
| Enterprise A&A roadmap — RBAC, OIDC, SAML, SCIM, MFA, AD/Entra, API tokens, session lifecycle, audit | `.claude/skills/auth-and-authz/SKILL.md` | invoke `/auth-and-authz` for any A&A planning, audit, or implementation work |
| MCP server architecture, tier-before-RBAC ordering, kill switches, audit pattern; Streamable HTTP transport (sessions, GET SSE, progress bridge) is committed direction — ADR-1005 exec-plan Decision 15 (binding security/bounds pre-commitments a–k) / track 2f | `docs/mcp-server.md` | `security-guardian` on `/mcp/v1/`, `mcp_server.{hpp,cpp}`, `mcp_jsonrpc.hpp`, `mcp_policy.hpp`, `mcp_transport.{hpp,cpp}`, `mcp_session.{hpp,cpp}`, `mcp_stream_bridge.{hpp,cpp}` change |
| Executions-history ladder — `command_id → execution_id` map, partial-index planner contract, SSE `ExecutionEventBus`, drawer data-attribute binding, `api.v1.events.subscribe` audit split; MCP `execute_instruction` is a tracked-execution producer (#1088). Invariant: one bus, one taxonomy (`/api/v1/events`) — never per-route event formats (consumers today: dashboard SSE + REST SSE; the MCP stream bridge joins as a third via exec-plan track 2f). | `docs/executions-history-ladder.md` | any change to `agent_service_impl.cpp` `cmd_execution_ids_`, `response_store` execution queries, `execution_event_bus.*`, `execution_tracker.*`, `rest_a4_envelope.{hpp,cpp}`, the `/api/v1/events` handler in `rest_api_v1.cpp`, the `execute_instruction` handler in `mcp_server.cpp`, `mcp_stream_bridge.{hpp,cpp}` (bus consumer — exec-plan track 2f), or executions-drawer markup |
| Compliance evaluation pipeline — `PolicyEvaluator` background thread (10s tick, 15s grace, ≥60s floor, 3600s default) drives check→verdict→status so authored policies actually evaluate; `policy_eval_thread_` joins before stores in `~ServerImpl`/`stop()`. Mints `polchk-*` ids `notify_exec_tracker` skips (no tracker row, no SSE — compliance is NOT in the executions drawer). Remediation is operator-gated only. | `docs/user-manual/policy-engine.md` | `cpp-safety` + `docs-writer` on `policy_evaluator.{hpp,cpp}`, the `PolicyStore` status writer, or the `polchk-` guard in `agent_service_impl.cpp` |
| `/auto` Pre-flight readiness — operator go/no-go checks across a device cohort before a fleet change. Born-on-PG `PreflightRunStore` (construction fail-CLOSED per ADR-0012, runtime durability-on-top, 14-day prune, owner-scoped reads); the background `PreflightRunner` re-dispatches the READ-ONLY checks to not-yet-answered FROZEN targets. LOAD-BEARING: that is safe ONLY because every check is read-only/idempotent — any future MUTATING check must re-resolve `devices_fn(creator)∩group` per dispatch, never reuse the frozen cohort. Mints `preflight-*` ids `notify_exec_tracker` skips. Concurrency contract (two writers, `complete_run` CAS, persist-gated completion): the ladder row in `docs/postgres-migration-ladder.md`. | `docs/user-manual/preflight.md` + `docs/executions-history-ladder.md` | `security-guardian` + `cpp-safety` + `docs-writer` on `preflight_run_store.*` / `preflight_runner.*` / `preflight_routes.*` / `preflight_eval.*` / `preflight_parse.hpp` / the `preflight-` guard in `agent_service_impl.cpp` |
| `/auto` Deploy (the ACT stage after pre-flight ASSESS) — stage + execute an installer on a pre-flight run's go-cohort via the `content_dist` plugin (NO new agent code). Born-on-PG `DeploymentRunStore`: the device step is STATEFUL (mutating), so the store exposes GUARDED one-way transitions and `claim_for_exec` is the execute-once CAS (three layers, see the ladder row). RE-AUTHORIZATION every tick (`devices_fn(viewer)∩cohort`) keeps the mutating step safe — a lost-scope device is skipped, never run. NO background runner in slice 1 (the page/MCP poll advances it). ANY future store mutation MUST stay a guarded transition (never an unconditional grid overwrite) or execute-once breaks. Mints `deployment-*` ids `notify_exec_tracker` skips. | `docs/user-manual/preflight.md` + `docs/executions-history-ladder.md` + `docs/postgres-migration-ladder.md` | `security-guardian` + `cpp-safety` + `docs-writer` on `deployment_run_store.*` / `deployment_engine.*` / `deployment_routes.*` / `deployment_parse.hpp` / `deployment_ui.cpp` / the `deployment-` guard in `agent_service_impl.cpp` |
| C++23 conventions, naming, headers, plugin ABI boundary | `docs/cpp-conventions.md` | `cpp-expert` on any C++ source change |
| C++ resource ownership and lifetime — fd/HANDLE/SOCKET/`FILE*`/SQLite/OpenSSL/BCrypt/C-string/thread/callback/temp-path ownership, RAII/scope guards, `string_view`/`span` validity, casts, syscall/process boundaries, sanitizer coverage | `docs/cpp-conventions.md` | `cpp-safety` on any C++ source change; `security-guardian` also enforces the ownership proof during Gate 2 |
| macOS workflow + Darwin pitfalls table | `docs/darwin-compat.md` | `cross-platform` on any macOS-affecting change |
| Prometheus metrics, label set, audit envelope, event format | `docs/observability-conventions.md` | `sre` and `architect` on any metrics/audit/event change |
| Response data types, audit envelope, inventory data for analytics | `docs/data-architecture.md` | `architect` and `sre` when designing schemas |
| User manual / YAML defs / REST API / Substrate primitive registration | docs-writer agent (`.claude/agents/docs-writer.md`) | docs-writer on every change as part of governance gate 2 |
| Guardian / Guaranteed State — real-time agent-side policy enforcement (guard categories, YAML DSL, `__guard__` wire protocol, server store, approval workflow, quarantine; standing invariants §24). DEX families: ruleless signal observations (`rule_id="__observation__"`, `event_type` = obs_type — the ruleless-ness IS the discriminator), state-poll/perf-breach, fleet blast-radius + per-signal alert routing, device + app perf-over-time, `/auto` VERIFY before/after. CRITICAL: fleet AND group app-perf reads floor sub-`kDexCohortFloor` `(version,day)` points to a count only (no singling-out); `/auto` VERIFY is EVIDENTIAL (no verdict/threshold/gate) and deliberately has NO floor — the audited `dex.app_perf.compare` read is the accountability that replaces suppression. BRD coverage map `docs/dex-brd-coverage.md` is local-only, deliberately untracked (commercially sensitive) — ask the operator if missing. | `docs/yuzu-guardian-design-v1.1.md` + delivery plan `docs/yuzu-guardian-windows-implementation-plan.md` + `docs/dex-signal-catalog.md` (+ the local-only `docs/dex-brd-coverage.md`) | `security-guardian` + `docs-writer` on any `guaranteed_state*`, `guardian_*`, `guard_*`, `dex_*`, `app_perf_*`, `sync_source_app_perf.*`, `verify_routes.*`, `verify_ui.*`, `/api/v1/dex/perf`, `__guard__`, or `__observation__` change |
| TAR dashboard — frames (retention-paused sources, scope-walking SQL, process tree + device DNS/ARP panels, Capture sources), URL structure, permissions. Adding a capture source? Use the CORE pattern (`docs/tar-implementer.md` §8) — NOT the self-contained perf/procperf/netqual tier pattern; ARP/DNS + the Capture-sources frame are ADR-0015 (opt-in, Windows-first; DNS is usage-class PII). Untrusted `tar.sql` runs only through read-only `TarDatabase::execute_user_query` (authorizer allowlist), never trusted `execute_query` (#760/#631). Per-source enable/disable fails CLOSED through the `canonical_source_enabled` tri-state (#560). `TarDatabase::open` integrity-checks and quarantines a corrupt `tar.db` aside or fails closed — never re-open-and-trust (#559). New streaming sources implement `ProcStreamCollector`, never a parallel path (`docs/tar-module-loads.md`). | `docs/tar-dashboard.md` + `docs/tar-implementer.md` + `docs/darwin-compat.md` | `architect` on `/tar` or `/fragments/tar/...` change; `plugin-developer` on TAR action surface; `cross-platform` + `cpp-safety` on `tar_proc_{stream,etw,es}.*`; `cpp-safety` + `docs-writer` on `tar_db.cpp` open/quarantine or `canonical_source_enabled`; `docs-writer` on dashboard nav |
| Scope walking — composable scope from previous query results (Yuzu's product differentiator). Result-set primitive, `result_sets.db`, `from_result_set:<id>` Scope kind, REST/DSL surface, lineage, audit chain | `docs/scope-walking-design.md` | `architect` + `dsl-engineer` on scope-engine/DSL/result-set change; `consistency-auditor` on audit chain; `security-guardian` on cross-operator authz |
| System architecture — cross-cutting design reference (Operator/Server/Agent/Gateway, REST/MCP/dashboard surfaces, plugin ABI boundary) | `docs/architecture.md` | `architect` on cross-cutting design changes |
| Tag/scope DSL operator reference — `tag:X`, `props.X`, `ostype`, `hostname`, `arch`, `agent_version` resolution; recipes for asset tagging | `docs/asset-tagging-guide.md` | `dsl-engineer` on scope/tag-DSL changes; `architect` when a new scope kind is added |
| Agentic-first invariants A1–A5 (dashboard parity, discovery, observability, error envelope, agentic context contract) — applies to every new MCP tool, REST route, dashboard fragment, or error site. A5 (exec-plan Decision 16, track 2g): every new/materially-changed MCP tool ships standard annotations (`destructiveHint` truthful vs tier), decision-grade description, bounded input schema, typed output schema, honest `retry_after_ms` — machine metadata, never prose-only. Shape contracts for the SSE + A4 error envelopes live in `server/core/src/rest_a4_envelope.hpp`, reusable by future MCP / discovery surfaces. | `docs/agentic-first-principle.md` | `consistency-auditor` on every PR; `security-guardian` + `architect` on relevant surfaces; on `rest_a4_envelope.{hpp,cpp}` or the `/api/v1/events` handler |
| Enterprise-platform parity matrix — competitor capability comparison and gap analysis (complements `docs/capability-map.md`) | `docs/enterprise-parity-plan.md` | `architect` on capability-map / roadmap changes; `enterprise-readiness` agent during Gate 6 |
| CI cache patterns — split `actions/cache/restore` + paired `actions/cache/save` for GHA-hosted; local `runner.tool_cache` for self-hosted; **never `save-always: true`** (zizmor guard enforces) | `.claude/skills/ci-cache/SKILL.md` | `build-ci` on `actions/cache@`, vcpkg cache scope, ccache scope, or self-hosted-runner cache wiring |
| Agent privilege model — dedicated `_yuzu` / `yuzu` / `NT SERVICE\YuzuAgent` account, narrow sudo NOPASSWD + LSA privileges, per-plugin privilege matrix, production virtual-service-account vs dev local-user paths, install scripts `scripts/install-agent-user.{sh,ps1}`; the doc has the new-privileged-plugin procedure. | `docs/agent-privilege-model.md` | `security-guardian` on any plugin shell-out / sudoers / setcap change; `cross-platform` on any change that gates a plugin behind a privileged command; `plugin-developer` when adding a new privileged plugin (the doc has the procedure) |
| Fleet visualization (3D) — REST surface, page-shell, renderer, and process-layer invariants for the 11-PR `feat/viz-engine` ladder | `docs/fleet-viz-invariants.md` | `security-guardian` + `docs-writer` on `viz_routes.{hpp,cpp}` / `fleet_topology_store.{hpp,cpp}` / `viz_page_ui.cpp` / `static/yuzu-viz.js` / `--viz-disable` / `Config::viz_disable` |
| Network quality dashboard (`/network`) — MEASUREMENT-FIRST device/local-link health lens (interval retransmit rate + RTT + throughput). `yuzu.net_retrans_pct` is an INTERVAL delta, NOT the disproven lifetime ratio; `yuzu.net_degraded` is RETIRED (gauge absent-not-zero). Windows retransmit is whole-stack + unvalidated (#1465), so it is WITHHELD from the `yuzu_fleet_net_retrans_pct` gauge (Linux-only today; still on the page/REST, caveated); the other net gauges carry an `os` label — never alert on a cross-OS aggregate. Agent heartbeat keys are pinned to `kNetTag*` by static_assert. | `docs/user-manual/network.md` | `security-guardian` + `docs-writer` on `network_routes.{hpp,cpp}` / `network_perf_model.{hpp,cpp}` / `network_perf_rules.hpp` / `network_ui.cpp` / `net_quality_sampler.{hpp,cpp}` / `tar_netqual.hpp` / the `yuzu.net_*` heartbeat block / `yuzu_fleet_net_*` |
| Device pages (`/devices` fleet list + `/device?id=`) — the SHARED device surface: Device info / DEX / Guardian lens tabs + "Get live info" dispatch-and-poll live snapshot; every kind has its own `device.live.<kind>` audit verb so usage-class reads stay separately countable (works-council). CRITICAL: (1) ALL behavioural-PII access-audit funnels through `server/core/src/rest_audit.hpp` (`emit_behavioral_audit`, #1647) — posture per surface: REST fail-closed 503 + `Sec-Audit-Failed`, dashboard HTML and MCP set-and-proceed; NEVER reintroduce an inline bool-capture on a new PII route (last un-migrated: the `device.live.*` REST route; #1703). (2) Result polls are scoped at the store seam — `ResponsesFn` threads `agent_id` into `ResponseQuery{.agent_id}` (#1634); the post-filter is defense-in-depth only. | `docs/user-manual/device-management.md` | `security-guardian` + `docs-writer` on `device_routes.{hpp,cpp}` / `device_ui.cpp` / `DeviceRoutes` / the `device.live.*` audit verbs / `processes/{list_hashed,list_tree}` / `network_config/arp` / the live-snapshot JS in `guardian_page_ui.cpp` / `rest_audit.hpp` |
| OS capability matrix — per-capability × per-OS snapshot of what the agent collects/enforces, each row citing its in-code source of truth. Curated and **will drift**; durable fix = generate it from the machine-readable per-OS metadata. When changing per-OS support, record the other platforms' status there too. | `docs/os-capability-matrix.md` | `docs-writer` + `cross-platform` on any per-OS support change |
| Agent daily-sync framework + installed-software inventory (ADR-0016) — agent pushes per-source endpoint state daily over `ReportInventory` (hash-skip, jittered `need_full`, weekly full-floor); sources: #1 `installed_software` (`list_inventory` action — **blob contract v2**, a 12-field honest-empty-per-ecosystem NEVRA+signature record, pure parse helpers in `installed_apps_inventory.hpp`; the operator-facing `list` action stays byte-unchanged), #2 `app_perf`, #3 `device_ci` (serial/UUID/MAC = GDPR personal data → behavioural-PII audit tier). CRITICAL: (1) `inventory_state.last_seen`/`first_seen` = SERVER receipt time, never agent `collected_at` (#1685 — a skewed/hostile agent must not hide a dark endpoint); (2) a new sync source is a new `plugin_data` map KEY, NOT a proto field — no `agent_pb`/`gateway_pb` regen; (3) Windows registry STRING reads use `Reg*W` via `agents/shared/win_str.hpp`, never `Reg*A` (#1662/#1682 — semantics + carve-outs in `docs/cpp-conventions.md`); (4) blob contract v2's 12-field order is hashed byte-identically on agent (`sync_source_installed_software.cpp`) and server (`software_inventory_store.cpp`) — a field-order change on one side without the other breaks hash agreement permanently. | `docs/adr/0016-agent-daily-sync-framework.md` + `docs/user-manual/inventory.md` | `security-guardian` + `docs-writer` + `architect` on `sync_scheduler.*` / `sync_source_*` / `inventory_*` / `device_ci_ingestion.*` / `software_inventory_store.*` / `device_inventory_store.*` / `software_catalog_rollup.*` / the `ReportInventory`+`ProxyInventory` handlers / the `Inventory` securable |
| SQLite `sqlite3_changes()` after `step()` on a shared FULLMUTEX connection is a data race + correctness bug (it reads `db->nChange` without the per-connection mutex; FULLMUTEX serialises calls, not the step→changes pair). Use `RETURNING` on the statement itself, or wrap the pair under `sqlite3_db_mutex`. #1033 tracks 24 legacy sites; every new/modified store must use a correct idiom. | issue #1033 | `cpp-expert` and `architect` on any new `sqlite3_changes()` call site on a shared store connection |
| **Server storage substrate — PostgreSQL** (2026-06-09); the agent stays SQLite (`agent.db` + the federated edge warehouse). The server fails closed at boot — NO SQLite fallback — when `--postgres-dsn`/`YUZU_POSTGRES_DSN` is unset/unreachable (ADR-0006/0007). New server stores default to Postgres (no new server SQLite store without an exception ADR); ALL existing server stores migrate — none stays SQLite (ADR-0006 Update 2026-06-22). Secrets are NEVER a plain Postgres column — verify-only hash or `SecretCodec` envelope blob (mechanism SHIPPED, ADR-0010); `security-guardian` review on every secret-column migration. Author contract (failure posture, lease discipline, cross-store query-owner seam): ADR-0012; recipe + substrate quick facts: `docs/postgres-store-playbook.md`; ordered queue: `docs/postgres-migration-ladder.md`. | ADR-0006/0007/0008 (incl. Correction)/0010/0012 + `docs/postgres-store-playbook.md` + `docs/postgres-migration-ladder.md` | `architect` + `sre` on any server store/schema change; `build-ci` on CI Postgres service; `release-deploy` on deploy/compose; `security-guardian` on any secret-at-rest |
| **Headless platform & use-case engines (ADR-1005)** — the server is headless and use-case-agnostic: every behavior of every capability must be reachable by an authenticated external principal via versioned REST **and** MCP (or a recorded exception in ADR-1005's exception ledger), discoverable (A2/A3), carrying the A4 error envelope, with no in-process-only behavior and RBAC + audit enforced at the API — no UI-only capabilities (a dashboard fragment is not an API twin). On-behalf-of assertions are rejected on every ingress surface (REST, MCP, agent gRPC; sole recorded exception: the four health-probe paths ignore them — a header-stamping proxy must not crash-loop the server); engine principals are a distinct principal class — never impersonation. Use-case interpretation (e.g. vulnerability management) lives in separately-deployed use-case engines (UCE), not the server; the first module re-homes the server-side NVD sync/matching via a strangler migration. Phase-by-phase program status, decision log, and the vuln-module milestones (M1–M4; M3 = the parity **+ confinement** gate that authorizes the irreversible server-side deletion) live in the execution plan — read it for what is currently in flight before adding anything engine- or API-surface-shaped. | `docs/adr/1005-headless-platform-use-case-engines.md` (stable policy) + `docs/adr-1005-execution-plan.md` (current phase status) — both land with PRs #1918/#1926 | `consistency-auditor` on every capability-adding PR (standing question — governance Gate 4 preamble item 8); `architect` + `security-guardian` on any new REST route / MCP tool / dashboard fragment / ingress surface, and on any change to `on_behalf_guard.hpp` / `grpc_on_behalf_interceptor.hpp` / `principal_class.hpp` / the pre-routing chokepoint in `server.cpp` |

## Guardian engine — stores

Working on Guardian / Guaranteed State? **Read `docs/yuzu-guardian-design-v1.1.md` first** — §9.1 = the `guaranteed-state.db` / `GuaranteedStateStore` schema; §24 = the standing invariants (`Push`-seed scope, `__guard__` defence-in-depth, gateway-safe wire payloads, the enforce-gate chokepoint). Second store: `BaselineStore` (`server/core/src/baseline_store.{hpp,cpp}`) — a **Baseline** is the only deployable unit; push fan-out + heartbeat reconcile gate on `deployed_member_rule_ids()`, sourced from each deploy's **`deployed_snapshot`, NOT the live member set** — edits reach agents only after a `Push`-gated re-deploy (keeps "what is enforced" behind `Push`, not `Write`). `dangerous_enforce_in_spec` (`guardian_rule_spec.cpp`) is the **single chokepoint** gating dangerous enforce-promotion — any new dangerous-enforce path must **EXTEND it, never add a parallel gate**. Published schema enums ↔ agent per-type support arrays are bound by the H2/G9 cross-check tests: add/remove a type in **both or neither**. Operator doc: `docs/user-manual/guaranteed-state.md`; model: `docs/guardian-baseline-model.md`; PR ladder: `docs/yuzu-guardian-windows-implementation-plan.md`.

## Test conventions — shared helpers

Use `yuzu::test::unique_temp_path(prefix)` / `yuzu::test::TempDbFile` from `tests/unit/test_helpers.hpp` for any test temp file or SQLite DB. **Never** salt uniqueness with `std::hash<std::thread::id>` or `std::chrono::steady_clock` — silent collisions under Defender-induced I/O serialisation (flake #473; rationale: header comment + #482).

**Standing invariant:** both self-hosted CI pools run multiple runner agents as ONE shared OS identity on ONE box — Windows "Wee Tam" (4 agents, all LOCAL SYSTEM, `deploy/windows/README.md`) and Linux "Big Tam" (4 agents, all the `runner` user sharing `$HOME`, `docs/ci-architecture.md`). A fixed registry key/port/named-object/path is a cross-JOB shared resource, not just cross-test — two concurrent CI jobs on the same box can collide (#1871's `RegistryGuard` family; the gateway eunit `health_port` fix was the same bug on Linux). Salt every such identifier per-test/per-process like `unique_temp_path()` — see `test_guard_registry.cpp`'s `TempRegKey`/`TempEnforceKey`.

For server tests that need a live `ExecutionTracker` in `AgentServiceImpl`, use the `TrackerScope` RAII helper in `tests/unit/server/test_agent_service_impl.cpp` — `:memory:` SQLite, `set_execution_tracker`, nulls the borrowed pointer before the tracker destructs (the production shutdown contract, `agent_service_impl.hpp:113`). Pattern: `GatewayResponseHarness h; TrackerScope ts{h.svc}; auto exec_id = ts.make_exec();`. Promote to `test_helpers.hpp` once a second file needs it (H-9 follow-up from PR #1068).

For server tests that need live **PostgreSQL**, use `PostgresTestDb` + `YUZU_REQUIRE_PG_DB(var)` from `test_helpers.hpp` (behind `YUZU_TEST_ENABLE_PG`, server suite only). Connects to `YUZU_TEST_POSTGRES_DSN`, creates an ephemeral `yuzu_test_<salt>_<n>` database, drops it `WITH (FORCE)`. Skip-vs-fail contract: env **unset** → skip cleanly (local dev); **set but broken** → FAIL (`scripts/ci/ensure-postgres.sh` guarantees a reachable instance on every CI server-test leg). Local: `docker run -d -e POSTGRES_USER=yuzu -e POSTGRES_PASSWORD=yuzu -e POSTGRES_DB=yuzu -p 5433:5432 postgres:18` then `export YUZU_TEST_POSTGRES_DSN=postgresql://yuzu:yuzu@localhost:5433/yuzu`.

## Agent skills

The Matt Pocock engineering skills (`to-issues`, `triage`, `to-prd`, `improve-codebase-architecture`, `diagnose`, `tdd`, `zoom-out`, `grill-with-docs`) are installed **user-global**, not committed — they follow the operator, not collaborators. Re-run `/setup-matt-pocock-skills` to change.

### Plugin scope — `frontend-design` is marketing-only

The `frontend-design` plugin is scoped to **marketing / sales / demo surfaces only** — its deliberately-varied light/dark aesthetic fits a standalone pitch surface, not the consistency-prizing **dark-theme-only** product. Use it on the Cedar & Vale sales deck (`deploy/docker/cedar-vale/app/`) and future standalone marketing pages. **Never on product UI** — `server/core/src/*_ui.cpp`, `server/core/static/*`, explicitly including the in-product fleet visualization (`viz_page_ui.cpp`, `viz_host_page_ui.cpp`, `yuzu-viz*.js` — product despite the name). Product UI stays HTMX-first, server-rendered, dark-theme-only.

**Product UI — no htmx `hx-on`.** Dashboard CSP is `script-src 'self' 'unsafe-inline'` (no `unsafe-eval`); htmx compiles `hx-on:*` with `new Function()`, which CSP **blocks at runtime — the handler silently does nothing**. Use a plain inline `onclick`/`oninput` calling a JS helper, or an `htmx:afterSettle` body listener. Core hx attrs (`hx-get`/`hx-post`/`hx-target`/`hx-swap`/`hx-trigger`/`hx-swap-oob`, `HX-Trigger` header) don't eval — fine. Verify button-driven JS by clicking in a headless browser and checking for a CSP `pageerror`, not just that the page renders. See memory `project-dashboard-csp-no-hx-on.md`.

### Issue tracker, triage labels, domain docs

GitHub issues at `github.com/Tr3kkR/Yuzu` via the `gh` CLI (`docs/agents/issue-tracker.md`). Triage labels: the canonical five (`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`) plus a broader categorization set (`docs/agents/triage-labels.md`). Domain docs: `CONTEXT.md` at the repo root, ADRs under `docs/adr/` (`docs/agents/domain.md`).

## CLAUDE.md updates

Architectural decisions, new stores, churning subsystems, and cross-cutting concerns belong here; stable reference material an agent already loads belongs in `docs/` with a pointer here (heuristic: memory `feedback_claude_md_scope.md`; precedent: the Erlang gateway section → `docs/erlang-gateway-build.md`). Keep this file under 40k characters — routed-concern rows hold only the catastrophic-if-violated invariants + doc pointers; the detail goes in the routed doc.
