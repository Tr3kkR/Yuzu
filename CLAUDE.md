# Yuzu — Claude Code Guide

## What is Yuzu?

Yuzu is an agentic enterprise endpoint management platform — a single control plane where agentic colleagues can query, command, scan, patch, and enforce policy compliance on Windows, Linux, and macOS fleets in real time. Think of it as an open-source alternative to commercial endpoint management platforms, built from scratch in C++23.

The project's goal is to match the full capability set of mature enterprise platforms (see `docs/capability-map.md`) while using modern architecture: gRPC/Protobuf transport, Prometheus-native metrics, SQLite for embedded storage, and a plugin ABI that is stable across compiler versions.

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

The word **agent** is overloaded; the rest of this file relies on these definitions:

- **Agent daemon** — the C++ binary in `agents/core/` that runs on each managed endpoint and executes plugins. The thing the rest of this codebase usually means by "agent".
- **Governance agent** — the `.claude/agents/*.md` review actors run during the `/governance` pipeline. The thing the "Agent Team & Governance" section below describes.
- **Agentic worker** — an external LLM-driven client (Claude, GPT, in-house) that drives Yuzu through MCP, REST, or the dashboard. The thing the agentic-first principle (`docs/agentic-first-principle.md`) is about.

When in doubt in commit messages, PR descriptions, or new docs, use the disambiguated form.

## Agent Team & Governance

Specialized agents live in `.claude/agents/` (each file declares its own role, triggers, and reference docs). The `workflow-orchestrator` agent owns the gate sequence; the `/governance` skill (`.claude/skills/governance/SKILL.md`) is the entry point for running the full pipeline on a commit range.

Pipeline (8 gates, convention-enforced — no git hook): Change Summary + Resource Ledger (C++ resource changes) → security-guardian + docs-writer deep-dive → domain-triggered review (`cpp-expert` + `cpp-safety` on any C++ change; `cpp-safety` on raw resource/process/cast) → happy-path + unhappy-path + consistency-auditor (parallel) → chaos-injector (skipped if no findings) → compliance-officer + sre + enterprise-readiness (parallel) → findings addressed (CRITICAL/HIGH block merge) → iterate. Use `/governance <range>`, not hand-running — waves 1–4 shipped 4 CRITICAL command-injection vulns without it.

## Darwin Compatibility

This Claude instance is the designated **macOS/Darwin compatibility guardian**. The `cross-platform` agent loads `docs/darwin-compat.md` on any change that may affect macOS — that doc holds the standing reconciliation workflow (fetch → pull → diff → reconfigure → compile → `bash scripts/run-tests.sh all` → commit) and the standing pitfalls table (`/var` symlink, SQLite mutex, `rebar3 ct --dir`, `curl -f`, `prometheus_httpd`).

## Erlang Gateway Build & Quality

Touching `gateway/` or any `*.erl` file? **Read `docs/erlang-gateway-build.md` first.** It holds the build/verify commands, toolchain activation (`source scripts/ensure-erlang.sh`), the always-run-dialyzer rule, the mandatory-`--dir`/#337 and eunit-isolation/#336 gotchas, and the standing pitfalls table (`ctx` dep, `-spec` contracts, circuit-breaker dead code, benign `gpb` warning, stray `.beam`, shutdown flush). The `gateway-erlang` agent loads it automatically on any `gateway/`/`.erl` change; use the `/gateway-eunit` and `/gateway-dialyzer` skills for routine runs.

## UAT Environment (Server ↔ Gateway ↔ Agent)

Standing up or debugging the stack? **Read `docs/uat-environment.md` first.** It covers the three mutually-exclusive rigs (`scripts/start-UAT.sh` native; `scripts/start-viz-uat.sh` containerised viz; `scripts/start-demo.sh` release-pinned Cedar & Vale sales demo — full runbook in `docs/demo-environment.md`), the port-assignment table, and gateway command forwarding (the `--gateway-upstream` / `--gateway-mode` / `--gateway-command-addr` flags, `--trusted-nat-cidr`, and the `agent_registry.cpp` `send_to()` dispatch flow). All three rigs bind host ports 8080 + 50051, so only one runs at a time. The `release-deploy` agent loads the doc on any compose / UAT-script change.

## Pre-commit testing with /test

The `/test` skill (`.claude/skills/test/SKILL.md`) is the single-command pre-commit/pre-push gate — compiles HEAD, upgrades from the previous release image, runs the standard test surface, persists every gate result and sub-step timing to a SQLite test-runs DB at `~/.local/share/yuzu/test-runs.db` (XDG dir, survives `git clean`; override with `YUZU_TEST_DB=path`). Three modes: `--quick` (~10 min sanity), default (~30–45 min), `--full` (~60–120 min — adds OTA, dispatched sanitizers, coverage enforcement, perf measure-and-report). Query history via `bash scripts/test/test-db-query.sh --latest|--last N|--diff A B|--trend ...|--flaky`. Coverage baseline (`tests/coverage-baseline.json`) and perf calibration (`docs/perf-baseline-calibration-2026-05-03.md`) details live in the skill — perf is measure-only as of 2026-05-03 (no σ band, ceiling-bounded distributions).

## Instruction Engine

The content plane: YAML-defined `InstructionDefinition` → `InstructionSet` → `ProductPack`, executed via the `CommandRequest` wire protocol; `yaml_source` is authoritative, denormalized columns are for queries. Architecture: `docs/Instruction-Engine.md`; DSL spec: `docs/yaml-dsl-spec.md`; tutorial: `docs/getting-started.md`.

**Build-time gotcha:** PyYAML is a **hard build dependency** — `meson setup` fails the configure step without it. Shipped content is build-time embedded (`embed_content.py` → `bundled_content.cpp`, seeded into `instructions.db` on first boot); the runtime never reads YAML from disk — there is no `--content-dir` flag. Details + rationale: `docs/Instruction-Engine.md` "Build-time content embedding".

The **executions-history ladder** (PR 2/3 `execution_id` correlation + SSE) carries a stack of invariants every successor PR must check — see `docs/executions-history-ladder.md` (also in Routed concerns below).

## Enterprise Readiness and SOC 2

The path from feature-complete to enterprise-deployable is scoped in `docs/enterprise-readiness-soc2-first-customer.md` across 7 workstreams (A GRC, B Identity, C AppSec, D Reliability, E Data, F Secure SDLC, G Customer Assurance). Every code change is evaluated against this plan by the compliance-officer, sre, and enterprise-readiness agents during Gate 6 of the governance pipeline.

## Development Roadmap

Roadmap: `docs/roadmap.md`. Capability map: `docs/capability-map.md`. Headline progress figure in the capability map is overstated — treat with skepticism (see memory `project_capability_map_accuracy.md`). When working on an issue, check the roadmap for dependencies and the capability map for target context.

## Build

Meson is the sole build system. **Every time you add, remove, or rename a source file, update `meson.build` in the affected directory** and verify the build compiles.

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

# 2. Configure (use the per-OS canonical name — see "Per-OS build directory convention" below)
meson setup build-linux \
  --buildtype=debug \
  -Dcmake_prefix_path=$VCPKG_ROOT/installed/x64-linux \
  -Dbuild_tests=true

# 3. Build
meson compile -C build-linux
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

### Per-OS build directory convention

Same source tree is built from multiple hosts (WSL2 + native Windows on the same box, plus a separate macOS); per-OS dirs prevent clobbering:

| Host    | Build dir       |
|---------|-----------------|
| Linux   | `build-linux`   |
| Windows | `build-windows` |
| macOS   | `build-macos`   |

Use `scripts/setup.sh` (auto-picks the dir) or pass `-C build-<os>` to `meson compile`/`meson test`. If setup.sh finds a dir whose recorded source path looks like another host's, it refuses to reconfigure unless `--wipe` — prevents opaque ninja "dyndep is not an input"/Windows-path failures when a Windows builddir is reused under WSL2. `setup.sh` no longer auto-wipes; defaults to `--reconfigure`.

### Windows build

`docs/windows-build.md` is the source of truth — MSYS2 bash sequence, the `setup_msvc_env.sh` + `scripts/ensure-erlang.sh` activation pair, full path inventory, and the two hard rules: **never use `vcvars64.bat`** (extension exit-1 corrupts wrappers) and **never Clang from `C:\Program Files\LLVM\bin`** (must be cl.exe/MSVC). `cross-platform` and `build-ci` agents load this on any Windows-touching change.

### Cross-compilation
```bash
./scripts/setup.sh --cross-file meson/cross/aarch64-linux-gnu.ini
```
Cross files live in `meson/cross/`. Native files for CI compiler selection live in `meson/native/`.

## Test

Every test target carries a short `suite:` label (`agent`, `tar`, `server`) so `--suite <name>` filters directly — no more guessing `"yuzu:server unit tests"`:

```bash
meson test -C build-linux --suite server --print-errorlogs
meson test -C build-linux --suite agent --print-errorlogs
meson test -C build-linux --suite tar --print-errorlogs
meson test -C build-linux --print-errorlogs              # everything
```

Tests require `-Dbuild_tests=true`. The Catch2 dependency is only installed by vcpkg on `x64 | arm64` platforms. The ARM64 cross-compile CI job intentionally skips tests.

### Direct binary invocation

For Catch2 tag filtering (`[rest][token]`, `[mgmt][cycle]`, etc.) or when you want raw output, call the test binary directly. `scripts/link-tests.sh` maintains symlinks at a stable top-level path per component and triplet so you never have to remember the build-dir layout:

```bash
tests-build-server-linux_x64/yuzu_server_tests "[rest][token]"
tests-build-agent-linux_x64/yuzu_agent_tests "[metrics]"
tests-build-tar-linux_x64/yuzu_tar_tests
```

The symlinks are created automatically at the end of `scripts/setup.sh`. If you build from a fresh checkout with plain `meson setup`, run `bash scripts/link-tests.sh` once after the first successful `meson compile` to populate them. Triplet suffix is derived from the host (`linux_x64`, `linux_arm64`, `macos_arm64`, `windows_x64`). Binaries stay live because the symlinks point at the real build output — no need to re-run the script after every rebuild.

`tests-build-*/` is gitignored.

### Third-party warning suppression

Every `dependency()` in `meson.build` and subdirectory files is marked `include_type: 'system'` so vcpkg / gRPC / abseil / protobuf / Catch2 deprecation warnings are treated as `-isystem` and silenced. Our own code is still under `warning_level=3`. **Do not remove `include_type: 'system'`** when adding new dependencies — it's load-bearing for build-log readability.

## Project layout

```
agents/core/      Agent daemon (gRPC client, plugin loader, trigger engine)
agents/plugins/   44 plugins
server/core/      Server daemon (sessions, auth, dashboard, REST API, policy engine)
gateway/          Erlang/OTP gateway (standalone rebar3 project)
sdk/              Public SDK — stable C ABI (plugin.h) + C++23 wrapper
proto/            Protobuf definitions (source of truth for wire protocol)
tests/unit/       Catch2 unit tests
docs/             Architecture docs, conventions, roadmap, capability map
```

`proto/meson.build` invokes `proto/gen_proto.py` which runs `protoc` and rewrites `#include` paths to flatten subdirectory prefixes — generated headers ship as `"common.pb.h"` rather than `"yuzu/common/v1/common.pb.h"`. Result is the `yuzu_proto` static library, exposed via `yuzu_proto_dep`. The `build-ci` agent owns this codegen flow.

## vcpkg
- Manifest: `vcpkg.json`. Pinned baseline: `4b77da7fed37817f124936239197833469f1b9a8` (matches `vcpkgGitCommitId` in CI).
- `builtin-baseline` is required because of the `version>=` constraint on abseil. Without it vcpkg resolves against HEAD.
- OpenSSL is a **required dependency on every platform including Windows**. vcpkg's gRPC port compiles its TLS / JWT / PEM code paths against OpenSSL headers regardless of linkage mode, so `grpc.lib` has unresolved references to `BIO_*`, `EVP_*`, `PEM_*`, `X509_*`, `OPENSSL_sk_*` that must be satisfied by `libssl.lib` + `libcrypto.lib` at final link time. A previous iteration of `vcpkg.json` marked openssl `"platform": "!windows"` with a comment that gRPC would use schannel — that was aspirational, never actually wired up, and confirmed wrong by the #375 option D canary's LNK2019 errors. The comment and platform filter have been removed; openssl is an unconditional top-level dep.
- `catch2` is platform-filtered to `x64 | arm64` (not 32-bit ARM).
- **Windows grpc/protobuf/abseil is load-bearing — both halves.** The `triplets/x64-windows.cmake` static-linkage override AND `meson.build`'s Windows-specific `cxx.find_library()` hand-wired `protobuf_dep`/`grpcpp_dep` construction are the **only configuration we've found** that simultaneously avoids LNK2038 (meson cmake-dep bug) and LNK2005 (abseil DLL symbol conflicts). Do not simplify either half without reading `.claude/agents/build-ci.md` "Windows MSVC static-link history and #375" — full timeline, every failed approach, and the #376 strategic escape (migrate off gRPC to QUIC) are there. Linux/macOS are unaffected.

## CI architecture

Three-tier split (April 2026): Tier 1 PR fast-path (`ci.yml`, one Linux + one Windows + one macOS + `proto-compat`, <10 min), Tier 2 push to dev/main (full matrix, no sanitizers/coverage per #410), Tier 3 nightly cron (`nightly.yml`, sanitizers + coverage on Linux self-hosted — failure auto-opens `nightly-broken`; **no merge to main while that issue is open**). Full reference (cache contract, runner topology, persistence, canary, corruption recovery): `docs/ci-architecture.md`. `workflow_dispatch` and cron only fire once the workflow file is on `main` — new workflows added on `dev` are dormant until merged. `build-ci` owns the matrix; `cross-platform` owns Windows/macOS specifics.

## Release workflow gates

The `release:` job in `.github/workflows/release.yml` runs `scripts/check-compose-versions.sh` as its **first step**, before any artifact download. The script walks an explicit list of tracked compose files (including `docker-compose.demo.yml`) and rejects any `ghcr.io/<owner>/yuzu-{server,gateway,agent}(-chisel)?:X.Y.Z` reference that is (a) a bare numeric tag rather than `${YUZU_VERSION:-...}`, or (b) a parameterised default that does not equal the tag being released (`${GITHUB_REF_NAME#v}`). The `-chisel` repo suffix is recognised; floating tags (`latest`, `local`, sha-pinned) are ignored. Passing explicit file paths after the version overrides the tracked list (used by `tests/shell/test_check_compose_versions.sh`).

**Before tagging a release**, bump the `${YUZU_VERSION:-X.Y.Z}` default in every tracked compose file to the new version and verify locally:

```bash
bash scripts/check-compose-versions.sh 0.10.0
```

The release job will otherwise fail after all build matrix jobs have run, wasting ~30–60 min of runner time without publishing anything. When adding a new compose file to the repo, also add it to the `FILES` array at the top of `scripts/check-compose-versions.sh` — auto-discovery is deliberately off so opt-in is explicit.

## Routed concerns (read the doc, not this file)

| Concern | Doc | Loaded by |
|---|---|---|
| Authentication, RBAC, headers, tokens, self-target principal-destruction guard (#397/#403) | `docs/auth-architecture.md` | `security-guardian` on auth/RBAC/crypto/header/token change |
| AuthDB invariants — `auth.db` mode, migration, lifetime, seed-vs-live, role-field-ignored, gate audit, cleanup cadence, snapshot-and-release | `.claude/agents/authdb.md` | `authdb` agent on `auth_db.{hpp,cpp}` / `auth_routes.*` / `auth_manager.cpp` change |
| Enterprise A&A roadmap — RBAC, OIDC, SAML, SCIM, MFA, AD/Entra, API tokens, session lifecycle, audit | `.claude/skills/auth-and-authz/SKILL.md` | invoke `/auth-and-authz` for any A&A planning, audit, or implementation work |
| MCP server architecture, tier-before-RBAC ordering, kill switches, audit pattern | `docs/mcp-server.md` | `security-guardian` on `/mcp/v1/`, `mcp_server.{hpp,cpp}`, `mcp_jsonrpc.hpp`, `mcp_policy.hpp` change |
| Executions-history ladder — `command_id → execution_id` map, partial-index planner contract, SSE event bus, drawer data-attribute binding, two-consumer / one-bus / one-taxonomy invariant (sprint W5.1 second consumer `/api/v1/events`), `api.v1.events.subscribe` audit verb split, MCP `execute_instruction` as a tracked-execution producer (#1088) | `docs/executions-history-ladder.md` | any change to `agent_service_impl.cpp` `cmd_execution_ids_`, `response_store` execution queries, `execution_event_bus.*`, `execution_tracker.*`, `rest_a4_envelope.{hpp,cpp}`, the `/api/v1/events` handler in `rest_api_v1.cpp`, the `execute_instruction` handler in `mcp_server.cpp`, or executions-drawer markup |
| Compliance evaluation pipeline — `PolicyEvaluator` background thread (10s cadence, 15s grace, interval ≥60s floor, default 3600s) drives the check→verdict→`PolicyStore::update_agent_status` path so authored policies actually evaluate (was dead code). Wired in `server.cpp` (hoisted shared `command_dispatch_fn`, `policy_eval_thread_`, joined before stores in `~ServerImpl`/`stop()`). Mints `polchk-*` correlation ids that `notify_exec_tracker` **skips** (no tracker row, no SSE — compliance is NOT in the executions drawer). Remediation is manual/operator-gated only. | `docs/user-manual/policy-engine.md` | `cpp-safety` + `docs-writer` on any change to `policy_evaluator.{hpp,cpp}`, the `PolicyStore` status writer, or the `polchk-` guard in `agent_service_impl.cpp` |
| C++23 conventions, naming, headers, plugin ABI boundary | `docs/cpp-conventions.md` | `cpp-expert` on any C++ source change |
| C++ resource ownership and lifetime — fd/HANDLE/SOCKET/`FILE*`/SQLite/OpenSSL/BCrypt/C-string/thread/callback/temp-path ownership, RAII/scope guards, `string_view`/`span` validity, casts, syscall/process boundaries, sanitizer coverage | `docs/cpp-conventions.md` | `cpp-safety` on any C++ source change; `security-guardian` also enforces the ownership proof during Gate 2 |
| macOS workflow + Darwin pitfalls table | `docs/darwin-compat.md` | `cross-platform` on any macOS-affecting change |
| Prometheus metrics, label set, audit envelope, event format | `docs/observability-conventions.md` | `sre` and `architect` on any metrics/audit/event change |
| Response data types, audit envelope, inventory data for analytics | `docs/data-architecture.md` | `architect` and `sre` when designing schemas |
| User manual / YAML defs / REST API / Substrate primitive registration | docs-writer agent (`.claude/agents/docs-writer.md`) | docs-writer on every change as part of governance gate 2 |
| Guardian / Guaranteed State — real-time agent-side policy enforcement, guard categories, YAML DSL, `__guard__` wire protocol, server store, approval workflow, quarantine, **standing invariants §24** | `docs/yuzu-guardian-design-v1.1.md` + delivery plan `docs/yuzu-guardian-windows-implementation-plan.md` | `security-guardian` + `docs-writer` on any `guaranteed_state*`, `guardian_*` (engine, routes, ingest, **push_builder**), `guard_*.{hpp,cpp}`, or `__guard__` change |
| TAR dashboard — three frames (retention-paused sources, scope-walking SQL, process tree viewer), URL structure, permissions. **Untrusted `tar.sql` operator SQL must go through `TarDatabase::execute_user_query` (read-only connection + `sqlite3` authorizer allowlisting registry warehouse tables), never the trusted `execute_query` (#760/#631).** | `docs/tar-dashboard.md` | `architect` on `/tar` or `/fragments/tar/...` change; `plugin-developer` on TAR action surface; `docs-writer` on dashboard nav |
| Scope walking — composable scope from previous query results (Yuzu's product differentiator). Result-set primitive, `result_sets.db`, `from_result_set:<id>` Scope kind, REST/DSL surface, lineage, audit chain | `docs/scope-walking-design.md` | `architect` + `dsl-engineer` on scope-engine/DSL/result-set change; `consistency-auditor` on audit chain; `security-guardian` on cross-operator authz |
| System architecture — cross-cutting design reference (Operator/Server/Agent/Gateway, REST/MCP/dashboard surfaces, plugin ABI boundary) | `docs/architecture.md` | `architect` on cross-cutting design changes |
| Tag/scope DSL operator reference — `tag:X`, `props.X`, `ostype`, `hostname`, `arch`, `agent_version` resolution; recipes for asset tagging | `docs/asset-tagging-guide.md` | `dsl-engineer` on scope/tag-DSL changes; `architect` when a new scope kind is added |
| Agentic-first invariants A1–A4 (dashboard parity, discovery, observability, error envelope) — applies to every new MCP tool, REST route, dashboard fragment, or error site. Shape contracts for the JSON SSE envelope and the A4 error envelope live in `server/core/src/rest_a4_envelope.hpp` and are reusable by future MCP / discovery surfaces. | `docs/agentic-first-principle.md` | `consistency-auditor` on every PR; `security-guardian` + `architect` on relevant surfaces; on any change to `rest_a4_envelope.{hpp,cpp}` or the `/api/v1/events` handler |
| Enterprise-platform parity matrix — competitor capability comparison and gap analysis (complements `docs/capability-map.md`) | `docs/enterprise-parity-plan.md` | `architect` on capability-map / roadmap changes; `enterprise-readiness` agent during Gate 6 |
| CI cache patterns — split `actions/cache/restore` + paired `actions/cache/save` for GHA-hosted; local `runner.tool_cache` for self-hosted; **never `save-always: true`** (zizmor guard enforces) | `.claude/skills/ci-cache/SKILL.md` | `build-ci` on any change touching `actions/cache@`, vcpkg cache scope, ccache scope, or self-hosted-runner cache wiring |
| Agent privilege model — dedicated `_yuzu` / `yuzu` / `NT SERVICE\YuzuAgent` account, narrow `sudo NOPASSWD` entries (Linux/macOS) and LSA privileges (Windows), per-plugin privilege matrix, **production virtual-service-account vs dev local-user paths**, install scripts at `scripts/install-agent-user.{sh,ps1}` | `docs/agent-privilege-model.md` | `security-guardian` on any plugin shell-out / sudoers / setcap change; `cross-platform` on any change that gates a plugin behind a privileged command; `plugin-developer` when adding a new privileged plugin (the doc has the procedure) |
| Fleet visualization (3D) — REST surface, page-shell, renderer, and process-layer invariants for the 11-PR `feat/viz-engine` ladder | `docs/fleet-viz-invariants.md` | `security-guardian` + `docs-writer` on any change to `viz_routes.{hpp,cpp}` / `fleet_topology_store.{hpp,cpp}` / `viz_page_ui.cpp` / `static/yuzu-viz.js` / `--viz-disable` / `Config::viz_disable` |
| SQLite `sqlite3_changes()` after `sqlite3_step()` on a FULLMUTEX connection is a data race + correctness bug — `sqlite3_changes()` reads `db->nChange` without the per-connection mutex, so it races any concurrent `step()` on the same handle. FULLMUTEX serialises individual API calls but not the `step → changes` pair. **Use `RETURNING` on the statement itself** so the result is carried in the step return code; or for cases that genuinely need a count, wrap the pair under `sqlite3_db_mutex`. Issue #1033 tracks 24 live store sites still carrying this anti-pattern; until it is closed, every new or modified store must use one of the two correct idioms. | issue #1033 | `cpp-expert` and `architect` on any new `sqlite3_changes()` call site on a shared store connection |

## Guardian engine — stores

Working on Guardian / Guaranteed State? **Read `docs/yuzu-guardian-design-v1.1.md` first** — §9.1 has the `guaranteed-state.db` / `GuaranteedStateStore` schema and §24 the standing invariants (`Push`-seed scope, `__guard__` defence-in-depth, gateway-safe wire payloads). Key facts: agent-side `guardian_engine.{hpp,cpp}` does two-phase startup (`start_local()` pre-network, `sync_with_server()` post-Register); KV namespace `__guardian__`; reserved plugin name `__guard__` intercepted in `agent.cpp` before the plugin match loop; proto `proto/yuzu/guardian/v1/guaranteed_state.proto` (package `yuzu.guardian.v1`, separate from `yuzu.agent.v1`). PR ladder: `docs/yuzu-guardian-windows-implementation-plan.md`. (Also in Routed concerns below.)

**Second store — Baselines (`guardian-baselines.db` / `BaselineStore`, `server/core/src/baseline_store.{hpp,cpp}`).** A **Baseline** is the only deployable unit (M:N member Guards + an include/exclude management-group assignment + a draft/deployed lifecycle). The push fan-out and heartbeat reconcile gate on `BaselineStore::deployed_member_rule_ids()`, which sources the enforced set from each deployed Baseline's **`deployed_snapshot`** (the members captured at deploy), **not** the live member set — so editing a deployed Baseline's members only reaches agents after a Push-gated re-deploy rewrites the snapshot (this is the load-bearing invariant: it keeps "what is enforced" behind `Push`, not `Write`). New/modified SQLite transactions in the Guardian stores use the `SqliteTxn` + `SqliteStmt` RAII owners in `server/core/src/sqlite_raii.hpp` (ROLLBACK-unless-`commit()` + guaranteed `finalize`, so an exception between `BEGIN` and `COMMIT` can't wedge the shared connection). Operator-facing: `docs/user-manual/guaranteed-state.md`; model: `docs/guardian-baseline-model.md`.

## Test conventions — shared helpers

Use `yuzu::test::unique_temp_path(prefix)` / `yuzu::test::TempDbFile` from `tests/unit/test_helpers.hpp` for any test temp file or SQLite DB. **Never** salt uniqueness with `std::hash<std::thread::id>` or `std::chrono::steady_clock` — silent collisions under Defender-induced I/O serialisation on `yuzu-local-windows` (flake #473). Rationale and residual adoption: header comment + #482.

For server tests that need a live `ExecutionTracker` wired into `AgentServiceImpl`, use the `TrackerScope` RAII helper in `tests/unit/server/test_agent_service_impl.cpp` — it opens a `:memory:` SQLite DB, constructs the tracker, calls `set_execution_tracker`, and nulls the borrowed pointer before the tracker destructs (matches the production shutdown contract at `agent_service_impl.hpp:113`). Pattern: `GatewayResponseHarness h; TrackerScope ts{h.svc}; auto exec_id = ts.make_exec();`. The `:memory:` choice deliberately sidesteps the `unique_temp_path` race for shutdown-ordered tests; promote to `test_helpers.hpp` once a second test file needs the pattern (tracked via the H-9 follow-up issue from PR #1068 governance).

## Agent skills

Per-repo configuration for the Matt Pocock engineering skills (`to-issues`, `triage`, `to-prd`, `qa`, `improve-codebase-architecture`, `diagnose`, `tdd`, `zoom-out`, `grill-with-docs`). Re-run `/setup-matt-pocock-skills` to change.

### Plugin scope — `frontend-design` is marketing-only

The `frontend-design` plugin (`frontend-design@claude-plugins-official`) is scoped to **marketing / sales / demo presentation surfaces only**. Its design ethos — bold, deliberately-varied aesthetics that "vary between light and dark themes" — is right for a standalone pitch surface and wrong for the product, which prizes consistency and is **dark-theme-only**.

- **Use it on:** the Cedar & Vale sales deck at `deploy/docker/cedar-vale/app/` (standalone Node app — `deck.css`, `machine.js`, slide assets) and any future standalone marketing/landing page. These are presentation apps, not the product.
- **Do NOT use it on:** the operator dashboard or any product UI — `server/core/src/*_ui.cpp`, `server/core/static/*`. This explicitly includes the **in-product fleet visualization** (`viz_page_ui.cpp`, `viz_host_page_ui.cpp`, `server/core/static/yuzu-viz*.js`, governed by `docs/fleet-viz-invariants.md`) — despite the name, it is product, not marketing. Product UI stays HTMX-first, server-rendered, dark-theme-only; follow the existing dashboard conventions, never `frontend-design`.

**Product UI — no htmx `hx-on`.** The dashboard CSP is `script-src 'self' 'unsafe-inline'` (no `unsafe-eval`); htmx compiles `hx-on:*` handlers with `new Function()`, which CSP **blocks at runtime — the handler silently does nothing**. Use a plain inline `onclick`/`oninput` (allowed by `unsafe-inline`) calling a JS helper, or a `document.body.addEventListener('htmx:afterSettle', …)` body listener, instead. htmx core attrs (`hx-get`/`hx-post`/`hx-target`/`hx-swap`/`hx-trigger`/`hx-swap-oob`, the `HX-Trigger` response header) are fine — they don't eval. Verify button-driven JS by clicking it in a headless browser and checking for a CSP `pageerror`, not just that the page renders. See memory `project-dashboard-csp-no-hx-on.md`.

### Issue tracker

GitHub issues at `github.com/Tr3kkR/Yuzu` via the `gh` CLI. See `docs/agents/issue-tracker.md`.

### Triage labels

Canonical defaults (`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`); only `wontfix` exists in the repo's label set today. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context layout — `CONTEXT.md` at the repo root, ADRs under `docs/adr/`. See `docs/agents/domain.md`.

## CLAUDE.md updates

Architectural decisions, new stores, new plugin patterns, churning subsystems, and cross-cutting concerns belong here so future Claude sessions read them before touching code. Stable reference material that an agent already loads belongs in `docs/` with a one-line pointer here. See memory `feedback_claude_md_scope.md` for the heuristic — Build / Release stay resident because the work is unstable or local-host-specific; mature areas route to `docs/` with a short "read this first" statement once an agent/skill/hook carries the load (precedent: the Erlang gateway build/quality section moved to `docs/erlang-gateway-build.md`).
