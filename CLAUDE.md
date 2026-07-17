# Yuzu — Claude Code Guide

## What is Yuzu?

Yuzu is an agentic enterprise endpoint management platform — a single control plane where agentic colleagues query, command, scan, patch, and enforce policy compliance on Windows/Linux/macOS fleets in real time; an open-source alternative to commercial endpoint platforms, built in C++23.

Goal: match mature-platform capability (`docs/capability-map.md`) with modern architecture — gRPC/Protobuf transport, Prometheus-native metrics, **PostgreSQL server substrate + SQLite on the agent** (ADR-0006), and a compiler-stable plugin ABI.

## Target Architecture

```
Operators (agentic AI · browser · REST API · automation)
    │  ▼
Yuzu Server — REST API v1 (token/session auth) · HTMX dashboard (server-rendered, **dark-theme-only**) ·
    Instruction Engine · Policy Engine (Guaranteed State) · Response/Scope/RBAC/Audit ·
    Scheduler · Metrics (/metrics) · Management Groups
    │  gRPC / Protobuf / mTLS (bidirectional streaming)  ▼
Yuzu Agent (per endpoint) — Plugin Host (**stable C ABI** .so/.dll) · Trigger Engine ·
    KV Storage (SQLite) · Content Distribution (hash-verified stage+execute) ·
    User Interaction (Windows) · per-plugin Metrics
```
Full component reference: `docs/architecture.md`.

## Glossary — three meanings of "agent"

The word **agent** is overloaded; this file relies on these definitions — use the disambiguated form in commits, PRs, and new docs:

- **Agent daemon** — the C++ binary in `agents/core/` on each managed endpoint that executes plugins (the usual meaning of "agent" here).
- **Governance agent** — the `.claude/agents/*.md` review actors run during `/governance`.
- **Agentic worker** — an external LLM-driven client driving Yuzu via MCP, REST, or the dashboard (agentic-first, `docs/agentic-first-principle.md`).

## Context discipline

Context is the scarce resource. Keep this thread lean; spend file-reading budget in subagents.

- **Search before reading.** Grep (it *is* ripgrep) skips `.gitignore` (build dirs, `vcpkg_installed/`, generated `*.pb.*`, `*.beam`, `tests-build-*`); then Read only the line ranges you need.
- **Read / Glob / `find` do NOT honor `.gitignore`** — keep them out of build/vendored/generated trees (`*.pb.h/.cc`, `vcpkg_installed/`) unless required.
- **Delegate broad reads.** Unknown locations or many-file sweeps → an `Explore` (or `general-purpose`) subagent that returns conclusions, not file dumps.
- **Summarise and hand off proactively** — long thread: record files touched, facts learned, open questions, next command; continue or spawn a fresh agent.
- **For code changes:** owning module → its tests → smallest coherent patch → targeted suite (`meson test -C build-<os> --suite <agent|server|tar>`) before the broad one.

## Agent Team & Governance

Specialized agents live in `.claude/agents/` (each declares its role, triggers, reference docs). `workflow-orchestrator` owns the gate sequence; `/governance` is the entry point for the full pipeline on a commit range.

Pipeline (8 gates, convention-enforced): Change Summary + Resource Ledger → security-guardian + docs-writer → domain-triggered (`cpp-expert` + `cpp-safety` on any C++) → happy-path + unhappy-path + consistency-auditor → chaos-injector (skipped if no findings) → compliance-officer + sre + enterprise-readiness → findings addressed (CRITICAL/HIGH block merge) → iterate. Use `/governance <range>`, not hand-running — waves 1–4 shipped 4 CRITICAL command-injection vulns without it.

## Darwin Compatibility

This Claude instance is the designated **macOS/Darwin compatibility guardian**. The `cross-platform` agent loads `docs/darwin-compat.md` on any macOS-affecting change — it holds the reconciliation workflow + standing pitfalls table.

## Erlang Gateway Build & Quality

Touching `gateway/` or any `*.erl`? **Read `docs/erlang-gateway-build.md` first** — build/verify commands, toolchain activation (`source scripts/ensure-erlang.sh`), the always-run-dialyzer rule, the mandatory-`--dir`/#337 and eunit-isolation/#336 gotchas, the pitfalls table. `gateway-erlang` loads it on any `gateway/`/`.erl` change; `/gateway-eunit` + `/gateway-dialyzer` for routine runs.

## UAT Environment (Server ↔ Gateway ↔ Agent)

Standing up or debugging the stack? **Read `docs/uat-environment.md` first** — the three mutually-exclusive rigs (`scripts/start-UAT.sh` native; `scripts/start-viz-uat.sh` containerised viz; `scripts/start-demo.sh` release-pinned Cedar & Vale demo, runbook `docs/demo-environment.md`), the port table, gateway command forwarding (`--gateway-upstream`/`--gateway-mode`/`--gateway-command-addr`, `--trusted-nat-cidr`, the `agent_registry.cpp` `send_to()` flow). All three bind 8080 + 50051 — only one runs at a time. `release-deploy` loads it on any compose/UAT-script change.

## Pre-commit testing with /test

The `/test` skill (`.claude/skills/test/SKILL.md`) is the single-command pre-commit/pre-push gate — compiles HEAD, upgrades from the previous release image, runs the standard test surface, persists every gate result + timing to a SQLite DB at `~/.local/share/yuzu/test-runs.db` (survives `git clean`; override `YUZU_TEST_DB=path`). Modes: `--quick` (~10 min), default (~30–45 min), `--full` (~60–120 min — adds OTA, sanitizers, coverage enforcement, perf measure-only). History: `bash scripts/test/test-db-query.sh --latest|--last N|--diff A B|--trend|--flaky`.

## Instruction Engine

The content plane: YAML-defined `InstructionDefinition` → `InstructionSet` → `ProductPack`, executed via `CommandRequest`; `yaml_source` authoritative, denormalized columns for queries. Architecture: `docs/Instruction-Engine.md`; DSL: `docs/yaml-dsl-spec.md`; tutorial: `docs/getting-started.md`.

**Build-time gotcha:** PyYAML is a **hard build dependency** (`meson setup` fails without it). Shipped content is build-time embedded (`embed_content.py` → `bundled_content.cpp`, seeded into `instructions.db` on first boot); the runtime never reads YAML from disk (no `--content-dir` flag). See `docs/Instruction-Engine.md`.

## Enterprise Readiness and SOC 2

Enterprise-deployable is scoped in `docs/enterprise-readiness-soc2-first-customer.md` across 7 workstreams (GRC, Identity, AppSec, Reliability, Data, Secure SDLC, Customer Assurance); the Gate 6 agents evaluate every change against it.

## Development Roadmap

Roadmap: `docs/roadmap.md`. Capability map: `docs/capability-map.md` — its headline progress figure is overstated (memory `project_capability_map_accuracy.md`). Check the roadmap for dependencies before starting an issue.

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

Per-OS build dirs prevent clobbering when one tree is built from multiple hosts (WSL2 + native Windows + macOS): `build-linux` / `build-windows` / `build-macos`. Use `scripts/setup.sh` (auto-picks) or `-C build-<os>`. If setup.sh finds a dir recorded for another host it refuses to reconfigure unless `--wipe` (prevents opaque ninja "dyndep is not an input"/Windows-path failures from reusing a Windows builddir under WSL2); it never auto-wipes, defaults to `--reconfigure`.

### Windows build

`docs/windows-build.md` is the source of truth — MSYS2 bash sequence, the `setup_msvc_env.sh` + `scripts/ensure-erlang.sh` activation pair, path inventory, and two hard rules: **never `vcvars64.bat`** (extension exit-1 corrupts wrappers), **never Clang from `C:\Program Files\LLVM\bin`** (must be cl.exe/MSVC). `cross-platform` + `build-ci` load this on any Windows-touching change.

**Provisioning a native Windows CI runner** — see `deploy/windows/README.md` (provisioning spec, `toolchain-manifest.json`, runner self-test; gateway toolchain via `YUZU_ESCRIPT`/`YUZU_REBAR3`; the 4 runners share one vcpkg cache via `RUNNER_TOOL_CACHE`).

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
- Manifest `vcpkg.json`; pinned baseline `4b77da7fed37817f124936239197833469f1b9a8` (matches `vcpkgGitCommitId` in CI). `builtin-baseline` is required by the abseil `version>=` constraint — without it vcpkg resolves against HEAD.
- OpenSSL is **required on every platform including Windows** — gRPC's TLS/JWT/PEM paths compile against OpenSSL headers regardless of linkage, so `grpc.lib` needs `libssl`+`libcrypto`; it is an unconditional top-level dep (the old `!windows`/schannel filter was disproven, #375).
- `catch2` is platform-filtered to `x64 | arm64` (not 32-bit ARM).
- **libpq (ADR-0006/0008):** on Windows it is a **DLL** (the static override covers only the grpc stack), shipped via the release zip's vcpkg-DLL sweep; `libpq_dep` is gated on `build_server` (agent stays SQLite); manifest pins `default-features: false, features: [openssl]`; the buildtype-conditional `_vcpkg_lib_win` pick is load-bearing (pure-C libpq has no `detect_mismatch`, so a wrong-CRT lib links silently). No cmake target carries static libpq's full closure (`libpgcommon`/`libpgport` live in `libpq.pc`'s `Libs.private`) — `meson.build`'s `libpq_dep` block wires it explicitly.
- **Windows grpc/protobuf/abseil is load-bearing — both halves.** The `triplets/x64-windows.cmake` static-linkage override AND meson's hand-wired `protobuf_dep`/`grpcpp_dep` (`cxx.find_library()`) are the only config that avoids both LNK2038 and LNK2005 — don't simplify either half without reading `.claude/agents/build-ci.md` (full #375 timeline + #376 QUIC escape). Linux/macOS unaffected.

## CI architecture

Three-tier split: Tier 1 PR fast-path (`ci.yml`, one Linux + Windows + macOS + `proto-compat`, <10 min), Tier 2 push to dev/main (full matrix, no sanitizers/coverage, #410), Tier 3 nightly (`nightly.yml`, sanitizers + coverage — failure auto-opens `nightly-broken`; **no merge to main while it is open**). `workflow_dispatch`/cron fire only once the workflow file is on `main` — new workflows on `dev` are dormant until merged. Full reference: `docs/ci-architecture.md`; `build-ci` owns the matrix, `cross-platform` the Windows/macOS specifics.

**Standing invariant — failure-path `if:` guards need an explicit status function.** A GitHub Actions `if:` containing **no** status-check function (`success()`/`failure()`/`always()`/`cancelled()`) has an implicit `success()` ANDed onto it. So `if: steps.X.outcome == 'failure'` is **unsatisfiable** — `success()` is already false the moment X fails, so the step can never run. Every failure-path step (diagnostics, stack captures, artifact uploads on red) must lead with `failure() && …` or `failure() || cancelled()` explicitly. This silently skipped the nightly TSan gdb capture on every red nightly for two months (#1038); `grep -n "outcome ==" .github/workflows/` before trusting any failure-path guard.

## Release workflow gates

The `release:` job (`.github/workflows/release.yml`) runs `scripts/check-compose-versions.sh` **first** — it rejects any tracked-compose `ghcr.io/<owner>/yuzu-{server,gateway,agent}(-chisel)?:X.Y.Z` that is a bare numeric tag or a `${YUZU_VERSION:-...}` default ≠ the tag being released (floating tags ignored). **Before tagging**, bump the `${YUZU_VERSION:-X.Y.Z}` default in every tracked compose file and verify: `bash scripts/check-compose-versions.sh 0.12.0` — else the job fails only after the full build matrix. New compose file ⇒ add it to the script's `FILES` array (auto-discovery is deliberately off).

Additionally, `docker-publish`/`docker-publish-chisel` run `scripts/ci/verify-healthcheck-invariants.sh` **between build and push** (#751), so an image whose compose healthcheck tool (bash+`/dev/tcp`, busybox `wget --spider`) has silently gone missing is never published. The same gate runs on PRs via `docker-healthcheck-invariants.yml`. See `docs/ci-architecture.md` → "Gates outside the tier ladder".

## Changelog

**Never edit `CHANGELOG.md`** — add one fragment file `changelog.d/<PR#>-<slug>.<section>.md` (body = the finished `- ` bullet), assembled at release. A hook + the `Changelog fragments` CI job enforce this; see `changelog.d/README.md`.

## Routed concerns (read the doc, not this file)

| Concern | Doc | Loaded by |
|---|---|---|
| Authentication, RBAC, headers, tokens, self-target principal-destruction guard (#397/#403). Every new list/fan-out read of per-agent data MUST use the admit-then-filter `authorize_list_read` chokepoint (World A, ADR-0017) — never a bare global `require_permission` (inert for confined operators; fails open on a corrupt `rbac.db`). **Engine principals** (ADR-1005 class; `engine_principal_store.*`, ADR-0031) are default-deny: they resolve authority RBAC-only in `require_permission`/`require_scoped_permission` (never the pre-RBAC legacy or service-scoped fallback — 403 RBAC-off/no-grant, 503 store-unavailable) and can **NEVER** hold admin/built-in/wildcard (`dangerous`-class gate `validate_assignment`). Fleet-wide grants are authored via `/api/v1/engine-principals/{id}/roles` + MCP twins; the boot-time `engine:` namespace-collision scan fails **closed** (a non-open `rbac.db` refuses boot). | `docs/auth-architecture.md` + `docs/adr/0031-engine-principal-store.md` | `security-guardian` on auth/RBAC/crypto/header/token change, incl. `engine_principal_store.*` / `/engine-principals` routes |
| PKI / internal CA — `ca.db` (`CaStore`) holds cert metadata + CRL versions + the root key's opaque `key_ref` ONLY; the CA root **private key is never in the DB** (behind `KeyProvider`). `sign_agent_csr` is the single shared signer for direct `Register` AND gateway `ProxyRegister` — subject/SAN/EKU server-chosen, CSR ignored. Revoke is serial-scoped (DENY an agent to stop re-issuance). Composes stay plaintext until PR5b — **do not internet-expose `:50051`** (fleet-RCE). | `docs/pki-architecture.md` | `security-guardian` + `cpp-safety` + `docs-writer` on `x509_ca.{hpp,cpp}` / `key_provider.{hpp,cpp}` / `secure_buffer.hpp` / `aes_gcm.hpp` / `pg/secret_codec.{hpp,cpp}` (ADR-0010 secrets seam — also on any new `KeyProvider`/`KekProvider` subclass) / `ca_store.{hpp,cpp}` / `agent_csr.{hpp,cpp}` / `ca_routes.{hpp,cpp}` / `/api/v1/ca/`; `gateway-erlang` on `gateway/config/sys.config*` / gateway `*_pb.erl` / `yuzu_gw_app.erl` TLS |
| AuthDB invariants — `auth.db` mode, migration, lifetime, seed-vs-live, role-field-ignored, gate audit, cleanup cadence, snapshot-and-release | `.claude/agents/authdb.md` | `authdb` agent on `auth_db.{hpp,cpp}` / `auth_routes.*` / `auth.{hpp,cpp}` change |
| Enterprise A&A roadmap — RBAC, OIDC, SAML, SCIM, MFA, AD/Entra, API tokens, session lifecycle, audit | `.claude/skills/auth-and-authz/SKILL.md` | invoke `/auth-and-authz` for any A&A planning, audit, or implementation work |
| MCP server architecture, tier-before-RBAC ordering, kill switches, audit pattern; Streamable HTTP transport (sessions, GET SSE, progress bridge) is committed direction — ADR-1005 exec-plan Decision 15 (binding security/bounds pre-commitments a–k) / track 2f | `docs/mcp-server.md` | `security-guardian` on `/mcp/v1/`, `mcp_server.{hpp,cpp}`, `mcp_jsonrpc.hpp`, `mcp_policy.hpp`, `mcp_transport.{hpp,cpp}`, `mcp_session.{hpp,cpp}`, `mcp_stream_bridge.{hpp,cpp}` change |
| Executions-history ladder — `command_id → execution_id` map, SSE `ExecutionEventBus`, `api.v1.events.subscribe` audit split; MCP `execute_instruction` is a tracked-execution producer (#1088). Invariant: one bus, one taxonomy (`/api/v1/events`) — never per-route event formats (consumers: dashboard SSE + REST SSE; MCP stream bridge joins as a third via track 2f). | `docs/executions-history-ladder.md` | any change to `agent_service_impl.cpp` `cmd_execution_ids_`, `response_store` execution queries, `execution_event_bus.*`, `execution_tracker.*`, `rest_a4_envelope.{hpp,cpp}`, the `/api/v1/events` handler in `rest_api_v1.cpp`, the `execute_instruction` handler in `mcp_server.cpp`, `mcp_stream_bridge.{hpp,cpp}` (bus consumer — exec-plan track 2f), or executions-drawer markup |
| Compliance evaluation pipeline — `PolicyEvaluator` background thread (10s tick, 15s grace, ≥60s floor, 3600s default) drives check→verdict→status; `policy_eval_thread_` joins before stores in `~ServerImpl`/`stop()`. Mints `polchk-*` ids `notify_exec_tracker` skips (no tracker row, no SSE — NOT in the executions drawer). Remediation is operator-gated only. | `docs/user-manual/policy-engine.md` | `cpp-safety` + `docs-writer` on `policy_evaluator.{hpp,cpp}`, the `PolicyStore` status writer, or the `polchk-` guard in `agent_service_impl.cpp` |
| `/auto` Pre-flight readiness — operator go/no-go checks across a device cohort before a fleet change. Born-on-PG `PreflightRunStore` (construction fail-CLOSED per ADR-0012, 14-day prune, owner-scoped reads); background `PreflightRunner` re-dispatches READ-ONLY checks to not-yet-answered FROZEN targets. LOAD-BEARING: safe ONLY because every check is read-only/idempotent — any future MUTATING check must re-resolve `devices_fn(creator)∩group` per dispatch, never reuse the frozen cohort. Mints `preflight-*` ids `notify_exec_tracker` skips. Concurrency contract (two writers, `complete_run` CAS): the ladder row in `docs/postgres-migration-ladder.md`. | `docs/user-manual/preflight.md` + `docs/executions-history-ladder.md` | `security-guardian` + `cpp-safety` + `docs-writer` on `preflight_run_store.*` / `preflight_runner.*` / `preflight_routes.*` / `preflight_eval.*` / `preflight_parse.hpp` / the `preflight-` guard in `agent_service_impl.cpp` |
| `/auto` Deploy (the ACT stage after pre-flight ASSESS) — stage + execute an installer on a pre-flight run's go-cohort via the `content_dist` plugin (NO new agent code). Born-on-PG `DeploymentRunStore`: the device step is STATEFUL (mutating) → GUARDED one-way transitions + `claim_for_exec` execute-once CAS (see the ladder row). RE-AUTHORIZATION every tick (`devices_fn(viewer)∩cohort`) keeps the mutating step safe — a lost-scope device is skipped, never run. NO background runner in slice 1 (page/MCP poll advances it). ANY future store mutation MUST stay a guarded transition (never an unconditional grid overwrite) or execute-once breaks. Mints `deployment-*` ids `notify_exec_tracker` skips. | `docs/user-manual/preflight.md` + `docs/executions-history-ladder.md` + `docs/postgres-migration-ladder.md` | `security-guardian` + `cpp-safety` + `docs-writer` on `deployment_run_store.*` / `deployment_engine.*` / `deployment_routes.*` / `deployment_parse.hpp` / `deployment_ui.cpp` / the `deployment-` guard in `agent_service_impl.cpp` |
| C++23 conventions, naming, headers, plugin ABI boundary | `docs/cpp-conventions.md` | `cpp-expert` on any C++ source change |
| C++ resource ownership and lifetime — fd/HANDLE/SOCKET/`FILE*`/SQLite/OpenSSL/BCrypt/C-string/thread/callback/temp-path ownership, RAII/scope guards, `string_view`/`span` validity, casts, syscall/process boundaries, sanitizer coverage | `docs/cpp-conventions.md` | `cpp-safety` on any C++ source change; `security-guardian` also enforces the ownership proof during Gate 2 |
| macOS workflow + Darwin pitfalls table | `docs/darwin-compat.md` | `cross-platform` on any macOS-affecting change |
| Prometheus metrics, label set, audit envelope, event format | `docs/observability-conventions.md` | `sre` and `architect` on any metrics/audit/event change |
| Response data types, audit envelope, inventory data for analytics | `docs/data-architecture.md` | `architect` and `sre` when designing schemas |
| User manual / YAML defs / REST API / Substrate primitive registration | docs-writer agent (`.claude/agents/docs-writer.md`) | docs-writer on every change as part of governance gate 2 |
| Guardian / Guaranteed State — real-time agent-side policy enforcement (guard categories, YAML DSL, `__guard__` wire protocol, approval workflow, quarantine; §24 invariants). DEX families: ruleless signal observations (`rule_id="__observation__"`, `event_type` = obs_type — the ruleless-ness IS the discriminator); plus state-poll/perf-breach, blast-radius/alert-routing, device+app perf-over-time, `/auto` VERIFY. CRITICAL: fleet AND group app-perf reads floor sub-`kDexCohortFloor` `(version,day)` points to a count only (no singling-out); `/auto` VERIFY is EVIDENTIAL (no verdict/threshold/gate) and deliberately has NO floor — the audited `dex.app_perf.compare` read replaces suppression. BRD map `docs/dex-brd-coverage.md` is local-only/untracked (commercially sensitive) — ask the operator if missing. | `docs/yuzu-guardian-design-v1.1.md` + `docs/yuzu-guardian-windows-implementation-plan.md` + `docs/dex-signal-catalog.md` | `security-guardian` + `docs-writer` on any `guaranteed_state*`, `guardian_*`, `guard_*`, `dex_*`, `app_perf_*`, `sync_source_app_perf.*`, `verify_routes.*`, `verify_ui.*`, `/api/v1/dex/perf`, `__guard__`, or `__observation__` change |
| Spark detection layer (ADR-0021) — `SparkEngine` is the agent's sole detection primitive (watchers multiplexed **by mechanism, not rule**; inline tier core-internal + enforce-only + µs-latency, queued tier for all else). Rung 1 shipped observe-only, no consumer. Rung 7 wired Guardian as the first consumer via `GuardianEngine::reconcile_rule_locked()` - the sole per-rule arm/disarm chokepoint enforcing mutual exclusion (a rule is armed in at most one of legacy `guards_` or `spark_runtime_`, never both; an arm failure is errored, never a silent fallback). `prefer_spark_` defaults `false`; `agent.cpp` has zero `wire_spark_engine()` call sites yet, so legacy `IGuard` remains the sole live path. F3 (`hard_exit.hpp`): a detached Guardian I/O worker can't be joined, so `main.cpp`/`service_win.cpp` `hard_exit()` rather than race C++ teardown against one still active past a bounded grace. | `docs/adr/0021-spark-reflex-architecture.md` + `docs/spark-stage2-guardian-consumer-design.md` + `docs/yuzu-guardian-design-v1.1.md` | `security-guardian` + `cpp-safety` on `spark_engine.*` / `spark.hpp` / `spark_mechanism.*` / `spark_*.{hpp,cpp}` / `guardian_spark_*.{hpp,cpp}` / `hard_exit.hpp` |
| TAR dashboard — frames, URL structure, permissions. Adding a capture source? Use the CORE pattern (`docs/tar-implementer.md` §8), NOT the self-contained tier pattern; ARP/DNS + Capture-sources frame are ADR-0015 (opt-in, Windows-first; DNS is usage-class PII). Untrusted `tar.sql` runs only through read-only `TarDatabase::execute_user_query` (authorizer allowlist), never trusted `execute_query` (#760/#631). Per-source enable/disable fails CLOSED via the `canonical_source_enabled` tri-state (#560). `TarDatabase::open` integrity-checks + quarantines a corrupt `tar.db` aside or fails closed — never re-open-and-trust (#559). New streaming sources implement `ProcStreamCollector`, never a parallel path (`docs/tar-module-loads.md`). | `docs/tar-dashboard.md` + `docs/tar-implementer.md` + `docs/darwin-compat.md` | `architect` on `/tar` or `/fragments/tar/...` change; `plugin-developer` on TAR action surface; `cross-platform` + `cpp-safety` on `tar_proc_{stream,etw,es}.*`; `cpp-safety` + `docs-writer` on `tar_db.cpp` open/quarantine or `canonical_source_enabled`; `docs-writer` on dashboard nav |
| Scope walking — composable scope from previous query results (product differentiator). Result-set primitive, `result_sets.db`, `from_result_set:<id>` Scope kind, REST/DSL surface, lineage, audit chain | `docs/scope-walking-design.md` | `architect` + `dsl-engineer` on scope-engine/DSL/result-set change; `consistency-auditor` on audit chain; `security-guardian` on cross-operator authz |
| System architecture — cross-cutting design reference (Operator/Server/Agent/Gateway, REST/MCP/dashboard surfaces, plugin ABI boundary) | `docs/architecture.md` | `architect` on cross-cutting design changes |
| Tag/scope DSL operator reference — `tag:X`, `props.X`, `ostype`, `hostname`, `arch`, `agent_version` resolution; recipes for asset tagging | `docs/asset-tagging-guide.md` | `dsl-engineer` on scope/tag-DSL changes; `architect` when a new scope kind is added |
| Agentic-first invariants A1–A5 (dashboard parity, discovery, observability, error envelope, agentic context contract) — applies to every new MCP tool, REST route, dashboard fragment, or error site. A5 (exec-plan Decision 16, track 2g): every new/materially-changed MCP tool ships standard annotations (`destructiveHint` truthful vs tier), decision-grade description, bounded input schema, typed output schema, honest `retry_after_ms` — machine metadata, never prose-only. SSE + A4 error-envelope shape contracts live in `server/core/src/rest_a4_envelope.hpp`. | `docs/agentic-first-principle.md` | `consistency-auditor` on every PR; `security-guardian` + `architect` on relevant surfaces; on `rest_a4_envelope.{hpp,cpp}` or the `/api/v1/events` handler |
| Enterprise-platform parity matrix — competitor capability comparison and gap analysis (complements `docs/capability-map.md`) | `docs/enterprise-parity-plan.md` | `architect` on capability-map / roadmap changes; `enterprise-readiness` agent during Gate 6 |
| CI cache patterns — split `actions/cache/restore` + paired `actions/cache/save` for GHA-hosted; local `runner.tool_cache` for self-hosted; **never `save-always: true`** (zizmor guard enforces) | `.claude/skills/ci-cache/SKILL.md` | `build-ci` on `actions/cache@`, vcpkg cache scope, ccache scope, or self-hosted-runner cache wiring |
| Agent privilege model — dedicated `_yuzu` / `yuzu` / `NT SERVICE\YuzuAgent` account, narrow sudo NOPASSWD + LSA privileges, per-plugin privilege matrix, prod virtual-service-account vs dev local-user, install scripts `scripts/install-agent-user.{sh,ps1}`; the doc has the new-privileged-plugin procedure. | `docs/agent-privilege-model.md` | `security-guardian` on any plugin shell-out / sudoers / setcap change; `cross-platform` on any change that gates a plugin behind a privileged command; `plugin-developer` when adding a new privileged plugin (the doc has the procedure) |
| Fleet visualization (3D) — REST surface, page-shell, renderer, and process-layer invariants for the 11-PR `feat/viz-engine` ladder | `docs/fleet-viz-invariants.md` | `security-guardian` + `docs-writer` on `viz_routes.{hpp,cpp}` / `fleet_topology_store.{hpp,cpp}` / `viz_page_ui.cpp` / `static/yuzu-viz.js` / `--viz-disable` / `Config::viz_disable` |
| Network quality dashboard (`/network`) — MEASUREMENT-FIRST device/local-link health lens (interval retransmit rate + RTT + throughput). `yuzu.net_retrans_pct` is an INTERVAL delta, NOT the disproven lifetime ratio; `yuzu.net_degraded` is RETIRED (gauge absent-not-zero). Windows retransmit is whole-stack + unvalidated (#1465) → WITHHELD from `yuzu_fleet_net_retrans_pct` (Linux-only today; still on page/REST, caveated); other net gauges carry an `os` label — never alert on a cross-OS aggregate. Agent heartbeat keys pinned to `kNetTag*` by static_assert. | `docs/user-manual/network.md` | `security-guardian` + `docs-writer` on `network_routes.{hpp,cpp}` / `network_perf_model.{hpp,cpp}` / `network_perf_rules.hpp` / `network_ui.cpp` / `net_quality_sampler.{hpp,cpp}` / `tar_netqual.hpp` / the `yuzu.net_*` heartbeat block / `yuzu_fleet_net_*` |
| Device pages (`/devices` + `/device?id=`) — SHARED device surface: Device info / DEX / Guardian lens tabs + "Get live info" dispatch-and-poll snapshot; every kind has its own `device.live.<kind>` audit verb — usage-class reads stay separately countable (works-council). CRITICAL: (1) ALL behavioural-PII access-audit funnels through `server/core/src/rest_audit.hpp` (`emit_behavioral_audit`, #1647) — REST fail-closed 503 + `Sec-Audit-Failed`, dashboard HTML + MCP set-and-proceed; NEVER reintroduce an inline bool-capture on a new PII route (last un-migrated: `device.live.*` REST; #1703). (2) Result polls scoped at the store seam — `ResponsesFn` threads `agent_id` into `ResponseQuery{.agent_id}` (#1634); post-filter is defense-in-depth only. | `docs/user-manual/device-management.md` | `security-guardian` + `docs-writer` on `device_routes.{hpp,cpp}` / `device_ui.cpp` / `DeviceRoutes` / the `device.live.*` audit verbs / `processes/{list_hashed,list_tree}` / `network_config/arp` / the live-snapshot JS in `guardian_page_ui.cpp` / `rest_audit.hpp` |
| OS capability matrix — per-capability × per-OS snapshot of what the agent collects/enforces, each row citing its in-code source. Curated and **will drift**; durable fix = generate from the per-OS metadata. When changing per-OS support, record the other platforms' status too. | `docs/os-capability-matrix.md` | `docs-writer` + `cross-platform` on any per-OS support change |
| Agent daily-sync framework + installed-software inventory (ADR-0016) — agent pushes per-source endpoint state daily over `ReportInventory` (hash-skip); sources: #1 `installed_software` (`list_inventory` — **blob contract v2**, honest-empty NEVRA+signature, parse helpers `installed_apps_inventory.hpp`; operator `list` action byte-unchanged), #2 `app_perf`, #3 `device_ci` (serial/UUID/MAC = GDPR personal data → behavioural-PII tier). CRITICAL: (1) `inventory_state.last_seen`/`first_seen` = SERVER receipt time, never agent `collected_at` (#1685); (2) a new sync source is a new `plugin_data` map KEY, NOT a proto field (no `agent_pb`/`gateway_pb` regen); (3) Windows registry STRING reads use `Reg*W` via `agents/shared/win_str.hpp`, never `Reg*A` (#1662/#1682, `docs/cpp-conventions.md`); (4) blob v2's 12-field order is hashed byte-identically on agent (`sync_source_installed_software.cpp`) + server (`software_inventory_store.cpp`) — a one-sided field-order change breaks hash agreement permanently. | `docs/adr/0016-agent-daily-sync-framework.md` + `docs/user-manual/inventory.md` | `security-guardian` + `docs-writer` + `architect` on `sync_scheduler.*` / `sync_source_*` / `inventory_*` / `device_ci_ingestion.*` / `software_inventory_store.*` / `device_inventory_store.*` / `software_catalog_rollup.*` / the `ReportInventory`+`ProxyInventory` handlers / the `Inventory` securable |
| SQLite `sqlite3_changes()` after `step()` on a shared FULLMUTEX connection is a data race + correctness bug (reads `db->nChange` without the per-connection mutex; FULLMUTEX serialises calls, not the step→changes pair). Use `RETURNING`, or wrap the pair under `sqlite3_db_mutex`. #1033 tracks 24 legacy sites; every new/modified store must use a correct idiom. | issue #1033 | `cpp-expert` and `architect` on any new `sqlite3_changes()` call site on a shared store connection |
| **Server storage substrate — PostgreSQL**; agent stays SQLite (`agent.db` + federated edge warehouse). Server fails closed at boot — NO SQLite fallback — when `--postgres-dsn`/`YUZU_POSTGRES_DSN` is unset/unreachable (ADR-0006/0007). New server stores default to Postgres (no new server SQLite store without an exception ADR); ALL existing server stores migrate — none stays SQLite (ADR-0006 Update). Secrets are NEVER a plain Postgres column — verify-only hash or `SecretCodec` envelope blob (SHIPPED, ADR-0010); `security-guardian` review on every secret-column migration. Author contract: ADR-0012; recipe: `docs/postgres-store-playbook.md`; ordered queue: `docs/postgres-migration-ladder.md`. | ADR-0006/0007/0008 (incl. Correction)/0010/0012 + `docs/postgres-store-playbook.md` + `docs/postgres-migration-ladder.md` | `architect` + `sre` on any server store/schema change; `build-ci` on CI Postgres service; `release-deploy` on deploy/compose; `security-guardian` on any secret-at-rest |
| **Headless platform & use-case engines (ADR-1005)** — server is headless/use-case-agnostic: every capability behavior reachable by an authenticated external principal via versioned REST **and** MCP (or a recorded ADR-1005 ledger exception), discoverable (A2/A3), A4 error envelope, no in-process-only behavior, RBAC + audit at the API — no UI-only capabilities (a dashboard fragment is not an API twin). On-behalf-of assertions rejected on every ingress (REST, MCP, agent gRPC; sole exception: the four health-probe paths ignore them — a header-stamping proxy must not crash-loop the server); engine principals are a distinct principal class, never impersonation. Use-case interpretation (e.g. vuln mgmt) lives in separately-deployed use-case engines (UCE), not the server; the first UCE re-homes server-side NVD sync/matching (strangler migration). Exec plan holds status + decision log + vuln milestones (M1–M4; M3 = the parity **+ confinement** gate authorizing the irreversible server-side deletion) — read it before adding anything engine- or API-surface-shaped. | `docs/adr/1005-headless-platform-use-case-engines.md` (policy) + `docs/adr-1005-execution-plan.md` (phase status) | `consistency-auditor` on every capability-adding PR (Gate 4 preamble item 8); `architect` + `security-guardian` on any new REST route / MCP tool / dashboard fragment / ingress surface, and on any change to `on_behalf_guard.hpp` / `grpc_on_behalf_interceptor.hpp` / `principal_class.hpp` / the pre-routing chokepoint in `server.cpp` |

## Guardian engine — stores

Working on Guardian / Guaranteed State? **Read `docs/yuzu-guardian-design-v1.1.md` first** — §9.1 = `guaranteed-state.db` / `GuaranteedStateStore` schema; §24 = standing invariants (`Push`-seed scope, `__guard__` defence-in-depth, gateway-safe wire payloads, enforce-gate chokepoint). Catastrophic ones: (1) `BaselineStore` (`server/core/src/baseline_store.{hpp,cpp}`) — a **Baseline** is the only deployable unit; push fan-out + heartbeat reconcile gate on `deployed_member_rule_ids()`, sourced from each deploy's **`deployed_snapshot`, NOT the live member set** (what's enforced stays behind `Push`, not `Write`). (2) `dangerous_enforce_in_spec` (`guardian_rule_spec.cpp`) is the **single chokepoint** for dangerous enforce-promotion — **EXTEND it, never fork**. (3) Published schema enums ↔ agent per-type support arrays are bound by the H2/G9 cross-check tests — add/remove a type in **both or neither**. Docs: `docs/user-manual/guaranteed-state.md`, `docs/guardian-baseline-model.md`, `docs/yuzu-guardian-windows-implementation-plan.md`.

## Test conventions — shared helpers

Use `yuzu::test::unique_temp_path(prefix)` / `yuzu::test::TempDbFile` / `yuzu::test::TempDir` from `tests/unit/test_helpers.hpp` for any test temp file, SQLite DB, or scratch dir. **Never** salt uniqueness with `std::hash<std::thread::id>` or `std::chrono::steady_clock` — silent collisions under Defender-induced I/O serialisation (flake #473; #482). Pass a **`yuzu_test_` (underscore) prefix** so names land inside the Wee Tam Defender path-exclusion wildcard `yuzu_*` (`scripts/windows-runner-defender-exclusions.ps1`) — the helpers' default `yuzu-test-` (hyphen) prefix does NOT match it; all three helpers take an explicit prefix for exactly this.

**Standing invariant:** both self-hosted CI pools run 4 runner agents as ONE shared OS identity on ONE box — Windows "Wee Tam" (LOCAL SYSTEM, `deploy/windows/README.md`), Linux "Big Tam" (`runner` user sharing `$HOME`, `docs/ci-architecture.md`). A fixed registry key/port/named-object/path is a cross-JOB shared resource — two concurrent CI jobs on one box collide (#1871's `RegistryGuard` family; same bug on Linux gateway eunit `health_port`). Salt every such identifier per-test/per-process like `unique_temp_path()` — see `test_guard_registry.cpp`'s `TempRegKey`/`TempEnforceKey`.

For server tests that need a live `ExecutionTracker` in `AgentServiceImpl`, use the `TrackerScope` RAII helper in `tests/unit/server/test_agent_service_impl.cpp` — `:memory:` SQLite, `set_execution_tracker`, nulls the borrowed pointer before the tracker destructs (the production shutdown contract, `agent_service_impl.hpp:113`). Promote to `test_helpers.hpp` once a second file needs it.

For server tests needing live **PostgreSQL**, use `PostgresTestDb` + `YUZU_REQUIRE_PG_DB(var)` from `test_helpers.hpp` (behind `YUZU_TEST_ENABLE_PG`, server suite only). Creates an ephemeral `yuzu_test_<epoch>_<salt>_<n>` DB on `YUZU_TEST_POSTGRES_DSN`, drops it `WITH (FORCE)`; the name-embedded epoch drives a suite-start sweep of databases leaked by killed runs. Skip-vs-fail: env **unset** → skip (local dev); **set but broken** → FAIL (`scripts/ci/ensure-postgres.sh` guarantees a reachable instance on every CI server-test leg). **Store-behaviour tests use the pre-migrated template variant** `YUZU_REQUIRE_PG_DB_TPL(var, tpl)` + a file-local `PgTestTemplate` (clones an already-migrated DB — per-test migration DDL drove the 2026-07-12 Windows server-suite timeout; recipe: `docs/postgres-store-playbook.md` step 7); plain `YUZU_REQUIRE_PG_DB` is only for migration / fresh-DB / pg-substrate behaviour tests. Local: run `postgres:18` on `:5433`, then `export YUZU_TEST_POSTGRES_DSN=postgresql://yuzu:yuzu@localhost:5433/yuzu`.

## Agent skills

The Matt Pocock engineering skills are **user-global**, not committed — they follow the operator. Re-run `/setup-matt-pocock-skills` to change.

**`/dev-team`** is committed **project-level** (`.claude/skills/dev-team/`), *unlike* the Matt Pocock set above — so every collaborator gets it via git. It runs an Opus "senior" session that plans and delegates to Sonnet `junior-developer` subagents (scoped edits, targeted tests, then `/test --quick`), consulting a Fable `enterprise-architect` (both in `.claude/agents/`) for material or disputed calls, then integrates the result behind `/test` + `/governance`. Invoke `/dev-team <task>`. If Fable is unavailable in an environment, override `enterprise-architect`'s frontmatter to `model: opus` **as a local-only edit — do not commit it** (it is environment-specific; committing would force `model: opus` on every collaborator whose environment *does* have Fable). Keep the change out of any PR, or carry it via user-global config that shadows the committed agent file.

### Plugin scope — `frontend-design` is marketing-only

The `frontend-design` plugin is **marketing / sales / demo surfaces only** — its varied light/dark aesthetic fits a standalone pitch surface, not the **dark-theme-only** product. Use on the Cedar & Vale deck (`deploy/docker/cedar-vale/app/`) + future marketing pages. **Never on product UI** — `server/core/src/*_ui.cpp`, `server/core/static/*`, incl. in-product fleet viz (`viz_*_ui.cpp`, `yuzu-viz*.js` — product despite the name). Product UI stays HTMX-first, server-rendered, dark-theme-only.

**Product UI — no htmx `hx-on`.** Dashboard CSP is `script-src 'self' 'unsafe-inline'` (no `unsafe-eval`); htmx compiles `hx-on:*` with `new Function()`, which CSP **blocks at runtime — the handler silently does nothing**. Use a plain inline `onclick`/`oninput` calling a JS helper, or an `htmx:afterSettle` body listener. Core `hx-*` attrs + the `HX-Trigger` header don't eval — fine. Verify button-driven JS in a headless browser for a CSP `pageerror`, not just that the page renders. See memory `project-dashboard-csp-no-hx-on.md`.

### Issue tracker, triage labels, domain docs

GitHub issues at `github.com/Tr3kkR/Yuzu` via the `gh` CLI (`docs/agents/issue-tracker.md`). Triage labels: the canonical five plus a broader categorization set (`docs/agents/triage-labels.md`). Domain docs: `CONTEXT.md` at the repo root, ADRs under `docs/adr/` (`docs/agents/domain.md`).

## CLAUDE.md updates

Architectural decisions, new stores, churning subsystems, and cross-cutting concerns belong here; stable reference material an agent already loads belongs in `docs/` with a pointer here (heuristic: memory `feedback_claude_md_scope.md`; precedent: the Erlang gateway section → `docs/erlang-gateway-build.md`). Keep this file under 40k characters — routed-concern rows hold only the catastrophic-if-violated invariants + doc pointers; the detail goes in the routed doc.
