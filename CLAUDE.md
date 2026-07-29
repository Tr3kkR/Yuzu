# Yuzu — Claude Code Guide

## Active workstreams (temporary — 2026-07-29 → ~2026-08-05)

Four parallel streams are running across three machines. **Read `docs/workstreams.md` and the
`STREAM.md` at your worktree root before starting work.** Work belongs to exactly one stream:
`ci` (CI/test revamp) · `adr17` (list-read confinement) · `adr31` (decomposition) ·
`pg` (SQLite → Postgres). If a task is outside all four, say so and ask rather than starting it.

Shulgi's Windows and WSL2 halves are one shared box and a live runner host — **take the semaphore
(`~/yz/bin/shulgi-lock`) before any build or test there, and release it when done.**

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

**Agent** is overloaded — use the disambiguated form in commits, PRs, and new docs:

- **Agent daemon** — the C++ binary in `agents/core/` on each managed endpoint that executes plugins (the usual meaning here).
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

CI history is separate and per runner: Big Tam stores `/srv/ci/work-N/_tool/yuzu-test-runs/yuzu-bigtam-linux-N/test-runs.db`; Wee Tam stores `D:\ci\test-runs\yuzu-weetam-windows-N\test-runs.db`. The files persist outside checkouts and are never shared by runner agents. `ci.yml` records job and Meson test-entry outcomes/timings plus recovered known flakes; query via `test-db-query.sh ci-stats|ci-suite-stats|ci-flakes`. See `docs/ci-architecture.md` for provisioning and schema details.

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

Tests require `-Dbuild_tests=true`. vcpkg installs Catch2 only on `x64 | arm64`; the ARM64 cross-compile CI job intentionally skips tests.

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
agents/plugins/   49 plugins
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

**Standing invariant — failure-path `if:` guards need an explicit status function.** A GitHub Actions `if:` containing **no** status-check function (`success()`/`failure()`/`always()`/`cancelled()`) has an implicit `success()` ANDed onto it. So `if: steps.X.outcome == 'failure'` is **unsatisfiable** — `success()` is already false the moment X fails. Every failure-path step (diagnostics, stack captures, artifact uploads on red) must lead with `failure() && …` or `failure() || cancelled()` explicitly. This silently skipped the nightly TSan gdb capture on every red nightly for two months (#1038); `grep -n "outcome ==" .github/workflows/` before trusting any failure-path guard.

## Release workflow gates

The `release:` job (`.github/workflows/release.yml`) runs `scripts/check-compose-versions.sh` **first** — it rejects any tracked-compose `ghcr.io/<owner>/yuzu-{server,gateway,agent}(-chisel)?:X.Y.Z` that is a bare numeric tag or a `${YUZU_VERSION:-...}` default ≠ the tag being released (floating tags ignored). **Before tagging**, bump the `${YUZU_VERSION:-X.Y.Z}` default in every tracked compose file and verify: `bash scripts/check-compose-versions.sh 0.12.0` — else the job fails only after the full build matrix. New compose file ⇒ add it to the script's `FILES` array (auto-discovery is deliberately off).

`docker-publish`/`docker-publish-chisel` also run `scripts/ci/verify-healthcheck-invariants.sh` **between build and push** (#751), so an image whose compose healthcheck tool (bash+`/dev/tcp`, busybox `wget --spider`) has silently gone missing is never published. The same gate runs on PRs via `docker-healthcheck-invariants.yml`. See `docs/ci-architecture.md` → "Gates outside the tier ladder".

## Changelog

**Never edit `CHANGELOG.md`** — add one fragment file `changelog.d/<PR#>-<slug>.<section>.md` (body = the finished `- ` bullet), assembled at release. A hook + the `Changelog fragments` CI job enforce this; see `changelog.d/README.md`.

## Routed concerns (read the doc, not this file)

One row per concern — catastrophic-if-violated invariants, routed doc, loading agents — imported from `.claude/routed-concerns.md` (same authority as this file; split out only for the 40k-per-file ceiling):

@.claude/routed-concerns.md

## Guardian engine — stores

Working on Guardian / Guaranteed State? **Read `docs/yuzu-guardian-design-v1.1.md` first** — §9.1 = `guaranteed-state.db` / `GuaranteedStateStore` schema; §24 = standing invariants (`Push`-seed scope, `__guard__` defence-in-depth, gateway-safe wire payloads, enforce-gate chokepoint). Catastrophic ones: (1) `BaselineStore` (`server/core/src/baseline_store.{hpp,cpp}`) — a **Baseline** is the only deployable unit; push fan-out + heartbeat reconcile gate on `deployed_member_rule_ids()`, sourced from each deploy's **`deployed_snapshot`, NOT the live member set** (what's enforced stays behind `Push`, not `Write`). (2) `dangerous_enforce_in_spec` (`guardian_rule_spec.cpp`) is the **single chokepoint** for dangerous enforce-promotion — **EXTEND it, never fork**. (3) Published schema enums ↔ agent per-type support arrays are bound by the H2/G9 cross-check tests — add/remove a type in **both or neither**. Docs: `docs/user-manual/guaranteed-state.md`, `docs/guardian-baseline-model.md`, `docs/yuzu-guardian-windows-implementation-plan.md`.

## Test conventions — shared helpers

Use `yuzu::test::unique_temp_path(prefix)` / `yuzu::test::TempDbFile` / `yuzu::test::TempDir` from `tests/unit/test_helpers.hpp` for any test temp file, SQLite DB, or scratch dir. **Never** salt uniqueness with `std::hash<std::thread::id>` or `std::chrono::steady_clock` — silent collisions under Defender-induced I/O serialisation (flake #473; #482). Pass a **`yuzu_test_` (underscore) prefix** so names land inside the Wee Tam Defender path-exclusion wildcard `yuzu_*` (`scripts/windows-runner-defender-exclusions.ps1`) — the helpers' default `yuzu-test-` (hyphen) prefix does NOT match it; all three helpers take an explicit prefix for this.

**Standing invariant:** both self-hosted CI pools run 4 runner agents as ONE shared OS identity on ONE box — Windows "Wee Tam" (LOCAL SYSTEM, `deploy/windows/README.md`), Linux "Big Tam" (`runner` user sharing `$HOME`, `docs/ci-architecture.md`). A fixed registry key/port/named-object/path is a cross-JOB shared resource — two concurrent CI jobs on one box collide (#1871's `RegistryGuard` family; same bug on Linux gateway eunit `health_port`). Salt every such identifier per-test/per-process like `unique_temp_path()` — see `test_guard_registry.cpp`'s `TempRegKey`/`TempEnforceKey`.

For route-handler tests, `TestRouteSink` (`tests/unit/server/test_route_sink.hpp`, used by 41 files) mirrors `httplib::Server`'s parsing of the path, the query string, and an `application/x-www-form-urlencoded` body into `req.params` (query first, so query wins) — and **nothing else**: no path percent-decoding, no multipart/chunked, no duplicate headers, and none of the pre/post-routing pipeline. So a gate that moves into pre-routing leaves every sink test green. Two traps: `Post(path, body)` defaults to `application/json` and does NOT populate `req.params` (omitting the content-type silently tests a handler's fallback instead of its production branch — the #1786 false-green, re-armable), and fixtures must declare the sink **after** the route owner it registers (its handlers capture the owner's `this`). Contract pinned by `tests/unit/server/test_route_sink_harness.cpp`.

For server tests that need a live `ExecutionTracker` in `AgentServiceImpl`, use the `TrackerScope` RAII helper in `tests/unit/server/test_agent_service_impl.cpp` — `:memory:` SQLite, `set_execution_tracker`, nulls the borrowed pointer before the tracker destructs (the production shutdown contract, `agent_service_impl.hpp:113`). Promote to `test_helpers.hpp` once a second file needs it.

For server tests needing live **PostgreSQL**, use `PostgresTestDb` + `YUZU_REQUIRE_PG_DB(var)` from `test_helpers.hpp` (behind `YUZU_TEST_ENABLE_PG`, server suite only). Creates an ephemeral `yuzu_test_<epoch>_<salt>_<n>` DB on `YUZU_TEST_POSTGRES_DSN`, drops it `WITH (FORCE)`; the name-embedded epoch drives a suite-start sweep of databases leaked by killed runs. Skip-vs-fail: env **unset** → skip (local dev); **set but broken** → FAIL (`scripts/ci/ensure-postgres.sh` guarantees a reachable instance on every CI server-test leg). **Store-behaviour tests use the pre-migrated template variant** `YUZU_REQUIRE_PG_DB_TPL(var, tpl)` + a file-local `PgTestTemplate` (clones an already-migrated DB — per-test migration DDL drove the 2026-07-12 Windows server-suite timeout; recipe: `docs/postgres-store-playbook.md` step 7); plain `YUZU_REQUIRE_PG_DB` is only for migration / fresh-DB / pg-substrate behaviour tests. Local: run `postgres:18` on `:5433`, then `export YUZU_TEST_POSTGRES_DSN=postgresql://yuzu:yuzu@localhost:5433/yuzu`.

## Agent skills

The Matt Pocock engineering skills are **user-global**, not committed — they follow the operator. Re-run `/setup-matt-pocock-skills` to change.

**`/dev-team`** is committed **project-level** (`.claude/skills/dev-team/`), *unlike* the Matt Pocock set above — so every collaborator gets it via git. It runs a configurable senior-led fleet: an Opus senior that plans and delegates to a junior fleet, an optional architect plan-review gate before dispatch, and an optional doc-writer second wave after code lands — all behind `/test` + `/governance`. Fleet config (junior model, architect backend, doc-writer) is read from `~/.claude/skills/dev-team/config.json` (user-global, not committed; gitignored in the skill dir) and confirmed via `AskUserQuestion` at every invocation. Backends: architect = `fable` (Anthropic agent) / `codex-sol` (gpt-5.6-sol, reads repo) / `kimi` (kimi-k2.7-code, static-only); junior = `haiku` / `sonnet` / `opus`. Defaults: `sonnet` juniors, `fable` architect, no doc-writer. Invoke `/dev-team <task>`.

### Plugin scope — `frontend-design` is marketing-only

The `frontend-design` plugin is **marketing / sales / demo surfaces only** — its varied light/dark aesthetic fits a standalone pitch surface, not the **dark-theme-only** product. Use on the Cedar & Vale deck (`deploy/docker/cedar-vale/app/`) + future marketing pages. **Never on product UI** — `server/core/src/*_ui.cpp`, `server/core/static/*`, incl. in-product fleet viz (`viz_*_ui.cpp`, `yuzu-viz*.js` — product despite the name). Product UI stays HTMX-first, server-rendered, dark-theme-only.

**Product UI — no htmx `hx-on`.** Dashboard CSP is `script-src 'self' 'unsafe-inline'` (no `unsafe-eval`); htmx compiles `hx-on:*` with `new Function()`, which CSP **blocks at runtime — the handler silently does nothing**. Use a plain inline `onclick`/`oninput` calling a JS helper, or an `htmx:afterSettle` body listener. Core `hx-*` attrs + the `HX-Trigger` header don't eval — fine. Verify button-driven JS in a headless browser for a CSP `pageerror`, not just that the page renders. See memory `project-dashboard-csp-no-hx-on.md`.

### Issue tracker, triage labels, domain docs

Issues follow `docs/agents/issue-standard.md`: dedupe before filing; automation never closes `security`/`do-not-close` issues. Commands: `docs/agents/issue-tracker.md`; labels: `docs/agents/triage-labels.md`. Domain docs: `CONTEXT.md`, ADRs in `docs/adr/` (`docs/agents/domain.md`).

## CLAUDE.md updates

Architectural decisions, new stores, churning subsystems, and cross-cutting concerns belong here; stable reference material an agent already loads belongs in `docs/` with a pointer here (heuristic: memory `feedback_claude_md_scope.md`; precedent: the Erlang gateway section → `docs/erlang-gateway-build.md`). Keep this file AND each file it imports (the routed-concerns table, `.claude/routed-concerns.md`) under 40k characters each — routed-concern rows hold only the catastrophic-if-violated invariants + doc pointers; the detail goes in the routed doc.
