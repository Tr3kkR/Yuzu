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

## Agent Team & Governance

Specialized agents live in `.claude/agents/` (each file declares its own role, triggers, and reference docs). The `workflow-orchestrator` agent owns the gate sequence; the `/governance` skill (`.claude/skills/governance/SKILL.md`) is the entry point for running the full pipeline on a commit range.

Pipeline (8 gates, convention-enforced — no git hook): Change Summary → security-guardian + docs-writer mandatory deep-dive → domain-triggered review → happy-path + unhappy-path + consistency-auditor (parallel) → chaos-injector (skipped if no findings) → compliance-officer + sre + enterprise-readiness (parallel) → findings addressed (CRITICAL/HIGH block merge) → iterate.

**Better process makes better products.** Waves 1–4 shipped without governance and accumulated 4 CRITICAL command-injection vulnerabilities, untested stores, stale docs, and performance bottlenecks — all caught before production but they should have been caught before commit. Use `/governance <range>` rather than hand-running.

## Darwin Compatibility

This Claude instance is the designated **macOS/Darwin compatibility guardian**. The `cross-platform` agent loads `docs/darwin-compat.md` on any change that may affect macOS — that doc holds the standing reconciliation workflow (fetch → pull → diff → reconfigure → compile → `bash scripts/run-tests.sh all` → commit) and the standing pitfalls table (`/var` symlink, SQLite mutex, `rebar3 ct --dir`, `curl -f`, `prometheus_httpd`).

## Erlang Gateway Build & Quality

The gateway (`gateway/`) is a standalone rebar3 project. It compiles independently from the C++ codebase.

### Build & verify commands
```bash
cd gateway
rebar3 compile                               # compile
rebar3 eunit --dir apps/yuzu_gw/test         # unit tests (148 tests)
rebar3 dialyzer                              # type analysis — must be warning-free
rebar3 ct --dir apps/yuzu_gw/test --suite <name>  # Common Test
```

**Always run `rebar3 dialyzer` after any Erlang change.** Compilation succeeding is not enough — dialyzer catches type violations, dead code, and missing dependencies that the compiler silently accepts. The project uses `warnings_as_errors` for compile but dialyzer warnings are separate.

**`--dir apps/yuzu_gw/test` is mandatory on `rebar3 eunit`**, not optional. Without it, rebar3 3.27 intersects discovered test modules against the `src/`-derived `modules` list in `yuzu_gw.app` and rejects every orphan test module (`*_tests` without a 1:1 src counterpart, every `*_SUITE` file, helpers) with `Module X not found in project` before running a single test. Tracked as **#337**; `scripts/run-tests.sh erlang-unit` already applies the workaround, but if you invoke rebar3 directly you must pass the flag yourself.

**`rebar3 eunit --module X` does NOT give you test isolation.** It runs the full `--dir` phase first, then the module filter, **in the same BEAM VM**. The second run inherits polluted state — meck mocks, registered names, leaked processes, send_after timers — from the first, so a passing filtered run does not prove the test is order-independent, and a failing filtered run may be failing because of pollution rather than the test itself. For real isolation, `rm -rf gateway/_build/test` between runs (forces a fresh BEAM) or drop into `erl -pa _build/test/lib/yuzu_gw/ebin -pa _build/test/lib/*/ebin` and call test functions directly. This gotcha wasted meaningful debugging time on #336.

Use the `gateway-eunit` and `gateway-dialyzer` skills (in `.claude/skills/`) for routine invocations — they bundle the toolchain activation, the `--dir` flag, and result interpretation.

### Toolchain activation (Erlang on PATH)

`rebar3` and the meson custom_target that wraps it both need `erl` on PATH. Forgetting to activate is the usual cause of phantom `.gateway_built` failures while the C++ targets succeed. Source the cross-platform helper before any gateway work and verify:

```bash
source scripts/ensure-erlang.sh           # default: latest 28.x
source scripts/ensure-erlang.sh 28.4.2    # exact pin
command -v erl >/dev/null || { echo "Erlang missing"; exit 1; }
```

The helper probes kerl → asdf → Homebrew (macOS) → MSYS2 installer (Windows) and **always returns 0** so it can't trip the caller's `set -e`. Callers MUST verify `command -v erl` themselves. Default version tracks `release.yml`'s `erlef/setup-beam` `otp-version` — bump both together. Native `cmd.exe`/PowerShell is out of scope; documented Windows build path is MSYS2 bash.

### Standing Erlang pitfalls

| Area | Issue |
|---|---|
| `ctx` dependency | `ctx:background/0` is used for grpcbox RPC calls. `ctx` is a transitive dep of `grpcbox` but must be listed in `yuzu_gw.app.src` `applications` since we call it directly — otherwise dialyzer can't find it in the PLT. **Rule: if you call a function from a transitive dependency, add it to the applications list.** |
| `-spec` contracts | If a function spec says `-spec f(map()) -> ok`, passing an atom like `f(some_atom)` compiles fine but dialyzer flags it. Always respect `-spec` contracts, even in catch/fallback paths. |
| Circuit breaker dead code | `on_success/1` and `on_failure/1` only receive states `closed` or `half_open` (never `open`, because `check_circuit/1` rejects before the RPC runs). Don't add catchall clauses for states that are structurally unreachable — dialyzer knows the type is fully covered. |
| `gpb` plugin warning | `Plugin gpb does not export init/1` is a benign warning from rebar3 — gpb is used via `grpc` config, not as a rebar3 plugin. Ignore it. |
| Stray `.beam` / crash dumps | `erl_crash.dump` and loose `.beam` files in the gateway root are artifacts. They should be gitignored or deleted, never committed. |
| Shutdown flush | During `stop/1`, `flush_sync/0` is the correct way to drain the heartbeat buffer. Do not fall back to `queue_heartbeat/1` with sentinel atoms — it violates the `map()` spec and would corrupt the buffer. If `flush_sync` fails, the process is already dead and the buffer is lost. |

## UAT Environment (Server ↔ Gateway ↔ Agent)

A Linux UAT script at `scripts/linux-start-UAT.sh` stands up the full stack, verifies connectivity, and runs command round-trip tests. Usage:

```bash
bash scripts/linux-start-UAT.sh          # start + verify (6 automated tests)
bash scripts/linux-start-UAT.sh stop     # kill all
bash scripts/linux-start-UAT.sh status   # show running processes
```

### Port assignments

Server and gateway defaults do not conflict — all three components can run on the same box without overrides:

| Port | Component | Purpose |
|------|-----------|---------|
| 8080 | Server | Web dashboard + REST API |
| 50051 | Server | Agent gRPC (direct connections) |
| 50052 | Server | Management gRPC |
| 50055 | Server | Gateway upstream (registration, heartbeats) |
| 50051 | Gateway | Agent-facing gRPC (agents connect here) |
| 50063 | Gateway | Management/command forwarding (server sends commands here) |
| 8081 | Gateway | Health/readiness (`/healthz`, `/readyz`) |
| 9568 | Gateway | Prometheus metrics |

### Gateway command forwarding

The gateway's primary function is **command fanout** — relaying commands from the server to potentially millions of agents and aggregating responses. This requires three server flags:

1. **`--gateway-upstream 0.0.0.0:50055`** — Enables the `GatewayUpstream` gRPC service so the gateway can proxy agent registrations and batch heartbeats to the server.
2. **`--gateway-mode`** — Relaxes Subscribe stream peer-mismatch validation so gateway-proxied agents can receive commands (their Register and Subscribe peers are both the gateway's address, not the agent's).
3. **`--gateway-command-addr localhost:50063`** — Points the server at the gateway's `ManagementService` for command forwarding. Without this, commands to gateway-connected agents are queued in `gw_pending_` but never forwarded. The server calls `SendCommand` (server-streaming RPC) on this address; the gateway fans out to agents and streams responses back.

The dispatch flow in `agent_registry.cpp` `send_to()`:
- Agent has a local Subscribe stream → write directly (direct-connect agents)
- Agent has a `gateway_node` but no local stream → queue to `gw_pending_` for gateway forwarding
- `forward_gateway_pending()` drains the queue via `gw_mgmt_stub_->SendCommand()`

The gateway uses port range 5006x (vs server's 5005x); `gateway/config/sys.config` and `grpcbox` `listen_opts` are configured independently and must match. UAT credentials: fresh `yuzu-server.cfg` with PBKDF2-SHA256 hashed `admin` / `adminpassword1` per run; state lives under `/tmp/yuzu-uat/` and is wiped on each start.

### Known bug: stale DB breaks session auth on restart

If the server is restarted against an existing data directory (stale SQLite databases from a prior run), session authentication breaks: `authenticate()` succeeds (HTTP 200, Set-Cookie returned) but `validate_session()` fails on subsequent requests (HTTP 401). The UAT script works around this by doing `rm -rf /tmp/yuzu-uat` before each run. This bug should be investigated — the in-memory `sessions_` map and the database state may be interacting incorrectly on restart.

## Pre-commit testing with /test

The `/test` skill (`.claude/skills/test/SKILL.md`) is the single-command pre-commit/pre-push gate. It compiles HEAD, stands up the previous released image (GitHub's current "Latest release" tag from `ghcr.io/tr3kkr/yuzu-*`, resolved at runtime via `gh api repos/Tr3kkR/Yuzu/releases/latest`; pin an older baseline with `--old-version X.Y.Z`), upgrades it to HEAD, verifies data preservation and migrations, then runs the standard test surface (unit + EUnit + dialyzer + CT + integration + e2e + synthetic UAT + puppeteer). Every gate result and sub-step timing is persisted to a SQLite test-runs DB at `~/.local/share/yuzu/test-runs.db` so operators can compare runs over time, spot flaky gates, and trend upgrade durations.

Three modes:

- `/test --quick` — sanity check (~10 min): build + unit + EUnit + dialyzer + synthetic UAT
- `/test` (default, ~30-45 min): build + upgrade test + standard gates + fresh stack + coverage report
- `/test --full` (~60-120 min): adds OTA Linux + OTA Windows (PR3), sanitizers dispatched to `yuzu-wsl2-linux`, coverage enforce + perf enforce

Query historical runs via `bash scripts/test/test-db-query.sh --latest|--last N|--diff A B|--trend timing=phase2.image-swap|--flaky --days 14|--export RUN_ID|--prune 100`. Power users can `python3 scripts/test/test_db.py query ...` directly.

The DB lives outside the repo (XDG data dir) so it persists across `git clean` and survives repo re-clones. Override with `YUZU_TEST_DB=path`.

**Coverage / perf baselines.** `--full` enforces `tests/coverage-baseline.json` (real numbers as of 2026-04-25 captured against `40acd33`: branch 26.8% / line 51.8% on the 5950X dev box, 0.5 pp slack) and `tests/perf-baselines.json` (4 metrics on 5950X, 10% tolerance, hardware fingerprint locked). The PR2 `__seed: true` sentinel is gone and the gates enforce in `--full`. The perf baseline records hardware fingerprint (CPU + RAM); mismatch auto-downgrades the gate to WARN so a 5950X baseline doesn't produce false failures on the MBP and vice versa. Both gates refuse `--capture-baselines` when the underlying test suite exited non-zero, so a broken environment cannot permanently anchor a bad baseline. The `__seed: true` sentinel is still honored as a defensive WARN if anyone re-introduces it (do not — to disable enforcement temporarily, edit `slack_pp` / `tolerance_pct` and document why). Regenerate on the target box with `bash scripts/test/{coverage,perf}-gate.sh --run-id manual --capture-baselines` after a clean test run, and commit the updated JSON alongside the change that earned it — `git blame` is the audit trail.

**Sanitizers.** `--full` Phase 6 dispatches `.github/workflows/sanitizer-tests.yml` on the `yuzu-wsl2-linux` self-hosted runner via `scripts/test/dispatch-runner-job.sh`. Local runs would pin the dev box for ~15 min per sanitizer rebuild; the runner absorbs that cost in the background. Runner offline → WARN, not FAIL, with operator retry instructions in the gate notes.

## Instruction Engine

The content plane. YAML-defined `InstructionDefinition` → `InstructionSet` → `ProductPack` with typed parameter and result schemas, executed via the `CommandRequest` wire protocol. DSL: `apiVersion: yuzu.io/v1alpha1`, six `kind` values (`InstructionDefinition`, `InstructionSet`, `PolicyFragment`, `Policy`, `TriggerTemplate`, `ProductPack`). Definitions are persisted with verbatim `yaml_source` as the source of truth plus denormalized columns for queries.

- Architecture: `docs/Instruction-Engine.md`
- DSL spec: `docs/yaml-dsl-spec.md`
- Beginner tutorial: `docs/getting-started.md`

### Executions-history ladder — `command_id → execution_id` mapping invariant (PR 2+)

`responses.execution_id` is populated at write time by an in-memory
`cmd_execution_ids_` map inside `AgentServiceImpl` (under `cmd_times_mu_`).
The mapping is registered at dispatch time INSIDE `cmd_dispatch` BEFORE any
RPC is sent — closes the FAST-agent race where a sub-millisecond loopback
agent could reply before a post-dispatch registration. The `CommandDispatchFn`
typedef carries `execution_id` as its sixth parameter; pass empty to opt out
(out-of-band dispatch / no-tracker callers).

**Known coverage gap (every PR in this ladder must check this).** Only
`/api/instructions/:id/execute` (`workflow_routes.cpp`) creates an execution
row AND threads `execution_id` into `cmd_dispatch`. The following dispatch
surfaces produce `execution_id=''` responses, falling back to the legacy
timestamp-window join in the executions detail drawer:

- Workflow-step dispatch (`/api/workflows/:id/execute` step `cmd_dispatch`
  callback at `workflow_routes.cpp` line ~925)
- MCP `execute_instruction` (`mcp_server.cpp`)
- Schedule / approval-triggered dispatch
- Rerun (`/api/executions/:id/rerun` via `create_rerun` — does not currently
  dispatch a command, so the gap is structural, not a wiring bug)

Closing each gap is the scope of PR 2.x follow-ups. **When adding any new
dispatch path that creates an execution row, it MUST thread `execution_id`
into `cmd_dispatch`** — failure produces silent empty-string tagging with
no error or warning.

**Multi-agent fan-out invariant.** A single `command_id` is dispatched to N
agents; each agent sends its own response with the same `command_id`.
Terminal-status branches in `agent_service_impl.cpp` do NOT erase
`cmd_execution_ids_` — erasing on the first agent's terminal would leave
agents 2..N stamping empty `execution_id`. Map entries persist for process
lifetime; a periodic sweeper is filed as PR 2.x. The accepted bounded leak
matches the existing `cmd_send_times_` / `cmd_first_seen_` shape under the
same `cmd_times_mu_`.

**Server restart caveat.** The mapping is in-memory; restart loses it.
In-flight commands at restart time produce responses tagged `execution_id=''`
that use the legacy fallback in the drawer.

**Partial-index planner contract.** `idx_resp_execution_ts ON
responses(execution_id, timestamp) WHERE execution_id != ''` requires the
WHERE clause to syntactically subsume the partial-index predicate. Every
query against this index must include `AND execution_id != ''` redundantly,
or SQLite falls back to a full table scan. See `query_by_execution`'s SQL
in `response_store.cpp` for the canonical form.

### Executions-history ladder — PR 3 SSE live updates

`ExecutionEventBus` (`server/core/src/execution_event_bus.{hpp,cpp}`) is
the per-execution SSE bus that backs `GET /sse/executions/{id}`. Owned by
`ServerImpl`, declared BEFORE `execution_tracker_` in the member list so
the bus outlives the tracker (the tracker borrows the bus pointer via
`set_event_bus`). On the explicit shutdown path the order is also tracker
first, then bus.

**Publisher invariant.** Three `ExecutionTracker` mutators publish onto
the bus when set:
- `update_agent_status` → `agent-transition` (one event per agent
  state change; payload is the `AgentExecStatus` JSON).
- `refresh_counts` → `execution-progress` (counts snapshot) AND, when the
  recompute crosses the all-agents-responded threshold, a terminal
  `execution-completed` (status=succeeded|completed). The progress event
  precedes the terminal event so an SSE client receives counts then
  status.
- `mark_cancelled` → terminal `execution-completed` (status=cancelled).

**Bounded ring buffer.** Per execution: `kBufferCap=1000` events FIFO,
~30 s window in practice. Replay walks events with `id > Last-Event-ID`
on reconnect. Channels marked terminal are GC'd by
`gc_terminal_channels` once `kRetentionAfterTerminalSec=60` elapses AND
no live subscribers remain. GC runs opportunistically from `publish` so
no separate timer thread is required.

**Client-side bootstrap is data-attribute-driven.** The list-row markup
carries `data-execution-id` and `data-execution-status`; the drawer's
KPI strip carries `id="exec-kpi-{id}"`; per-agent table rows carry
`id="per-agent-row-{exec_id}-{agent_id}"`; per-agent status badges carry
`.per-agent-status` and `.per-agent-exit-code` classes. **Every PR that
touches drawer markup MUST keep these stamps stable** — they are the
client SSE listener's binding contract. Renaming any of them is a
silent regression: the listener falls back to no-op and the drawer
freezes mid-execution with no error.

**Audit policy.** `execution.live_subscribe` audits on first connect per
session-per-execution (deduped). SSE auto-reconnect inside the dedup
window does NOT re-audit. The forensic-grade audit on read remains on
`/fragments/executions/{id}/detail`'s `execution.detail.view`.

**Hard predecessor for PR 3.** PR 2.5 (#670) replaced the 16-arg
`WorkflowRoutes::register_routes` with a `WorkflowRoutes::Deps` struct.
**Do not regress that signature** — adding new dependencies to the
workflow routes goes through the struct, not new positional arguments.

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

The CI overhaul (April 2026) split work into three tiers. Plan: `/home/dornbrn/.claude/plans/our-ci-has-been-piped-castle.md`. The `build-ci` agent owns the matrix; `cross-platform` owns Windows/macOS specifics.

**Tier 1 — PR fast-path** (`ci.yml` on `pull_request`): one Linux variant (gcc-13 debug on `yuzu-wsl2-linux`), one Windows variant (MSVC debug on `yuzu-local-windows`), one macOS variant (appleclang debug on GHA-hosted `macos-15`), plus `proto-compat`. Wall target: <10 min per leg.

**Tier 2 — push to dev/main** (`ci.yml` on push to those branches): full 4-way Linux matrix (gcc-13 / clang-19 × debug / release), 2-way Windows, 2-way macOS. **No sanitizers, no coverage** — those moved out (#410 closed as not-planned).

**Tier 3 — nightly cron** (`nightly.yml`, `0 6 * * *` UTC + `workflow_dispatch`): ASan+UBSan, TSan, coverage, all on the self-hosted Linux runner. On any leg failure, the `alert` job auto-opens or comments on a `nightly-broken` issue. **Discipline norm: no merge to main while a `nightly-broken` issue is open.** That's the lever — sanitizers don't gate every PR; nightly catches regressions and gates main.

`workflow_dispatch` only works once a workflow file exists on the **default branch (`main`)**. Cron schedules likewise. New workflows added on `dev` are dormant until merged.

### Self-hosted runner topology

One runner process per OS, single source of throughput:

| Runner | Host | Jobs |
|---|---|---|
| `yuzu-wsl2-linux` | Shulgi 5950X WSL2 Ubuntu 24.04 | proto-compat, linux matrix, nightly (asan/tsan/coverage), cache-prune-linux |
| `yuzu-local-windows` | Shulgi native Windows 11 | windows matrix, cache-prune-windows |
| `macos-15` | GitHub-hosted | macos matrix |

Inventory declared in `.github/runner-inventory.json`. The sentinel at `runner-inventory-sentinel.yml` (every 30 min) compares actual to expected and opens a `runner-inventory-drift` issue on mismatch. Both the sentinel and the new ci.yml `preflight` job share `scripts/ci/runner-health-check.py` (`--mode sentinel` vs `--mode preflight`). Preflight gates downstream self-hosted jobs with explicit `if: needs.preflight.outputs.<runner>_healthy == 'true'` — fail-closed: a degraded runner skips its jobs in <30 s rather than queueing 30 min into a stalled runner. Requires the `RUNNER_INVENTORY_TOKEN` PAT secret (fine-grained, Administration:read on Tr3kkR/Yuzu); without it preflight returns false and self-hosted jobs are skipped with a clear reason.

### Universal vcpkg cache-key contract

`scripts/ci/vcpkg-triplet-sentinel.sh` is the single source of truth for "have the inputs to vcpkg actually changed?". Key:

```
sha256(vcpkg.json + vcpkg-configuration.json + triplets/<triplet>.cmake + $VCPKG_COMMIT)
```

Stored at `vcpkg_installed/.<triplet>-cachekey.sha256`. On drift, wipes ONLY `vcpkg_installed/<triplet>/` — never `vcpkg/`, never `runner.tool_cache`, never ccache. Persistence: self-hosted in `${runner.tool_cache}/yuzu-vcpkg-binary-cache-{linux,asan,windows}` (per-triplet, outside workspace). macOS uses `actions/cache@v5` keyed on the same invariant.

The script must run cleanly under MSYS2 bash on Windows. **Do NOT use `set -e` + `[[ test ]] && cmd` short-circuits** — they silently exit under MSYS2 (cost us run #25051196135). Use `if/fi` blocks and explicit per-command error checks.

### Persistence + recovery

Self-hosted checkouts use `clean: false`. Pre-checkout wipes `build-<os>/` ONLY on branch change; vcpkg state is invalidated by the sentinel above. `meson setup --reconfigure` when `meson-info/` exists. Manual recovery: `bash scripts/ci/runner-reset.sh` (`git clean -fdx -e vcpkg/ -e vcpkg_installed/ -e build-*/`) — **the only sanctioned in-repo nuke path**; never `rm -rf` runner caches (memory `feedback_vcpkg_cache.md`).

### Per-OS build directory names

Matrix: `build-{linux,windows,macos}`. Nightly variants: `build-linux-{asan,tsan,coverage}`. sanitizer-tests.yml + release.yml + pre-release.yml follow the same convention so the warm asan binary cache is shared. Closes #406.

### Workflow-PR canary

`ci.yml`'s `detect-ci-changes` + `canary` jobs run only when a PR touches `.github/workflows/`, `.github/actions/`, or `scripts/ci/`. Canary mirrors the linux build on a fresh-disk GHA-hosted `ubuntu-24.04` with `actions/cache` for vcpkg — catches workflow regressions before main.

### Cache pruning

`cache-prune.yml` runs weekly (Sun 04:00 UTC) on each self-hosted runner. Deletes `${RUNNER_TOOL_CACHE}/yuzu-vcpkg-binary-cache-*/<file>` >30 days old. Does not touch ccache (own LRU at `CCACHE_MAXSIZE=30G`).

### vcpkg state corruption — recovery path

If a Windows CI run repeatedly fails at `Install vcpkg packages` with a missing `.pc` file under `vcpkg_installed/x64-windows/lib/pkgconfig/`, the corruption is in `vcpkg/packages/` (which the cache-key sentinel does NOT reach). Recovery procedure + full corruption-path inventory: `docs/ci-troubleshooting.md` §7. Don't leave the recovery step in `ci.yml` after an incident — it defeats the cache.

## Release workflow gates

The `release:` job in `.github/workflows/release.yml` runs `scripts/check-compose-versions.sh` as its **first step**, before any artifact download. The script walks an explicit list of tracked compose files and rejects any `ghcr.io/<owner>/yuzu-{server,gateway,agent}:X.Y.Z` reference that is (a) a bare numeric tag rather than `${YUZU_VERSION:-...}`, or (b) a parameterised default that does not equal the tag being released (`${GITHUB_REF_NAME#v}`). Floating tags (`latest`, `local`, sha-pinned) are ignored.

**Before tagging a release**, bump the `${YUZU_VERSION:-X.Y.Z}` default in every tracked compose file to the new version and verify locally:

```bash
bash scripts/check-compose-versions.sh 0.10.0
```

The release job will otherwise fail after all build matrix jobs have run, wasting ~30–60 min of runner time without publishing anything. When adding a new compose file to the repo, also add it to the `FILES` array at the top of `scripts/check-compose-versions.sh` — auto-discovery is deliberately off so opt-in is explicit.

## Routed concerns (read the doc, not this file)

| Concern | Doc | Loaded by |
|---|---|---|
| Authentication, RBAC, headers, tokens, self-target principal-destruction guard (#397/#403) | `docs/auth-architecture.md` | `security-guardian` on auth/RBAC/crypto/header/token change |
| MCP server architecture, tier-before-RBAC ordering, kill switches, audit pattern | `docs/mcp-server.md` | `security-guardian` on `/mcp/v1/`, `mcp_server.{hpp,cpp}`, `mcp_jsonrpc.hpp`, `mcp_policy.hpp` change |
| C++23 conventions, naming, headers, plugin ABI boundary | `docs/cpp-conventions.md` | `cpp-expert` on any C++ source change |
| macOS workflow + Darwin pitfalls table | `docs/darwin-compat.md` | `cross-platform` on any macOS-affecting change |
| Prometheus metrics, label set, audit envelope, event format | `docs/observability-conventions.md` | `sre` and `architect` on any metrics/audit/event change |
| Response data types, audit envelope, inventory data for analytics | `docs/data-architecture.md` | `architect` and `sre` when designing schemas |
| User manual / YAML defs / REST API / Substrate primitive registration | docs-writer agent (`.claude/agents/docs-writer.md`) | docs-writer on every change as part of governance gate 2 |
| Guardian / Guaranteed State — real-time agent-side policy enforcement, guard categories, YAML DSL, `__guard__` wire protocol, server store, approval workflow, quarantine | `docs/yuzu-guardian-design-v1.1.md` + delivery plan `docs/yuzu-guardian-windows-implementation-plan.md` | `security-guardian` + `docs-writer` on any `guaranteed_state*`, `guard_engine*`, `guard_*.{hpp,cpp}`, or `__guard__` change |
| TAR dashboard — three frames (retention-paused sources, scope-walking SQL, process tree viewer), URL structure, permissions | `docs/tar-dashboard.md` | `architect` on `/tar` or `/fragments/tar/...` change; `plugin-developer` on TAR action surface; `docs-writer` on dashboard nav |
| Scope walking — composable scope from previous query results (Yuzu's product differentiator). Result-set primitive, `result_sets.db`, `from_result_set:<id>` Scope kind, REST/DSL surface, lineage, audit chain | `docs/scope-walking-design.md` | `architect` + `dsl-engineer` on scope-engine/DSL/result-set change; `consistency-auditor` on audit chain; `security-guardian` on cross-operator authz |

## Guardian engine — stores and architectural notes

The Guardian rollout is Windows-first per the delivery plan. Server-side state lives in one new SQLite file opened at startup next to `policy_store_`:

- **`guaranteed-state.db`** (PR 1) — `GuaranteedStateStore` with `guaranteed_state_rules` + `guaranteed_state_events`. Rule yaml_source is authoritative; denormalised columns (severity, os_target, scope_expr) are indexes. Events are an immutable audit-style log (no FK cascade on rule delete; historical events persist for forensic review — matches `audit_store` retention discipline). Proto lives at `proto/yuzu/guardian/v1/guaranteed_state.proto` (package `yuzu.guardian.v1` — deliberately separate from `yuzu.agent.v1` so Guardian wire contracts evolve independently). Full schema + design: `docs/yuzu-guardian-design-v1.1.md` §9.1.

Agent-side Guardian PR 2 shipped in `agents/core/src/guardian_engine.{hpp,cpp}`. Two-phase startup (`start_local()` pre-network, `sync_with_server()` post-Register), KV namespace `__guardian__`, reserved plugin name `__guard__` intercepted in `agent.cpp` before the plugin match loop. Actions: `push_rules`, `get_status`. Every rule reports `errored` until PR 3 lands the Registry Guard. The `guard_*.{hpp,cpp}` files remain PR 3+ (guard implementations per guard_category / guard_type). See `docs/yuzu-guardian-windows-implementation-plan.md` for the PR ladder.

### Guardian invariants that keep reappearing in governance

- **RBAC `Push` seed is Guardian-only.** `rbac_store.cpp` has TWO operation arrays: `ops[]` (the full catalogue, 6 entries including `Push`) and `crud_ops[]` (the 5 ops cross-seeded to every securable type in the Administrator + ITServiceOwner role loops). `Push` is deliberately absent from `crud_ops[]` and is granted explicitly per role on `GuaranteedState` alone. **Do not add `Push` to `crud_ops[]` or cross-seed it** — every role gaining `*:Push` silently grants a privilege that any future handler consulting `perm_fn(..., "Push")` on a non-Guardian securable would accept. This is the H-4 invariant from Guardian PR 2 hardening round 2; see issue #485 for the upgrade-path migration that removes stale cross-type grants on deployments that ran pre-H-4 code.
- **Reserved plugin name `__guard__` is intercepted before the plugin match loop.** Load-time rejection lives in `plugin_loader.cpp` (PR #453); dispatch-time intercept lives in `agent.cpp` in front of the plugin scan (PR 2). Both halves must stay — the load-time check is the primary defence, the dispatch-time intercept is defence-in-depth. See #477 for the known `dlopen`-before-name-check gap that the load-time check inherits.
- **Guardian wire payloads in `CommandRequest.parameters` are not gateway-safe.** Any field that carries raw proto bytes (serialised `GuaranteedStatePush`, binary signatures, etc.) must NOT be placed in a `map<string, string>` that the gateway will re-encode via `gpb:e_type_string`. The Erlang gateway runs `unicode:characters_to_binary/1` which rejects invalid UTF-8 varints — the crash surface lands the moment Guardian PR 3 wires fan-out. See #478 for the schema/wire fix.

## Test conventions — shared helpers

For any test that creates a temp file or SQLite database, use `yuzu::test::unique_temp_path(prefix)` or `yuzu::test::TempDbFile` from `tests/unit/test_helpers.hpp`. The helper uses a process-local `mt19937_64`-seeded salt plus an atomic monotonic counter — **never** use `std::hash<std::thread::id>` or `std::chrono::steady_clock` as a uniqueness salt. That pattern produces silent collisions under Defender-induced I/O serialisation on the `yuzu-local-windows` runner (flake #473). The shared header was introduced in Guardian PR 2 hardening round 2 (H-8); see #482 for the residual adoption work across 5 test files.

## CLAUDE.md updates

Architectural decisions, new stores, new plugin patterns, churning subsystems, and cross-cutting concerns belong here so future Claude sessions read them before touching code. Stable reference material that an agent already loads belongs in `docs/` with a one-line pointer here. See memory `feedback_claude_md_scope.md` for the heuristic — Build / Release / Erlang stay resident because the work is unstable or foreign; mature areas can be split out.
