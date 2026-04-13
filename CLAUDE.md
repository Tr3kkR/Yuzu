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
| unhappy-path | Unhappy Path Reviewer | Failure-mode interrogation, risk register feeding chaos-injector |
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
| compliance-officer | Compliance Officer | SOC 2 control alignment, evidence generation, change traceability, audit readiness |
| sre | Site Reliability Engineer | SLOs, observability, backup/recovery, capacity planning, hardened deployment |
| enterprise-readiness | Enterprise Readiness | Customer assurance package, security questionnaires, deployment experience, pilot readiness |

**Workflow:** architect first (design) → feature agents (implement) → erlang-dev (review Erlang code) → cross-platform (compile) → security-guardian (review) → happy-path + unhappy-path + consistency-auditor (parallel analysis) → chaos-injector (failure scenarios) → quality-engineer (test) → docs-writer (document) → compliance-officer + sre + enterprise-readiness (parallel operational review) → build-ci (CI green) → performance (if data-plane) → release-deploy (if packaging).

**DSL touchpoints:** dsl-engineer is invoked as a feature agent for scope targeting, policy conditions (CEL), trigger template expressions, parameter binding, workflow primitives, and any YAML DSL spec evolution.

**Correctness & resilience touchpoints:** happy-path, unhappy-path, and consistency-auditor are invoked for all changes during full governance. consistency-auditor is additionally invoked when changes touch protobuf schemas, database schemas, API contracts, or cross-component state. chaos-injector runs after all three complete, synthesizing risks into executable failure scenarios. Gate 5 (chaos analysis) is skipped if neither unhappy-path nor consistency-auditor produce findings. Gate 4 agents run in parallel — this is a deliberate speed/completeness tradeoff; compound findings that span failure-mode and consistency domains are synthesized by chaos-injector in gate 5. The governance orchestrator should pass prior gate findings as context to gate 4 agents to avoid duplicated effort.

### Governance

**Better process makes better products.** Every code change follows mandatory governance gates — no shortcuts, no exceptions:

1. **Change Summary** — the producing agent writes a structured summary (files, what, why, interfaces affected, security surface, user-facing impact) shared with ALL agents.
2. **Mandatory deep-dive** — security-guardian and docs-writer read every modified file for every change. Security reviews block on CRITICAL/HIGH findings. Documentation blocks if user-facing changes lack doc updates.
3. **Domain-triggered review** — architect, quality-engineer, cross-platform, performance, build-ci, dsl-engineer, erlang-dev, gateway-erlang, plugin-developer, and release-deploy review when changes touch their domain.
4. **Correctness & resilience analysis** — happy-path, unhappy-path, and consistency-auditor run in parallel. happy-path validates normal-condition correctness. unhappy-path performs systematic failure-mode interrogation and produces a risk register. consistency-auditor checks cross-component state/schema/contract consistency. All three are mandatory during full governance; consistency-auditor also triggers on schema evolution and protocol changes.
5. **Chaos analysis** — chaos-injector ingests outputs from unhappy-path and consistency-auditor (plus happy-path correctness baseline as optional context) to generate controlled failure scenarios with success criteria and rollback procedures. Runs only after gate 4 completes. Skipped if neither unhappy-path nor consistency-auditor produce findings.
6. **Operational & compliance review** — compliance-officer, sre, and enterprise-readiness run in parallel. compliance-officer verifies SOC 2 control alignment and evidence chain. sre reviews observability, deployment hardening, and recovery posture. enterprise-readiness verifies customer-facing documentation and assurance package consistency. All three are mandatory during full governance.
7. **All findings addressed** before merge — CRITICAL/HIGH are blocking, MEDIUM should be fixed, LOW addressed.
8. **Iterate** — re-review after fixes until the team gives a clean bill. No commit until governance passes.

**Known limitation:** The governance pipeline is convention-enforced, not automated. There are no git hooks or CI checks that verify gate completion. Discipline and peer review are the enforcement mechanism. Future improvement: add governance attestation artifacts or PR checklist requirements.

**Lesson learned:** Waves 1-4 shipped without governance and accumulated 4 CRITICAL command injection vulnerabilities, untested stores, stale docs, and performance bottlenecks. These were caught before production but should have been caught before commit.

## Darwin Compatibility

This Claude instance is the designated **macOS/Darwin compatibility guardian** for Yuzu. When Windows-originated changes land on `origin/dev`, the standing workflow is:

1. `git fetch origin && git status` — confirm branch state.
2. `git pull` — fast-forward to latest dev.
3. `git diff HEAD~N..HEAD --stat` — review what changed.
4. Identify which previous Darwin fixes are still present in the new tree.
5. `meson setup build-macos --reconfigure ...` if `meson.build` changed.
6. `meson compile -C build-macos` — fix any new compile errors.
7. `bash scripts/run-tests.sh all` — fix any new test failures.
8. Commit clean with a Darwin-fix commit message.

### Standing Darwin pitfalls

| Area | Issue |
|---|---|
| Path comparisons | macOS `/var` → `/private/var` symlink: always call `fs::canonical()` on both sides before comparing paths in tests. |
| SQLite concurrency | All stores must open with `sqlite3_open_v2()` using `SQLITE_OPEN_READWRITE \| SQLITE_OPEN_CREATE \| SQLITE_OPEN_FULLMUTEX` flags — never plain `sqlite3_open()`. Application-level mutexes (`shared_mutex`) are retained as defense-in-depth and are **required** (not optional) for stores with cached prepared statements, because FULLMUTEX does not make bind-step-reset sequences atomic. |
| Erlang rebar3 ct | Always pass `--dir apps/yuzu_gw/test` together with `--suite` flags. |
| `curl -f` in tests | Do **not** use `-f` where 4xx is an acceptable response — it causes `|| echo "000"` fallbacks to contaminate the status code variable. |
| `prometheus_httpd` | Use `start/0` with `application:set_env(prometheus, prometheus_http, [{port, P}, {path, "/metrics"}])` — `start/1` does not exist. Call `application:ensure_all_started(prometheus_httpd)` first so `prometheus_http_impl:setup/0` runs before the first scrape. |

After any cross-platform change, always run `bash scripts/run-tests.sh all` on Darwin before committing.

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

The gateway and the meson custom_target that drives `rebar3 compile` both
require `erl` on PATH. WSL2 / Linux dev shells typically rely on
[kerl](https://github.com/kerl/kerl) and need `source $(kerl path <ver>)/activate`
before any build; macOS uses Homebrew or asdf; MSYS2 bash on Windows reads the
native installer (`C:\Program Files\Erlang OTP\bin` on modern installers,
`C:\Program Files\erl-<ver>\bin` on older ones). Forgetting to activate is a
common cause of phantom `.gateway_built` failures from `meson compile` even
though the C++ targets succeed.

**Use the helper.** Before any gateway work — `rebar3`, `meson compile`, or any
script that touches `gateway/` — source the cross-platform helper and verify
`erl` is on PATH:

```bash
source scripts/ensure-erlang.sh           # default: latest 28.x
source scripts/ensure-erlang.sh 28.4.2    # exact pin
command -v erl >/dev/null || { echo "Erlang missing"; exit 1; }
```

The script is a no-op if `erl` is already on PATH **and runs** (it probes with
`erl -version`, so broken symlinks and wrong-arch binaries don't pass the
check). Otherwise it tries, in order:

1. **kerl** — matches the requested version exactly or as a major-version
   prefix (so `28` finds `28.4.2`); falls back to the highest installed `28.x`.
2. **asdf** — uses `asdf which erl` (works on both classic and the 0.16+
   rewrite that dropped `asdf where`).
3. **Homebrew** — *macOS only*, via `brew --prefix erlang`.
4. **MSYS2 Windows installer probe** — *MSYS2 bash on Windows only*, scans
   both `Program Files` locations for the latest installed OTP.

The helper **always returns 0** — a sourced script that returns non-zero would
trip the parent shell's `set -e`. Callers MUST verify `command -v erl`
themselves (see usage above). If no detector succeeds, the helper prints
actionable install instructions to stderr.

The default version argument tracks `.github/workflows/release.yml`'s
`erlef/setup-beam` `otp-version`; bump both together. Native `cmd.exe` /
PowerShell sessions are out of scope — Yuzu's documented Windows build path is
MSYS2 bash (see `setup_msvc_env.sh`, the sibling MSVC activation helper).

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

### Gateway config (`gateway/config/sys.config`)

The gateway uses its own port range (5006x) to avoid conflicts with the server (5005x). Both the `yuzu_gw` app config AND the `grpcbox` `listen_opts` must match (they're configured independently).

### Credential generation

The script generates a fresh `yuzu-server.cfg` with PBKDF2-SHA256 hashed credentials on each run (`admin` / `adminpassword1`). All UAT state lives under `/tmp/yuzu-uat/` and is wiped on each start.

### Known bug: stale DB breaks session auth on restart

If the server is restarted against an existing data directory (stale SQLite databases from a prior run), session authentication breaks: `authenticate()` succeeds (HTTP 200, Set-Cookie returned) but `validate_session()` fails on subsequent requests (HTTP 401). The UAT script works around this by doing `rm -rf /tmp/yuzu-uat` before each run. This bug should be investigated — the in-memory `sessions_` map and the database state may be interacting incorrectly on restart.

## Pre-commit testing with /test

The `/test` skill (`.claude/skills/test/SKILL.md`) is the single-command pre-commit/pre-push gate. It compiles HEAD, stands up the previous released image (`v0.10.0` from `ghcr.io/tr3kkr/yuzu-*`), upgrades it to HEAD, verifies data preservation and migrations, then runs the standard test surface (unit + EUnit + dialyzer + CT + integration + e2e + synthetic UAT + puppeteer). Every gate result and sub-step timing is persisted to a SQLite test-runs DB at `~/.local/share/yuzu/test-runs.db` so operators can compare runs over time, spot flaky gates, and trend upgrade durations.

Three modes:

- `/test --quick` — sanity check (~10 min): build + unit + EUnit + dialyzer + synthetic UAT
- `/test` (default, ~30-45 min): build + upgrade test + standard gates + fresh stack
- `/test --full` (~60-120 min): adds OTA Linux + OTA Windows (PR3), sanitizers (PR2, dispatched to `yuzu-wsl2-linux`), coverage enforce + perf enforce (PR2)

Query historical runs via `bash scripts/test/test-db-query.sh --latest|--last N|--diff A B|--trend timing=phase2.image-swap|--flaky --days 14|--export RUN_ID|--prune 100`. Power users can `python3 scripts/test/test_db.py query ...` directly.

The DB lives outside the repo (XDG data dir) so it persists across `git clean` and survives repo re-clones. Override with `YUZU_TEST_DB=path`.

PR1 lands the skill scaffold + upgrade test path + standard Phase 5 gates. PR2 will land the coverage/perf/sanitizer gates + baselines. PR3 will land the cross-platform OTA self-exec tests + Windows agent build dispatch on `yuzu-local-windows`.

## Instruction Engine

The content plane. YAML-defined `InstructionDefinition` → `InstructionSet` → `ProductPack` with typed parameter and result schemas, executed via the `CommandRequest` wire protocol. DSL: `apiVersion: yuzu.io/v1alpha1`, six `kind` values (`InstructionDefinition`, `InstructionSet`, `PolicyFragment`, `Policy`, `TriggerTemplate`, `ProductPack`). Definitions are persisted with verbatim `yaml_source` as the source of truth plus denormalized columns for queries.

- Architecture: `docs/Instruction-Engine.md`
- DSL spec: `docs/yaml-dsl-spec.md`
- Beginner tutorial: `docs/getting-started.md`

## Enterprise Readiness and SOC 2

The path from feature-complete to enterprise-deployable is scoped in `docs/enterprise-readiness-soc2-first-customer.md` across 7 workstreams (A GRC, B Identity, C AppSec, D Reliability, E Data, F Secure SDLC, G Customer Assurance). Every code change is evaluated against this plan by the compliance-officer, sre, and enterprise-readiness agents during Gate 6 of the governance pipeline.

## Development Roadmap

Roadmap: `docs/roadmap.md`. Capability map: `docs/capability-map.md`. Headline progress figure in the capability map is overstated — treat with skepticism (see memory `project_capability_map_accuracy.md`). When working on an issue, check the roadmap for dependencies and the capability map for target context.

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

The same source tree is built from multiple hosts (WSL2 Linux + native
Windows on the same physical machine, plus a separate macOS dev box). To
keep them from clobbering each other, `scripts/setup.sh` selects a
**per-OS canonical build directory**:

| Host    | Build dir       |
|---------|-----------------|
| Linux   | `build-linux`   |
| Windows | `build-windows` |
| macOS   | `build-macos`   |

Always use `scripts/setup.sh` (which picks the right dir automatically) or
pass `-C build-<os>` explicitly to `meson compile` / `meson test`. If
`scripts/setup.sh` finds an existing dir whose recorded source path looks
like a different host's, it refuses to reconfigure unless `--wipe` is
passed — this prevents the opaque ninja "dyndep is not an input" / Windows-
path failures you get when a Windows-configured `builddir` is reused under
WSL2 (and vice versa). All `build-*/` and legacy `builddir*/` paths are in
`.gitignore`.

`./scripts/setup.sh` no longer auto-wipes an existing build directory —
pass `--wipe` if you actually want to start from scratch, otherwise it
runs `meson setup --reconfigure` and preserves prior compilation state.

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

## CI matrix

Defined in `.github/workflows/ci.yml` — four jobs: linux (ubuntu-24.04, GCC 13 + Clang 18), windows (windows-2022, MSVC VS 17), macos (macos-14 Apple Silicon, Apple Clang), arm64-cross (ubuntu-24.04, aarch64-linux-gnu gcc, tests skipped). vcpkg binary cache is `actions/cache` on `vcpkg/installed`, keyed on `vcpkg.json` + `vcpkg-configuration.json` hash.

## Release workflow gates

The `release:` job in `.github/workflows/release.yml` runs `scripts/check-compose-versions.sh` as its **first step**, before any artifact download. The script walks an explicit list of tracked compose files and rejects any `ghcr.io/<owner>/yuzu-{server,gateway,agent}:X.Y.Z` reference that is (a) a bare numeric tag rather than `${YUZU_VERSION:-...}`, or (b) a parameterised default that does not equal the tag being released (`${GITHUB_REF_NAME#v}`). Floating tags (`latest`, `local`, sha-pinned) are ignored.

**Before tagging a release**, bump the `${YUZU_VERSION:-X.Y.Z}` default in every tracked compose file to the new version and verify locally:

```bash
bash scripts/check-compose-versions.sh 0.10.0
```

The release job will otherwise fail after all build matrix jobs have run, wasting ~30–60 min of runner time without publishing anything. When adding a new compose file to the repo, also add it to the `FILES` array at the top of `scripts/check-compose-versions.sh` — auto-discovery is deliberately off so opt-in is explicit.

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
source ./setup_msvc_env.sh           # MSVC paths
source scripts/ensure-erlang.sh      # Erlang/OTP on PATH (gateway target)
meson compile -C build-windows       # canonical Windows dir; coexists with build-linux from WSL2
```

**IMPORTANT — do NOT use vcvars64.bat.** It returns exit code 1 due to optional extension failures (Clang, bundled CMake, ConnectionManager) even though cl.exe is set up correctly. This causes `.bat` wrapper scripts to abort or misbehave. `setup_msvc_env.sh` sets all MSVC paths directly in MSYS2 bash and is the only supported build method.

`scripts/ensure-erlang.sh` is the sibling helper for the Erlang/OTP toolchain (see "Toolchain activation (Erlang on PATH)" under the Erlang gateway section). Source both before invoking meson if your build touches the gateway custom_target.

### Cross-compilation
```bash
./scripts/setup.sh --cross-file meson/cross/aarch64-linux-gnu.ini
```
Cross files live in `meson/cross/`. Native files for CI compiler selection live in `meson/native/`.

### Windows toolchain requirements

Full path inventory (cl.exe, cmake, ninja, python, meson, vcpkg, protoc, grpc_cpp_plugin) lives in `docs/windows-build.md`. All of it is configured automatically by `setup_msvc_env.sh`. Hard rule: **do not use Clang** (`C:\Program Files\LLVM\bin`) — must use cl.exe / MSVC.

## Authentication & Authorization

Full feature history, OIDC/AD details, tiered agent enrollment, and CSP/security-header construction live in `docs/auth-architecture.md`. Hard invariants that every session must respect:

- **mTLS** for agent ↔ server gRPC is mandatory; there is no plain-gRPC path.
- **HTTPS default** — `https_enabled` defaults to `true`. `--no-https` is dev-only.
- **Secure bind default** — Web UI binds to `127.0.0.1`; overriding to `0.0.0.0` logs a startup warning.
- **Metrics auth** — `/metrics` is localhost-only unauthenticated; remote scrapes require auth unless `--metrics-no-auth` is set for monitoring infra.
- **Private key perms** — server refuses to start if a TLS private key file is group/others-readable on Unix.
- **Error envelope** — all API responses use `{"error":{"code":N,"message":"..."},"meta":{"api_version":"v1"}}`; health probes use `{"status":"..."}`.
- **HTTP security headers** — CSP, HSTS (HTTPS-only), X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy are emitted on every response. Construction lives in `server/core/src/security_headers.{hpp,cpp}`. CSP extensions go through `--csp-extra-sources` which is validated at CLI parse. Never hand-roll header emission elsewhere — route through `HeaderBundle::make()`/`apply()`.
- **Owner-scoped API token revocation (#222)** — `DELETE /api/v1/tokens/{id}` and `DELETE /api/settings/api-tokens/{id}` reject cross-user revoke attempts with 404 unless the caller holds the global `admin` role. Every new token-lifecycle endpoint must follow the same owner-check pattern.

## MCP (Model Context Protocol) Server

Full architecture, tier policy, tool list, and Phase 2 roadmap live in `docs/mcp-server.md`. Load-bearing rules:

- **Embed point:** `POST /mcp/v1/` inside the same httplib server as REST and dashboard. Module lives at `server/core/src/mcp_server.{hpp,cpp}` and mirrors `RestApiV1` — injected store pointers, same callback signatures.
- **Tier check runs BEFORE RBAC.** `mcp_policy.hpp` enforces static allow-lists per tier (`readonly`, `operator`, `supervised`); RBAC is a second gate, not the first. Never skip the tier check.
- **MCP tokens** piggyback on `api_token_store` with the `mcp_tier` column and mandatory expiry (≤90 days). The owner-scoped revocation rules from the Auth section apply.
- **Kill switches:** `--mcp-disable` (rejects all `/mcp/v1/` with `kMcpDisabled`), `--mcp-read-only` (blocks non-read tools). Respect both in every new endpoint.
- **Audit pattern:** every MCP tool call emits `action="mcp.<tool_name>"` and populates the `mcp_tool` field on `AuditEvent`. Don't log MCP traffic through any other path.
- **Output serialization:** use the local `JObj`/`JArr` string builders, not `nlohmann::json` output (56GB template bloat). `nlohmann::json` is OK for parsing only.

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
