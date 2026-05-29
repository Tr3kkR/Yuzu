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

Pipeline (8 gates, convention-enforced — no git hook): Change Summary with Resource Ledger for C++ resource changes → security-guardian + docs-writer mandatory deep-dive → domain-triggered review (including `cpp-expert` and `cpp-safety` for any C++ source change, plus `cpp-safety` for raw resource/process/cast triggers) → happy-path + unhappy-path + consistency-auditor (parallel) → chaos-injector (skipped if no findings) → compliance-officer + sre + enterprise-readiness (parallel) → findings addressed (CRITICAL/HIGH block merge) → iterate.

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

A cross-platform UAT script at `scripts/start-UAT.sh` (Linux + macOS) stands up the full stack, verifies connectivity, and runs command round-trip tests. The historical `scripts/linux-start-UAT.sh` name is kept as a thin shim that execs the canonical script. Usage:

```bash
bash scripts/start-UAT.sh          # start + verify (6 automated tests)
bash scripts/start-UAT.sh stop     # kill all
bash scripts/start-UAT.sh status   # show running processes
```

### viz-UAT (container-based, feat/viz-engine ladder)

`scripts/start-viz-uat.sh` stands up a three-container Docker stack (server + gateway + agent) for the visualization feature ladder. **Cannot run alongside `start-UAT.sh`** — both bind host ports 8080 *and* 50051. Auto-detects arm64 vs amd64 and sets `--build-arg TRIPLET` accordingly; default `x64-linux` preserves the `release.yml` path. The launcher exports `VIZ_UAT_CONFIG` (absolute path to a generated `yuzu-server.cfg`); do not invoke `docker compose -f docker-compose.viz-uat.yml up` directly. State dir `/tmp/yuzu-viz-uat/`; scale agents with `VIZ_UAT_AGENTS=N`. Set `VIZ_UAT_AGENT_MODE=vm` to skip the in-container agent and print the enrollment token + host-exposed gateway address for running a native `yuzu-agent` on an OrbStack VM / bare-metal host — needed for PR 8+ visuals that depend on real loopback workloads. `VIZ_UAT_AGENT_MODE=none` skips agent startup entirely. **Note:** `scripts/start-UAT.sh` (the native, non-container UAT) force-wipes `/tmp/yuzu-uat/` on each start to work around a stale-DB session-auth bug (#947); do not remove that wipe without first closing the issue. See `bash scripts/start-viz-uat.sh --help` for full usage.

### Cedar & Vale demo environment (release-pinned, sales)

`scripts/start-demo.sh` stands up a three-tier **chiselled** Docker stack (server + gateway + N agent replicas) from release-pinned GHCR images. **Cannot run alongside `start-viz-uat.sh` or `start-UAT.sh`** — all three bind host ports 8080 and 50051 (the launcher pre-checks and refuses to start if they are busy). Clean-start by default (wipes `/tmp/yuzu-demo/` + compose volumes); `--keep` preserves state. Distinct from the viz-UAT rig. The **agent-bundle** delivery image (`docs/agent-bundle.md`, `scripts/build-agent-bundle.sh`) ships the agent for `linux-x64` / `windows-x64` / `macos-arm64` to design partners who can only `docker pull` — published + cosign-signed + SBOM'd by the `docker-publish-agent-bundle` release job. Full runbook: `docs/demo-environment.md`.

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
2. **`--gateway-mode`** — Subscribe stream peer-mismatch validation accepts the agent's Register peer IP (default rule) **OR** an IP previously recorded in the trusted-gateway peer set via `GatewayUpstreamServiceImpl::ProxyRegister` (W1.3 / #826). Entries are noted only on a successful enrollment branch and expire after 1h (LRU-capped at 1024 entries). Without `--gateway-mode` the trusted-set lookup is skipped — direct-connect agents only ever match their Register peer. Layered defence note: this rule scopes Subscribe to known gateway IPs but does NOT defend against a sniffed `session_id` presented from inside the gateway's IP space; the agent_id↔session binding from W1.4 (#827) is the layer that closes that.
3. **`--gateway-command-addr localhost:50063`** — Points the server at the gateway's `ManagementService` for command forwarding. Without this, commands to gateway-connected agents are queued in `gw_pending_` but never forwarded. The server calls `SendCommand` (server-streaming RPC) on this address; the gateway fans out to agents and streams responses back.

`--trusted-nat-cidr <cidr>[,…]` (`Config::trusted_nat_cidrs`, #1128) is the direct-connect analogue of `--gateway-mode`'s trusted-IP relaxation: when a direct agent's Register and Subscribe source IPs both fall inside one declared CIDR (multi-egress NAT / proxy pool / CG-NAT / SD-WAN), the per-session peer-IP mismatch is downgraded to *advisory* (audit `result="ok" outcome=advisory` + `yuzu_grpc_subscribe_peer_advisory_total`) instead of rejected. mTLS-identity match does the same downgrade but is **opt-in** via `--nat-trust-mtls-identity` (`Config::nat_trust_mtls_identity`, default off) — it is a session-replay bypass under a shared fleet-wide client cert, so it requires the operator to affirm per-agent certs (gov UP-2). Strict exact-match stays the default; mismatches outside both accommodations still reject; an empty extracted IP always rejects (#826). The pure decision is `AgentServiceImpl::evaluate_peer_binding`; gateway origin-IP attribution rides `RegisterRequest.gateway_observed_peer` (#1064, server-side consumed; gateway population is a follow-up — grpcbox can't see the direct transport peer, QUIC #376 will). See `docs/auth-architecture.md` "Per-session peer binding and NAT-aware relaxation".

The dispatch flow in `agent_registry.cpp` `send_to()`:
- Agent has a local Subscribe stream → write directly (direct-connect agents)
- Agent has a `gateway_node` but no local stream → queue to `gw_pending_` for gateway forwarding
- `forward_gateway_pending()` drains the queue via `gw_mgmt_stub_->SendCommand()`

The gateway uses port range 5006x (vs server's 5005x); `gateway/config/sys.config` and `grpcbox` `listen_opts` are configured independently and must match. UAT credentials: fresh `yuzu-server.cfg` with PBKDF2-SHA256 hashed `admin` / `adminpassword1` per run; state lives under `/tmp/yuzu-uat/` and is wiped on each start.

## Pre-commit testing with /test

The `/test` skill (`.claude/skills/test/SKILL.md`) is the single-command pre-commit/pre-push gate — compiles HEAD, upgrades from the previous release image, runs the standard test surface, persists every gate result and sub-step timing to a SQLite test-runs DB at `~/.local/share/yuzu/test-runs.db` (XDG dir, survives `git clean`; override with `YUZU_TEST_DB=path`). Three modes: `--quick` (~10 min sanity), default (~30–45 min), `--full` (~60–120 min — adds OTA, dispatched sanitizers, coverage enforcement, perf measure-and-report). Query history via `bash scripts/test/test-db-query.sh --latest|--last N|--diff A B|--trend ...|--flaky`. Coverage baseline (`tests/coverage-baseline.json`) and perf calibration (`docs/perf-baseline-calibration-2026-05-03.md`) details live in the skill — perf is measure-only as of 2026-05-03 (no σ band, ceiling-bounded distributions).

## Instruction Engine

The content plane. YAML-defined `InstructionDefinition` → `InstructionSet` → `ProductPack` with typed parameter and result schemas, executed via the `CommandRequest` wire protocol. DSL: `apiVersion: yuzu.io/v1alpha1`, six `kind` values (`InstructionDefinition`, `InstructionSet`, `PolicyFragment`, `Policy`, `TriggerTemplate`, `ProductPack`). Definitions are persisted with verbatim `yaml_source` as the source of truth plus denormalized columns for queries.

- Architecture: `docs/Instruction-Engine.md`
- DSL spec: `docs/yaml-dsl-spec.md`
- Beginner tutorial: `docs/getting-started.md`

### Shipped content is build-time embedded — there is no filesystem load path

`content/definitions/*.yaml` and `content/packs/*.yaml` are converted to JSON envelopes by `server/core/scripts/embed_content.py` at build time, written into `bundled_content.cpp` as the `kBundledDefinitions` / `kBundledSets` vectors, linked into `yuzu-server`, and seeded into `instructions.db` on first boot via `import_definition_json` (conflict-skip on subsequent boots so operator REST/dashboard edits win). The runtime never reads YAML from disk — there is no `--content-dir` flag and none of the install packages ship the YAMLs separately. This is identical on Linux, macOS, and Windows.

**PyYAML is a hard build dependency.** `meson setup` probes `python -c "import yaml"` and fails the configure step if it's missing; `embed_content.py` itself fails the build (non-zero exit) on missing PyYAML, missing `content/` directory, missing required fields in any `InstructionDefinition`, or zero parsed defs. The historical "warn and emit empty bundle" fallback (which silently produced binaries with empty Instructions tabs) was removed. Provision PyYAML with `pip install pyyaml` (Linux/macOS) or `pacman -S python-yaml` (MSYS2).

### Executions-history ladder

PR 2 (`responses.execution_id` correlation) and PR 3 (SSE live updates) ship
a stack of invariants every successor PR must check — `cmd_execution_ids_`
race-free dispatch registration, the `execution_id=''` coverage-gap list,
multi-agent fan-out non-erase rule, partial-index `WHERE execution_id != ''`
planner contract, `ExecutionEventBus` lifetime ordering, the data-attribute
binding contract on drawer markup, and the `WorkflowRoutes::Deps` struct that
PR 2.5 (#670) made the **hard predecessor** for any new dispatch surface.
Full reference: `docs/executions-history-ladder.md`.

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
| C++23 conventions, naming, headers, plugin ABI boundary | `docs/cpp-conventions.md` | `cpp-expert` on any C++ source change |
| C++ resource ownership and lifetime — fd/HANDLE/SOCKET/`FILE*`/SQLite/OpenSSL/BCrypt/C-string/thread/callback/temp-path ownership, RAII/scope guards, `string_view`/`span` validity, casts, syscall/process boundaries, sanitizer coverage | `docs/cpp-conventions.md` | `cpp-safety` on any C++ source change; `security-guardian` also enforces the ownership proof during Gate 2 |
| macOS workflow + Darwin pitfalls table | `docs/darwin-compat.md` | `cross-platform` on any macOS-affecting change |
| Prometheus metrics, label set, audit envelope, event format | `docs/observability-conventions.md` | `sre` and `architect` on any metrics/audit/event change |
| Response data types, audit envelope, inventory data for analytics | `docs/data-architecture.md` | `architect` and `sre` when designing schemas |
| User manual / YAML defs / REST API / Substrate primitive registration | docs-writer agent (`.claude/agents/docs-writer.md`) | docs-writer on every change as part of governance gate 2 |
| Guardian / Guaranteed State — real-time agent-side policy enforcement, guard categories, YAML DSL, `__guard__` wire protocol, server store, approval workflow, quarantine, **standing invariants §24** | `docs/yuzu-guardian-design-v1.1.md` + delivery plan `docs/yuzu-guardian-windows-implementation-plan.md` | `security-guardian` + `docs-writer` on any `guaranteed_state*`, `guard_engine*`, `guard_*.{hpp,cpp}`, or `__guard__` change |
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

`guaranteed-state.db` (PR 1) holds `GuaranteedStateStore` with rules + events
tables; rule `yaml_source` is authoritative, denormalised columns are
indexes; events are an immutable audit-style log. Proto lives at
`proto/yuzu/guardian/v1/guaranteed_state.proto` (package `yuzu.guardian.v1` —
separate from `yuzu.agent.v1` so wire contracts evolve independently).
Agent-side `guardian_engine.{hpp,cpp}` (PR 2) does two-phase startup
(`start_local()` pre-network, `sync_with_server()` post-Register), KV
namespace `__guardian__`, reserved plugin name `__guard__` intercepted in
`agent.cpp` before the plugin match loop. Schema: `docs/yuzu-guardian-design-v1.1.md`
§9.1; standing invariants (`Push`-seed scope, `__guard__` defence-in-depth,
gateway-safe wire payloads): same doc §24; PR ladder:
`docs/yuzu-guardian-windows-implementation-plan.md`.

## Test conventions — shared helpers

Use `yuzu::test::unique_temp_path(prefix)` / `yuzu::test::TempDbFile` from `tests/unit/test_helpers.hpp` for any test temp file or SQLite DB. **Never** salt uniqueness with `std::hash<std::thread::id>` or `std::chrono::steady_clock` — silent collisions under Defender-induced I/O serialisation on `yuzu-local-windows` (flake #473). Rationale and residual adoption: header comment + #482.

For server tests that need a live `ExecutionTracker` wired into `AgentServiceImpl`, use the `TrackerScope` RAII helper in `tests/unit/server/test_agent_service_impl.cpp` — it opens a `:memory:` SQLite DB, constructs the tracker, calls `set_execution_tracker`, and nulls the borrowed pointer before the tracker destructs (matches the production shutdown contract at `agent_service_impl.hpp:113`). Pattern: `GatewayResponseHarness h; TrackerScope ts{h.svc}; auto exec_id = ts.make_exec();`. The `:memory:` choice deliberately sidesteps the `unique_temp_path` race for shutdown-ordered tests; promote to `test_helpers.hpp` once a second test file needs the pattern (tracked via the H-9 follow-up issue from PR #1068 governance).

## Agent skills

Per-repo configuration for the Matt Pocock engineering skills (`to-issues`, `triage`, `to-prd`, `qa`, `improve-codebase-architecture`, `diagnose`, `tdd`, `zoom-out`, `grill-with-docs`). Re-run `/setup-matt-pocock-skills` to change.

### Plugin scope — `frontend-design` is marketing-only

The `frontend-design` plugin (`frontend-design@claude-plugins-official`) is scoped to **marketing / sales / demo presentation surfaces only**. Its design ethos — bold, deliberately-varied aesthetics that "vary between light and dark themes" — is right for a standalone pitch surface and wrong for the product, which prizes consistency and is **dark-theme-only**.

- **Use it on:** the Cedar & Vale sales deck at `deploy/docker/cedar-vale/app/` (standalone Node app — `deck.css`, `machine.js`, slide assets) and any future standalone marketing/landing page. These are presentation apps, not the product.
- **Do NOT use it on:** the operator dashboard or any product UI — `server/core/src/*_ui.cpp`, `server/core/static/*`. This explicitly includes the **in-product fleet visualization** (`viz_page_ui.cpp`, `viz_host_page_ui.cpp`, `server/core/static/yuzu-viz*.js`, governed by `docs/fleet-viz-invariants.md`) — despite the name, it is product, not marketing. Product UI stays HTMX-first, server-rendered, dark-theme-only; follow the existing dashboard conventions, never `frontend-design`.

### Issue tracker

GitHub issues at `github.com/Tr3kkR/Yuzu` via the `gh` CLI. See `docs/agents/issue-tracker.md`.

### Triage labels

Canonical defaults (`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`); only `wontfix` exists in the repo's label set today. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context layout — `CONTEXT.md` at the repo root, ADRs under `docs/adr/`. See `docs/agents/domain.md`.

## CLAUDE.md updates

Architectural decisions, new stores, new plugin patterns, churning subsystems, and cross-cutting concerns belong here so future Claude sessions read them before touching code. Stable reference material that an agent already loads belongs in `docs/` with a one-line pointer here. See memory `feedback_claude_md_scope.md` for the heuristic — Build / Release / Erlang stay resident because the work is unstable or foreign; mature areas can be split out.
