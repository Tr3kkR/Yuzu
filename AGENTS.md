# Yuzu — Codex Agent Guide

## What is Yuzu?

Yuzu is an agentic enterprise endpoint management platform — a single control plane where agentic colleagues can query, command, scan, patch, and enforce policy compliance on Windows, Linux, and macOS fleets in real time. An open-source alternative to commercial endpoint management platforms, built from scratch in C++23: gRPC/Protobuf transport, Prometheus-native metrics, **PostgreSQL server-side storage with SQLite embedded on the agent** (ADR-0006 — see the Postgres row in Routed concerns), and a compiler-stable plugin ABI. Architecture reference: `docs/architecture.md`; capability targets: `docs/capability-map.md`.

## Glossary — three meanings of "agent"

The word **agent** is overloaded; the rest of this file relies on these definitions:

- **Agent daemon** — the C++ binary in `agents/core/` that runs on each managed endpoint and executes plugins. The thing the rest of this codebase usually means by "agent".
- **Governance agent** — the `.codex/agents/*.md` review actors run during the `/governance` pipeline.
- **Agentic worker** — an external LLM-driven client (Claude, GPT, in-house) that drives Yuzu through MCP, REST, or the dashboard. The thing the agentic-first principle (`docs/agentic-first-principle.md`) is about.

When in doubt in commit messages, PR descriptions, or new docs, use the disambiguated form.

## Context discipline

Context is the scarce resource. Keep this thread lean; spend file-reading budget in subagents where you have them.

- **Search before reading.** Use `rg` (ripgrep) to locate symbols, call sites, config keys, tests, and error strings before opening files. `rg` already skips everything in `.gitignore` (build dirs, `vcpkg_installed/`, generated `*.pb.*`, `*.beam`, `tests-build-*`, coverage/asan/tsan dirs). Then read only the line ranges you need — not whole directories.
- **Plain file reads and `find` do NOT honor `.gitignore`** — don't point them at build, vendored, or generated trees; don't open generated protobuf (`*.pb.h/.cc`) or `vcpkg_installed/` unless explicitly required.
- **Delegate broad reads** to a subagent when you have one: have it sweep many files and return conclusions, not file dumps. Prefer a summary of findings over pasting large code blocks into this thread.
- **Summarise and hand off proactively** — don't wait for a context threshold. When a thread gets long, record: files touched, facts learned, open questions, next command — then continue from that summary.
- **For code changes:** find the owning module → find its tests → make the smallest coherent patch → run the targeted suite (`meson test -C build-<os> --suite <agent|server|tar>`) before the broad one.

## Build

Meson is the sole build system. **Every time you add, remove, or rename a source file, update `meson.build` in the affected directory** and verify the build compiles.

Prerequisites: Meson 1.11.1, Ninja, CMake (required by Meson's cmake dependency method — not a build system here), a C++23 compiler (GCC 13+, Clang 18+, MSVC 19.38+, or Apple Clang 15+), vcpkg (set `VCPKG_ROOT`), and **PyYAML** (hard configure-time dependency — `meson setup` fails without it). Linux also needs `bison flex`; macOS needs `autoconf automake libtool` (vcpkg's libpq port builds postgres from source); Windows needs nothing new (vcpkg auto-acquires winflexbison).

```bash
./scripts/setup.sh                              # debug build, default compiler
./scripts/setup.sh --buildtype release --lto    # release + LTO
./scripts/setup.sh --tests                      # enable tests
./scripts/setup.sh --native-file meson/native/linux-gcc13.ini       # CI compiler selection
./scripts/setup.sh --cross-file meson/cross/aarch64-linux-gnu.ini   # cross-compile
```
The script runs `vcpkg install` then `meson setup` automatically. Cross files live in `meson/cross/`, native files in `meson/native/`.

Manual configure (when not using setup.sh):
```bash
vcpkg install --triplet x64-linux --x-manifest-root=.
meson setup build-linux \
  --buildtype=debug \
  -Dcmake_prefix_path=$VCPKG_ROOT/installed/x64-linux \
  -Dbuild_tests=true
meson compile -C build-linux
```

| Option | Default | Notes |
|---|---|---|
| `-Dbuild_agent` / `-Dbuild_server` / `-Dbuild_examples` | true | Components |
| `-Dbuild_tests` | false | Catch2 suite — vcpkg installs Catch2 on `x64 \| arm64` only; the ARM64 cross-compile CI job skips tests |
| `-Db_lto` | false | Link-time optimisation |
| `-Db_sanitize=address,undefined` / `-Db_sanitize=thread` | none | ASan+UBSan / TSan |

### Per-OS build directory convention

The same source tree is built from multiple hosts; per-OS dirs prevent clobbering: `build-linux`, `build-windows`, `build-macos`. Use `scripts/setup.sh` (auto-picks the dir) or pass `-C build-<os>`. If setup.sh finds a dir whose recorded source path looks like another host's, it refuses to reconfigure unless `--wipe` — prevents opaque ninja "dyndep is not an input"/Windows-path failures when a Windows builddir is reused under WSL2. setup.sh never auto-wipes; it defaults to `--reconfigure`.

### Build landmines

- **Shipped content is build-time embedded** (`embed_content.py` → `bundled_content.cpp`, seeded into `instructions.db` on first boot). The runtime never reads YAML from disk — **there is no `--content-dir` flag**. Rationale: `docs/Instruction-Engine.md` "Build-time content embedding".
- **Every `dependency()` in meson files is marked `include_type: 'system'`** so vcpkg/gRPC/abseil/protobuf/Catch2 warnings are silenced while our code stays at `warning_level=3`. Do not remove it when adding dependencies.
- **Windows build: never `vcvars64.bat`** (extension exit-1 corrupts wrappers) and **never Clang from `C:\Program Files\LLVM\bin`** (must be cl.exe/MSVC). Source of truth: `docs/windows-build.md`.
- **vcpkg** — manifest `vcpkg.json`, pinned baseline `4b77da7fed37817f124936239197833469f1b9a8` (matches CI's `vcpkgGitCommitId`); `builtin-baseline` is required by the abseil `version>=` constraint. OpenSSL is an **unconditional** dependency on every platform including Windows (`grpc.lib` has unresolved OpenSSL references; schannel was never wired — #375). Static libpq's closure (`libpgcommon`/`libpgport` + OpenSSL) is hand-wired in the meson `libpq_dep` block; on Windows libpq is a **DLL** (ADR-0008 Correction); `libpq_dep` is gated on `build_server`. The Windows grpc/protobuf/abseil static-link pairing (the `triplets/x64-windows.cmake` override **and** the hand-wired `find_library` construction) is load-bearing — **do not simplify either half** without reading `.codex/agents/build-ci.md` "Windows MSVC static-link history and #375".

## Test

Every test target carries a short `suite:` label (`agent`, `tar`, `server`) so `--suite <name>` filters directly:

```bash
meson test -C build-linux --suite server --print-errorlogs
meson test -C build-linux --suite agent --print-errorlogs
meson test -C build-linux --suite tar --print-errorlogs
meson test -C build-linux --print-errorlogs              # everything
```

Tests require `-Dbuild_tests=true`. For Catch2 tag filtering (`[rest][token]`, `[mgmt][cycle]`) or raw output, call the binaries directly — `scripts/link-tests.sh` (run automatically at the end of setup.sh) maintains stable symlinks per component and triplet (`linux_x64`, `linux_arm64`, `macos_arm64`, `windows_x64`):

```bash
tests-build-server-linux_x64/yuzu_server_tests "[rest][token]"
tests-build-agent-linux_x64/yuzu_agent_tests "[metrics]"
tests-build-tar-linux_x64/yuzu_tar_tests
```

`tests-build-*/` is gitignored.

### Test conventions — shared helpers

- Temp files and SQLite DBs: `yuzu::test::unique_temp_path(prefix)` / `yuzu::test::TempDbFile` from `tests/unit/test_helpers.hpp`. **Never** salt uniqueness with `std::hash<std::thread::id>` or `std::chrono::steady_clock` — silent collisions under Defender-induced I/O serialisation on `yuzu-local-windows` (flake #473; rationale in the header comment + #482).
- Live `ExecutionTracker` wired into `AgentServiceImpl`: the `TrackerScope` RAII helper in `tests/unit/server/test_agent_service_impl.cpp` — `GatewayResponseHarness h; TrackerScope ts{h.svc}; auto exec_id = ts.make_exec();`.
- Live **PostgreSQL**: `PostgresTestDb` + the `YUZU_REQUIRE_PG_DB(var)` macro from `tests/unit/test_helpers.hpp`. Skip-vs-fail contract: `YUZU_TEST_POSTGRES_DSN` **unset** → test skips cleanly; **set but broken** → test FAILS. Local instance: `docker run -d -e POSTGRES_USER=yuzu -e POSTGRES_PASSWORD=yuzu -e POSTGRES_DB=yuzu -p 5433:5432 postgres:18` then `export YUZU_TEST_POSTGRES_DSN=postgresql://yuzu:yuzu@localhost:5433/yuzu`.

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

`proto/meson.build` invokes `proto/gen_proto.py`, which runs `protoc` and rewrites `#include` paths to flatten subdirectory prefixes — generated headers ship as `"common.pb.h"` rather than `"yuzu/common/v1/common.pb.h"`; the result is the `yuzu_proto` static library, exposed via `yuzu_proto_dep` (owned by `build-ci`).

Domain docs: `CONTEXT.md` at the repo root, ADRs under `docs/adr/` (see `docs/agents/domain.md`).

## Workflows

- **Governance** — specialized review agents live in `.codex/agents/`; the `/governance` skill (`.codex/skills/governance/SKILL.md`) runs the 8-gate pipeline on a commit range (CRITICAL/HIGH findings block merge). Use `/governance <range>`, not hand-running — waves 1–4 shipped 4 CRITICAL command-injection vulns without it.
- **Pre-commit/pre-push testing** — the `/test` skill (`.codex/skills/test/SKILL.md`): `--quick` (~10 min), default (~30–45 min), `--full` (~60–120 min). Results persist to `~/.local/share/yuzu/test-runs.db` (override with `YUZU_TEST_DB`); query via `scripts/test/test-db-query.sh`. CI runner test-DB topology and provisioning: `docs/ci-architecture.md`.
- **CI** — three tiers: PR fast-path (`ci.yml`), push to dev/main (full matrix, no sanitizers/coverage per #410), nightly cron (`nightly.yml`, sanitizers + coverage; failure auto-opens `nightly-broken` — **no merge to main while that issue is open**). New workflows fire only once merged to main. Reference: `docs/ci-architecture.md`; cache rules: `.codex/skills/ci-cache/SKILL.md`.
- **Release** — before tagging, bump the `${YUZU_VERSION:-X.Y.Z}` default in every tracked compose file and verify with `bash scripts/check-compose-versions.sh X.Y.Z`; the `release:` job runs that script first and fails after ~30–60 min of wasted matrix builds otherwise. New compose files must be added to the script's `FILES` array (opt-in, no auto-discovery).
- **Planning** — roadmap `docs/roadmap.md`; capability map `docs/capability-map.md` (headline progress figure is overstated — treat with skepticism). Enterprise/SOC 2 plan: `docs/enterprise-readiness-soc2-first-customer.md` (evaluated at governance Gate 6). Issues at `github.com/Tr3kkR/Yuzu` via `gh` — see `docs/agents/issue-tracker.md` and `docs/agents/triage-labels.md`.

## Product UI conventions

The operator dashboard is HTMX-first, server-rendered, and **dark-theme-only** (`server/core/src/*_ui.cpp`, `server/core/static/*`). **Never use htmx `hx-on`**: the dashboard CSP is `script-src 'self' 'unsafe-inline'` (no `unsafe-eval`), and htmx compiles `hx-on:*` handlers with `new Function()` — CSP blocks them and the handler **silently does nothing**. Use a plain inline `onclick`/`oninput` calling a JS helper, or a `document.body.addEventListener('htmx:afterSettle', …)` listener. htmx core attrs (`hx-get`/`hx-post`/`hx-target`/`hx-swap`/`hx-trigger`/`hx-swap-oob`, the `HX-Trigger` header) are fine. Verify button-driven JS by clicking it in a headless browser and checking for a CSP `pageerror`, not just that the page renders.

The `frontend-design` plugin is scoped to **marketing / sales / demo surfaces only** (the Cedar & Vale deck at `deploy/docker/cedar-vale/app/`). Never use it on product UI — and the in-product fleet visualization (`viz_page_ui.cpp`, `yuzu-viz*.js`, governed by `docs/fleet-viz-invariants.md`) **is product**, despite the name.

## Cross-cutting landmines

Rules with no single owning routed doc — read before touching the named area:

- **SQLite `sqlite3_changes()` after `sqlite3_step()` on a shared FULLMUTEX connection is a data race** — it reads `db->nChange` without the per-connection mutex and races any concurrent `step()`. Use `RETURNING` on the statement itself, or wrap the pair under `sqlite3_db_mutex` when a count is genuinely needed. Issue #1033 tracks the remaining legacy sites; until it closes, every new or modified store must use one of the two correct idioms.
- **Secrets are never a plain column** in a server store — verify-only hashes or AES-256-GCM envelope blobs via `SecretCodec` (KEK behind `KekProvider`), per ADR-0010.

## Routed concerns (read the doc, not this file)

Rows are discriminators — **trigger → what to read first → who loads it**. The invariants live in the target docs, not in this table.

| Concern | Read first | Loaded by / trigger |
|---|---|---|
| Authentication, RBAC, headers, tokens | `docs/auth-architecture.md` | `security-guardian` on auth/RBAC/crypto/header/token change |
| PKI / internal CA | `docs/pki-architecture.md` | `security-guardian` + `cpp-safety` + `docs-writer` on `x509_ca.*`, `key_provider.*`, `secure_buffer.hpp`, `aes_gcm.hpp`, `pg/secret_codec.*`, `ca_store.*`, `agent_csr.*`, `ca_routes.*`, `/api/v1/ca/`, or any new `KeyProvider`/`KekProvider` subclass; `gateway-erlang` on gateway TLS config / `*_pb.erl` |
| AuthDB invariants | `.codex/agents/authdb.md` | `authdb` agent on `auth_db.*` / `auth_routes.*` / `auth.*` change |
| Enterprise A&A (OIDC, SAML, SCIM, MFA, AD/Entra) | `.codex/skills/auth-and-authz/SKILL.md` | invoke `/auth-and-authz` for any A&A planning, audit, or implementation work |
| MCP server | `docs/mcp-server.md` | `security-guardian` on `/mcp/v1/`, `mcp_server.*`, `mcp_jsonrpc.hpp`, `mcp_policy.hpp` change |
| Executions-history ladder | `docs/executions-history-ladder.md` | any change to `agent_service_impl.cpp` `cmd_execution_ids_`, `response_store` execution queries, `execution_event_bus.*`, `execution_tracker.*`, `rest_a4_envelope.*`, the `/api/v1/events` handler, MCP `execute_instruction`, or executions-drawer markup |
| Compliance evaluation pipeline (`PolicyEvaluator`, `polchk-*`) | `docs/user-manual/policy-engine.md` | `cpp-safety` + `docs-writer` on `policy_evaluator.*`, the `PolicyStore` status writer, or the `polchk-` guard in `agent_service_impl.cpp` |
| C++23 conventions, resource ownership, plugin ABI | `docs/cpp-conventions.md` | `cpp-expert` / `cpp-safety` on any C++ source change |
| macOS/Darwin compatibility | `docs/darwin-compat.md` | `cross-platform` on any macOS-affecting change |
| Erlang gateway build & quality | `docs/erlang-gateway-build.md` | `gateway-erlang` on any `gateway/` or `*.erl` change; `/gateway-eunit` and `/gateway-dialyzer` skills |
| UAT rigs & demo environment | `docs/uat-environment.md` (+ `docs/demo-environment.md`) | `release-deploy` on any compose / UAT-script change |
| Instruction engine (YAML content plane) | `docs/Instruction-Engine.md` + `docs/yaml-dsl-spec.md` | any instruction-definition / DSL / content change |
| Prometheus metrics, audit envelope, event format | `docs/observability-conventions.md` | `sre` and `architect` on any metrics/audit/event change |
| Response data types, inventory analytics | `docs/data-architecture.md` | `architect` and `sre` when designing schemas |
| User manual / YAML defs / REST API docs | `.codex/agents/docs-writer.md` | `docs-writer` on every change as part of governance gate 2 |
| Guardian / Guaranteed State + DEX | `docs/yuzu-guardian-design-v1.1.md` (§9.1 schema, §24 invariants) + `docs/guardian-baseline-model.md` + `docs/dex-signal-catalog.md` + `docs/user-manual/guaranteed-state.md` + `docs/user-manual/dex.md` | `security-guardian` + `docs-writer` on any `guaranteed_state*`, `guardian_*`, `guard_*.{hpp,cpp}`, `dex_*`, `tar_proc_perf`, `/api/v1/dex/perf`, `__guard__`, or `__observation__` change |
| TAR dashboard | `docs/tar-dashboard.md` + `docs/tar-implementer.md` + `docs/tar-module-loads.md` | `architect` on `/tar` or `/fragments/tar/...`; `plugin-developer` on the TAR action surface; `cross-platform` + `cpp-safety` on `tar_proc_{stream,etw,es}.*`; `cpp-safety` + `docs-writer` on `tar_db.cpp` or `canonical_source_enabled` |
| Scope walking (result sets) | `docs/scope-walking-design.md` | `architect` + `dsl-engineer` on scope-engine/DSL/result-set change; `consistency-auditor` on the audit chain; `security-guardian` on cross-operator authz |
| System architecture | `docs/architecture.md` | `architect` on cross-cutting design changes |
| Tag/scope DSL operators | `docs/asset-tagging-guide.md` | `dsl-engineer` on scope/tag-DSL changes; `architect` when a new scope kind is added |
| Agentic-first invariants A1–A5 | `docs/agentic-first-principle.md` | `consistency-auditor` on every PR; `security-guardian` + `architect` on relevant surfaces; any change to `rest_a4_envelope.*` or the `/api/v1/events` handler |
| Enterprise-platform parity matrix | `docs/enterprise-parity-plan.md` | `architect` on capability-map / roadmap changes; `enterprise-readiness` agent during Gate 6 |
| Agent privilege model | `docs/agent-privilege-model.md` | `security-guardian` on any plugin shell-out / sudoers / setcap change; `cross-platform` on privilege-gated plugins; `plugin-developer` when adding a privileged plugin |
| Fleet visualization (3D) | `docs/fleet-viz-invariants.md` | `security-guardian` + `docs-writer` on `viz_routes.*`, `fleet_topology_store.*`, `viz_page_ui.cpp`, `static/yuzu-viz*.js`, `--viz-disable` |
| Network quality dashboard (`/network`) | `docs/user-manual/network.md` | `security-guardian` + `docs-writer` on `network_routes.*`, `network_perf_*`, `net_quality_sampler.*`, `tar_netqual.hpp`, the `yuzu.net_*` heartbeat block, `yuzu_fleet_net_*` |
| Device pages (`/devices`, `/device?id=`) | `docs/user-manual/device-management.md` | `security-guardian` + `docs-writer` on `device_routes.*`, `device_ui.cpp`, `rest_audit.hpp`, the `device.live.*` verbs, `processes/{list_hashed,list_tree}`, or the live-snapshot JS |
| OS capability matrix | `docs/os-capability-matrix.md` | `docs-writer` + `cross-platform` on any per-OS support change |
| Server storage substrate (PostgreSQL) | `docs/adr/0012-server-postgres-store-contract.md` + `docs/postgres-store-playbook.md` + `docs/postgres-migration-ladder.md` + ADR-0006/0007/0008(+Correction)/0010 | `architect` + `sre` on any server store/schema change; `build-ci` on CI Postgres; `release-deploy` on deploy/compose; `security-guardian` on any secret-at-rest |
| Windows build & CI runner provisioning | `docs/windows-build.md` + `deploy/windows/README.md` | `cross-platform` + `build-ci` on any Windows-touching change |
| CI architecture & test-runs DBs | `docs/ci-architecture.md` | `build-ci` owns the matrix; `cross-platform` owns Windows/macOS specifics |

## AGENTS.md updates

This file is a **routing layer, not a reference manual**. Resident content is limited to: identity, glossary, context discipline, build/test commands, product-UI conventions, and the cross-cutting landmines. Everything else is a one-line routing row — a discriminator (trigger → doc), never a summary of the doc's content. When a routed area gains an invariant, write it in the target doc; touch the row only to add or tighten a trigger. Build/Test stay resident because the work is unstable or local-host-specific; mature areas route to `docs/` with a short "read this first" row once an agent/skill/hook carries the load (precedent: the Erlang gateway section moved to `docs/erlang-gateway-build.md`). See memory `feedback_claude_md_scope.md` for the heuristic.
