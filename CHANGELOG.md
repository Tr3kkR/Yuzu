# Changelog

All notable changes to Yuzu are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.10.0] - 2026-04-12

### Added

- **`/governance` skill** at `.claude/skills/governance/SKILL.md` — a
  reusable prompt-writing runbook for the Gate 1–7 governance pipeline
  defined in CLAUDE.md. Provides parameterized agent preambles, the
  Gate 3 domain-triggered decision matrix, conditional Gate 5 chaos
  analysis, and a "Known patterns" section seeded with the five
  failure modes caught in the #222/#224 governance run (sibling IDOR,
  cycle-safe parity, error-branch info disclosure, enumeration oracle,
  readiness probe coverage). Default range is `dev..HEAD` because
  Yuzu's main working branch is `dev`, not `main`. Invoke with
  `/governance <commit-range>` — the skill doesn't fully automate
  (judgment calls on Gate 3 fan-out and Gate 5 skip still required)
  but cuts per-run prompt-writing overhead roughly in half.

- New Prometheus metrics for the auth and audit subsystems:
  `yuzu_server_token_cache_hits_total`, `yuzu_server_token_cache_misses_total`,
  and `yuzu_server_token_cache_size` expose API-token cache effectiveness so
  cold-cache stampedes after restart are visible to operators.
  `yuzu_server_audit_events_total{result}` counts audit-event writes bucketed
  by `success`/`failure`/`denied`/`other`.
- `tests/test_changelog_order.py` enforces reverse-chronological ordering of
  CHANGELOG sections (Keep a Changelog convention). Wired in as a meson test
  (`changelog order`, suite `docs`) and as a new lightweight GitHub Actions
  workflow (`Docs Lint`) that triggers on `CHANGELOG.md` / `docs/**` edits —
  CHANGELOG drift is now caught in CI rather than discovered months later.

### Changed

- **CodeQL workflow is manual-only and runs on the self-hosted Linux
  runner.** `.github/workflows/codeql.yml` previously ran on
  `ubuntu-24.04` via `push` to `main` + weekly schedule, consuming
  GitHub-hosted Actions minutes on every merge. It now targets
  `[self-hosted, Linux]` (same runner as `release.yml`) and triggers
  only on `workflow_dispatch` — fire via the Actions UI or
  `gh workflow run codeql.yml`. No `push`/`pull_request`/`schedule`
  triggers, so it cannot gate PR merges and is not listed in any
  branch protection required check. Output lands in the GitHub
  Security tab under "Code scanning alerts" for informational review.
  Preflight now uses the same `gcc-13 / cmake / ninja / meson / ccache`
  dependency-check pattern as `release.yml`, uses the runner's
  pre-installed vcpkg (drops `lukka/run-vcpkg@v11`), and wraps the
  compiler with ccache for fast repeat runs. Private-repo caveat:
  if the repo ever flips private, CodeQL will require GitHub
  Advanced Security — the action enforces the entitlement check
  server-side regardless of where the job runs.

- **`integration-test.sh` — sleep-assert sweep, gateway-crash regex,
  env-overridable ports.** Three drift fixes to
  `scripts/integration-test.sh` that together reduce per-run
  wall-clock and eliminate two assertion false positives:
  1. **Heartbeat metric wait is now loop-poll, not sleep-assert.**
     The previous `sleep 10` started before the agent finished
     enrolling (which can take ~12s on a cold run with enrollment-
     token retry backoff), so by the time the sleep ended the
     agent's 5s-interval heartbeat thread hadn't fired yet and the
     `yuzu_heartbeats_received_total` assertion failed with no
     signal that the wait budget was wrong. Now a 30s loop-poll on
     `/metrics` that exits the instant the counter appears — sub-
     second on warm runs, still succeeds within 30s on cold runs.
  2. **Gateway-stability regex tightened.** The old
     `grep -qi "crash\|supervisor.*error\|SIGTERM"` tripped on
     benign `[info]`-level diagnostic log lines of the form
     `[info] crash: class=exit exception={noproc,...}` that the
     gateway emits when an agent's first registration attempt
     races the upstream `gen_server` startup (the agent's built-in
     exponential backoff resolves it in ~6s). The regex now
     matches only actual Erlang crash markers:
     `CRASH REPORT|=ERROR REPORT|Supervisor: .* terminating|\[error\].*SIGTERM`.
  3. **Env-overridable port defaults.** Every `SERVER_*_PORT` and
     `GW_*_PORT` now uses `${VAR:-default}` so the script can
     coexist with other live stacks — notably the docker UAT from
     `scripts/docker-start-UAT.sh`, which binds `50055` and `50063`
     on the host. Override pattern:
     `SERVER_GW_PORT=50155 GW_MGMT_PORT=50163 bash scripts/integration-test.sh`.
  Bonus sweep: replaced `sleep 3` gateway grpcbox startup with
  `wait_for_port $GW_AGENT_PORT`, and `sleep 2` agent-disconnect
  propagation with a 2s poll on `kill -0` of the killed PID.
  Verified: 22/22 PASS on first run with zero flakes.

- **Friction pass on build / test workflow** — four developer-experience
  fixes from the governance-run retrospective:
  - **Third-party warnings silenced.** Every `dependency()` in the
    top-level `meson.build` and each subdirectory file now carries
    `include_type: 'system'`, so vcpkg / gRPC / abseil / protobuf /
    Catch2 deprecation warnings become `-isystem` includes and no
    longer appear in compile output. Our own code remains under
    `warning_level=3`. Compile logs dropped by dozens of lines per
    incremental build without a wrapper script in the way.
  - **Short test suite names.** `tests/meson.build` now attaches
    `suite: 'agent' | 'server' | 'tar'` to each `test()` call, so
    `meson test -C build-linux --suite server` works directly — no
    more guessing `"yuzu:server unit tests"` or `"unit tests"`.
  - **Stable top-level test binary paths.** New
    `scripts/link-tests.sh` creates
    `/tests-build-<component>-<triplet>/` directories (e.g.
    `tests-build-server-linux_x64/yuzu_server_tests`) as symlinks
    to the real build output. `scripts/setup.sh` runs it
    automatically after configure. Gitignored. Binaries stay live
    across rebuilds because the symlinks point at paths, not
    contents. Catch2 tag filtering (e.g. `[token][owner]`) is now
    one line from the repo root without remembering the build-dir
    layout.
  - **`.gitignore` cleanup.** Added `.codex`, `test_output.txt`,
    `test_xml.txt`, `update.finished`, `node_modules/`,
    `__pycache__/`, `gateway/.deps_cache/`, `gateway/ebin/`, and
    `/tests-build-*/` so `git status` no longer carries session
    noise from dev-machine artifacts.

- **`CLAUDE.md` slimmed from 571 → 484 lines** by splitting three
  implementation-detail sections into dedicated `docs/` files and
  compressing four already-linked sections to pointers. The Auth &
  Authorization feature history (inventory of mTLS, OIDC, AD/Entra,
  Windows cert store, CSP construction, etc.) moved to
  `docs/auth-architecture.md`; only the hard invariants that every
  session must respect (mTLS, HTTPS default, localhost bind,
  `/metrics` auth, owner-scoped token revoke) remain in CLAUDE.md.
  The MCP server architecture and 22-tool inventory moved to
  `docs/mcp-server.md`; only the tier-before-RBAC rule, kill-switch
  flags, audit pattern, and `JObj`/`JArr` serialization rule remain.
  The Windows build toolchain path table moved to
  `docs/windows-build.md`; CLAUDE.md keeps the "MSYS2 bash +
  `setup_msvc_env.sh`, NOT `vcvars64.bat`" rule. Instruction Engine,
  Enterprise Readiness / SOC 2, Development Roadmap, and CI matrix
  sections were compressed to pointers since the target docs already
  exist. Build, Deploy, Release, Erlang Gateway, UAT Environment,
  Darwin Compatibility, and Agent Team / Governance sections stay
  resident intact — churning subsystems and areas that repeatedly
  need re-loading belong in CLAUDE.md, not in `docs/`.

- `AuthRoutes` exposes a public `resolve_session(req)` helper that performs the
  three-tier auth resolution (cookie → `Authorization: Bearer` → `X-Yuzu-Token`)
  used by `require_auth`, `make_audit_event`, and `emit_event`, plus the eight
  call sites in `server.cpp` that previously inlined fragments of the same logic.
  Removes a shadow copy of `extract_session_cookie` from `server.cpp`.

- **Per-OS canonical build directory** — `scripts/setup.sh` now defaults the
  build directory to `build-linux`, `build-windows`, or `build-macos` based on
  the host OS so the same source tree can be configured concurrently from
  WSL2 and a native Windows shell — and a separate macOS dev box — without
  the build dirs trampling each other. The script refuses to reuse a build
  dir whose `meson-info.json` source path was recorded on a different host
  unless `--wipe` is passed (catches the opaque "ninja dyndep is not an
  input" / Windows-path failures from cross-host reuse). It also stops
  auto-wiping existing dirs — `--wipe` is now opt-in; default behaviour is
  `meson setup --reconfigure` to preserve prior compilation state. The
  legacy `builddir/` is gone from the tree; CLAUDE.md documents the
  convention. `YUZU_BUILDDIR` env var still overrides everywhere.

### Breaking

- **API token revocation is owner-scoped** — non-admin users can no longer
  revoke API tokens they do not own. A caller holding `ApiToken:Delete` may
  revoke only tokens whose `principal_id` matches their session username;
  the global `admin` role is the sole bypass. Deployments that used a
  shared non-admin service account to rotate tokens for other principals
  will begin receiving `HTTP 404 token not found` after upgrade. Either
  grant the rotation account the global `admin` role, or refactor the
  rotation so each principal owns its own token (recommended). The same
  constraint applies to both `DELETE /api/v1/tokens/{id}` and
  `DELETE /api/settings/api-tokens/{id}`. See
  `docs/user-manual/server-admin.md` "Upgrade Notes" for details.

### Fixed

- **UAT script `python` vs `python3` drift.**
  `scripts/docker-start-UAT.sh` (8 inline sites) and
  `scripts/uat-command-test.sh` (2 inline sites) both invoked
  `python -c` for JSON / regex parsing. WSL2 Ubuntu has no `python`
  symlink — only `python3` — so every inline parser silently
  returned empty string, and every downstream numeric check
  degraded without error:
  - `docker-start-UAT.sh`: the 10 embedded connectivity tests
    (server registered count, gateway connected count, Prometheus
    target count, ClickHouse event count, os_info round-trip
    parsing) all read "0" or empty strings and reported test
    failures against a stack that was actually working.
  - `uat-command-test.sh`: every command dispatch reported
    `dispatch error` because the `cmd_id` extraction returned
    empty. All 138 test cases failed. After the fix: 136 PASS /
    0 FAIL / 2 legitimate long-running-plugin timeouts
    (`firewall.rules`, `chargen.chargen_start`).

  Both scripts now use `python3 -c` via a mechanical sed fix.
  Worth a broader audit:
  `grep -rn '\bpython -c' scripts/` would surface any remaining
  sites that were missed.

- **`scripts/docker-start-UAT.sh` build dir detection.** The
  script hardcoded `BUILDDIR=$YUZU_ROOT/builddir`, which predates
  the per-OS build dir convention that landed in `830ba7c`. On a
  fresh clone configured via `scripts/setup.sh`, the agent binary
  now lives at `build-linux/agents/core/yuzu-agent` (or
  `build-macos` / `build-windows`), and the preflight check
  reported "yuzu-agent not found — run: meson compile -C builddir"
  even though the binary existed under the new name. Fixed by
  detecting the host OS and selecting `build-<os>`, falling back
  to the legacy `builddir/` path for older trees. Also added
  `Bash(bash scripts/docker-start-UAT.sh:*)` and the `./` variant
  to the project allowlist at `.claude/settings.json`.

- **Governance Gate 4 follow-up hardening** — Gate 4 unhappy-path and
  consistency-auditor surfaced three new BLOCKING items on the prior
  hardening round; all are addressed here:
  - **Denied-branch token-table leak regression (UP-11)** — the prior
    hardening round's new 404 denied branch on
    `DELETE /api/settings/api-tokens/:id` called
    `render_api_tokens_fragment()` which lists ALL users' tokens with no
    principal filter. A non-owner probe therefore received a 404
    response with a complete fleet-wide token table in the HTML body —
    worse than the IDOR the round was closing. The denied branch now
    returns a minimal static error fragment with no token data.
  - **`render_api_tokens_fragment` cross-user enumeration (C1)** — the
    same underlying `list_tokens()` leak affected the success-path
    re-render (`POST`, `DELETE` success) and the `GET
    /fragments/settings/api-tokens` panel load. The fragment now takes
    a `filter_principal` argument. All four call sites pass
    `session->username` for non-admin sessions and empty (full view)
    for admins, matching the `GET /api/v1/tokens` scoping that
    `rest_api_v1.cpp` already enforced. A new
    `ApiTokenStore: list_tokens(principal) scopes results to owner`
    unit test pins the store contract the fix relies on.
  - **Audit-trail integrity, `principal_role` hardcoded `"admin"`
    (C2, Gate 4 unhappy-path UP-9, Gate 4 happy-path SHOULD, Gate 2
    re-review NICE)** — three audit emission sites in
    `settings_routes.cpp` (token create, token revoke success, token
    revoke denied) hardcoded `.principal_role = "admin"`. This was
    benign when the panel was admin-only but became a forensic lie
    once the hardening round opened the handlers to non-admin callers
    with `ApiToken:Delete`. All three sites now read
    `auth::role_to_string(session->role)`, matching the convention in
    `auth_routes.cpp`.
  - **Test fixture brittleness** — `create_token_for` in
    `test_rest_api_tokens.cpp` used `listing.back()`, but
    `list_tokens` orders by `created_at DESC`, so `.back()` is the
    oldest token. Swapped to `.front()` with a comment so future
    multi-token tests in the same harness do not silently regress.

- **Governance hardening round for #222 and #224** — Gate 2 security review
  on the original fixes surfaced two HIGH sibling findings that are
  addressed here:
  - **Dashboard IDOR** — `DELETE /api/settings/api-tokens/:token_id` (the
    HTMX Settings path) had the same ownership gap as the REST handler
    closed by #222. It now looks up the token, rejects cross-user revokes
    with a generic 404 fragment, and emits a `denied` audit event with
    `detail=owner=<principal>` so forensics can tell an enumeration probe
    from a real not-found.
  - **`get_ancestor_ids` cycle safety** — the companion BFS-upward walk
    in `ManagementGroupStore` still had no visited-node tracking, only a
    depth-10 cap. `RbacStore::check_scoped_permission` unions ancestors
    into the set of groups used for role resolution, so on a cyclic DB a
    user could inherit spurious permissions from phantom ancestors
    reported by the cycle's alternating output. `get_ancestor_ids` now
    carries the same `unordered_set<std::string> visited` + warning-log
    pattern as `get_descendant_ids`.
  - **Enumeration oracle closed on REST `DELETE /api/v1/tokens/:id`** —
    the original fix returned `403 "cannot revoke another user's API
    token"` for cross-user revokes, which let a non-owner with
    `ApiToken:Delete` distinguish "token does not exist" (404) from
    "exists but not yours" (403) and enumerate valid token ids. Both
    paths now return `404 "token not found"` with an identical response
    body; the audit log still carries the distinction server-side via
    `result=denied` + `detail=owner=<principal>`.
  - **`create_group` self-parent** — the create path accepted a
    caller-supplied `group.id == group.parent_id` and produced an
    immediate 1-row self-cycle. It now returns
    `"group cannot be its own parent"` from the same layer as
    `update_group`.
  - **REST-handler test coverage (#222 follow-up)** — the original fix
    landed with store-level coverage only. A new
    `tests/unit/server/test_rest_api_tokens.cpp` spins up a real
    `httplib::Server` on a random port, registers `RestApiV1` routes
    with mock `auth_fn`/`perm_fn`/`audit_fn`, and exercises all four
    paths end-to-end: owner self-revoke, admin cross-user bypass,
    non-owner → 404 (no oracle), unknown id → 404 (no audit). 5 HTTP
    cases, 55 assertions, plus the existing store-level cases.
  - **Store-test fixture parallelism** — both
    `test_management_group_store.cpp` and `test_api_token_store.cpp`
    used hardcoded SQLite paths (`/tmp/test_mgmt_groups.db`,
    `/tmp/test_api_tokens.db`) that would collide under
    `meson test --num-processes N`. Each `TempDb` now builds a unique
    path per instance from `std::thread::id` + `steady_clock`, matching
    the `unique_temp_path` pattern already used in
    `test_rest_api_t2.cpp`.
  - **Deep / self-loop cycle regression tests** — the original fix
    only tested a 2-node cycle. New cases exercise a 3-node A→B→C→A
    cycle and the degenerate self-loop `parent_id == id` on a single
    row. A reparent-to-root regression test guards the null-bind
    branch in `update_group` that the cycle/depth block now gates on.

- **API token revocation is now owner-scoped (#222)** — `DELETE
  /api/v1/tokens/:token_id` previously required only `ApiToken:Delete`
  permission without verifying ownership, so any user with that
  permission could enumerate token IDs (the handler always returned 404
  for unknown IDs but 200 for any real token) and revoke other users'
  tokens. The handler now looks up the token via a new
  `ApiTokenStore::get_token(token_id)` method, rejects cross-user
  revokes with `403` and a `denied` audit event, and only allows the
  bypass for callers holding the global `admin` role. Owner-scoped
  audit detail (`owner=<principal>`) is logged on both success and
  denial paths so forensics can distinguish intent.

- **`get_descendant_ids` is cycle-safe; `update_group` validates
  `parent_id` (#224)** — the management-group BFS traversal had no
  visited-node tracking and no depth cap, so any existing cycle in
  `management_groups.parent_id` (injectable via legacy tooling or
  bugs) would hang the server thread indefinitely. It now carries an
  `unordered_set<std::string> visited` and a `10_000` node safety cap,
  logging a warning if the cap is hit. Independently,
  `ManagementGroupStore::update_group` now rejects self-parent,
  parent-not-found, cycle-forming, and depth-exceeding updates at the
  store layer so non-REST callers (admin tooling, tests, future
  endpoints) cannot bypass the checks that previously only lived in
  the REST handler. Store unit tests cover injected-cycle termination
  via a direct SQLite write that mimics on-disk corruption.

- **Docker-compose UAT image tags parameterized** — `docker-compose.uat.yml`
  was shipping with hardcoded `ghcr.io/tr3kkr/yuzu-{server,gateway}:0.8.1-rc0`
  references that were not updated when the version bumped to 0.9.0, so a
  tester running the file fresh would pull the wrong images. The tags are
  now parameterized as `${YUZU_VERSION:-0.9.0}` so operators can override at
  `docker compose up` time, and a new `scripts/check-compose-versions.sh`
  runs as the first step of the release workflow's `release:` job — it
  rejects any hardcoded `yuzu-{server,gateway,agent}:X.Y.Z` references in
  tracked compose files and verifies the parameterized default matches the
  tag being released, so a stale default blocks the release before any
  assets are published. A corrected `docker-compose.uat.yml` was uploaded as
  a v0.9.0 GitHub release asset to unblock current UAT testers.

- Login page no longer renders `[object Object]` on bad credentials. The inline
  JS in `login_ui.cpp` was reading `resp.error` directly from the structured
  error envelope (`{"error":{"code":N,"message":"..."}}`) and assigning the
  object to `textContent`. It now reads `resp.error.message`, with a string
  fallback for legacy responses and a status-keyed default if parsing fails.
  Fixes #333.

- **`ConcurrencyManager::try_acquire` TOCTOU race** — the count-then-insert
  sequence used a separate `SELECT COUNT(*)` and `INSERT OR IGNORE`, so two
  concurrent callers could each read `count < limit`, each insert, and exceed
  the configured `global:N` or `per-definition` cap. `SQLITE_OPEN_FULLMUTEX`
  serializes individual API calls but does not bind two-statement sequences
  together, so it could not catch this. Fix collapses the check and write
  into a single atomic statement: `INSERT OR IGNORE … SELECT … WHERE
  (SELECT COUNT(*) …) < ?`. The COUNT subquery and the INSERT execute as
  one statement under SQLite's per-statement write lock, so the cap is now
  honored under contention. Idempotent re-acquire of the same
  `(definition_id, execution_id)` is preserved via a follow-up existence
  check on the no-op path. Removes the dead `std::shared_mutex mtx_` member
  in `ConcurrencyManager` and `ScheduleEngine` (declared but never acquired
  by any method) — both classes prepare-and-finalize their statements per
  call, so the application-level mutex is unnecessary on top of FULLMUTEX.
  Fixes #330.

- **Audit Trail Integrity Fix (YZA-2026-001)** — Audit log and analytics event
  rows for requests authenticated via `Authorization: Bearer` or `X-Yuzu-Token`
  now populate the `principal` and `principal_role` fields. Previously these
  helpers resolved the principal from the session cookie only, so every
  API-token-authenticated request — including every MCP tool call — wrote audit
  rows with empty `principal`, breaking attribution for SOC 2 evidence purposes.
  The same gap affected `def.created_by` on instruction creation,
  `sched.created_by` on schedule creation, the `user` recorded by execution
  rerun/cancel, and the `reviewer` recorded by approval approve/reject.

  This is a forward-only fix: pre-fix audit rows are not backfilled. Operators
  auditing a window that spans v0.9.0 (released 2026-04-11) and v0.10.0 should
  expect a bimodal `principal` distribution split at the merge date — pre-fix
  token-authenticated rows will have empty `principal`. Cookie auth and login
  flows are unchanged.

### Tests

Test-suite changes are listed separately so other teams can follow test
development independently from the primary software changelog.

- **TOCTOU regression test for `ConcurrencyManager`** — new `[threading]`
  cases in `tests/unit/server/test_concurrency_manager.cpp` race 64 threads
  against `try_acquire("global:3")` and `per-definition` on a
  `SQLITE_OPEN_FULLMUTEX` `:memory:` connection, asserting that exactly the
  configured limit wins. Adds a `TestDbMt` RAII helper for thread-safe
  in-memory connections, and a non-threaded idempotent re-acquire case.
  Server unit-test count: 1112 → 1128 cases.

- **`scripts/run-tests.sh` (and integration / UAT scripts) honour the per-OS
  canonical build directory** — `build-linux` / `build-windows` / `build-macos`
  selected from `uname` (and overridable via `YUZU_BUILDDIR`). Removes the
  hard-coded `builddir/` path that broke under WSL2 once the Windows-side
  build dir disappeared.

- **`run-tests.sh erlang-unit` invokes `rebar3 eunit --dir=apps/yuzu_gw/test`**
  — works around rebar3 3.27 auto-discovery rejecting test modules whose name
  has no 1:1 src/ counterpart (`circuit_breaker_tests`, `env_override_tests`,
  `scale_tests`, every `*_SUITE` file, etc.). The bare `rebar3 eunit`
  invocation would error out with "Module … not found in project" before
  running any test. Tracking issue: #337.

- **Gateway eunit fixture leak: `agent_tests:starts_streaming` cancellation**
  — `yuzu_gw_health_nf_tests:cleanup/1` only killed the mock pids it captured
  in `setup/0`, but the `readyz_503_dead_process` test kills the original
  `yuzu_gw_registry` mock and re-registers a fresh `mock_loop/0` pid that the
  cleanup tracking never sees. The leaked mock survived into every subsequent
  test module; downstream tests checked `whereis(yuzu_gw_registry)` and
  reused it as if it were the real gen_server. When `agent_tests:setup`
  fired, `yuzu_gw_agent:init/1` issued `gen_server:call(yuzu_gw_registry,
  {register, …})` against the mock, which received the message and silently
  recursed without replying — eunit cancelled the call at its 5-second limit
  and the rest of `agent_tests` (14 tests) never ran. The full eunit suite
  reported "Passed: 132. One or more tests were cancelled" instead of the
  expected 148. Fixes:
  - `health_nf_tests:cleanup/1` now looks up the *current* registered pid
    via `whereis/1` for each name it owned at setup time, so re-registered
    mocks are killed too.
  - `agent_tests:setup/0` defensively detects a stale mock under
    `yuzu_gw_registry` (anything whose `proc_lib:initial_call/1` is not
    `{gen_server, init_it, _}`), unregisters it, and starts a real
    registry — guarding against the same class of leak from any future
    test module.
  - `agent_tests:setup/0` also asserts `whereis(yuzu_gw_upstream) =:=
    undefined` so meck-coexisting-with-a-live-gen_server failures fail
    loudly at the boundary instead of producing opaque downstream timeouts.
  - `circuit_breaker_nf_tests`, `circuit_breaker_tests`, and
    `upstream_tests` cleanup paths now use synchronous
    `gen_server:stop(Pid, shutdown, 5000)` instead of `exit(Pid, shutdown)
    + timer:sleep(50)`. The sleep was racy on busy boxes (WSL2 in
    particular) and could leave the upstream gen_server alive into the
    next test module. Eunit count: 133 passing (with all 15 `agent_tests`
    cases cancelled) → 148 passing. Fixes #336.

- **`scripts/integration-test.sh` fixes** — admin password bumped from 8 to
  12 characters to satisfy the post-v0.9 length requirement; `--no-https`
  added so the server starts without TLS in test mode; port matrix split so
  single-host gateway + server no longer collide on 50051 (server `5005x`,
  gateway `5006x`); `YUZU_KEEP_WORK_DIR=1` env var preserves
  `/tmp/yuzu-integration.*` after teardown for post-mortem of failed runs.

- **`scripts/linux-start-UAT.sh` `kill_stale` matches the gateway** —
  `pgrep -f "beam.smp"` is replaced with `pgrep -f "yuzu_gw[/_]"` because
  the rebar3 release wrapper rewrites `cmdline` so the binary name doesn't
  appear in `/proc/$pid/cmdline`. Previous behaviour leaked the gateway
  beam between UAT runs and tied up port 9568 / 50063 indefinitely.

- **`scripts/e2e-security-test.sh` no longer skips on missing creds** —
  honours `YUZU_ADMIN_PASS` env var, then auto-detects against the canonical
  UAT password (`YuzuUatAdmin1!`) and the post-tightening `adminpassword1`
  before falling back to legacy short passwords. Hard-fails if no candidate
  works rather than silently skipping the auth-bearing test categories.
  Brings the security suite from 33 → 60 tests against a live UAT stack.

## [0.9.0] - 2026-04-11

### Added

#### Server
- **`--data-dir` CLI flag** (env: `YUZU_DATA_DIR`) — separates SQLite database storage from the config file location. Required for containerized deployments where the config is mounted read-only but databases need a writable volume. Path is resolved to canonical form at startup (symlinks followed). A writable probe runs at startup to fail fast if the directory is not writable, rather than deferring to the first DB open.
- **`execute_instruction` MCP tool** — dispatches plugin commands to agents via MCP JSON-RPC. Accepts `plugin`, `action`, `params`, `scope`, and `agent_ids`. Returns a `command_id` for asynchronous result polling via `query_responses`. Plugin and action names are normalized to lowercase before dispatch. MCP tool count: 22 → 23.
  - `operator` tier: executes immediately (auto-approved).
  - `supervised` tier: returns `-32006 APPROVAL_REQUIRED` with an explicit message that approval-gated MCP execution is not yet implemented.
  - `readonly` tier: blocked.
  - If neither `scope` nor `agent_ids` is provided, defaults to all agents (documented in tool description as a warning).

#### Testing
- **Puppeteer E2E test expanded** (`Synthetic-UAT-Puppeteer.js`) — 70 → 115 non-destructive commands. Cross-platform path support via `YUZU_AGENT_OS` env var. Added: `network_config dns_cache`, `network_actions ping/flush_dns`, `users group_members`, `filesystem search/search_dir/create_temp/create_temp_dir`, `vuln_scan cve_scan/config_scan/inventory`, `storage set/get/list`, `tags set/get/get_all/check/count`, `agent_actions set_log_level`, TAR extended, `chargen start/stop`, `wol check`, registry read-only (Windows), `windows_updates` extended.
- **REST API command test expanded** (`scripts/uat-command-test.sh`) — 145 → 151 dispatches. Added: `agent_actions set_log_level`, `network_actions flush_dns`, `filesystem create_temp/create_temp_dir`, `interaction notify`. Removed destructive `status switch`.
- **MCP Haiku subagent test framework** — stdio-to-HTTP MCP adapter (`scripts/mcp-http-adapter.js`), Claude Code agent definition (`.claude/agents/mcp-uat-tester.md`), and test harness (`scripts/e2e-mcp-haiku-test.sh`) that invokes Haiku to exercise all MCP tools end-to-end.
- **15 `execute_instruction` unit tests** (`tests/unit/server/test_mcp_server.cpp`) — happy dispatch, null dispatch_fn, missing params, zero agents, default scope, explicit agent_ids, params forwarding, non-string params, read_only_mode, readonly/operator/supervised tier enforcement, audit trail on success and failure.
- **`--setup` flag on all E2E test scripts** — optional Docker Compose lifecycle management. Default: health-check and fail fast. `--setup`: bring up `docker-compose.local.yml`, wait for health, then run.
- Tool count assertions changed from exact equality to `>= 23` minimum with named presence checks — no more magic numbers that break when tools are added.

#### Deployment
- **`docker-compose.local.yml` port topology** — gateway owns host port 50051 (agent-facing), server agent port is container-internal only. Agents connect to `localhost:50051` with default settings.
- **`docker-compose.local.yml` uses `--data-dir /var/lib/yuzu`** — config at `/etc/yuzu/yuzu-server.cfg` (read-only Docker config mount), databases at `/var/lib/yuzu` (writable volume).

### Changed
- `AuthManager::state_dir()` — enrollment tokens and pending agents now written to `--data-dir` when set, instead of always using the config file's parent directory. `reload_state()` re-loads from the new location after `set_data_dir()`.
- `Config::db_dir()` helper method — all ~25 DB path derivations in `server.cpp` use `cfg_.db_dir()` instead of `cfg_.auth_config_path.parent_path()`.
- MCP `read_only_mode` and `mcp_disabled` flags captured by reference (not value) so runtime toggle via Settings UI takes effect without server restart.
- MCP operator tier no longer requires approval for `Execution/Execute` — matches documented "auto-approved" behavior.
- MCP approval-gated operations return `-32006 APPROVAL_REQUIRED` (was `-32603 Internal Error`). Audit status logged as `"approval_required"` instead of `"failure"`.
- `linux-start-UAT.sh` gateway startup changed from `erl` direct to rebar3 prod release binary.
- Default password in test scripts updated to `adminpassword1` (Docker UAT default) with `YUZU_PASS` env var override.

### Documentation
- `docs/user-manual/server-admin.md` — `--data-dir` flag added to CLI flags table and Data Storage section.
- `docs/user-manual/mcp.md` — `execute_instruction` tool added (#23), tool count updated, tier authorization table corrected (operator execution is auto-approved), approval workflow table updated, troubleshooting section clarified.
- `CLAUDE.md` — MCP Phase 1 updated (23 tools, `execute_instruction` documented), Phase 2 reduced to 5 remaining tools.
- `.claude/agents/release-deploy.md` — UAT environment knowledge documented (port topology, data directory separation, Docker file/directory race condition, Grafana dashboard packaging gap, enrollment token API).

## [0.8.1] - 2026-04-11

### Added

#### Testing
- **Comprehensive MCP protocol test suite** (`scripts/e2e-mcp-test.sh`, 140 tests) — exercises all 22 read-only tools, 3 resources, 4 prompts, JSON-RPC protocol methods (initialize, ping, notifications), parameter validation, authentication enforcement, audit trail verification, Phase 2 write tool guards, response format validation, and sequential call state isolation.
- **Expanded REST API E2E test suite** (`scripts/e2e-api-test.sh`, 153 tests) — 26 new sections covering execution statistics, help system, webhook/policy/workflow/instruction-set CRUD, YAML validation, approvals, execution lifecycle with response polling, notifications, agent properties, runtime config, analytics, NVD, inventory queries, directory/discovery, scope engine, 17 settings fragments, 5 dashboard fragments, SSE stream connectivity, static asset delivery, security header verification, MCP endpoint reachability, topology, statistics, license, software deployment, and patch management.
- **Expanded plugin command test** (`scripts/uat-command-test.sh`, ~115 commands across 36 groups) — 12 new plugin groups: example plugin (ping/echo), asset tags, network actions, storage KV CRUD, tags CRUD, TAR extended (sql/configure), vulnerability scanning extended (scan/cve_scan/config_scan), Wake-on-LAN check, chargen traffic generation, HTTP client extended, certificates, and Windows update patch connectivity. Filesystem and IOC tests auto-detect Linux vs Windows and use appropriate paths.

#### Infrastructure
- **Docker Compose local UAT stack** (`docker-compose.local.yml`, gitignored) — uses locally-built images (`yuzu-server:local`, `yuzu-gateway:local`) with full observability (Prometheus, Grafana, ClickHouse). Dashboards provisioned via Docker configs. Separate from `docker-compose.uat.yml` which references ghcr.io images for remote testers.

### Fixed

#### Server
- **Web server connection drops under modest load** — increased cpp-httplib TCP listen backlog from 5 to 128 via `-DCPPHTTPLIB_LISTEN_BACKLOG=128` compile flag. The default backlog of 5 caused the kernel to reject incoming TCP connections when more than 5 were queued for acceptance, resulting in HTTP 000 (connection refused) errors during serial API testing at ~50 requests. Also increased socket read/write timeouts from 5s to 30s to prevent in-progress connections from being dropped under load.
- **Parameterized instruction definitions returning "Unknown Action"** — agent plugins register actions in lowercase but instruction definitions preserved the original case from YAML. Added `std::tolower` normalization at all three creation paths (JSON POST, YAML POST, and the `CommandDispatchFn` adapter).
- **Approval gate not enforced on instruction execution** — `ApprovalManager` was fully implemented but never wired into `workflow_routes::register_routes`. Added approval_mode validation on create/update, fail-closed gate on execute (auto/always/role-gated/unknown), and 202 response for pending approvals.
- **PUT /api/instructions/:id resetting approval_mode** — full-object replacement was overwriting existing fields including `approval_mode`. Changed to partial update preserving unspecified fields.
- **Agent heartbeat deadlock and session races** — fixed heartbeat processing deadlock, session race conditions during re-enrollment, and gateway connection lifecycle issues.

#### Gateway
- **EUnit test cascade failure** (7 modules, 47 tests) — root cause was `yuzu_gw_scale_tests` starting `yuzu_gw_router` and `yuzu_gw_heartbeat_buffer` in test functions without stopping them in cleanup. Fixed cleanup to stop all started processes, added defensive `catch meck:unload` before `meck:new` in all test setups, and defensive `case whereis` for `start_link` calls.
- **`compute_scheduler_util` undef in gauge tests** — function was behind `-ifdef(TEST)` guard but rebar3 test profile didn't propagate `{d, 'TEST'}` to umbrella app compilation. Fixed by unconditionally exporting the function.
- **`agent_count/0` returning `undefined`** — `ets:info(Table, size)` returns `undefined` for nonexistent tables. Added guard clause in `yuzu_gw_registry.erl`.

### Documentation
- `docs/user-manual/rest-api.md` — added 202 response documentation for instruction execute endpoint.
- `docs/user-manual/instructions.md` — documented approval executor-side behavior and action case-insensitivity.
- `docs/yaml-dsl-spec.md` — added case-insensitivity note to action field specification.

## [0.8.0] - 2026-04-09

### Added

#### Security
- **HTTP security response headers (SOC2-C1, #310)** — every HTTP response (dashboard, REST API, MCP, metrics, health probes) now carries six headers: `Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy` (deny-all baseline for camera/mic/geo/usb/etc.), and `Strict-Transport-Security: max-age=31536000; includeSubDomains` on HTTPS deployments. The CSP also appends `upgrade-insecure-requests` on HTTPS.
- New `--csp-extra-sources` CLI flag (env: `YUZU_CSP_EXTRA_SOURCES`) for whitelisting customer CDNs, monitoring beacons, or analytics endpoints. Validated at startup with strict allow-list — rejects control bytes, semicolons, commas, `'unsafe-eval'`, `'strict-dynamic'`, and other unsafe CSP keywords.
- New `server/core/src/security_headers.{hpp,cpp}` module (`yuzu::server::security` namespace) with `HeaderBundle::make()`/`apply()` shared between the production server and the unit/integration tests, ensuring header logic cannot drift between code and tests.
- New `tests/unit/server/test_security_headers.cpp` (38 cases / 146 assertions) and `tests/unit/server/test_static_js_bundle.cpp` (11 cases / 30 assertions) covering CSP construction, validation grammar, end-to-end emission via real `httplib::Server`, and embedded HTMX bundle integrity.
- Resolved security header bundle is logged at INFO at startup so operators can confirm activation: `Security headers active: CSP=N bytes, HSTS=on/off, ...`.

#### Server
- **HTMX 2.0.4 runtime and htmx-ext-sse 2.2.2 extension embedded in the server binary** (`server/core/src/static_js_bundle.cpp`) and served from same-origin `GET /static/htmx.js` and `GET /static/sse.js`. The dashboard works in **air-gapped deployments out of the box** with no internet connectivity required. The HTMX bundle is split into 4 chunks of ≤14000 bytes (MSVC raw string literal limit C2026) and concatenated at static-init into a single `extern const std::string`. Reassembled output is byte-identical to the upstream minified file (50918 bytes). Both upstream packages are 0BSD which imposes no redistribution conditions.

### Changed

#### Security
- **CSP `script-src` is now fully `'self'`-only** with no external CDN allowance — `https://unpkg.com` whitelist removed because HTMX is now served same-origin. Improves SOC 2 supply-chain posture and removes a third-party origin from the dashboard's attack surface.
- All six dashboard-bearing UI templates (`dashboard_ui.cpp`, `settings_ui.cpp`, `compliance_ui.cpp`, `instruction_ui.cpp`, `statistics_ui.cpp`, `topology_ui.cpp`) migrated from `<script src="https://unpkg.com/htmx.org@2.0.4">` to `<script src="/static/htmx.js">`. Same for the SSE extension.

#### UAT Scripts
- `scripts/win-start-UAT.sh` and `scripts/linux-start-UAT.sh`: added `--listen 0.0.0.0:50054` to the server invocation when running with the gateway on the same host. In single-host UAT both server and gateway default to `:50051` for agent gRPC; without the override the server wins the bind and the agent connects directly, bypassing the gateway. Confirmed via `gw-session-` prefix on the agent session ID. Multi-host production deployments are unaffected.

### Fixed

- **Agent registration never reported OS or architecture** — `agents/core/src/agent.cpp` declared compile-time `kAgentOs`/`kAgentArch` constants for every supported platform but never plumbed them into `RegisterRequest.info.platform`. The `Platform` sub-message was always empty, so the server stored `os=""` and `arch=""` for every agent, the dashboard scope panel meta line read `<agent_id> · / · vX.Y.Z` (orphaned `/` between empty fields), and the OTA updater couldn't match agent platform to update binaries. Fix: populate `info->mutable_platform()->set_os/set_arch/set_version` during the registration build. New `get_os_version()` helper uses `RtlGetVersion` via NTDLL on Windows (avoids manifest-based version spoofing) and `uname()` on Unix. Verified end-to-end: `/api/agents` now returns `{os: "windows", arch: "x86_64"}` and the scope panel meta line reads `<agent_id> · windows/x86_64 · vX.Y.Z`.
- **Dashboard scope panel showed "0 agents" under strict CSP** — the SOC2-C1 CSP introduced in commit 7474006 forbade `'unsafe-eval'`, but the dashboard relied on HTMX's `hx-on:` attributes and `hx-vals="js:..."` syntax which both internally call `new Function(...)`. The browser silently blocked the eval, so the scope-list HTMX poll fired without its `selected` parameter and the SSE-driven refresh hooks never ran. Effect: registered agents appeared in the server's API and could execute commands, but never appeared in the dashboard scope panel — even when they responded successfully. Fix: replaced all 8 eval-requiring HTMX attributes in `dashboard_ui.cpp` (3× `hx-on:htmx:sse-message`, 2× `hx-on::after-*`, 1× `hx-on::before-request`, 2× `hx-vals="js:..."`) with equivalent `addEventListener` and `htmx:configRequest` event-listener bindings in the existing inline `<script>` block, which is covered by the `'unsafe-inline'` allowance and does not require `'unsafe-eval'`. Verified end-to-end via headless Chrome: scope panel populates (`agent_count_text: "1 agent"`, `scope_list_child_count: 6`) and `browser_errors` count drops from 1 to 0 in the Synthetic UAT report.
- **Dashboard `agents` map was indexed wrong** — the `/fragments/scope-list` endpoint returns the agent list as a JSON array of `{agent_id, hostname, ...}` objects, but the dashboard's JS expected an object keyed by `agent_id`. `agentDisplayName(agentId)` and `cmdPalette.agentsCache` both silently failed to look up agents by ID. Fix: convert the array to a `{agent_id: agentObj}` map in the new `htmx:afterSwap` handler before assigning to the global `agents` variable.
- Closed M11 in `Release-Candidate.local.MD` risk register: HTMX no longer loaded from external `unpkg.com` CDN.

### Documentation

- `docs/user-manual/security-hardening.md` rewritten with: a six-row CSP/HSTS/X-Frame-Options/X-Content-Type-Options/Referrer-Policy/Permissions-Policy table, the `'unsafe-inline'` rationale, embedded HTMX runtime explanation (replacing the old "unpkg.com allowance" section), `--csp-extra-sources` validation behavior with rejection examples, "Behind a reverse proxy" CSP-intersection note, bandwidth note (~700-900 bytes/response overhead), and a corrected `curl | grep -E` verification example.
- `CLAUDE.md` Authentication & Authorization section updated to document the SOC2-C1 implementation, the local HTMX embedding, and the validated `--csp-extra-sources` flag.
- `docs/test-coverage.md` registers the new `test_security_headers.cpp` and `test_static_js_bundle.cpp` suites.
- `docs/user-manual/rest-api.md` cross-links to the new HTTP Security Response Headers section.
- `docs/user-manual/server-admin.md` documents the new `--csp-extra-sources` flag with rejection grammar.

## [0.7.1] - 2026-04-08

### Added

#### Server
- ClickHouse analytics event drain with CLI configuration parameters
- TAR data warehouse: typed SQLite tables, SQL query engine, rollup aggregation
- Instruction execute API endpoint for programmatic command dispatch
- Rich Grafana dashboard templates for fleet analytics and observability
- Ctrl+K command palette enabled on all dashboard pages
- Default evaluation credentials (`admin/administrator`, `user/useroperator`) documented with change-immediately warning

#### Infrastructure
- Enterprise readiness plan for SOC 2 compliance and first customer preparation
- Enterprise installers: DEB and RPM packages with systemd integration
- Pre-release QA pipeline with release workflow artifact validation
- Docker UAT environment with dep-cached builds and automated tests
- Windows UAT environment with Prometheus + Grafana observability stack
- Puppeteer synthetic UAT tests for end-to-end browser validation
- Pre-populated CI Docker images for faster build times
- Self-hosted runner infrastructure (Linux, Windows)
- NuGet binary cache as fallback for vcpkg package caching
- 3 new governance agents: compliance-officer, SRE, enterprise-readiness
- `scripts/docker-release.sh` — local Docker build + push script with `--dry-run` and `--build-only` flags

### Changed

#### Networking — Port Standardization
- **Port 50051 is now the universal agent door** — server listens on 50051 in standalone mode, gateway listens on 50051 in scaled deployments. Agents always connect to `<host>:50051` regardless of topology.
- Gateway agent-facing port changed from 50061 → 50051 (all configs, compose files, scripts, docs)
- Stale port 50054 references corrected to 50051 across 25 files
- Standalone Docker Compose (`docker-compose.yml`) simplified — server + agent only, no gateway required
- Gateway Docker Compose (`docker-compose.full-uat.yml`) updated for gateway-mode server deployment

#### Docker
- Server Dockerfile defaults to zero-arg startup: `--listen 0.0.0.0:50051 --no-tls --no-https --web-address 0.0.0.0 --web-port 8080 --config /var/lib/yuzu/yuzu-server.cfg`
- Gateway Dockerfile upgraded from Erlang/OTP 27 to 28 (pinned digest)
- Gateway Dockerfile exposes health port 8081
- Agent Docker image removed from release pipeline (use native installers instead)
- Multi-arch Docker builds removed (linux/amd64 only; macOS agent uses native installer)

#### Build & CI
- Release workflow gateway build upgraded from OTP 27 to OTP 28

### Fixed

#### Security — CRITICAL
- **SIGBUS crash in SQLite stores under concurrent HTTP load (#329)** — all 30 stores migrated from `sqlite3_open()` to `sqlite3_open_v2()` with `SQLITE_OPEN_FULLMUTEX`, enabling SQLite's serialized threading mode per-connection. Runtime `sqlite3_threadsafe()` guard added at server and agent startup. WAL mode and `busy_timeout` pragma consistency enforced across all stores.

#### Security — MEDIUM
- XSS, error information leakage, and missing SQLite pragmas (governance findings)
- MCP thread-safety race conditions identified and fixed via ThreadSanitizer
- CEL list index undefined behavior on out-of-bounds access

#### Server
- Gateway command forwarding: IPv6 port conflict resolution and retry logic
- ClickHouse analytics drain connection and ingest reliability
- Enter key form submission fixed on all dashboard pages
- Patch manager test crash on Windows

#### Build & CI
- macOS CI upgraded to macos-15 (Xcode 16) with `clock_cast` and CTAD compatibility fixes
- Clang upgraded 18 → 19 with CoreFoundation linkage and `from_chars` portability fixes
- ARM64 cross-compile: pkg-config path resolution for vcpkg
- Windows: migrated to `x64-windows-static-md` vcpkg triplet, static gRPC/abseil linkage fixes (LNK2005/LNK2019)
- Windows system libraries migrated to `#pragma comment(lib)` for build reliability
- LTO disabled for problematic configurations (Linux x64 self-hosted, Clang 19 release)
- Apple Clang: deduction guide for `ScopeExit`, `execvpe` platform guard, `environ` linkage
- CI concurrency: per-SHA group to prevent self-cancellation
- InnoSetup plugin paths corrected for Windows installer builds
- Linux ARM64 cross-compile removed from CI (no ARM64 runner available)

## [0.7.0] - 2026-03-30

### Added

#### Gateway
- Gateway defaults moved to own port range (5006x) — server, gateway, and agent can now run on the same box without port overrides
  - Agent-facing gRPC: 50051 → 50061
  - Management gRPC: 50052/50053 → 50063
  - Health HTTP: 8080 → 8081 (consistent across dev and prod configs)
- UAT enrollment token automatically saved to `/tmp/yuzu-uat/enrollment-token` for CT suite consumption

#### Server
- Semantic YAML syntax highlighting in the Instructions editor preview pane
  - `type: question` renders green, `type: action` orange, `approval: required` red, `concurrency: single/serial` yellow
  - Color legend now matches actual preview output
- YAML editor value color changed from near-blue (#a5d6ff) to gray-white (#c9d1d9) for clearer key/value contrast

#### Infrastructure
- Linux UAT script (`scripts/linux-start-UAT.sh`) with full server-gateway-agent stack, 6 automated connectivity and command round-trip tests
- `real_upstream_SUITE` CT suite auto-reads enrollment token from UAT environment (no manual token setup needed)

### Fixed
- YAML editor preview now triggers on paste events (changed HTMX trigger from `keyup` to `input` for cross-browser compatibility with Safari/context-menu paste)
- Stale database directories no longer break session authentication on server restart (UAT script wipes state on each run)
- Help command display and result table clearing on HTMX dashboard
- Enrollment token `max_uses` increased from 10 to 1000 to support CT suite test runs

## [0.6.0] - 2026-03-28

### Changed (Architecture — God Object Decomposition)

- **server.cpp decomposed from 11,437 to 4,411 LOC** — ServerImpl is now a slim composition root
- 24 new files extracted (9,008 LOC total), each independently compilable and testable
- Route modules use callback-injection pattern: `register_routes(httplib::Server&, AuthFn, PermFn, AuditFn, ...stores...)`
- Extracted route modules: `auth_routes`, `settings_routes`, `compliance_routes`, `workflow_routes`, `notification_routes`, `webhook_routes`, `discovery_routes`
- Extracted inner classes: `agent_registry`, `agent_service_impl`, `gateway_service_impl`, `event_bus`
- `InstructionDbPool` RAII wrapper replaces raw `sqlite3*` pointer for shared instruction DB (fixes G3-ARCH-T2-002)
- `route_types.hpp` provides shared `AuthFn`/`PermFn`/`AuditFn` callback type aliases
- `AgentServiceImpl` mutable members moved from public to private
- Governance findings G3-ARCH-001, G3-ARCH-T2-001, G3-ARCH-T2-002 marked FIXED in code review register

### Fixed
- Scoped API tokens with null `TagStore` now return 503 instead of silently granting access
- `InstructionDbPool` member declaration order corrected — destroyed after all consumers

### Added
- Wave 8: Release hardening (schema migrations, env var config, rate limiting, log rotation, health endpoints)
- MCP (Model Context Protocol) server embedded at `/mcp/v1/` with JSON-RPC 2.0 transport
- 22 read-only MCP tools: list_agents, get_agent_details, query_audit_log, list_definitions, get_definition, query_responses, aggregate_responses, query_inventory, list_inventory_tables, get_agent_inventory, get_tags, search_agents_by_tag, list_policies, get_compliance_summary, get_fleet_compliance, list_management_groups, get_execution_status, list_executions, list_schedules, validate_scope, preview_scope_targets, list_pending_approvals
- 3 MCP resources: yuzu://server/health, yuzu://compliance/fleet, yuzu://audit/recent
- 4 MCP prompts: fleet_overview, investigate_agent, compliance_report, audit_investigation
- Three-tier MCP authorization model (readonly, operator, supervised) enforced before RBAC
- MCP token support via existing API token system with mandatory expiration (max 90 days)
- `--mcp-disable` kill switch and `--mcp-read-only` mode CLI flags (+ YUZU_MCP_DISABLE / YUZU_MCP_READ_ONLY env vars)
- Audit trail integration for all MCP tool calls with `mcp_tool` field on AuditEvent
- MCP unit tests covering JSON-RPC parsing, tier policy, token integration, and store interactions

### Changed (Capability Audit — 2026-03-26)

- Capability map audited against codebase: 32 capabilities marked "not started" or "partial" were already implemented
- Corrected total from 96/142 (68%) to **150/184 (82%)**
- Updated per-domain summary counts and progress bars
- Plugin coverage matrix expanded from 29 to 44 entries with all plugin categories

#### Capabilities confirmed implemented (previously marked not started)
- **Network:** WiFi scanning (4.6), Wake-on-LAN (4.7), ARP subnet discovery (4.10)
- **User/Session:** Primary user determination (6.2), local group membership (6.3), connection history (6.4), active sessions (6.5)
- **Patch Management:** Deployment orchestration (8.3), per-device status tracking (8.4), metadata retrieval (8.5), fleet compliance summary (8.7)
- **Security:** Device quarantine with whitelist (9.6), IOC checking (9.7), certificate inventory (9.8), quarantine status tracking (9.9)
- **File System:** ACL/permissions inspection (10.7), Authenticode verification (10.8), find-by-hash (10.14)
- **Inventory:** Table enumeration (15.3)
- **Auth:** Management-group-scoped roles (18.4), AD/Entra integration via Graph API (18.6)
- **Device Mgmt:** Hierarchical management groups (19.4), device discovery (19.5), custom properties (19.6), deployment jobs (19.7)
- **Notifications:** System notifications (21.3), webhook event subscriptions (21.4)
- **Infrastructure:** Product packs with Ed25519 signing (22.8)

#### Capabilities upgraded from partial to done
- **Platform Configuration (22.4):** RuntimeConfigStore with safe-key whitelist, no-restart updates
- **Gateway / Scale-Out (22.5):** Full Erlang/OTP gateway with circuit breaker, heartbeat batching, health endpoints
- **REST API (24.3):** Versioned `/api/v1/` prefix, 70+ endpoints, OpenAPI spec, CORS allowlist
- **Data Export (24.5):** CSV and JSON export endpoints with Content-Disposition headers

#### Capabilities upgraded from not started to partial
- **Reboot Management (8.6):** `reboot_if_needed` flag on patch deployments (no scheduled reboot workflow yet)
- **System Health Monitoring (22.1):** /livez, /readyz probes + Prometheus metrics (no CPU/memory/queue monitoring yet)

### Added (Governance — 2026-03-28)
- 4 governance review agents: happy-path, unhappy-path, consistency-auditor, chaos-injector
- 7-gate governance process (expanded from 5 gates) with mandatory correctness & resilience analysis
- REST API v1 documentation for 25 previously undocumented endpoints (inventory, execution statistics, device tokens, software deployment, license management, topology, fleet statistics, file retrieval, OpenAPI spec)
- Agent reconnect loop with exponential backoff (1s to 5min) on registration or stream failure
- Semver downgrade protection in OTA updater — rejects older/equal versions
- Per-plugin KV namespace isolation — `PluginContextImpl` with correct `plugin_name` per plugin

### Fixed (Full Governance Review — ~380 findings across 492 files)

#### Security — CRITICAL (5 fixed)
- OIDC JWT signature verification via JWKS — forged ID tokens were previously accepted
- 4 SQLite stores had mutexes declared but never locked (tag, discovery, instruction, deployment)

#### Security — HIGH (18 fixed)
- Replaced `std::regex` with RE2 in CEL `.matches()` and scope `MATCHES` operator (ReDoS)
- CEL evaluation wall-clock timeout (prevents infinite loops in policy evaluation)
- 11 SQLite stores gained shared_mutex protection for thread-safe concurrent access
- RBAC permission cache to reduce per-request SQL query amplification
- API token IDs extended from 12-char to 24-char hex (96-bit collision resistance)
- MCP kill switch now evaluated at runtime, not just startup
- ApprovalManager TOCTOU fixed with mutex + atomic WHERE on concurrent approve/reject
- MCP read_only_mode captured by reference for runtime toggle support
- Prometheus histogram `observe()` fixed — was double-counting across all bucket boundaries
- Agent double plugin shutdown prevented on normal exit
- Stagger/delay capped at 5min each to prevent thread pool worker exhaustion

#### Security — MEDIUM (25 fixed)
- Minimum password length enforced (12 characters)
- Expired sessions opportunistically reaped
- Token generation switched from mt19937_64 to CSPRNG (RAND_bytes)
- Security response headers added (X-Frame-Options, HSTS, X-Content-Type-Options)
- CSRF protection via Origin header validation
- RBAC `set_permission` validates effect as "allow" or "deny"
- OIDC pending challenges capped at 1000 entries with expiry cleanup
- MCP `/health` resource now requires RBAC check
- Dead CORS helper removed (was reflecting arbitrary Origin)
- Execution statistics limit clamped to 1000
- CEL recursion depth reduced from 64 to 16; string concatenation capped at 64 KiB
- Unknown characters in CEL lexer return Error token instead of silent skip
- Scope engine NOT recursion protected with DepthGuard
- Response/audit store cleanup threads wrapped in proper mutex locks
- Fleet compliance cache writes corrected from shared_lock to unique_lock
- Non-thread-safe static RNGs made thread_local
- Deleted user sessions now invalidated; session role updated on role change
- Offline agents get 24hr staleness TTL on compliance status
- MCP automation gets separate rate limit bucket from dashboard
- Approval workflow: 7-day TTL and 1000 pending cap
- CEL unresolved variables produce tri-state (true/false/error) instead of silent false

#### Agent & Plugins (10 fixed)
- `SecureZeroMemory` on CNG + CAPI intermediate key blobs after cert store export
- Symlink rejection before plugin dlopen
- OTA updater download size capped at 512 MiB
- Content distribution staging directory set to owner-only permissions
- Hash re-verification before executing staged content
- HTTP client SSRF protection extended to CGNAT (100.64/10) and benchmarking (198.18/15) ranges
- HTTP client response body capped at 100 MiB
- `script_exec` output capped at 16 MiB; `setsid()` + `kill(-pid, SIGKILL)` for process group cleanup
- `script_exec` child environment sanitized (PATH, HOME, USER, LANG, LC_ALL, TERM, TZ only)
- Certificate plugin command injection fixed: hex-only thumbprint validation, safe path checks, temp file for PEM parsing

#### Gateway
- 5 dialyzer warnings resolved (ctx dependency, contract violations, dead code)
- gpb bumped 4.21.2 → 4.21.7 for OTP 28 compatibility
- Gateway proto synced from canonical (added stagger_seconds, delay_seconds)

#### Documentation
- REST API v1 now 100% documented (was 48% undocumented)
- Full governance review document with cross-tier finding register
- Erlang gateway build pitfalls documented in CLAUDE.md

### Fixed (RC Sprint — 52 findings resolved)

#### Security (CRITICAL + HIGH)
- Gateway now uses TLS for upstream gRPC connections (was plaintext)
- Gateway health/readiness endpoints (`/healthz`, gRPC Health Check)
- Gateway circuit breaker with exponential backoff for upstream failures
- AnalyticsEventStore thread safety — mutex protection on query methods
- Proto codegen reproducibility — protoc version validation
- Web UI binds to `127.0.0.1` by default (was `0.0.0.0`)
- HTTPS enabled by default — operators must provide cert/key or use `--no-https`
- `/metrics` requires authentication for remote access (localhost exempt, `--metrics-no-auth` override)
- Private key file permission validation on Unix (refuses group/others-readable)
- Certificate hot-reload with PEM validation, cert/key match, and permission checks
- CORS headers on all `/api/` endpoints via `set_post_routing_handler`

#### Server
- REST API unit test suite (previously 0 tests for 1,355 LOC, 31+ endpoints)
- JSON error envelope on all error responses: `{"error":{"code":N,"message":"..."},"meta":{"api_version":"v1"}}`
- Health probe contract: `/livez` and `/readyz` return `{"status":"..."}`

#### Gateway
- Command duration metrics (was hard-coded to 0)
- Backpressure alerting for agent send buffer
- grpcbox dependency pinned
- Graceful shutdown with in-flight command draining
- .appup files for hot code upgrades

#### Build & Packaging
- Binary signing for Windows (Authenticode) and macOS (codesign + notarization)
- Sanitizer CI jobs (ASan+UBSan, TSan)
- Release workflow artifact validation with SHA256 checksums
- deb/rpm package integration
- Docker health checks in all 3 Dockerfiles
- Docker base images pinned to sha256 digests
- buf lint + breaking change CI job for proto compatibility

#### Agent & Plugins
- Agent UUID generation uses CSPRNG (RAND_bytes/BCryptGenRandom, was Mersenne Twister)
- Plugin ABI runtime version check — sdk_version field, ABI v3
- OIDC client secret moved to Authorization: Basic header (RFC 6749 §2.3.1)

#### Build Hardening
- Compiler hardening flags: `_FORTIFY_SOURCE=2`, `-fstack-protector-strong`, full RELRO, PIE
- MSVC `/DYNAMICBASE /HIGHENTROPYVA /NXCOMPAT` for ASLR + DEP

#### Documentation
- macOS x64 limitation documented in README and user manual
- cliff.toml added for git-cliff changelog automation

## [0.1.0] - 2026-03-21

### Added

#### Server
- HTMX-based web dashboard with dark theme, role-based context bar, command palette
- REST API v1 with CORS support and OpenAPI documentation (133+ endpoints)
- Server-side response persistence with filtering, pagination, and aggregation (SQLite)
- Audit trail system with structured JSON events and configurable retention
- Device tagging system with hierarchical scope expression engine (AND/OR/NOT/LIKE/IN)
- Instruction engine: YAML-defined definitions, sets, scheduling, approval workflows
- Workflow primitives (if, foreach, retry) for multi-step instruction chains
- Policy engine with CEL-like compliance expressions and fleet compliance dashboard
- Granular RBAC with 6 roles, 14 securable types, per-operation permissions
- Management groups for hierarchical device grouping and access scoping
- OIDC SSO integration (tested with Microsoft Entra ID)
- Token-based API authentication (Bearer and X-Yuzu-Token)
- System notifications (in-app) and event subscriptions (webhooks with HMAC-SHA256)
- Product packs with Ed25519 signature verification for bundled YAML distribution
- Active Directory / Entra ID integration via Microsoft Graph API
- Agent deployment jobs and patch deployment workflow orchestration
- Device discovery (subnet scanning with ARP + ping sweep)
- Custom properties on devices with schema validation
- Runtime configuration API with safe key whitelist
- Inventory table enumeration and item lookup
- NVD CVE feed sync with vulnerability matching
- ClickHouse and JSONL analytics event drains
- Prometheus /metrics endpoint with fleet health gauges and request histograms
- CSV and JSON data export
- HTTPS for web dashboard with HTTP→HTTPS redirect
- Error code taxonomy (1xxx-4xxx)
- Concurrency enforcement (5 modes)

#### Agent
- Plugin architecture with stable C ABI (version 2, min 1) and C++ CRTP wrapper
- 44 plugins: hardware, network, security, filesystem, registry, WMI, WiFi, WoL, and more
- Trigger engine: interval, file_change, service_status, event_log, registry_change, startup
- Agent-side key-value storage (SQLite-backed, per-plugin namespaces)
- HTTP client plugin (cpp-httplib, no shell) with SSRF protection
- Content staging and execution (CreateProcessW/fork+execvp, no system())
- Desktop user interaction: notifications, questions, surveys, DND mode (Windows)
- Timeline Activity Record (TAR): persistent process tree, network, service, user session tracking
- OTA auto-update with hash verification and rollback
- Bounded thread pool (4-32 workers, 1000 max queue) with output buffering
- Windows certificate store integration (CryptoAPI/CNG)
- Tiered agent enrollment (manual approval, pre-shared tokens, platform trust stubs)

#### Gateway
- Erlang/OTP gateway node with process-per-agent supervision
- Heartbeat buffer (dedicated gen_server, batched upstream flush)
- Consistent hash ring for multi-gateway deployments
- Prometheus metrics endpoint

#### Infrastructure
- Meson + vcpkg build system with cross-platform support (Windows/Linux/macOS/ARM64)
- CI matrix: GCC 13, Clang 18, MSVC, Apple Clang, ARM64 cross-compile
- AddressSanitizer, ThreadSanitizer, and code coverage CI jobs
- Docker deployment (3 multi-stage Dockerfiles, docker-compose.yml)
- Systemd service units with security hardening
- GitHub Actions release workflow (3 platforms, SHA256 checksums)
- 628+ unit test cases across 44 test files

### Security
- 51 security findings identified and fixed (5 CRITICAL, 15 HIGH, 15 MEDIUM, 16 LOW)
- Eliminated 4 CRITICAL command injection vulnerabilities (replaced system()/popen() with safe alternatives)
- mTLS for agent-server gRPC with certificate chain validation
- PBKDF2 password hashing for local authentication
- Command-line redaction in TAR (configurable patterns)
- SSRF protection with private IP range blocking
- Input validation on all REST API endpoints
- Registry sensitive path audit logging
- PRAGMA secure_delete on TAR database

