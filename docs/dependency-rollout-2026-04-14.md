# Dependabot Rollout — April 2026

**Status:** in progress
**Started:** 2026-04-14
**Owner:** TBD per tier (see Resume Pointer)
**Closes:** #363 (rollout completion), #366 follow-up (CODEOWNERS)
**Driver PR (foundation):** #372 (merged 2026-04-14)

## Why this doc exists

This is a long, multi-tier rollout with expected breakages — primarily
node20 → node24 runner-version interactions on self-hosted hosts. Yuzu's
context window will not survive the entire rollout in one session, so
this file is the **durable state of record**. Every Claude session
working on this rollout should:

1. Read this file end-to-end before doing anything.
2. Update the **Resume Pointer** before context handoff.
3. Append to the **Event Log** at the bottom on every state change.
4. Cross-link tasks via the in-session TaskList (`TaskList` tool) and the
   GitHub PR numbers in the **Tier Table**.

When this rollout closes, the doc converts to a brief lessons-learned
addendum and the live tracking sections collapse.

## Background

Yuzu had 7 open Dependabot PRs targeting `main` against a stale base
that lacked the `0fe5eac` LNK2038 Windows debug fix (still on `dev` as
of 2026-04-14, awaiting the next dev→main reconcile). All 7 had failing
or stale CI for that reason. Four are major Node 24 action bumps
(`actions/cache@v5`, `actions/upload-artifact@v7`,
`actions/download-artifact@v8`, `actions/github-script@v8`,
`codecov/codecov-action@v6`) that require GitHub Actions Runner
≥ 2.327.1 on every host that executes them — including the self-hosted
`yuzu-wsl2-linux` and `yuzu-local-windows` runners.

#372 (merged 2026-04-14) added `target-branch: dev` to every
Dependabot ecosystem entry so future PRs route correctly, plus the
`pip` ecosystem + scheduled vcpkg baseline workflow that closed the
automation gap from #363. The 7 existing PRs still target `main` until
they are explicitly recreated.

## Tier Table

PR numbers in **bold** are the *original* PRs against `main`. After
recreate, the new PR numbers go in the **Recreated As** column.

| Tier | Task | Original PR | Recreated As | Action / Bump | Risk | Self-hosted? | Status |
|---|---|---|---|---|---|---|---|
| 0a  | #1  | —    | — | Verify runners ≥ 2.327.1 | Gate | Yes | **done** (both 2.333.1) |
| 0b  | n/a | —    | — | Migrate ci.yml Windows MSVC → yuzu-local-windows (#374) | Gate | **Yes** | plumbing done (commit `3960f46`); exposed #375 |
| 0bb | #14 | —    | — | Fix Windows MSVC LNK2038 (#375) — option D: static triplet + hand-rolled `cxx.find_library()` for grpc/protobuf | **Gate (P0)** | Yes | in progress (folded into #373) |
| 0c  | #2  | —    | — | `@dependabot recreate` × 7 | Gate | n/a | **PAUSED on #375** |
| 1  | #3  | **#335** | TBD | `ubuntu` digest 186072b → 84e77de | Low | No | pending |
| 1  | #4  | **#248** | TBD | `alpine` 3.22 → 3.23 (gateway) | Low | No | pending |
| 2  | #5  | **#300** | TBD | `codecov-action` 5 → 6 | Med (node24 but github-hosted) | No | pending |
| 3  | #6  | **#243** | TBD | `actions/github-script` 7 → 8 | Med-High | **Yes** | pending |
| 3  | #7  | **#241** | TBD | `actions/cache` 4 → 5 | High (19 sites) | **Yes** | pending |
| 4  | #8  | **#242** | TBD | `actions/upload-artifact` 4 → 7 | High | **Yes** | pending |
| 4  | #9  | **#250** | TBD | `actions/download-artifact` 4 → 8 | **Highest** (digest=error) | **Yes** | pending |
| 5  | #11 | n/a  | — | Centralize Dockerfile meson pins | Low | n/a | pending |
| —  | #10 | n/a  | — | Standing breakage triage | n/a | n/a | pending |

Task IDs (`#N`) refer to the in-session `TaskList`, **not** GitHub
issues. `gh issue view <number>` and `gh pr view <number>` are
unambiguous because they share the same numeric space — task IDs are
always single or double-digit and namespaced to the rollout doc.

## Phase 0 — Gates

### 0a · Verify self-hosted runner versions (Task #1)

**Goal:** confirm both `yuzu-wsl2-linux` and `yuzu-local-windows`
runners are at ≥ 2.327.1 (Node 24 minimum). The GitHub API does not
expose runner binary version, so this requires a shell on each box.

**Commands (run by operator):**
```bash
# yuzu-wsl2-linux (WSL2 on Shulgi 5950X)
cd ~/actions-runner && ./config.sh --version

# yuzu-local-windows (native Windows on Shulgi 5950X)
cd "$HOME/actions-runner" ; ./config.cmd --version  # PowerShell
# or in MSYS2 bash:
cd ~/actions-runner && ./config.sh --version
```

**If either is < 2.327.1:**
1. Verify the runner is idle: `gh api repos/Tr3kkR/Yuzu/actions/runners`
   → `busy:false`. **Do not upgrade while busy** — a mid-job
   reinstall corrupts the workdir and any in-flight CI.
2. Stop the runner service.
3. Download the latest runner package from
   https://github.com/actions/runner/releases.
4. Re-bootstrap with the same registration token (no
   `./config.sh remove` needed for in-place upgrades — see runner docs).
5. Restart the service and confirm with `./config.sh --version`.
6. Capture the before/after versions in the Event Log.

**Blocks:** Tasks #6, #7, #8, #9 (Tier 3 + Tier 4).

### 0b · Recreate Dependabot PRs against dev (Task #2)

**Goal:** retarget the 7 existing PRs at `dev` so they pick up the
LNK2038 fix and any other pending dev-only changes on rebase.

**Commands:**
```bash
for n in 241 242 243 248 250 300 335; do
  gh pr comment "$n" --body "@dependabot recreate"
done
```

**Expected outcome:** Dependabot closes each PR within ~5 min and
opens a new PR against `dev`. The new PR numbers go in the
**Recreated As** column above and feed into the per-tier merge tasks.

**Blocks:** Tasks #3 through #9.

## Phase 1 — Docker base bumps (Tasks #3, #4)

Lowest-risk tier. Both bumps are docker-only, no Node 24 exposure.
Independent — can merge in either order once green.

- **#3 (was #335)** — `ubuntu:24.04` digest bump for Dockerfile.agent +
  Dockerfile.server. Risk: apt package version drift on the new digest.
- **#4 (was #248)** — `alpine 3.22 → 3.23` for Dockerfile.gateway
  runtime stage. Risk: musl/openssl/libstdc++ minor version bump that
  the gateway release links against. Local sanity: `docker build -f
  deploy/docker/Dockerfile.gateway -t yuzu-gw-test .`.

**Validation gate before merging:** the recreated PR's CI run on the
`dev` base must be fully green (Linux, Windows, macOS). If any platform
fails, that's the breakage — file under Task #10 and triage before
merging.

## Phase 2 — Single-site github-hosted Node 24 (Task #5)

- **#5 (was #300)** — `codecov-action 5 → 6`. Single call site at
  `ci.yml:607` in the Coverage (GCC 13) job, runs on `ubuntu-24.04`
  (github-hosted, auto-updated runner — Node 24 already supported).
  No self-hosted exposure. The recreate against `dev` should turn
  the historical "all 4 jobs FAIL" into clean green.

**Why this tier exists separately:** it lets the rollout build
confidence on a real Node 24 action without yet exposing self-hosted
runners. If codecov@v6 surfaces an unexpected secret/input rename, that
breakage is github-hosted-only and easy to revert.

## Phase 3 — Multi-site Node 24 (Tasks #6, #7)

This is where self-hosted runner exposure begins. **Task #1 must
complete before either of these merges.**

### #6 (was #243) — actions/github-script 7 → 8

- 11 call sites: ci.yml (6 github-hosted), codeql.yml (1, **matrix
  including self-hosted Windows**), release.yml (4, self-hosted Linux × 3 +
  github-hosted Windows × 1).
- Post-merge validation:
  ```bash
  gh workflow run codeql.yml --ref dev
  gh run watch  # follow the most recent run
  ```
  Watch the self-hosted Windows matrix slot — that's the canary for the
  runner-version gate. Expected fail mode: `Error: This action requires
  a GitHub Actions runner of version 2.327.1 or higher`. If that fires,
  immediately `gh pr revert <new-num> --base dev`, file the breakage
  under Task #10, and reopen Task #1 to upgrade the runner.
- release.yml self-hosted exposure won't be exercised until the next
  release tag — flag a follow-up watch in the Event Log.

### #7 (was #241) — actions/cache 4 → 5

- 19 call sites — highest blast radius of the cache-class actions.
- Same self-hosted exposure pattern as #6 plus an additional cache-key
  compatibility concern. cache@v5 should be backward-compat on cache
  reads but watch for unexplained cache-miss surges in the next CI run
  (signal that key derivation changed).
- Post-merge validation: dispatch codeql.yml again. By this point the
  runner-version gate should be settled.

## Phase 4 — Artifact actions (Tasks #8, #9)

Highest-impact tier. These touch the release path.

### #8 (was #242) — actions/upload-artifact 4 → 7

- 18 call sites: ci.yml × 1, pre-release.yml × 7, release.yml × 8,
  **sanitizer-tests.yml × 2 (self-hosted yuzu-wsl2-linux)**.
- v6 = Node 24, v7 = ESM module + opt-in `archive: false` direct upload
  (we don't use it).
- Post-merge validation:
  ```bash
  gh workflow run sanitizer-tests.yml --ref dev -f suite=both
  gh run watch
  ```
  Watch the artifact upload step on both ASan and TSan jobs — that
  exercises upload-artifact@v7 against the self-hosted Linux runner.
  Failure mode: ESM resolution errors on the runner's bundled node, or
  the same runner-version error.

### #9 (was #250) — actions/download-artifact 4 → 8

- 6 call sites, all in release path: pre-release.yml × 5, release.yml × 1.
- **v8 changes `digest-mismatch` default from warning to error.** Any
  artifact whose hash doesn't match the server's recorded hash will now
  fail the job hard. Previously this was silently logged.
- Post-merge validation: the next pre-release run is the canary. If any
  artifact fails with "digest mismatch" that is a real artifact
  corruption signal that was previously masked — **do not just downgrade
  to warning**, investigate root cause (network truncation, upload
  retry race, etc.). If no pre-release is queued, manually dispatch:
  ```bash
  gh workflow run pre-release.yml --ref dev
  ```

## Phase 5 — Cleanup (Task #11)

After all tiers merge, centralize the 5 Dockerfile meson pins
(`deploy/docker/Dockerfile.{agent,server,ci,ci-linux,runner-linux}`)
on `requirements-ci.txt` so future Dependabot meson bumps propagate
without manual sync. Also remove the `ARG MESON_VERSION=1.9.2`
declarations from `Dockerfile.ci-linux` and `Dockerfile.runner-linux`,
and add `requirements-ci.txt` to the `ci-runner-image.yml` paths
trigger.

## Standing — Breakage triage (Task #10)

For every breakage encountered during any tier:
1. File a GitHub issue with title `[deps-rollout] <action>: <symptom>`.
2. Tag with `regression`, `dependencies`, and the relevant tier label.
3. Capture: workflow + job, error message, surface area, proposed fix,
   whether the breakage was in the action itself or in an interaction
   with our setup.
4. Cross-reference the issue from this doc's Event Log.
5. Decide: hotfix-and-continue, revert-and-defer, or accept-as-known.

## Resume Pointer

> **Session handoff 2026-04-14 ~18:25 UTC.** Option D C++ link is
> solid on Windows MSVC — every C++ target compiles and links on
> both debug and release, every C++ test passes. The last blocking
> gate is `yuzu:gateway eunit` / `yuzu:gateway ct` on Windows, and
> the latest iteration of `scripts/test_gateway.py` (commit `6d8aa5a`,
> pushed at handoff) removes the `b33f1df` pre-fetch step that was
> itself causing a Windows-only regression. The in-flight fix chain
> is now: `220e7bd` (option D C++ clean, gateway EUnit hex.pm flake)
> → `b33f1df` (pre-fetch retry added, **regressed** on Windows with
> cover-races-compile on `gateway_pb.beam`) → `d20852b` (docs-only
> handoff) → `6d8aa5a` (drop `--deps_only` pre-fetch, bump actual
> test retry to 4 attempts).
>
> **Windows failure that `6d8aa5a` fixes.** On push CI run
> `24412646165` the `b33f1df` pre-fetch produced a consistent ~10s
> failure in BOTH Windows MSVC variants:
> - release → gateway **EUNIT** failed at 10.40s with
>   `{cover,get_abstract_code,...,{file_error,".../gateway_pb.beam",enoent}}`
> - debug → gateway **CT** failed at 10.50s with the same cover
>   stack (just a different test crossed the cover race first).
>
> Root cause per the `6d8aa5a` commit message: the test profile has
> `cover_enabled => true`, so eunit/ct fire cover instrumentation
> immediately after `===> Compiling yuzu_gw`. On Linux/macOS the
> `_build/test/lib/yuzu_gw/src/` is a symlink to `apps/yuzu_gw/src/`
> and the compile pipeline is synchronous, so cover always sees a
> consistent ebin. On Windows symlinks are out, the pre-fetch leaves
> `_build/test/lib/yuzu_gw/` in a state where the subsequent
> incremental compile races cover's `pmap_spawn` scan — `gateway_pb`
> (the gpb-generated proto module) is in cover's module list but
> `gateway_pb.beam` is not yet on disk when cover's `beam_lib` read
> fires, and cover blows up before the parallel compile worker
> finishes writing. Dropping the pre-fetch eliminates the state
> handoff and keeps `run_with_retry` on the actual test invocation
> for hex.pm flake coverage. The `yuzu-local-windows` hex cache is
> already warm from prior runs so pre-fetch was redundant.
>
> **Next action:** wait for the push CI run on `6d8aa5a` (and the
> paired PR run on the same head — once pushed they should be the
> latest entries in `gh run list --workflow=ci.yml --limit=5`).
> Expected outcome on Windows:
> - Vcpkg install: cache hit (only script change since 220e7bd)
> - Configure / build: same as 220e7bd, debug + release link clean
> - gateway EUNIT: **148/148 PASS** (validated locally with edited
>   script, 24s elapsed)
> - gateway CT: PASS, or 6/7 with the existing OTP 25 CT I/O race
>   detection swallowing a teardown crash
>
> If green: **merge PR #373** (squash or merge-commit, see #369 for
> the reconcile pattern), **close #375** with a pointer at
> `.claude/agents/build-ci.md` "Windows MSVC static-link history
> and #375" as the lessons-learned record, **dispatch Task #2** —
> the dependabot recreate cycle. Tasks #3 → #9 unblock in tier
> order per the Tier Table.
>
> If red on the same cover error: the `6d8aa5a` hypothesis is wrong
> and the issue is pre-existing rebar3/cover-on-Windows behavior,
> not the pre-fetch. Next step would be adding `--jobs 1` to the
> rebar3 test commands to force serialized compilation, OR adding
> an explicit `rebar3 as test compile` step between the wipe and
> the eunit invocation (i.e., put the pre-fetch back but without
> `--deps_only`).
>
> If red on a new C++ link error: it's a new transitive lib
> surfacing in option D's hand-rolled `cxx.find_library()` list.
> Apply the iteration pattern from the a61a787 → 713ae8c → 46ea61f
> → 220e7bd chain.
>
> Tasks #1 and #14 done. Tasks #2-#9 (dependabot rollout) **PAUSED**
> pending #375 closure on the `6d8aa5a` CI cycle. Tasks #11-#13
> unblocked anytime. Task #15 (hex.pm hardening) is now on hold —
> the `run_with_retry` helper is retained and hex.pm flakes still
> retry on the actual test invocation, but the explicit pre-fetch
> step experiment failed and is not being reattempted in this form.
> Task #16 (move off gRPC) deferred per P1 #376.
>
> Canary commits on `dev`: `b33f1df` (pre-fetch, regressed)
> `d20852b` (docs-only) `6d8aa5a` (pre-fetch drop, this session's
> fix). The earlier `24412648443` PR run in an older version of
> this Resume Pointer is stale — the PR head moved when `d20852b`
> landed, and then again when `6d8aa5a` landed. Use
> `gh pr view 373 --json statusCheckRollup` to get the live PR CI
> run ID before diagnosing.

## Sub-agent delegation pattern

Each tier merge is a self-contained unit of work that fits the
`build-ci` agent's domain. The pattern for delegating a tier to a
sub-agent:

1. Read this doc (the agent inherits no session memory).
2. Pick the tier task by ID and re-read the relevant Phase section.
3. Execute the validation gate + merge + post-merge validation.
4. Append a structured event-log entry.
5. Update the Tier Table status column.
6. Return a ≤ 200-word summary to the parent session.

A typical delegation prompt skeleton:

```
Read docs/dependency-rollout-2026-04-14.md end-to-end, then execute
Tier <N> Task #<id> for <action>. Validation gate is <X>; merge if
green; post-merge validation is <Y>. If any step fails, do NOT
attempt to fix it — instead, append a breakage entry to the Event Log,
file the triage issue per Task #10, and return.
```

Use the `build-ci` agent for action bumps and Dockerfile work; use the
`cross-platform` agent for Dockerfile changes that affect the agent or
gateway runtime; use the `general-purpose` agent if neither fits.

## Event Log

Append-only. Newest entries at the top. Format:
`YYYY-MM-DD HH:MM UTC · <actor> · <event>`.

- **2026-04-14 ~18:25 UTC** · Claude session · **`b33f1df` pre-fetch
  regression diagnosed and fixed in `6d8aa5a`.** Push CI run
  `24412646165` on `b33f1df` failed BOTH Windows MSVC variants on
  gateway tests at the ~10s mark: release hit the failure on eunit
  (4/7 FAIL), debug hit it on ct (4/7 FAIL). Same cover-tool error
  stack in both cases —
  `{cover,get_abstract_code,2,...,{file_error,".../gateway_pb.beam",enoent}}`.
  Diagnosis: the `b33f1df` pre-fetch step (`rebar3 as test compile
  --deps_only`) left `_build/test/lib/yuzu_gw/` in a state where
  the subsequent `rebar3 as test eunit` incremental compile raced
  cover's `pmap_spawn` scan. On Linux/macOS this is harmless
  because `_build/test/lib/yuzu_gw/src/` is a symlink to the source
  tree and cover sees a consistent view of ebin at all times; on
  Windows (symlinks unavailable, rebar3 copies files instead) the
  race fires and cover errors before the parallel compile worker
  finishes writing `gateway_pb.beam`. Pre-fetch was redundant on
  the persistent `yuzu-local-windows` runner (hex cache already
  warm) so the fix is to drop the pre-fetch entirely. `6d8aa5a`
  removes the pre-fetch step, bumps `run_with_retry(max_attempts=2
  → 4)` on the actual test invocation for hex.pm flake protection,
  and preserves the `run_with_retry` helper unchanged. Linux repro
  of the edited script: 148/148 tests pass in 24s. PR #373 debug
  run `24413181387` was cancelled at 18:20 UTC to free the Windows
  runner for the new `6d8aa5a` cycle. Session handoff written
  at the same time. Strategic escape P1 #376 (QUIC migration)
  still deferred; the goal is to close #375 with this simpler
  test-script fix rather than revisit the transport-layer rewrite.
- **2026-04-14 ~16:30 UTC** · Claude session · **Session handoff. Option D
  fully validated on commit `220e7bd` for both Windows MSVC debug and
  release.** End state: every C++ target links cleanly on both variants
  (no LNK2038, no LNK2005, no LNK2019), every C++ test passes
  (`yuzu:agent unit tests`, `yuzu:server unit tests`, `yuzu:gateway ct`).
  The only remaining failure is `yuzu:gateway eunit` failing on
  intermittent hex.pm fetch flake (rebar3 fails to fetch meck or
  proper from hexpm — varies per run, classic transient flake).
  Commit `b33f1df` adds a pre-fetch + retry wrapper to
  `scripts/test_gateway.py` (4-attempt exponential backoff on hex.pm
  failures, populates rebar3's user cache before the actual test runs)
  to close the hex.pm gap. CI for `b33f1df` is queued at handoff —
  push run `24412646165`, PR run `24412648443`. Next session picks up
  by watching that cycle, then merging #373 and dispatching Task #2
  if green. The full option D iteration history (12e40ae → a61a787 →
  713ae8c → 46ea61f → 220e7bd → b33f1df) demonstrates the pattern
  for adding new transitive libs to option D's `cxx.find_library()`
  list — see `.claude/agents/build-ci.md` "Windows MSVC static-link
  history and #375" for the long form. P1 #376 (move off gRPC to
  QUIC) remains the strategic escape but is deferred until customer
  commitments ship.
- **2026-04-14 ~12:40 UTC** · Claude session · **Option H failed on release
  with LNK2005, switching to option D.** The option H push CI run on
  `d3c0b80` completed with a mixed result the PR CI run hadn't shown:
  Windows MSVC debug passed (6/7 tests green, only gateway CT failed on
  hex.pm flake), but Windows MSVC release failed with dozens of
  LNK2005 duplicate symbol errors — `grpc.lib(*.cc.obj)` and
  `grpc++.lib(*.cc.obj)` defining `absl::lts_20260107::Mutex::Dtor`
  "already defined in abseil_dll.lib(abseil_dll.dll)". Root cause:
  vcpkg's grpc port forces static linkage regardless of
  `VCPKG_LIBRARY_LINKAGE` (it logs `-- Note: grpc only supports static
  library linkage`), and abseil's inlined template symbols get embedded
  directly into grpc.lib's object files at grpc's compile time. When
  the linker pulls in both `grpc.lib` (with embedded absl symbols) and
  `abseil_dll.lib` (re-exporting them from the DLL), LNK2005 fires.
  The historical "abseil DLL symbol conflicts" warning in the original
  triplet comment was **accurate and still current** for abseil
  `20260107.1` — modern abseil does NOT resolve the conflict for
  vcpkg's grpc port static-build case. Why debug tolerated the
  collision and release with LTO did not is unclear; we did not
  investigate further because (a) academic curiosity wasn't worth
  another CI cycle against a known-failing approach, and (b) even if
  debug-with-LTO-off happened to work it would be a "limping
  production build" customers should not ship. **Option H reverted
  in `895336e`, then the doc correction + option D planning landed in
  `ceb7690` + `2916947`.**
  **Option D** — restore the static-linkage override on the
  `x64-windows` triplet AND bypass meson's cmake dep method on Windows
  for protobuf/grpc by declaring the deps manually via
  `cxx.find_library()` with build-type-conditional search dirs. This
  threads both failure modes simultaneously: static linkage avoids the
  LNK2005 abseil-DLL-vs-grpc-embedded-absl conflict (no DLL in the
  install tree → no cross-boundary duplicate symbol), and the
  hand-rolled find_library avoids LNK2038 (meson is told exactly which
  .lib to link for each build type, so the cmake-dep translator's
  release-path bias doesn't get to choose). Linux/macOS continue to
  use `dependency('protobuf', method: 'cmake', ...)` unchanged because
  gcc/clang don't have MSVC's runtime-library variant ABI. The
  transitive absl closure is enumerated at configure time via
  `run_command(python3 -c 'import glob; ...' )` so a vcpkg abseil
  bump doesn't require a parallel meson.build edit. **Strategic escape
  tracked as P1 issue #376** — migrate transport off gRPC to QUIC,
  deferred until customer commitments ship.
- **2026-04-14 ~11:55 UTC** · Claude session · **Option B failed the same
  way, switching to option H.** The option B CI cycle (commit `1445cdb`)
  confirmed the root cause is a **meson cmake-dep translation limitation**,
  not anything wrong with vcpkg or CMake. Direct filesystem inspection of
  `vcpkg_installed/x64-windows/share/protobuf/` via the runner-side bash
  script showed the install tree is correct and complete:
  - `protobuf-targets.cmake` uses the standard `foreach(include)` glob
    to load both per-config files
  - `protobuf-targets-debug.cmake` correctly sets
    `IMPORTED_LOCATION_DEBUG "${_IMPORT_PREFIX}/debug/lib/libprotobufd.lib"`
    and appends `DEBUG` to `IMPORTED_CONFIGURATIONS`
  - `protobuf-targets-release.cmake` correctly sets
    `IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/libprotobuf.lib"`
    and appends `RELEASE` to `IMPORTED_CONFIGURATIONS`
  - Both `libprotobuf.lib` (release, `/lib/`) and `libprotobufd.lib`
    (debug with `d` suffix, `/debug/lib/`) exist on disk
  A normal cmake build with `CMAKE_BUILD_TYPE=Debug` would resolve
  `protobuf::libprotobuf` to `IMPORTED_LOCATION_DEBUG` via generator
  expression at configure time. Meson's cmake dep probe does NOT —
  it reads one `IMPORTED_LOCATION_*` property (the release variant)
  and bakes that path into its meson dependency representation
  regardless of the active build type. `-DCMAKE_BUILD_TYPE=Debug`
  (option B) makes `find_package` succeed (which it now does — the
  Configure step is green) but doesn't influence meson's translation
  of imported target locations. Known meson limitation.
  **Option H** — drop the `PORT MATCHES "^(abseil|grpc|protobuf|upb|
  re2|c-ares|utf8-range)$"` static-linkage override from
  `triplets/x64-windows.cmake` entirely. With dynamic linkage, vcpkg
  builds these as DLLs + import libs. Import libs don't carry CRT
  variant info — they're symbol stubs pointing at DLL entries — so
  debug user code can link against a release-CRT DLL without LNK2038.
  DLL itself embeds its own CRT via `vcruntime*.dll` side-by-side at
  runtime. Known risk: the original override was there to prevent
  "abseil DLL symbol conflicts"; if modern abseil (in vcpkg as
  `20260107.1`) reintroduces that, we fall back to option D (explicit
  `cxx.find_library()` with build-type-conditional dirs) — documented
  in the triplet comment so the next reader doesn't re-litigate.
- **2026-04-14 ~10:45 UTC** · Claude session · **Per-build-type triplets
  reverted; switching to option B.** Commit `413a281` (per-build-type
  `x64-windows-debug` / `x64-windows-release` triplets) reverted via
  `git revert` (commit `895336e`) after the canary CI cycle exposed
  two independent vcpkg-side problems:
  (1) The `catch2` port's `portfile.cmake` is not `VCPKG_BUILD_TYPE=debug`
  safe — it calls `vcpkg_replace_string` on a release-side pkgconfig
  file that doesn't exist in a debug-only install tree, failing BUILD
  at catch2 install time for `x64-windows-debug`. This is a vcpkg port
  bug; fixing it upstream is out of scope for the rollout.
  (2) The `x64-windows-release` install got far enough for `protobuf`
  and `grpc` to install successfully, but meson's cmake dep probe
  rejected the install with `gRPC could not be found because dependency
  Protobuf could not be found`. Filesystem inspection via
  `/mnt/c/Users/natha/inspect-vcpkg.sh` confirmed the debug tree was
  wiped by `actions/checkout` on the subsequent debug job before I
  could diagnose the release-side state in detail, but the cmake trace
  pattern (version file loads, but no `protobuf-config.cmake` follows)
  is consistent with a version-file compatibility-check rejection in
  the single-variant install — possibly meson's cmake TryCompile-style
  probe not setting `CMAKE_SIZEOF_VOID_P` and the version file's arch
  check flipping `PACKAGE_VERSION_UNSUITABLE=TRUE`. Either way, the
  per-build-type approach is fighting vcpkg's manifest-mode behavior
  on two fronts.
  **Course correction — option B.** New commit adds explicit
  `cmake_args: ['-DCMAKE_BUILD_TYPE=Debug'|'Release']` to
  `meson.build`'s `dependency('protobuf', method: 'cmake', ...)` and
  `dependency('gRPC', method: 'cmake', ...)` calls, Windows only.
  This forces meson's cmake probe to explicitly request the matching
  config, so vcpkg's imported targets select
  `IMPORTED_LOCATION_{DEBUG,RELEASE}` to match the user code's
  `/MDd` vs `/MD` CRT variant. The shared `triplets/x64-windows.cmake`
  (which builds both variants) stays as-is — the option B fix is a
  meson.build change only. New tier 0bb replaces the prior 0bb in the
  Tier Table. Task #14 re-scoped to track the option B canary.
- **2026-04-14 ~08:40 UTC** · Claude session · **Rollout PAUSED on P0 #375.**
  The Phase 0b runner migration canary (commit `3960f46` on dev,
  in PR #373) succeeded on every plumbing step — toolchain assertion,
  45 GB disk check, force-fresh-vcpkg, vcpkg install, meson configure,
  379 of 380 ninja steps. Then `tests/yuzu_server_tests.exe` linking
  failed with LNK2038 release/debug variant mismatches against
  `libprotobuf.lib`. The `0fe5eac` LNK2038 fix was triplet-only and
  incomplete. Initially attempted per-build-type triplets (#375 option
  A) as the fix — see the newer 10:45 UTC entry above for why that
  approach was abandoned and option B took over.
- **2026-04-14 ~06:50 UTC** · Claude session · **Sequencing correction.**
  Operator caught that the runner-migration work (issue #374) is a
  force-multiplier for the rest of the rollout, not a follow-up: each
  of the 7 Dependabot PRs needs a Windows MSVC debug cycle, and on the
  github-hosted 4-vCPU `windows-2022` runner gRPC alone takes ~90 min;
  on the 32-core / 48 GB self-hosted host the same compile finishes in
  a fraction of the time. The original "let #373 finish first" plan was
  sunk-cost reasoning. Course-corrected: cancelled #373's in-flight CI
  on `cd190f2`, folded the ci.yml Windows MSVC migration to
  `[self-hosted, Windows, X64]` into the reconcile (drop pip+choco
  install, add toolchain assertion + 45 GB disk check, drop ccache and
  vcpkg_installed actions/cache, add Force-fresh-vcpkg-on-triplet-drift
  step, MSYS2 bash shell, build dir → `build-windows-ci/`). New tier
  **0b** added between 0a and the recreate cycle. pre-release.yml
  Windows installer smoke test deferred to a follow-up because the
  install/uninstall side effects need an isolated install path on the
  persistent host before it can move.
- **2026-04-14 ~05:30 UTC** · Claude session · Task #1 (runner version
  gate) **completed without operator action**. Both `yuzu-wsl2-linux`
  and `yuzu-local-windows` confirmed on runner version `2.333.1` —
  well above the 2.327.1 floor required by Node 24 actions. Evidence:
  codeql.yml run `24380031360` (dev branch) — both matrix jobs logged
  `Current runner version: '2.333.1'` at "Set up job" step on
  2026-04-14T03:52:23Z. Memory `project_github_runners.md` had this
  for the Linux box from 2026-04-10; the in-progress codeql run
  confirmed Windows is matched. Tasks #6, #7, #8, #9 are now blocked
  only on #2 (recreate cycle), not on the runner gate.
- **2026-04-14 ~05:00 UTC** · Claude session · Rollout doc created. Phase 0
  not yet started. Tasks #1–#11 created in TaskList. PR #372 (the
  foundation that added `target-branch: dev` and the `pip` ecosystem)
  is the only completed work.
