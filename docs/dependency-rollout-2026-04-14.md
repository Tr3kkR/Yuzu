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
| 0b  | n/a | —    | — | Migrate ci.yml Windows MSVC → yuzu-local-windows (#374) | Gate | **Yes** | **done** (commit `3960f46`) |
| 0bb | #14 | —    | — | Fix Windows MSVC LNK2038 (#375) — option D static-link triplet + parallel-compile race | **Gate (P0)** | Yes | **done** (PR #373 merged as `bf95d3b`) |
| 0c  | #2  | —    | — | `@dependabot recreate` × 7 | Gate | n/a | **done** — all 8 open PRs `base=dev` |
| 0d  | n/a | n/a      | **#385**         | `meson` 1.9.2 → 1.11.0 (new pip ecosystem from #372) | Gate (build graph) | n/a | pending — tier separately, see Resume Pointer |
| 1  | #3  | **#335** | #335 (in place)  | `ubuntu` digest 186072b → 84e77de | Low | No | **next** |
| 1  | #4  | **#248** | #248 (in place)  | `alpine` 3.22 → 3.23 (gateway) | Low | No | **next** |
| 2  | #5  | **#300** | #300 (in place)  | `codecov-action` 5 → 6 | Med (node24 but github-hosted) | No | pending |
| 3  | #6  | **#243** | **#386** (now 7→9) | `actions/github-script` 7 → **9** | Med-High | **Yes** | pending |
| 3  | #7  | **#241** | #241 (in place)  | `actions/cache` 4 → 5 | High (19 sites) | **Yes** | pending |
| 4  | #8  | **#242** | #242 (in place)  | `actions/upload-artifact` 4 → 7 | High | **Yes** | pending |
| 4  | #9  | **#250** | #250 (in place)  | `actions/download-artifact` 4 → 8 | **Highest** (digest=error) | **Yes** | pending |
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

> **Session handoff 2026-04-15 ~17:00 UTC.** Phase 0 is **fully
> clear**. All eight open Dependabot PRs target `dev`, are MERGEABLE,
> and PR-time CI is green across the board. **Tier 1 is ready to
> start whenever an operator picks it up** (see `Slot the new meson
> PR` below for the one open question to decide first).
>
> **Phase 0 closure recap:**
>
> - **0a (Task #1)** — `yuzu-wsl2-linux` and `yuzu-local-windows`
>   runners are both at 2.333.1 (well above the 2.327.1 Node 24
>   floor).
> - **0b** — Windows MSVC migration to `yuzu-local-windows` shipped
>   in `3960f46`.
> - **0bb (Task #14, #375)** — option D static-link + parallel-compile
>   race fix landed via PR #373 squash-merge `bf95d3b`. `meson.build`
>   is at 0.11.0. Lessons-learned record is `.claude/agents/build-ci.md`
>   "Windows MSVC static-link history and #375". The full narrative
>   of the option D iteration (commits `a61a787 → 713ae8c → 46ea61f
>   → 220e7bd → b33f1df → 6d8aa5a → f0b84c7 → 5b2996c`) and the
>   gateway parallel-compile race diagnosis live in the
>   2026-04-14 ~22:00 UTC and 2026-04-15 ~12:00 UTC Event Log entries
>   below; do not re-derive from this Resume Pointer.
> - **0c (Task #2)** — `@dependabot recreate` cycle complete. One
>   real recreation: `#243 → #386`, the latter offering 7 → **9**
>   instead of 7 → 8 because GitHub Actions released github-script
>   v9 during the #375 pause window. The other six PRs (#335, #248,
>   #300, #241, #242, #250) were rebased in place onto `dev` and
>   kept their original PR numbers — for those, the `Recreated As`
>   column in the Tier Table reads `(in place)`.
>
> **Open Dependabot PRs (all `base=dev`, all MERGEABLE):**
>
> | Tier | PR | Bump | Notes |
> |---|---|---|---|
> | 1 | #335 | ubuntu digest `186072b` → `84e77de` | docker-only |
> | 1 | #248 | alpine 3.22 → 3.23 | docker-only (gateway runtime) |
> | 2 | #300 | codecov-action 5 → 6 | github-hosted Node 24 canary |
> | 3 | **#386** | actions/github-script 7 → **9** | recreated from #243; v9 dropped during the #375 pause window so the bump widened by one major |
> | 3 | #241 | actions/cache 4 → 5 | 19 sites, self-hosted Node 24 |
> | 4 | #242 | actions/upload-artifact 4 → 7 | release path |
> | 4 | #250 | actions/download-artifact 4 → 8 | release path; digest=error |
> | 0d | **#385** | meson 1.9.2 → 1.11.0 | NEW — pip ecosystem from #372; not in the original Tier Table; **slot before Tier 1** |
>
> **What "PR-time CI green" actually means here.** Every open PR
> shows the same 4-success / 3-skipped rollup:
> `Proto backward-compat`, `Linux gcc-13 debug`, `Windows MSVC
> debug`, `macOS debug` succeed; `Sanitizers (ASan+UBSan)`,
> `Sanitizers (TSan)`, `Coverage (GCC 13)` skip. **The PR-event
> matrix in `.github/workflows/ci.yml` lines 91-97 deliberately
> excludes `clang-19` and the `release` build_type via
> `matrix.exclude` on `pull_request` events** as a CI-cost
> optimization — the Linux self-hosted runner is single-process so
> the 4-way (gcc-13 / clang-19) × (debug / release) matrix is
> serialized; running all four on every PR commit doubles the wall
> time. Windows MSVC and macOS jobs apply the same release-only
> exclude on PRs for the same reason. Sanitizers and coverage gate
> on labels / schedule, hence the SKIPPED rows. clang-19 + release
> builds run on the post-merge `push` event against `dev` and on
> nightly schedules.
>
> **Implication for this rollout.** None of the dependabot tiers
> below touch C++ source, so clang-19-vs-gcc-13 divergence is not
> a real merge-gate risk; the post-merge push run is the safety net
> that exercises clang-19 + release. If this rollout had touched
> C++ source we would tighten the gate by either (a) running
> `gh workflow run ci.yml --ref <branch>` against the dependabot
> branch directly to force a `push`-event matrix expansion, or
> (b) adding a `dependabot-c++` label that the workflow honors with
> a separate matrix include. We are not doing either; the tiers are
> CI-config-only.
>
> **Resolved — the clang-19 debug "regression" on
> `24450261405/71437121999` was a WSL2 VM cycling false positive,
> not a clang-19 code regression.** Diagnosis 2026-04-15 ~17:30 UTC:
> in the failed job, steps 1-13 (Setup → Build → Test → ccache
> stats) and step 24 (Post Cache vcpkg) all completed SUCCESS;
> step 25 `Post Cache ccache` was `in_progress` with conclusion
> `null` and step 26 `Post Run actions/checkout` was `pending` —
> classic runner-killed-mid-cleanup signature. The 33-minute gap
> between job `71437121999` ending at 11:34:10Z and the next
> `yuzu-wsl2-linux` job (`Linux clang-19 release` job
> `71437122003`) starting at 12:07:33Z confirms the runner agent
> was offline (normal pickup is seconds), matching the WSL2
> utility VM idle-reaper pattern documented as entry #1 of
> `docs/ci-troubleshooting.md`. **Validated** by job
> `71453384876` on the very next run `24455027178`
> (workflow_dispatch on `675d636`): the same `Linux clang-19
> debug` code path completed all 27 steps SUCCESS in 4m 53s
> including `Post Cache ccache` and `Complete job`. The two-part
> fix (`vmIdleTimeout=-1` in `/mnt/c/Users/natha/.wslconfig` plus
> `loginctl enable-linger dornbrn`) is **deployed and verified
> in place** on the WSL2 host. **No standing caveat remains for
> the dependabot rollout** — Phase 0 is genuinely clear. **One
> follow-up flagged but not blocking the rollout:** on the same
> validation run `24455027178`, `Linux gcc-13 debug` job
> `71453384781` failed mid-Test step (Build SUCCESS, Test
> interrupted at 15m 11s, all subsequent steps `null`). Different
> signature from `71437121999` (failure point is Test, not Post
> Cache ccache), so it is either a second VM cycling event with a
> shorter wall-clock, a Test-step timeout, or a real test
> failure — separate diagnostic, owed to Track B but does not
> block dependabot tier dispatch. Do not conflate the two.
>
> **Next action — start Tier 1.** Dispatch `#335` ubuntu and `#248`
> alpine. Both are docker-only, independent, and can merge in
> either order. Validation gate per Phase 1 is the recreated PR's
> CI run on the rebased branch + a local
> `docker build -f deploy/docker/Dockerfile.{server,agent,gateway}`
> sanity. After Tier 1 lands cleanly, advance to Tier 2 (`#300`
> codecov-action) which is the single-site github-hosted Node 24
> canary; Tier 2 is where the Node 24 surface area first widens.
>
> **Slot the new meson PR (decision needed before Tier 1).** `#385`
> (meson 1.9.2 → 1.11.0) is not in the original Tier Table — it
> dropped after #372 added the pip ecosystem to
> `.github/dependabot.yml`. Meson governs the entire build graph
> and is currently pinned in five Dockerfiles (which is what the
> Tier 5 cleanup task exists to centralize). Recommended
> classification: **slot before Tier 1 as Tier 0d**, treat as its
> own gate, because every downstream tier's docker build picks up
> the new meson immediately and a meson regression would mask
> itself as a dependabot-PR build failure with no easy bisect.
> Validation gate for #385: a `docker build` of all three
> Dockerfiles plus a clean `meson setup build-linux --reconfigure`
> on the WSL2 box. **Open question for the operator:** if you would
> rather defer #385 until after Tier 5 (centralize the pins first,
> then bump once), close it with a `dependabot ignore this minor
> version` comment and proceed straight to Tier 1.
>
> Tasks #1, #14, and #2 done. Tasks #3-#9 unblocked (start with
> #3 + #4 in Tier 1 once #385 / Tier 0d is decided). Tasks #11-#13
> unblocked anytime. Task #15 (hex.pm hardening) on hold. Task #16
> (move off gRPC) deferred per P1 #376.

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

- **2026-04-15 ~17:30 UTC** · Claude session · **Diagnosis: the
  clang-19 debug "regression" on run `24450261405` job
  `71437121999` was a WSL2 utility VM cycling false positive, not
  a clang-19 code regression.** Pulled the failed job's step trace
  via `gh api repos/Tr3kkR/Yuzu/actions/jobs/71437121999`. Steps
  1-13 (Setup → Install packages → Cache ccache → Setup vcpkg →
  Install vcpkg → Configure Meson → **Build** → **Test** → ccache
  stats) and step 24 (Post Cache vcpkg) all completed SUCCESS.
  Step 25 `Post Cache ccache` is `in_progress` with conclusion
  `null` (never finished), step 26 `Post Run actions/checkout` is
  `pending` (never started). Job marked failure at 11:34:10Z after
  40m 54s wall time. Cross-checked against the runner timeline:
  `gh api repos/Tr3kkR/Yuzu/actions/runs/24450261405/jobs` shows
  the next `yuzu-wsl2-linux` job (`Linux clang-19 release` job
  `71437122003`) didn't pick up until 12:07:33Z — a **33-minute
  gap** vs. the seconds-to-minutes normal pickup, signature of
  the runner agent dying with the host VM. This matches the
  WSL2 utility VM idle-reaper failure mode documented as entry #1
  of `docs/ci-troubleshooting.md` (commit `819568b`). **Validated**
  on the very next CI run, `24455027178` (workflow_dispatch on
  `675d636`, fired at 12:40:57Z, after the WSL2 keep-alive fix
  was in place): the same `Linux clang-19 debug` code path on job
  `71453384876` completed all 27 steps SUCCESS in 4m 53s including
  `Post Cache ccache` and `Complete job`. Verified the two-part
  fix is **actually deployed**: `cat /mnt/c/Users/natha/.wslconfig`
  shows `vmIdleTimeout=-1` (with the explanatory comment block) and
  `loginctl show-user dornbrn` returns `Linger=yes`. Resume Pointer
  refreshed: removed the "Standing caveat — clang-19 regression on
  dev" paragraph that was added in the 17:00 UTC refresh, replaced
  with a "Resolved" entry holding the diagnosis. **Memory pointer
  `project_session_handover_2026-04-15b.md` should also be updated
  to mark item #2 of "Open work / pickup points" (Diagnose Linux
  clang-19 debug regression) as done; that update is part of this
  same diagnostic batch.** **One follow-up surfaced** that does
  NOT block the dependabot rollout: `Linux gcc-13 debug` job
  `71453384781` on the same validation run `24455027178` failed
  mid-Test step (Build SUCCESS at step 11, Test step 12 interrupted
  at 15m 11s wall, steps 13-26 all `null`). Different signature
  from `71437121999` — failure point is Test, not Post Cache
  ccache — so it is either a second WSL2 VM cycling event with a
  shorter wall-clock, a Test-step timeout, or an actual test
  failure. Separate diagnostic owed to Track B; do not conflate
  with the resolved clang-19 case.
- **2026-04-15 ~17:00 UTC** · Claude session · **Phase 0 fully clear,
  Tier 1 unblocked. Resume Pointer refreshed.** Status check after
  the WSL2 keep-alive + CI troubleshooting runbook commits landed.
  Confirmed via `gh pr list --author app/dependabot --state open`
  + `gh pr view <n> --json statusCheckRollup,mergeable,baseRefName`:
  (1) PR #373 was merged as `bf95d3b`, which closed #375 and
  unblocked Phase 0. (2) The `@dependabot recreate` cycle dispatched
  by the previous session resulted in **one true recreation**
  (#243 → **#386** — v9 dropped during the pause window so the bump
  widened from 7→8 to 7→**9**) plus **six in-place rebases** that
  kept their original PR numbers (#335, #248, #300, #241, #242,
  #250). (3) **One new pip-ecosystem PR not in the original Tier
  Table — #385** meson 1.9.2 → 1.11.0, dropped because #372 added
  the pip ecosystem to `.github/dependabot.yml` after the table was
  written. Slotted as Tier 0d before Tier 1 because meson governs
  the entire build graph and is pinned in five Dockerfiles. (4) All
  8 open PRs report `base=dev`, `mergeable=MERGEABLE`, and the
  standard 4-success / 3-skipped PR-time CI rollup (`Proto
  backward-compat`, `Linux gcc-13 debug`, `Windows MSVC debug`,
  `macOS debug` SUCCESS; `Sanitizers ASan+UBSan`, `Sanitizers TSan`,
  `Coverage GCC 13` SKIPPED). Resume Pointer wholesale-replaced —
  the prior 156-line #375 narrative was preserved in the
  2026-04-14 ~22:00 UTC and 2026-04-15 ~12:00 UTC entries below
  (no information loss). Documented in this refresh: the PR-time
  CI matrix in `.github/workflows/ci.yml` lines 91-97 deliberately
  excludes `clang-19` and `release` build_type via `matrix.exclude`
  on `pull_request` events as a self-hosted runner cost
  optimization (Linux runner is single-process, 4-way matrix
  serializes), so "PR green" does **not** mean "clang-19 green"
  until the post-merge push run on `dev` lands. Standing caveat
  recorded: `dev` carries an unresolved clang-19 debug regression
  from CI run `24450261405` job `71437121999` that is independent
  of this rollout but visible on every post-merge push run.
  **Next action:** dispatch Tier 1 (#335 + #248) once the operator
  decides whether to slot #385 as Tier 0d or close-and-defer it
  until Tier 5 centralizes the meson pins.
- **2026-04-15 ~12:00 UTC** · Claude session · **Push run Windows green
  on `5b2996c`; PR run hit vcpkg grpc applocal flake and was rerun.**
  The `f0b84c7` parallel-race fix is **validated** on Windows: push CI
  run `24426124422` (Windows MSVC debug + release both on the same
  SHA `5b2996c`) completed with `gateway eunit OK 58.58s` and
  `gateway ct OK 78.39s` — the first fully green gateway suite pair
  on Windows MSVC in this fix chain. Linux gcc-13/clang-19 and macOS
  debug/release were all green on both the push and PR runs.
  However, PR run `24426126324` on the same commit hit a **distinct,
  unrelated** failure: vcpkg's grpc build step failed inside
  `vcpkg_copy_tool_dependencies` invoking `applocal.ps1` against
  `grpc_csharp_plugin.exe`, with vcpkg reporting
  `error: building grpc:x64-windows failed with: BUILD_FAILED`
  after a full 9.8-minute fresh grpc rebuild. This is a known
  grpc-on-vcpkg Windows flake class and is orthogonal to any code in
  this PR — the push run on the same SHA did not hit it because it
  had a warm vcpkg binary cache, the PR run apparently got a cache
  miss (push run was `cancelled` at workflow level before its cache
  write step ran, so the PR run rebuilt from scratch and rolled the
  dice on the flake). Job
  `71360390333` rerun dispatched via `gh run rerun 24426126324
  --failed`. Expected outcome: either a cache-hit short path (if the
  push run did write some cache layer after all) or a second fresh
  grpc build that hopefully doesn't roll the flake this time. No
  code changes. If a second rerun also hits the vcpkg grpc flake,
  the next escalation is to push a vcpkg binary-cache warmup commit
  (empty `[ci skip]`-style no-op) so the cache is populated without
  gating merge on flake-probability.
- **2026-04-14 ~22:00 UTC** · Claude session · **Parallel-compile
  race between gateway eunit and gateway ct fixed in `f0b84c7`.**
  Push CI run `24419434652` on `fea3702` (the `6d8aa5a` pre-fetch
  drop + docs handoff) confirmed the cover-race fix: gateway
  **eunit** now passes on Windows MSVC debug (30.75s, 148 tests).
  But it exposed a SECOND distinct Windows-only failure — the two
  gateway test suites race each other on `_build/test/lib/<dep>/`
  because meson schedules them in parallel by default. Whichever
  rebar3 process loses the race fails fast (~5-9s) in `proper`'s
  compile with
  `failed to rename proper_orddict.bea# to proper_orddict.beam:
   no such file or directory`,
  while the winning suite finishes cleanly at ~30-55s. The failing
  suite flipped between eunit and ct across the three Windows
  variants — release ran eunit fast-fail + ct green, debug ran ct
  fast-fail + eunit green, PR debug ran eunit fast-fail + ct green.
  Root cause is Windows file-system semantics — POSIX atomic
  rename on Linux/macOS survives the race, Windows `MoveFileEx`
  can fail if another process already consumed the temp file.
  Fix in `f0b84c7`: set a distinct `REBAR_BASE_DIR` per suite in
  `meson.build` (`_build_eunit` vs `_build_ct`), `test_gateway.py`
  honors the env var when computing its ebin wipe path, and
  `.gitignore` gets the two new dirs. Two disjoint `_build/` trees
  cannot race. Local Linux repro with
  `REBAR_BASE_DIR=.../gateway/_build_eunit`: 148/148 PASS in 24s,
  identical to the default base-dir runtime. Fallback if `f0b84c7`
  still fails: add `is_parallel: false` to both gateway test()
  entries in meson.build (strict serialization, ~30s extra test
  time). Push + PR CI on `f0b84c7` head queued at handoff — the
  Windows runner cycle takes ~90 minutes for all three Windows
  jobs to drain through the one self-hosted runner.
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
