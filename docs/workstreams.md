# Active workstreams — 2026-07-29

**This file is temporary.** It exists for roughly one week (to ~2026-08-05) to keep four
parallel efforts from colliding on shared machines. When the streams close, delete this file
and the pointer blocks in `CLAUDE.md` and `AGENTS.md`. See "Teardown" at the end.

Every agent — Claude, Codex, Kimi — reads this before starting work.

## The rule

**Four streams are active. Work belongs to exactly one of them.** If a task is not in one of the
four, do not start it: say so and ask. Drive-by fixes outside your stream are how these branches
collided last time. File an issue instead.

| # | Stream | Slug | Scope |
|---|---|---|---|
| 1 | CI/test revamp | `ci` | The ladder of small CI/test units (U01–U10 and successors): speed, reliability, determinism, telemetry, reproducibility. |
| 2 | ADR-0017 list-read confinement | `adr17` | The admit-then-filter `authorize_list_read` chokepoint and its PR-B follow-ons. |
| 3 | ADR-0031 decomposition | `adr31` | Presentation / core / engine split — ADR-0031/0032/0033 sequencing under ADR-1005. **Design-only today.** |
| 4 | SQLite → Postgres | `pg` | Migrating the remaining server stores off SQLite per the migration ladder. |

## Where the work lives

Same shape on all three machines, so a path tells you the stream without asking:

```
<yz-root>/<stream>/<unit>/          one git worktree per unit of work
<yz-root>/_attic/                   preserved patches from retired branches — read-only
<yz-root>/_lock/                    the Shulgi access semaphore (Shulgi only)
<yz-root>/bin/                      lock helpers
```

| Machine | `<yz-root>` | Clone it worktrees from |
|---|---|---|
| Mac (authoring, macOS builds, PG work) | `/Users/nathan/yz` | `/Users/nathan/Yuzu` |
| Shulgi Windows (MSVC/Windows validation) | `C:\Users\natha\yz` | `C:\Users\natha\Yuzu` |
| Shulgi WSL2 (Linux/gateway validation) | `/home/dornbrn/yz` | `/home/dornbrn/Yuzu` |

Each worktree root carries an untracked `STREAM.md` naming its stream, unit, branch, PR and next
action. Read it first. It is excluded via `.git/info/exclude`, so it never shows up in `git status`
and never lands in a commit.

Create a new unit worktree:

```sh
git -C <clone> worktree add -b <stream>/<slug> <yz-root>/<stream>/<slug> origin/dev
```

Branch naming for **new** branches is `<stream>/<slug>` (`pg/audit-store`, `adr17/pr-b-…`).
In-flight branches keep their existing names — renaming a branch with an open PR is not worth
the churn. The directory carries the stream identity either way.

### Machine roles

- **Mac** is where authoring happens for every stream, plus macOS compiles and local Postgres work.
- **Shulgi Windows** is for MSVC builds, Windows test suites, and the Windows toolchain contract.
- **Shulgi WSL2** is for Linux builds, the Erlang gateway, and Linux suites.

Validation worktrees on Shulgi are created on demand and removed when the unit lands — do not
leave a checkout per unit sitting on either half.

## Shulgi is one shared box — take the lock

The Windows half and the WSL2 half are **one physical machine**, shared by all four streams, and
it is still a live GitHub Actions runner host. Two streams building at once produce timeouts that
look exactly like flaky tests but are not. A contended result is not evidence.

**Take the semaphore before any build, test, or validation run on Shulgi. Release it as soon as
you are done, including when the run fails.**

From the Mac:

```sh
~/yz/bin/shulgi-lock status
~/yz/bin/shulgi-lock acquire <stream> <unit> [minutes] [wait_minutes] "what you are doing"
~/yz/bin/shulgi-lock extend  <token> [minutes]
~/yz/bin/shulgi-lock release <token>
```

Inside WSL2: `/home/dornbrn/yz/bin/yz-shulgi-lock.sh <same actions>`
On Windows: `powershell -File C:\Users\natha\yz\bin\yz-shulgi-lock.ps1 <same actions>`

All three drive one mutex directory on the shared NTFS path, so the halves serialise against
each other, not just within themselves.

What to expect:

- `acquire` prints `YZLOCK-TOKEN=<token>`. Keep it — `release` and `extend` require it, which is
  what stops one stream releasing another's lock.
- **Exit 0** acquired · **exit 2** timed out waiting · **exit 3** a GitHub runner worker is busy.
- Exit 3 is not a problem to route around. Testing against a live CI job is what produced the
  contention noise in the first place. Wait, or use `-AllowRunnerBusy` for read-only inspection.
- Waiters queue FIFO; `status` shows the holder and the queue.
- Default hold is 45 minutes. If your run will take longer, `extend` before it lapses. A holder
  more than 15 minutes past expiry is treated as crashed and may be broken by the next waiter —
  every break is recorded in `_lock/history.log`.
- Ask for the time you need. Sitting on the lock "just in case" blocks three other streams.

## Stream detail

### 1 · `ci` — CI/test revamp

Handover: `/Users/nathan/Desktop/Yuzu CI revamp handover 2026-07-29.md` (authoritative session
state). Design input: `docs/proposals/ci-test-architecture-review.md`. Reference:
`docs/ci-architecture.md`, `.claude/skills/ci-cache/SKILL.md`.

Units — one worktree each under `<yz-root>/ci/`. State as of 2026-08-02:

| Unit | Dir | PR | State |
|---|---|---|---|
| U01 resource envelopes | — | #2601 | merged |
| U02 canary classifier | `u02-canary-classifier` | #2616 | merged |
| U03 runner control | `u03-runner-control` | #2612 | merged |
| U05 runner preparation | `u05-prepare-runner` | — | **uncommitted; branch carries no commits and is 184 behind `dev`** |
| U06 toolchain contract | `u06-toolchain-contract` | #2617 | merged |
| U07 flake expiry | — | #2602 | merged |
| U08 TAR determinism | `u08-tar-determinism` | #2613 | merged |
| U09 annotation adapter | `u09-annotation-adapter` | #2608 | merged |
| U10 guardian refill | `u10-guardian-refill` | #2615 | merged |
| CodeQL dispatch invariant | `codeql-invariant` | #2621 | merged |

U05 is the only unit still outstanding. Every other worktree in this stream is landed and can be
torn down; check each for unpushed work first.

Two prototypes are **preserved but must not be published** — runner admission and U04 execution
trust. Both are blocked on the same prerequisite: every runner service needs its own non-admin OS
identity and in-job elevation has to go. Their patches are in `_attic/`.

Standing rules for this stream, carried from the handover: do not restart, stop, reprovision or
cancel any runner or runner service; do not blindly rerun failed CI — read the log and separate
product defects from contention; do not report a platform result that was not observed.

### 2 · `adr17` — list-read confinement

Read: `docs/auth-architecture.md`, ADR-0017, `docs/adr/0031-engine-principal-store.md`.

The `authorize_list_read` admit-then-filter chokepoint. Every new list or fan-out read of
per-agent data goes through it — never a bare global `require_permission`, which is inert for
confined operators and fails open on a corrupt `rbac.db`.

Open work: **#1715** (global↔management-group permission combining — deny precedence) was the
prerequisite and is now **closed**, so PR-B is unblocked: **#2473** wrapper + engine-principal
guard, **#2474** authz decision metric and deny-reason split, **#2475** resolver cache and loop
hoist, **#2477** worked cross-boundary docs example. Robustness edges in **#2476**. All five open.

Interlock, from ADR-1005: no ballot-A5 code ships before engine principals plus the ADR-0017 gate
(#1714, prerequisite #1715). #1716 is the closed doc-honesty companion — **not** the gate.

Starter worktree: `<yz-root>/adr17/pr-b` on `adr17/pr-b-require-list-read`.

Note when reading CLAUDE.md's routed-concerns row for engine principals: two of its authorization
claims are overstated — see #2485. Trust the ADR and the code, not that row.

### 3 · `adr31` — presentation / core / engine decomposition

Read: `docs/adr/0031-presentation-core-engine-decomposition.md`,
`docs/adr/0032-use-case-admission-protocol.md`, `docs/adr/0033-access-control-spine.md`,
`docs/adr/1005-headless-platform-use-case-engines.md`, `docs/adr-1005-execution-plan.md`.

ADR-0031/0032/0033 are accepted but **design-only and bind prospectively**. The first deliverable
is sequencing, not code: **#2193** wants the ADR-0032 interlock items (a)–(n) tracked as real
issues rather than markdown rows. Do that before proposing implementation slices.

Invariants that constrain every slice: core owns the public API and is the sole authority, others
may only narrow it (INV-31-4, no private core API); no cross-component DB access (INV-31-3);
engines are headless — core admits each run, mints a short-lived audience-bound grant, and
confines every engine read against the admitting operator's *current* authority; no grant is a
bearer capability over data.

Starter worktree: `<yz-root>/adr31/plan` on `adr31/decomposition-plan`.

### 4 · `pg` — SQLite → Postgres server stores

Read: `docs/postgres-migration-ladder.md` (the ordered queue), `docs/postgres-store-playbook.md`
(the recipe), ADR-0012 (the author contract), ADR-0006/0007/0008/0010.

Both pilots have merged — **#2496** `ResultSetStore` and **#2497** `InventoryStore`. The per-store
conventions they established (type-distinguishable authoritative reads, backfill RAII, degrade
audit + metric, `stop()` unwire, `/readyz` + `/healthz` wiring) are what the rest of the ladder
copies; read one of them before opening a new store PR.

In flight as of 2026-08-02, one worktree each under `<yz-root>/pg/`: **#2663** `GuaranteedStateStore`
(Wave 1.1), **#2691** `ResponseStore` (1.2), **#2697** `AuditStore` (1.3), **#2703** `RbacStore`
(2.1), **#2708** `ManagementGroupStore` (2.2) — all open. `FleetTopologyStore` is unstarted.

Every store migrates behind its own per-store ADR and PR. Secrets are never a plain column —
verify-only hash or a `SecretCodec` envelope, with `security-guardian` review on every
secret-column migration.

Local Postgres: `postgres:18` on `:5433` is flaky under concurrent load. For gate runs stand up a
dedicated disposable instance on another port and point `YUZU_TEST_POSTGRES_DSN` at it. Use the
pre-migrated template fixtures (`YUZU_REQUIRE_PG_DB_TPL`) for store-behaviour tests — per-test
migration DDL is what drove the Windows server-suite timeout.

## Standing conventions (unchanged, restated because they bite)

- PR base is **`dev`**, never `main`.
- Never edit `CHANGELOG.md` — add one `changelog.d/<PR#>-<slug>.<section>.md` fragment.
- Run the whole `/governance` pipeline; do not pre-judge a change as too small.
- `/test` before commit or push.
- Several sessions share one checkout. **Check `git branch --show-current` before every commit.**

## Teardown

When the streams close:

```sh
# 1. every unit is merged, closed, or its branch pushed
git -C /Users/nathan/Yuzu worktree list

# 2. drop the worktrees, then the tree
git -C /Users/nathan/Yuzu worktree remove <each>
git -C /Users/nathan/Yuzu worktree prune
rm -rf /Users/nathan/yz            # after rescuing anything still wanted from _attic/

# 3. same on both Shulgi halves
# 4. delete this file and the pointer blocks in CLAUDE.md and AGENTS.md
```

`_attic/` holds the only copy of some uncommitted work (U05's patch, the two blocked prototypes,
a few unpushed commits). Check it before deleting the tree.
