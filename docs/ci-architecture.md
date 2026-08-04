# CI architecture — runner topology, vcpkg cache, persistence

Reference for Yuzu's three-tier CI architecture (April 2026 overhaul).
CLAUDE.md keeps the headline tier breakdown + runner topology; this document
holds the cache-key contract, persistence rules, and operational knobs that
the `build-ci` agent loads on workflow / vcpkg / scripts/ci changes.

Plan of record: `/home/dornbrn/.claude/plans/our-ci-has-been-piped-castle.md`.
Failure-mode runbook: `docs/ci-troubleshooting.md`.

## Tier summary (mirrors CLAUDE.md)

- **Tier 1 — PR fast-path** (`ci.yml` on `pull_request`): one Linux variant
  (gcc-15 debug on the `yuzu-bigtam-linux` pool), one Windows variant (MSVC debug on
  the `yuzu-weetam-windows` pool), one macOS variant (appleclang debug on GHA-hosted
  `macos-15`), plus `proto-compat`. Wall target: <10 min per leg.
- **Tier 2 — push to dev/main** (`ci.yml` on push): full 4-way Linux matrix
  (gcc-15 / clang-21 × debug / release), 2-way Windows, 2-way macOS. **No
  sanitizers, no coverage** — those moved out (#410).
- **Tier 3 — nightly cron** (`nightly.yml`, `0 6 * * *` UTC +
  `workflow_dispatch`): ASan+UBSan, TSan, coverage on the Big Tam pool
  (`yuzu-bigtam-linux`, gated on `bigtam_pool_healthy`), plus a Windows ASan
  leg (`windows-asan`, agent-only, Wee Tam pool, gated on
  `weetam_pool_healthy`) covering the Windows-only spark mechanisms that the
  Linux sanitizers can't reach (#1934a). On any leg failure, the `alert` job auto-opens or comments on a
  `nightly-broken` issue. **Discipline norm: no merge to main while a
  `nightly-broken` issue is open.**

  The TSan leg preloads `$RUNNER_TEMP/libgai_sync_shim.so` to replace glibc's
  `getaddrinfo_a()` async DNS path with synchronous `getaddrinfo()` on the
  calling thread. Required because cpp-httplib enables
  `CPPHTTPLIB_USE_NON_BLOCKING_GETADDRINFO=ON` by default (vcpkg port), which
  makes glibc spawn an async-DNS helper thread via `clone3` directly —
  bypassing TSan's `pthread_create` interceptor — so the helper's per-thread
  allocator state is never initialised and the first `malloc()` from it
  segfaults inside `__tsan::SizeClassAllocator64LocalCache::Allocate
  (this=0x8)` (#438). Scoped to the TSan job via step-level `env: LD_PRELOAD`;
  production keeps the non-blocking-DNS behaviour. The shim is built by
  `scripts/ci/build-gai-sync-shim.sh` — a **single** script shared by both this
  workflow and `sanitizer-tests.yml` so the two can't drift (#1038 CS-03); it
  compiles with `gcc-15 -Werror` and `_Static_assert`s glibc's private
  `struct gaicb` layout (`ar_result`=24, `__return`=32, `sizeof`=56), so an ABI
  reshuffle fails the build loudly instead of silently corrupting adjacent
  memory. Built into `$RUNNER_TEMP`, not a fixed `/tmp` path, because Big Tam
  runs 4 runner agents under one OS identity and a fixed path is a cross-job
  collision class (#1038 R-15).

  On Test **failure or job cancellation**, the TSan job's `Capture stack trace
  under gdb` diagnostic (`scripts/ci/tsan-gdb-capture.py`) derives **every**
  failing test binary from the meson junit, maps each to its binary+args via
  `meson introspect`, and replays each under `gdb -batch` with its own Catch2
  seed and shard filter, dumping `thread apply all bt full` + `info registers`
  into `build-linux-tsan/stack-capture.log`, which rides the `meson-testlog-tsan`
  artifact (uploaded on `failure() || cancelled()`). The cancelled path is the
  60-min-timeout **hang** case: it infers the unfinished entries and
  SIGINT-interrupts gdb for a live backtrace. Best-effort — it always exits 0
  and never changes pass/fail. **Guard note (#1038):** the step's `if:` must keep
  an explicit `failure() || cancelled()`; a bare `steps.test.outcome ==
  'failure'` gets an implicit `success()` ANDed on and is unreachable — that
  defect silently skipped this step on every red nightly from 2026-05-15 to
  2026-07-14.

`workflow_dispatch` only works once a workflow file exists on the **default
branch (`main`)**. Cron schedules likewise. New workflows added on `dev` are
dormant until merged.

### Trusted fork pull-request CI

Automatic `pull_request` runs from forks are deliberately fail-closed. They
must never emit healthy self-hosted runner outputs, because fork code is not
trusted to execute on Big Tam or Wee Tam. The ordinary preflight fails red
when it detects a fork; it does not bypass runner control.

After static review, a maintainer may approve one immutable fork revision.
First run the hosted review workflow and wait for it to pass:

```bash
gh workflow run fork-dynamic-review.yml --ref main \
  -f pr_number=123 -f head_sha=<40-character-head-sha>
gh run list --workflow=fork-dynamic-review.yml --limit 5
```

Then dispatch the trusted gate using that exact SHA and successful review run:

```bash
gh workflow run trusted-fork-ci.yml --ref main \
  -f pr_number=123 \
  -f head_sha=<40-character-head-sha> \
  -f review_run_id=<successful-review-run-id>
```

The wrapper requires the PR to remain open, verifies that its current head is
the supplied SHA, requires the hosted review run to match the same PR and SHA,
and invokes the reusable `ci.yml` matrix. The reusable workflow also requires
the repository-only `TRUSTED_FORK_CI_GATE` secret, so a fork cannot call it
directly. The wrapper passes only that sentinel and `RUNNER_INVENTORY_TOKEN`;
the PAT is consumed by a hosted, base-workflow-revision runner-control step
before the approved fork revision is checked out. Trusted self-hosted jobs
start from a clean workspace, use run-private ccache/test state, disable vcpkg
binary sources, and purge the workspace afterwards. They never read or write
the normal `runner.tool_cache` caches. This deliberate approval therefore
executes the full PR gate without turning a reviewed fork into a cache-publisher
or exposing the administration-scoped PAT to fork-controlled code.

## Gates outside the tier ladder

### Plugin spawn lexical gate (`plugin-spawn-gate.yml`, ADR-3002 decision 10a)

A per-PR grep over `agents/plugins/*` and `agents/core` for a raw
process-spawn token (the `fork`/`exec` family, `system`, `popen`,
`CreateProcess` family, ...) outside the registered allowlist —
`scripts/ci/check-plugin-spawn-lexical.sh` carries the full
token/allowlist contract in its own header. It is tier (a) of a
two-tier enforcement scheme; a scheduled, call-identity-aware CodeQL
query is tier (b), the deep net for what a lexical scan can't see. See
`docs/adr/3002-acquisition-ladder.md:459-488` for why neither tier
alone is sufficient.

It runs as its **own workflow**, not folded into `ci.yml`: a source
grep needs no build, so it doesn't share `ci.yml`'s build-dependent
PR fast-path or `changes`-job path filtering — there is nothing
expensive to skip, so the workflow simply always runs on every PR and
push to `main`/`dev`. A failing lexical scan is a **merge-blocking**
required check; remediation is either moving the call into the
registered allowlist (if it is a legitimate, reviewed acquisition
path) or removing the raw spawn in favour of the sanctioned subprocess
runner.

### Capability matrix drift gate (`check-capability-matrix.sh`, #2204)

Runs on every Linux CI leg immediately after `Build`, once
`capmatrix-gen` and every `agents/plugins/*/` shared object already
exist. The script discovers the full plugin set from the source tree
itself — not a hand-maintained subset — so a missing capability-matrix
artifact for **any** plugin is a hard failure, never a silent skip,
and a stale generated block in `docs/os-capability-matrix.md` fails
the same way. It currently runs in **ratchet mode only**: the
undeclared-plugin count must not grow PR-over-PR; it does not yet
hard-fail on any plugin being undeclared (that is a later PR). A
companion step, `tests/shell/test_capability_matrix_gate.sh` (#2204
finding F10), exercises both the "renders a DECLARED descriptor" path
and both ratchet-rejection branches against the real built binary and
the real gate script, using the `tests/fixtures/abi4/` declaring
fixture plugin inside throwaway git repos — it also runs right after
`Build` for the same reason (needs the built artifacts), not on the
preflight shell-gate step.

Both steps are **merge-blocking** required checks. A red
capability-matrix gate on a fork or source build is remediated by
running `capmatrix-gen` against the local build and committing the
refreshed generated block between the `<!-- BEGIN GENERATED -->` /
`<!-- END GENERATED -->` markers in `docs/os-capability-matrix.md`, or
by declaring the newly undeclared plugin(s) so the ratchet count stops
growing — `check-capability-matrix.sh`'s own header spells out the
three drifts it catches and the ratchet-baseline mechanics.

### Docker healthcheck invariants (`docker-healthcheck-invariants.yml`, #751)

The five Yuzu **application** images' compose healthchecks depend on a tool baked
into the image, not on the application: **bash + `/dev/tcp` + `grep`** for
`yuzu-server`, **busybox `wget --spider`** for `yuzu-gateway`, and
**`/bin/busybox`** (by absolute path) for the three FROM-scratch chisel images.
Nothing else exercises those tools. A base-image swap, a dropped apt package, or a
chisel slice change that stops shipping the busybox symlink breaks nothing at
build time and nothing at boot — it breaks only the healthcheck, so Compose parks
every container `unhealthy` forever and anything with `depends_on: condition:
service_healthy` never starts, with no application failure to point at.

`yuzu-postgres` is published and healthchecked too (`pg_isready` + `psql`), but it
is `FROM postgres:*` — those tools are the image's whole purpose — so it has no
role in the gate and `docker-publish-postgres` has no pre-push check. `agent-chisel`
is gated **pre-emptively**: no compose healthchecks an agent image today.

The probes are a hard-coded copy of the healthcheck commands, so both the script
and the workflow's change-filter carry a **KEEP IN SYNC** list of every file that
defines one — including the two easy-to-miss ones,
`scripts/test/docker-compose.upgrade-test.yml` and the compose heredocs inlined in
`pre-release.yml`.

`scripts/ci/verify-healthcheck-invariants.sh` is the gate. It runs each image's
real healthcheck probe **against a live HTTP listener** in a shared network
namespace, so exit 0 is the only passing outcome. Probing a *closed* port cannot
distinguish a working bash from a bash built without net redirections — both
return 1 — which is why the naive "accept 0 or 1" check that #751 originally
proposed passes a broken image (verified against a bash compiled
`--disable-net-redirections`).

**Placement — it runs in two places, sharing one script:**

| Where | When | Why |
|---|---|---|
| `docker-healthcheck-invariants.yml` | PRs + pushes to `dev`/`main` | Catches a base-image swap in the PR that introduces it, not weeks later at release. |
| `release.yml` (`docker-publish`, `docker-publish-chisel`) | Between image build and registry push | A broken image is never published. Verifying after the push would leave a broken tag in GHCR. |

It is deliberately **not** in `ci.yml`: the Tier-1 fast path must stay under 10
min and these builds are far too heavy. It is equally deliberately **not**
`paths:`-filtered — per #1978, a path-filtered workflow that later becomes a
*required* check never reports on PRs it filters out, so the check sits at
"Expected — waiting for status" forever and a non-admin can never merge. Instead
the workflow always runs and a cheap `changes` job skips the build matrix.

That is necessary but **not sufficient for a matrix job**. Per `actions/runner#952`
a matrix job skipped at the job level is skipped *before* the matrix expands, so it
emits none of its inner check-run names — "skipped" never appears and the required
context hangs anyway. A `required-check-stubs` job (mirroring `ci.yml`'s
`docs-required-checks`) emits the five `Verify <role> healthcheck invariant` names
when the matrix is skipped, and fails red rather than hanging if the classifier
itself dies. **Only with that stub are the five contexts safe to add to branch
protection.**

The PR matrix reuses release.yml's local buildcache **read-only** (`cache-from`
with no `cache-to`), so it never evicts release layers and adds no cache directory
`cache-prune.yml` doesn't know about. Inside `release.yml` the verification build
likewise has no `cache-to`: it shares one buildkitd instance with the push build,
so the push hits BuildKit's own solver cache and rebuilds nothing.

## Self-hosted runner topology

| Runner | Host | Jobs |
|---|---|---|
| `yuzu-bigtam-linux-{0..3}` | Big Tam Threadripper 9970X, native Ubuntu **26.04** (gcc-15/clang-21) — 4 L3/CCD-pinned runners (`0-7,32-39`; `8-15,40-47`; `16-23,48-55`; `24-31,56-63`), Ninja capped at `-j16` | **all self-hosted Linux** (shared label `yuzu-bigtam-linux`): ci.yml `linux` matrix, `proto-compat`, sanitizer-tests (asan/tsan), nightly (asan/tsan/coverage), codeql Linux leg, **release.yml** (build-linux, build-gateway, docker-publish\*), cache-prune-linux. 4 runners on one host. Provisioned from [`deploy/linux/`](../deploy/linux/README.md). |
| `yuzu-weetam-windows-{0..3}` | Wee Tam 9970X native Windows 11 — 4 CCD-pinned runners, shared label `yuzu-weetam-windows` | **all self-hosted Windows**: ci.yml `windows`, nightly `windows-asan`, codeql Windows leg, release `build-windows`, instructions-windows-validate, cache-prune-windows. Provisioned from [`deploy/windows/`](../deploy/windows/README.md). |
| `macos-15` | GitHub-hosted | macos matrix |

**Retired 2026-06-21:** `yuzu-wsl2-linux` (Shulgi WSL2 Ubuntu 24.04, label
`yuzu-shulgi`) and `yuzu-local-windows` (Shulgi native Windows) — superseded by
Big Tam and Wee Tam. Remove them from `.github/runner-inventory.json` to silence
the inventory sentinel. `proto-compat` and `cache-prune-linux` use the bare
`[self-hosted, Linux, X64]` label (no compiler), so they resolve to Big Tam.

### Ubuntu 26.04 migration (Big Tam) — COMPLETE

Big Tam is a native **Ubuntu 26.04 (Resolute)** box, default toolchain **GCC 15 /
Clang 21** (vs Shulgi's 24.04 GCC 13 / Clang 19). **Every self-hosted Linux job
runs on Big Tam**: ci.yml `linux` (#1609), then sanitizer-tests / nightly / codeql
Linux, then release.yml + the remaining Windows→Wee Tam stragglers (#1615). The
supporting scaffolding:

- Native files `meson/native/linux-gcc15.ini` + `linux-clang21.ini` are the live
  toolchain files (they also set `-fuse-ld=mold`; see Build speed below). The
  24.04 `linux-gcc13.ini`/`linux-clang19.ini` stay only for the GHA-hosted
  ubuntu-24.04 canary.
- The CI runner image (`Dockerfile.ci-linux`), the local `Dockerfile.ci`, and the
  four sanitizer images (`Dockerfile.{server,agent}-{asan,tsan}`) are on
  `ubuntu:26.04` + gcc-15/clang-21. `gcc-13`/`clang-19` stay installable from the
  archive but are not the defaults.
- `pre-release.yml`'s `install-deb` smoke matrix has an `ubuntu:26.04` leg.

`ImageOS` stays `ubuntu24` on every leg (setup-beam has no `ubuntu26` prebuilt
OTP; the 24.04 OTP runs fine on 26.04 — same `libcrypto.so.3` soname). Big Tam
runs 4 runners on one host, so every apt step is `flock`-serialized on
`/tmp/yuzu-ci-apt.lock`, the shared CI Postgres container is flock-serialized too
(`scripts/ci/ensure-postgres.sh`), and meson is installed per-job via
`pip --user` (it is not a host default). Full history + per-file detail:
**`docs/ci-ubuntu-2604-cutover.md`**.

Each Big Tam runner is bounded to one kernel-reported L3 domain via a systemd
drop-in (`CPUAffinity` plus cgroup `AllowedCPUs`) and exports
`YUZU_BUILD_JOBS=16`. Linux's SMT numbering is split: L3 0 is
`0-7,32-39`, not the contiguous Windows `0-15`. CI passes that cap explicitly
to `meson compile -j`; a process affinity mask does not make Ninja's default
processor detection affinity-aware, while `-j16` alone is not an L3 pin. The
versioned source and verification commands are in
[`deploy/linux/`](../deploy/linux/README.md).

### Build speed (Big Tam)

The `runner` user (shared `HOME=/home/runner` across r0–r3) is provisioned once
for fast, download-free builds:

- **ccache** `max_size=50G`, compression on — the host default is 5 GiB, far too
  small for ~700 TUs × variants. ci.yml/nightly cap at 30G via the
  `CCACHE_MAXSIZE` env; release.yml now sets `CCACHE_MAXSIZE=30G` too (it had been
  inheriting the host default).
- **mold** linker (`apt install mold`), wired via `-fuse-ld=mold` in the gcc-15 /
  clang-21 native files — large cut in link time on the big `yuzu-server` /
  `yuzu-agent` binaries and the release LTO link.
- **meson** 1.11.1 + the rest of `requirements-ci.txt` persist in the runner
  user's `~/.local`, so the per-job `pip install --user --require-hashes` is a
  no-op (no re-download).
- **rpm** (rpmbuild) installed for release.yml's packaging step — absent on a
  fresh 26.04 (it was the first-Big-Tam-release blocker). Note: Big Tam ships RPM
  **6.0** vs Shulgi's 4.x — watch the first release.

The Windows toolchain is codified in [`deploy/windows/`](../deploy/windows/README.md)
(the native-Windows analog of `deploy/docker/Dockerfile.ci-linux`): a versioned
provisioning spec, a manifest, and a runner self-test. All four runners share one
vcpkg binary cache via `RUNNER_TOOL_CACHE=D:\ci\tool_cache` (mirroring
`CCACHE_DIR`), so the CCD split doesn't fragment the cache 4×. The provisioner
also enforces the four exact Defender work-root exclusions (`D:\ci\work-0` …
`work-3`), covering each runner's `_temp` and build outputs without excluding
user/system `%TEMP%` or the whole `D:\ci` tree. The pin wrapper routes native
`TEMP`/`TMP` and MSYS2 `TMPDIR` into the matching per-runner `_temp`; the CI
telemetry start step exports the same values for already-running listeners.

### Windows test-phase concurrency gate

Wee Tam's 4 runners are CCD-pinned, but affinity partitions only **cores** — not
DRAM bandwidth, the disk, or the Defender minifilter. So when several Windows jobs
run their **test** phase at the same time, the heavy unit-test suites
(`server ~[pg]`/`[pg]`, `agent`, `tar`) slow roughly linearly and hit their meson
timeouts: per-runner telemetry (`ci_test_suites`) measured `server ~[pg]` at
c0≈289 s → c2≈467 s → c4≈603 s — a **guaranteed** timeout once ≥4 test phases
overlap, and a 22–25 % timeout rate on the `server ~[pg]`/`tar` suites overall.
Big Tam (Linux) scales **flat** under the identical 4-on-one-box topology — cheap
`fork()`/VFS/page-cache and no AV minifilter keep per-op cost low — so it needs no
gate.

`ci.yml`'s Windows **Test** step therefore wraps the run in
[`scripts/ci/with-test-slot.sh`](../scripts/ci/with-test-slot.sh) — a crash-safe
`flock` gate (a killed job releases its slot via OS fd-close, so a timeout never
leaks a slot) that caps concurrent heavy test phases to **2 per box** (the
**build** phase stays 4-wide) — and passes `--num-processes 2` so meson's own
fan-out can't pile the two ~400–600 s server shards onto one CCD+cluster. The slot
count is the first knob to revisit (→3) once per-op cost is cut (Defender `%TEMP%`
exclusion, RAM-disk data dirs). Full diagnosis: the `tests/meson.build`
server-shard comment.

### Persistent runner-local test history

Every self-hosted runner agent owns a separate `test-runs.db` outside its
checkout. Big Tam stores it below that agent's registered tool cache at
`/srv/ci/work-N/_tool/yuzu-test-runs/yuzu-bigtam-linux-N/test-runs.db`;
Wee Tam stores it at
`D:\ci\test-runs\yuzu-weetam-windows-N\test-runs.db`. The files survive
`actions/checkout`, branch-switch build wipes and runner restarts. They are
deliberately per-agent rather than per-host: telemetry must not introduce a
shared SQLite writer lock between the four jobs whose contention it measures.

The Linux and Windows jobs in `ci.yml` call `scripts/ci/ci-telemetry.py` near
job start and from an `always()` finalizer. Schema v3 records GitHub run attempt,
job/platform/runner, commit/branch/event, conclusion and wall time, ccache ratio,
each Meson test entry's result/duration/timeout, and any listed flake recovered
by `flake-retry`. A cancelled job normally finalizes as `cancelled`; a hard kill
that prevents post-steps intentionally leaves an `in_progress` row, which is
itself evidence of runner/job termination rather than a fabricated result.

Provisioning is versioned in
[`deploy/linux/Provision-BigTam-Runner-Telemetry.sh`](../deploy/linux/Provision-BigTam-Runner-Telemetry.sh)
and [`deploy/windows/Provision-Windows-Runner.ps1`](../deploy/windows/Provision-Windows-Runner.ps1).
Query a runner in place by setting `YUZU_TEST_DB` and using:

```bash
bash scripts/test/test-db-query.sh ci-stats --since 30d
bash scripts/test/test-db-query.sh ci-suite-stats --since 30d
bash scripts/test/test-db-query.sh ci-flakes --since 30d
```

GitHub-hosted macOS agents are ephemeral and cannot meet this runner-local
persistence contract; their test logs remain retained Actions artifacts.

Inventory declared in `.github/runner-inventory.json`. The sentinel at
`runner-inventory-sentinel.yml` (every 30 min) compares actual to expected
and opens a `runner-inventory-drift` issue on mismatch. Both the sentinel
and the new ci.yml `preflight` job share `scripts/ci/runner-health-check.py`
(`--mode sentinel` vs `--mode preflight`). Preflight gates downstream
self-hosted jobs with explicit
`if: needs.preflight.outputs.<runner>_healthy == 'true'`. Each workflow also
declares its required pools with `--require-pool`. A wholly unavailable
required pool fails preflight red instead of silently turning its required
jobs into successful skips. The control interface distinguishes observed
runner drift from authentication, API/transport, and malformed-response
failures; missing evidence is a failure, never an inferred healthy state.
The query requires the `RUNNER_INVENTORY_TOKEN` PAT secret (fine-grained,
Administration:read on Tr3kkR/Yuzu). Expected failures publish a typed
`failure_kind` and `failure_report`; an unexpected crash before those outputs
still takes the sentinel's fallback issue path.

Automatic fork PRs are rejected before the runner query and cannot emit
healthy self-hosted outputs. Runner-control failures and required-pool outages
are red operational failures. In particular, an offline Big Tam or Wee Tam
pool causes nightly preflight to fail and the nightly alert opens
`nightly-broken`; the repository discipline remains **no merge to main while
that issue is open**. Follow `docs/ci-troubleshooting.md` before closing it.

As of #1978, preflight also emits a `code_changed` output (from
`scripts/ci/detect-code-change.sh`); the build jobs additionally gate on
`&& code_changed == 'true'`, so a docs-only PR skips the whole matrix. The
matrix-expanded required contexts (`Linux gcc-15 debug`, `Windows MSVC debug`,
`macOS debug`) would otherwise stay "Expected" forever on a docs-only PR
(a top-level-skipped matrix job emits none of its inner check names), so a
`docs-required-checks` stub emits those exact names as success when
`code_changed == 'false'`. `ci.yml` no longer path-filters `pull_request`;
the `push:` trigger keeps its docs `paths-ignore`.

## Postgres for server tests (`YUZU_TEST_POSTGRES_DSN`)

ADR-0006 decision 8: every tier that runs the server **`[pg]`** suite gets a
real PostgreSQL and exports `YUZU_TEST_POSTGRES_DSN`. The shipped substrate is
**PostgreSQL 18** (`deploy/docker/Dockerfile.postgres`), and the Linux/docker +
Windows legs test against it; the server SQL is version-agnostic (13+), so a
runner-native cluster on an older major still exercises the suites correctly.
One script implements it everywhere — `scripts/ci/ensure-postgres.sh`, inserted
as an `Ensure Postgres (server tests)` step between Build and Test in ci.yml
(linux / windows) and nightly.yml (asan / tsan / coverage).

**macOS does NOT run the server `[pg]` suite (ADR-0035; #2394).** The Yuzu
server is a Linux-only component (macOS/Windows are agent-only platforms), and
GHA-hosted macos-15 runs a *single* brew Postgres cluster. After the
auth→Postgres migration (ADR-0006) roughly doubled the `[pg]` population to
~660 clone-bound cases (`CREATE DATABASE … TEMPLATE` + `DROP … FORCE` per
case), one slow cluster cannot service that within the per-suite meson budget,
and sharding does not help — parallel shards contend on the one cluster (both
hit their timeout). So the macOS leg deliberately **does not provision Postgres
/ export the DSN**: every `[pg]` server test then SKIPS (env-unset → skip, the
same contract the Catch2 PG fixtures use), completing in milliseconds, while
the non-PG server suite (`~[pg]`), the agent suite, and the Apple-Clang compile
still run. Linux + Windows keep full `[pg]` coverage. Re-enabling it requires
first solving the single-cluster capacity problem (per-shard clusters or a
cheaper per-test isolation model than database-per-test).
Resolution order inside the script:

1. **Pre-set `YUZU_TEST_POSTGRES_DSN`** (runner-level env) — the escape
   hatch for any bespoke runner setup. On a **multi-agent box** (runner
   name ending `-<n>`, i.e. the 4-runner pools) the pre-set DSN names the
   *agent-0* cluster and agent `<n>` uses **port + `<n>`** when that
   per-agent cluster answers a probe — one instance per agent, so
   concurrent jobs never share a WAL/buffer pool (#2094, the 2026-07-12
   Wee Tam server-suite timeouts). Until a box is provisioned with the
   extra clusters the script falls back to the shared pre-set DSN with a
   `::warning` — no flag day. Runners without a `-<n>` suffix use the DSN
   as-is. **The DSN must not set `options=`, and `PGOPTIONS` must be unset
   in the job environment** (checked unconditionally, before path
   selection) — either silently disables PgPool's `statement_timeout`/
   `lock_timeout` safety-bound GUCs (`pg_pool.cpp`'s `conninfo_has_options_`
   gate), caught by the `[pg][hardening]` test "PgPool injects
   statement_timeout and lock_timeout GUCs". Put durability tuning in
   `postgresql.conf` via `ALTER SYSTEM` instead (#2167).
2. **Docker** (self-hosted Linux) — idempotent persistent container
   (`docker start` || `docker run --restart unless-stopped`, image pinned
   to the same digest as `deploy/docker/Dockerfile.postgres`'s base;
   one-time cost per runner). On the multi-agent `yuzu-bigtam-linux` pool
   each agent gets **its own container** — `yuzu-ci-postgres-<n>` on
   `127.0.0.1:15440+<n>`, `max_connections=400` (#2094/#2096),
   self-created on the agent's first job. Single-agent boxes keep the
   shared `yuzu-ci-postgres` on `127.0.0.1:15432`. The 15440+ base and
   15432 avoid colliding with native clusters (5432), the dev pg-canary
   (5433), and the UAT sidecar (15433). Lifecycle is `flock`-serialized
   per container name.
3. **brew** (GHA-hosted macOS, no docker) — `postgresql@18` bottle +
   throwaway trust-auth cluster under `$RUNNER_TEMP` on
   `127.0.0.1:15432`.
4. **Native cluster on `127.0.0.1:5432`** — the generic self-hosted
   Windows precondition: a PostgreSQL 16+ Windows service with role
   `yuzu` / password `yuzu` / database `yuzu_test`, bootstrapped
   **once** per runner (installer or `choco install postgresql16`, then
   `createuser`/`createdb` as above). When `psql` is on PATH the script
   authenticates the conventional DSN with `SELECT 1` before exporting
   it — a TCP listener with the wrong credentials produces a `::warning`
   and no DSN rather than a false "ready". Without `psql` it falls back
   to the bare TCP probe with a loud unverified-credential warning.
   Prefer the runner-level env override (path 1) if the box already runs
   Postgres with different credentials.

   **Wee Tam (`yuzu-weetam-windows`) uses path 1, not path 4:** each runner
   provides native PostgreSQL **18** services — agent 0's winget-installed
   `postgresql-x64-18-yuzu-ci` on `:5433` plus one initdb'd cluster per
   further agent (`postgresql-x64-18-yuzu-ci-<n>` on `:5433+<n>`, #2094) —
   and a machine-level `YUZU_TEST_POSTGRES_DSN` (the agent-0 DSN; path 1
   derives the per-agent port) that wins before the docker probe, so the
   leg stays deterministic regardless of any Docker engine state.
   Provisioning specifics live in
   [`deploy/windows/`](../deploy/windows/README.md). (The retired
   `yuzu-local-windows` box ran a PG 16 binaries-zip service on 5433 — see
   git history if that bootstrap pattern is ever needed again.)
5. Nothing found → `::error`, exit 1.

**Fatal on every non-success path since #1320 PR 1 (`SOFT_EXIT=1`):**
the pg substrate suites (`[pg]`-tagged cases in the server suite)
consume the DSN and skip cleanly when it is unset — so a runner without
a database would silently skip that coverage. `exit "$SOFT_EXIT"`
(= exit 1) is reached on every failure path: Docker container not ready
in 60 s (path 2), brew cluster not ready (path 3), native-cluster
credential failure when `psql` is available (path 4), and nothing found
(path 5). The one non-fatal exception is path 4 without `psql`: a TCP
probe alone produces a `::warning` and still exports the conventional
DSN (credential **unverified** — wrong credentials then surface as
downstream `[pg]` test failures; install `psql` on the runner's PATH,
e.g. `C:\Program Files\PostgreSQL\18\bin` on the `yuzu-weetam-windows` runners, to
get the authenticated gate instead). Locally the tests still skip when
`YUZU_TEST_POSTGRES_DSN` is unset; when it is set but unreachable they
fail rather than skip.

Local-dev note: to run the non-pg server tests on a machine with no
Docker and no Postgres, invoke the test binary directly
(`tests-build-server-*/yuzu_server_tests`) with `YUZU_TEST_POSTGRES_DSN`
unset — the `[pg]` cases skip cleanly. The `/test` skill and CI
deliberately hard-fail at the ensure-postgres step instead (that is the
gate working, not a skill bug).

Operational notes for shared instances: on a box where a Postgres
instance IS still shared across concurrent jobs (single-agent boxes, or
a multi-agent box before its per-agent instances are provisioned —
the fallback `::warning`), the migration runner's advisory locks are
**cluster-wide**, so same-named stores in different ephemeral test
databases briefly serialize on each other (transaction-scoped locks:
never deadlock, never cross-database corruption). The 4-agent pools run
**one instance per agent** (#2094) precisely so no job shares WAL/fsync
bandwidth — or advisory-lock space — with a concurrent job. After the
Big Tam cutover the legacy shared `yuzu-ci-postgres` container on
`:15432` is unused there and can be `docker rm -f`'d.

**Test-database lifecycle (PR #2091).** Ephemeral per-case databases
(`yuzu_test_<epoch>_<salt>_<n>`, created/dropped by `PostgresTestDb`) coexist
with run-lifetime shared clones (one clone and persistent pool for each
instantiated eligible high-volume test file) and per-process **template** databases
(`yuzu_test_tpl_<epoch>_<salt>_<key>`, built once by `PgTestTemplate` and
dropped at `testRunEnded`). At run end the listener invokes one ordered shared
cleanup primitive: it drains every persistent pool first, drops those clones,
then drops the templates, all before libpq/OpenSSL teardown. The active footprint
is therefore the per-case databases currently in flight, one clone per
instantiated shared-fixture file, and up to ~a dozen templates for each of the
box's 4 runner agents. A pile-up is NOT
automatically "teardown is failing": names embed their creation epoch, and
every suite start sweeps names older than 6 h (`kTestDbStaleAfterSeconds`),
so leaks from killed runs self-heal within that window; the sweep prints a
`sweep saw N ... dropped M` summary in the job log. A weekly out-of-band
janitor complements it (#1367): `cache-prune.yml` (Sundays 04:00 UTC +
`workflow_dispatch`) runs `scripts/ci/sweep-test-databases.sh` on both
self-hosted boxes, so leaks reclaim even on a box that stops running `[pg]`
legs. The janitor self-discovers the per-agent topology from #2094/#2114 —
every running `yuzu-ci-postgres(-<n>)` container on the docker boxes, and in
DSN mode the machine DSN's base port plus the next three per-agent ports
(dark higher ports are the normal pre-cutover state and skip silently); a
degraded sweep (psql missing, cluster dark, a pass query failing) exits
nonzero so the weekly run goes red rather than rotting silently.
Epoch-named databases age by the same >6 h/server-clock rule; names
the epoch sweeper can never parse (pre-epoch format `yuzu_test_<salt>_<n>`,
implausible clock stamps) are dropped only when the datdir's `PG_VERSION`
mtime exceeds 7 days AND the database has zero active backends
(superuser-only via `pg_stat_file`; dropped without FORCE so a racing
connection vetoes). Hand-cleaning a wedged instance: only ever touch
`yuzu_test_*`/`yuzu_test_tpl_*` names; prefer "name-epoch older than 6 h"
over "no current connections" (a live fixture is momentarily
connection-free between drop and re-create); pre-epoch-format names are
reclaimed by the weekly cron after 7 days — hand-clean only if one must go
sooner. The server suite's meson timeout was recalibrated 600 s → 900 s in
the same PR, then split into `[pg]`/`~[pg]` shards at 600 s each (#2092;
see the comment above the two `test('server ...', ...)` entries in
`tests/meson.build`).

## Universal vcpkg cache-key contract

`scripts/ci/vcpkg-triplet-sentinel.sh` is the single source of truth for
"have the inputs to vcpkg actually changed?". Key:

```
sha256(vcpkg.json + vcpkg-configuration.json + triplets/<triplet>.cmake + $VCPKG_COMMIT)
```

Stored at `vcpkg_installed/.<triplet>-cachekey.sha256`. On drift, wipes
`vcpkg_installed/<triplet>/` AND `vcpkg_installed/vcpkg/` (the
per-workspace registry — `info/`, `status`, `updates/`. Leaving the
registry behind after wiping the triplet tree leaves orphaned
`info/<port>_<triplet>.list` entries that make the next `vcpkg install`
short-circuit to "already installed" and then fail post-install
pkgconfig validation; this was #741.) Never touches `$WS/vcpkg/` (the
sibling vcpkg tool root, owned by lukka/run-vcpkg), never
`runner.tool_cache`, never ccache. Persistence: self-hosted in
`${runner.tool_cache}/yuzu-vcpkg-binary-cache-{linux,asan,windows}`
(per-triplet, outside workspace). macOS uses `actions/cache@v5` keyed on
the same invariant.

The script must run cleanly under MSYS2 bash on Windows. **Do NOT use
`set -e` + `[[ test ]] && cmd` short-circuits** — they silently exit under
MSYS2 (cost us run #25051196135). Use `if/fi` blocks and explicit
per-command error checks.

## Persistence and recovery

Normal self-hosted checkouts use `clean: false`. Pre-checkout wipes
`build-<os>/` ONLY on branch change; vcpkg state is invalidated by the
sentinel above. A trusted fork execution is the intentional exception: it uses
`clean: true`, private temporary ccache/test paths, `VCPKG_BINARY_SOURCES=clear`,
and a final checkout-only purge. `meson setup --reconfigure` when
`meson-info/` exists. Manual recovery:
`bash scripts/ci/runner-reset.sh`
(`git clean -fdx -e vcpkg/ -e vcpkg_installed/ -e build-*/`) — **the only
sanctioned in-repo nuke path**; never `rm -rf` runner caches (memory
`feedback_vcpkg_cache.md`).

## Per-OS build directory names

Matrix: `build-{linux,windows,macos}`. Nightly variants:
`build-linux-{asan,tsan,coverage}`. `sanitizer-tests.yml` + `release.yml` +
`pre-release.yml` follow the same convention so the warm asan binary cache
is shared. Closes #406.

## Flaky-test retry (`flake-retry`)

`scripts/ci/flake-retry.py` wraps the `meson test` step on `ci.yml`'s three
test legs (PR fast-path + push matrix; **not** nightly/sanitizer, which stay
fail-loud so a real ASan/TSan race is never masked). Every run — green
included — first gets the #2093 duration watchdog: a per-suite
duration/budget table in the step summary, plus a `::warning` for any suite
past 80% of its meson timeout (reporting only; pass/fail semantics never
change). On a clean run it does nothing further. On failure it isolates the
failed **Catch2 case(s)** — it re-runs the
failed suite binary (located via `meson introspect --tests`) with Catch2's own
junit reporter, since meson's junit is only suite-level — then:

- any failed case **not** in `tests/known-flaky.json` (scoped to this OS) →
  the job **fails** (real regressions stay blocking);
- a failed suite that can't be classified per-case (non-Catch2, e.g. the
  gateway eunit/ct legs, or a crash/timeout with no junit) → **fails** (never
  mask);
- a **listed** case is retried in isolation up to 2× (`--retries`); the job
  passes only if it recovers, and a listed case that fails every retry still
  **fails** (a regression *inside* a flaky test is caught too).

`tests/known-flaky.json` is the static, in-repo, PR-curated source of truth —
one entry per case with `platforms` (OS-scoped; `["all"]` = cross-platform),
`reason`, tracking `issue`, accountable `owner`, and ISO-8601 `added` and
`expires` dates. Every field is required for every entry, including entries for
another OS. An entry expires at the end of its stated date; an expired or
malformed list fails before `meson test` starts, so stale exemptions cannot
silently mask a red build. Cross-platform flakes emit a loud `::warning` (they
signal a genuinely nondeterministic test, not an env quirk); OS-scoped ones a
`::notice`. Entries older than 90 days still get a soft `::warning` before their
hard expiry. Case names and platform values are unique, and `all` cannot be
combined with an OS. Expiry uses the UTC calendar date; the validator's clock is
injectable for hermetic tests.

The job summary + annotations remain the immediate signal. In addition,
`flake-retry.py` writes `meson-logs/flake-retry.json`; the job finalizer imports
recovered listed cases into the runner's `ci_flake_events` table alongside the
suite timings. `tests/known-flaky.json` remains the reviewed source of truth —
the database is observation history, never an implicit allowlist. This is
reversible test tooling — no ADR (rationale in the wrapper header).

**Triage note — shared-fixture files fail as a cluster on a PG blip.** The
shared-DB + TRUNCATE fixture files (#2362, #2603: `test_software_inventory_store`,
`test_software_licensing_*`, `test_product_registry_store`,
`test_rest_access_review`, `test_engine_principal_{lifecycle,integration}`, and
later conversions) hold one clone + one pool for the whole file. A Postgres
blip mid-file therefore reds out *several unrelated-looking CRUD cases in one
file* — and flake-retry's isolated re-run (fresh process, fresh clone) will
often recover them, so the incident can masquerade as N independent "recovered
known flakes". Before treating such a cluster as N regressions (or adding them
to `known-flaky.json`), grep the junit failure text for
`PGRES_COMMAND_OK`, `REQUIRE( lease )`, `is_open()`, or the bundle/reset tags
(`[ApiTokenStorePgShared]`, `[AuthDbPgShared]`, `[EpLcShared]`,
`[EpIntegShared]`, `[AccRevShared]`, `acc_rev_reset`) — a cluster of those in
one file is one PG-instance event, not a test bug.

## Workflow-PR canary

`ci.yml`'s `detect-ci-changes` + `canary` jobs run when a PR or main push
touches `.github/workflows/`, `.github/actions/`, or `scripts/ci/`. The named
`ci-infrastructure` class in `scripts/ci/detect-code-change.sh` owns both the
path rules and `git diff` error handling. If the diff cannot be established,
it returns changed=true so the canary runs fail-closed. Canary mirrors the
linux build on a fresh-disk GHA-hosted `ubuntu-24.04` with `actions/cache` for
vcpkg — catches workflow regressions before main.

## Cache pruning + weekly maintenance

`cache-prune.yml` runs weekly (Sun 04:00 UTC) on each self-hosted runner.
Deletes `${RUNNER_TOOL_CACHE}/yuzu-vcpkg-binary-cache-*/<file>` >30 days
old. Does not touch ccache (own LRU at `CCACHE_MAXSIZE=30G`).
Also sweeps the buildx local cache the chisel images write
(`/mnt/d/docker-buildcache/*-chisel`, `mode=max` — several GB/arch, no
built-in eviction); whole-`*-chisel`-dir mtime sweep >30 days, Linux only.
Since #1367 the same run also executes `scripts/ci/sweep-test-databases.sh`
on both boxes — the weekly out-of-band janitor for leaked `yuzu_test_*`
databases (thresholds and semantics: "Test-database lifecycle" above).

## Chiselled demo images + agent bundle (release-time)

`docker-publish-chisel` (in `release.yml`) builds the server/gateway/agent
`*.chisel` images multi-arch — linux/amd64 native + linux/arm64 via **QEMU**
— on the self-hosted Linux runner. The emulated arm64 vcpkg-from-source
compile can hold that single runner slot up to its 360-min timeout, so the
job carries a `cancel-in-progress: true` concurrency group (a re-tagged
release supersedes a stale build instead of queueing behind it). It is
**not** in the `release` job's `needs:`, so a slow/failed demo-image build
never blocks the actual release. The sustainable fix for the QEMU cost is a
native arm64 runner — the open decision tracked in `docs/demo-environment.md`
("Publishing").

`docker-publish-agent-bundle` runs **after** `release` (it repackages the
release's own signed agent archives) on a GitHub-hosted runner — no
compilation, so no self-hosted dependency — and cosign-signs + SBOMs +
attests the pushed `yuzu-agent-bundle-chisel` image like the other publish
jobs.

## vcpkg state corruption — recovery path

If a Windows CI run repeatedly fails at `Install vcpkg packages` with a
missing `.pc` file under `vcpkg_installed/x64-windows/lib/pkgconfig/`, the
corruption is in `vcpkg/packages/` (which the cache-key sentinel does NOT
reach). Recovery procedure + full corruption-path inventory:
`docs/ci-troubleshooting.md` §7. Don't leave the recovery step in `ci.yml`
after an incident — it defeats the cache.
