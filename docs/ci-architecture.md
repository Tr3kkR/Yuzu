# CI architecture — runner topology, vcpkg cache, persistence

Reference for Yuzu's three-tier CI architecture (April 2026 overhaul).
CLAUDE.md keeps the headline tier breakdown + runner topology; this document
holds the cache-key contract, persistence rules, and operational knobs that
the `build-ci` agent loads on workflow / vcpkg / scripts/ci changes.

Plan of record: `/home/dornbrn/.claude/plans/our-ci-has-been-piped-castle.md`.
Failure-mode runbook: `docs/ci-troubleshooting.md`.

## Tier summary (mirrors CLAUDE.md)

- **Tier 1 — PR fast-path** (`ci.yml` on `pull_request`): one Linux variant
  (gcc-13 debug on `yuzu-wsl2-linux`), one Windows variant (MSVC debug on
  `yuzu-local-windows`), one macOS variant (appleclang debug on GHA-hosted
  `macos-15`), plus `proto-compat`. Wall target: <10 min per leg.
- **Tier 2 — push to dev/main** (`ci.yml` on push): full 4-way Linux matrix
  (gcc-13 / clang-19 × debug / release), 2-way Windows, 2-way macOS. **No
  sanitizers, no coverage** — those moved out (#410).
- **Tier 3 — nightly cron** (`nightly.yml`, `0 6 * * *` UTC +
  `workflow_dispatch`): ASan+UBSan, TSan, coverage on the self-hosted Linux
  runner. On any leg failure, the `alert` job auto-opens or comments on a
  `nightly-broken` issue. **Discipline norm: no merge to main while a
  `nightly-broken` issue is open.**

  The TSan leg preloads `/tmp/libgai_sync_shim.so` (built inline from a
  ~30-line C file at job start) to replace glibc's `getaddrinfo_a()` async
  DNS path with synchronous `getaddrinfo()` on the calling thread. Required
  because cpp-httplib enables `CPPHTTPLIB_USE_NON_BLOCKING_GETADDRINFO=ON`
  by default (vcpkg port), which makes glibc spawn an async-DNS helper
  thread via `clone3` directly — bypassing TSan's `pthread_create`
  interceptor — so the helper's per-thread allocator state is never
  initialised and the first `malloc()` from it segfaults inside
  `__tsan::SizeClassAllocator64LocalCache::Allocate (this=0x8)` (#438).
  Scoped to the TSan job via step-level `env: LD_PRELOAD`; production
  keeps the non-blocking-DNS behaviour. The same shim is mirrored into
  `sanitizer-tests.yml` so `/test --full` benefits identically.

  On Test failure, the TSan job's `Capture stack trace under gdb`
  diagnostic re-runs `yuzu_server_tests` under `gdb -batch` with the
  Catch2 seed replayed, dumps `thread apply all bt full` + `info
  registers`, and rides the existing `meson-testlog-tsan` artifact.

`workflow_dispatch` only works once a workflow file exists on the **default
branch (`main`)**. Cron schedules likewise. New workflows added on `dev` are
dormant until merged.

## Self-hosted runner topology

| Runner | Host | Jobs |
|---|---|---|
| `yuzu-wsl2-linux` | Shulgi 5950X WSL2 Ubuntu 24.04 | proto-compat, linux matrix, nightly (asan/tsan/coverage), cache-prune-linux |
| `yuzu-local-windows` | Shulgi native Windows 11 | windows matrix, cache-prune-windows |
| `macos-15` | GitHub-hosted | macos matrix |

Inventory declared in `.github/runner-inventory.json`. The sentinel at
`runner-inventory-sentinel.yml` (every 30 min) compares actual to expected
and opens a `runner-inventory-drift` issue on mismatch. Both the sentinel
and the new ci.yml `preflight` job share `scripts/ci/runner-health-check.py`
(`--mode sentinel` vs `--mode preflight`). Preflight gates downstream
self-hosted jobs with explicit
`if: needs.preflight.outputs.<runner>_healthy == 'true'` — fail-closed: a
degraded runner skips its jobs in <30 s rather than queueing 30 min into a
stalled runner. Requires the `RUNNER_INVENTORY_TOKEN` PAT secret
(fine-grained, Administration:read on Tr3kkR/Yuzu); without it preflight
returns false and self-hosted jobs are skipped with a clear reason.

## Postgres for server tests (`YUZU_TEST_POSTGRES_DSN`)

ADR-0006 decision 8: every tier that runs server tests gets a real
PostgreSQL 16 and exports `YUZU_TEST_POSTGRES_DSN`. One script implements
it everywhere — `scripts/ci/ensure-postgres.sh`, inserted as an
`Ensure Postgres 16 (server tests)` step between Build and Test in
ci.yml (linux / windows / macos) and nightly.yml (asan / tsan / coverage).
Resolution order inside the script:

1. **Pre-set `YUZU_TEST_POSTGRES_DSN`** (runner-level env) — trusted
   as-is. The escape hatch for any bespoke runner setup.
2. **Docker** (self-hosted Linux: `yuzu-wsl2-linux` / `yuzu-shulgi`) —
   idempotent persistent container `yuzu-ci-postgres` on
   `127.0.0.1:15432` (`docker start` || `docker run --restart
   unless-stopped`, image pinned to the same digest as
   `deploy/docker/Dockerfile.postgres`'s base). One-time cost per runner;
   port 15432 avoids colliding with native clusters or UAT rigs on 5432.
3. **brew** (GHA-hosted macOS, no docker) — `postgresql@16` bottle +
   throwaway trust-auth cluster under `$RUNNER_TEMP` on
   `127.0.0.1:15432`.
4. **Native cluster on `127.0.0.1:5432`** — the `yuzu-local-windows`
   precondition: a PostgreSQL 16 Windows service with role `yuzu` /
   password `yuzu` / database `yuzu_test`, bootstrapped **once** per
   runner (installer or `choco install postgresql16`, then
   `createuser`/`createdb` as above). When `psql` is on PATH the script
   authenticates the conventional DSN with `SELECT 1` before exporting
   it — a TCP listener with the wrong credentials produces a `::warning`
   and no DSN rather than a false "ready". Without `psql` it falls back
   to the bare TCP probe with a loud unverified-credential warning.
   Prefer the runner-level env override (path 1) if the box already runs
   Postgres with different credentials.
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
e.g. `C:\Program Files\PostgreSQL\16\bin` on `yuzu-local-windows`, to
get the authenticated gate instead). Locally the tests still skip when
`YUZU_TEST_POSTGRES_DSN` is unset; when it is set but unreachable they
fail rather than skip.

Local-dev note: to run the non-pg server tests on a machine with no
Docker and no Postgres, invoke the test binary directly
(`tests-build-server-*/yuzu_server_tests`) with `YUZU_TEST_POSTGRES_DSN`
unset — the `[pg]` cases skip cleanly. The `/test` skill and CI
deliberately hard-fail at the ensure-postgres step instead (that is the
gate working, not a skill bug).

Two operational notes for shared instances: the `yuzu-ci-postgres`
container is shared across concurrent jobs on a runner — the migration
runner's advisory locks are **cluster-wide**, so same-named stores in
different ephemeral test databases briefly serialize on each other
(transaction-scoped locks: never deadlock, never cross-database
corruption). And every test database is created/dropped per case by the
`PostgresTestDb` fixture; a `yuzu_test_*` pile-up on a shared instance
means teardown is failing and is logged to stderr by the fixture.

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

Self-hosted checkouts use `clean: false`. Pre-checkout wipes `build-<os>/`
ONLY on branch change; vcpkg state is invalidated by the sentinel above.
`meson setup --reconfigure` when `meson-info/` exists. Manual recovery:
`bash scripts/ci/runner-reset.sh`
(`git clean -fdx -e vcpkg/ -e vcpkg_installed/ -e build-*/`) — **the only
sanctioned in-repo nuke path**; never `rm -rf` runner caches (memory
`feedback_vcpkg_cache.md`).

## Per-OS build directory names

Matrix: `build-{linux,windows,macos}`. Nightly variants:
`build-linux-{asan,tsan,coverage}`. `sanitizer-tests.yml` + `release.yml` +
`pre-release.yml` follow the same convention so the warm asan binary cache
is shared. Closes #406.

## Workflow-PR canary

`ci.yml`'s `detect-ci-changes` + `canary` jobs run only when a PR touches
`.github/workflows/`, `.github/actions/`, or `scripts/ci/`. Canary mirrors
the linux build on a fresh-disk GHA-hosted `ubuntu-24.04` with
`actions/cache` for vcpkg — catches workflow regressions before main.

## Cache pruning

`cache-prune.yml` runs weekly (Sun 04:00 UTC) on each self-hosted runner.
Deletes `${RUNNER_TOOL_CACHE}/yuzu-vcpkg-binary-cache-*/<file>` >30 days
old. Does not touch ccache (own LRU at `CCACHE_MAXSIZE=30G`).
Also sweeps the buildx local cache the chisel images write
(`/mnt/d/docker-buildcache/*-chisel`, `mode=max` — several GB/arch, no
built-in eviction); whole-`*-chisel`-dir mtime sweep >30 days, Linux only.

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
