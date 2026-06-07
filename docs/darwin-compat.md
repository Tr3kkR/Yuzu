# Darwin (macOS) Compatibility Guide

This Claude instance is the designated **macOS/Darwin compatibility guardian** for Yuzu. The `cross-platform` agent loads this document on any change that may affect macOS builds, tests, or runtime behavior.

CLAUDE.md keeps a one-line pointer; this document holds the workflow and the standing pitfalls table.

## Standing workflow

When Windows-originated changes land on `origin/dev`, the standing reconciliation workflow is:

1. `git fetch origin && git status` — confirm branch state.
2. `git pull` — fast-forward to latest dev.
3. `git diff HEAD~N..HEAD --stat` — review what changed.
4. Identify which previous Darwin fixes are still present in the new tree.
5. `meson setup build-macos --reconfigure ...` if `meson.build` changed.
6. `meson compile -C build-macos` — fix any new compile errors.
7. `bash scripts/run-tests.sh all` — fix any new test failures.
8. Commit clean with a Darwin-fix commit message.

After **any** cross-platform change, always run `bash scripts/run-tests.sh all` on Darwin before committing.

## Standing Darwin pitfalls

| Area | Issue |
|---|---|
| Path comparisons | macOS `/var` → `/private/var` symlink: always call `fs::canonical()` on both sides before comparing paths in tests. |
| SQLite concurrency | All stores must open with `sqlite3_open_v2()` using `SQLITE_OPEN_READWRITE \| SQLITE_OPEN_CREATE \| SQLITE_OPEN_FULLMUTEX` flags — never plain `sqlite3_open()`. Application-level mutexes (`shared_mutex`) are retained as defense-in-depth and are **required** (not optional) for stores with cached prepared statements, because FULLMUTEX does not make bind-step-reset sequences atomic. |
| Erlang rebar3 ct | Always pass `--dir apps/yuzu_gw/test` together with `--suite` flags. |
| `curl -f` in tests | Do **not** use `-f` where 4xx is an acceptable response — it causes `|| echo "000"` fallbacks to contaminate the status code variable. |
| `prometheus_httpd` | Use `start/0` with `application:set_env(prometheus, prometheus_http, [{port, P}, {path, "/metrics"}])` — `start/1` does not exist. Call `application:ensure_all_started(prometheus_httpd)` first so `prometheus_http_impl:setup/0` runs before the first scrape. |

## Per-OS build directory

The Yuzu source tree is built from multiple hosts (WSL2 Linux + native Windows on the same physical machine, plus this macOS dev box). `scripts/setup.sh` selects the canonical `build-macos` directory automatically and refuses to reconfigure a directory whose recorded source path looks like a different host's. See CLAUDE.md `## Build` → `### Per-OS build directory convention` for the full rule.

## macOS `/test` prerequisites

Before invoking `/test` (the pre-commit/pre-push gate skill) on a fresh macOS dev box, install:

| Tool | Install | Why |
|---|---|---|
| GNU bash 5+ | `brew install bash` | `mapfile` and `declare -A` are bash-4-only; stock `/bin/bash` 3.2 trips the version guards in `preflight.sh`, `perf-gate.sh`, `teardown.sh`, `test-fixtures-verify.sh` |
| Erlang/OTP 28 | via kerl (see `scripts/ensure-erlang.sh` or `scripts/darwin-activate-erlang.sh` if you've created a local shim) | Gateway build + EUnit + dialyzer |
| OrbStack or Docker Desktop | GUI / `brew install --cask orbstack` | Phase 1 image build + Phase 2 upgrade-test. Without a running Docker daemon both phases SKIP gracefully (the rest of `/test` continues), but you cannot exercise the upgrade-test surface |

UAT bring-up is `bash scripts/start-UAT.sh` (cross-platform; `linux-start-UAT.sh` is a back-compat shim). The `_portable.sh` helper auto-discovers OrbStack at `/Applications/OrbStack.app/Contents/MacOS/xbin/docker` and Docker Desktop at `/Applications/Docker.app/Contents/Resources/bin/docker` — you do not need either on PATH globally.
