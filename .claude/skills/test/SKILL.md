---
name: test
description: Run the Yuzu pre-commit/pre-push test pipeline. Compiles HEAD, stands up the previous release, upgrades it, runs the full standard test surface, records every result + sub-step timing into a durable SQLite test-runs DB. Use when the user says "/test" or asks to run the full test pipeline before commit.
---

# test

Runbook for the Yuzu `/test` pipeline. This skill is a **bash-first orchestrator**, not an agent fan-out. Each phase is one or more shell invocations the LLM executes via the `Bash` tool. The LLM's job is to interpret failures, decide whether to continue, and produce the consolidated report at the end. Every gate result + sub-step timing lands in `~/.local/share/yuzu/test-runs.db` so the operator can compare runs over time.

## Usage

```
/test                  — default mode (~30-45 min): build + upgrade test + standard gates
/test --quick          — sanity check (~10 min): build + unit + EUnit + dialyzer (no live stack)
/test --full           — pre-tag (~60-120 min): adds OTA, sanitizers, perf, coverage enforce
/test --force-cleanup  — tear down THIS RUN's dangling test containers before starting
/test --keep-stack     — leave docker stacks running after the run (debugging)
```

Modes are layered: `--full` includes everything `default` runs, `default` includes everything `--quick` runs. The most common invocation is bare `/test` before `git push`.

**`--quick` does NOT include synthetic UAT or any other test that needs a live stack.** Quick mode is build + offline unit/EUnit/dialyzer only — there is no Phase 4 stack stand-up in quick mode, so no Phase 5 gate that requires HTTP to a live server. If you need stack-level confidence, use default mode.

## Workflow summary

```
Phase 0 — Preflight             (toolchains, ports, disk, docker, init DB)
Phase 1 — Build HEAD            (meson + rebar3 + docker build local :test images)
Phase 2 — Upgrade Test          (v0.10.0 → HEAD: fixtures, migrate, verify)
Phase 3 — OTA Agent Test        (--full only — Linux + Windows self-exec)
Phase 4 — Fresh Stack Stand-up  (full-uat at HEAD + native agent)
Phase 5 — Test Gates (parallel) (unit / EUnit / dialyzer / CT / integration /
                                 e2e-api / e2e-mcp / e2e-security /
                                 synthetic UAT / puppeteer)
Phase 6 — Sanitizers            (--full only — dispatched to yuzu-wsl2-linux runner)
Phase 7 — Coverage + Perf       (--full only — enforce baselines)
Phase 8 — Teardown + Summary    (down stacks, finalize test_runs row, print table)
```

Phase 1 is the only mandatory-blocking phase — if HEAD doesn't compile, nothing else can run. Every other phase runs to completion regardless of upstream failures so the operator gets a prioritized fix list in one pass.

**Every phase emits structured timing data into the test-runs DB.** Top-level gate timings land in `test_gates.duration_seconds`; sub-step timings (upgrade phases, OTA flow steps, individual command round-trips) land in `test_timings`. This is how trend analysis catches "Phase 2 upgrade got 3× slower since last week" without grepping log files.

> **PR1 status (this is the first ship of the skill).** Phases 0, 1, 2, 4, 5, 8 land in PR1. Phases 3 (cross-platform OTA), 6 (sanitizers via runner dispatch), and 7 (coverage + perf with baselines) are stubbed in `--full` mode with a "planned for PR2/PR3" message and recorded as `SKIP` rows in `test_gates`. The skill remains useful in default mode because the upgrade test path — the user's stated headline priority — is fully wired.

## Step 0 — Initialise run state

Generate a unique run ID and start the DB record. Run these in order at the start of every invocation:

```bash
RUN_ID="$(date +%s)-$$"
COMMIT="$(git rev-parse HEAD)"
BRANCH="$(git rev-parse --abbrev-ref HEAD)"
TEST_DIR="/tmp/yuzu-test-${RUN_ID}"
LOG_DIR="$HOME/.local/share/yuzu/test-runs/${RUN_ID}"
mkdir -p "$TEST_DIR" "$LOG_DIR"

# Pick mode from operator args (default if no flag)
MODE="${YUZU_TEST_MODE:-default}"  # quick / default / full

bash scripts/test/test-db-write.sh run-start \
    --run-id "$RUN_ID" \
    --commit "$COMMIT" \
    --branch "$BRANCH" \
    --mode "$MODE"
```

Record `RUN_ID` in your scratch space so every subsequent gate call can reference it. The DB row is in `RUNNING` state until Phase 8 finalizes it.

## Phase 0 — Preflight

```bash
bash scripts/test/preflight.sh                 # sanity checks
# or with cleanup:
bash scripts/test/preflight.sh --force-cleanup # tear down dangling test containers
```

**On failure**: do NOT proceed. Exit non-zero. Preflight failures are operator-fixable (free a port, clean up dangling containers, install a missing toolchain, free disk). The skill should print the preflight output verbatim and stop.

The preflight script also creates the test-runs DB at `~/.local/share/yuzu/test-runs.db` if missing, so the run-start above is safe to call.

Record gate result:
```bash
PREFLIGHT_START=$(date +%s)
bash scripts/test/preflight.sh && PRE_STATUS=PASS || PRE_STATUS=FAIL
PREFLIGHT_DUR=$(( $(date +%s) - PREFLIGHT_START ))
bash scripts/test/test-db-write.sh gate \
    --run-id "$RUN_ID" --phase 0 --gate "Preflight" \
    --status "$PRE_STATUS" --duration "$PREFLIGHT_DUR"
[[ "$PRE_STATUS" == "FAIL" ]] && { bash scripts/test/teardown.sh --run-id "$RUN_ID" --status ABORTED; exit 1; }
```

## Phase 1 — Build HEAD

Three sub-gates that can run in parallel via `&` + `wait`. Use the
unconditional `meson compile -C build-linux` form rather than naming
specific targets — the explicit-target form requires those targets to
exist (`yuzu_server_tests` only exists when `-Dbuild_tests=true`) and
the bare-name resolution can collide with sibling targets if multiple
subprojects define the same name.

```bash
# Build C++ binaries (server + agent + tests if enabled)
(
    set -e
    BUILD_START=$(date +%s)
    if meson compile -C build-linux > "$LOG_DIR/build-cpp.log" 2>&1; then
        STATUS=PASS
    else
        STATUS=FAIL
    fi
    DUR=$(( $(date +%s) - BUILD_START ))
    bash scripts/test/test-db-write.sh gate \
        --run-id "$RUN_ID" --phase 1 --gate "Build (C++)" \
        --status "$STATUS" --duration "$DUR" --log "build-cpp.log"
    bash scripts/test/test-db-write.sh timing \
        --run-id "$RUN_ID" --gate phase1 --step meson-compile --ms $((DUR * 1000))
) &

# Build Erlang gateway. Don't swallow ensure-erlang.sh errors — if Erlang
# is missing, we want the rebar3 invocation to surface the real diagnosis.
# `as prod release` (not just `compile`) is required so Phase 4's
# linux-start-UAT.sh can launch the gateway from gateway/_build/prod/rel/.
(
    set -e
    BUILD_START=$(date +%s)
    cd gateway
    source ../scripts/ensure-erlang.sh
    if rebar3 as prod release > "$LOG_DIR/build-erlang.log" 2>&1; then
        STATUS=PASS
    else
        STATUS=FAIL
    fi
    DUR=$(( $(date +%s) - BUILD_START ))
    bash scripts/test/test-db-write.sh gate \
        --run-id "$RUN_ID" --phase 1 --gate "Build (Erlang)" \
        --status "$STATUS" --duration "$DUR" --log "build-erlang.log"
    bash scripts/test/test-db-write.sh timing \
        --run-id "$RUN_ID" --gate phase1 --step rebar3-release --ms $((DUR * 1000))
) &

# Build local docker images for the upgrade test target (skip in --quick).
# Tag with the ghcr.io prefix directly so the upgrade-test compose file
# picks it up without a separate `docker tag` step in Phase 2.
if [[ "$MODE" != "quick" ]]; then
    (
        set -e
        BUILD_START=$(date +%s)
        if docker build \
            -t "ghcr.io/tr3kkr/yuzu-server:0.10.1-test-${RUN_ID}" \
            --label "yuzu.commit=$(git rev-parse HEAD)" \
            -f deploy/docker/Dockerfile.server . \
            > "$LOG_DIR/build-images.log" 2>&1; then
            STATUS=PASS
        else
            STATUS=FAIL
        fi
        DUR=$(( $(date +%s) - BUILD_START ))
        bash scripts/test/test-db-write.sh gate \
            --run-id "$RUN_ID" --phase 1 --gate "Build (HEAD docker images)" \
            --status "$STATUS" --duration "$DUR" --log "build-images.log"
        bash scripts/test/test-db-write.sh timing \
            --run-id "$RUN_ID" --gate phase1 --step docker-build --ms $((DUR * 1000))
    ) &
fi

wait
```

**Detect Phase 1 failure before continuing.** `wait` always exits 0 after
all background jobs complete — individual subshell failures do NOT
propagate via `wait`. Query the DB explicitly to detect any FAIL gate
in Phase 1 and short-circuit:

```bash
PHASE1_FAILS=$(python3 scripts/test/test_db.py query --export "$RUN_ID" \
    | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(sum(1 for g in d.get('gates', []) if g.get('phase') == 1 and g.get('status') == 'FAIL'))
")
if [[ "$PHASE1_FAILS" -gt 0 ]]; then
    echo "Phase 1 FAILED ($PHASE1_FAILS gates) — see logs in $LOG_DIR/build-*.log"
    bash scripts/test/teardown.sh --run-id "$RUN_ID" --status ABORTED
    exit 1
fi
```

Phase 1 is the only mandatory-blocking phase. If HEAD doesn't compile,
nothing else can run.

## Phase 2 — Upgrade Test (the user's headline priority)

Skipped in `--quick`. In default and `--full`:

```bash
bash scripts/test/test-upgrade-stack.sh \
    --run-id "$RUN_ID" \
    --old-version 0.10.0 \
    --new-version "0.10.1-test-${RUN_ID}" \
    --new-image-loaded 1 \
    --test-dir "$TEST_DIR"
```

The script records its own gate row (`Upgrade vOLD->vNEW`) and sub-step timings (`pull-old-images`, `stack-up-old`, `fixtures-write`, `image-swap`, `ready-after-upgrade`, `fixtures-verify`, `synthetic-uat-against-upgraded`). The skill doesn't need to record anything additional.

**On failure**: Phase 2 failure is informative but not blocking — continue to Phase 4. The teardown reads gate counts at the end and the operator decides whether to commit.

## Phase 3 — OTA Agent Test (PR3, stubbed in PR1)

For `--full` only:

```bash
if [[ "$MODE" == "full" ]]; then
    bash scripts/test/test-db-write.sh gate \
        --run-id "$RUN_ID" --phase 3 --gate "OTA Linux" \
        --status SKIP --duration 0 --notes "planned for PR3"
    bash scripts/test/test-db-write.sh gate \
        --run-id "$RUN_ID" --phase 3 --gate "OTA Windows" \
        --status SKIP --duration 0 --notes "planned for PR3"
    bash scripts/test/test-db-write.sh gate \
        --run-id "$RUN_ID" --phase 3 --gate "OTA macOS" \
        --status SKIP --duration 0 --notes "hardware pending Apple Silicon arrival"
fi
```

Once PR3 lands, replace the SKIP stubs with the real script invocations:
```bash
bash scripts/test/test-ota-agent-linux.sh   --run-id "$RUN_ID"
bash scripts/test/test-ota-agent-windows.sh --run-id "$RUN_ID"
bash scripts/test/test-ota-agent-macos.sh   --run-id "$RUN_ID"   # SKIP until hardware arrives
```

## Phase 4 — Fresh Stack Stand-up

Skipped in `--quick`. Default and `--full` use the existing `linux-start-UAT.sh` to bring up server+gateway+agent natively (faster than docker for Phase 5 e2e gates that hit the live stack):

```bash
PHASE4_START=$(date +%s)
if bash scripts/linux-start-UAT.sh > "$LOG_DIR/fresh-stack.log" 2>&1; then
    STATUS=PASS
else
    STATUS=FAIL
fi
DUR=$(( $(date +%s) - PHASE4_START ))
bash scripts/test/test-db-write.sh gate \
    --run-id "$RUN_ID" --phase 4 --gate "Fresh stack stand-up" \
    --status "$STATUS" --duration "$DUR" --log "fresh-stack.log"
```

**`linux-start-UAT.sh` correctly returns non-zero on any connectivity test failure** (this is the post-PR1 behavior — earlier versions exited 0 unconditionally, see CHANGELOG `[Unreleased]`). The Phase 4 gate's PASS/FAIL accurately reflects whether the 6 inline connectivity tests passed against the fresh stack. The Phase 5 Synthetic UAT gate runs again standalone with sub-step timing capture into the test-runs DB — both gates are intentional, not a duplicate.

## Phase 5 — Test Gates (parallel)

Run all gates concurrently via `&` + `wait`. Each is a self-contained bash invocation that captures its own log to `$LOG_DIR/<gate>.log`. Don't try to collect their stdout — read the log paths in the failure summary instead.

The pattern for every gate (note: `eval "$cmd"` is safe here because every
caller below passes a literal string constructed inline in this same skill;
the `cmd` argument is never read from operator input or external state):
```bash
gate_run() {
    local gate_name="$1" log_basename="$2" cmd="$3" phase="${4:-5}"
    (
        local start=$(date +%s)
        # eval is intentional: cmd contains compound shell expressions like
        # 'cd gateway && source ../scripts/ensure-erlang.sh; rebar3 ...'.
        # All cmd strings are author-controlled constants, never user input.
        if eval "$cmd" > "$LOG_DIR/$log_basename" 2>&1; then
            local status=PASS
        else
            local status=FAIL
        fi
        local dur=$(( $(date +%s) - start ))
        bash scripts/test/test-db-write.sh gate \
            --run-id "$RUN_ID" --phase "$phase" --gate "$gate_name" \
            --status "$status" --duration "$dur" --log "$log_basename"
    ) &
}
```

The default-mode Phase 5 fan-out:

```bash
gate_run "C++ unit (Catch2)" "unit-cpp.log" \
    "meson test -C build-linux --suite agent --suite server --suite tar --suite proto --suite docs --print-errorlogs"

gate_run "EUnit" "eunit.log" \
    "cd gateway && source ../scripts/ensure-erlang.sh 2>/dev/null; rebar3 eunit --dir apps/yuzu_gw/test"

gate_run "Dialyzer" "dialyzer.log" \
    "cd gateway && source ../scripts/ensure-erlang.sh 2>/dev/null; rebar3 dialyzer"

gate_run "CT suites" "ct.log" \
    "cd gateway && source ../scripts/ensure-erlang.sh 2>/dev/null; rebar3 ct --dir apps/yuzu_gw/test --suite=yuzu_gw_e2e_SUITE,yuzu_gw_integration_SUITE,yuzu_gw_metrics_e2e_SUITE,yuzu_gw_prometheus_SUITE"

gate_run "Integration" "integration.log" \
    "bash scripts/integration-test.sh"

gate_run "REST API E2E" "e2e-api.log" \
    "bash scripts/e2e-api-test.sh"

gate_run "MCP E2E" "e2e-mcp.log" \
    "bash scripts/e2e-mcp-test.sh"

gate_run "Security E2E" "e2e-security.log" \
    "bash scripts/e2e-security-test.sh"

# Synthetic UAT — Phase 4's linux-start-UAT.sh already ran its own 6
# tests; this gate runs them again standalone with timing capture into
# the test-runs DB. Skip if Phase 4 was the source.
gate_run "Synthetic UAT" "synthetic-uat.log" \
    "bash scripts/test/synthetic-uat-tests.sh \
        --dashboard http://localhost:8080 \
        --user admin --password 'YuzuUatAdmin1!' \
        --gateway-health http://localhost:8081 \
        --gateway-metrics http://localhost:9568 \
        --run-id $RUN_ID --gate-name phase5-synthetic-uat"

# Puppeteer is warn-only — flaky on first run
(
    start=$(date +%s)
    if node tests/puppeteer/dashboard-help-test.mjs > "$LOG_DIR/puppeteer.log" 2>&1; then
        STATUS=PASS
    else
        STATUS=WARN  # not FAIL — puppeteer is best-effort
    fi
    DUR=$(( $(date +%s) - start ))
    bash scripts/test/test-db-write.sh gate \
        --run-id "$RUN_ID" --phase 5 --gate "Puppeteer" \
        --status "$STATUS" --duration "$DUR" --log "puppeteer.log"
) &

wait
```

`--quick` runs only the unit / EUnit / dialyzer subset (NO synthetic UAT — quick mode skips Phase 4 and has no live stack). `--full` adds the optional MCP agent gate (invokes `mcp-uat-tester` via the Agent tool against the live stack).

## Phase 6 — Sanitizers (PR2, stubbed in PR1)

```bash
if [[ "$MODE" == "full" ]]; then
    bash scripts/test/test-db-write.sh gate \
        --run-id "$RUN_ID" --phase 6 --gate "Sanitizers (ASan+UBSan)" \
        --status SKIP --duration 0 --notes "planned for PR2 — dispatch to yuzu-wsl2-linux"
    bash scripts/test/test-db-write.sh gate \
        --run-id "$RUN_ID" --phase 6 --gate "Sanitizers (TSan)" \
        --status SKIP --duration 0 --notes "planned for PR2 — dispatch to yuzu-wsl2-linux"
fi
```

Once PR2 lands, replace with `bash scripts/test/sanitizer-gate.sh --run-id "$RUN_ID"`. The sanitizer gate dispatches a workflow on `yuzu-wsl2-linux` via `dispatch-runner-job.sh`, polls for completion, downloads logs, parses results, and writes `test_gates` rows.

## Phase 7 — Coverage + Perf (PR2, stubbed in PR1)

```bash
if [[ "$MODE" == "full" ]]; then
    bash scripts/test/test-db-write.sh gate \
        --run-id "$RUN_ID" --phase 7 --gate "Coverage" \
        --status SKIP --duration 0 --notes "planned for PR2 — locked baseline + 0.5pp slack"
    bash scripts/test/test-db-write.sh gate \
        --run-id "$RUN_ID" --phase 7 --gate "Perf" \
        --status SKIP --duration 0 --notes "planned for PR2 — locked baseline + 10% tolerance"
fi
```

Once PR2 lands, replace with `bash scripts/test/coverage-gate.sh --run-id "$RUN_ID"` and `bash scripts/test/perf-gate.sh --run-id "$RUN_ID"`.

## Phase 8 — Teardown + Summary

```bash
bash scripts/test/teardown.sh --run-id "$RUN_ID"
```

The teardown script:
1. Stops every `yuzu-test-${RUN_ID}-*` compose project
2. Removes `/tmp/yuzu-test-${RUN_ID}/`
3. Calls `test-db-write.sh run-finish --run-id "$RUN_ID"` which aggregates gate counts and computes overall status (any FAIL → FAIL, any WARN → WARN, else PASS)

After teardown, print the final summary by querying the just-finished run:

```bash
bash scripts/test/test-db-query.sh --latest
```

The skill should also produce a markdown table in its own response (so the operator sees it inline in the chat) summarizing the same data:

```
## /test run <RUN_ID>
Commit: <sha>  Branch: <branch>  Mode: <mode>  Duration: <wall>

| Phase | Gate                       | Status | Duration | Log                                              | Notes |
| ...   | ...                        | ...    | ...      | ...                                              | ...   |

Overall: N FAIL, M WARN — <commit decision>
```

## Querying the test-runs DB

The DB lives at `~/.local/share/yuzu/test-runs.db` and persists across runs. Common queries:

```bash
# Most recent run with full gate detail
bash scripts/test/test-db-query.sh --latest

# Last 10 runs (one row each)
bash scripts/test/test-db-query.sh --last 10

# Side-by-side diff of two runs
bash scripts/test/test-db-query.sh --diff RUN_A RUN_B

# How has the upgrade-test image-swap step trended?
bash scripts/test/test-db-query.sh --trend timing=phase2.image-swap

# How has branch coverage trended on the dev branch?
bash scripts/test/test-db-query.sh --trend metric=branch_coverage_overall --branch dev

# Which gates have flapped PASS↔FAIL in the last 14 days?
bash scripts/test/test-db-query.sh --flaky --days 14

# Dump a single run as JSON
bash scripts/test/test-db-query.sh --export RUN_ID

# Prune old runs (keep most recent 100)
bash scripts/test/test-db-query.sh --prune 100
```

Power users can `python3 scripts/test/test_db.py query ...` directly, or `python3 -c "import sqlite3; ..."` against the DB for ad-hoc analysis.

## Failure handling

The skill is designed so a single gate failure does NOT short-circuit the run. Goals:

1. **Always finalize the run row.** Even on a hard error or interrupt, `teardown.sh --run-id "$RUN_ID"` should be called so the DB has `finished_at` set and `overall_status` is something other than `RUNNING`. Wrap the body of the run in a `trap 'bash scripts/test/teardown.sh --run-id "$RUN_ID" --status ABORTED' ERR INT TERM` near the top.
2. **Phase 1 (build) is the only hard short-circuit.** Build failures mean nothing else can run.
3. **All other phases run to completion.** The operator gets a prioritized fix list in one pass instead of a fix-rerun loop.
4. **Print failure summaries inline.** When a gate fails, the skill should `tail -50 "$LOG_DIR/<gate>.log"` so the operator sees the actual error without having to find the log path themselves.

## Cost / ROI

| Mode | Phases | Wall clock | Use case |
|---|---|---|---|
| `--quick` | 0, 1 (no images), 5-subset, 8 | 8-15 min | "About to commit, want a fast sanity check" |
| default | 0, 1, 2, 4, 5, 8 | 25-45 min | "About to push to dev" |
| `--full` | 0-8 (PR2/PR3 features lit) | 60-120 min | "About to tag a release" |

Default mode is the recommended pre-push gate. The upgrade test in Phase 2 catches the highest-stakes class of bugs (silent data loss on schema migration) which no other local gate finds.

## Known risks

1. **Port collisions** from prior interrupted runs — preflight + `--force-cleanup` flag.
2. **Stale Docker volumes** — `test-upgrade-stack.sh` always `down -v`s its own project before `up`.
3. **Disk space** — preflight refuses < 20 GB free.
4. **WSL2 + native dockerd** — preflight verifies `docker context show` is `default`, not `desktop-linux`.
5. **Erlang rebar3 cache pollution** — gateway gates always source `scripts/ensure-erlang.sh` first; the `--dir apps/yuzu_gw/test` flag is mandatory per bug #337.
6. **Fixture write race with migrations** — `test-fixtures-write.sh` polls `/readyz` for `{"status":"ready"}` (not `/livez`) before writing — uses the #339 compound-fix readiness contract.
7. **Self-hosted runner availability** (PR2/PR3) — sanitizers and Windows OTA depend on `yuzu-wsl2-linux` and `yuzu-local-windows` runners being online; offline → WARN, not FAIL.
8. **DB grows unbounded** — auto-prune kicks in after 100 runs by default (`YUZU_TEST_DB_RETENTION_RUNS`).

## Post-run follow-ups

After a successful run, the operator typically wants to:

1. **Commit and push** — the green run is the gate. Reference `RUN_ID` in the commit message for traceability.
2. **Compare to the prior run** — `test-db-query.sh --diff <prev> <current>` shows what changed in gate status and timings.
3. **Investigate WARN gates** — these don't block but accumulate as tech debt. File issues if patterns emerge across runs.
4. **Bump baselines** (PR2+) — if a legitimate coverage drop or perf regression is intentional, run `coverage-gate.sh --capture-baselines` or `perf-gate.sh --capture-baselines` and commit the updated JSON files.

After a failed run:

1. **Read the failing log files** under `~/.local/share/yuzu/test-runs/${RUN_ID}/`.
2. **Re-run with `--force-cleanup`** if dangling state from the failed run is suspected.
3. **`--keep-stack`** lets you poke at the live UAT environment after the test exits.
