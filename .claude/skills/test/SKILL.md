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
Phase 2 — Upgrade Test          (latest release → HEAD: fixtures, migrate, verify)
Phase 3 — OTA Agent Test        (--full only — Linux + Windows self-exec)
Phase 7a — Perf gate            (--full only — runs HERE on a quiet box,
                                 BEFORE Phase 4 brings up the UAT stack;
                                 perf is fully self-contained and contention-
                                 sensitive, so it must measure with no other
                                 yuzu processes running)
Phase 4 — Fresh Stack Stand-up  (full-uat at HEAD + native agent — STAYS UP
                                 through Phase 8 so humans can poke at the
                                 stack before /release)
Phase 5 — Test Gates (parallel) (unit / EUnit / dialyzer / CT / integration /
                                 e2e-api / e2e-mcp / e2e-security /
                                 synthetic UAT / puppeteer)
Phase 6 — Sanitizers            (--full only — dispatched to yuzu-wsl2-linux runner)
Phase 7b — Coverage             (--full only — enforces tests/coverage-baseline.json)
Phase 8 — Teardown + Summary    (cleans Phase 2 compose projects + scratch dir,
                                 finalises run row; LEAVES THE UAT ALIVE on
                                 purpose — do NOT call linux-start-UAT.sh stop)
```

**Wall-clock order: 0, 1, 2, 3, 7a-perf, 4, 5, 6, 7b-coverage, 8.** Perf is intentionally pulled forward of Phase 4 because it has no functional dependency on the UAT stack (every upstream RPC is meck'd inside the suite, gateway components run in-process) but its measurements are extremely sensitive to CPU/scheduler contention. Running perf on a quiet box — after Phase 1 binaries exist but before Phase 2's docker compose, Phase 4's native server+gateway+agent, and Phase 5's parallel fan-out — gives the most-isolated environment available in the pipeline. DB phase numbers stay stable (`phase=7` for both perf and coverage) so the report table groups them together at the end; the wall-clock split is purely an isolation guarantee.

**Phase 8 leaves the UAT alive.** `scripts/test/teardown.sh` only stops Docker compose projects matching `yuzu-test-${RUN_ID}-*` (Phase 2 fixtures); it does not touch the native processes started by `linux-start-UAT.sh`. This is deliberate: a successful `/test --full` run leaves a working UAT at the tested HEAD so humans can sanity-check it before cutting `/release`. Do **not** add `bash scripts/linux-start-UAT.sh stop` to your orchestration — if the operator wants the stack down they can run it themselves.

Phase 1 is the only mandatory-blocking phase — if HEAD doesn't compile, nothing else can run. Every other phase runs to completion regardless of upstream failures so the operator gets a prioritized fix list in one pass.

**Every phase emits structured timing data into the test-runs DB.** Top-level gate timings land in `test_gates.duration_seconds`; sub-step timings (upgrade phases, OTA flow steps, individual command round-trips) land in `test_timings`. This is how trend analysis catches "Phase 2 upgrade got 3× slower since last week" without grepping log files.

> **PR2 status.** Phases 0, 1, 2, 4, 5, 6, 7, 8 are wired. Phase 3 (cross-platform OTA self-exec) is still stubbed pending PR3; its gate rows record as `SKIP` with a "planned for PR3" note. Phase 6 (sanitizers) dispatches `.github/workflows/sanitizer-tests.yml` onto the `yuzu-wsl2-linux` self-hosted runner; if the runner is offline the gate records WARN and the rest of the run continues. Phase 7 (coverage + perf) runs locally against `tests/coverage-baseline.json` and `tests/perf-baselines.json` — PR2 ships these as **permissive seeds**, and the first operator run on a new dev box should use `--capture-baselines` to lock real numbers then commit the updated JSON alongside their next change.

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
    --new-version "0.10.1-test-${RUN_ID}" \
    --new-image-loaded 1 \
    --test-dir "$TEST_DIR"
```

`--old-version` is omitted so the script resolves it from GitHub's current
"Latest release" at runtime (`gh api repos/Tr3kkR/Yuzu/releases/latest`).
This keeps the upgrade baseline tracking whatever the last published stable
tag is without needing a pipeline edit each release. Pass `--old-version
X.Y.Z` to pin an older baseline for debugging.

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

## Phase 7a — Perf gate (runs HERE, before Phase 4)

`--full` only. Despite the `7a` label (rows are tagged `phase=7` in the DB so they group with coverage in the report), the perf gate runs **here** in wall-clock order — after Phase 3 has finished but before Phase 4 brings up the UAT stack. This is the most-quiesced point in the pipeline:

- Phase 1 build is done (binaries exist; ccache hits stop competing).
- Phase 2 docker compose has been torn down.
- Phase 3 is just DB writes.
- Phase 4 hasn't started, so no native server/gateway/agent.
- Phase 5 hasn't started, so no parallel fan-out CPU pressure.

The perf suite is fully self-contained (every upstream RPC meck'd, gateway components in-process), so it has no functional dependency on the live stack. Running it here avoids the contention failure mode observed in run `1777704747-244808` where measurements taken while the Phase 4 UAT stack was still up landed below the 10% tolerance.

```bash
if [[ "$MODE" == "full" ]]; then
    bash scripts/test/perf-gate.sh --run-id "$RUN_ID"
fi
```

`perf-gate.sh` enforces this contract from its own side too: at startup it scans the seven UAT-related ports (8080, 50051, 50052, 50055, 50063, 8081, 9568) and refuses to run if any are listening, with a clear FAIL row noting which ports were busy. The `--allow-busy` flag bypasses the check for debug invocations but is rejected when combined with `--capture-baselines` so contended numbers can never anchor a committed baseline. The gate also records `perf_loadavg_pre` / `perf_loadavg_post` metrics so trend queries can distinguish a real regression from a measurement taken under load.

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

### Pre-warm rebar3 dep caches (mandatory, sequential)

EUnit, Dialyzer, CT suites, and CT real-upstream all invoke `rebar3` against the same project. Run in parallel, they race on dep fetching: each calls `Verifying dependencies...` and decides to re-fetch `proper`/`meck`/`covertool` into `_build/{default,test}/lib/`, and concurrent extraction corrupts the partially-fetched packages so the loser sees `Dependency failure: source for proper does not contain a recognizable project`. Once a fetch is in-flight a sibling rebar3 also can't `rm -rf` the partial dir (`Directory not empty`) because the writer still has open file handles. This was observed in run `1777704747-244808` and is a property of rebar3, not of the gates.

The cure is to fetch deps **serially** before the fan-out. Both the `test` and `default` profiles need warming because EUnit/CT use `_build/test/` while Dialyzer uses `_build/default/`. After this step the parallel rebar3 commands skip the fetch path and just compile + run their stage:

```bash
(
    cd gateway
    source ../scripts/ensure-erlang.sh 2>/dev/null
    rebar3 as test compile > "$LOG_DIR/prewarm-test.log" 2>&1 || true
    rebar3 compile         > "$LOG_DIR/prewarm-default.log" 2>&1 || true
)
```

Pre-warm failures use `|| true` because if either profile genuinely can't compile, the corresponding gate (EUnit / Dialyzer / CT) will fail with the same error and that gate's log is the right reporting surface — the pre-warm step is for cache correctness, not for gating.

The pattern for every gate (note: `eval "$cmd"` is safe here because every
caller below passes a literal string constructed inline in this same skill;
the `cmd` argument is never read from operator input or external state):
```bash
gate_run() {
    local gate_name="$1" log_basename="$2" cmd="$3" phase="${4:-5}"
    # Capture project root BEFORE entering the subshell. Several gates
    # eval a `cd gateway && rebar3 ...` compound — that cd survives into
    # the post-eval test-db-write.sh invocation, so a relative path would
    # resolve against gateway/ and fail. The absolute path keeps the
    # writer reachable regardless of where the gate's cmd left $PWD.
    local project_root="$PWD"
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
        bash "$project_root/scripts/test/test-db-write.sh" gate \
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

# Real-upstream CT suite — lives under apps/yuzu_gw/integration_test/
# (separate dir from the regular test/ tree so CI's `rebar3 ct --dir
# apps/yuzu_gw/test` discovery does NOT pick it up). Requires:
#   1. A live yuzu-server reachable on 127.0.0.1:50055 (Phase 4 brings
#      this up via linux-start-UAT.sh).
#   2. YUZU_GW_TEST_TOKEN env var set to a valid enrollment token, OR
#      linux-start-UAT.sh must have just run (its scratch dir is
#      probed for the token).
# Failing either prerequisite, the suite reports {test_case_failed,
# "No enrollment token: …"} per-case rather than a useful skip — file
# an upstream issue if you hit that during /test.
gate_run "CT real-upstream" "ct-real-upstream.log" \
    "cd gateway && source ../scripts/ensure-erlang.sh 2>/dev/null; rebar3 ct --dir apps/yuzu_gw/integration_test --suite=yuzu_gw_real_upstream_SUITE"

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

## Phase 6 — Sanitizers (PR2)

Sanitizer rebuilds are dispatched to the `yuzu-wsl2-linux` self-hosted runner via `workflow_dispatch`. Running them locally would pin the dev box for ~15 min of compile time each; the always-on runner absorbs that cost while the operator continues Phase 5 gates locally.

```bash
if [[ "$MODE" == "full" ]]; then
    bash scripts/test/sanitizer-gate.sh --run-id "$RUN_ID"
fi
```

The gate script:
1. Resolves the current commit (`git rev-parse HEAD`) and dispatches `.github/workflows/sanitizer-tests.yml` via `scripts/test/dispatch-runner-job.sh`
2. Polls the run to completion (default 90 min budget — covers queued + compile + test)
3. Downloads `sanitizer-asan*` and `sanitizer-tsan*` artifacts into `/tmp/yuzu-test-${RUN_ID}/sanitizer/`
4. Parses each sanitizer log for `ERROR: AddressSanitizer`, `ERROR: LeakSanitizer`, `WARNING: ThreadSanitizer`, `ThreadSanitizer: data race`, `runtime error:`
5. Writes two Phase 6 rows to `test_gates`: `Sanitizers (ASan+UBSan)` and `Sanitizers (TSan)`

**Runner-offline path (WARN, not FAIL).** If `yuzu-wsl2-linux` is offline or the dispatch times out, both gates record `WARN` with notes explaining the operator retry path. The skill continues with the rest of the run rather than blocking on CI infrastructure that's out of reach.

**Workflow-file requirement.** `workflow_dispatch` evaluates the workflow file on the target ref. If you're dispatching against a commit that doesn't have `sanitizer-tests.yml` yet (e.g. running /test from an older branch), the dispatch will fail hard. The gate treats that as WARN per the offline-runner path.

**Suite selection.** Default runs both (ASan+UBSan and TSan). Override with `--suite asan` or `--suite tsan` on the gate script — useful when diagnosing a single finding and you don't want the second rebuild to compete for runner time.

## Phase 7b — Coverage (PR2)

Coverage runs locally on the operator's dev box, at the end of the pipeline (after Phase 5 gates and Phase 6 sanitizer dispatch). It uses `build-linux-coverage/` (separate from the main `build-linux/` to keep ccache hit rates intact). Coverage is contention-tolerant — it's measuring code-execution coverage, not throughput, so the live UAT stack from Phase 4 doesn't affect the numbers. The earlier perf gate (Phase 7a) already ran on a quiet box.

```bash
if [[ "$MODE" == "full" ]]; then
    bash scripts/test/coverage-gate.sh --run-id "$RUN_ID"
elif [[ "$MODE" == "default" ]]; then
    # Default mode: coverage in report-only (metric recorded, no enforce);
    # perf skipped (default-mode budget is too tight for the ~3-5 min
    # CT suite plus registry churn).
    bash scripts/test/coverage-gate.sh --run-id "$RUN_ID" --report-only || true
    bash scripts/test/test-db-write.sh gate \
        --run-id "$RUN_ID" --phase 7 --gate "Perf" \
        --status SKIP --duration 0 --notes "perf gate runs in --full only"
fi
```

**Coverage enforcement.** The gate parses gcovr `--json-summary` (filter set mirrored from `.github/workflows/ci.yml` so local/CI numbers match Codecov; gate also passes `--native-file meson/native/linux-gcc13.ini` so the compiler matches CI's coverage job), records `branch_coverage_overall` and `line_coverage_overall` metrics, and compares against `tests/coverage-baseline.json`. In `--full` mode the gate fails if branch coverage drops below `baseline.branch_percent - slack_pp` (default 0.5 pp). Default mode records the metric but doesn't enforce — `--report-only` short-circuits the comparison. The default-mode invocation wraps the script in `|| true` so a transient gcovr or build failure writes its own WARN row and does not block the rest of the run; in `--full` mode the gate is called without `|| true`, so build or parse failures surface as FAIL.

**Perf enforcement.** The gate runs the `registration,heartbeat,fanout,churn` CT groups (endurance deliberately excluded — it runs for 5 minutes and belongs in a scheduled nightly), parses throughput and latency metrics from `ct:pal` output, records them as `perf_*` metrics (ops/sec for throughput, ms or ms/agent for latency), and compares against `tests/perf-baselines.json` with a 10% tolerance. Throughput metrics (`*_ops_sec`) regress when current < baseline × 0.9; latency metrics (`*_ms`, `*_ms_per_agent`) regress when current > baseline × 1.1.

**Hardware fingerprint guard.** The perf baseline records the hardware fingerprint (CPU model + RAM) of the machine that captured it. When the current fingerprint doesn't match, the gate auto-downgrades to WARN regardless of regressions — a 30% delta between the 5950X dev box and the Apple Silicon MBP is not a real regression. Both baselines need a separate capture per machine.

**Baseline update workflow.**
1. Make a change you believe deserves a new baseline (coverage up, perf up, or an accepted trade-off).
2. **Pre-flight**: run `bash scripts/test/preflight.sh` and a clean `meson test -C build-linux-coverage` (for coverage) or a clean `rebar3 ct --suite yuzu_gw_perf_SUITE` (for perf). If tests are failing, the gate will now refuse `--capture-baselines` with `FAIL: refused --capture-baselines: meson test exit=N` — this is the UP-18 guard protecting you from anchoring a broken-environment baseline.
3. Run `bash scripts/test/coverage-gate.sh --run-id manual --capture-baselines` and/or `bash scripts/test/perf-gate.sh --run-id manual --capture-baselines`. Both rewrite the JSON file with current numbers + `captured_at` + `captured_commit` + (perf only) hardware fingerprint, AND print a diff of old-vs-new values before overwrite so you can sanity-check the direction.
4. `git add tests/coverage-baseline.json tests/perf-baselines.json` alongside your feature commit. `git blame` on those files is the audit trail.
5. Do NOT capture a baseline in the middle of an unrelated change — the commit SHA recorded in the baseline becomes the receipt for "this is the code that earned these numbers."

**Baseline refresh cadence.** Recapture both baselines at every `vX.Y.0` release tag on the canonical dev box (5950X for perf, any Linux with GCC 13 for coverage). Commit the updated JSON in the release-prep commit. Coverage drift between release trains is informative trend data; perf drift across hardware generations is silenced by the hardware-fingerprint auto-downgrade, so recapture-at-release keeps each train's perf baseline honest for its target hardware.

**Seed sentinel (historical + defensive).** The `__seed: true` sentinel was the PR2 mechanism that kept the gates from silently green-passing while baselines were placeholders. Both gate scripts honor it: `__seed: true` forces WARN regardless of measured numbers, even alongside otherwise-real values. The seed phase has concluded — current `tests/coverage-baseline.json` and `tests/perf-baselines.json` hold real captured numbers (branch 26.8% / line 51.8% on the 5950X; perf metrics with hardware fingerprint locked) and the sentinel is absent, so enforcement is live. Do **not** re-add `__seed: true` to a real baseline file as a "temporary disable" knob — the gates will WARN as designed, but this defeats the regression detector. To adjust thresholds, edit `slack_pp` or `tolerance_pct` directly (and document why in the commit message). To regenerate after a legitimate coverage / perf shift, follow the Baseline update workflow above.

**Concurrent --full runs on the same ref.** The sanitizer workflow's `concurrency: cancel-in-progress: false` group means a second dispatch queues behind the first until it completes (Phase 6 only — coverage/perf run locally and have their own coverage-gate race behavior). If you re-run `/test --full` immediately after a successful run on the same commit, expect Phase 6 to sit queued. Use `--suite asan` or `--suite tsan` on the gate script to halve runtime when re-running a specific finding.

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
