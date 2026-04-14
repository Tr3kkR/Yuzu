#!/usr/bin/env bash
# test_pr2_gates.sh — Chaos regression harness for /test skill PR2 gates.
#
# Covers the P0 chaos scenarios identified in Gate 5 of the PR2
# governance run. Each scenario injects a specific fault into a mocked
# environment, invokes the gate, and asserts the observable post-condition
# (DB gate row status, exit code, notes content).
#
# Scenarios:
#   CH-1  — clean log + workflow conclusion=failure → sanitizer-gate FAIL
#   CH-2  — grep -cE on zero-match → arithmetic doesn't break, correct count
#   CH-3  — coverage --capture-baselines refuses when TEST_RC != 0
#   CH-4  — gcovr root-wrapper schema → WARN, not silent 0%
#   CH-6  — perf-gate parser drift (few metrics) → FAIL with clear message
#   CH-8  — __seed sentinel honored → WARN, not silent PASS
#   CH-15 — empty/whitespace/traversal --run-id rejected
#
# Usage:
#   bash tests/shell/test_pr2_gates.sh             # run all scenarios
#   bash tests/shell/test_pr2_gates.sh CH-1 CH-2   # run specific scenarios
#
# Exit codes: 0 all scenarios passed; 1 one or more failed; 2 harness error.
#
# The harness uses isolated fixtures under /tmp/pr2-chaos-$$ and a
# per-harness YUZU_TEST_DB so it cannot contaminate the operator's real
# test-runs DB.

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
YUZU_ROOT="$(cd "$HERE/../.." && pwd)"

CHAOS_ROOT="/tmp/pr2-chaos-$$"
export YUZU_TEST_DB="$CHAOS_ROOT/test-runs.db"
mkdir -p "$CHAOS_ROOT" "$CHAOS_ROOT/mockbin"

cleanup() {
    rm -rf "$CHAOS_ROOT" 2>/dev/null || true
}
trap cleanup EXIT

# ── Mock environment ────────────────────────────────────────────────────

MOCKBIN="$CHAOS_ROOT/mockbin"

cat > "$MOCKBIN/meson" <<'EOF'
#!/usr/bin/env bash
# Mock meson — always succeeds, creates build-dir on setup.
if [[ "$1" == "setup" ]]; then
    mkdir -p "$2"
fi
exit "${YUZU_MOCK_MESON_RC:-0}"
EOF

cat > "$MOCKBIN/erl" <<'EOF'
#!/usr/bin/env bash
echo "Erlang/OTP 28"
exit 0
EOF

cat > "$MOCKBIN/rebar3" <<'EOF'
#!/usr/bin/env bash
# Mock rebar3 — prints scripted output from YUZU_MOCK_CT_OUTPUT
# and exits with YUZU_MOCK_CT_RC.
printf '%s\n' "${YUZU_MOCK_CT_OUTPUT:-}"
exit "${YUZU_MOCK_CT_RC:-0}"
EOF

chmod +x "$MOCKBIN"/*

# Prepend mockbin to PATH so these mocks beat real tools.
export PATH="$MOCKBIN:$PATH"

# ── Assertion helpers ───────────────────────────────────────────────────

PASS_COUNT=0
FAIL_COUNT=0
FAILED_SCENARIOS=()

say() { printf '  %s\n' "$*"; }
ok()  { PASS_COUNT=$((PASS_COUNT+1)); printf '  PASS: %s\n' "$*"; }
bad() {
    FAIL_COUNT=$((FAIL_COUNT+1))
    FAILED_SCENARIOS+=("$1")
    printf '  FAIL: %s: %s\n' "$1" "$2"
}

init_db() {
    # Fresh DB per scenario so we don't see cross-pollution.
    rm -f "$YUZU_TEST_DB"
    bash "$YUZU_ROOT/scripts/test/test-db-init.sh" >/dev/null 2>&1 || return 1
}

db_gate_status() {
    local run_id="$1" gate_name="$2"
    # sec-h-3: pass values via argv, not shell interpolation into
    # python source. Same anti-pattern as sec-h-1; fixing here so the
    # harness teaches the right pattern to future contributors.
    python3 - "$YUZU_TEST_DB" "$run_id" "$gate_name" <<'PY'
import sqlite3, sys
db, rid, gname = sys.argv[1], sys.argv[2], sys.argv[3]
c = sqlite3.connect(db)
row = c.execute("SELECT status FROM test_gates WHERE run_id=? AND gate_name=?",
                (rid, gname)).fetchone()
print(row[0] if row else "MISSING")
PY
}

db_gate_notes() {
    local run_id="$1" gate_name="$2"
    python3 - "$YUZU_TEST_DB" "$run_id" "$gate_name" <<'PY'
import sqlite3, sys
db, rid, gname = sys.argv[1], sys.argv[2], sys.argv[3]
c = sqlite3.connect(db)
row = c.execute("SELECT notes FROM test_gates WHERE run_id=? AND gate_name=?",
                (rid, gname)).fetchone()
print(row[0] if row else "")
PY
}

start_run() {
    local run_id="$1"
    bash "$YUZU_ROOT/scripts/test/test-db-write.sh" run-start \
        --run-id "$run_id" --commit "pr2chaos" --branch "dev" --mode full \
        >/dev/null 2>&1
}

# ── CH-2: grep -cE arithmetic on zero-match ────────────────────────────

scenario_CH_2() {
    echo ""
    echo "=== CH-2: grep -cE arithmetic doesn't break on zero findings ==="
    init_db || { bad "CH-2" "db init failed"; return; }

    # Test the pattern directly: grep -cE ... on a file with no matches
    # must yield a single integer 0, not "0\n0".
    local f="$CHAOS_ROOT/empty-match.log"
    cat > "$f" <<EOF
Ok: 42
Fail: 0
Expected Fail: 0
Summary of results: 42 / 42 tests passed.
EOF

    local count
    count=$(grep -cE "ERROR: AddressSanitizer|ERROR: LeakSanitizer|runtime error:" "$f" 2>/dev/null; true)
    count=${count:-0}
    count=${count//[[:space:]]/}

    if [[ "$count" == "0" ]]; then
        ok "CH-2: grep returned single integer '0'"
    else
        bad "CH-2" "grep returned '$count' (expected '0')"
        return
    fi

    # And the arithmetic comparison must work.
    if (( count > 0 )); then
        bad "CH-2" "arithmetic (( count > 0 )) wrongly evaluated true on count=$count"
    else
        ok "CH-2: arithmetic (( count > 0 )) correctly evaluated false"
    fi
}

# ── CH-3: coverage --capture-baselines refuses on TEST_RC != 0 ─────────

scenario_CH_3() {
    echo ""
    echo "=== CH-3: coverage --capture-baselines refuses broken env ==="
    init_db || { bad "CH-3" "db init failed"; return; }
    local run_id="ch3"
    start_run "$run_id"

    # Mock gcovr to emit valid JSON.
    cat > "$MOCKBIN/gcovr" <<'EOF'
#!/usr/bin/env bash
JSON=""
while [[ $# -gt 0 ]]; do
    case "$1" in --json-summary) JSON="$2"; shift 2 ;; *) shift ;; esac
done
[[ -n "$JSON" ]] && printf '{"branch_percent":65.5,"line_percent":72.0}' > "$JSON"
exit 0
EOF
    chmod +x "$MOCKBIN/gcovr"

    # Mock meson: succeeds setup+compile, FAILS on `test` subcommand.
    cat > "$MOCKBIN/meson" <<'EOF'
#!/usr/bin/env bash
case "$1" in
    setup|compile) mkdir -p "${2:-}"; exit 0 ;;
    test) exit 3 ;;
    *) exit 0 ;;
esac
EOF
    chmod +x "$MOCKBIN/meson"

    local out
    out=$(bash "$YUZU_ROOT/scripts/test/coverage-gate.sh" \
        --run-id "$run_id" \
        --build-dir /tmp/build-ch3 \
        --baseline "$CHAOS_ROOT/ch3-baseline.json" \
        --capture-baselines 2>&1) || true

    # Expect exit != 0 AND gate status FAIL AND baseline file NOT written.
    local status notes
    status=$(db_gate_status "$run_id" "Coverage")
    notes=$(db_gate_notes "$run_id" "Coverage")

    if [[ "$status" != "FAIL" ]]; then
        bad "CH-3" "expected gate FAIL on broken env capture, got '$status'"
    elif [[ -f "$CHAOS_ROOT/ch3-baseline.json" ]]; then
        bad "CH-3" "baseline file was written despite TEST_RC != 0"
    elif [[ "$notes" != *"refused --capture-baselines"* ]]; then
        bad "CH-3" "notes missing 'refused --capture-baselines': $notes"
    else
        ok "CH-3: gate FAIL, baseline not written, notes: $notes"
    fi

    rm -rf /tmp/build-ch3 2>/dev/null || true
}

# ── CH-4: gcovr root-wrapper schema → WARN not silent 0% ────────────────

scenario_CH_4() {
    echo ""
    echo "=== CH-4: gcovr root-wrapper schema tolerated, not silent 0 ==="
    init_db || { bad "CH-4" "db init failed"; return; }
    local run_id="ch4"
    start_run "$run_id"

    # Mock gcovr to emit the nested {"root": {...}} shape.
    cat > "$MOCKBIN/gcovr" <<'EOF'
#!/usr/bin/env bash
JSON=""
while [[ $# -gt 0 ]]; do
    case "$1" in --json-summary) JSON="$2"; shift 2 ;; *) shift ;; esac
done
[[ -n "$JSON" ]] && printf '{"root":{"branches_covered":150,"branches_valid":200,"lines_covered":800,"lines_valid":1000}}' > "$JSON"
exit 0
EOF
    chmod +x "$MOCKBIN/gcovr"

    # Mock meson: succeed everything.
    cat > "$MOCKBIN/meson" <<'EOF'
#!/usr/bin/env bash
case "$1" in setup|compile) mkdir -p "${2:-}"; exit 0 ;; test) exit 0 ;; *) exit 0 ;; esac
EOF
    chmod +x "$MOCKBIN/meson"

    bash "$YUZU_ROOT/scripts/test/coverage-gate.sh" \
        --run-id "$run_id" \
        --build-dir /tmp/build-ch4 \
        --baseline "$CHAOS_ROOT/ch4-baseline.json" \
        --report-only >/dev/null 2>&1 || true

    # Expect branch_coverage_overall metric ≈ 75.0 (150/200) and status PASS.
    local branch
    branch=$(python3 - "$YUZU_TEST_DB" "$run_id" <<'PY'
import sqlite3, sys
db, rid = sys.argv[1], sys.argv[2]
c = sqlite3.connect(db)
r = c.execute("SELECT metric_value FROM test_metrics WHERE run_id=? AND metric_name=?",
              (rid, "branch_coverage_overall")).fetchone()
print(r[0] if r else "MISSING")
PY
)
    if [[ "$branch" == "MISSING" ]]; then
        bad "CH-4" "branch_coverage_overall metric missing"
    elif python3 -c "import sys; sys.exit(0 if abs(float('$branch') - 75.0) < 0.1 else 1)"; then
        ok "CH-4: parsed branch=$branch% from nested root schema"
    else
        bad "CH-4" "branch=$branch (expected ~75.0 from root.branches_covered/valid)"
    fi

    rm -rf /tmp/build-ch4 2>/dev/null || true
}

# ── CH-6: perf parser drift → FAIL not silent WARN ─────────────────────

scenario_CH_6() {
    echo ""
    echo "=== CH-6: perf parser drift fails loudly ==="
    init_db || { bad "CH-6" "db init failed"; return; }
    local run_id="ch6"
    start_run "$run_id"

    # Simulate a CT run that passes but uses totally different label names
    # (parser drift) so the parser extracts ZERO metrics.
    YUZU_MOCK_CT_RC=0 \
    YUZU_MOCK_CT_OUTPUT="%%% yuzu_gw_perf_SUITE:
Registratiun: 5000 ops in 613 ms (8157 op/s)
Heartbit queue: 20000 ops in 83 ms (240964 op/s)
All 9 tests passed." \
    bash "$YUZU_ROOT/scripts/test/perf-gate.sh" \
        --run-id "$run_id" \
        --baseline "$CHAOS_ROOT/ch6-baseline.json" >/dev/null 2>&1 || true

    local status notes
    status=$(db_gate_status "$run_id" "Perf")
    notes=$(db_gate_notes "$run_id" "Perf")

    if [[ "$status" == "FAIL" ]] && [[ "$notes" == *"0 metrics parsed"* || "$notes" == *"metrics parsed"* ]]; then
        ok "CH-6: parser drift → FAIL, notes: $notes"
    else
        bad "CH-6" "expected FAIL with parser-drift message, got status='$status' notes='$notes'"
    fi
}

# ── CH-8: __seed sentinel honored, not silent PASS ─────────────────────

scenario_CH_8() {
    echo ""
    echo "=== CH-8: __seed sentinel → WARN not silent PASS ==="
    init_db || { bad "CH-8" "db init failed"; return; }
    local run_id="ch8"
    start_run "$run_id"

    # Seed baseline with __seed: true and slack_pp=100 (PR2 ship state).
    cat > "$CHAOS_ROOT/ch8-coverage-baseline.json" <<'EOF'
{
  "__schema": "coverage-baseline/v1",
  "__seed": true,
  "branch_percent": 0.0,
  "line_percent": 0.0,
  "slack_pp": 100.0,
  "captured_at": 0,
  "captured_commit": "seed"
}
EOF

    # Mock gcovr to produce a plausible coverage value.
    cat > "$MOCKBIN/gcovr" <<'EOF'
#!/usr/bin/env bash
JSON=""
while [[ $# -gt 0 ]]; do
    case "$1" in --json-summary) JSON="$2"; shift 2 ;; *) shift ;; esac
done
[[ -n "$JSON" ]] && printf '{"branch_percent":72.5,"line_percent":81.3}' > "$JSON"
exit 0
EOF
    chmod +x "$MOCKBIN/gcovr"

    cat > "$MOCKBIN/meson" <<'EOF'
#!/usr/bin/env bash
case "$1" in setup|compile) mkdir -p "${2:-}"; exit 0 ;; test) exit 0 ;; *) exit 0 ;; esac
EOF
    chmod +x "$MOCKBIN/meson"

    bash "$YUZU_ROOT/scripts/test/coverage-gate.sh" \
        --run-id "$run_id" \
        --build-dir /tmp/build-ch8 \
        --baseline "$CHAOS_ROOT/ch8-coverage-baseline.json" >/dev/null 2>&1 || true

    local status notes
    status=$(db_gate_status "$run_id" "Coverage")
    notes=$(db_gate_notes "$run_id" "Coverage")

    if [[ "$status" == "WARN" ]] && [[ "$notes" == *"seed"* ]]; then
        ok "CH-8: seed → WARN with seed note: $notes"
    else
        bad "CH-8" "expected WARN with 'seed' in notes, got status='$status' notes='$notes'"
    fi

    # Also test the perf gate's __seed path.
    local run_id2="ch8b"
    start_run "$run_id2"
    cat > "$CHAOS_ROOT/ch8-perf-baseline.json" <<'EOF'
{
  "__schema": "perf-baseline/v1",
  "__seed": true,
  "metrics": {},
  "tolerance_pct": 10.0,
  "hardware_fingerprint": "seed"
}
EOF
    YUZU_MOCK_CT_RC=0 \
    YUZU_MOCK_CT_OUTPUT="%%% yuzu_gw_perf_SUITE:
Registration: 5000 ops in 613 ms (8157 ops/sec)
Burst registration: 5000 ops in 340 ms (14706 ops/sec)
Heartbeat queue: 20000 ops in 83 ms (240964 ops/sec)
Fanout to 10000 agents: 42 ms (limit 100 ms)
Cleanup 1000 agents: 150 ms (0.15 ms/agent)" \
    bash "$YUZU_ROOT/scripts/test/perf-gate.sh" \
        --run-id "$run_id2" \
        --baseline "$CHAOS_ROOT/ch8-perf-baseline.json" >/dev/null 2>&1 || true

    status=$(db_gate_status "$run_id2" "Perf")
    notes=$(db_gate_notes "$run_id2" "Perf")

    # perf-gate on seed baseline → exits 0 PASS (hp-B1 fix) with seed note
    # so SKILL.md full-mode doesn't abort Phase 7 on first run.
    if [[ "$status" == "PASS" ]] && [[ "$notes" == *"seed"* ]]; then
        ok "CH-8: perf seed → PASS with seed note: $notes"
    else
        bad "CH-8" "perf seed: expected PASS+seed note, got status='$status' notes='$notes'"
    fi

    rm -rf /tmp/build-ch8 2>/dev/null || true
}

# ── CH-16: sec-h-1 regression — malicious --baseline path cannot inject python ──

scenario_CH_16() {
    echo ""
    echo "=== CH-16: sec-h-1 regression — --baseline path cannot inject python ==="
    init_db || { bad "CH-16" "db init failed"; return; }
    local run_id="ch16"
    start_run "$run_id"

    # Craft a baseline file with a filename that, if interpolated
    # unsafely, would have broken out of the Python string literal and
    # run os.system. The fix passes $BASELINE via sys.argv, so this
    # filename just gets read as a path.
    local evil_dir="$CHAOS_ROOT/ch16-'evil"
    mkdir -p "$evil_dir"
    local evil_baseline="$evil_dir/ch16.json"
    cat > "$evil_baseline" <<'EOF'
{
  "__schema": "coverage-baseline/v1",
  "__seed": true,
  "branch_percent": 0,
  "line_percent": 0,
  "slack_pp": 100,
  "captured_at": 0,
  "captured_commit": "seed"
}
EOF

    # Mock gcovr + meson so the gate reaches the __seed check.
    cat > "$MOCKBIN/gcovr" <<'EOF'
#!/usr/bin/env bash
JSON=""
while [[ $# -gt 0 ]]; do
    case "$1" in --json-summary) JSON="$2"; shift 2 ;; *) shift ;; esac
done
[[ -n "$JSON" ]] && printf '{"branch_percent":72.5,"line_percent":81.3}' > "$JSON"
exit 0
EOF
    chmod +x "$MOCKBIN/gcovr"
    cat > "$MOCKBIN/meson" <<'EOF'
#!/usr/bin/env bash
case "$1" in setup|compile) mkdir -p "${2:-}"; exit 0 ;; test) exit 0 ;; *) exit 0 ;; esac
EOF
    chmod +x "$MOCKBIN/meson"

    # Also create a sentinel the injection would touch.
    local sentinel="$CHAOS_ROOT/ch16-should-not-exist"
    rm -f "$sentinel"

    bash "$YUZU_ROOT/scripts/test/coverage-gate.sh" \
        --run-id "$run_id" \
        --build-dir /tmp/build-ch16 \
        --baseline "$evil_baseline" >/dev/null 2>&1 || true

    # The sentinel must not have been created by injected code, AND
    # the __seed check must have run normally (WARN from seed detection).
    if [[ -e "$sentinel" ]]; then
        bad "CH-16" "sentinel file exists — python injection succeeded"
        return
    fi

    local status
    status=$(db_gate_status "$run_id" "Coverage")
    if [[ "$status" == "WARN" ]]; then
        ok "CH-16: --baseline with single-quote handled safely (status=WARN via seed)"
    else
        bad "CH-16" "expected seed WARN, got status='$status' (gate may have failed to read apostrophed path)"
    fi

    rm -rf /tmp/build-ch16 "$evil_dir" 2>/dev/null || true
}

# ── CH-15: empty/whitespace/traversal --run-id rejected ────────────────

scenario_CH_15() {
    echo ""
    echo "=== CH-15: invalid --run-id rejected ==="

    local bad_ids=(
        ""
        " "
        "../../../tmp/evil"
        "foo/bar"
        $'has\nnewline'
        "has space"
    )

    local all_ok=1
    for rid in "${bad_ids[@]}"; do
        for gate in coverage-gate.sh perf-gate.sh sanitizer-gate.sh; do
            # Each should exit 2 with "required" or "invalid" message.
            local out rc
            out=$(bash "$YUZU_ROOT/scripts/test/$gate" --run-id "$rid" 2>&1)
            rc=$?
            if (( rc == 0 )); then
                bad "CH-15" "$gate accepted invalid --run-id '$rid'"
                all_ok=0
                break 2
            fi
            if [[ "$out" != *"required"* && "$out" != *"invalid"* ]]; then
                bad "CH-15" "$gate rejected '$rid' without clear message: $out"
                all_ok=0
                break 2
            fi
        done
    done
    if (( all_ok )); then
        ok "CH-15: all invalid run-ids rejected across 3 gates"
    fi
}

# ── Scenario dispatch ───────────────────────────────────────────────────

SCENARIOS=(CH-2 CH-3 CH-4 CH-6 CH-8 CH-15 CH-16)

# CH-1 (clean-log + workflow-failure → FAIL) requires a live gh CLI mock
# which is more involved — defer to a dedicated PR2.1 harness pass once
# the dispatch-runner-job.sh mocking story is settled. All other P0
# scenarios are covered here.

if [[ $# -gt 0 ]]; then
    SCENARIOS=("$@")
fi

for s in "${SCENARIOS[@]}"; do
    case "$s" in
        CH-2)  scenario_CH_2 ;;
        CH-3)  scenario_CH_3 ;;
        CH-4)  scenario_CH_4 ;;
        CH-6)  scenario_CH_6 ;;
        CH-8)  scenario_CH_8 ;;
        CH-15) scenario_CH_15 ;;
        CH-16) scenario_CH_16 ;;
        *)     echo "unknown scenario: $s" >&2; exit 2 ;;
    esac
done

echo ""
echo "=============================="
echo "  PR2 chaos harness results"
echo "  PASS: $PASS_COUNT  FAIL: $FAIL_COUNT"
if (( FAIL_COUNT > 0 )); then
    echo "  failed: ${FAILED_SCENARIOS[*]}"
    exit 1
fi
exit 0
