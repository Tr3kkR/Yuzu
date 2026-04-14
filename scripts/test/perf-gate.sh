#!/usr/bin/env bash
# perf-gate.sh — Phase 7 perf gate for /test (PR2).
#
# Runs rebar3 ct --suite=yuzu_gw_perf_SUITE with configured agent/heartbeat
# counts, parses throughput from the suite output, compares against
# tests/perf-baselines.json, and writes metric rows to the test-runs DB.
#
# Hardware fingerprint guard: the baseline JSON records the fingerprint
# of the machine that captured it (lscpu model + RAM). When the current
# fingerprint doesn't match, the gate auto-downgrades to report-only mode
# and writes WARN instead of FAIL — a 30% regression on Nathan's 5950X
# vs a baseline captured on the M5Max MBP is not a real regression.
#
# Metrics parsed from `ct:pal` output of yuzu_gw_perf_SUITE:
#   - registration_ops_sec       ← "Registration: N ops in M ms (O ops/sec)"
#   - burst_registration_ops_sec ← "Burst registration: ..."
#   - heartbeat_queue_ops_sec    ← "Heartbeat queue: ..."
#   - fanout_10k_ms              ← "Fanout to 10000 agents: M ms ..."
#   - fanout_100k_ms             ← "Fanout to 100000 agents: M ms ..."
#   - session_cleanup_ms_per_agent ← "Cleanup N agents: M ms (K ms/agent)"
#
# Required arguments:
#   --run-id ID       — /test run ID (DB foreign key)
#
# Optional arguments:
#   --baseline PATH   — baseline JSON (default: tests/perf-baselines.json)
#   --tolerance-pct F — regression tolerance (default: 10)
#   --capture-baselines — rewrite baseline from current run
#   --report-only     — parse + record metrics, don't enforce
#   --agents N        — YUZU_PERF_AGENTS override (default: 5000 for gate speed)
#   --heartbeats N    — YUZU_PERF_HEARTBEATS override (default: 20000)
#   --fanout N        — YUZU_PERF_FANOUT override (default: 5000)
#   --groups LIST     — CT groups to run (default: registration,heartbeat,fanout,churn)
#                       (endurance deliberately excluded — it runs for minutes
#                       and belongs in a scheduled nightly, not a gate)
#
# Exit codes:
#   0  measured, within tolerance (or --report-only, or hw mismatch WARN)
#   1  regression beyond tolerance on matching hardware
#   2  internal failure (rebar3/meck missing; runs as WARN)

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
YUZU_ROOT="$(cd "$HERE/../.." && pwd)"

RUN_ID=""
BASELINE=""
TOLERANCE_PCT="10"
CAPTURE=0
REPORT_ONLY=0
PERF_AGENTS="5000"
PERF_HEARTBEATS="20000"
PERF_FANOUT="5000"
PERF_GROUPS="registration,heartbeat,fanout,churn"

usage() {
    cat <<EOF
usage: $0 --run-id ID [options]

Required:
  --run-id ID

Optional:
  --baseline PATH            (default: tests/perf-baselines.json)
  --tolerance-pct F          (default: 10)
  --capture-baselines        rewrite baseline from current run (then PASS)
  --report-only              parse + record metrics, don't enforce
  --agents N                 YUZU_PERF_AGENTS (default: 5000)
  --heartbeats N             YUZU_PERF_HEARTBEATS (default: 20000)
  --fanout N                 YUZU_PERF_FANOUT (default: 5000)
  --groups LIST              CT groups (default: registration,heartbeat,fanout,churn)
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --run-id)             RUN_ID="$2"; shift 2 ;;
        --baseline)           BASELINE="$2"; shift 2 ;;
        --tolerance-pct)      TOLERANCE_PCT="$2"; shift 2 ;;
        --capture-baselines)  CAPTURE=1; shift ;;
        --report-only)        REPORT_ONLY=1; shift ;;
        --agents)             PERF_AGENTS="$2"; shift 2 ;;
        --heartbeats)         PERF_HEARTBEATS="$2"; shift 2 ;;
        --fanout)             PERF_FANOUT="$2"; shift 2 ;;
        --groups)             PERF_GROUPS="$2"; shift 2 ;;
        -h|--help)            usage; exit 0 ;;
        *)                    echo "perf-gate: unknown arg: $1" >&2; usage >&2; exit 2 ;;
    esac
done

if [[ -z "$RUN_ID" ]]; then
    echo "perf-gate: --run-id required" >&2
    exit 2
fi

# Validate RUN_ID before it's interpolated into filesystem paths (UP-9).
if [[ ! "$RUN_ID" =~ ^[A-Za-z0-9._-]+$ ]]; then
    echo "perf-gate: invalid --run-id '$RUN_ID' (allowed: A-Z a-z 0-9 . _ -)" >&2
    exit 2
fi

BASELINE="${BASELINE:-$YUZU_ROOT/tests/perf-baselines.json}"

LOG_DIR="$HOME/.local/share/yuzu/test-runs/$RUN_ID"
mkdir -p "$LOG_DIR"

GATE_LOG="$LOG_DIR/perf.log"
: > "$GATE_LOG"

echo ""
echo "Phase 7 — Perf (run $RUN_ID)"
echo "============================"
echo "  baseline:      $BASELINE"
echo "  tolerance-pct: $TOLERANCE_PCT"
echo "  capture:       $CAPTURE  report-only: $REPORT_ONLY"
echo "  agents=$PERF_AGENTS heartbeats=$PERF_HEARTBEATS fanout=$PERF_FANOUT"
echo "  groups:        $PERF_GROUPS"
echo ""

GATE_START=$(date +%s)

write_gate() {
    local status="$1" duration="$2" notes="$3"
    bash "$HERE/test-db-write.sh" gate \
        --run-id "$RUN_ID" \
        --phase 7 \
        --gate "Perf" \
        --status "$status" \
        --duration "$duration" \
        --log "perf.log" \
        --notes "$notes"
}

write_metric() {
    local name="$1" value="$2" unit="$3"
    bash "$HERE/test-db-write.sh" metric \
        --run-id "$RUN_ID" \
        --name "$name" \
        --value "$value" \
        --unit "$unit"
}

# ── Activate Erlang ─────────────────────────────────────────────────────

if [[ -f "$YUZU_ROOT/scripts/ensure-erlang.sh" ]]; then
    # shellcheck disable=SC1091
    source "$YUZU_ROOT/scripts/ensure-erlang.sh" 2>>"$GATE_LOG" || true
fi
if ! command -v erl >/dev/null 2>&1; then
    write_gate WARN 0 "erl not on PATH — source scripts/ensure-erlang.sh"
    exit 2
fi
if ! command -v rebar3 >/dev/null 2>&1; then
    write_gate WARN 0 "rebar3 not on PATH"
    exit 2
fi

# ── Hardware fingerprint ────────────────────────────────────────────────

fingerprint() {
    local cpu mem
    cpu=$(grep -m1 "^model name" /proc/cpuinfo 2>/dev/null | sed 's/.*: //' || echo "unknown")
    if [[ -r /proc/meminfo ]]; then
        mem=$(awk '/^MemTotal:/ {printf "%dGB", $2/1024/1024}' /proc/meminfo)
    else
        mem="unknown"
    fi
    echo "${cpu} | ${mem}"
}

HW_FINGERPRINT=$(fingerprint)
echo "perf-gate: hardware fingerprint: $HW_FINGERPRINT" | tee -a "$GATE_LOG"

# ── Run the perf suite ─────────────────────────────────────────────────

PERF_LOG_RAW="$LOG_DIR/perf-suite.log"
: > "$PERF_LOG_RAW"

echo "perf-gate: running yuzu_gw_perf_SUITE (groups=$PERF_GROUPS)" | tee -a "$GATE_LOG"

# rebar3 ct --group is comma-separated with no spaces.
# --verbose so ct:pal output reaches stdout (not just the html log).
# Exit code is ignored here — we'll read the parsed metrics instead,
# so a single failed assertion doesn't nuke all the metrics from the
# other cases.
CT_RC=0
(
    cd "$YUZU_ROOT/gateway"
    # Keep test compile isolated from the eunit cache to avoid #336 crossfire.
    YUZU_PERF_AGENTS="$PERF_AGENTS" \
    YUZU_PERF_HEARTBEATS="$PERF_HEARTBEATS" \
    YUZU_PERF_FANOUT="$PERF_FANOUT" \
    rebar3 ct \
        --dir apps/yuzu_gw/test \
        --suite yuzu_gw_perf_SUITE \
        --group "$PERF_GROUPS" \
        --verbose \
        >>"$PERF_LOG_RAW" 2>&1
) || CT_RC=$?

echo "perf-gate: rebar3 ct exit=$CT_RC" | tee -a "$GATE_LOG"

# Copy the raw log into the gate log so the summary table points at one file.
{
    echo "--- rebar3 ct --suite yuzu_gw_perf_SUITE ---"
    tail -200 "$PERF_LOG_RAW" 2>/dev/null
} >> "$GATE_LOG"

# ── Parse metrics ───────────────────────────────────────────────────────
#
# The suite uses assert_throughput which prints:
#   "Registration: 5000 ops in 613 ms (8157 ops/sec)"
#   "Burst registration: 5000 ops in 340 ms (14706 ops/sec)"
#   "Heartbeat queue: 20000 ops in 83 ms (240964 ops/sec)"
#   "Fanout to 10000 agents: 42 ms (limit 100 ms)"
#   "Cleanup 1000 agents: 150 ms (0.15 ms/agent)"
#
# Also: "fanout_10k: N agents, limit M ms" header and
#       "~B concurrent fanouts to ~B agents: ~B ms"
#
# Parsing is intentionally regex-lite — the test log is stable enough
# that fancy parsers would be overkill. Each metric is optional; missing
# metrics don't fail the gate, they just don't enforce.

parse_metrics() {
    local log="$1" metric value
    declare -A metrics=()

    if [[ ! -s "$log" ]]; then
        return 1
    fi

    # UP-12: strip ANSI escape sequences before matching. rebar3 ct with
    # TERM set may emit colorized ct:pal output; the escape codes break
    # literal substring matching because they can appear inside the label
    # text. Strip them per-line.
    #
    # Throughput lines: "Label: N ops in M ms (O ops/sec)"
    while IFS= read -r line; do
        line=$(echo "$line" | sed $'s/\x1b\\[[0-9;]*[a-zA-Z]//g')
        case "$line" in
            *"Registration:"*"ops/sec"*)
                value=$(echo "$line" | sed -nE 's/.*\(([0-9]+)[[:space:]]*ops\/sec\).*/\1/p')
                [[ -n "$value" ]] && metrics[registration_ops_sec]="$value"
                ;;
            *"Burst registration:"*"ops/sec"*)
                value=$(echo "$line" | sed -nE 's/.*\(([0-9]+)[[:space:]]*ops\/sec\).*/\1/p')
                [[ -n "$value" ]] && metrics[burst_registration_ops_sec]="$value"
                ;;
            *"Heartbeat queue:"*"ops/sec"*)
                value=$(echo "$line" | sed -nE 's/.*\(([0-9]+)[[:space:]]*ops\/sec\).*/\1/p')
                [[ -n "$value" ]] && metrics[heartbeat_queue_ops_sec]="$value"
                ;;
            *"Fanout to 10000 agents:"*)
                value=$(echo "$line" | sed -nE 's/.*Fanout to 10000 agents:[[:space:]]*([0-9]+)[[:space:]]*ms.*/\1/p')
                [[ -n "$value" ]] && metrics[fanout_10k_ms]="$value"
                ;;
            *"Fanout to 100000 agents:"*)
                value=$(echo "$line" | sed -nE 's/.*Fanout to 100000 agents:[[:space:]]*([0-9]+)[[:space:]]*ms.*/\1/p')
                [[ -n "$value" ]] && metrics[fanout_100k_ms]="$value"
                ;;
            *"Cleanup "*"agents:"*"ms/agent)")
                # "Cleanup 1000 agents: 150 ms (0.15 ms/agent)"
                value=$(echo "$line" | sed -nE 's/.*\(([0-9.]+)[[:space:]]*ms\/agent\).*/\1/p')
                [[ -n "$value" ]] && metrics[session_cleanup_ms_per_agent]="$value"
                ;;
        esac
    done < "$log"

    # Emit parsed metrics as "name=value" lines.
    for metric in "${!metrics[@]}"; do
        printf "%s=%s\n" "$metric" "${metrics[$metric]}"
    done
}

PARSED="$(parse_metrics "$PERF_LOG_RAW")"

# Count how many metrics parsed for the min-metrics threshold (qa-S1 / UP-12).
METRIC_COUNT=0
if [[ -n "$PARSED" ]]; then
    METRIC_COUNT=$(echo "$PARSED" | grep -c "=")
fi

# qa-B1 / UP-7: propagate CT exit code to gate outcome.
# A non-zero CT exit is a real failure signal even if some metrics were
# extractable from the passing cases. CT exit 1 means a test assertion
# failed → FAIL. Exit codes > 1 are typically tooling/compile failures
# → WARN (the gate infrastructure couldn't produce a verdict).
#
# qa-S1: if CT succeeded but the parser extracted fewer than 3 of the
# expected 5-6 metrics, that's a parser drift (label rename, ANSI mangling,
# format change). FAIL with a specific message rather than silently
# WARNing with "no metrics parsed".

if [[ $CT_RC -eq 1 ]]; then
    GATE_DUR=$(( $(date +%s) - GATE_START ))
    # If we captured ANY metrics, record them before failing.
    if [[ -n "$PARSED" ]]; then
        echo "perf-gate: recording $METRIC_COUNT partial metrics before FAIL" | tee -a "$GATE_LOG"
        while IFS='=' read -r name value; do
            [[ -z "$name" ]] && continue
            case "$name" in
                *_ops_sec) write_metric "perf_$name" "$value" "ops/sec" ;;
                *_ms_per_agent) write_metric "perf_$name" "$value" "ms/agent" ;;
                *_ms) write_metric "perf_$name" "$value" "ms" ;;
                *) write_metric "perf_$name" "$value" "" ;;
            esac
        done <<< "$PARSED"
    fi
    write_gate FAIL "$GATE_DUR" "CT suite FAIL (rebar3 exit=$CT_RC) — yuzu_gw_perf_SUITE assertion failed, see perf-suite.log"
    exit 1
fi

if [[ $CT_RC -gt 1 ]]; then
    GATE_DUR=$(( $(date +%s) - GATE_START ))
    write_gate WARN "$GATE_DUR" "CT tooling failure (rebar3 exit=$CT_RC) — compile/toolchain broken, see perf-suite.log"
    exit 2
fi

# CT succeeded → we must have ≥3 of the expected metrics or the parser
# has drifted and we should FAIL rather than silently drop signal.
if [[ -z "$PARSED" ]]; then
    GATE_DUR=$(( $(date +%s) - GATE_START ))
    write_gate FAIL "$GATE_DUR" "CT PASS but 0 metrics parsed — yuzu_gw_perf_SUITE ct:pal format changed? see perf-suite.log"
    exit 1
fi
if (( METRIC_COUNT < 3 )); then
    GATE_DUR=$(( $(date +%s) - GATE_START ))
    write_gate FAIL "$GATE_DUR" "CT PASS but only $METRIC_COUNT/5 metrics parsed — parser drift, see perf-suite.log"
    exit 1
fi

echo "perf-gate: parsed $METRIC_COUNT metrics:" | tee -a "$GATE_LOG"
echo "$PARSED" | sed 's/^/  /' | tee -a "$GATE_LOG"

# Record each metric. Throughput is in ops/sec; latency is in ms.
while IFS='=' read -r name value; do
    [[ -z "$name" ]] && continue
    case "$name" in
        *_ops_sec) write_metric "perf_$name" "$value" "ops/sec" ;;
        *_ms_per_agent) write_metric "perf_$name" "$value" "ms/agent" ;;
        *_ms) write_metric "perf_$name" "$value" "ms" ;;
        *) write_metric "perf_$name" "$value" "" ;;
    esac
done <<< "$PARSED"

# ── Capture mode: rewrite baseline and exit ─────────────────────────────

if [[ $CAPTURE -eq 1 ]]; then
    # UP-18 / co-2 / sre-3: refuse capture if the suite didn't pass cleanly
    # (CT_RC != 0 is already fatal above, but we also require a minimum
    # metric count so a parser drift doesn't anchor an incomplete baseline).
    if (( METRIC_COUNT < 3 )); then
        GATE_DUR=$(( $(date +%s) - GATE_START ))
        NOTE="refused --capture-baselines: only $METRIC_COUNT/5 metrics parsed — fix parser or CT output first"
        echo "perf-gate: $NOTE" | tee -a "$GATE_LOG"
        write_gate FAIL "$GATE_DUR" "$NOTE"
        exit 1
    fi

    # Diff old vs new if a prior baseline exists (hp-S1).
    if [[ -f "$BASELINE" ]]; then
        echo "perf-gate: diffing old vs new metrics:" | tee -a "$GATE_LOG"
        YUZU_PARSED="$PARSED" python3 - "$BASELINE" <<'PY' | tee -a "$GATE_LOG"
import json, os, sys
with open(sys.argv[1]) as f:
    old = json.load(f).get("metrics", {})
new = {}
for line in os.environ.get("YUZU_PARSED", "").strip().splitlines():
    if "=" in line:
        k, v = line.split("=", 1)
        try:
            new[k.strip()] = float(v.strip())
        except ValueError:
            pass
for k in sorted(set(old) | set(new)):
    o = old.get(k, "(absent)")
    n = new.get(k, "(absent)")
    marker = " *" if o != n else ""
    print(f"  {k:<40} {str(o):>16} -> {str(n):>16}{marker}")
PY
    fi

    echo "perf-gate: --capture-baselines set — rewriting $BASELINE"
    YUZU_PARSED="$PARSED" python3 - "$BASELINE" "$HW_FINGERPRINT" "$YUZU_ROOT" <<'PY'
import json, os, subprocess, sys, time
path, hw, repo = sys.argv[1:]
metrics = {}
for line in os.environ.get("YUZU_PARSED", "").strip().splitlines():
    if "=" in line:
        k, v = line.split("=", 1)
        try:
            metrics[k.strip()] = float(v.strip())
        except ValueError:
            pass
try:
    commit = subprocess.check_output(
        ["git", "-C", repo, "rev-parse", "HEAD"], text=True
    ).strip()
except Exception:
    commit = "unknown"
baseline = {
    "__schema": "perf-baseline/v1",
    "__doc": (
        "Locked perf baseline enforced by scripts/test/perf-gate.sh. "
        "Hardware fingerprint mismatch auto-downgrades to WARN (not FAIL). "
        "Regenerate with 'bash scripts/test/perf-gate.sh --run-id manual --capture-baselines' "
        "then commit this file alongside the change."
    ),
    "captured_at": int(time.time()),
    "captured_commit": commit,
    "hardware_fingerprint": hw,
    "tolerance_pct": 10.0,
    "metrics": metrics,
}
with open(path, "w") as f:
    json.dump(baseline, f, indent=2, sort_keys=True)
    f.write("\n")
print(f"perf-gate: wrote baseline to {path}")
PY
    GATE_DUR=$(( $(date +%s) - GATE_START ))
    write_gate PASS "$GATE_DUR" "captured perf baseline ($HW_FINGERPRINT)"
    exit 0
fi

# ── Compare against baseline ───────────────────────────────────────────

if [[ ! -f "$BASELINE" ]]; then
    GATE_DUR=$(( $(date +%s) - GATE_START ))
    write_gate WARN "$GATE_DUR" "no baseline at $BASELINE — run with --capture-baselines"
    exit 2
fi

COMPARE_RC=0
RESULT=$(YUZU_PARSED="$PARSED" python3 - "$BASELINE" "$HW_FINGERPRINT" "$TOLERANCE_PCT" <<'PY'
import json, math, os, sys
baseline_path, hw, tol_pct = sys.argv[1], sys.argv[2], float(sys.argv[3])
with open(baseline_path) as f:
    baseline = json.load(f)
baseline_hw = baseline.get("hardware_fingerprint", "")
effective_tol = float(baseline.get("tolerance_pct", tol_pct))
is_seed = bool(baseline.get("__seed"))

current = {}
for line in os.environ.get("YUZU_PARSED", "").strip().splitlines():
    if "=" in line:
        k, v = line.split("=", 1)
        try:
            current[k.strip()] = float(v.strip())
        except ValueError:
            pass

b_metrics = baseline.get("metrics", {})
if not current:
    print("WARN: no current metrics parsed")
    sys.exit(2)

# UP-10 / co-2 / sre-2: honor the __seed sentinel explicitly. Seed
# baseline → all current metrics are recorded, no enforcement, return
# exit 0 (PASS, not WARN) so SKILL.md full-mode doesn't see a non-zero
# and abort Phase 7. This matches hp-B1: the first-run-on-seed story.
if is_seed or not b_metrics:
    if is_seed:
        print(f"PASS (seed baseline): {len(current)} metrics recorded — run --capture-baselines to enable enforcement")
    else:
        print(f"PASS (empty baseline): {len(current)} metrics recorded — run --capture-baselines to enable enforcement")
    sys.exit(0)

# Hardware mismatch → auto-downgrade
if baseline_hw and baseline_hw != hw:
    print(f"WARN: hw mismatch (baseline='{baseline_hw[:40]}' current='{hw[:40]}') — report-only")
    sys.exit(2)

# sec-L4: guard against baseline corruption. A non-finite, zero, or
# negative baseline value would create trivial-pass conditions.
bad_baseline = []
for name, v in b_metrics.items():
    try:
        fv = float(v)
    except (TypeError, ValueError):
        bad_baseline.append(f"{name}=nan")
        continue
    if not math.isfinite(fv) or fv <= 0:
        bad_baseline.append(f"{name}={fv}")
if bad_baseline:
    print(f"WARN: baseline has invalid metric values: {', '.join(bad_baseline[:5])} — re-capture")
    sys.exit(2)

# Throughput metrics (*_ops_sec): regression if current < baseline * (1 - tol)
# Latency metrics   (*_ms / *_ms_per_agent): regression if current > baseline * (1 + tol)
regressions = []
improvements = []
missing = []
checked = 0
for name, b in b_metrics.items():
    if name not in current:
        missing.append(name)
        continue
    c = current[name]
    checked += 1
    tol_frac = effective_tol / 100.0
    if name.endswith("_ops_sec"):
        floor = b * (1.0 - tol_frac)
        if c + 1e-9 < floor:
            regressions.append(f"{name}: {c:.0f} < floor {floor:.0f} (baseline {b:.0f})")
        elif c > b * 1.05:
            improvements.append(f"{name}: {c:.0f} > {b:.0f}")
    else:
        ceiling = b * (1.0 + tol_frac)
        if c > ceiling + 1e-9:
            regressions.append(f"{name}: {c:.2f} > ceiling {ceiling:.2f} (baseline {b:.2f})")
        elif c < b * 0.95:
            improvements.append(f"{name}: {c:.2f} < {b:.2f}")

# UP-13: if the current run is missing baseline metrics, something in
# the suite silently didn't produce output. Surface this as WARN so
# the gate doesn't quietly check only a subset.
if missing and not regressions:
    print(f"WARN: {len(missing)} baseline metrics not in current run: {','.join(missing[:5])} (checked {checked})")
    sys.exit(2)

if regressions:
    print(f"FAIL: {len(regressions)} regressions, {len(improvements)} improvements (checked {checked})")
    for r in regressions[:5]:
        print(f"  {r}")
    sys.exit(1)
print(f"PASS: {checked} metrics within {effective_tol}% tolerance, {len(improvements)} improved, {len(missing)} missing")
PY
) || COMPARE_RC=$?

echo "perf-gate: $RESULT" | tee -a "$GATE_LOG"

GATE_DUR=$(( $(date +%s) - GATE_START ))

if [[ $REPORT_ONLY -eq 1 ]]; then
    write_gate PASS "$GATE_DUR" "report-only: $RESULT"
    exit 0
fi

case $COMPARE_RC in
    0) write_gate PASS "$GATE_DUR" "$RESULT"; exit 0 ;;
    1) write_gate FAIL "$GATE_DUR" "$RESULT"; exit 1 ;;
    2) write_gate WARN "$GATE_DUR" "$RESULT"; exit 2 ;;
    *) write_gate WARN "$GATE_DUR" "compare rc=$COMPARE_RC: $RESULT"; exit 2 ;;
esac
