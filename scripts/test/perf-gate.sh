#!/usr/bin/env bash
# perf-gate.sh — Perf measurement step for /test (PR2).
#
# As of 2026-05-03 this is no longer a regression-detecting gate. It runs
# `rebar3 ct --suite=yuzu_gw_perf_SUITE`, parses throughput/latency metrics
# from ct:pal output, records them to the test-runs DB, and prints a
# human-readable summary. Operators inspect the numbers in context — trend
# via `bash scripts/test/test-db-query.sh --trend`, distribution shape via
# `tests/perf-baseline-provenance-N300.{jsonl,json}`.
#
# Background: the N=300 calibration on 2026-05-03 found that 3 of the 4
# gateway perf metrics are not Gaussian — they're ceiling-bounded with long
# left tails — so neither σ nor %-tolerance bands are statistically
# defensible. Until the gate is rebuilt around percentile primitives, perf
# is measured-and-reported, not enforced. Full rationale and the deferred
# redesign live in docs/perf-baseline-calibration-2026-05-03.md.
#
# What the script still does:
#   - Quiesce check: refuses to run if any of the seven UAT-related ports
#     is listening, because contended measurements mislead the human
#     eyeballing the report (the same trap that drove run 1777704747-244808
#     below tolerance under the old gate).
#   - Hardware fingerprint capture: recorded as a metric so trend queries
#     can group runs by box.
#   - Loadavg pre/post: recorded so a noisy sample is identifiable post-hoc.
#   - Metric parse + DB write: every parsed metric becomes a `perf_*` row
#     under the run.
#   - Always exits PASS when measurement completed; WARN only when tooling
#     prevented measurement (rebar3/erl missing, CT compile broken, parser
#     drift detected). Never FAILs on a metric value.
#
# Required arguments:
#   --run-id ID       — /test run ID (DB foreign key)
#
# Optional arguments:
#   --agents N        — YUZU_PERF_AGENTS override (default: 5000)
#   --heartbeats N    — YUZU_PERF_HEARTBEATS override (default: 20000)
#   --fanout N        — YUZU_PERF_FANOUT override (default: 5000)
#   --groups LIST     — CT groups (default: registration,heartbeat,fanout,churn)
#   --allow-busy      — skip the quiesce check (debug only — numbers will
#                       be contended)
#
# Exit codes:
#   0  metrics measured and recorded (gate row PASS)
#   2  internal failure — rebar3/erl missing, CT tooling broken, no
#      metrics parsed, or quiesce check fired (gate row WARN/FAIL)

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
YUZU_ROOT="$(cd "$HERE/../.." && pwd)"

RUN_ID=""
PERF_AGENTS="5000"
PERF_HEARTBEATS="20000"
PERF_FANOUT="5000"
PERF_GROUPS="registration,heartbeat,fanout,churn"
ALLOW_BUSY=0

usage() {
    cat <<EOF
usage: $0 --run-id ID [options]

Required:
  --run-id ID

Optional:
  --allow-busy               skip the quiesce check (debug-only — measurements
                             will be contended)
  --agents N                 YUZU_PERF_AGENTS (default: 5000)
  --heartbeats N             YUZU_PERF_HEARTBEATS (default: 20000)
  --fanout N                 YUZU_PERF_FANOUT (default: 5000)
  --groups LIST              CT groups (default: registration,heartbeat,fanout,churn)
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --run-id)             RUN_ID="$2"; shift 2 ;;
        --allow-busy)         ALLOW_BUSY=1; shift ;;
        --agents)             PERF_AGENTS="$2"; shift 2 ;;
        --heartbeats)         PERF_HEARTBEATS="$2"; shift 2 ;;
        --fanout)             PERF_FANOUT="$2"; shift 2 ;;
        --groups)             PERF_GROUPS="$2"; shift 2 ;;
        -h|--help)            usage; exit 0 ;;
        # Removed-as-of-2026-05-03 flags. The gate no longer reads a baseline
        # file or supports tolerance/capture/report-only modes. Reject loudly
        # so call sites get pointed at the change rather than silently doing
        # nothing.
        --baseline|--tolerance-pct|--capture-baselines|--report-only)
            echo "perf-gate: '$1' was removed on 2026-05-03 — perf is now measure-and-report, not gated." >&2
            echo "perf-gate: see docs/perf-baseline-calibration-2026-05-03.md for the rationale." >&2
            exit 2
            ;;
        *)                    echo "perf-gate: unknown arg: $1" >&2; usage >&2; exit 2 ;;
    esac
done

if [[ -z "$RUN_ID" ]]; then
    echo "perf-gate: --run-id required" >&2
    exit 2
fi

# Validate RUN_ID before it's interpolated into filesystem paths.
if [[ ! "$RUN_ID" =~ ^[A-Za-z0-9._-]+$ ]]; then
    echo "perf-gate: invalid --run-id '$RUN_ID' (allowed: A-Z a-z 0-9 . _ -)" >&2
    exit 2
fi

LOG_DIR="$HOME/.local/share/yuzu/test-runs/$RUN_ID"
mkdir -p "$LOG_DIR"

GATE_LOG="$LOG_DIR/perf.log"
: > "$GATE_LOG"

echo ""
echo "Phase 7 — Perf (run $RUN_ID, measure-and-report)"
echo "================================================"
echo "  agents=$PERF_AGENTS heartbeats=$PERF_HEARTBEATS fanout=$PERF_FANOUT"
echo "  groups: $PERF_GROUPS"
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

# ── Quiesce check ───────────────────────────────────────────────────────
#
# Even without a regression gate, contended measurements mislead the human
# eyeballing the report. The check refuses to run if any of the well-known
# UAT ports is listening; --allow-busy bypasses for debug.

QUIET_PORTS=(
    8080   # server dashboard / REST
    50051  # server agent gRPC + gateway agent-facing gRPC
    50052  # server management gRPC
    50055  # server gateway upstream
    50063  # gateway management/command forwarding
    8081   # gateway health
    9568   # gateway prometheus
)

ports_in_use() {
    if ! command -v ss >/dev/null 2>&1; then
        return 0  # no ss → cannot prove busy; assume quiet
    fi
    local -a busy=()
    local listeners
    listeners=$(ss -tnlH 2>/dev/null || true)
    for port in "${QUIET_PORTS[@]}"; do
        if echo "$listeners" | awk '{print $4}' | grep -qE ":${port}$"; then
            busy+=("$port")
        fi
    done
    if [[ ${#busy[@]} -eq 0 ]]; then
        echo ""
    else
        local IFS=,
        echo "${busy[*]}"
    fi
}

if [[ "$ALLOW_BUSY" == "0" ]]; then
    BUSY_PORTS=$(ports_in_use)
    if [[ -n "$BUSY_PORTS" ]]; then
        cat <<EOF | tee -a "$GATE_LOG" >&2
perf-gate: refusing to run — UAT stack appears to be up (ports: $BUSY_PORTS)
  Perf measurements are too sensitive to CPU/scheduler contention to coexist
  with a running stack. Run \`bash scripts/linux-start-UAT.sh stop\` first,
  or pass --allow-busy if you understand the numbers will be contended.
EOF
        write_gate FAIL 0 "refused: UAT ports listening ($BUSY_PORTS)"
        exit 2
    fi
fi

LOADAVG_PRE=$(awk '{print $1}' /proc/loadavg 2>/dev/null || echo "0.0")
echo "perf-gate: loadavg pre=$LOADAVG_PRE" | tee -a "$GATE_LOG"

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

CT_RC=0
(
    cd "$YUZU_ROOT/gateway"
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

LOADAVG_POST=$(awk '{print $1}' /proc/loadavg 2>/dev/null || echo "0.0")
echo "perf-gate: loadavg post=$LOADAVG_POST" | tee -a "$GATE_LOG"
write_metric "perf_loadavg_pre" "$LOADAVG_PRE" "load"
write_metric "perf_loadavg_post" "$LOADAVG_POST" "load"

{
    echo "--- rebar3 ct --suite yuzu_gw_perf_SUITE ---"
    tail -200 "$PERF_LOG_RAW" 2>/dev/null
} >> "$GATE_LOG"

# ── Parse metrics ───────────────────────────────────────────────────────

parse_metrics() {
    local log="$1" value
    declare -A metrics=()

    if [[ ! -s "$log" ]]; then
        return 1
    fi

    while IFS= read -r line; do
        # Strip ANSI escape sequences (rebar3 ct may colorize ct:pal).
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
                value=$(echo "$line" | sed -nE 's/.*\(([0-9.]+)[[:space:]]*ms\/agent\).*/\1/p')
                [[ -n "$value" ]] && metrics[session_cleanup_ms_per_agent]="$value"
                ;;
        esac
    done < "$log"

    for name in "${!metrics[@]}"; do
        printf "%s=%s\n" "$name" "${metrics[$name]}"
    done
}

PARSED="$(parse_metrics "$PERF_LOG_RAW")"
METRIC_COUNT=0
if [[ -n "$PARSED" ]]; then
    METRIC_COUNT=$(echo "$PARSED" | grep -c "=")
fi

# Tooling failure → WARN, surface what we got. Anything else → record and PASS.

if [[ $CT_RC -gt 1 ]]; then
    GATE_DUR=$(( $(date +%s) - GATE_START ))
    write_gate WARN "$GATE_DUR" "CT tooling failure (rebar3 exit=$CT_RC) — compile/toolchain broken, see perf-suite.log"
    exit 2
fi

# CT exit=1 means a perf-suite assertion fired (e.g. a hard-coded latency
# limit inside the suite). We still record any metrics that did parse,
# emit a WARN noting the suite assertion, and exit cleanly. Treating it
# as PASS would hide a real signal; treating it as FAIL would re-introduce
# the gating behaviour we just removed.
if [[ $CT_RC -eq 1 ]]; then
    if [[ -n "$PARSED" ]]; then
        echo "perf-gate: recording $METRIC_COUNT metrics (CT assertion fired):" | tee -a "$GATE_LOG"
        echo "$PARSED" | sed 's/^/  /' | tee -a "$GATE_LOG"
        while IFS='=' read -r name value; do
            [[ -z "$name" ]] && continue
            case "$name" in
                *_ops_sec)      write_metric "perf_$name" "$value" "ops/sec" ;;
                *_ms_per_agent) write_metric "perf_$name" "$value" "ms/agent" ;;
                *_ms)           write_metric "perf_$name" "$value" "ms" ;;
                *)              write_metric "perf_$name" "$value" "" ;;
            esac
        done <<< "$PARSED"
    fi
    GATE_DUR=$(( $(date +%s) - GATE_START ))
    write_gate WARN "$GATE_DUR" "CT suite asserted (rebar3 exit=$CT_RC) — see perf-suite.log; metrics recorded"
    exit 2
fi

# CT succeeded but parser extracted nothing → drift signal worth surfacing.
if [[ -z "$PARSED" ]]; then
    GATE_DUR=$(( $(date +%s) - GATE_START ))
    write_gate WARN "$GATE_DUR" "CT PASS but 0 metrics parsed — yuzu_gw_perf_SUITE ct:pal format changed? see perf-suite.log"
    exit 2
fi

echo "perf-gate: parsed $METRIC_COUNT metrics:" | tee -a "$GATE_LOG"
echo "$PARSED" | sed 's/^/  /' | tee -a "$GATE_LOG"

while IFS='=' read -r name value; do
    [[ -z "$name" ]] && continue
    case "$name" in
        *_ops_sec)      write_metric "perf_$name" "$value" "ops/sec" ;;
        *_ms_per_agent) write_metric "perf_$name" "$value" "ms/agent" ;;
        *_ms)           write_metric "perf_$name" "$value" "ms" ;;
        *)              write_metric "perf_$name" "$value" "" ;;
    esac
done <<< "$PARSED"

GATE_DUR=$(( $(date +%s) - GATE_START ))
write_gate PASS "$GATE_DUR" "measured $METRIC_COUNT metrics on $HW_FINGERPRINT"
exit 0
