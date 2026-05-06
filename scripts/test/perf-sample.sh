#!/usr/bin/env bash
# perf-sample.sh — drive perf-gate.sh N times and accumulate per-metric
# samples to a JSONL file for distributional analysis.
#
# Each iteration writes one JSON object per line to the output file,
# making the run resumable: if the script is killed mid-way, re-running
# with --resume picks up at the next iteration. The file is opened with
# `>>` and flushed line-at-a-time so an OS crash mid-write only loses
# one sample.
#
# Usage:
#   bash scripts/test/perf-sample.sh --runs 20 --output /tmp/perf-samples.jsonl
#   bash scripts/test/perf-sample.sh --runs 20 --output /tmp/perf-samples.jsonl --resume

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
YUZU_ROOT="$(cd "$HERE/../.." && pwd)"

RUNS=20
OUTPUT=""
RESUME=0
LABEL="perf-sample"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --runs)   RUNS="$2"; shift 2 ;;
        --output) OUTPUT="$2"; shift 2 ;;
        --resume) RESUME=1; shift ;;
        --label)  LABEL="$2"; shift 2 ;;
        -h|--help)
            sed -n 's/^# \{0,1\}//p' "$0" | head -20
            exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

[[ -z "$OUTPUT" ]] && { echo "perf-sample: --output required" >&2; exit 2; }

# Resolve to absolute path; create parent dir.
case "$OUTPUT" in
    /*) ;;
    *) OUTPUT="$PWD/$OUTPUT" ;;
esac
mkdir -p "$(dirname "$OUTPUT")"

START_ITER=1
if [[ $RESUME -eq 1 && -f "$OUTPUT" ]]; then
    DONE=$(wc -l < "$OUTPUT" | tr -d ' ')
    START_ITER=$((DONE + 1))
    echo "perf-sample: resuming from iteration $START_ITER (already have $DONE samples in $OUTPUT)"
fi

if [[ $START_ITER -gt $RUNS ]]; then
    echo "perf-sample: already have $((START_ITER - 1)) >= --runs $RUNS samples; nothing to do"
    exit 0
fi

# Activate Erlang once for the whole script (perf-gate.sh sources it
# again per run, but having it on PATH avoids the "[ensure-erlang]"
# banner repeating in every iteration log).
# shellcheck disable=SC1091
source "$YUZU_ROOT/scripts/ensure-erlang.sh" 2>/dev/null || true

# Pre-flight: refuse to start if UAT ports are listening. perf-gate.sh
# does this per-run too, but checking once up front lets us bail before
# we burn the first iteration's compile time.
# shellcheck source=scripts/test/_portable.sh
. "$YUZU_ROOT/scripts/test/_portable.sh"
QUIET_PORTS=(8080 50051 50052 50055 50063 8081 9568)
BUSY=()
BUSY_CSV=$(listening_ports_among "${QUIET_PORTS[@]}")
if [[ -n "$BUSY_CSV" ]]; then
    IFS=',' read -ra BUSY <<< "$BUSY_CSV"
fi
if [[ ${#BUSY[@]} -gt 0 ]]; then
    echo "perf-sample: refusing to start — UAT ports listening: ${BUSY[*]}" >&2
    echo "perf-sample: run 'bash scripts/linux-start-UAT.sh stop' first" >&2
    exit 2
fi

WALL_START=$(date +%s)
echo "perf-sample: $RUNS iterations → $OUTPUT (label=$LABEL)"
echo "perf-sample: estimated wall clock: $((RUNS * 63 / 60)) min"

for i in $(seq "$START_ITER" "$RUNS"); do
    ITER_START=$(date +%s)
    RUN_ID="${LABEL}-$(printf '%04d' "$i")-$(date +%s)"
    LOG_DIR="$HOME/.local/share/yuzu/test-runs/${RUN_ID}"
    mkdir -p "$LOG_DIR"

    # Quiet a stub run row so perf-gate's DB writes have a parent.
    bash "$HERE/test-db-write.sh" run-start \
        --run-id "$RUN_ID" \
        --commit "$(git rev-parse HEAD)" \
        --branch "$(git rev-parse --abbrev-ref HEAD)" \
        --mode full > /dev/null 2>&1

    # As of 2026-05-03 perf-gate.sh is measure-and-report by default —
    # no --report-only flag needed (and the flag is now rejected). The
    # gate parses + records metrics, exits PASS. Capture exit so a failed
    # iteration doesn't kill the whole sampling run.
    bash "$HERE/perf-gate.sh" --run-id "$RUN_ID" \
        > "$LOG_DIR/perf-gate.out" 2>&1
    PG_RC=$?

    # Pull the parsed metrics directly from the gate's stdout block.
    # Format from perf-gate.sh:
    #   perf-gate: parsed N metrics:
    #     registration_ops_sec=18727
    #     session_cleanup_ms_per_agent=0.05
    #     heartbeat_queue_ops_sec=2836075
    #     burst_registration_ops_sec=14749
    PARSED=$(grep -E '^  [a-z_]+=' "$LOG_DIR/perf-gate.out" || true)
    LOADAVG_PRE=$(awk '/loadavg pre=/{ sub(/.*pre=/,""); print; exit }' "$LOG_DIR/perf-gate.out" 2>/dev/null || echo "")
    LOADAVG_POST=$(awk '/loadavg post=/{ sub(/.*post=/,""); print; exit }' "$LOG_DIR/perf-gate.out" 2>/dev/null || echo "")

    # Build a single-line JSON record. python is faster than 6 sed calls
    # and gets the float quoting right.
    python3 - "$RUN_ID" "$i" "$ITER_START" "$PG_RC" "$LOADAVG_PRE" "$LOADAVG_POST" "$PARSED" <<'PY' >> "$OUTPUT"
import json, sys
run_id, iteration, ts, rc, lpre, lpost, parsed = sys.argv[1:8]
metrics = {}
for line in parsed.splitlines():
    line = line.strip()
    if "=" not in line:
        continue
    k, v = line.split("=", 1)
    try:
        metrics[k] = int(v)
    except ValueError:
        try:
            metrics[k] = float(v)
        except ValueError:
            metrics[k] = v
record = {
    "run_id": run_id,
    "iteration": int(iteration),
    "started_at": int(ts),
    "perf_gate_rc": int(rc),
    "loadavg_pre": float(lpre) if lpre else None,
    "loadavg_post": float(lpost) if lpost else None,
    "metrics": metrics,
}
print(json.dumps(record))
PY

    # Reclaim disk: the run's log dir is bulky (gigabytes after 20 runs).
    # Keep the perf-suite.log (smallest, the raw bench numbers); drop the
    # rest. Comment out if you need the full log later.
    rm -f "$LOG_DIR/perf-gate.out"
    rm -rf "$LOG_DIR/sanitizer" 2>/dev/null

    ITER_DUR=$(( $(date +%s) - ITER_START ))
    DONE=$i
    REMAIN=$((RUNS - DONE))
    echo "  [$DONE/$RUNS] rc=$PG_RC dur=${ITER_DUR}s eta=$((REMAIN * ITER_DUR / 60))min  load=$LOADAVG_PRE→$LOADAVG_POST"
done

WALL_DUR=$(( $(date +%s) - WALL_START ))
echo "perf-sample: done — $RUNS iterations in $((WALL_DUR / 60)) min, output=$OUTPUT"
