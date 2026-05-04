#!/usr/bin/env bash
# perf-cron-runner.sh — wait until a target time, then run an N-sample
# perf calibration on the local hardware.
#
# Designed to be invoked under setsid+nohup so it survives the parent
# shell's exit. Use it in place of system cron/at when those aren't
# available (Shulgi WSL2 has neither at nor atd as of 2026-05-02).
#
# Usage:
#   bash scripts/test/perf-cron-runner.sh \
#       --start-at 2026-05-02T23:00:00Z \
#       --runs 300 \
#       --output tests/perf-baseline-provenance-N300.jsonl \
#       --label v0.12.0-baseline-calibration \
#       --log ~/.local/share/yuzu/perf-cron-N300.log
#
# OR with relative timing (--in N seconds):
#   bash scripts/test/perf-cron-runner.sh \
#       --in 600 --runs 20 --output /tmp/perf-N20-trial.jsonl \
#       --label cron-trial-N20 --log ~/.local/share/yuzu/perf-cron-trial.log
#
# Detached invocation pattern (the recommended way to actually use this):
#   setsid nohup bash scripts/test/perf-cron-runner.sh ... </dev/null \
#       >>~/.local/share/yuzu/perf-cron-DETACH.log 2>&1 &
#   disown
#
# When the run finishes the script writes a sibling marker file
# `<output>.done` containing the exit status and total wall time, so
# polling code can detect completion without parsing stdout.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
YUZU_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

START_AT=""
RELATIVE_IN=""
RUNS=""
OUTPUT=""
LABEL=""
LOG=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --start-at) START_AT="$2"; shift 2 ;;
        --in)       RELATIVE_IN="$2"; shift 2 ;;
        --runs)     RUNS="$2"; shift 2 ;;
        --output)   OUTPUT="$2"; shift 2 ;;
        --label)    LABEL="$2"; shift 2 ;;
        --log)      LOG="$2"; shift 2 ;;
        -h|--help)
            sed -n 's/^# \{0,1\}//p' "$0" | head -30
            exit 0
            ;;
        *) echo "perf-cron-runner: unknown arg: $1" >&2; exit 2 ;;
    esac
done

[[ -z "$RUNS" ]]   && { echo "perf-cron-runner: --runs required" >&2; exit 2; }
[[ -z "$OUTPUT" ]] && { echo "perf-cron-runner: --output required" >&2; exit 2; }
[[ -z "$LABEL" ]]  && { echo "perf-cron-runner: --label required" >&2; exit 2; }
[[ -z "$LOG" ]]    && LOG="$HOME/.local/share/yuzu/perf-cron-${LABEL}.log"

# Resolve to absolute paths so a chdir inside the wait or sampler can't
# break things.
case "$OUTPUT" in /*) ;; *) OUTPUT="$YUZU_ROOT/$OUTPUT" ;; esac
case "$LOG"    in /*) ;; *) LOG="$YUZU_ROOT/$LOG"      ;; esac
mkdir -p "$(dirname "$OUTPUT")" "$(dirname "$LOG")"

# Logging via tee so a `tail -F "$LOG"` from another shell sees progress
# as it happens.
exec >>"$LOG" 2>&1

echo "============================================================"
echo "perf-cron-runner started"
echo "  cwd:        $YUZU_ROOT"
echo "  pid:        $$"
echo "  args:       --runs $RUNS --label $LABEL --output $OUTPUT"
echo "  start-at:   ${START_AT:-(none)}"
echo "  in:         ${RELATIVE_IN:-(none)} seconds"
echo "  log:        $LOG"
echo "  invoked at: $(date -u +%Y-%m-%dT%H:%M:%SZ) UTC ($(TZ=Europe/London date '+%H:%M %Z'))"
echo "============================================================"

cd "$YUZU_ROOT"

# Wait until the target time. Both --start-at and --in are supported;
# --start-at wins if both are passed.
if [[ -n "$START_AT" ]]; then
    target_epoch=$(date -d "$START_AT" +%s 2>/dev/null || true)
    if [[ -z "$target_epoch" ]]; then
        echo "perf-cron-runner: bad --start-at '$START_AT' (need RFC3339 e.g. 2026-05-02T23:00:00Z)" >&2
        exit 2
    fi
    now=$(date +%s)
    wait_secs=$((target_epoch - now))
    if [[ $wait_secs -lt 0 ]]; then
        echo "perf-cron-runner: --start-at is in the past (now=$(date -u) target=$START_AT). Aborting." >&2
        exit 2
    fi
    echo "perf-cron-runner: sleeping $wait_secs seconds until $START_AT"
elif [[ -n "$RELATIVE_IN" ]]; then
    wait_secs=$RELATIVE_IN
    echo "perf-cron-runner: sleeping $wait_secs seconds (relative)"
else
    echo "perf-cron-runner: neither --start-at nor --in given — running immediately"
    wait_secs=0
fi

if [[ $wait_secs -gt 0 ]]; then
    sleep "$wait_secs"
fi

echo
echo "============================================================"
echo "perf-cron-runner: wait done — kicking off capture"
echo "  start time: $(date -u +%Y-%m-%dT%H:%M:%SZ) UTC"
echo "============================================================"

CAPTURE_START=$(date +%s)

# Pre-flight: stop any UAT stack so ports are free + the box is quiesced.
# perf-sample.sh enforces the same check internally and would refuse to
# start; doing it here gives us a clean log entry.
echo
echo "--- pre-flight: stop UAT (if up) ---"
bash scripts/linux-start-UAT.sh stop 2>&1 || true
sleep 1

LISTENING=$(ss -tnlH 2>/dev/null | awk '{print $4}' | grep -cE ':(8080|50051|50052|50055|50063|8081|9568)$' || true)
if [[ "$LISTENING" != "0" ]]; then
    echo "perf-cron-runner: $LISTENING UAT ports still listening after stop — aborting"
    exit 3
fi

# Activate Erlang
echo
echo "--- pre-flight: source ensure-erlang.sh ---"
# shellcheck disable=SC1091
source scripts/ensure-erlang.sh
if ! command -v erl >/dev/null 2>&1; then
    echo "perf-cron-runner: erl not on PATH after ensure-erlang.sh — aborting"
    exit 3
fi
echo "  erl: $(command -v erl)"

# The actual sampler. Detach from this script's stdout so a fresh log file
# is the source of truth for the sampler's own output.
echo
echo "--- capture: perf-sample.sh --runs $RUNS --label $LABEL ---"
bash scripts/test/perf-sample.sh \
    --runs "$RUNS" \
    --output "$OUTPUT" \
    --label "$LABEL"
SAMPLER_RC=$?

CAPTURE_END=$(date +%s)
DUR=$((CAPTURE_END - CAPTURE_START))

echo
echo "============================================================"
echo "perf-cron-runner: capture done"
echo "  exit:      $SAMPLER_RC"
echo "  duration:  ${DUR}s ($((DUR/60)) min)"
echo "  output:    $OUTPUT"
echo "  finished:  $(date -u +%Y-%m-%dT%H:%M:%SZ) UTC"
echo "============================================================"

# Post-capture stats (so the next session can pick them up trivially).
if [[ -f scripts/test/perf-stats.py && -f "$OUTPUT" ]]; then
    PROVENANCE_JSON="${OUTPUT%.jsonl}.json"
    echo
    echo "--- post-capture: perf-stats.py → $PROVENANCE_JSON ---"
    python3 scripts/test/perf-stats.py "$OUTPUT" --output-json "$PROVENANCE_JSON" || \
        echo "perf-cron-runner: stats analysis failed (rc=$?), but capture file is intact"
fi

# Sibling marker file. Polling code can `[[ -f X.done ]]` to detect
# completion without parsing this log. Format: one line per status field.
{
    echo "exit=$SAMPLER_RC"
    echo "duration_seconds=$DUR"
    echo "wall_minutes=$((DUR/60))"
    echo "started_at=$(date -u -d "@$CAPTURE_START" +%Y-%m-%dT%H:%M:%SZ)"
    echo "finished_at=$(date -u -d "@$CAPTURE_END" +%Y-%m-%dT%H:%M:%SZ)"
    echo "host=$(hostname)"
    echo "n_samples_requested=$RUNS"
    echo "n_samples_actual=$(wc -l <"$OUTPUT" 2>/dev/null || echo 0)"
    echo "label=$LABEL"
    echo "log=$LOG"
} > "${OUTPUT}.done"

echo
echo "perf-cron-runner: marker written → ${OUTPUT}.done"
exit $SAMPLER_RC
