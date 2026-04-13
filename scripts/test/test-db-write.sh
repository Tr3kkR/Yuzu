#!/usr/bin/env bash
# test-db-write.sh — Helper for /test gates to record results to the DB.
#
# Thin wrapper around scripts/test/test_db.py. Subcommands:
#
#   run-start  --run-id ID --commit SHA --branch B --mode MODE [--notes N]
#       Open a new test_runs row in RUNNING state and create the per-run
#       log directory under ~/.local/share/yuzu/test-runs/${RUN_ID}/.
#
#   run-finish --run-id ID [--status PASS|FAIL|WARN|ABORTED]
#       Aggregate gate counts, set finished_at/total_duration_seconds, and
#       compute overall_status (auto: any FAIL→FAIL, any WARN→WARN, else PASS).
#       Optional --status overrides the computed value.
#
#   gate    --run-id ID --phase N --gate NAME --status PASS|FAIL|WARN|SKIP \
#           --duration SECONDS [--log REL_PATH] [--notes "..."]
#       Record one gate result. Idempotent on (run_id, gate_name).
#
#   timing  --run-id ID --gate NAME --step NAME --ms N
#       Record a sub-step duration in milliseconds. Idempotent.
#
#   metric  --run-id ID --name NAME --value FLOAT [--unit UNIT]
#       Record a quantitative measurement (coverage %, perf ops/sec, etc.).
#
# Honors YUZU_TEST_DB=path to override the default DB location.
#
# Examples:
#   bash scripts/test/test-db-write.sh run-start \
#       --run-id "$RUN_ID" --commit "$(git rev-parse HEAD)" \
#       --branch dev --mode default
#   bash scripts/test/test-db-write.sh gate \
#       --run-id "$RUN_ID" --phase 2 --gate "Upgrade v0.10.0->HEAD" \
#       --status PASS --duration 192 --notes "8/8 fixtures preserved"
#   bash scripts/test/test-db-write.sh timing \
#       --run-id "$RUN_ID" --gate phase2 --step image-swap --ms 1240
#   bash scripts/test/test-db-write.sh metric \
#       --run-id "$RUN_ID" --name branch_coverage_overall --value 71.3 --unit %

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"

if [[ $# -lt 1 ]]; then
    echo "usage: $0 {run-start|run-finish|gate|timing|metric} [args...]" >&2
    exit 2
fi

exec python3 "$HERE/test_db.py" "$@"
