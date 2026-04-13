#!/usr/bin/env bash
# test-db-query.sh — Operator-facing query wrapper for the test-runs DB.
#
# Thin wrapper around `python3 scripts/test/test_db.py query`. Power users
# can run that directly or `python3 -c "import sqlite3; ..."` against
# ~/.local/share/yuzu/test-runs.db for ad-hoc analysis.
#
# Usage:
#   bash scripts/test/test-db-query.sh                           # last 10 runs
#   bash scripts/test/test-db-query.sh --latest                  # most recent + gate detail
#   bash scripts/test/test-db-query.sh --last 20                 # last 20 runs
#   bash scripts/test/test-db-query.sh --diff RUN_A RUN_B        # gate diff
#   bash scripts/test/test-db-query.sh --trend metric=branch_coverage_overall
#   bash scripts/test/test-db-query.sh --trend timing=phase2.image-swap
#   bash scripts/test/test-db-query.sh --trend timing=phase3-linux.ota-download --branch dev
#   bash scripts/test/test-db-query.sh --flaky --days 30
#   bash scripts/test/test-db-query.sh --export RUN_ID           # dump JSON
#   bash scripts/test/test-db-query.sh --prune 100               # keep last 100 runs

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"

exec python3 "$HERE/test_db.py" query "$@"
