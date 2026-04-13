#!/usr/bin/env bash
# test-db-init.sh — Initialize the Yuzu test-runs SQLite database.
#
# Thin wrapper around scripts/test/test_db.py. The Python module owns the
# schema definition and migration logic; this script exists so bash callers
# (preflight.sh, the SKILL, scripts/run-tests.sh extensions) have a stable
# subprocess entry point that doesn't depend on the sqlite3 CLI.
#
# Usage:
#   bash scripts/test/test-db-init.sh             # create if missing, stamp v1
#   bash scripts/test/test-db-init.sh --check     # exit 0 iff present and v1
#   YUZU_TEST_DB=/tmp/x.db bash scripts/test/test-db-init.sh

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"

if [[ "${1:-}" == "--check" ]]; then
    exec python3 "$HERE/test_db.py" init --check
fi

exec python3 "$HERE/test_db.py" init
