#!/usr/bin/env bash
# Provision one persistent test-runs.db per Big Tam GitHub runner agent.
#
# Run from a Yuzu checkout on Big Tam:
#   sudo bash deploy/linux/Provision-BigTam-Runner-Telemetry.sh
#
# The script does not restart runners (which could kill an active CI job).
# ci.yml derives the same path immediately from RUNNER_TOOL_CACHE/RUNNER_NAME;
# the systemd drop-ins make YUZU_TEST_DB available to every workflow after the
# next planned runner restart.

set -euo pipefail

RUNNER_COUNT="${RUNNER_COUNT:-4}"
RUNNER_USER="${RUNNER_USER:-runner}"
RUNNER_ROOT_BASE="${RUNNER_ROOT_BASE:-/home/runner}"
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TEST_DB="$REPO_ROOT/scripts/test/test_db.py"

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "Provision-BigTam-Runner-Telemetry.sh must run as root (use sudo)" >&2
  exit 1
fi
if [[ ! -f "$TEST_DB" ]]; then
  echo "test DB schema tool missing at $TEST_DB" >&2
  exit 1
fi
if ! id "$RUNNER_USER" >/dev/null 2>&1; then
  echo "runner user '$RUNNER_USER' does not exist" >&2
  exit 1
fi

for ((index=0; index<RUNNER_COUNT; index++)); do
  runner_name="yuzu-bigtam-linux-$index"
  runner_root="$RUNNER_ROOT_BASE/r$index"
  runner_config="$runner_root/.runner"
  if [[ ! -r "$runner_config" ]]; then
    echo "runner configuration not readable: $runner_config" >&2
    exit 1
  fi
  # The work path becomes root-owned systemd configuration below. Treat the
  # runner-writable .runner file only as an assertion against the canonical
  # registration path; never interpolate its value into the drop-in.
  work_folder="/srv/ci/work-$index"
  if ! python3 -c \
    'import json,sys; data=json.load(open(sys.argv[1], encoding="utf-8")); sys.exit(0 if data.get("workFolder") == sys.argv[2] else 1)' \
    "$runner_config" "$work_folder"; then
    echo "runner workFolder does not match the canonical path for $runner_name" >&2
    exit 1
  fi
  if [[ ! -d "$work_folder/_tool" ]]; then
    echo "runner tool cache is missing for $runner_name: $work_folder/_tool" >&2
    exit 1
  fi
  tool_cache="$work_folder/_tool"
  db="$tool_cache/yuzu-test-runs/$runner_name/test-runs.db"
  unit="actions.runner.Tr3kkR-Yuzu.$runner_name.service"

  if ! systemctl cat "$unit" >/dev/null 2>&1; then
    echo "runner service not found: $unit" >&2
    exit 1
  fi

  install -d -o "$RUNNER_USER" -g "$RUNNER_USER" -m 0750 "$(dirname "$db")"
  sudo -u "$RUNNER_USER" env YUZU_TEST_DB="$db" python3 "$TEST_DB" init

  dropin="/etc/systemd/system/$unit.d"
  install -d -m 0755 "$dropin"
  tmp="$(mktemp)"
  printf '[Service]\nEnvironment="YUZU_TEST_DB=%s"\n' "$db" > "$tmp"
  install -o root -g root -m 0644 "$tmp" "$dropin/yuzu-ci-telemetry.conf"
  rm -f "$tmp"

  test -s "$db"
  echo "$runner_name telemetry: $db"
done

systemctl daemon-reload
echo "Big Tam telemetry provisioned. Apply the drop-ins at the next safe restart:"
echo "  sudo systemctl restart 'actions.runner.Tr3kkR-Yuzu.yuzu-bigtam-linux-*.service'"
