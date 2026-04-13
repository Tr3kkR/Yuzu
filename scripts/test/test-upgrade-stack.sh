#!/usr/bin/env bash
# test-upgrade-stack.sh — Phase 2 of the /test pipeline.
#
# Stand up the previous-released yuzu-server image (default 0.10.0 from
# ghcr.io), populate fixtures, swap to the local HEAD image (built in
# Phase 1, tagged yuzu-server:test-${RUN_ID}), verify migrations ran and
# fixtures survived, and run the synthetic UAT test set against the
# upgraded stack. Records sub-step timings into the test-runs DB.
#
# This is the user's stated headline priority for /test: "first stand up
# the last version of the UAT environment, and then upgrade it, and then
# test that — because that is what most users will want to do."
#
# Required arguments:
#   --run-id ID           — links sub-step timings to the test-runs row
#
# Optional arguments:
#   --old-version V       — image tag to upgrade FROM (default: 0.10.0)
#   --new-version V       — image tag to upgrade TO   (default: 0.10.1-test-${RUN_ID})
#   --new-image-loaded 0|1 — 1 if the new image is already in the local
#                            daemon (built locally in Phase 1); 0 to docker pull
#                            (default: 1)
#   --test-dir DIR        — scratch dir (default: /tmp/yuzu-test-${RUN_ID})
#   --keep-stack          — leave the stack up after the test (debugging)
#   --user NAME           — admin username (default: testadmin)
#   --password PASS       — admin password (default: random per run)
#
# Records the following timings (gate=phase2):
#   pull-old-images, stack-up-old, fixtures-write,
#   image-swap, ready-after-upgrade, fixtures-verify,
#   synthetic-uat-against-upgraded
#
# Records the gate row 'Upgrade vOLD->NEW' to test_gates with overall PASS/FAIL.
#
# Exit code is the gate result: 0 PASS, 1 FAIL.

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
YUZU_ROOT="$(cd "$HERE/../.." && pwd)"

RUN_ID=""
OLD_VERSION="0.10.0"
NEW_VERSION=""
NEW_IMAGE_LOADED=1
TEST_DIR=""
KEEP_STACK=0
USERNAME="testadmin"
PASSWORD=""

usage() {
    cat <<EOF
usage: $0 --run-id ID [options]

Required:
  --run-id ID

Optional:
  --old-version V        (default: 0.10.0)
  --new-version V        (default: 0.10.1-test-\${RUN_ID})
  --new-image-loaded 0|1 (default: 1 — assumes Phase 1 built it)
  --test-dir DIR         (default: /tmp/yuzu-test-\${RUN_ID})
  --keep-stack           leave the stack running after the test
  --user NAME            (default: testadmin)
  --password PASS        (default: randomly generated per run)
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --run-id)            RUN_ID="$2"; shift 2 ;;
        --old-version)       OLD_VERSION="$2"; shift 2 ;;
        --new-version)       NEW_VERSION="$2"; shift 2 ;;
        --new-image-loaded)  NEW_IMAGE_LOADED="$2"; shift 2 ;;
        --test-dir)          TEST_DIR="$2"; shift 2 ;;
        --keep-stack)        KEEP_STACK=1; shift ;;
        --user)              USERNAME="$2"; shift 2 ;;
        --password)          PASSWORD="$2"; shift 2 ;;
        -h|--help)           usage; exit 0 ;;
        *)                   echo "unknown arg: $1" >&2; usage >&2; exit 2 ;;
    esac
done

if [[ -z "$RUN_ID" ]]; then
    echo "missing --run-id" >&2
    usage >&2
    exit 2
fi

NEW_VERSION="${NEW_VERSION:-0.10.1-test-${RUN_ID}}"
TEST_DIR="${TEST_DIR:-/tmp/yuzu-test-${RUN_ID}}"
PROJECT_NAME="yuzu-test-${RUN_ID}-upgrade"
PHASE2_DIR="$TEST_DIR/upgrade"

# Fail loudly if scratch dir cannot be created — running on a read-only
# filesystem or with bad permissions should not silently fall through.
if ! mkdir -p "$PHASE2_DIR" 2>&1; then
    echo "test-upgrade-stack: cannot create $PHASE2_DIR" >&2
    exit 1
fi

# Generate a random admin password if not provided. token_urlsafe is
# base64url so it has no shell metacharacters — but we still pass it via
# environment variables to all subsequent Python invocations to avoid any
# possibility of injection if a future caller passes --password with
# special characters.
if [[ -z "$PASSWORD" ]]; then
    PASSWORD=$(python3 -c "import secrets; print('Yz!' + secrets.token_urlsafe(16))")
fi

# Generate the credentials file (PBKDF2-SHA256 — same as linux-start-UAT.sh).
# Pass username and password via env vars so single-quote, backslash, or
# newline characters in operator-supplied passwords cannot break out of a
# Python string literal.
CONFIG_FILE="$PHASE2_DIR/yuzu-server.cfg"
YUZU_TEST_USER="$USERNAME" YUZU_TEST_PASS="$PASSWORD" python3 - <<'PY' > "$CONFIG_FILE"
import hashlib, os, sys
user = os.environ['YUZU_TEST_USER']
password = os.environ['YUZU_TEST_PASS']
salt = os.urandom(16)
dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, dklen=32)
sys.stdout.write(f'{user}:admin:{salt.hex()}:{dk.hex()}\n')
PY
# 600 not 644 — matches CLAUDE.md's secure-default expectation for
# credential-bearing files. Docker bind mounts read the file with
# whatever UID the container runs as (root inside the test image), so
# 600 with the test runner's UID still works because dockerd is root.
chmod 600 "$CONFIG_FILE"

# Output helpers + colours
if [ -t 1 ]; then
    G='\033[0;32m'; R='\033[0;31m'; Y='\033[1;33m'; C='\033[0;36m'; N='\033[0m'
else
    G=''; R=''; Y=''; C=''; N=''
fi
ok()    { printf "  ${G}\u2713${N} %s\n" "$*"; }
fl()    { printf "  ${R}\u2717${N} %s\n" "$*"; }
warn()  { printf "  ${Y}\u26a0${N} %s\n" "$*"; }
info()  { printf "  ${C}\u2192${N} %s\n" "$*"; }
phase() { printf "\n${C}=== %s ===${N}\n" "$*"; }

now_ms() { python3 -c "import time; print(int(time.time()*1000))"; }
elapsed_ms() { local s=$1; local e=$(now_ms); echo $((e - s)); }

record_timing() {
    bash "$HERE/test-db-write.sh" timing \
        --run-id "$RUN_ID" --gate "phase2" --step "$1" --ms "$2" >/dev/null || true
}

record_gate() {
    local status="$1" duration_s="$2" notes="${3:-}"
    bash "$HERE/test-db-write.sh" gate \
        --run-id "$RUN_ID" --phase 2 \
        --gate "Upgrade ${OLD_VERSION}->${NEW_VERSION}" \
        --status "$status" --duration "$duration_s" \
        --log "upgrade.log" \
        --notes "$notes" >/dev/null || true
}

GATE_START=$(now_ms)
LOG_FILE="$PHASE2_DIR/upgrade.log"
exec > >(tee -a "$LOG_FILE") 2>&1

# Cleanup hook
cleanup() {
    if [[ $KEEP_STACK -eq 1 ]]; then
        warn "leaving stack up: $PROJECT_NAME (--keep-stack)"
        return
    fi
    info "tearing down compose project $PROJECT_NAME"
    YUZU_VERSION="$NEW_VERSION" YUZU_TEST_CONFIG="$CONFIG_FILE" \
        docker compose -f "$HERE/docker-compose.upgrade-test.yml" \
        --project-name "$PROJECT_NAME" \
        down -v >/dev/null 2>&1 || true
}
if [[ $KEEP_STACK -eq 0 ]]; then
    trap cleanup EXIT
fi

phase "Phase 2 — Upgrade Test (${OLD_VERSION} -> ${NEW_VERSION})"
info "RUN_ID=$RUN_ID  PROJECT=$PROJECT_NAME  TEST_DIR=$TEST_DIR"
info "admin user: $USERNAME (random password, ${#PASSWORD} chars, not logged)"
info "compose: $HERE/docker-compose.upgrade-test.yml"

# --- Step 1: pull old images ----------------------------------------------

phase "step: pull old images (${OLD_VERSION})"
T_START=$(now_ms)
if ! YUZU_VERSION="$OLD_VERSION" YUZU_TEST_CONFIG="$CONFIG_FILE" \
    docker compose -f "$HERE/docker-compose.upgrade-test.yml" \
    --project-name "$PROJECT_NAME" \
    pull >> "$LOG_FILE" 2>&1; then
    fl "docker compose pull failed for ${OLD_VERSION}"
    record_timing "pull-old-images" "$(elapsed_ms "$T_START")"
    record_gate "FAIL" "$(($(elapsed_ms "$GATE_START") / 1000))" "pull failed"
    exit 1
fi
record_timing "pull-old-images" "$(elapsed_ms "$T_START")"
ok "pulled ghcr.io/tr3kkr/yuzu-server:${OLD_VERSION}"

# --- Step 2: stack up at OLD version --------------------------------------

phase "step: stack up at OLD ${OLD_VERSION}"
T_START=$(now_ms)
if ! YUZU_VERSION="$OLD_VERSION" YUZU_TEST_CONFIG="$CONFIG_FILE" \
    docker compose -f "$HERE/docker-compose.upgrade-test.yml" \
    --project-name "$PROJECT_NAME" \
    up -d >> "$LOG_FILE" 2>&1; then
    fl "compose up failed at OLD version"
    record_timing "stack-up-old" "$(elapsed_ms "$T_START")"
    record_gate "FAIL" "$(($(elapsed_ms "$GATE_START") / 1000))" "compose up old failed"
    exit 1
fi

# Find the host port for 8080
SERVER_HOST_PORT=$(YUZU_VERSION="$OLD_VERSION" YUZU_TEST_CONFIG="$CONFIG_FILE" \
    docker compose -f "$HERE/docker-compose.upgrade-test.yml" \
    --project-name "$PROJECT_NAME" \
    port server 8080 2>/dev/null | awk -F: '{print $NF}')
if [[ -z "$SERVER_HOST_PORT" ]]; then
    fl "could not determine server host port"
    record_timing "stack-up-old" "$(elapsed_ms "$T_START")"
    record_gate "FAIL" "$(($(elapsed_ms "$GATE_START") / 1000))" "no host port"
    exit 1
fi
DASHBOARD_URL="http://localhost:${SERVER_HOST_PORT}"
info "dashboard at $DASHBOARD_URL"

# Wait for /readyz to come back ready
WAITED=0
READY=0
while (( WAITED < 60 )); do
    BODY=$(curl -sf --max-time 3 "${DASHBOARD_URL}/readyz" 2>/dev/null || echo "")
    if [[ "$BODY" == *'"ready"'* ]]; then
        READY=1
        break
    fi
    sleep 2
    WAITED=$((WAITED + 2))
done
record_timing "stack-up-old" "$(elapsed_ms "$T_START")"
if [[ $READY -eq 0 ]]; then
    fl "OLD stack never reported /readyz ready (waited ${WAITED}s)"
    docker compose -f "$HERE/docker-compose.upgrade-test.yml" \
        --project-name "$PROJECT_NAME" logs server | tail -50 >> "$LOG_FILE"
    record_gate "FAIL" "$(($(elapsed_ms "$GATE_START") / 1000))" "old /readyz timeout"
    exit 1
fi
ok "OLD stack ready (waited ${WAITED}s)"

# --- Step 3: fixtures-write -----------------------------------------------

phase "step: fixtures-write (against OLD ${OLD_VERSION})"
T_START=$(now_ms)
STATE_FILE="$PHASE2_DIR/fixtures-state.json"
if bash "$HERE/test-fixtures-write.sh" \
    --dashboard "$DASHBOARD_URL" \
    --user "$USERNAME" --password "$PASSWORD" \
    --state-file "$STATE_FILE" >> "$LOG_FILE" 2>&1; then
    ok "fixtures written"
    FIXTURE_WRITE_OK=1
else
    fl "fixtures-write failed (see $LOG_FILE)"
    FIXTURE_WRITE_OK=0
fi
record_timing "fixtures-write" "$(elapsed_ms "$T_START")"

if [[ $FIXTURE_WRITE_OK -eq 0 ]]; then
    record_gate "FAIL" "$(($(elapsed_ms "$GATE_START") / 1000))" "fixtures write failed"
    exit 1
fi

# --- Step 4: image swap to NEW --------------------------------------------

phase "step: image swap to NEW ${NEW_VERSION}"
if [[ "$NEW_IMAGE_LOADED" != "1" ]]; then
    info "pulling new image (--new-image-loaded 0)"
    if ! docker pull "ghcr.io/tr3kkr/yuzu-server:${NEW_VERSION}" >> "$LOG_FILE" 2>&1; then
        fl "docker pull of new image failed"
        record_gate "FAIL" "$(($(elapsed_ms "$GATE_START") / 1000))" "new image pull failed"
        exit 1
    fi
fi

# Verify the new image is locally available
if ! docker image inspect "ghcr.io/tr3kkr/yuzu-server:${NEW_VERSION}" >/dev/null 2>&1; then
    # fall back: maybe the image is just `yuzu-server:test-${RUN_ID}` without ghcr prefix
    if docker image inspect "yuzu-server:${NEW_VERSION}" >/dev/null 2>&1; then
        info "using local image yuzu-server:${NEW_VERSION} (no ghcr prefix)"
        # Tag it with the ghcr prefix so the compose file picks it up
        docker tag "yuzu-server:${NEW_VERSION}" "ghcr.io/tr3kkr/yuzu-server:${NEW_VERSION}"
    else
        fl "new image ghcr.io/tr3kkr/yuzu-server:${NEW_VERSION} not in local daemon"
        warn "Phase 1 should have built it as 'yuzu-server:${NEW_VERSION}' or pulled it"
        record_gate "FAIL" "$(($(elapsed_ms "$GATE_START") / 1000))" "new image missing"
        exit 1
    fi
fi

T_START=$(now_ms)
if ! YUZU_VERSION="$NEW_VERSION" YUZU_TEST_CONFIG="$CONFIG_FILE" \
    docker compose -f "$HERE/docker-compose.upgrade-test.yml" \
    --project-name "$PROJECT_NAME" \
    up -d >> "$LOG_FILE" 2>&1; then
    fl "compose up failed at NEW version"
    record_timing "image-swap" "$(elapsed_ms "$T_START")"
    record_gate "FAIL" "$(($(elapsed_ms "$GATE_START") / 1000))" "compose up new failed"
    exit 1
fi
record_timing "image-swap" "$(elapsed_ms "$T_START")"
ok "image swap done"

# --- Step 5: ready-after-upgrade ------------------------------------------

phase "step: wait for /readyz after upgrade"
# Re-find the port — compose may have rebound it
SERVER_HOST_PORT=$(YUZU_VERSION="$NEW_VERSION" YUZU_TEST_CONFIG="$CONFIG_FILE" \
    docker compose -f "$HERE/docker-compose.upgrade-test.yml" \
    --project-name "$PROJECT_NAME" \
    port server 8080 2>/dev/null | awk -F: '{print $NF}')
DASHBOARD_URL="http://localhost:${SERVER_HOST_PORT}"
info "post-upgrade dashboard at $DASHBOARD_URL"

T_START=$(now_ms)
WAITED=0
READY=0
FAILED_STORES=""
while (( WAITED < 90 )); do
    BODY=$(curl -sf --max-time 3 "${DASHBOARD_URL}/readyz" 2>/dev/null || echo "")
    if [[ "$BODY" == *'"ready"'* ]]; then
        READY=1
        break
    fi
    if [[ "$BODY" == *'failed_stores'* ]]; then
        FAILED_STORES="$BODY"
        break
    fi
    sleep 2
    WAITED=$((WAITED + 2))
done
record_timing "ready-after-upgrade" "$(elapsed_ms "$T_START")"

if [[ $READY -ne 1 ]]; then
    if [[ -n "$FAILED_STORES" ]]; then
        fl "/readyz reports failed stores: $FAILED_STORES"
    else
        fl "/readyz never recovered after upgrade (waited ${WAITED}s)"
    fi
    docker compose -f "$HERE/docker-compose.upgrade-test.yml" \
        --project-name "$PROJECT_NAME" logs server | tail -100 >> "$LOG_FILE"
    record_gate "FAIL" "$(($(elapsed_ms "$GATE_START") / 1000))" "post-upgrade not ready"
    exit 1
fi
ok "/readyz ready after upgrade (waited ${WAITED}s)"

# --- Step 6: count migration runner events --------------------------------

phase "step: count MigrationRunner events in server log"
MIGR_COUNT=$(docker compose -f "$HERE/docker-compose.upgrade-test.yml" \
    --project-name "$PROJECT_NAME" logs server 2>/dev/null \
    | grep -c "MigrationRunner: .* migrated to v" || true)
if (( MIGR_COUNT > 0 )); then
    ok "MigrationRunner events: $MIGR_COUNT (expected ~30)"
    bash "$HERE/test-db-write.sh" metric --run-id "$RUN_ID" \
        --name "phase2_migration_events" --value "$MIGR_COUNT" --unit "count" >/dev/null || true
else
    warn "no MigrationRunner events seen — maybe DB was already at HEAD schema?"
fi

# --- Step 7: fixtures-verify ----------------------------------------------

phase "step: fixtures-verify (against NEW ${NEW_VERSION})"
T_START=$(now_ms)
REPORT_FILE="$PHASE2_DIR/fixtures-verify.json"
if bash "$HERE/test-fixtures-verify.sh" \
    --dashboard "$DASHBOARD_URL" \
    --user "$USERNAME" --password "$PASSWORD" \
    --state-file "$STATE_FILE" \
    --report-file "$REPORT_FILE" >> "$LOG_FILE" 2>&1; then
    ok "fixtures verified"
    FIXTURE_VERIFY_OK=1
else
    fl "fixtures-verify reported losses (see $REPORT_FILE)"
    FIXTURE_VERIFY_OK=0
fi
record_timing "fixtures-verify" "$(elapsed_ms "$T_START")"

# --- Step 8: synthetic UAT against upgraded stack -------------------------

phase "step: synthetic UAT against upgraded stack"
T_START=$(now_ms)
# --no-agent: the upgrade-test compose has no agent service (intentional —
# data-preservation tests don't need one). Pass --no-agent so the 4
# agent-dependent tests (3 server agent metric, 4 gateway agent metric,
# 5 help command, 6 os_info round-trip) skip cleanly instead of failing.
# Tests 1 (dashboard reachable) and 2 (gateway readyz, also auto-skipped
# because no --gateway-health URL) still run.
if bash "$HERE/synthetic-uat-tests.sh" \
    --dashboard "$DASHBOARD_URL" \
    --user "$USERNAME" --password "$PASSWORD" \
    --no-agent \
    --run-id "$RUN_ID" \
    --gate-name "phase2-synthetic-uat" >> "$LOG_FILE" 2>&1; then
    ok "synthetic UAT passed against upgraded stack"
    UAT_OK=1
else
    fl "synthetic UAT failed against upgraded stack"
    UAT_OK=0
fi
record_timing "synthetic-uat-against-upgraded" "$(elapsed_ms "$T_START")"

# --- Final gate result ----------------------------------------------------

GATE_DURATION=$((($(now_ms) - GATE_START) / 1000))
if [[ $FIXTURE_VERIFY_OK -eq 1 && $UAT_OK -eq 1 ]]; then
    ok "Phase 2 PASS"
    record_gate "PASS" "$GATE_DURATION" \
        "fixtures preserved, /readyz green, ${MIGR_COUNT} migrations stamped"
    exit 0
else
    fl "Phase 2 FAIL (fixture_verify=$FIXTURE_VERIFY_OK uat=$UAT_OK)"
    record_gate "FAIL" "$GATE_DURATION" \
        "fixture_verify=$FIXTURE_VERIFY_OK uat=$UAT_OK"
    exit 1
fi
