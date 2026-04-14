#!/usr/bin/env bash
# test-fixtures-verify.sh — Verify the fixture set written by
# test-fixtures-write.sh is still present after an upgrade.
#
# Reads the state file produced by the writer and re-checks every fixture
# against the (now-upgraded) server. Each check produces a per-fixture
# {name, status, expected, actual} entry in fixtures-verify.json.
#
# Exit codes:
#   0  every fixture survived
#   1  one or more fixtures missing (data loss during upgrade)
#   2  bad arguments
#
# Usage:
#   bash scripts/test/test-fixtures-verify.sh \
#       --dashboard http://localhost:8080 \
#       --user admin --password 'YuzuUatAdmin1!' \
#       --state-file /tmp/yuzu-test-${RUN_ID}/fixtures-state.json \
#       --report-file /tmp/yuzu-test-${RUN_ID}/fixtures-verify.json

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"

DASHBOARD_URL=""
USERNAME="admin"
PASSWORD=""
STATE_FILE=""
REPORT_FILE=""
TIMEOUT_S=15

usage() {
    cat <<EOF
usage: $0 --dashboard URL --password PASS --state-file PATH [--report-file PATH]

Required:
  --dashboard URL
  --password PASS
  --state-file PATH        the file written by test-fixtures-write.sh

Optional:
  --user NAME              admin user (default: admin)
  --report-file PATH       per-fixture verify status (default: alongside state file)
  --timeout SECONDS        per-call timeout (default: 15)
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dashboard)   DASHBOARD_URL="$2"; shift 2 ;;
        --user)        USERNAME="$2"; shift 2 ;;
        --password)    PASSWORD="$2"; shift 2 ;;
        --state-file)  STATE_FILE="$2"; shift 2 ;;
        --report-file) REPORT_FILE="$2"; shift 2 ;;
        --timeout)     TIMEOUT_S="$2"; shift 2 ;;
        -h|--help)     usage; exit 0 ;;
        *)             echo "unknown arg: $1" >&2; usage >&2; exit 2 ;;
    esac
done

if [[ -z "$DASHBOARD_URL" || -z "$PASSWORD" || -z "$STATE_FILE" ]]; then
    usage >&2
    exit 2
fi
if [[ ! -f "$STATE_FILE" ]]; then
    echo "state file $STATE_FILE not found — did test-fixtures-write.sh run?" >&2
    exit 2
fi

if [[ -z "$REPORT_FILE" ]]; then
    REPORT_FILE="$(dirname "$STATE_FILE")/fixtures-verify.json"
fi

if [ -t 1 ]; then
    G='\033[0;32m'; R='\033[0;31m'; Y='\033[1;33m'; C='\033[0;36m'; N='\033[0m'
else
    G=''; R=''; Y=''; C=''; N=''
fi
ok()   { printf "  ${G}\u2713${N} %s\n" "$*"; PRESERVED=$((PRESERVED + 1)); }
fl()   { printf "  ${R}\u2717${N} %s\n" "$*"; LOST=$((LOST + 1)); }
warn() { printf "  ${Y}\u26a0${N} %s\n" "$*"; SKIPPED=$((SKIPPED + 1)); }
info() { printf "  ${C}\u2192${N} %s\n" "$*"; }

PRESERVED=0
LOST=0
SKIPPED=0
COOKIES="$(mktemp -t yuzu-test-verify.XXXXXX)"
trap 'rm -f "$COOKIES"' EXIT

# Parse state file. Use env var passing so a state-file path containing
# quotes or special chars can't inject into the Python source. The `key`
# argument is a literal bash positional arg ($1) at the call site — the
# callers pass hardcoded keys, but we still validate via env var for
# consistency with the heredoc pattern elsewhere.
read_state() {
    YUZU_VFY_STATE="$STATE_FILE" YUZU_VFY_KEY="$1" python3 - <<'PY'
import json, os
with open(os.environ['YUZU_VFY_STATE']) as f:
    s = json.load(f)
print(s.get(os.environ['YUZU_VFY_KEY'], ''))
PY
}

# Initialize per-fixture report (will be rewritten with results)
declare -A RESULTS

set_result() {
    RESULTS["$1"]="$2"
}

# --- /readyz wait ---------------------------------------------------------

info "waiting for $DASHBOARD_URL/readyz to be ready (post-upgrade)"
WAITED=0
READYZ=""
while (( WAITED < TIMEOUT_S * 2 )); do
    READYZ=$(curl -sf --max-time 3 "$DASHBOARD_URL/readyz" 2>/dev/null || echo "")
    if [[ "$READYZ" == *'"ready"'* ]]; then
        ok "/readyz ready (no failed_stores)"
        set_result "readyz" "preserved"
        break
    fi
    if [[ "$READYZ" == *'failed_stores'* ]]; then
        fl "/readyz reports failed stores: $READYZ"
        set_result "readyz" "FAILED_STORES: $READYZ"
        break
    fi
    sleep 1
    WAITED=$((WAITED + 1))
done
if [[ "$READYZ" != *'"ready"'* && "$READYZ" != *'failed_stores'* ]]; then
    fl "/readyz never responded ready (timed out at ${WAITED}s)"
    set_result "readyz" "timeout"
fi

# --- login still works ----------------------------------------------------

info "verifying login still works (proves user persistence)"
LOGIN_OK_BEFORE=$(read_state login_ok)
LOGIN_HTTP=$(curl -s -o /dev/null -w "%{http_code}" -c "$COOKIES" \
    --max-time "$TIMEOUT_S" \
    "$DASHBOARD_URL/login" \
    -d "username=${USERNAME}&password=${PASSWORD}" 2>/dev/null || echo "000")
if [[ "$LOGIN_HTTP" =~ ^[23] ]]; then
    ok "login HTTP $LOGIN_HTTP"
    set_result "user_admin" "preserved"
else
    fl "login HTTP $LOGIN_HTTP — admin user lost"
    set_result "user_admin" "lost (HTTP $LOGIN_HTTP)"
fi

# --- audit log preserved + grew ------------------------------------------

info "verifying audit log preserved"
AUDIT_BASELINE=$(read_state audit_baseline)
AUDIT_BODY=$(curl -s -b "$COOKIES" --max-time "$TIMEOUT_S" \
    "$DASHBOARD_URL/api/v1/audit?limit=1000" 2>/dev/null || echo "")
if [[ -n "$AUDIT_BODY" ]]; then
    AUDIT_NOW=$(echo "$AUDIT_BODY" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    if isinstance(d, list):
        print(len(d))
    elif isinstance(d, dict):
        print(len(d.get('events', d.get('entries', d.get('data', [])))))
    else:
        print(0)
except: print(0)" 2>/dev/null || echo "0")
    if (( AUDIT_NOW >= AUDIT_BASELINE )); then
        ok "audit log $AUDIT_BASELINE → $AUDIT_NOW entries (preserved + grew)"
        set_result "audit_log" "preserved ($AUDIT_BASELINE → $AUDIT_NOW)"
    else
        fl "audit log shrank: $AUDIT_BASELINE → $AUDIT_NOW (data loss)"
        set_result "audit_log" "shrank ($AUDIT_BASELINE → $AUDIT_NOW)"
    fi
else
    warn "audit log endpoint did not respond — cannot verify"
    set_result "audit_log" "skipped"
fi

# --- enrollment tokens preserved ------------------------------------------

info "verifying enrollment tokens preserved"
ENROLL_PRESENT_BEFORE=$(read_state enrollment_token_present)
if [[ "$ENROLL_PRESENT_BEFORE" == "True" ]]; then
    # The public list endpoint is the HTMX fragment at
    # /fragments/settings/tokens — there is no REST v1 list for enrollment
    # tokens. Fragment body is an HTML <table>; a row per token is
    # "<tr><td><code>ID</code>...". An empty table renders a colspan row
    # with the "No tokens created" placeholder. Look for the <code> cell
    # — it only appears when at least one real token row exists.
    ENROLL_LIST=$(curl -s -b "$COOKIES" --max-time "$TIMEOUT_S" \
        "$DASHBOARD_URL/fragments/settings/tokens" 2>/dev/null || echo "")
    ENROLL_COUNT=$(echo "$ENROLL_LIST" | grep -oE '<td><code>[a-f0-9]+</code></td>' | wc -l)
    if (( ENROLL_COUNT >= 1 )); then
        ok "enrollment tokens preserved ($ENROLL_COUNT present)"
        set_result "enrollment_tokens" "preserved ($ENROLL_COUNT)"
    else
        fl "enrollment tokens lost (had >= 1, now 0)"
        set_result "enrollment_tokens" "lost"
    fi
else
    warn "no enrollment token was written — skipping verify"
    set_result "enrollment_tokens" "skipped"
fi

# --- API tokens preserved -------------------------------------------------

info "verifying API tokens preserved"
API_PRESENT_BEFORE=$(read_state api_token_present)
if [[ "$API_PRESENT_BEFORE" == "True" ]]; then
    # API tokens ARE exposed via REST v1 — use that instead of the
    # HTMX fragment. The v1 envelope is {"data":[...], "meta":{}}.
    API_LIST=$(curl -s -b "$COOKIES" --max-time "$TIMEOUT_S" \
        "$DASHBOARD_URL/api/v1/tokens" 2>/dev/null || echo "")
    if [[ -n "$API_LIST" && "$API_LIST" != *"\"error\""* ]]; then
        # Count tokens in data[] — a successful upgrade keeps at least 1.
        API_COUNT=$(echo "$API_LIST" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print(len(d.get('data', [])))
except: print(0)" 2>/dev/null || echo "0")
        if (( API_COUNT >= 1 )); then
            ok "API tokens preserved ($API_COUNT present)"
            set_result "api_tokens" "preserved ($API_COUNT)"
        else
            fl "API tokens lost (had >= 1, now 0)"
            set_result "api_tokens" "lost"
        fi
    else
        fl "API tokens endpoint failed or returned error: ${API_LIST:0:200}"
        set_result "api_tokens" "lost or endpoint broken"
    fi
else
    warn "no API token was written — skipping verify"
    set_result "api_tokens" "skipped"
fi

# --- guarantee inversion check (highest-stakes) ---------------------------
# If the writer recorded fixtures-written but verify managed to preserve
# zero of them, that's a guarantee inversion: /test reported PASS on the
# headline data-preservation invariant but actually verified nothing. This
# is exactly the failure mode UP-26 / SLO-VIOLATION-1 from the governance
# run. We hard-fail it here so the upgrade test cannot silently pass.
WROTE_COUNT=$(read_state wrote_count)
WROTE_COUNT=${WROTE_COUNT:-0}
if [[ $WROTE_COUNT -gt 0 && $PRESERVED -eq 0 ]]; then
    fl "guarantee inversion: writer recorded $WROTE_COUNT fixtures, verifier preserved 0 — every check skipped or failed"
    set_result "guarantee_inversion" "writer wrote $WROTE_COUNT, verify preserved 0"
fi

# --- write report ---------------------------------------------------------

mkdir -p "$(dirname "$REPORT_FILE")"
{
    echo "{"
    echo "  \"verified_at\": $(date +%s),"
    echo "  \"wrote_count\": $WROTE_COUNT,"
    echo "  \"preserved_count\": $PRESERVED,"
    echo "  \"lost_count\": $LOST,"
    echo "  \"skipped_count\": $SKIPPED,"
    echo "  \"fixtures\": {"
    first=1
    for k in "${!RESULTS[@]}"; do
        if [[ $first -eq 0 ]]; then echo ","; fi
        printf '    "%s": "%s"' "$k" "${RESULTS[$k]//\"/\\\"}"
        first=0
    done
    echo ""
    echo "  }"
    echo "}"
} > "$REPORT_FILE"

echo ""
TOTAL=$((PRESERVED + LOST + SKIPPED))
if [[ $LOST -eq 0 && ! ( $WROTE_COUNT -gt 0 && $PRESERVED -eq 0 ) ]]; then
    echo -e "${G}fixtures verify: $PRESERVED/$TOTAL preserved${N} ($SKIPPED skipped)"
    exit 0
else
    echo -e "${R}fixtures verify: $LOST LOST, $PRESERVED preserved, $SKIPPED skipped — DATA LOSS DETECTED${N}"
    if [[ $WROTE_COUNT -gt 0 && $PRESERVED -eq 0 ]]; then
        echo -e "${R}GUARANTEE INVERSION: writer recorded $WROTE_COUNT fixtures but zero were verified.${N}"
        echo -e "${R}This may indicate (a) silent data loss, (b) endpoint moved to a different path,${N}"
        echo -e "${R}or (c) the fixture API surface changed. Investigate the gate log immediately.${N}"
    fi
    exit 1
fi
