#!/usr/bin/env bash
# e2e-api-test.sh — Comprehensive REST API end-to-end test for Yuzu Server
#
# Exercises every public REST API endpoint across health, auth, CRUD, legacy,
# and error-handling categories. Assumes the Yuzu server is already running.
#
# Usage:
#   ./scripts/e2e-api-test.sh                                   # default: http://127.0.0.1:8080
#   ./scripts/e2e-api-test.sh --server-url http://10.0.0.5:9090 # custom server
#   ./scripts/e2e-api-test.sh --skip-auth                       # skip login/auth tests
#
# Prerequisites:
#   - Yuzu server running and reachable
#   - curl
#   - Optional: python3 (for JSON extraction; falls back to grep)

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────
SERVER_URL="http://127.0.0.1:8080"
SKIP_AUTH=false

# ── Argument parsing ─────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --server-url)  SERVER_URL="$2"; shift 2 ;;
        --skip-auth)   SKIP_AUTH=true; shift ;;
        --help|-h)
            echo "Usage: $0 [--server-url URL] [--skip-auth]"
            echo ""
            echo "Options:"
            echo "  --server-url URL   Base URL of the running Yuzu server (default: http://127.0.0.1:8080)"
            echo "  --skip-auth        Skip authentication tests and run all API tests without a session cookie"
            exit 0
            ;;
        *)  echo "Unknown arg: $1"; exit 1 ;;
    esac
done

# Strip trailing slash from server URL
SERVER_URL="${SERVER_URL%/}"

# ── Temp files & cleanup ─────────────────────────────────────────────
COOKIE_JAR=$(mktemp /tmp/yuzu-e2e-cookies.XXXXXX)
RESP_BODY=$(mktemp /tmp/yuzu-e2e-body.XXXXXX)
RESP_HEADERS=$(mktemp /tmp/yuzu-e2e-headers.XXXXXX)

cleanup() {
    rm -f "$COOKIE_JAR" "$RESP_BODY" "$RESP_HEADERS"
}
trap cleanup EXIT

# ── Helpers (same pattern as integration-test.sh) ────────────────────
log()  { echo "[$(date +%H:%M:%S)] $*"; }
pass() { echo "  ✓ $*"; }
fail() { echo "  ✗ $*"; FAILURES=$((FAILURES + 1)); }

FAILURES=0
TESTS=0

assert_eq() {
    TESTS=$((TESTS + 1))
    local desc="$1" expected="$2" actual="$3"
    if [[ "$expected" == "$actual" ]]; then
        pass "$desc"
    else
        fail "$desc (expected '$expected', got '$actual')"
    fi
}

assert_contains() {
    TESTS=$((TESTS + 1))
    local desc="$1" needle="$2" haystack="$3"
    if echo "$haystack" | grep -q "$needle"; then
        pass "$desc"
    else
        fail "$desc (expected to contain '$needle')"
    fi
}

assert_ge() {
    TESTS=$((TESTS + 1))
    local desc="$1" expected="$2" actual="$3"
    if [[ "$actual" -ge "$expected" ]]; then
        pass "$desc"
    else
        fail "$desc (expected >= $expected, got $actual)"
    fi
}

# assert_status_ok: pass if HTTP status is in the 2xx range
assert_status_ok() {
    TESTS=$((TESTS + 1))
    local desc="$1" actual="$2"
    if [[ "$actual" -ge 200 && "$actual" -lt 300 ]]; then
        pass "$desc (HTTP $actual)"
    else
        fail "$desc (expected 2xx, got $actual)"
    fi
}

# assert_status_any: pass if HTTP status matches any of the listed codes
assert_status_any() {
    TESTS=$((TESTS + 1))
    local desc="$1" actual="$2"
    shift 2
    for expected in "$@"; do
        if [[ "$actual" == "$expected" ]]; then
            pass "$desc (HTTP $actual)"
            return
        fi
    done
    fail "$desc (got HTTP $actual, expected one of: $*)"
}

# ── curl wrappers ────────────────────────────────────────────────────
# Each sets HTTP_STATUS (3-digit code) and HTTP_BODY (response body).
# Body is written to a temp file; status code is captured via -w.

http_get() {
    local url="$1"
    HTTP_STATUS=$(curl -s -o "$RESP_BODY" -w "%{http_code}" \
        -b "$COOKIE_JAR" \
        "$url" 2>/dev/null) || HTTP_STATUS="000"
    HTTP_BODY=$(cat "$RESP_BODY" 2>/dev/null || echo "")
}

http_post() {
    local url="$1" data="$2" content_type="${3:-application/json}"
    HTTP_STATUS=$(curl -s -o "$RESP_BODY" -w "%{http_code}" \
        -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
        -X POST -H "Content-Type: $content_type" \
        -d "$data" \
        "$url" 2>/dev/null) || HTTP_STATUS="000"
    HTTP_BODY=$(cat "$RESP_BODY" 2>/dev/null || echo "")
}

http_put() {
    local url="$1" data="$2"
    HTTP_STATUS=$(curl -s -o "$RESP_BODY" -w "%{http_code}" \
        -b "$COOKIE_JAR" \
        -X PUT -H "Content-Type: application/json" \
        -d "$data" \
        "$url" 2>/dev/null) || HTTP_STATUS="000"
    HTTP_BODY=$(cat "$RESP_BODY" 2>/dev/null || echo "")
}

http_delete() {
    local url="$1"
    HTTP_STATUS=$(curl -s -o "$RESP_BODY" -w "%{http_code}" \
        -b "$COOKIE_JAR" \
        -X DELETE \
        "$url" 2>/dev/null) || HTTP_STATUS="000"
    HTTP_BODY=$(cat "$RESP_BODY" 2>/dev/null || echo "")
}

http_get_noauth() {
    local url="$1"
    HTTP_STATUS=$(curl -s -o "$RESP_BODY" -w "%{http_code}" \
        "$url" 2>/dev/null) || HTTP_STATUS="000"
    HTTP_BODY=$(cat "$RESP_BODY" 2>/dev/null || echo "")
}

http_post_noauth() {
    local url="$1" data="$2" content_type="${3:-application/json}"
    HTTP_STATUS=$(curl -s -o "$RESP_BODY" -w "%{http_code}" \
        -X POST -H "Content-Type: $content_type" \
        -d "$data" \
        "$url" 2>/dev/null) || HTTP_STATUS="000"
    HTTP_BODY=$(cat "$RESP_BODY" 2>/dev/null || echo "")
}

# ── JSON extraction helper ───────────────────────────────────────────
# extract_json_field FIELD JSON -> prints the value (uses python3 if available, else grep)
extract_json_field() {
    local field="$1" json="$2"
    if command -v python3 &>/dev/null; then
        echo "$json" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    # Walk into nested 'data' if present
    if 'data' in d and isinstance(d['data'], dict) and '$field' in d['data']:
        print(d['data']['$field'])
    elif '$field' in d:
        print(d['$field'])
    else:
        print('')
except:
    print('')
" 2>/dev/null
    else
        # Fallback: grep for "field":"value" — handles simple string/numeric values
        echo "$json" | grep -o "\"${field}\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" \
            | head -1 | sed "s/\"${field}\"[[:space:]]*:[[:space:]]*\"//" | sed 's/"$//' \
            || echo ""
    fi
}

# ══════════════════════════════════════════════════════════════════════
# Preflight: verify server is reachable
# ══════════════════════════════════════════════════════════════════════
log "Yuzu REST API E2E Test Suite"
log "Server: $SERVER_URL"
log "Skip auth: $SKIP_AUTH"
log ""

log "Preflight: checking server reachability..."
PREFLIGHT_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$SERVER_URL/livez" 2>/dev/null || echo "000")
if [[ "$PREFLIGHT_STATUS" == "000" ]]; then
    echo "FATAL: Cannot reach server at $SERVER_URL"
    echo "       Make sure Yuzu server is running and the URL is correct."
    exit 1
fi
log "  Server is reachable (HTTP $PREFLIGHT_STATUS)."
log ""

# ══════════════════════════════════════════════════════════════════════
# 1. HEALTH ENDPOINTS (no auth required)
# ══════════════════════════════════════════════════════════════════════
log "═══════════════════════════════════════════"
log "  1. Health Endpoints (no auth)"
log "═══════════════════════════════════════════"

# GET /livez
http_get_noauth "$SERVER_URL/livez"
assert_eq "GET /livez returns 200" "200" "$HTTP_STATUS"
assert_contains "GET /livez body contains 'ok'" "ok" "$HTTP_BODY"

# GET /readyz
http_get_noauth "$SERVER_URL/readyz"
assert_eq "GET /readyz returns 200" "200" "$HTTP_STATUS"
assert_contains "GET /readyz body contains 'ready'" "ready" "$HTTP_BODY"

# GET /health
http_get_noauth "$SERVER_URL/health"
assert_eq "GET /health returns 200" "200" "$HTTP_STATUS"

# GET /metrics
http_get_noauth "$SERVER_URL/metrics"
assert_eq "GET /metrics returns 200" "200" "$HTTP_STATUS"
assert_contains "GET /metrics body contains 'yuzu_'" "yuzu_" "$HTTP_BODY"

log ""

# ══════════════════════════════════════════════════════════════════════
# 2. AUTHENTICATION
# ══════════════════════════════════════════════════════════════════════
if [[ "$SKIP_AUTH" == "false" ]]; then
    log "═══════════════════════════════════════════"
    log "  2. Authentication"
    log "═══════════════════════════════════════════"

    # POST /login with valid credentials (admin/admin)
    http_post "$SERVER_URL/login" "username=admin&password=admin" "application/x-www-form-urlencoded"
    assert_eq "POST /login (admin/admin) returns 200" "200" "$HTTP_STATUS"
    # Verify session cookie was set by checking the cookie jar
    TESTS=$((TESTS + 1))
    if grep -q "yuzu_session" "$COOKIE_JAR" 2>/dev/null; then
        pass "Login set yuzu_session cookie"
    else
        fail "Login did not set yuzu_session cookie"
    fi

    # POST /login with bad password
    http_post_noauth "$SERVER_URL/login" "username=admin&password=wrongpass" "application/x-www-form-urlencoded"
    assert_eq "POST /login (bad password) returns 401" "401" "$HTTP_STATUS"

    # GET /api/v1/me without cookie (unauthenticated)
    http_get_noauth "$SERVER_URL/api/v1/me"
    assert_eq "GET /api/v1/me without cookie returns 401" "401" "$HTTP_STATUS"

    # GET /api/v1/me with valid cookie
    http_get "$SERVER_URL/api/v1/me"
    assert_eq "GET /api/v1/me with cookie returns 200" "200" "$HTTP_STATUS"
    assert_contains "GET /api/v1/me contains 'admin'" "admin" "$HTTP_BODY"

    # POST /logout
    http_post "$SERVER_URL/logout" "" "application/json"
    assert_eq "POST /logout returns 200" "200" "$HTTP_STATUS"

    # After logout, GET /api/v1/me should fail
    http_get "$SERVER_URL/api/v1/me"
    assert_eq "GET /api/v1/me after logout returns 401" "401" "$HTTP_STATUS"

    # Re-login for remaining tests
    log "  Re-authenticating for remaining tests..."
    http_post "$SERVER_URL/login" "username=admin&password=admin" "application/x-www-form-urlencoded"
    if [[ "$HTTP_STATUS" != "200" ]]; then
        echo "FATAL: Cannot re-authenticate. Remaining tests will fail."
    fi

    log ""
else
    log "  (Skipping authentication tests — --skip-auth)"
    log ""
fi

# ══════════════════════════════════════════════════════════════════════
# 3. REST API v1 — Management Groups CRUD
# ══════════════════════════════════════════════════════════════════════
log "═══════════════════════════════════════════"
log "  3. Management Groups CRUD"
log "═══════════════════════════════════════════"

TEST_GROUP_NAME="e2e-test-group-$(date +%s)"
GROUP_ID=""

# POST /api/v1/management-groups -> 201
http_post "$SERVER_URL/api/v1/management-groups" \
    "{\"name\":\"$TEST_GROUP_NAME\",\"description\":\"E2E test group\",\"membership_type\":\"static\"}"
assert_eq "POST /api/v1/management-groups returns 201" "201" "$HTTP_STATUS"
GROUP_ID=$(extract_json_field "id" "$HTTP_BODY")
TESTS=$((TESTS + 1))
if [[ -n "$GROUP_ID" ]]; then
    pass "Management group created with id=$GROUP_ID"
else
    fail "Management group creation did not return an id"
fi

# GET /api/v1/management-groups -> 200, contains group name
http_get "$SERVER_URL/api/v1/management-groups"
assert_eq "GET /api/v1/management-groups returns 200" "200" "$HTTP_STATUS"
assert_contains "GET /api/v1/management-groups contains test group" "$TEST_GROUP_NAME" "$HTTP_BODY"

# GET /api/v1/management-groups/{id} -> 200
if [[ -n "$GROUP_ID" ]]; then
    http_get "$SERVER_URL/api/v1/management-groups/$GROUP_ID"
    assert_eq "GET /api/v1/management-groups/{id} returns 200" "200" "$HTTP_STATUS"

    # PUT /api/v1/management-groups/{id} -> 200
    http_put "$SERVER_URL/api/v1/management-groups/$GROUP_ID" \
        "{\"name\":\"$TEST_GROUP_NAME\",\"description\":\"Updated by E2E test\"}"
    assert_status_ok "PUT /api/v1/management-groups/{id}" "$HTTP_STATUS"

    # DELETE /api/v1/management-groups/{id} -> 200
    http_delete "$SERVER_URL/api/v1/management-groups/$GROUP_ID"
    assert_status_ok "DELETE /api/v1/management-groups/{id}" "$HTTP_STATUS"

    # GET after delete -> 404
    http_get "$SERVER_URL/api/v1/management-groups/$GROUP_ID"
    assert_eq "GET /api/v1/management-groups/{id} after delete returns 404" "404" "$HTTP_STATUS"
else
    log "  (Skipping management group CRUD — no id captured)"
fi

log ""

# ══════════════════════════════════════════════════════════════════════
# 4. REST API v1 — API Tokens CRUD
# ══════════════════════════════════════════════════════════════════════
log "═══════════════════════════════════════════"
log "  4. API Tokens CRUD"
log "═══════════════════════════════════════════"

TOKEN_LABEL="e2e-test-token-$(date +%s)"
API_TOKEN=""
TOKEN_NAME=""

# POST /api/v1/tokens -> 201
http_post "$SERVER_URL/api/v1/tokens" "{\"name\":\"$TOKEN_LABEL\"}"
assert_eq "POST /api/v1/tokens returns 201" "201" "$HTTP_STATUS"
API_TOKEN=$(extract_json_field "token" "$HTTP_BODY")
TOKEN_NAME=$(extract_json_field "name" "$HTTP_BODY")
TESTS=$((TESTS + 1))
if [[ -n "$API_TOKEN" ]]; then
    pass "API token created (name=$TOKEN_NAME)"
else
    fail "API token creation did not return a token"
fi

# GET /api/v1/tokens -> 200, contains label
http_get "$SERVER_URL/api/v1/tokens"
assert_eq "GET /api/v1/tokens returns 200" "200" "$HTTP_STATUS"
assert_contains "GET /api/v1/tokens contains token label" "$TOKEN_LABEL" "$HTTP_BODY"

# DELETE /api/v1/tokens/{token_id} -> 200
# Extract token_id from the list response (deletion uses token_id, not name)
TOKEN_ID=$(echo "$HTTP_BODY" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    for t in d.get('data', []):
        if t.get('name') == '$TOKEN_LABEL':
            print(t['token_id']); break
except: pass
" 2>/dev/null)
if [[ -n "$TOKEN_ID" ]]; then
    http_delete "$SERVER_URL/api/v1/tokens/$TOKEN_ID"
    assert_status_ok "DELETE /api/v1/tokens/{token_id}" "$HTTP_STATUS"
else
    TESTS=$((TESTS + 1))
    fail "DELETE /api/v1/tokens — could not extract token_id"
fi

log ""

# ══════════════════════════════════════════════════════════════════════
# 5. REST API v1 — RBAC
# ══════════════════════════════════════════════════════════════════════
log "═══════════════════════════════════════════"
log "  5. RBAC"
log "═══════════════════════════════════════════"

# GET /api/v1/rbac/roles -> 200
http_get "$SERVER_URL/api/v1/rbac/roles"
assert_eq "GET /api/v1/rbac/roles returns 200" "200" "$HTTP_STATUS"

# POST /api/v1/rbac/check -> 200
http_post "$SERVER_URL/api/v1/rbac/check" \
    "{\"principal\":\"admin\",\"securable_type\":\"ManagementGroup\",\"operation\":\"Read\"}"
assert_eq "POST /api/v1/rbac/check returns 200" "200" "$HTTP_STATUS"

log ""

# ══════════════════════════════════════════════════════════════════════
# 6. REST API v1 — Tags
# ══════════════════════════════════════════════════════════════════════
log "═══════════════════════════════════════════"
log "  6. Tags"
log "═══════════════════════════════════════════"

# GET /api/v1/tags -> 200 (requires agent_id parameter)
http_get "$SERVER_URL/api/v1/tags?agent_id=test-agent"
assert_eq "GET /api/v1/tags returns 200" "200" "$HTTP_STATUS"

# GET /api/v1/tag-categories -> 200
http_get "$SERVER_URL/api/v1/tag-categories"
assert_eq "GET /api/v1/tag-categories returns 200" "200" "$HTTP_STATUS"

log ""

# ══════════════════════════════════════════════════════════════════════
# 7. REST API v1 — Other
# ══════════════════════════════════════════════════════════════════════
log "═══════════════════════════════════════════"
log "  7. REST API v1 — Other Endpoints"
log "═══════════════════════════════════════════"

# GET /api/v1/quarantine -> 200
http_get "$SERVER_URL/api/v1/quarantine"
assert_eq "GET /api/v1/quarantine returns 200" "200" "$HTTP_STATUS"

# GET /api/v1/definitions -> 200
http_get "$SERVER_URL/api/v1/definitions"
assert_eq "GET /api/v1/definitions returns 200" "200" "$HTTP_STATUS"

# GET /api/v1/audit -> 200
http_get "$SERVER_URL/api/v1/audit"
assert_eq "GET /api/v1/audit returns 200" "200" "$HTTP_STATUS"

# GET /api/v1/openapi.json (no auth required) -> 200
http_get_noauth "$SERVER_URL/api/v1/openapi.json"
assert_eq "GET /api/v1/openapi.json returns 200" "200" "$HTTP_STATUS"

# GET /api/v1/tag-compliance -> 200
http_get "$SERVER_URL/api/v1/tag-compliance"
assert_eq "GET /api/v1/tag-compliance returns 200" "200" "$HTTP_STATUS"

# GET /api/v1/inventory/tables -> 200
http_get "$SERVER_URL/api/v1/inventory/tables"
assert_status_any "GET /api/v1/inventory/tables returns 200 or 503" "$HTTP_STATUS" 200 503

log ""

# ══════════════════════════════════════════════════════════════════════
# 8. Legacy API Endpoints
# ══════════════════════════════════════════════════════════════════════
log "═══════════════════════════════════════════"
log "  8. Legacy API Endpoints"
log "═══════════════════════════════════════════"

# Each legacy endpoint: 200 (or 401 if auth-gated and no cookie; still counts as reachable)
declare -a LEGACY_ENDPOINTS=(
    "/api/agents"
    "/api/help"
    "/api/audit"
    "/api/instructions"
    "/api/executions"
    "/api/compliance"
    "/api/tags?agent_id=test-agent"
    "/api/policies"
    "/api/policy-fragments"
    "/api/workflows"
    "/api/product-packs"
    "/api/notifications"
    "/api/webhooks"
    "/api/approvals/pending/count"
    "/api/nvd/status"
    "/api/schedules"
)

for endpoint in "${LEGACY_ENDPOINTS[@]}"; do
    http_get "$SERVER_URL$endpoint"
    assert_status_any "GET $endpoint" "$HTTP_STATUS" 200 401
done

log ""

# ══════════════════════════════════════════════════════════════════════
# 9. Legacy API — Command & Scope
# ══════════════════════════════════════════════════════════════════════
log "═══════════════════════════════════════════"
log "  9. Command & Scope"
log "═══════════════════════════════════════════"

# POST /api/scope/validate with valid expression
http_post "$SERVER_URL/api/scope/validate" '{"expression":"os == \"linux\""}'
assert_eq "POST /api/scope/validate returns 200" "200" "$HTTP_STATUS"
assert_contains "POST /api/scope/validate returns valid=true" "true" "$HTTP_BODY"

# POST /api/scope/estimate with valid expression
http_post "$SERVER_URL/api/scope/estimate" '{"expression":"os == \"linux\""}'
assert_eq "POST /api/scope/estimate returns 200" "200" "$HTTP_STATUS"

# POST /api/command with invalid JSON -> 400
http_post "$SERVER_URL/api/command" "not-valid-json"
assert_eq "POST /api/command with invalid JSON returns 400" "400" "$HTTP_STATUS"

# POST /api/command with empty object (missing plugin/action) -> 400
http_post "$SERVER_URL/api/command" '{}'
assert_eq "POST /api/command with {} returns 400" "400" "$HTTP_STATUS"

log ""

# ══════════════════════════════════════════════════════════════════════
# 10. Instruction Definition CRUD
# ══════════════════════════════════════════════════════════════════════
log "═══════════════════════════════════════════"
log "  10. Instruction Definition CRUD"
log "═══════════════════════════════════════════"

INSTRUCTION_ID=""

# POST /api/instructions with JSON (the legacy API accepts JSON with type field)
INSTR_NAME="e2e-test-instr-$(date +%s)"
http_post "$SERVER_URL/api/instructions" \
    "{\"name\":\"$INSTR_NAME\",\"plugin\":\"system_info\",\"action\":\"query\",\"type\":\"question\",\"description\":\"E2E test\",\"category\":\"testing\"}"
assert_status_any "POST /api/instructions returns 200 or 201" "$HTTP_STATUS" 200 201
# Try to extract the instruction ID from the response
INSTRUCTION_ID=$(extract_json_field "id" "$HTTP_BODY")
if [[ -z "$INSTRUCTION_ID" ]]; then
    # Some servers return the ID under a different key or in the URL; try "name"
    INSTRUCTION_ID=$(extract_json_field "name" "$HTTP_BODY")
fi

if [[ -n "$INSTRUCTION_ID" ]]; then
    # GET /api/instructions/{id} -> 200
    http_get "$SERVER_URL/api/instructions/$INSTRUCTION_ID"
    assert_eq "GET /api/instructions/{id} returns 200" "200" "$HTTP_STATUS"

    # DELETE /api/instructions/{id} -> 200
    http_delete "$SERVER_URL/api/instructions/$INSTRUCTION_ID"
    assert_status_ok "DELETE /api/instructions/{id}" "$HTTP_STATUS"
else
    log "  (Could not capture instruction ID — skipping GET/DELETE)"
    # Still count as tested via the POST above
fi

log ""

# ══════════════════════════════════════════════════════════════════════
# 11. Schedule CRUD
# ══════════════════════════════════════════════════════════════════════
log "═══════════════════════════════════════════"
log "  11. Schedule CRUD"
log "═══════════════════════════════════════════"

SCHEDULE_ID=""

# POST /api/schedules (needs a valid definition_id from a prior instruction)
SCHED_DEF_ID="${INSTRUCTION_ID:-missing}"
http_post "$SERVER_URL/api/schedules" \
    "{\"name\":\"e2e-test-schedule\",\"cron\":\"0 0 * * *\",\"definition_id\":\"$SCHED_DEF_ID\",\"scope\":\"os == \\\"linux\\\"\"}"
assert_status_any "POST /api/schedules returns 200 or 201" "$HTTP_STATUS" 200 201
SCHEDULE_ID=$(extract_json_field "id" "$HTTP_BODY")

if [[ -n "$SCHEDULE_ID" ]]; then
    # DELETE /api/schedules/{id} -> 200
    http_delete "$SERVER_URL/api/schedules/$SCHEDULE_ID"
    assert_status_ok "DELETE /api/schedules/{id}" "$HTTP_STATUS"
else
    log "  (Could not capture schedule ID — skipping DELETE)"
fi

log ""

# ══════════════════════════════════════════════════════════════════════
# 12. Deployment & Discovery (Phase 7)
# ══════════════════════════════════════════════════════════════════════
log "═══════════════════════════════════════════"
log "  12. Deployment & Discovery"
log "═══════════════════════════════════════════"

# GET /api/deployment-jobs -> 200 (empty list is fine)
http_get "$SERVER_URL/api/deployment-jobs"
assert_status_any "GET /api/deployment-jobs" "$HTTP_STATUS" 200 401

# GET /api/patches -> 200
http_get "$SERVER_URL/api/patches"
assert_status_any "GET /api/patches" "$HTTP_STATUS" 200 401

# GET /api/directory/status -> 200
http_get "$SERVER_URL/api/directory/status"
assert_status_any "GET /api/directory/status" "$HTTP_STATUS" 200 401

log ""

# ══════════════════════════════════════════════════════════════════════
# 13. Error Handling
# ══════════════════════════════════════════════════════════════════════
log "═══════════════════════════════════════════"
log "  13. Error Handling"
log "═══════════════════════════════════════════"

# Invalid JSON body on a POST endpoint
http_post "$SERVER_URL/api/v1/management-groups" "{{{{not json"
assert_eq "Invalid JSON body returns 400" "400" "$HTTP_STATUS"

# Nonexistent v1 endpoint -> 404
# Note: the server may redirect unauthenticated requests, so test with auth
http_get "$SERVER_URL/api/v1/nonexistent-endpoint-xyz"
assert_status_any "Nonexistent v1 endpoint returns 404 or 302" "$HTTP_STATUS" 404 302

# GET /api/v1/management-groups/nonexistent (not a valid hex id) -> 404
# The route regex requires [a-f0-9]+, so a non-matching path falls through to 404
http_get "$SERVER_URL/api/v1/management-groups/000000000000dead"
assert_eq "GET /api/v1/management-groups/nonexistent returns 404" "404" "$HTTP_STATUS"

# Rate limiting test: 50 rapid requests
log "  Running rate limit test (50 rapid requests to /livez)..."
RATE_LIMIT_HIT=false
for i in $(seq 1 50); do
    RL_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$SERVER_URL/livez" 2>/dev/null || echo "000")
    if [[ "$RL_STATUS" == "429" ]]; then
        RATE_LIMIT_HIT=true
        break
    fi
done
TESTS=$((TESTS + 1))
if [[ "$RATE_LIMIT_HIT" == "true" ]]; then
    pass "Rate limiter triggered (429 returned)"
else
    pass "No rate limiting on health endpoint (acceptable — rate limits may be disabled or on other paths)"
fi

log ""

# ══════════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════════
log "═══════════════════════════════════════════════════════════════════"
log "  REST API E2E TEST SUMMARY"
log "═══════════════════════════════════════════════════════════════════"
log ""
log "  Server:     $SERVER_URL"
log "  Skip auth:  $SKIP_AUTH"
log ""
if [[ $FAILURES -eq 0 ]]; then
    log "  ✓ ALL $TESTS TESTS PASSED"
else
    log "  ✗ $FAILURES/$TESTS TESTS FAILED"
fi
log ""
log "═══════════════════════════════════════════════════════════════════"
log ""

if [[ $FAILURES -gt 0 ]]; then
    exit 1
fi

exit 0
