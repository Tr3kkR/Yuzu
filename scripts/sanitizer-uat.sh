#!/bin/bash
# Yuzu Sanitizer UAT — run the full stack under ASan/UBSan or TSan
#
# Usage:
#   bash scripts/sanitizer-uat.sh asan          # ASan+UBSan (memory errors, leaks)
#   bash scripts/sanitizer-uat.sh tsan          # TSan (data races, deadlocks)
#   bash scripts/sanitizer-uat.sh asan stop     # stop the stack
#   bash scripts/sanitizer-uat.sh asan logs     # show sanitizer findings
#   bash scripts/sanitizer-uat.sh asan build    # rebuild images only

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

export PATH="/c/Program Files/Docker/Docker/resources/bin:$PATH"

SANITIZER="${1:-asan}"
ACTION="${2:-start}"

if [[ "$SANITIZER" != "asan" && "$SANITIZER" != "tsan" ]]; then
    echo "Usage: $0 <asan|tsan> [start|stop|logs|build]"
    exit 1
fi

COMPOSE_FILE="$REPO_ROOT/deploy/docker/docker-compose.sanitizer-uat.yml"
UAT_DIR="$REPO_ROOT/.uat-sanitizer"
export SANITIZER

# ── Build images ─────────────────────────────────────────────────────────
build_images() {
    echo "Building $SANITIZER-instrumented images..."

    # Ensure base CI image exists
    if ! docker image inspect yuzu-ci &>/dev/null; then
        echo "  Building base CI image first (this takes ~40 min)..."
        docker build -t yuzu-ci -f "$REPO_ROOT/deploy/docker/Dockerfile.ci" "$REPO_ROOT"
    fi

    # Ensure gateway image exists
    if ! docker image inspect yuzu-gateway &>/dev/null; then
        echo "  Building gateway image..."
        docker build -t yuzu-gateway -f "$REPO_ROOT/deploy/docker/Dockerfile.gateway" "$REPO_ROOT"
    fi

    echo "  Building server-$SANITIZER..."
    docker build -t "yuzu-server-$SANITIZER" \
        -f "$REPO_ROOT/deploy/docker/Dockerfile.server-$SANITIZER" "$REPO_ROOT"

    echo "  Building agent-$SANITIZER..."
    docker build -t "yuzu-agent-$SANITIZER" \
        -f "$REPO_ROOT/deploy/docker/Dockerfile.agent-$SANITIZER" "$REPO_ROOT"

    echo "  OK Images built"
}

# ── Generate server config ───────────────────────────────────────────────
generate_config() {
    mkdir -p "$UAT_DIR"

    local PASS_HASH
    PASS_HASH=$(python3 -c "
import hashlib, os, base64
salt = os.urandom(16)
dk = hashlib.pbkdf2_hmac('sha256', b'adminpassword1', salt, 600000)
print(base64.b64encode(salt).decode() + ':' + base64.b64encode(dk).decode())
" 2>/dev/null)

    cat > "$UAT_DIR/yuzu-server.cfg" <<CFGEOF
{
  "users": [
    {
      "username": "admin",
      "password_hash": "$PASS_HASH",
      "role": "admin"
    }
  ]
}
CFGEOF
    export UAT_CONFIG="$UAT_DIR/yuzu-server.cfg"
}

# ── Start ────────────────────────────────────────────────────────────────
start_stack() {
    echo "════════════════════════════════════════════════════════"
    echo "  Yuzu Sanitizer UAT — $SANITIZER"
    echo "════════════════════════════════════════════════════════"

    # Build if needed
    if ! docker image inspect "yuzu-server-$SANITIZER" &>/dev/null; then
        build_images
    fi

    generate_config

    echo ""
    echo "Starting stack..."
    docker compose -f "$COMPOSE_FILE" down --remove-orphans 2>/dev/null || true
    docker compose -f "$COMPOSE_FILE" up -d

    echo ""
    echo "Waiting for server..."
    for i in $(seq 1 30); do
        if curl -s -o /dev/null http://localhost:8080/livez 2>/dev/null; then
            echo "  OK Server up"
            break
        fi
        sleep 2
    done

    echo "Waiting for gateway..."
    for i in $(seq 1 15); do
        if curl -s -o /dev/null http://localhost:8081/healthz 2>/dev/null; then
            echo "  OK Gateway up"
            break
        fi
        sleep 2
    done

    # Create enrollment token
    echo "Creating enrollment token..."
    local TOKEN_HTML
    for attempt in 1 2 3; do
        TOKEN_HTML=$(curl -s -X POST http://localhost:8080/api/v1/enrollment-tokens \
            -H "Content-Type: application/json" \
            -d '{"description":"sanitizer-uat","max_uses":10,"expires_hours":24}' \
            -u admin:adminpassword1 2>/dev/null) && break
        sleep 3
    done
    local TOKEN
    TOKEN=$(echo "$TOKEN_HTML" | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))" 2>/dev/null || echo "")

    if [ -n "$TOKEN" ]; then
        echo "  OK Token: ${TOKEN:0:16}..."
        export ENROLLMENT_TOKEN="$TOKEN"
        # Restart agent with token
        docker compose -f "$COMPOSE_FILE" up -d agent
    else
        echo "  WARN Could not create enrollment token"
    fi

    echo ""
    echo "Waiting for agent registration..."
    sleep 5

    echo ""
    echo "════════════════════════════════════════════════════════"
    echo "  Running connectivity tests..."
    echo "════════════════════════════════════════════════════════"

    local PASS=0 FAIL=0

    # Test 1: Dashboard
    if curl -s -o /dev/null -w "%{http_code}" http://localhost:8080 | grep -q "200\|302"; then
        echo "  OK Dashboard reachable"; ((PASS++))
    else
        echo "  FAIL Dashboard"; ((FAIL++))
    fi

    # Test 2: Gateway health
    if curl -s http://localhost:8081/healthz 2>/dev/null | grep -qi "ok\|healthy"; then
        echo "  OK Gateway healthy"; ((PASS++))
    else
        echo "  FAIL Gateway health"; ((FAIL++))
    fi

    # Test 3: Agent registered
    local AGENT_COUNT
    AGENT_COUNT=$(curl -s http://localhost:8080/api/v1/agents -u admin:adminpassword1 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('agents',d.get('data',[]))))" 2>/dev/null || echo "0")
    if [ "$AGENT_COUNT" -ge 1 ] 2>/dev/null; then
        echo "  OK Agent registered ($AGENT_COUNT)"; ((PASS++))
    else
        echo "  WARN Agent not yet registered (may need enrollment)"; ((FAIL++))
    fi

    echo ""
    echo "════════════════════════════════════════════════════════"
    echo "  Sending test commands (exercises concurrent code paths)..."
    echo "════════════════════════════════════════════════════════"

    # Send several commands to exercise threading
    for cmd in "os_info os_name" "status list" "help list"; do
        local RESP
        RESP=$(curl -s -X POST http://localhost:8080/api/v1/commands \
            -H "Content-Type: application/json" \
            -d "{\"command\":\"$cmd\"}" \
            -u admin:adminpassword1 2>/dev/null)
        echo "  >> Sent: $cmd"
        sleep 2
    done

    echo ""
    echo "  Waiting for responses and sanitizer analysis..."
    sleep 10

    echo ""
    echo "════════════════════════════════════════════════════════"
    echo "  Checking sanitizer logs..."
    echo "════════════════════════════════════════════════════════"

    # Check for sanitizer findings
    local SAN_FINDINGS=0
    for container in yuzu-san-server yuzu-san-agent; do
        local FINDINGS
        FINDINGS=$(docker logs "$container" 2>&1 | grep -c -i "ERROR\|SUMMARY\|data race\|heap-use-after-free\|undefined behavior" || echo "0")
        if [ "$FINDINGS" -gt 0 ]; then
            echo "  !! $container: $FINDINGS sanitizer finding(s)"
            docker logs "$container" 2>&1 | grep -A3 -i "ERROR\|SUMMARY\|data race\|heap-use-after-free\|undefined behavior" | head -20
            SAN_FINDINGS=$((SAN_FINDINGS + FINDINGS))
        else
            echo "  OK $container: clean"
        fi
    done

    echo ""
    echo "════════════════════════════════════════════════════════"
    if [ "$SAN_FINDINGS" -eq 0 ]; then
        echo "  CLEAN — no sanitizer findings"
    else
        echo "  $SAN_FINDINGS sanitizer finding(s) — review with:"
        echo "    docker logs yuzu-san-server 2>&1 | grep -A10 'SUMMARY'"
        echo "    docker logs yuzu-san-agent 2>&1 | grep -A10 'SUMMARY'"
    fi
    echo ""
    echo "  Stack is running. Exercise it further, then check:"
    echo "    bash scripts/sanitizer-uat.sh $SANITIZER logs"
    echo "    bash scripts/sanitizer-uat.sh $SANITIZER stop"
    echo "════════════════════════════════════════════════════════"
}

# ── Stop ─────────────────────────────────────────────────────────────────
stop_stack() {
    echo "Stopping sanitizer UAT stack..."
    echo ""
    echo "Final sanitizer report:"
    show_logs
    echo ""
    docker compose -f "$COMPOSE_FILE" down --remove-orphans 2>/dev/null
    echo "Stopped."
}

# ── Logs ─────────────────────────────────────────────────────────────────
show_logs() {
    for container in yuzu-san-server yuzu-san-agent; do
        echo "=== $container ==="
        local FINDINGS
        FINDINGS=$(docker logs "$container" 2>&1 | grep -c -i "SUMMARY\|data race\|heap-use-after-free\|undefined behavior\|memory leak" || echo "0")
        if [ "$FINDINGS" -gt 0 ]; then
            docker logs "$container" 2>&1 | grep -B1 -A10 -i "SUMMARY\|data race\|heap-use-after-free\|undefined behavior\|memory leak" | head -50
        else
            echo "  Clean — no findings"
        fi
        echo ""
    done
}

# ── Dispatch ─────────────────────────────────────────────────────────────
case "$ACTION" in
    start)  start_stack ;;
    stop)   stop_stack ;;
    logs)   show_logs ;;
    build)  build_images ;;
    *)      echo "Usage: $0 <asan|tsan> [start|stop|logs|build]"; exit 1 ;;
esac
