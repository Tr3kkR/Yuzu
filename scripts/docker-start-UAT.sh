#!/usr/bin/env bash
# docker-start-UAT.sh — Yuzu UAT with Docker infrastructure + native agent
#
# Topology:
#   Agent (native) --> Gateway (Docker :50051) --> Server (Docker :50055)
#   Server (Docker) --> Gateway (Docker :50063) --> Agent  (command fanout)
#
# All infrastructure in Docker:
#   Server       (:8080 web, :50051 gRPC, :50055 upstream)
#   Gateway      (:50051 agent, :50063 mgmt, :9568 metrics, :8081 health)
#   Prometheus   (:9090) scrapes server + gateway via Docker network
#   ClickHouse   (:8123) receives analytics from server via Docker network
#   Grafana      (:3000) reads Prometheus + ClickHouse, dashboards provisioned
#
# Usage:
#   bash scripts/docker-start-UAT.sh          # start all
#   bash scripts/docker-start-UAT.sh stop     # stop all
#   bash scripts/docker-start-UAT.sh status   # show status
#   bash scripts/docker-start-UAT.sh rebuild  # rebuild server+gateway images, then start

set -euo pipefail

YUZU_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILDDIR="$YUZU_ROOT/builddir"
UAT_DIR="$YUZU_ROOT/.uat"
COMPOSE_FILE="$YUZU_ROOT/deploy/docker/docker-compose.full-uat.yml"

ADMIN_USER="admin"
ADMIN_PASS='YuzuUatAdmin1!'

# ── Docker CLI ───────────────────────────────────────────────────────────

if ! command -v docker > /dev/null 2>&1; then
    for docker_bin in \
        "/c/Program Files/Docker/Docker/resources/bin" \
        "$PROGRAMFILES/Docker/Docker/resources/bin"; do
        if [ -f "$docker_bin/docker.exe" ]; then
            export PATH="$PATH:$docker_bin"
            break
        fi
    done
fi

# ── Colours ──────────────────────────────────────────────────────────────

if [ -t 1 ]; then
    GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
else
    GREEN=''; RED=''; YELLOW=''; CYAN=''; NC=''
fi

ok()   { echo -e "  ${GREEN}OK${NC} $*"; }
fail() { echo -e "  ${RED}FAIL${NC} $*"; }
warn() { echo -e "  ${YELLOW}WARN${NC} $*"; }
info() { echo -e "  ${CYAN}>>${NC} $*"; }

# ── Helpers ──────────────────────────────────────────────────────────────

wait_for_http() {
    local url=$1 name=$2 timeout=${3:-30}
    local elapsed=0
    while true; do
        local code
        code=$(curl -s -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000")
        if [ "$code" != "000" ]; then
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
        if [ "$elapsed" -ge "$timeout" ]; then
            fail "$name not reachable at $url within ${timeout}s"
            return 1
        fi
    done
}

kill_agent() {
    echo "Stopping native agent..."
    local killed=0
    for proc in yuzu-agent.exe yuzu-agent; do
        if tasklist 2>/dev/null | grep -qi "$proc"; then
            taskkill //F //IM "$proc" 2>/dev/null && killed=$((killed + 1)) || true
        elif pgrep -x "$proc" > /dev/null 2>&1; then
            pkill -x "$proc" 2>/dev/null && killed=$((killed + 1)) || true
        fi
    done
    if [ "$killed" -eq 0 ]; then
        ok "No stale agent processes"
    else
        ok "Killed agent"
    fi
}

kill_docker() {
    echo "Stopping Docker containers..."
    UAT_CONFIG="$UAT_DIR/yuzu-server.cfg" \
    UAT_DASHBOARDS="$UAT_DIR/dashboards" \
        docker compose -f "$COMPOSE_FILE" down -v 2>/dev/null \
        && ok "Containers stopped" || ok "No containers running"
}

generate_config() {
    python -c "
import hashlib, os
salt = os.urandom(16)
dk = hashlib.pbkdf2_hmac('sha256', '${ADMIN_PASS}'.encode(), salt, 100000, dklen=32)
print(f'${ADMIN_USER}:admin:{salt.hex()}:{dk.hex()}')
" > "$UAT_DIR/yuzu-server.cfg"
}

prepare_dashboards() {
    local src="$YUZU_ROOT/deploy/grafana"
    local dst="$UAT_DIR/dashboards"
    mkdir -p "$dst"

    for f in "$src"/*.json; do
        [ -f "$f" ] || continue
        sed \
            -e 's|"\${DS_PROMETHEUS}"|{"type": "prometheus", "uid": "prometheus"}|g' \
            -e 's|"\${DS_CLICKHOUSE}"|{"type": "grafana-clickhouse-datasource", "uid": "clickhouse"}|g' \
            "$f" > "$dst/$(basename "$f")"
    done

    if [ -f "$src/yuzu-alerts.yml" ]; then
        cp "$src/yuzu-alerts.yml" "$dst/"
    fi
}

ensure_docker() {
    if docker info > /dev/null 2>&1; then
        return 0
    fi
    info "Docker not running — attempting to start Docker Desktop..."
    local docker_exe=""
    for candidate in \
        "/c/Program Files/Docker/Docker/Docker Desktop.exe" \
        "$PROGRAMFILES/Docker/Docker/Docker Desktop.exe" \
        "$LOCALAPPDATA/Docker/Docker Desktop.exe"; do
        if [ -f "$candidate" ]; then
            docker_exe="$candidate"
            break
        fi
    done
    if [ -z "$docker_exe" ]; then
        fail "Docker not running and Docker Desktop not found"
        return 1
    fi
    "$docker_exe" &
    disown
    local docker_wait=0
    while ! docker info > /dev/null 2>&1; do
        sleep 2
        docker_wait=$((docker_wait + 2))
        if [ "$docker_wait" -ge 60 ]; then
            fail "Docker Desktop did not start within 60s"
            return 1
        fi
    done
    ok "Docker Desktop started (${docker_wait}s)"
}

# ── Status ───────────────────────────────────────────────────────────────

show_status() {
    echo "=== Yuzu Docker UAT Stack Status ==="
    echo ""
    echo "Docker containers:"
    UAT_CONFIG="$UAT_DIR/yuzu-server.cfg" \
    UAT_DASHBOARDS="$UAT_DIR/dashboards" \
        docker compose -f "$COMPOSE_FILE" ps 2>/dev/null || echo "  (not running)"
    echo ""
    echo "Native agent:"
    if tasklist 2>/dev/null | grep -qi "yuzu-agent"; then
        ok "yuzu-agent running"
    elif pgrep -x yuzu-agent > /dev/null 2>&1; then
        ok "yuzu-agent running"
    else
        fail "yuzu-agent not running"
    fi
    echo ""
    echo "Endpoints:"
    echo "  Dashboard:   http://localhost:8080"
    echo "  Grafana:     http://localhost:3000 (admin/admin)"
    echo "  Prometheus:  http://localhost:9090"
    echo "  ClickHouse:  http://localhost:8123"
    echo "  GW Health:   http://localhost:8081/readyz"
    echo "  GW Metrics:  http://localhost:9568/metrics"
}

# ── Rebuild images ───────────────────────────────────────────────────────

rebuild_images() {
    echo ""
    echo "[0/5] Building Docker images..."

    info "Building yuzu-server image..."
    docker build -t yuzu-server -f "$YUZU_ROOT/deploy/docker/Dockerfile.server" "$YUZU_ROOT" \
        && ok "yuzu-server image built" \
        || { fail "yuzu-server build failed"; exit 1; }

    info "Building yuzu-gateway image..."
    docker build -t yuzu-gateway -f "$YUZU_ROOT/deploy/docker/Dockerfile.gateway" "$YUZU_ROOT" \
        && ok "yuzu-gateway image built" \
        || { fail "yuzu-gateway build failed"; exit 1; }
}

# ── Start ────────────────────────────────────────────────────────────────

start_all() {
    echo ""
    echo "=============================================="
    echo "       Yuzu Docker UAT Environment            "
    echo "=============================================="
    echo ""

    # ── Preflight ─────────────────────────────────────────────────────
    local errors=0

    # Agent binary (native)
    local agent_bin=""
    if [ -f "$BUILDDIR/agents/core/yuzu-agent.exe" ]; then
        agent_bin="$BUILDDIR/agents/core/yuzu-agent.exe"
    elif [ -f "$BUILDDIR/agents/core/yuzu-agent" ]; then
        agent_bin="$BUILDDIR/agents/core/yuzu-agent"
    else
        fail "yuzu-agent not found — run: meson compile -C builddir"
        errors=$((errors + 1))
    fi

    # Docker images
    if ! docker image inspect yuzu-server:latest > /dev/null 2>&1; then
        fail "yuzu-server:latest image not found — run: bash $0 rebuild"
        errors=$((errors + 1))
    fi
    if ! docker image inspect yuzu-gateway:latest > /dev/null 2>&1; then
        fail "yuzu-gateway:latest image not found — run: bash $0 rebuild"
        errors=$((errors + 1))
    fi

    if ! ensure_docker; then
        errors=$((errors + 1))
    fi

    if [ "$errors" -gt 0 ]; then
        echo ""; fail "$errors preflight check(s) failed — aborting"
        exit 1
    fi
    ok "Preflight checks passed"

    # ── Clean state ───────────────────────────────────────────────────
    kill_agent
    kill_docker
    rm -rf "$UAT_DIR"
    mkdir -p "$UAT_DIR/agent-data" "$UAT_DIR/dashboards"

    # ── Generate credentials ──────────────────────────────────────────
    generate_config
    ok "Generated server config ($ADMIN_USER / $ADMIN_PASS)"

    # ── Prepare dashboards ────────────────────────────────────────────
    prepare_dashboards
    ok "Prepared provisioned dashboards"

    # ── 1. Docker stack (server + gateway + monitoring) ───────────────
    echo ""
    echo "[1/2] Starting Docker stack (server + gateway + prometheus + clickhouse + grafana)..."

    UAT_CONFIG="$UAT_DIR/yuzu-server.cfg" \
    UAT_DASHBOARDS="$UAT_DIR/dashboards" \
        docker compose -f "$COMPOSE_FILE" up -d 2>&1 | tail -10

    # Wait for services
    if ! wait_for_http "http://localhost:8080/login" "Server" 45; then
        fail "Server did not start — check: docker logs yuzu-uat-server"
        exit 1
    fi
    ok "Server up (dashboard http://localhost:8080)"

    if ! wait_for_http "http://localhost:8081/readyz" "Gateway" 30; then
        fail "Gateway did not start — check: docker logs yuzu-uat-gateway"
        exit 1
    fi
    ok "Gateway up"

    if ! wait_for_http "http://localhost:9090/-/ready" "Prometheus" 30; then
        warn "Prometheus may still be starting"
    else
        ok "Prometheus up (http://localhost:9090)"
    fi

    if ! wait_for_http "http://localhost:8123/ping" "ClickHouse" 30; then
        warn "ClickHouse may still be starting"
    else
        ok "ClickHouse up (http://localhost:8123)"
    fi

    if ! wait_for_http "http://localhost:3000/api/health" "Grafana" 45; then
        warn "Grafana may still be starting (installing ClickHouse plugin...)"
    else
        ok "Grafana up (http://localhost:3000)"
    fi

    # ── Login & enrollment token ──────────────────────────────────────
    info "Creating enrollment token..."
    local enroll_token=""
    for _attempt in 1 2 3; do
        curl -s -L -c "$UAT_DIR/cookies.txt" http://localhost:8080/login \
            -d "username=${ADMIN_USER}&password=${ADMIN_PASS}" -o /dev/null 2>/dev/null || true

        local token_html
        token_html=$(curl -s -L -b "$UAT_DIR/cookies.txt" \
            -X POST http://localhost:8080/api/settings/enrollment-tokens \
            -d "label=uat-auto&max_uses=1000&ttl=86400" 2>/dev/null) || true
        enroll_token=$(echo "$token_html" | python -c "import sys,re; m=re.search(r'[a-f0-9]{64}', sys.stdin.read()); print(m.group() if m else '')" 2>/dev/null) || true

        if [ -n "$enroll_token" ]; then
            break
        fi
        sleep 2
    done

    if [ -z "$enroll_token" ]; then
        fail "Failed to create enrollment token"
        exit 1
    fi
    echo "$enroll_token" > "$UAT_DIR/enrollment-token"
    ok "Enrollment token created"

    # ── 2. Native agent (connects to gateway on host-exposed port) ────
    echo ""
    echo "[2/2] Starting yuzu-agent (native, -> gateway :50051)..."

    # When running a Windows .exe from WSL2, paths must be Windows-style.
    # The .exe cannot resolve /mnt/c/... paths — use wslpath to convert.
    local agent_data_dir="$UAT_DIR/agent-data"
    local agent_plugin_dir="$BUILDDIR/agents/plugins"
    if [[ "$agent_bin" == *.exe ]] && command -v wslpath > /dev/null 2>&1; then
        agent_data_dir=$(wslpath -w "$agent_data_dir")
        agent_plugin_dir=$(wslpath -w "$agent_plugin_dir")
    fi

    "$agent_bin" \
        --server localhost:50051 \
        --no-tls \
        --data-dir "$agent_data_dir" \
        --plugin-dir "$agent_plugin_dir" \
        --log-level info \
        --enrollment-token "$enroll_token" \
        > "$UAT_DIR/agent.log" 2>&1 &
    disown

    # Wait for registration
    local waited=0
    while ! grep -q "Registered with server" "$UAT_DIR/agent.log" 2>/dev/null; do
        sleep 1
        waited=$((waited + 1))
        if [ "$waited" -ge 20 ]; then
            fail "Agent did not register within 20s — check $UAT_DIR/agent.log"
            exit 1
        fi
    done
    local session_id
    session_id=$(grep "Registered with server" "$UAT_DIR/agent.log" | \
        python -c "import sys,re; lines=sys.stdin.read(); m=re.findall(r'session=[^ ,)]+', lines); print(m[-1] if m else 'unknown')" 2>/dev/null || echo "unknown")
    ok "Agent up ($session_id)"

    if echo "$session_id" | grep -q "gw-session"; then
        ok "Agent confirmed via gateway (gw-session prefix)"
    else
        warn "Agent session: $session_id (may not be routed through gateway)"
    fi

    # ── Connectivity Tests ────────────────────────────────────────────
    echo ""
    echo "=== Connectivity Tests ==="

    local tests_passed=0 tests_total=0

    # Test 1: Dashboard
    tests_total=$((tests_total + 1))
    local dash_code
    dash_code=$(curl -s -o /dev/null -w "%{http_code}" -b "$UAT_DIR/cookies.txt" http://localhost:8080/ 2>/dev/null)
    if [ "$dash_code" = "200" ]; then
        ok "Dashboard reachable (HTTP $dash_code)"
        tests_passed=$((tests_passed + 1))
    else
        fail "Dashboard returned HTTP $dash_code"
    fi

    # Test 2: Gateway health
    tests_total=$((tests_total + 1))
    local gw_health
    gw_health=$(curl -s -m 3 http://localhost:8081/readyz 2>/dev/null || echo '{"status":"error"}')
    if echo "$gw_health" | grep -q '"ready"'; then
        ok "Gateway healthy"
        tests_passed=$((tests_passed + 1))
    else
        fail "Gateway health: $gw_health"
    fi

    # Test 3: Server metrics — agent registered
    tests_total=$((tests_total + 1))
    local reg_count
    reg_count=$(curl -s http://localhost:8080/metrics 2>/dev/null | \
        python -c "import sys,re; m=re.search(r'yuzu_agents_registered_total (\d+)', sys.stdin.read()); print(m.group(1) if m else '0')" 2>/dev/null || echo "0")
    if [ "$reg_count" -ge 1 ]; then
        ok "Server sees $reg_count registered agent(s)"
        tests_passed=$((tests_passed + 1))
    else
        fail "Server shows 0 registered agents"
    fi

    # Test 4: Gateway metrics — agent connected
    tests_total=$((tests_total + 1))
    local gw_agents
    gw_agents=$(curl -s http://localhost:9568/metrics 2>/dev/null | \
        python -c "import sys,re; m=re.search(r'yuzu_gw_agents_connected_total\{[^}]*\} (\d+)', sys.stdin.read()); print(m.group(1) if m else '0')" 2>/dev/null || echo "0")
    if [ "$gw_agents" -ge 1 ]; then
        ok "Gateway shows $gw_agents connected agent(s)"
        tests_passed=$((tests_passed + 1))
    else
        fail "Gateway shows 0 connected agents"
    fi

    # Test 5: Prometheus scraping
    tests_total=$((tests_total + 1))
    sleep 3
    local up_count
    up_count=$(curl -s http://localhost:9090/api/v1/targets 2>/dev/null | \
        python -c "
import sys, json
try:
    d = json.load(sys.stdin)
    active = d.get('data',{}).get('activeTargets',[])
    print(sum(1 for t in active if t.get('health') == 'up'))
except: print(0)
" 2>/dev/null)
    if [ "$up_count" -ge 1 ]; then
        ok "Prometheus scraping $up_count target(s)"
        tests_passed=$((tests_passed + 1))
    else
        warn "Prometheus targets not yet up ($up_count) — may need another scrape cycle"
    fi

    # Test 6: Grafana health
    tests_total=$((tests_total + 1))
    local grafana_ok
    grafana_ok=$(curl -s http://localhost:3000/api/health 2>/dev/null | grep -c '"ok"' || echo "0")
    if [ "$grafana_ok" -ge 1 ]; then
        ok "Grafana healthy"
        tests_passed=$((tests_passed + 1))
    else
        fail "Grafana not healthy"
    fi

    # Test 7: ClickHouse schema
    tests_total=$((tests_total + 1))
    local ch_tables
    ch_tables=$(curl -s "http://localhost:8123/?query=SHOW+TABLES+FROM+yuzu" 2>/dev/null || echo "")
    if echo "$ch_tables" | grep -q "yuzu_events"; then
        ok "ClickHouse: yuzu.yuzu_events table exists"
        tests_passed=$((tests_passed + 1))
    else
        fail "ClickHouse: yuzu_events table not found"
    fi

    # Test 8: help command (plugin listing)
    echo ""
    echo "=== Command Tests ==="
    tests_total=$((tests_total + 1))
    local help_html
    help_html=$(curl -s -m 10 -b "$UAT_DIR/cookies.txt" \
        http://localhost:8080/api/help/html 2>/dev/null)
    local plugin_count
    plugin_count=$(echo "$help_html" | grep -o 'result-row' | wc -l)
    if [ "$plugin_count" -gt 0 ]; then
        ok "help: $plugin_count plugin actions listed"
        tests_passed=$((tests_passed + 1))
    else
        fail "help: no plugin actions returned"
    fi

    # Test 9: os_info round-trip (server -> gateway -> agent -> gateway -> server)
    tests_total=$((tests_total + 1))
    info "Sending 'os_info os_name' (full round-trip via gateway)..."
    local cmd_resp
    cmd_resp=$(curl -s -m 10 -b "$UAT_DIR/cookies.txt" \
        -X POST http://localhost:8080/api/command \
        -H "Content-Type: application/json" \
        -d '{"plugin":"os_info","action":"os_name"}' 2>/dev/null)
    local cmd_id
    cmd_id=$(echo "$cmd_resp" | python -c "import sys,json; print(json.load(sys.stdin).get('command_id',''))" 2>/dev/null || true)

    if [ -z "$cmd_id" ]; then
        fail "os_info: failed to dispatch (response: $cmd_resp)"
    else
        info "Command dispatched: $cmd_id"
        local os_result="" poll_count=0
        while [ $poll_count -lt 15 ]; do
            sleep 1
            poll_count=$((poll_count + 1))
            os_result=$(curl -s -b "$UAT_DIR/cookies.txt" \
                "http://localhost:8080/api/responses/$cmd_id" 2>/dev/null | \
                python -c "
import sys,json
d=json.load(sys.stdin)
for r in d.get('responses',[]):
    o = r.get('output','')
    if 'os_name|' in o:
        print(o.split('|',1)[1])
        break
" 2>/dev/null || true)
            [ -n "$os_result" ] && break
        done

        if [ -n "$os_result" ]; then
            ok "os_info: $os_result (round-trip ${poll_count}s)"
            tests_passed=$((tests_passed + 1))
        else
            fail "os_info: no response after ${poll_count}s"
            warn "Check: docker logs yuzu-uat-server"
            warn "Check: docker logs yuzu-uat-gateway"
            warn "Check: $UAT_DIR/agent.log"
        fi
    fi

    # Test 10: ClickHouse analytics ingest
    tests_total=$((tests_total + 1))
    info "Waiting for analytics drain to ClickHouse..."
    local ch_count=0
    for ch_attempt in $(seq 1 15); do
        ch_count=$(curl -s "http://localhost:8123/?query=SELECT+count()+FROM+yuzu.yuzu_events" 2>/dev/null || echo "0")
        ch_count=$(echo "$ch_count" | tr -d '[:space:]')
        if [ "$ch_count" -gt 0 ] 2>/dev/null; then
            break
        fi
        sleep 1
    done
    if [ "$ch_count" -gt 0 ] 2>/dev/null; then
        ok "ClickHouse: $ch_count event(s) ingested (${ch_attempt}s)"
        tests_passed=$((tests_passed + 1))
    else
        fail "ClickHouse: no events after 15s — check server analytics config"
    fi

    # ── Summary ───────────────────────────────────────────────────────
    echo ""
    if [ "$tests_passed" -eq "$tests_total" ]; then
        echo -e "${GREEN}=== All $tests_total/$tests_total tests passed ===${NC}"
    else
        echo -e "${YELLOW}=== $tests_passed/$tests_total tests passed ===${NC}"
    fi

    echo ""
    echo "=============================================="
    echo "       Docker UAT Stack Ready                 "
    echo "=============================================="
    echo ""
    echo "  Dashboard:   http://localhost:8080"
    printf "  Login:       %s / %s\n" "$ADMIN_USER" "$ADMIN_PASS"
    echo "  Grafana:     http://localhost:3000 (admin/admin)"
    echo "  Prometheus:  http://localhost:9090"
    echo "  ClickHouse:  http://localhost:8123"
    echo ""
    echo "  GW Health:   http://localhost:8081/readyz"
    echo "  GW Metrics:  http://localhost:9568/metrics"
    echo ""
    echo "  Agent (native) -> GW(:50051) -> Server(:50055)  [data]"
    echo "  Server -> GW(:50063) -> Agent                   [commands]"
    echo "  Server -> ClickHouse (Docker network)           [analytics]"
    echo "  Prometheus -> Server + GW (Docker network)      [metrics]"
    echo "  Grafana -> Prometheus + ClickHouse               [dashboards]"
    echo ""
    echo "  Agent log: $UAT_DIR/agent.log"
    echo "  Server:    docker logs -f yuzu-uat-server"
    echo "  Gateway:   docker logs -f yuzu-uat-gateway"
    echo "  Stop:      bash scripts/docker-start-UAT.sh stop"
    echo "=============================================="
}

# ── Main ─────────────────────────────────────────────────────────────────

case "${1:-start}" in
    start)   start_all ;;
    stop)    kill_agent; kill_docker; echo "Docker UAT stack stopped." ;;
    status)  show_status ;;
    rebuild) ensure_docker && rebuild_images && start_all ;;
    *)       echo "Usage: $0 {start|stop|status|rebuild}"; exit 1 ;;
esac
