#!/usr/bin/env bash
# linux-start-UAT.sh — Start a full Yuzu UAT environment on Linux
#
# Topology (all traffic flows through the gateway):
#   Agent ──→ Gateway(:50051) ──→ Server(:50055 upstream)
#                                   │
#   Server ──→ Gateway(:50063) ──→ Agent   (command fanout)
#
# Ports:
#   Server:   :50051 agent gRPC    :50055 gateway upstream
#             :50052 mgmt gRPC     :8080  web dashboard
#   Gateway:  :50051 agent-facing  :50063 mgmt (command forwarding)
#             :9568  metrics       :8081  health
#
# Usage:
#   bash scripts/linux-start-UAT.sh          # start + verify
#   bash scripts/linux-start-UAT.sh stop     # kill all
#   bash scripts/linux-start-UAT.sh status   # show running processes

set -euo pipefail

YUZU_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILDDIR="$YUZU_ROOT/builddir"
GATEWAY_DIR="$YUZU_ROOT/gateway"
UAT_DIR="/tmp/yuzu-uat"

ADMIN_USER="admin"
ADMIN_PASS='YuzuUatAdmin1!'

# Colours (disabled if not a terminal)
if [ -t 1 ]; then
    GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
else
    GREEN=''; RED=''; YELLOW=''; CYAN=''; NC=''
fi

ok()   { echo -e "  ${GREEN}✓${NC} $*"; }
fail() { echo -e "  ${RED}✗${NC} $*"; }
warn() { echo -e "  ${YELLOW}⚠${NC} $*"; }
info() { echo -e "  ${CYAN}→${NC} $*"; }

# ── Kill helpers ────────────────────────────────────────────────────────

kill_stale() {
    echo "Cleaning up stale Yuzu processes..."
    local killed=0

    for pattern in yuzu-server yuzu-agent; do
        local pids
        pids=$(pgrep -f "$pattern" 2>/dev/null || true)
        if [ -n "$pids" ]; then
            echo "$pids" | xargs kill -9 2>/dev/null || true
            ok "Killed $pattern (PIDs: $(echo $pids | tr '\n' ' '))"
            killed=$((killed + 1))
        fi
    done

    # Erlang BEAM (gateway)
    local beam_pids
    beam_pids=$(pgrep -f "beam.smp" 2>/dev/null || true)
    if [ -n "$beam_pids" ]; then
        echo "$beam_pids" | xargs kill -9 2>/dev/null || true
        ok "Killed gateway/beam.smp (PIDs: $(echo $beam_pids | tr '\n' ' '))"
        killed=$((killed + 1))
    fi

    if [ "$killed" -eq 0 ]; then
        ok "No stale processes found"
    fi

    # Wait for ports to release
    sleep 1
}

# ── Status ──────────────────────────────────────────────────────────────

show_status() {
    echo "=== Yuzu UAT Stack Status ==="
    for proc in yuzu-server yuzu-agent beam.smp; do
        if pgrep -f "$proc" > /dev/null 2>&1; then
            ok "$proc running (PID: $(pgrep -f "$proc" | head -1))"
        else
            fail "$proc not running"
        fi
    done
    echo ""
    echo "=== Listening Ports ==="
    ss -tlnp 2>/dev/null | grep -E ":(50051|50052|50055|50063|8080|8081|9568) " || echo "  (none)"
}

# ── Wait for port ───────────────────────────────────────────────────────

wait_for_port() {
    local port=$1 name=$2 timeout=${3:-15}
    local elapsed=0
    while ! ss -tlnp 2>/dev/null | grep -q ":${port} "; do
        sleep 1
        elapsed=$((elapsed + 1))
        if [ "$elapsed" -ge "$timeout" ]; then
            fail "$name did not bind to :$port within ${timeout}s"
            return 1
        fi
    done
    return 0
}

# ── Generate server config ──────────────────────────────────────────────

generate_config() {
    mkdir -p "$UAT_DIR"
    python3 -c "
import hashlib, os
salt = os.urandom(16)
dk = hashlib.pbkdf2_hmac('sha256', '${ADMIN_PASS}'.encode(), salt, 100000, dklen=32)
print(f'${ADMIN_USER}:admin:{salt.hex()}:{dk.hex()}')
" > "$UAT_DIR/yuzu-server.cfg"
    chmod 600 "$UAT_DIR/yuzu-server.cfg"
}

# ── Start stack ─────────────────────────────────────────────────────────

start_all() {
    echo ""
    echo "╔══════════════════════════════════════════════════╗"
    echo "║         Yuzu UAT Environment (Linux)             ║"
    echo "╚══════════════════════════════════════════════════╝"
    echo ""

    # ── Preflight checks ────────────────────────────────────────────────
    if [ ! -f "$BUILDDIR/server/core/yuzu-server" ]; then
        fail "yuzu-server not found at $BUILDDIR/server/core/yuzu-server"
        echo "    Run: meson compile -C builddir"
        exit 1
    fi
    if [ ! -f "$BUILDDIR/agents/core/yuzu-agent" ]; then
        fail "yuzu-agent not found at $BUILDDIR/agents/core/yuzu-agent"
        echo "    Run: meson compile -C builddir"
        exit 1
    fi
    if [ ! -d "$GATEWAY_DIR/_build/default/lib/yuzu_gw/ebin" ]; then
        fail "Gateway not compiled at $GATEWAY_DIR/_build"
        echo "    Run: cd gateway && rebar3 compile"
        exit 1
    fi
    if ! command -v erl > /dev/null 2>&1; then
        fail "erl not found in PATH"
        exit 1
    fi

    ok "Preflight checks passed"

    # ── Kill stale ──────────────────────────────────────────────────────
    kill_stale

    # ── Clean UAT state ─────────────────────────────────────────────────
    rm -rf "$UAT_DIR"
    mkdir -p "$UAT_DIR/agent-data"

    # ── Generate credentials ────────────────────────────────────────────
    generate_config
    ok "Generated server config ($ADMIN_USER / $ADMIN_PASS)"

    # ── 1. Server ───────────────────────────────────────────────────────
    echo ""
    echo "[1/3] Starting yuzu-server..."
    "$BUILDDIR/server/core/yuzu-server" \
        --no-tls \
        --no-https \
        --gateway-upstream 0.0.0.0:50055 \
        --gateway-mode \
        --gateway-command-addr localhost:50063 \
        --web-address 0.0.0.0 \
        --log-level info \
        --metrics-no-auth \
        --config "$UAT_DIR/yuzu-server.cfg" \
        > "$UAT_DIR/server.log" 2>&1 &
    local server_pid=$!

    if ! wait_for_port 8080 "yuzu-server" 10; then
        fail "Server failed to start. Check $UAT_DIR/server.log"
        exit 1
    fi
    ok "Server up (PID $server_pid)"
    info "Dashboard http://localhost:8080"
    info "Agent gRPC :50051  |  Gateway upstream :50055  |  Mgmt :50052"

    # ── 2. Gateway ──────────────────────────────────────────────────────
    echo ""
    echo "[2/3] Starting Erlang gateway..."
    (cd "$GATEWAY_DIR" && erl \
        -pa _build/default/lib/*/ebin \
        -config config/sys \
        -eval "application:ensure_all_started(yuzu_gw)" \
        -noshell \
        > "$UAT_DIR/gateway.log" 2>&1) &
    local gw_pid=$!

    if ! wait_for_port 50051 "gateway (agent-facing)" 15; then
        fail "Gateway failed to start. Check $UAT_DIR/gateway.log"
        exit 1
    fi
    # Also verify the management port bound (needed for command forwarding)
    if ! wait_for_port 50063 "gateway (mgmt/command)" 5; then
        fail "Gateway mgmt service failed to bind on :50063"
        warn "Command forwarding through gateway will not work"
    fi
    ok "Gateway up (PID $gw_pid)"
    info "Agent-facing :50051  |  Command mgmt :50063  |  Metrics :9568  |  Health :8081"

    # ── Login & create enrollment token ─────────────────────────────────
    info "Creating enrollment token..."
    curl -s -c "$UAT_DIR/cookies.txt" http://localhost:8080/login \
        -d "username=${ADMIN_USER}&password=${ADMIN_PASS}" -o /dev/null

    local token_html
    token_html=$(curl -s -b "$UAT_DIR/cookies.txt" \
        -X POST http://localhost:8080/api/settings/enrollment-tokens \
        -d "label=uat-auto&max_uses=1000&ttl=86400")
    local enroll_token
    enroll_token=$(echo "$token_html" | grep -oP '[a-f0-9]{64}' | head -1)

    if [ -z "$enroll_token" ]; then
        fail "Failed to create enrollment token"
        exit 1
    fi
    echo "$enroll_token" > "$UAT_DIR/enrollment-token"
    ok "Enrollment token created (saved to $UAT_DIR/enrollment-token)"

    # ── 3. Agent (via gateway) ──────────────────────────────────────────
    echo ""
    echo "[3/3] Starting yuzu-agent (→ gateway :50051)..."
    "$BUILDDIR/agents/core/yuzu-agent" \
        --server localhost:50051 \
        --no-tls \
        --data-dir "$UAT_DIR/agent-data" \
        --plugin-dir "$BUILDDIR/agents/plugins" \
        --log-level info \
        --enrollment-token "$enroll_token" \
        > "$UAT_DIR/agent.log" 2>&1 &
    local agent_pid=$!

    # Wait for registration
    local waited=0
    while ! grep -q "Registered with server" "$UAT_DIR/agent.log" 2>/dev/null; do
        sleep 1
        waited=$((waited + 1))
        if [ "$waited" -ge 15 ]; then
            fail "Agent did not register within 15s. Check $UAT_DIR/agent.log"
            exit 1
        fi
    done
    local session_id
    session_id=$(grep "Registered with server" "$UAT_DIR/agent.log" | grep -oP 'session=[^ ,)]+' | tail -1)
    ok "Agent up (PID $agent_pid) — $session_id"

    # Verify it routed through gateway (gw-session prefix)
    if echo "$session_id" | grep -q "gw-session"; then
        ok "Agent registered via gateway (confirmed by gw-session prefix)"
    else
        warn "Agent may not be routed through gateway ($session_id)"
    fi

    # ── Connectivity tests ──────────────────────────────────────────────
    echo ""
    echo "=== Connectivity Tests ==="

    local tests_passed=0 tests_total=0

    # Test 1: Dashboard reachable
    tests_total=$((tests_total + 1))
    local dash_code
    dash_code=$(curl -s -o /dev/null -w "%{http_code}" -b "$UAT_DIR/cookies.txt" http://localhost:8080/)
    if [ "$dash_code" = "200" ]; then
        ok "Dashboard reachable (HTTP $dash_code)"
        tests_passed=$((tests_passed + 1))
    else
        fail "Dashboard returned HTTP $dash_code"
    fi

    # Test 2: Gateway health (all subsystem checks)
    tests_total=$((tests_total + 1))
    local gw_health
    gw_health=$(curl -s http://localhost:8081/readyz 2>/dev/null || echo '{"status":"error"}')
    if echo "$gw_health" | grep -q '"ready"'; then
        ok "Gateway healthy (all checks pass)"
        tests_passed=$((tests_passed + 1))
    else
        fail "Gateway health: $gw_health"
    fi

    # Test 3: Server metrics show registered agent
    tests_total=$((tests_total + 1))
    local reg_count
    reg_count=$(curl -s http://localhost:8080/metrics | grep -oP 'yuzu_agents_registered_total \K[0-9]+' || echo "0")
    if [ "$reg_count" -ge 1 ]; then
        ok "Server sees $reg_count registered agent(s)"
        tests_passed=$((tests_passed + 1))
    else
        fail "Server shows 0 registered agents"
    fi

    # Test 4: Gateway metrics show agent connection
    tests_total=$((tests_total + 1))
    local gw_agents
    gw_agents=$(curl -s http://localhost:9568/metrics | grep -oP 'yuzu_gw_agents_connected_total\{[^}]*\} \K[0-9]+' || echo "0")
    if [ "$gw_agents" -ge 1 ]; then
        ok "Gateway shows $gw_agents connected agent(s)"
        tests_passed=$((tests_passed + 1))
    else
        fail "Gateway shows 0 connected agents"
    fi

    # Test 5: help command (server-side, via dashboard endpoint)
    echo ""
    echo "=== Command Tests ==="
    tests_total=$((tests_total + 1))
    info "Sending 'help' command..."
    local help_html
    help_html=$(curl -s -b "$UAT_DIR/cookies.txt" \
        -X POST http://localhost:8080/api/dashboard/execute \
        -d "instruction=help&scope=__all__" 2>/dev/null)
    local plugin_count
    plugin_count=$(echo "$help_html" | grep -o 'result-row' | wc -l)
    if [ "$plugin_count" -gt 0 ]; then
        ok "help: $plugin_count plugin actions listed"
        tests_passed=$((tests_passed + 1))
    else
        fail "help: no plugin actions returned"
    fi

    # Test 6: os_info command (full round-trip: server → gateway → agent → gateway → server)
    tests_total=$((tests_total + 1))
    info "Sending 'os_info os_name' via gateway command fanout..."
    local cmd_resp
    cmd_resp=$(curl -s -b "$UAT_DIR/cookies.txt" \
        -X POST http://localhost:8080/api/command \
        -H "Content-Type: application/json" \
        -d '{"plugin":"os_info","action":"os_name"}')
    local cmd_id
    cmd_id=$(echo "$cmd_resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('command_id',''))" 2>/dev/null)

    if [ -z "$cmd_id" ]; then
        fail "os_info: failed to dispatch (response: $cmd_resp)"
    else
        info "Command dispatched: $cmd_id"
        # Poll for response (max 15s)
        local os_result="" poll_count=0
        while [ $poll_count -lt 15 ]; do
            sleep 1
            poll_count=$((poll_count + 1))
            os_result=$(curl -s -b "$UAT_DIR/cookies.txt" \
                "http://localhost:8080/api/responses/$cmd_id" | \
                python3 -c "
import sys,json
d=json.load(sys.stdin)
for r in d.get('responses',[]):
    o = r.get('output','')
    if 'os_name|' in o:
        print(o.split('|',1)[1])
        break
" 2>/dev/null)
            [ -n "$os_result" ] && break
        done

        if [ -n "$os_result" ]; then
            ok "os_info: $os_result (round-trip ${poll_count}s)"
            tests_passed=$((tests_passed + 1))
        else
            fail "os_info: no response after ${poll_count}s (command may not have reached agent via gateway)"
            warn "Check server log: grep 'gateway' $UAT_DIR/server.log"
            warn "Check gateway log: tail $UAT_DIR/gateway.log"
        fi
    fi

    # ── Summary ─────────────────────────────────────────────────────────
    echo ""
    if [ "$tests_passed" -eq "$tests_total" ]; then
        echo -e "${GREEN}=== All $tests_total/$tests_total tests passed ===${NC}"
    else
        echo -e "${RED}=== $tests_passed/$tests_total tests passed ===${NC}"
    fi

    echo ""
    echo "╔══════════════════════════════════════════════════╗"
    echo "║              UAT Stack Ready                     ║"
    echo "╠══════════════════════════════════════════════════╣"
    echo "║  Dashboard:  http://localhost:8080               ║"
    printf "║  Login:      %-37s ║\n" "$ADMIN_USER / $ADMIN_PASS"
    echo "║  GW Health:  http://localhost:8081/readyz        ║"
    echo "║  GW Metrics: http://localhost:9568/metrics       ║"
    echo "╠══════════════════════════════════════════════════╣"
    echo "║  Agent → GW(:50051) → Server(:50055)  [data]    ║"
    echo "║  Server → GW(:50063) → Agent          [commands]║"
    echo "╠══════════════════════════════════════════════════╣"
    echo "║  Logs:  $UAT_DIR/{server,gateway,agent}.log     ║"
    echo "║  Stop:  bash scripts/linux-start-UAT.sh stop    ║"
    echo "╚══════════════════════════════════════════════════╝"
}

# ── Main ────────────────────────────────────────────────────────────────

case "${1:-start}" in
    start)  start_all ;;
    stop)   kill_stale; echo "UAT stack stopped." ;;
    status) show_status ;;
    *)      echo "Usage: $0 {start|stop|status}"; exit 1 ;;
esac
