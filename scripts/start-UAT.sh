#!/usr/bin/env bash
# start-UAT.sh — Start a full Yuzu UAT environment on Linux or macOS.
#
# Cross-platform replacement for the historical linux-start-UAT.sh.
# linux-start-UAT.sh remains as a backward-compat shim that execs this
# script. Internals branch on host:
#   - port checks via lsof (works on both BSD and Linux) — see
#     scripts/test/_portable.sh
#   - grep -oE rather than -oP (BSD grep has no Perl regex)
#   - awk replacements for grep -oP '\K' lookbehind tricks
# Linux behaviour, ports, exit semantics are unchanged.
#
# Topology (all traffic flows through the gateway):
#   Agent ──→ Gateway(:50051) ──→ Server(:50055 upstream)
#   (single-host UAT: server's direct agent listener moved to :50054 to
#    free :50051 for the gateway; in production these run on separate hosts)
#                                   │
#   Server ──→ Gateway(:50063) ──→ Agent   (command fanout)
#
# Ports:
#   Server:   :50054 agent gRPC    :50055 gateway upstream
#             :50052 mgmt gRPC     :8080  web dashboard
#   Gateway:  :50051 agent-facing  :50063 mgmt (command forwarding)
#             :9568  metrics       :8081  health
#
# Usage:
#   bash scripts/start-UAT.sh          # start + verify
#   bash scripts/start-UAT.sh stop     # kill all
#   bash scripts/start-UAT.sh status   # show running processes

set -euo pipefail

YUZU_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Per-OS canonical build dir (see CLAUDE.md "Per-OS build directory convention").
# This script is named linux-start-UAT.sh but defaults sensibly on macOS too;
# WSL2 falls under Linux. Override with YUZU_BUILDDIR=path.
if [[ -n "${YUZU_BUILDDIR:-}" ]]; then
    BUILDDIR="$YUZU_BUILDDIR"
elif [[ "$(uname -s)" == "Darwin" ]]; then
    BUILDDIR="$YUZU_ROOT/build-macos"
else
    BUILDDIR="$YUZU_ROOT/build-linux"
fi
GATEWAY_DIR="$YUZU_ROOT/gateway"
UAT_DIR="/tmp/yuzu-uat"

# Cross-platform helpers: port_listening, host_os.
# shellcheck source=scripts/test/_portable.sh
. "$YUZU_ROOT/scripts/test/_portable.sh"

ADMIN_USER="admin"
ADMIN_PASS='YuzuUatAdmin1!'

# ── Optional: launch the agent under a dedicated unprivileged account.
#
# When `--as-user USER` is passed, the yuzu-agent process is launched
# via `sudo -u USER -H env ...` instead of as the current user. This
# exercises the privilege model defined in docs/agent-privilege-model.md
# end-to-end: the agent itself is unprivileged, but the quarantine /
# services / firewall plugins shell out via `sudo -n` to the narrow
# NOPASSWD entries in /etc/sudoers.d/yuzu-agent.
#
# Prerequisites the script verifies before launching:
#   1. USER exists (`id USER`)
#   2. /etc/sudoers.d/yuzu-agent is present (proxy for "install-agent-user.sh
#      has been run")
#   3. USER can read the agent binary at $BUILDDIR/agents/core/yuzu-agent
#   4. USER can read the plugin dir at $BUILDDIR/agents/plugins
#   5. USER can write to /tmp/yuzu-uat/agent-data (the data dir)
#
# The first failure prints a friendly fix command and exits non-zero
# rather than starting an agent that will crash on first plugin call.
AGENT_AS_USER=""

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

    # Erlang BEAM (gateway). Match by yuzu_gw release path or node name
    # rather than beam.smp — release scripts rewrite cmdline so the binary
    # name doesn't appear in /proc/$pid/cmdline.
    local beam_pids
    beam_pids=$(pgrep -f "yuzu_gw[/_]" 2>/dev/null || true)
    if [ -n "$beam_pids" ]; then
        echo "$beam_pids" | xargs kill -9 2>/dev/null || true
        ok "Killed yuzu_gw beam (PIDs: $(echo $beam_pids | tr '\n' ' '))"
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
    # lsof is portable across BSD/Linux; ss is iproute2-only. Iterate the
    # ports we care about and print one row per listener so the output is
    # the same shape on both OSes.
    local _any=0 _p _line
    for _p in 50051 50052 50054 50055 50063 8080 8081 9568; do
        _line=$(lsof -iTCP:"$_p" -sTCP:LISTEN -P -n 2>/dev/null | tail -n +2)
        if [ -n "$_line" ]; then
            echo "$_line"
            _any=1
        fi
    done
    [ "$_any" -eq 0 ] && echo "  (none)"
}

# ── Wait for port ───────────────────────────────────────────────────────

wait_for_port() {
    local port=$1 name=$2 timeout=${3:-15}
    local elapsed=0
    while ! port_listening "$port"; do
        sleep 1
        elapsed=$((elapsed + 1))
        if [ "$elapsed" -ge "$timeout" ]; then
            fail "$name did not bind to :$port within ${timeout}s"
            return 1
        fi
    done
    # Surface cold-start duration so a future bump (Guardian PRs add
    # MigrationRunners) shows up as a leading indicator before the
    # next timeout breach. SRE-2.
    echo "  ✓ $name bound to :$port in ${elapsed}s"
    return 0
}

# ── --as-user pre-flight checks ────────────────────────────────────────
#
# Run a few cheap probes before we attempt to spawn the agent under a
# different account. These catch the common mistakes (forgot to run
# install-agent-user.sh, build dir not traversable by the target user,
# data dir not writable) and turn them into one-line fix instructions.
#
# Returns 0 if everything looks good, non-zero with a printed reason
# otherwise. Caller is expected to exit 1 on failure.

verify_as_user_prereqs() {
    local target_user="$1"
    local errs=0

    # 0. The caller's sudo cache must be primed for the rest of these
    # probes to be meaningful. `sudo -u $target_user -n test ...` fails
    # for TWO unrelated reasons that we'd otherwise conflate:
    #   - target user can't read the file       (the actual permission probe)
    #   - caller's sudo timestamp is stale     (no password cached yet)
    # Probe with a no-op `sudo -n true` first. If that fails, we know
    # we're in case 2 and bail with a single actionable instruction
    # rather than a misleading "binary not readable" cascade.
    if ! sudo -n true 2>/dev/null; then
        fail "sudo cache is empty — pre-flight needs to probe as '$target_user'"
        info "  fix: sudo -v   (then re-run this command)"
        return 1
    fi

    # 1. User exists
    if ! id "$target_user" >/dev/null 2>&1; then
        fail "user '$target_user' does not exist on this host"
        info "  fix: sudo bash scripts/install-agent-user.sh"
        return 1
    fi
    ok "user '$target_user' exists ($(id "$target_user" | tr ',' ' ' | head -c 80))"

    # 2. Sudoers grant present (proxy for "install script ran successfully")
    if [ ! -f /etc/sudoers.d/yuzu-agent ]; then
        fail "/etc/sudoers.d/yuzu-agent is missing — quarantine and other"
        fail "  privileged plugins will not work"
        info "  fix: sudo bash scripts/install-agent-user.sh"
        ((errs++))
    else
        ok "/etc/sudoers.d/yuzu-agent installed"
    fi

    # 3. Agent binary readable by target user. The probe runs as root
    # (sudo -n) then drops to target_user; we test BOTH the binary's
    # readability AND every parent directory's traverse permission,
    # because `_yuzu` reading the binary fails if any ancestor has the
    # other-execute bit clear. macOS Sequoia ships /Users/<name> at
    # mode 0750 owner <name>:staff — `_yuzu` is not in staff, can't
    # traverse, can't reach $BUILDDIR. Same trap exists on Linux for
    # any path under /home/<other-user>/.
    local agent_bin="$BUILDDIR/agents/core/yuzu-agent"
    if ! sudo -u "$target_user" -n test -r "$agent_bin" 2>/dev/null; then
        fail "agent binary at $agent_bin is not readable by '$target_user'"
        # Walk up the path and identify the first ancestor that's not
        # traversable, so the operator's fix is precise.
        local p="$agent_bin"
        local first_blocker=""
        while [ "$p" != "/" ] && [ -n "$p" ]; do
            p="$(dirname "$p")"
            if ! sudo -u "$target_user" -n test -x "$p" 2>/dev/null; then
                first_blocker="$p"
                break
            fi
        done
        if [ -n "$first_blocker" ]; then
            fail "  blocking traversal at: $first_blocker"
            info "  fix (dev box):  sudo chmod o+x \"$first_blocker\""
        fi
        info "  fix (build dir): chmod -R go+rX \"$BUILDDIR\""
        info "  fix (production): install the agent under /usr/local/bin via meson install"
        ((errs++))
    else
        ok "agent binary readable by '$target_user'"
    fi

    # 4. Plugin dir readable
    local plugin_dir="$BUILDDIR/agents/plugins"
    if ! sudo -u "$target_user" -n test -r "$plugin_dir" 2>/dev/null; then
        fail "plugin dir at $plugin_dir is not readable by '$target_user'"
        info "  fix: chmod -R go+rX \"$BUILDDIR\"  (one-time, dev box only)"
        ((errs++))
    else
        ok "plugin dir readable by '$target_user'"
    fi

    # 5. Test that sudo -n actually works FROM the target user (NOPASSWD
    # in /etc/sudoers.d/yuzu-agent). Run a harmless probe: sudo -u USER -n
    # /sbin/pfctl -s rules (macOS) — that's a read-only command we already
    # have a sudoers entry for. The double-sudo (we as nathan run sudo to
    # become _yuzu, who then runs sudo to become root) needs both halves
    # to be NOPASSWD; the inner half is the install-script's grant.
    local probe_cmd
    if [ "$(uname -s)" = "Darwin" ]; then
        probe_cmd="/sbin/pfctl -s rules"
    else
        probe_cmd="/usr/sbin/iptables -L -n"
    fi
    if ! sudo -u "$target_user" -n sudo -n $probe_cmd >/dev/null 2>&1; then
        warn "'$target_user' cannot exercise its sudoers grant non-interactively"
        warn "  quarantine + services.set_start_mode + flush_dns will fail"
        info "  fix: sudo bash scripts/install-agent-user.sh --check"
        # Not a hard failure — agent will still start, just degraded
    else
        ok "'$target_user' can sudo -n $probe_cmd (privileged plugins will work)"
    fi

    [ "$errs" -eq 0 ]
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
    printf '║         Yuzu UAT Environment (%-19s ║\n' "$(host_os))"
    echo "╚══════════════════════════════════════════════════╝"
    echo ""

    # ── Preflight checks ────────────────────────────────────────────────
    if [ ! -f "$BUILDDIR/server/core/yuzu-server" ]; then
        fail "yuzu-server not found at $BUILDDIR/server/core/yuzu-server"
        echo "    Run: meson compile -C $(basename "$BUILDDIR")"
        exit 1
    fi
    if [ ! -f "$BUILDDIR/agents/core/yuzu-agent" ]; then
        fail "yuzu-agent not found at $BUILDDIR/agents/core/yuzu-agent"
        echo "    Run: meson compile -C $(basename "$BUILDDIR")"
        exit 1
    fi
    if [ ! -d "$GATEWAY_DIR/_build/prod/rel/yuzu_gw" ]; then
        fail "Gateway release not built at $GATEWAY_DIR/_build/prod/rel/yuzu_gw"
        echo "    Run: cd gateway && rebar3 as prod release"
        exit 1
    fi

    ok "Preflight checks passed"

    # ── Kill stale ──────────────────────────────────────────────────────
    kill_stale

    # ── Clean UAT state ─────────────────────────────────────────────────
    #
    # If a prior run used --as-user, the agent left files owned by that
    # user (typically _yuzu) under $UAT_DIR. The current user can't `rm`
    # them. Try plain rm first; on failure, fall back to `sudo -n rm -rf`
    # which works if the operator's sudo cache is still warm. If both
    # fail, fall through to mkdir -p which will succeed for the new
    # subdirectories — the leftover files are mostly harmless (they get
    # overwritten by this run), and the operator gets a hint to rerun
    # `sudo -v` if they care about a fully fresh state.
    if ! rm -rf "$UAT_DIR" 2>/dev/null; then
        if sudo -n rm -rf "$UAT_DIR" 2>/dev/null; then
            ok "Cleared $UAT_DIR (had files owned by another user; sudo cleanup)"
        else
            warn "Could not fully clear $UAT_DIR (some files owned by another user)"
            warn "  manual fix: sudo rm -rf $UAT_DIR"
        fi
    fi
    mkdir -p "$UAT_DIR/agent-data"

    # ── Generate credentials ────────────────────────────────────────────
    generate_config
    ok "Generated server config ($ADMIN_USER / $ADMIN_PASS)"

    # ── 1. Server ───────────────────────────────────────────────────────
    # NOTE: --listen is moved off the default :50051 to :50054 because the
    # gateway will bind :50051 for agent-facing gRPC on this same host. In
    # multi-host production deployments the server can keep :50051 because
    # the gateway lives on a separate box; in single-host UAT we deconflict
    # by moving the server's direct agent listener out of the way. The
    # server's :50054 listener stays open for any direct agent connections
    # but in this UAT topology agents connect through the gateway only.
    echo ""
    echo "[1/3] Starting yuzu-server..."
    "$BUILDDIR/server/core/yuzu-server" \
        --no-tls \
        --no-https \
        --listen 0.0.0.0:50054 \
        --gateway-upstream 0.0.0.0:50055 \
        --gateway-mode \
        --gateway-command-addr localhost:50063 \
        --web-address 0.0.0.0 \
        --log-level info \
        --metrics-no-auth \
        --config "$UAT_DIR/yuzu-server.cfg" \
        > "$UAT_DIR/server.log" 2>&1 &
    local server_pid=$!

    if ! wait_for_port 8080 "yuzu-server" 30; then
        fail "Server failed to start. Check $UAT_DIR/server.log"
        exit 1
    fi
    ok "Server up (PID $server_pid)"
    info "Dashboard http://localhost:8080"
    info "Direct agent gRPC :50054  |  Gateway upstream :50055  |  Mgmt :50052"

    # ── 2. Gateway ──────────────────────────────────────────────────────
    echo ""
    echo "[2/3] Starting Erlang gateway..."
    local gw_rel="$GATEWAY_DIR/_build/prod/rel/yuzu_gw"
    if [ -x "$gw_rel/bin/yuzu_gw" ]; then
        ("$gw_rel/bin/yuzu_gw" foreground \
            > "$UAT_DIR/gateway.log" 2>&1) &
        local gw_pid=$!
    else
        fail "Gateway release not found at $gw_rel"
        fail "Run: cd gateway && rebar3 as prod release"
        exit 1
    fi

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
    # -oE rather than -oP so this works with BSD grep on macOS — fixed-
    # length hex doesn't need any Perl-specific regex features.
    enroll_token=$(echo "$token_html" | grep -oE '[a-f0-9]{64}' | head -1)

    if [ -z "$enroll_token" ]; then
        fail "Failed to create enrollment token"
        exit 1
    fi
    echo "$enroll_token" > "$UAT_DIR/enrollment-token"
    ok "Enrollment token created (saved to $UAT_DIR/enrollment-token)"

    # ── 3. Agent (via gateway) ──────────────────────────────────────────
    echo ""
    if [ -n "$AGENT_AS_USER" ]; then
        echo "[3/3] Starting yuzu-agent (→ gateway :50051) as user '$AGENT_AS_USER'..."
        verify_as_user_prereqs "$AGENT_AS_USER" || exit 1
        # Make agent-data writable by the runtime user; install-agent-user.sh
        # creates the canonical state dirs under /Library/Application Support/Yuzu
        # (or /var/lib/yuzu-agent on Linux), but the UAT script defaults to
        # $UAT_DIR/agent-data so it survives `start-UAT.sh stop` cleanups
        # without touching the production state path. Re-own the UAT dir
        # so the agent can write to it.
        mkdir -p "$UAT_DIR/agent-data"
        chown -R "$AGENT_AS_USER" "$UAT_DIR/agent-data" 2>/dev/null \
            || sudo -n chown -R "$AGENT_AS_USER" "$UAT_DIR/agent-data" 2>/dev/null \
            || warn "could not chown $UAT_DIR/agent-data to $AGENT_AS_USER"

        # `-H` resets HOME to the target user's home (which is /var/empty
        # for _yuzu — that's intentional, the agent doesn't need a HOME).
        # `env -i` would scrub everything; we keep PATH so sudo -n itself
        # works, and propagate YUZU_* envs so debug knobs survive.
        sudo -u "$AGENT_AS_USER" -H \
            env PATH="/usr/bin:/bin:/usr/sbin:/sbin" \
                YUZU_AGENT_LAUNCHED_AS="$AGENT_AS_USER" \
            "$BUILDDIR/agents/core/yuzu-agent" \
            --server localhost:50051 \
            --no-tls \
            --data-dir "$UAT_DIR/agent-data" \
            --plugin-dir "$BUILDDIR/agents/plugins" \
            --log-level info \
            --enrollment-token "$enroll_token" \
            > "$UAT_DIR/agent.log" 2>&1 &
    else
        echo "[3/3] Starting yuzu-agent (→ gateway :50051)..."
        "$BUILDDIR/agents/core/yuzu-agent" \
            --server localhost:50051 \
            --no-tls \
            --data-dir "$UAT_DIR/agent-data" \
            --plugin-dir "$BUILDDIR/agents/plugins" \
            --log-level info \
            --enrollment-token "$enroll_token" \
            > "$UAT_DIR/agent.log" 2>&1 &
    fi
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
    session_id=$(grep "Registered with server" "$UAT_DIR/agent.log" | grep -oE 'session=[^ ,)]+' | tail -1)
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

    # Test 2.5 (#620): /api/health alias parity with /health.
    # Both must return 200 AND identical JSON without auth so monitoring
    # integrations using either path keep working. The body-equality check
    # (governance Gate 7, consistency S3) catches a future regression where
    # the dual-mount lambda is split and one route diverges silently.
    tests_total=$((tests_total + 1))
    local h1 h2 c1 c2 b1 b2
    h1=$(curl -s -w "\n%{http_code}" --fail-with-body http://localhost:8080/health 2>/dev/null)
    h2=$(curl -s -w "\n%{http_code}" --fail-with-body http://localhost:8080/api/health 2>/dev/null)
    c1=$(printf '%s\n' "$h1" | tail -n1)
    c2=$(printf '%s\n' "$h2" | tail -n1)
    # Strip the trailing status code line to get the JSON body for comparison.
    b1=$(printf '%s\n' "$h1" | sed '$d')
    b2=$(printf '%s\n' "$h2" | sed '$d')
    if [ "$c1" = "200" ] && [ "$c2" = "200" ] && [ "$b1" = "$b2" ]; then
        ok "/health and /api/health return 200 with identical JSON (alias works)"
        tests_passed=$((tests_passed + 1))
    elif [ "$c1" != "200" ] || [ "$c2" != "200" ]; then
        fail "/health=$c1, /api/health=$c2 (#620 regression)"
    else
        fail "/health and /api/health diverged (handler split — #620 regression)"
    fi

    # Test 3: Server metrics show registered agent
    tests_total=$((tests_total + 1))
    local reg_count
    # awk replaces grep -oP '\K' (lookbehind) which BSD grep lacks.
    reg_count=$(curl -s http://localhost:8080/metrics | awk '/^yuzu_agents_registered_total /{print $2; exit}')
    [ -z "$reg_count" ] && reg_count=0
    if [ "$reg_count" -ge 1 ]; then
        ok "Server sees $reg_count registered agent(s)"
        tests_passed=$((tests_passed + 1))
    else
        fail "Server shows 0 registered agents"
    fi

    # Test 4: Gateway metrics show agent connection
    tests_total=$((tests_total + 1))
    local gw_agents
    gw_agents=$(curl -s http://localhost:9568/metrics | awk '/^yuzu_gw_agents_connected_total\{/{print $2; exit}')
    [ -z "$gw_agents" ] && gw_agents=0
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
        UAT_TEST_RESULT=0
    else
        echo -e "${RED}=== $tests_passed/$tests_total tests passed ===${NC}"
        UAT_TEST_RESULT=1
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
    echo "║  Stop:  bash scripts/start-UAT.sh stop          ║"
    echo "╚══════════════════════════════════════════════════╝"

    # Exit non-zero if any connectivity test failed. Callers (notably the
    # /test skill's Phase 4) rely on the exit code to determine whether the
    # stack is genuinely healthy or just listening on its ports.
    return ${UAT_TEST_RESULT:-0}
}

# ── Main ────────────────────────────────────────────────────────────────

# Parse optional flags BEFORE the action verb. Supported flags:
#   --as-user USER   launch yuzu-agent under USER via sudo -u
ACTION=""
while [ $# -gt 0 ]; do
    case "$1" in
        --as-user)  AGENT_AS_USER="$2"; shift 2 ;;
        --as-user=*) AGENT_AS_USER="${1#--as-user=}"; shift ;;
        -h|--help)
            cat <<EOF
Usage: $0 [options] {start|stop|status}

Options:
  --as-user USER       Launch yuzu-agent under the named system user via
                       sudo -u (default: current user). Pre-flight checks
                       verify the user, sudoers entry, and read access to
                       BUILDDIR before launching. Requires install-agent-user.sh
                       to have been run.

Actions:
  start                Bring up server + gateway + agent (default)
  stop                 Kill all Yuzu processes
  status               Show running processes + listening ports

Examples:
  bash scripts/start-UAT.sh
  bash scripts/start-UAT.sh --as-user _yuzu
  bash scripts/start-UAT.sh stop
EOF
            exit 0 ;;
        start|stop|status)
            ACTION="$1"; shift ;;
        *)
            echo "unknown arg: $1" >&2
            echo "use --help for usage." >&2
            exit 1 ;;
    esac
done

case "${ACTION:-start}" in
    start)  start_all ;;
    stop)   kill_stale; echo "UAT stack stopped." ;;
    status) show_status ;;
    *)      echo "Usage: $0 [options] {start|stop|status}"; exit 1 ;;
esac
