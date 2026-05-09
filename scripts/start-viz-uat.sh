#!/usr/bin/env bash
# start-viz-uat.sh -- Stand up the feat/viz-engine UAT stack in containers.
#
# Brings up server + gateway + agent in linux/$ARCH containers (arm64 native on
# Apple Silicon, x64 on Linux). Generates yuzu-server.cfg with hashed admin
# password, builds the three images via Dockerfile.server / Dockerfile.gateway
# / Dockerfile.agent (TARGETARCH-driven), starts server + gateway, issues an
# enrollment token via REST, then starts the agent. Verifies registration.
#
# Usage:
#   bash scripts/start-viz-uat.sh                # full bring-up (build if needed)
#   bash scripts/start-viz-uat.sh stop           # docker compose down -v + clean state
#   bash scripts/start-viz-uat.sh status         # ps + recent logs
#   bash scripts/start-viz-uat.sh fleet-snapshot # dispatch tar.fleet_snapshot to the agent
#
# Environment overrides:
#   VIZ_UAT_DIR           default: /tmp/yuzu-viz-uat
#   VIZ_UAT_AGENTS        default: 1     (compose --scale agent=N)
#   VIZ_UAT_SKIP_BUILD    default: ""    (set to 1 to skip docker build)
#   VIZ_UAT_PLATFORM      default: linux/$(uname -m mapped)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
COMPOSE_FILE="$REPO_ROOT/deploy/docker/docker-compose.viz-uat.yml"

VIZ_UAT_DIR=${VIZ_UAT_DIR:-/tmp/yuzu-viz-uat}
VIZ_UAT_AGENTS=${VIZ_UAT_AGENTS:-1}
VIZ_UAT_SKIP_BUILD=${VIZ_UAT_SKIP_BUILD:-}

ADMIN_USER=admin
ADMIN_PASS=adminpassword1

case "$(uname -m)" in
  arm64|aarch64) DEFAULT_PLATFORM=linux/arm64 ;;
  x86_64|amd64)  DEFAULT_PLATFORM=linux/amd64 ;;
  *) DEFAULT_PLATFORM=linux/$(uname -m) ;;
esac
VIZ_UAT_PLATFORM=${VIZ_UAT_PLATFORM:-$DEFAULT_PLATFORM}

# ── Pretty output ──────────────────────────────────────────────────────────
COLOR_R="\033[31m" COLOR_G="\033[32m" COLOR_Y="\033[33m" COLOR_B="\033[34m" COLOR_0="\033[0m"
ok()    { printf "${COLOR_G}[ok]${COLOR_0} %s\n" "$*"; }
info()  { printf "${COLOR_B}[..]${COLOR_0} %s\n" "$*"; }
warn()  { printf "${COLOR_Y}[!!]${COLOR_0} %s\n" "$*"; }
fail()  { printf "${COLOR_R}[xx]${COLOR_0} %s\n" "$*"; }

# ── Subcommands ────────────────────────────────────────────────────────────

cmd_stop() {
  info "Stopping viz-UAT stack..."
  ( cd "$REPO_ROOT" && docker compose -f "$COMPOSE_FILE" \
      --env-file <(echo "YUZU_ENROLLMENT_TOKEN=stub") \
      down -v --remove-orphans ) || true
  rm -rf "$VIZ_UAT_DIR"
  ok "Stopped + cleaned $VIZ_UAT_DIR"
}

cmd_status() {
  ( cd "$REPO_ROOT" && docker compose -f "$COMPOSE_FILE" \
      --env-file <(echo "YUZU_ENROLLMENT_TOKEN=stub") ps )
  echo ""
  info "Last 20 lines from each service:"
  for svc in server gateway agent; do
    echo "── $svc ──"
    ( cd "$REPO_ROOT" && docker compose -f "$COMPOSE_FILE" \
        --env-file <(echo "YUZU_ENROLLMENT_TOKEN=stub") \
        logs --tail=20 "$svc" 2>/dev/null ) || true
    echo ""
  done
}

cmd_fleet_snapshot() {
  if [ ! -f "$VIZ_UAT_DIR/cookies.txt" ]; then
    fail "$VIZ_UAT_DIR/cookies.txt missing — run start first"
    exit 1
  fi

  # Re-login to refresh the cookie -- the start-time session may have been
  # idle past the inactivity window. Cookie domain is "localhost" (the host
  # name used for login), so all subsequent calls also go via localhost.
  info "Refreshing operator session..."
  curl -fsS -c "$VIZ_UAT_DIR/cookies.txt" \
      "http://localhost:8080/login" \
      -d "username=${ADMIN_USER}&password=${ADMIN_PASS}" -o /dev/null

  info "Looking up registered agents..."
  local agents_json
  agents_json=$(curl -fsS -b "$VIZ_UAT_DIR/cookies.txt" \
      "http://localhost:8080/api/agents" 2>/dev/null)
  local agent_ids_json
  agent_ids_json=$(echo "$agents_json" \
      | python3 -c 'import json,sys; print(json.dumps([a["agent_id"] for a in json.load(sys.stdin)]))')
  local count
  count=$(echo "$agent_ids_json" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))')
  if [ "$count" -lt 1 ]; then
    fail "No registered agents -- run 'bash scripts/start-viz-uat.sh status' to inspect"
    exit 1
  fi
  ok "Found $count registered agent(s)"

  info "Dispatching crossplatform.tar.fleet_snapshot..."
  local resp
  resp=$(curl -fsS -b "$VIZ_UAT_DIR/cookies.txt" \
      -H "Content-Type: application/json" \
      -X POST "http://localhost:8080/api/instructions/crossplatform.tar.fleet_snapshot/execute" \
      -d "{\"agent_ids\":$agent_ids_json}" || true)
  local cmd_id
  cmd_id=$(echo "$resp" | python3 -c \
    'import json,sys;j=json.load(sys.stdin);print(j.get("command_id",""))' 2>/dev/null || true)
  if [ -z "$cmd_id" ]; then
    fail "Could not dispatch tar.fleet_snapshot:"
    fail "  $resp"
    exit 1
  fi
  ok "Dispatched: command_id=$cmd_id  (agents_reached=$(echo "$resp" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("agents_reached",0))'))"

  info "Waiting up to 20s for response..."
  local waited=0 response="" body
  while [ "$waited" -lt 20 ]; do
    body=$(curl -fsS -b "$VIZ_UAT_DIR/cookies.txt" \
        "http://localhost:8080/api/responses/$cmd_id" 2>/dev/null || true)
    if echo "$body" | grep -q '"output"'; then
      response=$body
      break
    fi
    sleep 1
    waited=$((waited + 1))
  done

  if [ -z "$response" ]; then
    fail "Timed out waiting for fleet_snapshot response"
    fail "  curl -b $VIZ_UAT_DIR/cookies.txt 'http://localhost:8080/api/responses/$cmd_id'"
    exit 1
  fi

  ok "Response received. Parsed fleet_snapshot.v1:"
  YUZU_VIZ_RESP="$response" python3 - <<'PY'
import json, os
data = json.loads(os.environ['YUZU_VIZ_RESP'])
rows = data if isinstance(data, list) else data.get('responses', data.get('data', [data]))
if not isinstance(rows, list):
    rows = [rows]
for r in rows:
    out = r.get('output', '')
    try:
        snap = json.loads(out)
        agent_id = r.get('agent_id', '?')
        schema = snap.get('schema')
        minor = snap.get('schema_minor')
        host = snap.get('hostname')
        ips = snap.get('local_ips')
        nproc = len(snap.get('processes', []))
        nconn = len(snap.get('connections', []))
        tp = snap.get('truncated_processes')
        tc = snap.get('truncated_connections')
        print('  agent_id:      ' + str(agent_id))
        print('  schema:        ' + str(schema) + ' (minor=' + str(minor) + ')')
        print('  hostname:      ' + str(host))
        print('  local_ips:     ' + str(ips))
        print('  processes:     ' + str(nproc) + ' entries (truncated=' + str(tp) + ')')
        print('  connections:   ' + str(nconn) + ' entries (truncated=' + str(tc) + ')')
        if snap.get('process_source_paused'):
            print('  process_source_paused: TRUE')
        if snap.get('tcp_source_paused'):
            print('  tcp_source_paused:     TRUE')
        if nproc:
            sample = [(p['pid'], p['name'], p.get('user', '')) for p in snap['processes'][:5]]
            print('  first 5 procs: ' + str(sample))
        if nconn:
            sample = [(c['proto'], c['local_addr'] + ':' + str(c['local_port']),
                       '->', c['remote_addr'] + ':' + str(c['remote_port']),
                       c['state']) for c in snap['connections'][:5]]
            print('  first 5 conns: ' + str(sample))
        print()
    except Exception as e:
        print('  (unparseable output, len=' + str(len(out)) + ': ' + str(e) + ')')
        print('  raw[:300]: ' + out[:300])
PY
}

# ── Generate server config ─────────────────────────────────────────────────

generate_config() {
  mkdir -p "$VIZ_UAT_DIR/viz-uat"
  python3 -c "
import hashlib, os
salt = os.urandom(16)
dk = hashlib.pbkdf2_hmac('sha256', '${ADMIN_PASS}'.encode(), salt, 100000, dklen=32)
print(f'${ADMIN_USER}:admin:{salt.hex()}:{dk.hex()}')
" > "$VIZ_UAT_DIR/viz-uat/yuzu-server.cfg"
  chmod 600 "$VIZ_UAT_DIR/viz-uat/yuzu-server.cfg"
  ok "Generated server config (admin / adminpassword1) at $VIZ_UAT_DIR/viz-uat/yuzu-server.cfg"
}

# ── Build images ───────────────────────────────────────────────────────────

build_images() {
  if [ -n "$VIZ_UAT_SKIP_BUILD" ]; then
    info "VIZ_UAT_SKIP_BUILD=1 — skipping docker build"
    return
  fi

  # vcpkg triplet derived from host arch. Server + agent Dockerfiles take a
  # --build-arg TRIPLET= (default x64-linux, override for arm64-linux).
  local triplet
  case "$VIZ_UAT_PLATFORM" in
    linux/arm64) triplet=arm64-linux ;;
    linux/amd64|linux/x64) triplet=x64-linux ;;
    *) fail "unsupported VIZ_UAT_PLATFORM=$VIZ_UAT_PLATFORM"; exit 1 ;;
  esac
  info "Building images for $VIZ_UAT_PLATFORM (vcpkg triplet=$triplet) — first run is 25-40 min..."
  cd "$REPO_ROOT"

  info "  building yuzu-server-viz-uat:latest ..."
  docker build --platform "$VIZ_UAT_PLATFORM" \
      --build-arg "TRIPLET=$triplet" \
      -t yuzu-server-viz-uat:latest \
      -f deploy/docker/Dockerfile.server .
  ok "  built yuzu-server-viz-uat:latest"

  info "  building yuzu-gateway-viz-uat:latest ..."
  docker build --platform "$VIZ_UAT_PLATFORM" \
      -t yuzu-gateway-viz-uat:latest \
      -f deploy/docker/Dockerfile.gateway .
  ok "  built yuzu-gateway-viz-uat:latest"

  info "  building yuzu-agent-viz-uat:latest ..."
  docker build --platform "$VIZ_UAT_PLATFORM" \
      --build-arg "TRIPLET=$triplet" \
      -t yuzu-agent-viz-uat:latest \
      -f deploy/docker/Dockerfile.agent .
  ok "  built yuzu-agent-viz-uat:latest"
}

# ── Wait helpers ───────────────────────────────────────────────────────────

wait_for_url() {
  local url=$1 desc=$2 timeout=${3:-90}
  local waited=0
  while [ "$waited" -lt "$timeout" ]; do
    if curl -fsS -o /dev/null "$url" 2>/dev/null; then
      ok "$desc reachable ($url)"
      return 0
    fi
    sleep 2
    waited=$((waited + 2))
  done
  fail "$desc not reachable at $url within ${timeout}s"
  return 1
}

# ── Bring-up ───────────────────────────────────────────────────────────────

cmd_start() {
  echo ""
  echo "╔══════════════════════════════════════════════════╗"
  printf '║  Yuzu Viz-UAT (%s) %*s║\n' "$VIZ_UAT_PLATFORM" $((33 - ${#VIZ_UAT_PLATFORM})) " "
  echo "╚══════════════════════════════════════════════════╝"
  echo ""

  # Stop any prior stack
  if [ -d "$VIZ_UAT_DIR" ]; then
    info "Tearing down any prior viz-UAT state..."
    cmd_stop || true
  fi
  mkdir -p "$VIZ_UAT_DIR"

  build_images
  generate_config

  cd "$REPO_ROOT"
  export VIZ_UAT_CONFIG="$VIZ_UAT_DIR/viz-uat/yuzu-server.cfg"

  # Phase 1: server + gateway (no token needed yet)
  info "Starting server + gateway..."
  YUZU_ENROLLMENT_TOKEN=stub docker compose -f "$COMPOSE_FILE" up -d server gateway
  wait_for_url "http://localhost:8080/login" "server dashboard" 90
  wait_for_url "http://localhost:8081/healthz" "gateway healthz" 60

  # Phase 2: login + create enrollment token
  info "Issuing enrollment token..."
  curl -fsS -c "$VIZ_UAT_DIR/cookies.txt" \
      "http://localhost:8080/login" \
      -d "username=${ADMIN_USER}&password=${ADMIN_PASS}" -o /dev/null
  local token_html
  # Field name is `ttl_hours` per settings_routes.cpp:3167; the previous
  # `ttl=86400` was silently dropped (resulting token had time_point::max
  # expiry). 24h is plenty for a UAT session. (gov round 2, DEP-R2-1.)
  token_html=$(curl -fsS -b "$VIZ_UAT_DIR/cookies.txt" \
      -X POST "http://localhost:8080/api/settings/enrollment-tokens" \
      -d "label=viz-uat&max_uses=1000&ttl_hours=24")
  local enroll_token
  enroll_token=$(echo "$token_html" | grep -oE '[a-f0-9]{64}' | head -1)
  if [ -z "$enroll_token" ]; then
    fail "Could not parse enrollment token from /api/settings/enrollment-tokens response"
    fail "  raw: $token_html"
    exit 1
  fi
  echo "$enroll_token" > "$VIZ_UAT_DIR/enrollment-token"
  chmod 600 "$VIZ_UAT_DIR/enrollment-token"
  chmod 600 "$VIZ_UAT_DIR/cookies.txt" 2>/dev/null || true
  ok "Enrollment token issued (saved to $VIZ_UAT_DIR/enrollment-token)"

  # Phase 3: agent(s)
  info "Starting agent (scale=$VIZ_UAT_AGENTS)..."
  YUZU_ENROLLMENT_TOKEN="$enroll_token" \
    docker compose -f "$COMPOSE_FILE" up -d --scale "agent=$VIZ_UAT_AGENTS" agent

  # Wait for at least one agent to register
  info "Waiting for agent registration..."
  local waited=0 reg=0
  while [ "$waited" -lt 60 ]; do
    reg=$(curl -fsS "http://localhost:8080/metrics" 2>/dev/null \
            | awk '/^yuzu_agents_registered_total /{print $2; exit}' || echo 0)
    reg=${reg:-0}
    if awk "BEGIN { exit !($reg >= 1) }"; then
      break
    fi
    sleep 2
    waited=$((waited + 2))
  done
  if ! awk "BEGIN { exit !($reg >= 1) }"; then
    fail "No agents registered within 60s. Check 'bash scripts/start-viz-uat.sh status'"
    exit 1
  fi
  ok "$reg agent(s) registered"

  echo ""
  echo "╔══════════════════════════════════════════════════╗"
  echo "║  Viz-UAT is up                                    ║"
  echo "╚══════════════════════════════════════════════════╝"
  echo ""
  echo "  Dashboard:   http://localhost:8080         (admin / adminpassword1)"
  echo "  Server API:  http://localhost:8080/api/v1/"
  echo "  Gateway:     http://localhost:8081/healthz | http://localhost:9568/metrics"
  echo "  State dir:   $VIZ_UAT_DIR"
  echo ""
  echo "  Exercise tar.fleet_snapshot:"
  echo "    bash scripts/start-viz-uat.sh fleet-snapshot"
  echo ""
  echo "  Tail logs:"
  echo "    docker compose -f $COMPOSE_FILE logs -f"
  echo ""
  echo "  Stop everything:"
  echo "    bash scripts/start-viz-uat.sh stop"
  echo ""
}

# ── Dispatch ────────────────────────────────────────────────────────────────

case "${1:-start}" in
  start)            cmd_start ;;
  stop|down)        cmd_stop ;;
  status|ps)        cmd_status ;;
  fleet-snapshot)   cmd_fleet_snapshot ;;
  *)
    cat <<USAGE
Usage: $(basename "$0") [start|stop|status|fleet-snapshot]

  start            (default) build + start + verify registration
  stop             docker compose down -v + clean \$VIZ_UAT_DIR
  status           docker compose ps + last log lines
  fleet-snapshot   dispatch crossplatform.tar.fleet_snapshot to all agents

Env overrides:
  VIZ_UAT_DIR=/tmp/yuzu-viz-uat
  VIZ_UAT_AGENTS=1     (--scale agent=N)
  VIZ_UAT_SKIP_BUILD=1 (skip docker build)
  VIZ_UAT_PLATFORM=linux/arm64
USAGE
    exit 2
    ;;
esac
