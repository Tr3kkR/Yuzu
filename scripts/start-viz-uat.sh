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
  info "Dispatching crossplatform.tar.fleet_snapshot to all registered agents..."

  # POST to /api/dashboard/run-instruction (or REST /api/v1/instructions/<id>/run).
  # Use the legacy dashboard route since it's the simplest "fan-out to scope" path
  # and start-UAT.sh's connectivity tests use it.
  local cmd_id
  cmd_id=$(curl -s -b "$VIZ_UAT_DIR/cookies.txt" \
      -X POST "http://localhost:8080/api/dashboard/run-instruction" \
      -d "id=crossplatform.tar.fleet_snapshot&scope=__all__" \
      | grep -oE '"command_id"[[:space:]]*:[[:space:]]*"[a-f0-9-]+"' \
      | grep -oE '[a-f0-9-]{36}' | head -1 || true)

  if [ -z "$cmd_id" ]; then
    warn "Could not parse command_id from /api/dashboard/run-instruction; "
    warn "trying REST /api/v1/instructions/.../run as fallback..."
    cmd_id=$(curl -s -b "$VIZ_UAT_DIR/cookies.txt" \
        -X POST "http://localhost:8080/api/v1/instructions/crossplatform.tar.fleet_snapshot/run" \
        -d "scope=__all__" \
        | grep -oE '"command_id"[[:space:]]*:[[:space:]]*"[a-f0-9-]+"' \
        | grep -oE '[a-f0-9-]{36}' | head -1 || true)
  fi

  if [ -z "$cmd_id" ]; then
    fail "Could not dispatch tar.fleet_snapshot. Inspect:"
    fail "  curl -v -b $VIZ_UAT_DIR/cookies.txt -X POST http://localhost:8080/api/dashboard/run-instruction -d 'id=crossplatform.tar.fleet_snapshot&scope=__all__'"
    exit 1
  fi
  ok "Dispatched: command_id=$cmd_id"

  info "Waiting up to 15s for response..."
  local waited=0 response=""
  while [ "$waited" -lt 15 ]; do
    response=$(curl -s -b "$VIZ_UAT_DIR/cookies.txt" \
        "http://localhost:8080/api/v1/responses?instruction_id=$cmd_id" 2>/dev/null || true)
    if echo "$response" | grep -q '"output"'; then
      break
    fi
    sleep 1
    waited=$((waited + 1))
  done

  if ! echo "$response" | grep -q '"output"'; then
    fail "Timed out waiting for fleet_snapshot response"
    fail "  curl -b $VIZ_UAT_DIR/cookies.txt 'http://localhost:8080/api/v1/responses?instruction_id=$cmd_id'"
    exit 1
  fi

  ok "Response received. Output (jq-formatted, key fields):"
  echo "$response" | python3 -c '
import json, sys
data = json.load(sys.stdin)
for r in data if isinstance(data, list) else data.get("responses", [data]):
    out = r.get("output", "")
    try:
        snap = json.loads(out)
        print(f"  agent_id: {r.get(\"agent_id\", \"?\")}")
        print(f"  schema:        {snap.get(\"schema\")}")
        print(f"  schema_minor:  {snap.get(\"schema_minor\")}")
        print(f"  hostname:      {snap.get(\"hostname\")}")
        print(f"  local_ips:     {snap.get(\"local_ips\")}")
        print(f"  processes:     {len(snap.get(\"processes\", []))} entries (truncated={snap.get(\"truncated_processes\")})")
        print(f"  connections:   {len(snap.get(\"connections\", []))} entries (truncated={snap.get(\"truncated_connections\")})")
        if snap.get("process_source_paused"): print("  process_source_paused: TRUE")
        if snap.get("tcp_source_paused"):     print("  tcp_source_paused:     TRUE")
        print(f"  first 3 processes: {[(p[\"pid\"], p[\"name\"]) for p in snap.get(\"processes\", [])[:3]]}")
        print(f"  first 3 conns:     {[(c[\"proto\"], c[\"local_addr\"], c[\"local_port\"], c[\"remote_addr\"], c[\"remote_port\"]) for c in snap.get(\"connections\", [])[:3]]}")
        print()
    except Exception as e:
        print(f"  (unparseable output: {e})")
        print(f"  raw: {out[:200]}")
'
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
  info "Building images for $VIZ_UAT_PLATFORM (this can take 25-40 min on first run)..."
  cd "$REPO_ROOT"

  # buildx is required for --platform; Docker Desktop installs it by default.
  for svc_dockerfile in \
      "yuzu-server-viz-uat:latest:deploy/docker/Dockerfile.server" \
      "yuzu-gateway-viz-uat:latest:deploy/docker/Dockerfile.gateway" \
      "yuzu-agent-viz-uat:latest:deploy/docker/Dockerfile.agent"; do
    local image=${svc_dockerfile%%:latest:*}:latest
    local dockerfile=${svc_dockerfile##*:latest:}
    info "  building $image ..."
    docker build \
        --platform "$VIZ_UAT_PLATFORM" \
        -t "$image" \
        -f "$dockerfile" \
        .
    ok "  built $image"
  done
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
  token_html=$(curl -fsS -b "$VIZ_UAT_DIR/cookies.txt" \
      -X POST "http://localhost:8080/api/settings/enrollment-tokens" \
      -d "label=viz-uat&max_uses=1000&ttl=86400")
  local enroll_token
  enroll_token=$(echo "$token_html" | grep -oE '[a-f0-9]{64}' | head -1)
  if [ -z "$enroll_token" ]; then
    fail "Could not parse enrollment token from /api/settings/enrollment-tokens response"
    fail "  raw: $token_html"
    exit 1
  fi
  echo "$enroll_token" > "$VIZ_UAT_DIR/enrollment-token"
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
