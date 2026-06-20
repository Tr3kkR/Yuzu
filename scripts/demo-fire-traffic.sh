#!/usr/bin/env bash
# demo-fire-traffic.sh — light the client→Envoy blue tubes in /viz/fleet.
#
# Drives sustained client→Envoy traffic from the demo client agents to the
# Cedar & Vale Envoy frontend (cv-frontend:8080), then polls the fleet-viz
# topology until the client→envoy tubes render.
#
# WHY script_exec + busybox wget (not http_client): the http_client plugin has
# SSRF protection that rejects private IPs (10/8, 172.16/12, 192.168/16) — and
# every container in the OrbStack/Docker network is on a private IP, so
# http_client refuses to hit cv-frontend by design. busybox wget (already in
# the chiselled agent image — no extra binary) has no such guard, and we run it
# via the script_exec plugin so the traffic is still a dispatched Yuzu
# instruction, not container plumbing.
#
# WHY a loop: the TAR connection sampler reads /proc/net/tcp on a 30–60s cadence
# (kernel eventing for short-lived connections is deferred — #1019). A single
# wget (~70ms) almost never coincides with a sampling tick. So each agent runs
# wget in a loop for the whole fire window, keeping a connection to Envoy
# essentially always ESTABLISHED; once any tick captures it, the fleet-snapshot
# warehouse keeps the tube rendered for up to an hour.
#
# Scope: every CONNECTED LINUX agent that is NOT a Cedar & Vale tier
# (yuzu-frontend/app/db) — i.e. exactly the client fleet. The native macOS
# agent is excluded (it cannot resolve the in-network cv-frontend hostname).
#
# Usage: bash scripts/demo-fire-traffic.sh [--duration N] [--url URL] [--broadcast]
# Env:   DEMO_BASE (default http://localhost:8080), DEMO_USER/DEMO_PASS.
set -uo pipefail

BASE="${DEMO_BASE:-http://localhost:8080}"
DUSER="${DEMO_USER:-admin}"; DPASS="${DEMO_PASS:-adminpassword1}"
URL="http://cv-frontend:8080/public/bg1.webm"
DURATION=120
BROADCAST=0
while [ $# -gt 0 ]; do
  case "$1" in
    --duration) DURATION="$2"; shift 2 ;;
    --url)      URL="$2";      shift 2 ;;
    --broadcast) BROADCAST=1;  shift ;;
    -h|--help)  sed -n '2,30p' "$0" | sed 's/^# \?//'; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 1 ;;
  esac
done

CJ="$(mktemp)"; trap 'rm -f "$CJ"' EXIT
echo "[fire] login $BASE as $DUSER"
curl -fsS -c "$CJ" "$BASE/login" -d "username=$DUSER&password=$DPASS" -o /dev/null \
  || { echo "[fire] login failed — is the stack up?" >&2; exit 1; }

# Per-agent busybox-wget loop that runs for ~DURATION seconds. Single-quoted so
# $(date ...) is evaluated by the agent's busybox sh, not here. script_exec's
# split_args is quote-aware, so the single-quoted loop reaches `sh -c` intact.
LOOP='e=$(( $(date +%s) + '"$DURATION"' )); while [ $(date +%s) -lt $e ]; do wget -q -O /dev/null --timeout=4 '"$URL"'; done'
INSTR="script_exec exec command=/bin/busybox timeout=$((DURATION + 20)) args=\"sh -c '$LOOP'\""

# Enumerate the client fleet (or broadcast).
TARGETS=()
if [ "$BROADCAST" = 1 ]; then
  TARGETS=(__all__); echo "[fire] broadcast mode (__all__)"
else
  while IFS= read -r line; do [ -n "$line" ] && TARGETS+=("$line"); done < <(
    curl -fsS -b "$CJ" "$BASE/api/agents" 2>/dev/null | python3 -c '
import sys, json
try: data = json.load(sys.stdin)
except Exception: sys.exit(0)
rows = data if isinstance(data, list) else (data.get("agents") or data.get("data") or [])
TIERS = {"yuzu-frontend","yuzu-app","yuzu-db"}
for a in rows:
    if not isinstance(a, dict): continue
    aid=a.get("agent_id") or a.get("id") or ""; host=str(a.get("hostname","")).lower()
    osv=str(a.get("ostype") or a.get("os_type") or a.get("os") or a.get("platform") or "").lower()
    if not aid or host in TIERS: continue
    if "darwin" in osv or "mac" in osv: continue
    if a.get("connected", a.get("is_connected", True)) is False: continue
    print(aid)')
  echo "[fire] ${#TARGETS[@]} client agents targeted"
  [ "${#TARGETS[@]}" -eq 0 ] && { echo "[fire] enumeration empty — broadcast fallback"; TARGETS=(__all__); }
fi

echo "[fire] dispatching ${DURATION}s wget-loop to each target..."
for t in "${TARGETS[@]}"; do
  curl -fsS -b "$CJ" -X POST "$BASE/api/dashboard/execute" \
    --data-urlencode "instruction=$INSTR" --data-urlencode "scope=$t" -o /dev/null 2>/dev/null &
done
wait
echo "[fire] loops running on agents; polling topology for client→envoy tubes..."

# Poll the fleet topology until client→frontend internal_fleet edges appear.
deadline=$(( $(date +%s) + DURATION + 30 ))
want=${#TARGETS[@]}; [ "$want" -eq 1 ] && want=25   # broadcast → expect ~25 clients
last=0
while [ "$(date +%s)" -lt "$deadline" ]; do
  sleep 12
  n=$(curl -fsS -b "$CJ" "$BASE/api/v1/viz/fleet/topology" 2>/dev/null | python3 -c '
import sys, json
d=json.load(sys.stdin); M=d["machines"]
hb={m.get("agent_id"):m.get("hostname") for m in M}
feips={ip for m in M if m.get("hostname")=="yuzu-frontend" for ip in (m.get("local_ips") or [])}
TIERS={"yuzu-frontend","yuzu-app","yuzu-db"}
clients=set()
for m in M:
    h=m.get("hostname","")
    if h in TIERS or str(h).endswith(".local"): continue
    for c in (m.get("connections") or []):
        if c.get("scope")!="internal_fleet": continue
        dip=(c.get("dst_addr") or "").replace("::ffff:","")
        if dip in feips or hb.get(c.get("dst_agent_id"))=="yuzu-frontend":
            clients.add(m.get("agent_id")); break
print(len(clients))' 2>/dev/null || echo 0)
  last=$n
  printf '[fire] client→envoy tubes lit: %s / %s\n' "$n" "$want"
  [ "${n:-0}" -ge "$want" ] && break
done
echo "[fire] done — $last client→envoy tubes. Topology: $BASE/viz/fleet"
