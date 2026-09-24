#!/usr/bin/env bash
# ha-readyz-scenarios.sh — WS-9 failover scenarios for HA WS-8 (ADR-2002 §12).
#
# Boots a REAL yuzu-server against a throwaway Postgres container and proves
# the /readyz contract a load balancer relies on:
#
#   A. frozen primary   `docker pause` the database (the kernel keeps ACKing, so
#                       no socket timeout fires) -> /readyz 503 within kStaleAfter
#                       (15s) + margin. The probe's own client-side deadlines
#                       normally catch it first (query 2s, then reconnect 5s:
#                       two failures -> pg=unreachable); pg=stale is the backstop
#                       if a tick ever wedged. /livez stays 200 (never restart a
#                       replica for a database outage); unpause -> 200 again.
#   B. refused primary  stop the database container (connection refused) ->
#                       /readyz 503 pg=unreachable within kFailThreshold x
#                       (kProbeInterval + tick) + margin; start it -> 200.
#   C. drain            SIGTERM a server started with --shutdown-drain-seconds 5:
#                       /readyz 503 "draining" at once, while /livez and ordinary
#                       routes keep answering for the whole grace window, then
#                       the process exits.
#
# Before WS-8, scenario A stayed green indefinitely and C closed the listener
# immediately (see pg_reachability_probe.hpp / shutdown_drain_rules.hpp).
#
# Requires: docker, curl, python3, openssl and a built yuzu-server. Exits 0 only
# when every scenario passes. Ports and container names are salted per run —
# the self-hosted CI runners share one OS identity (#1871).
#
# usage: ha-readyz-scenarios.sh [--server-bin PATH]
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
YUZU_ROOT="$(cd "$HERE/../.." && pwd)"
SERVER_BIN="${YUZU_ROOT}/build-linux/server/core/yuzu-server"
PG_IMAGE="${YUZU_HA_READYZ_PG_IMAGE:-postgres:18.4-bookworm@sha256:efef99e1558f86089bc84bece29208c0777a185ff717ec7fa288a652ce2d0adf}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --server-bin) SERVER_BIN="$2"; shift 2 ;;
        -h|--help)    sed -n '2,27p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
[[ -x "$SERVER_BIN" ]] || { echo "no server binary at $SERVER_BIN — build it, or pass --server-bin" >&2; exit 2; }

free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'; }
WEB="$(free_port)"; GRPC="$(free_port)"; MGMT="$(free_port)"; PGPORT="$(free_port)"

RIG="$(mktemp -d -t yuzu_ha_readyz.XXXXXX)"
PG="yuzu-ha-readyz-pg-$$-$RANDOM"
SERVER_PID=""
FAILS=0

cleanup() {
    [[ -n "$SERVER_PID" ]] && kill -KILL "$SERVER_PID" 2>/dev/null
    docker unpause "$PG" >/dev/null 2>&1
    docker rm -f "$PG" >/dev/null 2>&1
    rm -rf "$RIG"
}
trap cleanup EXIT

pass() { echo "  PASS  $*"; }
fail() { echo "  FAIL  $*"; FAILS=$((FAILS + 1)); }

code()  { curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://127.0.0.1:${WEB}$1"; }
body()  { curl -s --max-time 3 "http://127.0.0.1:${WEB}$1"; }

# wait_for <path> <http-code> <timeout-s> [body-substring] — echoes seconds taken.
wait_for() {
    local path="$1" want="$2" limit="$3" needle="${4:-}" start now
    start=$(date +%s)
    while :; do
        if [[ "$(code "$path")" == "$want" ]] && { [[ -z "$needle" ]] || body "$path" | grep -q -- "$needle"; }; then
            now=$(date +%s); echo $((now - start)); return 0
        fi
        now=$(date +%s)
        (( now - start >= limit )) && { echo $((now - start)); return 1; }
        sleep 0.5
    done
}

PG_PASS="$(openssl rand -hex 24)"
docker run -d --name "$PG" -e POSTGRES_USER=yuzu -e POSTGRES_PASSWORD="$PG_PASS" -e POSTGRES_DB=yuzu \
    -p "127.0.0.1:${PGPORT}:5432" "$PG_IMAGE" -c fsync=off >/dev/null || exit 2
pg_up() {
    for _ in $(seq 1 60); do
        docker exec "$PG" pg_isready -h 127.0.0.1 -U yuzu -d yuzu >/dev/null 2>&1 && return 0
        sleep 1
    done
    return 1
}
pg_up || { echo "postgres did not start" >&2; exit 2; }
DSN="postgresql://yuzu:${PG_PASS}@127.0.0.1:${PGPORT}/yuzu"

python3 -c "
import hashlib, os
salt = os.urandom(16)
dk = hashlib.pbkdf2_hmac('sha256', b'testpass123', salt, 100000, dklen=32)
print(f'admin:admin:{salt.hex()}:{dk.hex()}')" > "$RIG/yuzu-server.cfg"
chmod 600 "$RIG/yuzu-server.cfg"

boot() { # $@ = extra server flags
    "$SERVER_BIN" --listen "127.0.0.1:${GRPC}" --no-tls --no-https --no-default-certs \
        --web-address 127.0.0.1 --web-port "$WEB" --management "127.0.0.1:${MGMT}" \
        --postgres-dsn "$DSN" --config "$RIG/yuzu-server.cfg" --data-dir "$RIG" \
        --ca-dir "$RIG/certs" "$@" >> "$RIG/server.log" 2>&1 &
    SERVER_PID=$!
    if ! wait_for /readyz 200 90 >/dev/null; then
        echo "server never became ready; /readyz says: $(body /readyz)" >&2
        tail -20 "$RIG/server.log" >&2
        return 1
    fi
}

echo "== boot"
boot || exit 1
pass "server ready (web :$WEB, pg :$PGPORT)"

echo "== A: frozen primary (docker pause)"
docker pause "$PG" >/dev/null
if t=$(wait_for /readyz 503 20 '"pg":"'); then pass "/readyz 503 $(body /readyz | grep -o '"pg":"[a-z_]*"') after ${t}s (bound: kStaleAfter 15s + margin)"
else fail "/readyz not 503 within 20s: $(body /readyz)"; fi
[[ "$(code /livez)" == 200 ]] && pass "/livez still 200 while the database is frozen" || fail "/livez not 200 during the outage"
docker unpause "$PG" >/dev/null
if t=$(wait_for /readyz 200 20); then pass "/readyz 200 again ${t}s after unpause"
else fail "/readyz did not recover within 20s: $(body /readyz)"; fi

echo "== B: refused primary (container stopped)"
docker stop -t 5 "$PG" >/dev/null
if t=$(wait_for /readyz 503 20 '"pg":"'); then pass "/readyz 503 $(body /readyz | grep -o '"pg":"[a-z_]*"') after ${t}s"
else fail "/readyz not 503 within 20s: $(body /readyz)"; fi
docker start "$PG" >/dev/null && pg_up
if t=$(wait_for /readyz 200 30); then pass "/readyz 200 again ${t}s after restart"
else fail "/readyz did not recover within 30s: $(body /readyz)"; fi

echo "== C: drain (--shutdown-drain-seconds 5)"
kill -TERM "$SERVER_PID" 2>/dev/null
wait "$SERVER_PID" 2>/dev/null
SERVER_PID=""
boot --shutdown-drain-seconds 5 || exit 1
kill -TERM "$SERVER_PID"
if t=$(wait_for /readyz 503 3 '"draining"'); then pass "/readyz 503 draining ${t}s after SIGTERM"
else fail "/readyz not draining after SIGTERM: $(body /readyz)"; fi
sleep 2
[[ "$(code /livez)" == 200 ]] && pass "/livez 200 inside the grace window" || fail "/livez not served inside the grace window"
[[ "$(code /health)" == 200 ]] && pass "/health (an ordinary route) served inside the grace window" || fail "/health not served inside the grace window"
for _ in $(seq 1 120); do kill -0 "$SERVER_PID" 2>/dev/null || break; sleep 0.5; done
if kill -0 "$SERVER_PID" 2>/dev/null; then fail "server still running 60s after SIGTERM"
else pass "server exited after the grace window"; SERVER_PID=""; fi

echo
if (( FAILS == 0 )); then echo "ha-readyz-scenarios: ALL PASS"; exit 0; fi
echo "ha-readyz-scenarios: $FAILS FAILURE(S) — server log: kept below"; tail -30 "$RIG/server.log"
exit 1
