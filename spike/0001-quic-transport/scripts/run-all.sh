#!/usr/bin/env bash
# Drive the four PR 0 spike scenarios and capture evidence.
#
# For each scenario:
#   1. Kill any prior server on port 50053
#   2. Start fresh server (logs → docs/spike-results/.../server-<scenario>.log
#      stdout JSON → server-<scenario>.json)
#   3. Wait for the listener line
#   4. Run client (stderr → client-<scenario>.log; stdout JSON → client-<scenario>.json)
#   5. Wait for server to flush its JSON, then kill if needed
#   6. Compute pass/fail line per ADR pass criteria

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EVIDENCE="$(cd "$HERE/.." && pwd)/../docs/spike-results/0001-quic-transport"
SERVER_BIN="$HERE/cpp-server/build/yuzu_quic_spike_server"
CLIENT_RUN="$HERE/scripts/run-client.sh"
CLIENT_BIN="$HERE/erlang-client/_build/default/bin/yuzu_quic_spike_client"
CERT="$HERE/certs/server.crt"
KEY="$HERE/certs/server.key"
CA="$HERE/certs/ca.crt"
PORT=50053

mkdir -p "$EVIDENCE"

[[ -x "$SERVER_BIN" ]] || { echo "missing $SERVER_BIN — run cmake --build build first" >&2; exit 2; }
[[ -x "$CLIENT_BIN" ]] || { echo "missing $CLIENT_BIN — run rebar3 escriptize first" >&2; exit 2; }
[[ -x "$CLIENT_RUN" ]] || { echo "missing $CLIENT_RUN" >&2; exit 2; }
[[ -f "$CERT" && -f "$KEY" && -f "$CA" ]] || { echo "missing certs — run scripts/gen-certs.sh first" >&2; exit 2; }

kill_port() {
    local p="$1"
    local pids
    pids=$(lsof -ti udp:"$p" 2>/dev/null || true)
    if [[ -n "$pids" ]]; then
        echo "[run-all] killing pids $pids holding udp/$p"
        kill -TERM $pids 2>/dev/null || true
        sleep 0.5
        pids=$(lsof -ti udp:"$p" 2>/dev/null || true)
        if [[ -n "$pids" ]]; then
            kill -KILL $pids 2>/dev/null || true
        fi
    fi
}

start_server() {
    local mode="$1"
    local label="$2"
    local server_log="$EVIDENCE/server-$label.log"
    local server_json="$EVIDENCE/server-$label.json"
    rm -f "$server_log" "$server_json"
    echo "[run-all] starting server mode=$mode label=$label"
    "$SERVER_BIN" --port "$PORT" --cert "$CERT" --key "$KEY" --mode "$mode" \
        > "$server_json" 2> "$server_log" &
    SERVER_PID=$!
    # Wait for listener line.
    local tries=0
    while ! grep -q "listening on udp/" "$server_log" 2>/dev/null; do
        tries=$((tries + 1))
        if [[ $tries -gt 60 ]]; then
            echo "[run-all] server failed to start; tail of log:"
            tail -20 "$server_log" >&2
            kill -KILL "$SERVER_PID" 2>/dev/null || true
            return 1
        fi
        if ! kill -0 "$SERVER_PID" 2>/dev/null; then
            echo "[run-all] server exited prematurely"
            tail -20 "$server_log" >&2
            return 1
        fi
        sleep 0.1
    done
    echo "[run-all] server up (pid $SERVER_PID)"
    return 0
}

stop_server() {
    if [[ -n "${SERVER_PID:-}" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
        # Send TERM and wait briefly for graceful flush.
        kill -TERM "$SERVER_PID" 2>/dev/null || true
        for _ in 1 2 3 4 5 6 7 8 9 10; do
            kill -0 "$SERVER_PID" 2>/dev/null || break
            sleep 0.2
        done
        kill -KILL "$SERVER_PID" 2>/dev/null || true
    fi
    SERVER_PID=
}

run_client() {
    local mode="$1"
    local label="$2"
    local client_log="$EVIDENCE/client-$label.log"
    local client_json="$EVIDENCE/client-$label.json"
    rm -f "$client_log" "$client_json"
    echo "[run-all] running client mode=$mode label=$label"
    "$CLIENT_RUN" --mode "$mode" --cacert "$CA" \
        > "$client_json" 2> "$client_log"
    local rc=$?
    echo "[run-all] client exited rc=$rc"
    return $rc
}

scenario() {
    local label="$1"
    local server_mode="$2"
    local client_mode="$3"
    echo
    echo "=========================================="
    echo "[scenario $label]  server=$server_mode  client=$client_mode"
    echo "=========================================="
    kill_port "$PORT"
    start_server "$server_mode" "$label" || { RESULTS+=("$label:server-start-fail"); return; }
    set +e
    run_client "$client_mode" "$label"
    local crc=$?
    set -e
    stop_server
    # Give the server time to flush its JSON line.
    sleep 0.3
    RESULTS+=("$label:client-rc=$crc")
}

RESULTS=()

scenario handshake   normal      handshake
scenario bidi        normal      bidi-30s
scenario halfclose   normal      halfclose
scenario slowreader  slow-reader slow-reader

echo
echo "=========================================="
echo "[summary]"
for r in "${RESULTS[@]}"; do
    echo "  $r"
done
echo "Evidence: $EVIDENCE"
