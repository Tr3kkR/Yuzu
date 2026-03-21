#!/usr/bin/env bash
set -euo pipefail

# Yuzu Pre-flight Validation — checks system readiness before deployment.
# Usage: yuzu-preflight.sh [--component server|agent|both] [--fix] [--no-color]

COMPONENT="both"
FIX=false
NO_COLOR=false
CERT_DIR=""
SERVER_ADDR=""
FAILURES=0

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --component TYPE   Check server, agent, or both (default: both)"
    echo "  --cert-dir DIR     TLS certificate directory to validate"
    echo "  --server HOST:PORT Server address for agent connectivity test"
    echo "  --fix              Attempt auto-fix of simple issues"
    echo "  --no-color         Disable colored output"
    echo "  --help             Show this help"
}

pass() { if $NO_COLOR; then echo "[PASS] $1"; else echo -e "\033[32m[PASS]\033[0m $1"; fi; }
fail() { if $NO_COLOR; then echo "[FAIL] $1"; else echo -e "\033[31m[FAIL]\033[0m $1"; fi; FAILURES=$((FAILURES + 1)); }
warn() { if $NO_COLOR; then echo "[WARN] $1"; else echo -e "\033[33m[WARN]\033[0m $1"; fi; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --component) COMPONENT="$2"; shift 2 ;;
        --cert-dir)  CERT_DIR="$2"; shift 2 ;;
        --server)    SERVER_ADDR="$2"; shift 2 ;;
        --fix)       FIX=true; shift ;;
        --no-color)  NO_COLOR=true; shift ;;
        --help)      usage; exit 0 ;;
        *)           echo "Unknown option: $1"; usage; exit 1 ;;
    esac
done

echo "=== Yuzu Pre-flight Check ==="
echo "Component: $COMPONENT"
echo ""

# --- Binary checks ---
echo "--- Binaries ---"
if [[ "$COMPONENT" == "server" || "$COMPONENT" == "both" ]]; then
    if command -v yuzu-server &>/dev/null || [[ -x ./yuzu-server ]] || [[ -x ./builddir/server/core/yuzu-server ]]; then
        pass "yuzu-server binary found"
    else
        fail "yuzu-server binary not found in PATH or current directory"
    fi
fi

if [[ "$COMPONENT" == "agent" || "$COMPONENT" == "both" ]]; then
    if command -v yuzu-agent &>/dev/null || [[ -x ./yuzu-agent ]] || [[ -x ./builddir/agents/core/yuzu-agent ]]; then
        pass "yuzu-agent binary found"
    else
        fail "yuzu-agent binary not found in PATH or current directory"
    fi
fi

# --- Port checks (server only) ---
if [[ "$COMPONENT" == "server" || "$COMPONENT" == "both" ]]; then
    echo ""
    echo "--- Ports ---"
    for port in 8080 50051 50052; do
        if command -v ss &>/dev/null; then
            if ss -tlnp 2>/dev/null | grep -q ":${port} "; then
                fail "Port $port is already in use"
            else
                pass "Port $port is available"
            fi
        elif command -v netstat &>/dev/null; then
            if netstat -an 2>/dev/null | grep -q "LISTEN.*:${port} \|:${port}.*LISTEN"; then
                fail "Port $port is already in use"
            else
                pass "Port $port is available"
            fi
        else
            warn "Port $port — cannot check (no ss or netstat)"
        fi
    done
fi

# --- Disk space ---
echo ""
echo "--- Disk Space ---"
AVAIL_KB=$(df -k . 2>/dev/null | tail -1 | awk '{print $4}')
if [[ -n "$AVAIL_KB" ]] && [[ "$AVAIL_KB" -gt 512000 ]]; then
    pass "Disk space: $((AVAIL_KB / 1024)) MB available (>500MB required)"
else
    fail "Disk space: $((AVAIL_KB / 1024)) MB available (<500MB)"
fi

# --- sqlite3 ---
echo ""
echo "--- Dependencies ---"
if command -v sqlite3 &>/dev/null; then
    pass "sqlite3 found: $(sqlite3 --version 2>&1 | head -1)"
else
    warn "sqlite3 not found (needed for backup/restore)"
fi

# --- Data directory ---
echo ""
echo "--- Data Directory ---"
for dir in /var/lib/yuzu /etc/yuzu /var/log/yuzu; do
    if [[ -d "$dir" ]]; then
        if [[ -w "$dir" ]]; then
            pass "$dir exists and is writable"
        else
            fail "$dir exists but is NOT writable"
            if $FIX; then
                warn "  Attempting fix: chmod 750 $dir"
                chmod 750 "$dir" 2>/dev/null && pass "  Fixed" || fail "  Fix failed (try with sudo)"
            fi
        fi
    else
        warn "$dir does not exist"
        if $FIX; then
            warn "  Attempting fix: mkdir -p $dir"
            mkdir -p "$dir" 2>/dev/null && pass "  Created $dir" || fail "  Creation failed (try with sudo)"
        fi
    fi
done

# --- TLS certificates ---
if [[ -n "$CERT_DIR" ]]; then
    echo ""
    echo "--- TLS Certificates ---"
    if [[ -d "$CERT_DIR" ]]; then
        for cert in "$CERT_DIR"/*.pem "$CERT_DIR"/*.crt; do
            [[ -f "$cert" ]] || continue
            if command -v openssl &>/dev/null; then
                EXPIRY=$(openssl x509 -enddate -noout -in "$cert" 2>/dev/null | cut -d= -f2)
                if [[ -n "$EXPIRY" ]]; then
                    EXPIRY_EPOCH=$(date -d "$EXPIRY" +%s 2>/dev/null || date -jf "%b %d %H:%M:%S %Y %Z" "$EXPIRY" +%s 2>/dev/null || echo 0)
                    NOW_EPOCH=$(date +%s)
                    DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))
                    if [[ $DAYS_LEFT -lt 0 ]]; then
                        fail "$(basename "$cert"): EXPIRED ($EXPIRY)"
                    elif [[ $DAYS_LEFT -lt 30 ]]; then
                        warn "$(basename "$cert"): expires in $DAYS_LEFT days ($EXPIRY)"
                    else
                        pass "$(basename "$cert"): valid for $DAYS_LEFT days"
                    fi
                fi
            else
                warn "$(basename "$cert"): openssl not found, cannot check expiry"
            fi
        done
    else
        fail "Certificate directory not found: $CERT_DIR"
    fi
fi

# --- DNS / connectivity ---
if [[ -n "$SERVER_ADDR" ]]; then
    echo ""
    echo "--- Connectivity ---"
    HOST="${SERVER_ADDR%%:*}"
    PORT="${SERVER_ADDR##*:}"
    if command -v nc &>/dev/null; then
        if nc -z -w3 "$HOST" "$PORT" 2>/dev/null; then
            pass "Server reachable at $SERVER_ADDR"
        else
            fail "Cannot connect to server at $SERVER_ADDR"
        fi
    elif command -v curl &>/dev/null; then
        if curl -s --connect-timeout 3 "http://${SERVER_ADDR}" &>/dev/null; then
            pass "Server reachable at $SERVER_ADDR"
        else
            fail "Cannot connect to server at $SERVER_ADDR"
        fi
    else
        warn "Cannot test connectivity (no nc or curl)"
    fi
fi

# --- Summary ---
echo ""
echo "=== Pre-flight Summary ==="
if [[ $FAILURES -eq 0 ]]; then
    pass "All checks passed"
    exit 0
else
    fail "$FAILURES check(s) failed"
    exit 1
fi
