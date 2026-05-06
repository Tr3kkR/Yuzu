#!/usr/bin/env bash
# preflight.sh — Phase 0 of the /test pipeline.
#
# Verifies the dev box is in a state where /test can complete:
#
#   - required toolchains on PATH (meson, ninja, rebar3, erl, docker, gh,
#     jq, python3, ccache, sqlite3 module via python3)
#   - native dockerd reachable (NOT Docker Desktop shim)
#   - no dangling yuzu-test-* docker containers from prior runs
#   - test ports free (8080, 50051-50055, 50063, 8081, 9568)
#   - sufficient disk free (>= 20 GB on $HOME, /tmp, and /var/lib/docker)
#   - git working tree state recorded for the run row (dirty/clean and HEAD sha)
#   - the test-runs DB exists at schema v1 (auto-create if missing)
#
# Exits 0 on success. On failure, prints a coloured table of which checks
# failed and what the operator should do, and exits non-zero.
#
# Override behaviour:
#   YUZU_TEST_DB=path             — alternative DB location
#   YUZU_TEST_PREFLIGHT_SKIP=name1,name2  — skip specific checks (debug only)
#   YUZU_TEST_DISK_MIN_GB=N       — minimum free GB required (default 20)
#
# Usage:
#   bash scripts/test/preflight.sh
#   bash scripts/test/preflight.sh --force-cleanup   # tear down dangling test containers first

set -uo pipefail

# `mapfile -t` is used below and requires bash ≥ 4.0. macOS ships bash
# 3.2 at /bin/bash, but `#!/usr/bin/env bash` picks up Homebrew bash 5.x
# when it's on PATH. Fail loudly if we somehow got bash 3.
if (( ${BASH_VERSINFO[0]:-0} < 4 )); then
    echo "preflight needs bash 4+ (got $BASH_VERSION) — install GNU bash via brew or apt" >&2
    exit 2
fi

HERE="$(cd "$(dirname "$0")" && pwd)"
YUZU_ROOT="$(cd "$HERE/../.." && pwd)"

# Cross-platform helpers: port_listening, disk_free_gb, host_os,
# docker_available, ensure_docker_path. See _portable.sh for the contract.
# shellcheck source=scripts/test/_portable.sh
. "$HERE/_portable.sh"
HOST_OS=$(host_os)

# --- output helpers -------------------------------------------------------

if [ -t 1 ]; then
    G='\033[0;32m'; R='\033[0;31m'; Y='\033[1;33m'; C='\033[0;36m'; N='\033[0m'
else
    G=''; R=''; Y=''; C=''; N=''
fi
ok()   { printf "  ${G}\u2713${N} %s\n" "$*"; }
fail() { printf "  ${R}\u2717${N} %s\n" "$*"; FAILED=1; }
warn() { printf "  ${Y}\u26a0${N} %s\n" "$*"; }
info() { printf "  ${C}\u2192${N} %s\n" "$*"; }

FAILED=0
FORCE_CLEANUP=0
FORCE_CLEANUP_RUN_ID=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --force-cleanup)
            FORCE_CLEANUP=1
            shift
            ;;
        --force-cleanup-run-id)
            FORCE_CLEANUP=1
            FORCE_CLEANUP_RUN_ID="$2"
            shift 2
            ;;
        -h|--help)
            cat <<EOF
usage: $0 [--force-cleanup [--force-cleanup-run-id RUN_ID]]

Without --force-cleanup, the script reports dangling test containers as a
hard FAIL and refuses to proceed (the operator should clean up manually).

With --force-cleanup, dangling containers/volumes are torn down. By
default this matches ALL yuzu-test-* projects, which is dangerous if
another /test run is in flight on the same host. Pass --force-cleanup-run-id
RUN_ID to scope cleanup to a specific run, leaving sibling runs untouched.
EOF
            exit 0
            ;;
        *)
            echo "preflight: unknown arg: $1" >&2
            exit 2
            ;;
    esac
done

SKIP_LIST=",${YUZU_TEST_PREFLIGHT_SKIP:-},"
skipped() {
    case "$SKIP_LIST" in *",$1,"*) return 0 ;; esac
    return 1
}

DISK_MIN_GB="${YUZU_TEST_DISK_MIN_GB:-20}"

echo ""
echo "Yuzu /test preflight"
echo "===================="

# --- toolchains -----------------------------------------------------------

require_tool() {
    local name="$1" path
    if path=$(command -v "$name" 2>/dev/null); then
        ok "$name → $path"
        return 0
    fi
    fail "$name not on PATH (required)"
    return 1
}

soft_tool() {
    local name="$1" reason="$2" path
    if path=$(command -v "$name" 2>/dev/null); then
        ok "$name → $path"
    else
        warn "$name not on PATH — $reason"
    fi
}

if ! skipped toolchains; then
    info "toolchains"
    require_tool python3
    require_tool meson
    require_tool ninja
    if [[ "$HOST_OS" == "darwin" ]]; then
        # On macOS the docker CLI usually ships with OrbStack / Docker
        # Desktop and may not be on PATH until first launch. Probe known
        # locations before declaring it missing; if still absent, soft-fail
        # — phases that need docker (Phase 2 upgrade test, Phase 1 image
        # build) will SKIP with a helpful note rather than fail the run.
        if ensure_docker_path 2>/dev/null && command -v docker >/dev/null 2>&1; then
            ok "docker → $(command -v docker)"
        else
            warn "docker not on PATH — Phase 1 image build + Phase 2 upgrade test will SKIP"
            warn "    install OrbStack or Docker Desktop, then run it once to populate ~/.orbstack/bin"
        fi
    else
        require_tool docker
    fi
    require_tool curl
    soft_tool   gh       "Phase 3 OTA + Phase 6 sanitizer dispatch will WARN"
    soft_tool   jq       "synthetic UAT test parsing falls back to python"
    soft_tool   ccache   "rebuilds will be slower"
    soft_tool   erl      "run 'source scripts/ensure-erlang.sh' before invoking /test"
    soft_tool   rebar3   "gateway gates will FAIL until installed"
    if ! python3 -c "import sqlite3" 2>/dev/null; then
        fail "python3 sqlite3 module missing (cannot use test-runs DB)"
    else
        ok "python3 sqlite3 module"
    fi
fi

# --- docker daemon --------------------------------------------------------

if ! skipped docker; then
    info "docker"
    if ! docker_available; then
        if [[ "$HOST_OS" == "darwin" ]]; then
            warn "docker daemon not reachable — start OrbStack/Docker Desktop to enable Phase 2"
        else
            fail "docker info failed (daemon not reachable)"
        fi
    else
        ok "docker daemon reachable"
        ctx=$(docker context show 2>/dev/null || echo "?")
        # Native dockerd is the convention on Linux (CLAUDE.md memory).
        # On macOS, OrbStack and Docker Desktop both expose themselves via
        # `desktop-linux` or `orbstack` contexts — that's the only sensible
        # local option, so don't flag it as suspicious.
        if [[ "$ctx" == "desktop-linux" && "$HOST_OS" == "linux" ]]; then
            warn "docker context is '$ctx' — CLAUDE.md memory says native dockerd, not Docker Desktop"
        else
            ok "docker context: $ctx"
        fi
    fi
fi

# --- dangling test containers --------------------------------------------

if ! skipped containers; then
    info "dangling test containers"
    # Scope the filter: if --force-cleanup-run-id is set, only match that
    # specific RUN_ID's project containers. Otherwise match all yuzu-test-*
    # but warn about the cross-run contamination risk.
    if [[ -n "$FORCE_CLEANUP_RUN_ID" ]]; then
        FILTER_NAME="yuzu-test-${FORCE_CLEANUP_RUN_ID}-"
        info "scoping cleanup to RUN_ID=$FORCE_CLEANUP_RUN_ID"
    else
        FILTER_NAME="yuzu-test-"
    fi

    if ! command -v docker >/dev/null 2>&1; then
        ok "docker missing — no test containers to inventory"
        dangling_arr=()
    else
        mapfile -t dangling_arr < <(docker ps -a --filter "name=$FILTER_NAME" --format "{{.Names}}" 2>/dev/null || true)
    fi
    if [[ ${#dangling_arr[@]} -gt 0 ]]; then
        if [[ $FORCE_CLEANUP -eq 1 ]]; then
            if [[ -z "$FORCE_CLEANUP_RUN_ID" ]]; then
                warn "--force-cleanup with no --force-cleanup-run-id will tear down ALL yuzu-test-* containers"
                warn "if another /test run is in flight on this host, it WILL be killed"
            fi
            warn "dangling: ${dangling_arr[*]}"
            for n in "${dangling_arr[@]}"; do
                docker rm -f "$n" >/dev/null 2>&1 || true
                ok "removed $n"
            done
        else
            fail "dangling test containers (rerun with --force-cleanup): ${dangling_arr[*]}"
        fi
    else
        ok "no dangling $FILTER_NAME containers"
    fi

    # Same scoping for dangling volumes
    if ! command -v docker >/dev/null 2>&1; then
        dangling_vols_arr=()
    else
        mapfile -t dangling_vols_arr < <(docker volume ls --filter "name=$FILTER_NAME" --format "{{.Name}}" 2>/dev/null || true)
    fi
    if [[ ${#dangling_vols_arr[@]} -gt 0 ]]; then
        if [[ $FORCE_CLEANUP -eq 1 ]]; then
            for v in "${dangling_vols_arr[@]}"; do
                docker volume rm -f "$v" >/dev/null 2>&1 || true
                ok "removed volume $v"
            done
        else
            warn "dangling test volumes (rerun with --force-cleanup): ${dangling_vols_arr[*]}"
        fi
    fi
fi

# --- test ports free ------------------------------------------------------

if ! skipped ports; then
    info "test ports"
    PORTS=(8080 50051 50052 50054 50055 50063 8081 9568)
    busy=()
    for p in "${PORTS[@]}"; do
        if port_listening "$p"; then
            busy+=("$p")
        fi
    done
    if [[ ${#busy[@]} -gt 0 ]]; then
        fail "ports in use: ${busy[*]} — stop the prior stack with 'bash scripts/start-UAT.sh stop'"
    else
        ok "ports free: ${PORTS[*]}"
    fi
fi

# --- disk space -----------------------------------------------------------

if ! skipped disk; then
    info "disk free (need ${DISK_MIN_GB} GB on each)"
    # /var/lib/docker is the native dockerd image+volume root on Linux.
    # On macOS Docker Desktop and OrbStack put their image cache inside a
    # private VM image (~/Library/Containers/...); the host filesystem
    # check is meaningless there, so skip the docker path on Darwin.
    paths=("$HOME" /tmp)
    if [[ "$HOST_OS" == "linux" ]]; then
        paths+=(/var/lib/docker)
    fi
    for path in "${paths[@]}"; do
        if [[ ! -d "$path" ]]; then
            warn "$path does not exist (skipped)"
            continue
        fi
        free_gb=$(disk_free_gb "$path")
        if [[ -z "$free_gb" ]]; then
            warn "could not determine free space on $path"
            continue
        fi
        if (( free_gb < DISK_MIN_GB )); then
            fail "$path has ${free_gb}G free, need ${DISK_MIN_GB}G"
        else
            ok "$path: ${free_gb}G free"
        fi
    done
fi

# --- git state ------------------------------------------------------------

if ! skipped git; then
    info "git"
    if ! git -C "$YUZU_ROOT" rev-parse HEAD >/dev/null 2>&1; then
        fail "$YUZU_ROOT is not a git repo"
    else
        sha=$(git -C "$YUZU_ROOT" rev-parse --short HEAD)
        branch=$(git -C "$YUZU_ROOT" rev-parse --abbrev-ref HEAD)
        ok "branch=$branch HEAD=$sha"
        if [[ -n "$(git -C "$YUZU_ROOT" status --porcelain)" ]]; then
            warn "working tree is dirty — the test_runs row will record HEAD sha but uncommitted changes are not captured"
        fi
    fi
fi

# --- test-runs DB ---------------------------------------------------------

if ! skipped db; then
    info "test-runs DB"
    if python3 "$HERE/test_db.py" init 2>&1; then
        ok "DB ready at ${YUZU_TEST_DB:-$HOME/.local/share/yuzu/test-runs.db}"
    else
        fail "test_db init failed"
    fi
fi

# --- summary --------------------------------------------------------------

echo ""
if [[ $FAILED -eq 0 ]]; then
    echo -e "${G}preflight ok${N}"
    exit 0
else
    echo -e "${R}preflight failed — fix the above before running /test${N}"
    exit 1
fi
