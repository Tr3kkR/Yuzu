#!/usr/bin/env bash
# scripts/test/_portable.sh — sourceable cross-platform helpers for the
# /test pipeline. Branches on `uname -s` so a single invocation works on
# Linux (CI, WSL2) and macOS (operator dev box). Never modifies caller
# state unless the helper name explicitly says so (e.g. ensure_docker_path).
#
# Usage:
#   source scripts/test/_portable.sh
#   port_listening 8080 && echo busy
#   gb=$(disk_free_gb /tmp)
#   if docker_available; then ...; fi
#
# All helpers are tolerant of missing tools — they print empty string or
# return 1 rather than aborting under `set -e`. Callers decide policy.

# Re-source guard — sourcing twice is cheap but pointless.
if [[ "${_YUZU_PORTABLE_SOURCED:-}" == "1" ]]; then
    return 0 2>/dev/null || true
fi
_YUZU_PORTABLE_SOURCED=1

# host_os — print one of: linux, darwin, windows.
# windows is reported only when running under MSYS2/Cygwin (the supported
# Windows path per CLAUDE.md windows-build.md). Other identifiers fall
# back to linux because dockerd / iproute2 are the assumed environment.
host_os() {
    case "$(uname -s 2>/dev/null)" in
        Darwin)            echo darwin ;;
        MINGW*|MSYS*|CYGWIN*) echo windows ;;
        Linux|*)           echo linux ;;
    esac
}

# build_dir — the per-OS canonical meson build directory (CLAUDE.md
# "Per-OS build directory convention"). Relative path; caller prepends
# repo root if needed. Note: macOS uses "build-macos" (not "build-darwin")
# to match scripts/setup.sh and the convention table in CLAUDE.md.
build_dir() {
    local os
    os=$(host_os)
    case "$os" in
        darwin) echo "build-macos" ;;
        *)      echo "build-$os" ;;
    esac
}

# port_listening <port> — return 0 if a TCP socket is listening on the
# given port, 1 otherwise. Uses lsof (works on macOS + Linux). Falls
# back to ss on Linux if lsof is missing (CI containers sometimes lack
# lsof but always ship iproute2).
port_listening() {
    local port="$1"
    if command -v lsof >/dev/null 2>&1; then
        lsof -iTCP:"$port" -sTCP:LISTEN -P -n -t >/dev/null 2>&1
        return $?
    fi
    if command -v ss >/dev/null 2>&1; then
        ss -tlnH 2>/dev/null | awk '{print $4}' | grep -qE ":${port}\$"
        return $?
    fi
    return 1
}

# listening_ports_among <port> [port...] — print a comma-separated list
# of which of the given ports are currently listening. Empty if none.
listening_ports_among() {
    local busy=()
    local p
    for p in "$@"; do
        if port_listening "$p"; then
            busy+=("$p")
        fi
    done
    local IFS=,
    echo "${busy[*]}"
}

# disk_free_gb <path> — print integer GB free at $path, or empty string
# if the path doesn't exist or df fails. df -k is portable (POSIX); we
# convert kB to GB ourselves to avoid the BSD/GNU split on -BG/-g flags.
# Rounds to nearest (not floor) so a box with exactly 20.0 GB free isn't
# reported as 19 — which would trip the default DISK_MIN_GB=20 threshold
# in preflight.sh and produce a false-FAIL within ~512 MB of the boundary.
disk_free_gb() {
    local path="$1"
    [[ -d "$path" ]] || return 0
    df -k "$path" 2>/dev/null \
        | awk 'NR==2 {printf "%d\n", int($4 / 1024 / 1024 + 0.5)}'
}

# loadavg_1m — print 1-minute system load average as a float string.
loadavg_1m() {
    case "$(host_os)" in
        darwin)
            # `vm.loadavg` prints "{ 1.23 0.89 0.71 }"; strip the braces.
            sysctl -n vm.loadavg 2>/dev/null | awk '{print $2}'
            ;;
        linux)
            awk '{print $1}' /proc/loadavg 2>/dev/null
            ;;
        *)
            echo "0.0"
            ;;
    esac
}

# cpu_brand — print a single-line CPU brand string, or "unknown".
# Note: `grep ... | sed ... || echo unknown` does not work — sed exits 0
# on empty stdin and prints nothing. ARM kernels and some containers
# don't emit `model name` in /proc/cpuinfo (they use `Processor` or omit
# entirely), and Darwin can return empty if sysctl OID is missing on a
# stripped image. Capture into a variable and fall back explicitly.
cpu_brand() {
    local cpu=""
    case "$(host_os)" in
        darwin)
            cpu=$(sysctl -n machdep.cpu.brand_string 2>/dev/null)
            ;;
        linux)
            cpu=$(grep -m1 '^model name' /proc/cpuinfo 2>/dev/null | sed 's/.*: //')
            ;;
    esac
    [[ -n "$cpu" ]] || cpu="unknown"
    echo "$cpu"
}

# mem_total_gb — print integer GB of physical memory, or "unknown".
mem_total_gb() {
    case "$(host_os)" in
        darwin)
            local bytes
            bytes=$(sysctl -n hw.memsize 2>/dev/null) || { echo unknown; return; }
            echo "$(( bytes / 1024 / 1024 / 1024 ))GB"
            ;;
        linux)
            if [[ -r /proc/meminfo ]]; then
                awk '/^MemTotal:/ {printf "%dGB\n", $2/1024/1024}' /proc/meminfo
            else
                echo "unknown"
            fi
            ;;
        *)
            echo "unknown"
            ;;
    esac
}

# ensure_docker_path — if docker is not on PATH, probe known macOS
# locations (OrbStack, Docker Desktop) and prepend the first hit. Idempotent.
# Mutates PATH; call only if the caller actually wants docker invocation.
ensure_docker_path() {
    if command -v docker >/dev/null 2>&1; then
        return 0
    fi
    [[ "$(host_os)" == "darwin" ]] || return 1
    local cand
    for cand in \
        "$HOME/.orbstack/bin" \
        "/Applications/OrbStack.app/Contents/MacOS/xbin" \
        "/Applications/Docker.app/Contents/Resources/bin" \
        ; do
        if [[ -x "$cand/docker" ]]; then
            export PATH="$cand:$PATH"
            return 0
        fi
    done
    return 1
}

# docker_available — return 0 if `docker info` succeeds, 1 otherwise.
# Calls ensure_docker_path first so a Mac with OrbStack installed but
# unsymlinked is detected without the operator pre-configuring PATH.
docker_available() {
    ensure_docker_path 2>/dev/null
    command -v docker >/dev/null 2>&1 || return 1
    docker info >/dev/null 2>&1
}
