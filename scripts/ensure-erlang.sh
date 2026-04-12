#!/usr/bin/env bash
# scripts/ensure-erlang.sh
#
# Sourceable helper that puts `erl` (Erlang/OTP runtime) on PATH so the
# Yuzu gateway and meson custom_targets that invoke rebar3 can build.
#
# Usage:
#   source scripts/ensure-erlang.sh           # default: latest 28.x
#   source scripts/ensure-erlang.sh 28        # any 28.x
#   source scripts/ensure-erlang.sh 28.4.2    # exact pin
#   command -v erl >/dev/null || { echo "Erlang/OTP missing" >&2; exit 1; }
#
# This script:
#   - Is a no-op if `erl` is already on PATH AND actually runs.
#   - Tries kerl → asdf → Homebrew (macOS only) → Windows installer (MSYS2 only).
#   - ALWAYS returns 0 — callers MUST verify with `command -v erl` afterwards.
#     (Returning non-zero from a sourced script trips parent `set -e`.)
#
# The default version tracks `.github/workflows/release.yml`'s
# `erlef/setup-beam` `otp-version`. Bump them together.
#
# Supported environments: Linux, macOS, WSL2, MSYS2 bash on Windows.
# Native cmd.exe / PowerShell are NOT supported — use MSYS2 (CLAUDE.md).

# Refuse to run as a subprocess: PATH mutations would be discarded.
if [ "${BASH_SOURCE[0]:-$0}" = "${0}" ]; then
    echo "ensure-erlang.sh must be sourced: source scripts/ensure-erlang.sh" >&2
    exit 1
fi

# Bash-only: BASH_SOURCE, shopt, etc. dash/zsh are unsupported.
if [ -z "${BASH_VERSION:-}" ]; then
    echo "ensure-erlang.sh requires bash (got: ${SHELL:-unknown})" >&2
    return 0 2>/dev/null || true
fi

_yz_desired_erlang="${1:-28}"

# Reject characters that could cause grief in awk/glob/log expansion.
case "$_yz_desired_erlang" in
    *[!A-Za-z0-9._-]*)
        echo "[ensure-erlang] invalid version '$_yz_desired_erlang' — falling back to '28'" >&2
        _yz_desired_erlang=28
        ;;
esac

_yz_log() { printf '[ensure-erlang] %s\n' "$*" >&2; }

# Cache `uname -s` once so the failure path doesn't run uname after probes
# may have left PATH in an unusual state (also useful in test harnesses).
_yz_uname=$(uname -s 2>/dev/null || echo unknown)

# Liveness probe: `erl` exists AND can be invoked. Catches broken symlinks,
# missing libs, wrong-arch binaries.
_yz_have_erl() {
    command -v erl >/dev/null 2>&1 || return 1
    erl -version >/dev/null 2>&1
}

_yz_cleanup() {
    unset _yz_desired_erlang _yz_activated _yz_kerl_match _yz_asdf_erl \
          _yz_brew_prefix _yz_win_match _yz_win_bindir _yz_root _yz_cand \
          _yz_ver _yz_prev_nullglob _yz_uname _yz_orig_path
    unset -f _yz_log _yz_have_erl _yz_cleanup
}

# Snapshot PATH so the failure path can roll back any partial probe mutations
# (asdf/brew/MSYS2 each prepend before liveness-checking, and a failed kerl
# activate can leave fragments behind too).
_yz_orig_path="$PATH"

# Already on PATH and runs — silent success.
if _yz_have_erl; then
    _yz_cleanup
    return 0
fi

_yz_activated=""

# 1. kerl
if [ -z "$_yz_activated" ] && command -v kerl >/dev/null 2>&1; then
    # kerl install names are user-chosen and not necessarily the OTP version,
    # so match either the install_name (column 1) or the basename of the
    # install path (column 2). Accept exact match or "$desired." prefix
    # (so `28` matches `28.4.2`). Among matches, sort -V picks the highest.
    _yz_kerl_match=$(kerl list installations 2>/dev/null | awk \
        -v v="$_yz_desired_erlang" '
        {
            name = $1
            bn = $2
            sub(".*/", "", bn)
            if (name == v || bn == v ||
                index(name, v ".") == 1 || index(bn, v ".") == 1) {
                key = (bn ~ /^[0-9]/) ? bn : name
                print key "\t" $2
            }
        }' | sort -V | tail -n1 | cut -f2-)

    if [ -n "$_yz_kerl_match" ] && [ -f "$_yz_kerl_match/activate" ]; then
        # shellcheck disable=SC1090
        if source "$_yz_kerl_match/activate" 2>/dev/null && _yz_have_erl; then
            _yz_log "kerl activated: $_yz_kerl_match"
            _yz_activated="kerl"
        fi
    fi
fi

# 2. asdf — `asdf which erl` works on both classic and 0.16+ rewrites.
if [ -z "$_yz_activated" ] && command -v asdf >/dev/null 2>&1; then
    _yz_asdf_erl=$(asdf which erl 2>/dev/null || true)
    if [ -z "$_yz_asdf_erl" ]; then
        _yz_asdf_erl=$(asdf where erlang 2>/dev/null)/bin/erl
    fi
    if [ -n "$_yz_asdf_erl" ] && [ -x "$_yz_asdf_erl" ]; then
        export PATH="$(dirname "$_yz_asdf_erl"):$PATH"
        if _yz_have_erl; then
            _yz_log "asdf erlang: $(dirname "$_yz_asdf_erl")"
            _yz_activated="asdf"
        fi
    fi
fi

# 3. macOS Homebrew (Intel `/usr/local`, Apple Silicon `/opt/homebrew` — both
#    handled by `brew --prefix erlang`).
if [ -z "$_yz_activated" ] && [ "$_yz_uname" = "Darwin" ] && command -v brew >/dev/null 2>&1; then
    _yz_brew_prefix=$(brew --prefix erlang 2>/dev/null || true)
    if [ -n "$_yz_brew_prefix" ] && [ -d "$_yz_brew_prefix/bin" ]; then
        export PATH="$_yz_brew_prefix/bin:$PATH"
        if _yz_have_erl; then
            _yz_log "Homebrew erlang: $_yz_brew_prefix"
            _yz_activated="brew"
        fi
    fi
fi

# 4. MSYS2 on Windows: probe standard installer paths.
#    Modern installers (≥ OTP 26) use "Erlang OTP\bin\erl.exe" with no version
#    in the directory name; older ones use "erl-<ver>\bin\erl.exe". Sort by
#    extracted version so a versioned install always wins over the unversioned
#    fallback.
if [ -z "$_yz_activated" ]; then
    case "$_yz_uname" in
        MINGW*|MSYS*|CYGWIN*)
            _yz_prev_nullglob=$(shopt -p nullglob 2>/dev/null || echo "shopt -u nullglob")
            shopt -s nullglob

            _yz_win_match=$(
                {
                    for _yz_root in "/c/Program Files" "/c/Program Files (x86)"; do
                        for _yz_cand in "$_yz_root"/erl-*/bin/erl.exe; do
                            _yz_ver=${_yz_cand#"$_yz_root"/erl-}
                            _yz_ver=${_yz_ver%%/*}
                            printf '%s\t%s\n' "$_yz_ver" "$_yz_cand"
                        done
                        _yz_cand="$_yz_root/Erlang OTP/bin/erl.exe"
                        [ -f "$_yz_cand" ] && printf '0.0.0\t%s\n' "$_yz_cand"
                    done
                } | sort -V | tail -n1 | cut -f2-
            )

            eval "$_yz_prev_nullglob"

            if [ -n "$_yz_win_match" ] && [ -f "$_yz_win_match" ]; then
                _yz_win_bindir=$(dirname "$_yz_win_match")
                export PATH="$_yz_win_bindir:$PATH"
                if _yz_have_erl; then
                    _yz_log "Windows erlang: $_yz_win_bindir"
                    _yz_activated="msys2-windows"
                fi
            fi
            ;;
    esac
fi

if [ -z "$_yz_activated" ]; then
    # Roll back any half-applied PATH mutations from failed probes.
    PATH="$_yz_orig_path"
    _yz_log "Erlang/OTP not found. Yuzu gateway needs erl/rebar3 on PATH."
    _yz_log "Install options:"
    _yz_log "  - kerl:    https://github.com/kerl/kerl"
    _yz_log "  - asdf:    asdf plugin add erlang && asdf install erlang $_yz_desired_erlang"
    _yz_log "  - macOS:   brew install erlang"
    _yz_log "  - Windows: https://www.erlang.org/downloads (installs to C:\\Program Files\\Erlang OTP\\)"
fi

_yz_cleanup
return 0
