#!/usr/bin/env bash
# test_mfa_reset.sh — contract test for the `--mfa-reset` break-glass CLI (#1226).
#
# The break-glass path is the documented recovery from MFA-enforcement lockout
# (lost device, IdP not asserting amr, sole admin who could not enroll). It runs
# `yuzu-server --mfa-reset <user>`, clears the user's MFA, writes an audit row,
# and exits without starting the server. This verifies the CLI contract:
# existing user -> ok + exit 0; missing user -> error + exit 1; runs without
# requiring the TLS/HTTPS flags (it never serves).
#
# Run:  bash tests/shell/test_mfa_reset.sh
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || { cd "$(dirname "$0")/../.." && pwd; })"
# Locate a built server binary. An explicit YUZU_SERVER_BIN wins (CI sets it to
# the matrix build dir, e.g. build-linux-gcc-13-debug); otherwise scan the
# conventional per-OS dirs.
BIN=""
if [ -n "${YUZU_SERVER_BIN:-}" ] && [ -x "${YUZU_SERVER_BIN}" ]; then
  BIN="${YUZU_SERVER_BIN}"
else
  for d in build-linux build-macos build-windows; do
    for p in "$ROOT/$d/server/core/yuzu-server" "$ROOT/$d/server/core/yuzu-server.exe"; do
      [ -x "$p" ] && BIN="$p" && break
    done
    [ -n "$BIN" ] && break
  done
fi
if [ -z "$BIN" ]; then
  echo "SKIP: no built yuzu-server binary found (build with -Dbuild_server=true first)" >&2
  exit 0
fi

TMP="$(mktemp -d "${TMPDIR:-/tmp}/yuzu-mfareset-test.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

# Seed a config with one admin (PBKDF2-SHA256 100k/32B, the server's scheme).
python3 -c "
import hashlib, os
salt = os.urandom(16)
dk = hashlib.pbkdf2_hmac('sha256', 'pw'.encode(), salt, 100000, dklen=32)
print(f'admin:admin:{salt.hex()}:{dk.hex()}')
" > "$TMP/yuzu-server.cfg"
chmod 600 "$TMP/yuzu-server.cfg"

pass=0 fail=0
check() { # <desc> <expected-exit> <expected-substr>
  local desc="$1" want_exit="$2" want_sub="$3"; shift 3
  local out got
  set +e
  out="$("$BIN" --config "$TMP/yuzu-server.cfg" --data-dir "$TMP" --mfa-reset "$@" 2>/dev/null)"
  got=$?
  set -e
  if [ "$got" = "$want_exit" ] && printf '%s' "$out" | grep -qF "$want_sub"; then
    echo "ok   - $desc"; pass=$((pass+1))
  else
    echo "FAIL - $desc (exit=$got want=$want_exit; out=$out)"; fail=$((fail+1))
  fi
}

# Existing user: cleared, JSON ok, exit 0. (Idempotent on a not-enrolled row.)
check "reset existing user -> ok/exit 0" 0 '"status":"ok"' admin
# Missing user: error, exit 1.
check "reset missing user -> error/exit 1" 1 'not found' ghost

echo "---- $pass passed, $fail failed ----"
[ "$fail" -eq 0 ]
