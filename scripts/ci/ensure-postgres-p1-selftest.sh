#!/usr/bin/env bash
# ensure-postgres-p1-selftest.sh — drives scripts/ci/ensure-postgres.sh path 1
# end to end through a FAKE psql (canned rows and exit codes, no database, no
# network), asserting stdout (the exported DSN line, or its absence),
# stderr (::warning/::error/informational markers) and the fake psql's call
# log (was ALTER SYSTEM actually issued?). scripts/ci/pg-durability.sh's own
# --selftest covers the pure decide/heal-allowed/redact functions in
# isolation; this covers the ensure-postgres.sh GLUE around them — the psql
# resolution ladder, the per-agent probe-and-fallback, the no-fallback rule,
# and the fail arms — none of which is reachable without a live cluster
# otherwise.
#
# Precedent: scripts/ci/check-plugin-readme-touch.sh --selftest (a fake
# external tool on PATH, mktemp -d, ensure-postgres.sh re-exec'd as a
# subprocess with a fully explicit environment). bash 3.2 (macOS /bin/bash)
# AND bash 5.x (MSYS2 on Wee Tam) safe: no mapfile, no associative arrays,
# every `local` initialised.
#
# Usage: ensure-postgres-p1-selftest.sh   (no args)
set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ENSURE="$REPO_ROOT/scripts/ci/ensure-postgres.sh"
BASH_BIN="$(command -v bash)"

TMP="$(mktemp -d "${TMPDIR:-/tmp}/yuzu_test_pg_p1.XXXXXX")"
# shellcheck disable=SC2064
trap "rm -rf '$TMP'" EXIT

FAILURES=0
N=0

# A minimal, host-resolved PATH: path 1 (with a fake psql standing in for
# the real one) only ever needs dirname/sed/sleep/cat as EXTERNAL tools —
# everything else it touches (regex matching, /dev/tcp, string ops) is a
# bash builtin. Symlinking the host's real copies keeps this portable across
# macOS /bin/bash and MSYS2 bash without hard-coding either one's coreutils
# layout.
BASEBIN="$TMP/basebin"
mkdir -p "$BASEBIN"
for _tool in dirname sed sleep cat bash env; do
  _src="$(command -v "$_tool" 2>/dev/null || true)"
  if [[ -n "$_src" ]]; then ln -s "$_src" "$BASEBIN/$_tool"; fi
done

# ── fake psql ────────────────────────────────────────────────────────────
# Every invocation is appended to $FAKE_PSQL_STATE/calls.log (so a case can
# assert whether ALTER SYSTEM was actually issued). Behaviour is chosen by
# scanning the joined args for the SQL text ensure-postgres.sh/pg-durability
# .sh actually issue — a rows/rc pair per query shape, read from files so a
# large or multi-line fixture never risks an execve() ARG_MAX limit.
write_fake_psql() {
  local dir="$1"
  mkdir -p "$dir"
  cat > "$dir/psql" <<'FAKE'
#!/usr/bin/env bash
set -u
STATE="${FAKE_PSQL_STATE:?FAKE_PSQL_STATE not set}"
printf '%s\n' "$*" >> "$STATE/calls.log"
sql=""
for a in "$@"; do sql="$sql
$a"; done
case "$sql" in
  *'SELECT 1'*)
    rc=0
    [[ -f "$STATE/select1_rc" ]] && rc="$(cat "$STATE/select1_rc")"
    [[ "$rc" == "0" ]] && echo "1"
    exit "$rc"
    ;;
  *'ALTER SYSTEM SET fsync'*)
    echo "ALTER SYSTEM issued" >> "$STATE/calls.log"
    rc=0
    [[ -f "$STATE/heal_rc" ]] && rc="$(cat "$STATE/heal_rc")"
    if [[ "$rc" == "0" ]]; then
      : > "$STATE/healed"
      echo "t"
    fi
    exit "$rc"
    ;;
  *'pg_settings'*)
    if [[ -f "$STATE/healed" ]]; then
      rc=0
      [[ -f "$STATE/post_rows_rc" ]] && rc="$(cat "$STATE/post_rows_rc")"
      [[ -f "$STATE/post_rows_out" ]] && cat "$STATE/post_rows_out"
      exit "$rc"
    fi
    rc=0
    [[ -f "$STATE/rows_rc" ]] && rc="$(cat "$STATE/rows_rc")"
    [[ -f "$STATE/rows_out" ]] && cat "$STATE/rows_out"
    exit "$rc"
    ;;
  *)
    echo "fake-psql: unrecognised call: $*" >&2
    exit 99
    ;;
esac
FAKE
  chmod +x "$dir/psql"
}

FAKEBIN="$TMP/fakebin"
write_fake_psql "$FAKEBIN"

# ── fixtures (same shapes as pg-durability.sh --selftest) ──────────────────
CAP_DEFAULT=$'fsync|on|default\nfull_page_writes|on|default\nsynchronous_commit|on|default'
CAP_OFF=$'fsync|off|configuration file\nfull_page_writes|off|configuration file\nsynchronous_commit|off|configuration file'
CAP_REFUSED='psql: error: connection to server at "127.0.0.1", port 54319 failed: Connection refused'

# ── per-case state + invocation ─────────────────────────────────────────────
# new_state <rows_rc> <rows_out> <heal_rc> <post_rows_rc> <post_rows_out>
new_state() {
  local dir="$TMP/state.$N"
  mkdir -p "$dir"
  : > "$dir/calls.log"
  [[ -n "${1:-}" ]] && printf '%s' "$1" > "$dir/rows_rc"
  [[ -n "${2:-}" ]] && printf '%s' "$2" > "$dir/rows_out"
  [[ -n "${3:-}" ]] && printf '%s' "$3" > "$dir/heal_rc"
  [[ -n "${4:-}" ]] && printf '%s' "$4" > "$dir/post_rows_rc"
  [[ -n "${5:-}" ]] && printf '%s' "$5" > "$dir/post_rows_out"
  printf '%s' "$dir"
}

# invoke <state_dir> <runner_name> <github_actions> <dsn> <ci_psql> <path_has_psql 0|1>
# Sets globals OUT, ERR, RC. GITHUB_ENV is deliberately UNSET (mandatory: on
# real CI, emit_dsn would otherwise append a fake DSN to the real job env).
invoke() {
  local state="$1" runner="$2" gha="$3" dsn="$4" ci_psql="$5" path_has_psql="$6"
  local mypath="$BASEBIN"
  [[ "$path_has_psql" == "1" ]] && mypath="$FAKEBIN:$BASEBIN"
  ERR="$state/stderr"
  OUT="$(env -i \
    PATH="$mypath" \
    HOME="${HOME:-/tmp}" \
    RUNNER_NAME="$runner" \
    GITHUB_ACTIONS="$gha" \
    YUZU_TEST_POSTGRES_DSN="$dsn" \
    YUZU_CI_PSQL="$ci_psql" \
    FAKE_PSQL_STATE="$state" \
    YUZU_CI_PG_SLEEP_SCALE=0 \
    "$BASH_BIN" "$ENSURE" 2>"$ERR")"
  RC=$?
}

# expect <name> <field> <want> <got> — field is just a label for the message.
expect() {
  local name="$1" field="$2" want="$3" got="$4"
  if [[ "$got" == "$want" ]]; then
    echo "  ok: $name ($field)"
  else
    echo "  FAIL: $name ($field) expected=[$want] actual=[$got]" >&2
    FAILURES=$((FAILURES + 1))
  fi
}

expect_contains() {
  local name="$1" field="$2" needle="$3" haystack="$4"
  case "$haystack" in
    *"$needle"*) echo "  ok: $name ($field contains '$needle')" ;;
    *)
      echo "  FAIL: $name ($field) expected to contain [$needle], got:" >&2
      printf '%s\n' "$haystack" | sed 's/^/    /' >&2
      FAILURES=$((FAILURES + 1))
      ;;
  esac
}

expect_not_contains() {
  local name="$1" field="$2" needle="$3" haystack="$4"
  case "$haystack" in
    *"$needle"*)
      echo "  FAIL: $name ($field) expected NOT to contain [$needle], got:" >&2
      printf '%s\n' "$haystack" | sed 's/^/    /' >&2
      FAILURES=$((FAILURES + 1))
      ;;
    *) echo "  ok: $name ($field does not contain '$needle')" ;;
  esac
}

DSN0='postgresql://yuzu:yuzu@127.0.0.1:5433/yuzu_test'

# ── 1. ok ────────────────────────────────────────────────────────────────
N=$((N + 1))
state="$(new_state 0 "$CAP_OFF" '' '' '')"
invoke "$state" 'yuzu-fake-windows-0' true "$DSN0" "$FAKEBIN/psql" 0
err="$(cat "$state/stderr")"
expect "ok" "rc" "0" "$RC"
expect_contains "ok" "stdout" "YUZU_TEST_POSTGRES_DSN=${DSN0}" "$OUT"
expect_contains "ok" "stderr" "durability conformance ok" "$err"

# ── 2. heal ──────────────────────────────────────────────────────────────
N=$((N + 1))
state="$(new_state 0 "$CAP_DEFAULT" 0 0 "$CAP_OFF")"
invoke "$state" 'yuzu-fake-windows-0' true "$DSN0" "$FAKEBIN/psql" 0
err="$(cat "$state/stderr")"
calls="$(cat "$state/calls.log")"
expect "heal" "rc" "0" "$RC"
expect_contains "heal" "stderr" "healing with ALTER SYSTEM" "$err"
expect_contains "heal" "stderr" "durability healed" "$err"
expect_contains "heal" "stdout" "YUZU_TEST_POSTGRES_DSN=${DSN0}" "$OUT"
expect_contains "heal" "calls.log" "ALTER SYSTEM issued" "$calls"

# ── 3. drift, not healed (psql from PATH, not the manifest) ────────────────
N=$((N + 1))
state="$(new_state 0 "$CAP_DEFAULT" '' '' '')"
invoke "$state" 'yuzu-fake-windows-0' true "$DSN0" '' 1
err="$(cat "$state/stderr")"
calls="$(cat "$state/calls.log")"
expect "drift-not-healed" "rc" "0" "$RC"
expect_contains "drift-not-healed" "stderr" "NOT healing" "$err"
expect_contains "drift-not-healed" "stdout" "YUZU_TEST_POSTGRES_DSN=${DSN0}" "$OUT"
expect_not_contains "drift-not-healed" "calls.log" "ALTER SYSTEM issued" "$calls"

# ── 4. non-CI informational note (no ::warning) ─────────────────────────────
N=$((N + 1))
state="$(new_state 0 "$CAP_DEFAULT" '' '' '')"
invoke "$state" 'yuzu-fake-windows-0' '' "$DSN0" "$FAKEBIN/psql" 0
err="$(cat "$state/stderr")"
expect "non-ci-note" "rc" "0" "$RC"
expect_contains "non-ci-note" "stderr" "note —" "$err"
expect_not_contains "non-ci-note" "stderr" "::warning" "$err"
expect_contains "non-ci-note" "stdout" "YUZU_TEST_POSTGRES_DSN=${DSN0}" "$OUT"

# ── 5. read fails ────────────────────────────────────────────────────────
N=$((N + 1))
state="$(new_state 2 "$CAP_REFUSED" '' '' '')"
invoke "$state" 'yuzu-fake-windows-0' true "$DSN0" "$FAKEBIN/psql" 0
err="$(cat "$state/stderr")"
expect "read-fails" "rc" "1" "$RC"
expect_contains "read-fails" "stderr" "durability read failed" "$err"
expect_not_contains "read-fails" "stdout" "YUZU_TEST_POSTGRES_DSN=" "$OUT"

# ── 6. heal fails ────────────────────────────────────────────────────────
N=$((N + 1))
state="$(new_state 0 "$CAP_DEFAULT" 1 '' '')"
invoke "$state" 'yuzu-fake-windows-0' true "$DSN0" "$FAKEBIN/psql" 0
err="$(cat "$state/stderr")"
expect "heal-fails" "rc" "1" "$RC"
expect_contains "heal-fails" "stderr" "heal failed on" "$err"
expect_not_contains "heal-fails" "stdout" "YUZU_TEST_POSTGRES_DSN=" "$OUT"

# ── 7. still not off after heal ─────────────────────────────────────────────
N=$((N + 1))
state="$(new_state 0 "$CAP_DEFAULT" 0 0 "$CAP_DEFAULT")"
invoke "$state" 'yuzu-fake-windows-0' true "$DSN0" "$FAKEBIN/psql" 0
err="$(cat "$state/stderr")"
expect "still-not-off" "rc" "1" "$RC"
expect_contains "still-not-off" "stderr" "still not durability-off" "$err"
expect_not_contains "still-not-off" "stdout" "YUZU_TEST_POSTGRES_DSN=" "$OUT"

# ── 8. manifest-vouched per-agent probe fails — no fallback ─────────────────
N=$((N + 1))
state="$(new_state '' '' '' '' '')"
printf '1' > "$state/select1_rc"
invoke "$state" 'yuzu-fake-windows-1' true "$DSN0" "$FAKEBIN/psql" 0
err="$(cat "$state/stderr")"
expect "manifest-no-fallback" "rc" "1" "$RC"
expect_contains "manifest-no-fallback" "stderr" "NOT falling back to the shared agent-0 cluster" "$err"
expect_not_contains "manifest-no-fallback" "stdout" "YUZU_TEST_POSTGRES_DSN=" "$OUT"

# ── 9. PATH-psql per-agent probe fails — falls back, still drifts ──────────
N=$((N + 1))
state="$(new_state 0 "$CAP_DEFAULT" '' '' '')"
printf '1' > "$state/select1_rc"
invoke "$state" 'yuzu-fake-windows-1' true "$DSN0" '' 1
err="$(cat "$state/stderr")"
expect "path-psql-fallback" "rc" "0" "$RC"
expect_contains "path-psql-fallback" "stderr" "falling back to the SHARED pre-set DSN" "$err"
expect_contains "path-psql-fallback" "stderr" "NOT healing" "$err"
expect_contains "path-psql-fallback" "stdout" "YUZU_TEST_POSTGRES_DSN=${DSN0}" "$OUT"

# ── 10. no psql at all — fallback + UNVERIFIED (also covers the TCP-only
#        per-agent branch: the per-agent port has nothing listening) ───────
N=$((N + 1))
state="$(new_state '' '' '' '' '')"
invoke "$state" 'yuzu-fake-windows-1' true "$DSN0" '' 0
err="$(cat "$state/stderr")"
expect "no-psql-unverified" "rc" "0" "$RC"
expect_contains "no-psql-unverified" "stderr" "falling back to the SHARED pre-set DSN" "$err"
expect_contains "no-psql-unverified" "stderr" "UNVERIFIED" "$err"
expect_contains "no-psql-unverified" "stdout" "YUZU_TEST_POSTGRES_DSN=${DSN0}" "$OUT"

# ── 11. YUZU_CI_PSQL set but not executable — S5 warning, then demotes ─────
N=$((N + 1))
state="$(new_state 0 "$CAP_DEFAULT" '' '' '')"
invoke "$state" 'yuzu-fake-windows-0' true "$DSN0" "$TMP/no-such-psql" 1
err="$(cat "$state/stderr")"
expect "bad-yuzu-ci-psql" "rc" "0" "$RC"
expect_contains "bad-yuzu-ci-psql" "stderr" "YUZU_CI_PSQL is set but not executable" "$err"
expect_contains "bad-yuzu-ci-psql" "stdout" "YUZU_TEST_POSTGRES_DSN=${DSN0}" "$OUT"

if [[ "$FAILURES" -eq 0 ]]; then
  echo "ensure-postgres-p1-selftest: all $N cases ok"
  exit 0
fi
echo "ensure-postgres-p1-selftest: $FAILURES of $N cases FAILED" >&2
exit 1
