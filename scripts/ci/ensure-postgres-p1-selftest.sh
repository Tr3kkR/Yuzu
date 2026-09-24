#!/usr/bin/env bash
# ensure-postgres-p1-selftest.sh — drives scripts/ci/ensure-postgres.sh path 1
# end to end through a FAKE psql (canned rows and exit codes, no database, no
# external network — the only socket use is one loopback connect to a
# verified-closed port), asserting stdout (the exported DSN line, or its
# absence), stderr (::warning/::error/informational markers) and the fake
# psql's call log (was ALTER SYSTEM actually issued?). scripts/ci/pg-durability
# .sh's own --selftest covers the pure decide/heal-allowed/redact functions in
# isolation; this covers the ensure-postgres.sh GLUE around them — the psql
# resolution ladder, the per-agent probe-and-fallback, the no-fallback rule,
# and the fail arms — none of which is reachable without a live cluster
# otherwise.
#
# Precedent: scripts/ci/check-plugin-readme-touch.sh --selftest (a fake
# external tool on PATH, mktemp -d, ensure-postgres.sh re-exec'd as a
# subprocess with a fully explicit environment). bash 3.2 (macOS /bin/bash)
# parity is proven by running this harness directly; bash 5 parity is proven
# by running it under /opt/homebrew/bin/bash locally and on the Linux CI
# legs. The harness SKIPS on MSYS2/MinGW/Cygwin (below) — its stripped-PATH,
# `ln -s` tool-farm design (POSIX executable fakes under `env -i`) is
# unproven there; the live 'Ensure Postgres' step proves the path-1 glue on
# Wee Tam itself.
#
# Usage: ensure-postgres-p1-selftest.sh   (no args)
set -u

case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*)
    echo "ensure-postgres-p1-selftest: skipped on Windows (POSIX executable fakes + env -i tool farm); the live 'Ensure Postgres' step proves the path-1 glue on Wee Tam"
    exit 77
    ;;
esac

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ENSURE="$REPO_ROOT/scripts/ci/ensure-postgres.sh"
BASH_BIN="$BASH"

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
  *'yuzu-heal-identity-guard'*)
    # The heal call's own in-session DO-block guards (B1/S-6) are matched
    # here (before the ALTER SYSTEM branch below, since one invocation's
    # joined args contain both): a guard_rc fixture simulates one of them
    # RAISEing before any ALTER SYSTEM is reached — no "ALTER SYSTEM
    # issued" line, no state flip to healed.
    if [[ -f "$STATE/guard_rc" ]]; then
      rc="$(cat "$STATE/guard_rc")"
      [[ -f "$STATE/heal_fail_out" ]] && cat "$STATE/heal_fail_out"
      exit "$rc"
    fi
    echo "ALTER SYSTEM issued" >> "$STATE/calls.log"
    rc=0
    [[ -f "$STATE/heal_rc" ]] && rc="$(cat "$STATE/heal_rc")"
    if [[ "$rc" == "0" ]]; then
      : > "$STATE/healed"
      echo "t"
    else
      [[ -f "$STATE/heal_fail_out" ]] && cat "$STATE/heal_fail_out"
    fi
    exit "$rc"
    ;;
  *'pg_settings'*)
    if [[ -f "$STATE/healed" ]]; then
      rc=0
      [[ -f "$STATE/post_rows_rc" ]] && rc="$(cat "$STATE/post_rows_rc")"
      if [[ "$rc" == "0" ]]; then
        [[ -f "$STATE/post_rows_out" ]] && cat "$STATE/post_rows_out"
      else
        [[ -f "$STATE/post_rows_fail_out" ]] && cat "$STATE/post_rows_fail_out"
      fi
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
# Verbatim two-line real psql connection-refused capture (pg-durability.sh's
# own --selftest cap_refused fixture) — the fake psql cats this whole thing
# as one CAP_REFUSED row, so case 5 exercises the real second line too.
CAP_REFUSED=$'psql: error: connection to server at "127.0.0.1", port 54319 failed: Connection refused\n\tIs the server running on that host and accepting TCP/IP connections?'
# psql exit 0 but the row text is unparseable (e.g. a permission error) —
# not a connection failure.
CAP_NOSUPER='ERROR:  permission denied to set parameter "fsync"'
# S-2/QE-2: a post-read (heal / post-heal re-read) failure's output — one
# genuine server-originated ERROR: line that MUST reach the annotation
# under Actions (p1_server_diag), plus one non-server sentinel line that
# MUST NOT (proves the filter is selective, not just "print everything").
FAKE_FAIL_OUT=$'ERROR:  permission denied to set parameter "fsync"\nfake-psql-sentinel-should-not-appear'
FAKE_GUARD_FAIL_OUT=$'ERROR:  yuzu-heal-identity-guard: connected server 127.0.0.1 port 5433 is not loopback:5434\nfake-psql-sentinel-should-not-appear'

# ── per-case state + invocation ─────────────────────────────────────────────
# new_state <rows_rc> <rows_out> <heal_rc> <post_rows_rc> <post_rows_out>
#           [heal_fail_out] [post_rows_fail_out] [guard_rc]
new_state() {
  local dir="$TMP/state.$N"
  mkdir -p "$dir"
  : > "$dir/calls.log"
  [[ -n "${1:-}" ]] && printf '%s' "$1" > "$dir/rows_rc"
  [[ -n "${2:-}" ]] && printf '%s' "$2" > "$dir/rows_out"
  [[ -n "${3:-}" ]] && printf '%s' "$3" > "$dir/heal_rc"
  [[ -n "${4:-}" ]] && printf '%s' "$4" > "$dir/post_rows_rc"
  [[ -n "${5:-}" ]] && printf '%s' "$5" > "$dir/post_rows_out"
  [[ -n "${6:-}" ]] && printf '%s' "$6" > "$dir/heal_fail_out"
  [[ -n "${7:-}" ]] && printf '%s' "$7" > "$dir/post_rows_fail_out"
  [[ -n "${8:-}" ]] && printf '%s' "$8" > "$dir/guard_rc"
  printf '%s' "$dir"
}

# invoke <state_dir> <runner_name> <github_actions> <dsn> <ci_psql> <path_has_psql 0|1> [extra_env...]
# Sets globals OUT, ERR, RC. GITHUB_ENV is deliberately UNSET (mandatory: on
# real CI, emit_dsn would otherwise append a fake DSN to the real job env).
# extra_env entries are additional NAME=value pairs (e.g. PGHOST=127.0.0.1)
# folded into the same env -i invocation, for B1's env-override case.
invoke() {
  local state="$1" runner="$2" gha="$3" dsn="$4" ci_psql="$5" path_has_psql="$6"
  shift 6
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
    "$@" \
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

# port_open <host> <port> — pure-bash TCP probe, same idiom as
# ensure-postgres.sh's own tcp_probe. Returns 0 if something answers, 1 on a
# refused/closed/filtered port.
port_open() {
  local host="$1" port="$2"
  (exec 3<>"/dev/tcp/${host}/${port}") >/dev/null 2>&1
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
expect_contains "heal" "stderr" "durability healed on 127.0.0.1:5433 (attempt 1)" "$err"
expect_contains "heal" "stdout" "YUZU_TEST_POSTGRES_DSN=${DSN0}" "$OUT"
expect_contains "heal" "calls.log" "ALTER SYSTEM issued" "$calls"
expect_contains "heal" "calls.log" "--dbname=${DSN0}" "$calls"
# QE-2 (folded): the heal ::warning:: line flattens $rows via p1_flatten —
# assert it is single-line and TAB-free here, where real content IS printed
# (moved off case 5, which withholds under Actions and made the same
# assertion vacuous).
warn_line="$(grep '^::warning::.*healing with ALTER SYSTEM' "$err")"
expect "heal" "::warning:: line count" "1" "$(grep -c '^::warning::.*healing with ALTER SYSTEM' <<<"$err")"
expect "heal" "no tab byte in the heal ::warning:: line" "0" "$(grep -c $'\t' <<<"$warn_line")"

# ── 3. drift, not healed (psql from PATH, not the manifest) ────────────────
N=$((N + 1))
state="$(new_state 0 "$CAP_DEFAULT" '' '' '')"
invoke "$state" 'yuzu-fake-windows-0' true "$DSN0" '' 1
err="$(cat "$state/stderr")"
calls="$(cat "$state/calls.log")"
expect "drift-not-healed" "rc" "0" "$RC"
expect_contains "drift-not-healed" "stderr" "NOT healing" "$err"
expect_contains "drift-not-healed" "stderr" "psql source: path" "$err"
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

# ── 5. read fails (under Actions: raw psql diagnostic withheld) ────────────
N=$((N + 1))
state="$(new_state 2 "$CAP_REFUSED" '' '' '')"
invoke "$state" 'yuzu-fake-windows-0' true "$DSN0" "$FAKEBIN/psql" 0
err="$(cat "$state/stderr")"
expect "read-fails" "rc" "1" "$RC"
expect_contains "read-fails" "stderr" "durability read failed" "$err"
expect_not_contains "read-fails" "stdout" "YUZU_TEST_POSTGRES_DSN=" "$OUT"
expect "read-fails" "::error:: line count" "1" "$(grep -c '^::error::' "$state/stderr")"
error_line="$(grep '^::error::' "$state/stderr")"
expect_contains "read-fails" "::error:: line" "durability read failed" "$error_line"
expect_contains "read-fails" "::error:: line" "psql rc=2" "$error_line"
expect_not_contains "read-fails" "::error:: line" "Is the server running" "$error_line"

# ── 5b. read fails outside Actions — raw diagnostic RETAINED (developer
#        shells still get the real psql text, only public Actions
#        annotations withhold it) ───────────────────────────────────────────
N=$((N + 1))
state="$(new_state 2 "$CAP_REFUSED" '' '' '')"
invoke "$state" 'yuzu-fake-windows-0' '' "$DSN0" "$FAKEBIN/psql" 0
err="$(cat "$state/stderr")"
expect "read-fails-no-actions" "rc" "1" "$RC"
expect_contains "read-fails-no-actions" "stderr" "durability read failed" "$err"
expect_contains "read-fails-no-actions" "stderr" "Is the server running" "$err"
expect_not_contains "read-fails-no-actions" "stdout" "YUZU_TEST_POSTGRES_DSN=" "$OUT"
# B2: outside Actions the redacted DSN is still appended — and QE-2's
# TAB/one-line assertions belong here now, where the real (flattened)
# diagnostic text is actually printed.
expect_contains "read-fails-no-actions" "stderr" "(postgresql://***@127.0.0.1:5433/yuzu_test)" "$err"
error_line_noactions="$(grep '^::error::' <<<"$err")"
expect "read-fails-no-actions" "::error:: line count" "1" "$(grep -c '^::error::' <<<"$err")"
expect "read-fails-no-actions" "no tab byte anywhere in the ::error:: line" "0" "$(grep -c $'\t' <<<"$error_line_noactions")"

# ── 5c. malformed-URI password never reaches stderr under Actions ──────────
# Real psql (18.6) on an invalid percent-encoded DSN password exits 2 and
# echoes the offending token verbatim: `psql: error: invalid percent-encoded
# token: "codex_secret_%ZZ"`. Fake psql stands in for that exact capture.
N=$((N + 1))
CAP_BADURI='psql: error: invalid percent-encoded token: "codex_secret_%ZZ"'
DSN_BADURI='postgresql://alice:codex_secret_%ZZ@127.0.0.1:55439/postgres'
state="$(new_state 2 "$CAP_BADURI" '' '' '')"
invoke "$state" 'yuzu-fake-windows-0' true "$DSN_BADURI" "$FAKEBIN/psql" 0
err="$(cat "$state/stderr")"
expect "malformed-uri-withheld" "rc" "1" "$RC"
expect_not_contains "malformed-uri-withheld" "stderr" "codex_secret_%ZZ" "$err"
expect_contains "malformed-uri-withheld" "stderr" "psql rc=2" "$err"

# ── 5d/5e. B2: the read-failed arm no longer prints ANY DSN-derived string
#            under Actions (dsn_redacted dropped from that arm entirely),
#            so pg_dsn_redact's two known gaps — a backslash-escaped space,
#            a percent-encoded keyword — can no longer leak through it. ───
N=$((N + 1))
DSN_BSSPACE='postgresql://yuzu:correct\ horse@127.0.0.1:5433/db'
state="$(new_state 2 "$CAP_REFUSED" '' '' '')"
invoke "$state" 'yuzu-fake-windows-0' true "$DSN_BSSPACE" "$FAKEBIN/psql" 0
err="$(cat "$state/stderr")"
expect "read-fails-bsspace" "rc" "1" "$RC"
expect_not_contains "read-fails-bsspace" "stderr" "horse" "$err"

N=$((N + 1))
DSN_PCTKW='postgresql://yuzu@127.0.0.1:5433/db?pass%77ord=hunter2'
state="$(new_state 2 "$CAP_REFUSED" '' '' '')"
invoke "$state" 'yuzu-fake-windows-0' true "$DSN_PCTKW" "$FAKEBIN/psql" 0
err="$(cat "$state/stderr")"
expect "read-fails-pctkw" "rc" "1" "$RC"
expect_not_contains "read-fails-pctkw" "stderr" "hunter2" "$err"

# ── 6. heal fails (a server-originated ERROR reaches the annotation via
#       p1_server_diag; the fake's non-server sentinel line does not) ──────
N=$((N + 1))
state="$(new_state 0 "$CAP_DEFAULT" 1 '' '' "$FAKE_FAIL_OUT")"
invoke "$state" 'yuzu-fake-windows-0' true "$DSN0" "$FAKEBIN/psql" 0
err="$(cat "$state/stderr")"
expect "heal-fails" "rc" "1" "$RC"
expect_contains "heal-fails" "stderr" "heal failed on" "$err"
expect_contains "heal-fails" "stderr" "guard" "$err"
expect_contains "heal-fails" "stderr" 'ERROR:  permission denied to set parameter "fsync"' "$err"
expect_not_contains "heal-fails" "stderr" "fake-psql-sentinel-should-not-appear" "$err"
expect_not_contains "heal-fails" "stdout" "YUZU_TEST_POSTGRES_DSN=" "$OUT"

# ── 6b. B1/S-6: the heal's own in-session guard fires (simulated: the fake
#        exits 3 on the heal call without ever writing "ALTER SYSTEM
#        issued") — the heal-failed arm names the guard, no ALTER lands. ──
N=$((N + 1))
state="$(new_state 0 "$CAP_DEFAULT" '' '' '' "$FAKE_GUARD_FAIL_OUT" '' 3)"
invoke "$state" 'yuzu-fake-windows-0' true "$DSN0" "$FAKEBIN/psql" 0
err="$(cat "$state/stderr")"
calls="$(cat "$state/calls.log")"
expect "heal-guard-fails" "rc" "1" "$RC"
expect_contains "heal-guard-fails" "stderr" "heal failed on" "$err"
expect_contains "heal-guard-fails" "stderr" "identity guard" "$err"
expect_contains "heal-guard-fails" "stderr" "yuzu-heal-identity-guard" "$err"
expect_not_contains "heal-guard-fails" "stderr" "fake-psql-sentinel-should-not-appear" "$err"
expect_not_contains "heal-guard-fails" "calls.log" "ALTER SYSTEM issued" "$calls"

# ── 7. still not off after heal (rc=0 on the re-read: trusted rows print) ──
N=$((N + 1))
state="$(new_state 0 "$CAP_DEFAULT" 0 0 "$CAP_DEFAULT")"
invoke "$state" 'yuzu-fake-windows-0' true "$DSN0" "$FAKEBIN/psql" 0
err="$(cat "$state/stderr")"
expect "still-not-off" "rc" "1" "$RC"
expect_contains "still-not-off" "stderr" "still not durability-off" "$err"
expect_not_contains "still-not-off" "stdout" "YUZU_TEST_POSTGRES_DSN=" "$OUT"

# ── 7b. S-2 rule (c): the post-heal re-read itself fails (rc != 0) — a
#        distinct message from "still not off", filtered via
#        p1_server_diag exactly like the heal-failed arm. ─────────────────
N=$((N + 1))
state="$(new_state 0 "$CAP_DEFAULT" 0 2 '' '' "$FAKE_FAIL_OUT")"
invoke "$state" 'yuzu-fake-windows-0' true "$DSN0" "$FAKEBIN/psql" 0
err="$(cat "$state/stderr")"
expect "reread-fails" "rc" "1" "$RC"
expect_contains "reread-fails" "stderr" "could not re-read after heal" "$err"
expect_contains "reread-fails" "stderr" "psql rc=2" "$err"
expect_contains "reread-fails" "stderr" 'ERROR:  permission denied to set parameter "fsync"' "$err"
expect_not_contains "reread-fails" "stderr" "fake-psql-sentinel-should-not-appear" "$err"
expect_not_contains "reread-fails" "stdout" "YUZU_TEST_POSTGRES_DSN=" "$OUT"

# ── 8. manifest-vouched per-agent probe fails — no fallback ─────────────────
N=$((N + 1))
state="$(new_state '' '' '' '' '')"
printf '1' > "$state/select1_rc"
invoke "$state" 'yuzu-fake-windows-1' true "$DSN0" "$FAKEBIN/psql" 0
err="$(cat "$state/stderr")"
calls="$(cat "$state/calls.log")"
expect "manifest-no-fallback" "rc" "1" "$RC"
expect_contains "manifest-no-fallback" "stderr" "NOT falling back to the shared agent-0 cluster" "$err"
expect_not_contains "manifest-no-fallback" "stdout" "YUZU_TEST_POSTGRES_DSN=" "$OUT"
expect_not_contains "manifest-no-fallback" "calls.log" "ALTER SYSTEM issued" "$calls"
expect "manifest-no-fallback" "SELECT 1 attempts" "4" "$(grep -c 'SELECT 1' "$state/calls.log")"

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
# Needs base+1 (the derived per-agent port, agent index 1) to be genuinely
# CLOSED so the real /dev/tcp probe fails — a fixed base of 5433 false-fails
# on the Wee Tam Windows pool, where :5434 is agent 1's own live cluster.
# Search a short candidate list for a base whose neighbour port is
# verifiably closed right now (same idiom as ensure-postgres.sh's tcp_probe).
N=$((N + 1))
# UP-12: candidates below the ephemeral range (macOS 49152+, Linux
# 32768+) and outside well-known/registered CI ports, so a concurrent
# port-0 bind on this host can't race the check.
CASE10_BASE=""
for _cand in 5433 25573 26681 28734 29917 31184; do
  if ! port_open 127.0.0.1 "$((_cand + 1))"; then
    CASE10_BASE="$_cand"
    break
  fi
done
if [[ -z "$CASE10_BASE" ]]; then
  echo "  skip: no-psql-unverified (every candidate loopback port answers)"
else
  DSN10="postgresql://yuzu:yuzu@127.0.0.1:${CASE10_BASE}/yuzu_test"
  state="$(new_state '' '' '' '' '')"
  invoke "$state" 'yuzu-fake-windows-1' true "$DSN10" '' 0
  err="$(cat "$state/stderr")"
  expect "no-psql-unverified" "rc" "0" "$RC"
  expect_contains "no-psql-unverified" "stderr" "falling back to the SHARED pre-set DSN" "$err"
  expect_contains "no-psql-unverified" "stderr" "UNVERIFIED" "$err"
  expect_contains "no-psql-unverified" "stdout" "YUZU_TEST_POSTGRES_DSN=${DSN10}" "$OUT"
fi

# ── 11. YUZU_CI_PSQL set but not executable — S5 warning, then demotes ─────
N=$((N + 1))
state="$(new_state 0 "$CAP_DEFAULT" '' '' '')"
invoke "$state" 'yuzu-fake-windows-0' true "$DSN0" "$TMP/no-such-psql" 1
err="$(cat "$state/stderr")"
expect "bad-yuzu-ci-psql" "rc" "0" "$RC"
expect_contains "bad-yuzu-ci-psql" "stderr" "YUZU_CI_PSQL is set but not executable" "$err"
expect_contains "bad-yuzu-ci-psql" "stdout" "YUZU_TEST_POSTGRES_DSN=${DSN0}" "$OUT"

# ── 12. durability settings unreadable — psql exits 0 with non-row text ────
N=$((N + 1))
state="$(new_state 0 "$CAP_NOSUPER" '' '' '')"
invoke "$state" 'yuzu-fake-windows-0' true "$DSN0" "$FAKEBIN/psql" 0
err="$(cat "$state/stderr")"
calls="$(cat "$state/calls.log")"
expect "unreadable-settings" "rc" "1" "$RC"
expect_contains "unreadable-settings" "stderr" "durability settings unreadable" "$err"
expect_contains "unreadable-settings" "stderr" "unparseable" "$err"
expect_not_contains "unreadable-settings" "stdout" "YUZU_TEST_POSTGRES_DSN=" "$OUT"
expect_not_contains "unreadable-settings" "calls.log" "ALTER SYSTEM issued" "$calls"

# ── 13. per-agent HAPPY path — SELECT 1 ok, only the per-agent DSN healed
#         (nothing here) / conforms, and it alone is exported ─────────────
N=$((N + 1))
DSN1='postgresql://yuzu:yuzu@127.0.0.1:5434/yuzu_test'
state="$(new_state 0 "$CAP_OFF" '' '' '')"
invoke "$state" 'yuzu-fake-windows-1' true "$DSN0" "$FAKEBIN/psql" 0
err="$(cat "$state/stderr")"
expect "per-agent-happy" "rc" "0" "$RC"
expect_contains "per-agent-happy" "stdout" "YUZU_TEST_POSTGRES_DSN=${DSN1}" "$OUT"
expect_contains "per-agent-happy" "stderr" "per-agent port 5434" "$err"
expect_contains "per-agent-happy" "stderr" "durability conformance ok on 127.0.0.1:5434" "$err"
expect_not_contains "per-agent-happy" "stderr" "falling back" "$err"

# ── 14. B1: a `?port=` DSN is never provable — drift-only, no ALTER, even
#          though host/psql-source/Actions would otherwise allow a heal.
#          Exact repro shape from the governance finding: the authority
#          parses as :56551 but a query-string `port=` can redirect libpq
#          to :56552 — the DSN string alone cannot prove which one. ───────
N=$((N + 1))
DSN_QPORT='postgresql://yuzu@127.0.0.1:56551/postgres?port=56552'
state="$(new_state 0 "$CAP_DEFAULT" '' '' '')"
invoke "$state" 'yuzu-fake-windows-0' true "$DSN_QPORT" "$FAKEBIN/psql" 0
err="$(cat "$state/stderr")"
calls="$(cat "$state/calls.log")"
expect "qport-not-provable" "rc" "0" "$RC"
expect_contains "qport-not-provable" "stderr" "NOT healing" "$err"
expect_contains "qport-not-provable" "stderr" "cannot prove the target" "$err"
expect_contains "qport-not-provable" "stdout" "YUZU_TEST_POSTGRES_DSN=${DSN_QPORT}" "$OUT"
expect_not_contains "qport-not-provable" "calls.log" "ALTER SYSTEM issued" "$calls"

# ── 15. B1: a PGHOST-family env var in the job/runner environment refuses
#           the heal even for an otherwise-perfect manifest/loopback DSN —
#           libpq honours PGHOST over the DSN's own authority, so the DSN
#           string cannot prove where the connection actually lands. ──────
N=$((N + 1))
state="$(new_state 0 "$CAP_DEFAULT" '' '' '')"
invoke "$state" 'yuzu-fake-windows-0' true "$DSN0" "$FAKEBIN/psql" 0 PGHOST=127.0.0.1
err="$(cat "$state/stderr")"
calls="$(cat "$state/calls.log")"
expect "env-override-not-provable" "rc" "0" "$RC"
expect_contains "env-override-not-provable" "stderr" "cannot prove the target" "$err"
expect_contains "env-override-not-provable" "stderr" "PGHOST" "$err"
expect_not_contains "env-override-not-provable" "calls.log" "ALTER SYSTEM issued" "$calls"

# ── 16. per-agent read-fail (runner -1): the conformance READ itself fails
#          on the derived :5434 DSN — rc 1, no DSN exported. ───────────────
N=$((N + 1))
state="$(new_state 2 "$CAP_REFUSED" '' '' '')"
invoke "$state" 'yuzu-fake-windows-1' true "$DSN0" "$FAKEBIN/psql" 0
err="$(cat "$state/stderr")"
expect "per-agent-read-fails" "rc" "1" "$RC"
expect_contains "per-agent-read-fails" "stderr" "durability read failed on 127.0.0.1:5434" "$err"
expect_not_contains "per-agent-read-fails" "stdout" "YUZU_TEST_POSTGRES_DSN=" "$OUT"

# ── 17. per-agent unreadable settings (runner -1) on the derived :5434
#          DSN — rc 1, no DSN exported, no ALTER issued. ───────────────────
N=$((N + 1))
state="$(new_state 0 "$CAP_NOSUPER" '' '' '')"
invoke "$state" 'yuzu-fake-windows-1' true "$DSN0" "$FAKEBIN/psql" 0
err="$(cat "$state/stderr")"
calls="$(cat "$state/calls.log")"
expect "per-agent-unreadable" "rc" "1" "$RC"
expect_contains "per-agent-unreadable" "stderr" "durability settings unreadable on 127.0.0.1:5434" "$err"
expect_not_contains "per-agent-unreadable" "stdout" "YUZU_TEST_POSTGRES_DSN=" "$OUT"
expect_not_contains "per-agent-unreadable" "calls.log" "ALTER SYSTEM issued" "$calls"

# ── 18. BC-2/CA-2 shape: runner -1 drift->heal — all three ALTERs + the
#          reload go to the derived :5434 cluster, and NOTHING (no ALTER,
#          no dbname mention) targets the shared :5433 base DSN. ──────────
N=$((N + 1))
state="$(new_state 0 "$CAP_DEFAULT" 0 0 "$CAP_OFF")"
invoke "$state" 'yuzu-fake-windows-1' true "$DSN0" "$FAKEBIN/psql" 0
err="$(cat "$state/stderr")"
calls="$(cat "$state/calls.log")"
expect "per-agent-heal-port" "rc" "0" "$RC"
expect_contains "per-agent-heal-port" "stderr" "durability healed on 127.0.0.1:5434" "$err"
expect "per-agent-heal-port" "ALTER SYSTEM issued exactly once" "1" "$(grep -c 'ALTER SYSTEM issued' "$state/calls.log")"
alter_calls="$(grep -- '--dbname=.*ALTER SYSTEM\|ALTER SYSTEM' "$state/calls.log" | grep -v '^ALTER SYSTEM issued$')"
expect_not_contains "per-agent-heal-port" "ALTER-bearing calls" ":5433/" "$alter_calls"
expect_contains "per-agent-heal-port" "ALTER-bearing calls" ":5434/" "$alter_calls"

# ── 19. AGENT_IDX="">9 parity (S-5/CA-5): a runner name suffix of 10+
#          digits is NOT treated as a pool agent index — the base DSN is
#          exported as-is, with conformance run on the base cluster. ──────
N=$((N + 1))
state="$(new_state 0 "$CAP_OFF" '' '' '')"
invoke "$state" 'yuzu-fake-windows-10' true "$DSN0" "$FAKEBIN/psql" 0
err="$(cat "$state/stderr")"
expect "runner-suffix-10-not-agent" "rc" "0" "$RC"
expect_contains "runner-suffix-10-not-agent" "stdout" "YUZU_TEST_POSTGRES_DSN=${DSN0}" "$OUT"
expect_contains "runner-suffix-10-not-agent" "stderr" "durability conformance ok on 127.0.0.1:5433" "$err"
expect_not_contains "runner-suffix-10-not-agent" "stderr" "per-agent port" "$err"

if [[ "$FAILURES" -eq 0 ]]; then
  echo "ensure-postgres-p1-selftest: all $N cases ok"
  exit 0
fi
echo "ensure-postgres-p1-selftest: $FAILURES assertion(s) FAILED across $N cases" >&2
exit 1
