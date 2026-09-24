#!/usr/bin/env bash
# pg-durability.sh — pure decision/formatting library for the per-job
# Postgres durability-off conformance guard (Wee Tam Windows CI: every
# Windows job must verify, and heal if drifted, the fsync/synchronous_commit/
# full_page_writes=off settings of the per-agent cluster it is about to use,
# instead of discovering drift as a 700 s [pg]-shard TIMEOUT).
#
# This file is SOURCED into the CI step shell via the `source
# scripts/ci/ensure-postgres.sh` step in ci.yml, so every top-level name here
# is prefixed `pg_`/`pg_durability_` to avoid leaking into that shell. There
# is no top-level side-effecting code other than the guarded --selftest
# dispatch at the bottom.
#
# bash 3.2 (macOS /bin/bash) AND bash 5.x (MSYS2 on the Wee Tam Windows
# runners) both source this file under `set -euo pipefail` (the top of
# ensure-postgres.sh), so every `local` below is initialised on the same
# line it is declared — an uninitialised `local rc` read before assignment
# is silently tolerated by bash 3.2 but aborts bash 5 with "rc: unbound
# variable" (reproduced on this Mac: /opt/homebrew/bin/bash 5.3 aborts,
# /bin/bash 3.2 does not). No mapfile/associative-arrays/${var,,} (bash 3.2
# has none of those).
#
# Fixture provenance for --selftest: verbatim captures from a throwaway
# trust-auth PostgreSQL 18.6 cluster (Homebrew, aarch64-apple-darwin),
# 127.0.0.1:54318, captured 2026-09-24. Query used for the multi-row
# fixtures: SELECT name, setting, source FROM pg_settings WHERE name IN
# ('fsync','synchronous_commit','full_page_writes') ORDER BY name -tA. Four
# fixtures below are NOT separate live captures, but synthetic derivatives
# built from the real ones (the query above always returns all three rows
# well-formed, so a malformed/short/oversized read only happens via a
# synthetic fixture): the single-CRLF-line-endings fixture (line endings of
# the post-heal capture rewritten), the missing-synchronous_commit fixture
# (the default capture's third row dropped), the 2-field-row fixture (a
# row's own `|source` column dropped), and the 4-field-row fixture (an
# extra `|extra` column appended to a row). The guard-failure fixtures used
# by scripts/ci/ensure-postgres-p1-selftest.sh (the identity-guard and
# config-parse-guard RAISE text) are real PostgreSQL 18.6 captures too, with
# only their port numbers adjusted to the harness's own fixture ports —
# see that file's own fixture comments for their provenance.

# pg_durability_decide <allow_heal 0|1> <rows_text>
#
# rows_text is `name|setting|source` lines (as `psql -tA` prints them, CRLF
# tolerated, blank lines ignored). Exactly the three settings fsync,
# full_page_writes, synchronous_commit must each appear. Prints exactly one
# of:
#   ok                    — all three already read 'off' (any value other
#                            than 'off' counts as not-off, including
#                            synchronous_commit=local)
#   heal <names>          — allow_heal=1 and at least one of the three is not
#                            'off'; <names> lists every such setting, in the
#                            order its row appeared
#   drift <names>         — allow_heal=0, same detection as above
#   fail missing:<names>  — one or more of the three settings has no row
#   fail unparseable      — rows_text is empty, or contains no line with
#                            exactly three '|'-separated fields
#
# Returns 0 for ok/heal/drift, 1 for fail.
pg_durability_decide() {
  local allow_heal="$1" rows_text="$2"
  local line='' name='' setting='' source_col='' rest=''
  local seen_fsync=0 seen_fpw=0 seen_sc=0 saw_any_row=0
  local not_off_names=''
  # Strip \r (CRLF tolerance) without touching bash-3.2-unsupported
  # substitutions; a plain parameter substitution is fine on both.
  rows_text="${rows_text//$'\r'/}"
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    IFS='|' read -r name setting source_col rest <<<"$line"
    if [[ -z "$name" || -z "$setting" ]] || [[ "$rest" != "" ]]; then
      # Not a well-formed 3-field row (rest non-empty means >3 fields, or an
      # error line with no '|' at all leaves setting empty).
      continue
    fi
    # A 2-field line "name|value" leaves source_col empty (setting takes the
    # rest), and pg_settings.source is never empty for a real row — so
    # require a non-empty source_col to accept the row.
    [[ -z "$source_col" ]] && continue
    saw_any_row=1
    case "$name" in
      fsync) seen_fsync=1; [[ "$setting" != "off" ]] && { not_off_names="${not_off_names}${not_off_names:+ }fsync"; } ;;
      full_page_writes) seen_fpw=1; [[ "$setting" != "off" ]] && { not_off_names="${not_off_names}${not_off_names:+ }full_page_writes"; } ;;
      synchronous_commit) seen_sc=1; [[ "$setting" != "off" ]] && { not_off_names="${not_off_names}${not_off_names:+ }synchronous_commit"; } ;;
      *) : ;;
    esac
  done <<<"$rows_text"

  if [[ "$saw_any_row" != "1" ]]; then
    echo "fail unparseable"
    return 1
  fi
  local missing=''
  [[ "$seen_fsync" != "1" ]] && missing="${missing}${missing:+ }fsync"
  [[ "$seen_fpw" != "1" ]] && missing="${missing}${missing:+ }full_page_writes"
  [[ "$seen_sc" != "1" ]] && missing="${missing}${missing:+ }synchronous_commit"
  if [[ -n "$missing" ]]; then
    echo "fail missing:${missing// /,}"
    return 1
  fi

  if [[ -z "$not_off_names" ]]; then
    echo "ok"
    return 0
  fi
  if [[ "$allow_heal" == "1" ]]; then
    echo "heal ${not_off_names}"
  else
    echo "drift ${not_off_names}"
  fi
  return 0
}

# pg_heal_allowed <github_actions> <host> <psql_src> <provable 0|1>
#
# Returns 0 only when this job may run ALTER SYSTEM against the cluster. ALL
# FOUR conditions MUST hold, and the caller MUST compute each independently
# rather than assume one implies another:
#   $1 MUST be exactly "true" (GITHUB_ACTIONS) — never a developer shell or
#      a non-Actions CI tier;
#   $2 MUST be a loopback host, "127.0.0.1" or "localhost" (IPv6 loopback is
#      deliberately absent: pg_dsn_host_port's host group [^:/@]+ can never
#      yield "::1"/"[::1]", so an IPv6 DSN always reads '?' here and is
#      drift-only, never healed);
#   $3 MUST be exactly "manifest" (the psql came from YUZU_CI_PSQL, which is
#      only ever exported by deploy/windows/Assert-Toolchain.ps1
#      -ExportCiEnv from a Provision-Windows-Runner.ps1 manifest — the
#      manifest is the declaration that this cluster is disposable CI
#      infrastructure); and
#   $4 MUST be exactly "1" — the caller's own pg_dsn_target_provable("$dsn")
#      result, computed BEFORE calling this function (this function does
#      not call pg_dsn_target_provable itself, so a caller that skips that
#      call and passes a literal "1" defeats this whole condition — see
#      that function's doc comment for why a DSN with a query string or
#      more than one '@' in its authority cannot be trusted as a statement
#      of where libpq actually connects, e.g.
#      `postgresql://yuzu@127.0.0.1:P1/db?port=P2` reading host:port as P1
#      while libpq itself dials P2).
#
# This DSN-string check only bounds what a caller ATTEMPTS; it is not the
# authoritative bound on what a heal actually mutates — see the in-session
# identity guard inside ensure-postgres.sh's p1_conform for that.
pg_heal_allowed() {
  local github_actions="$1" host="$2" psql_src="$3" provable="$4"
  if [[ "$github_actions" == "true" ]] && [[ "$host" == "127.0.0.1" || "$host" == "localhost" ]] && [[ "$psql_src" == "manifest" ]] && [[ "$provable" == "1" ]]; then
    return 0
  fi
  return 1
}

# pg_dsn_host_port <dsn> — prints "host:port" for a URI-form DSN (the same
# regex the per-agent derivation in ensure-postgres.sh path 1 uses), else
# "?".
pg_dsn_host_port() {
  local dsn="$1"
  if [[ "$dsn" =~ ^(.*@([^:/@]+)):([0-9]+)(/.*)$ ]]; then
    echo "${BASH_REMATCH[2]}:${BASH_REMATCH[3]}"
  else
    echo "?"
  fi
}

# pg_dsn_redact <dsn> — strips userinfo (user[:password]) from a URI-form
# DSN's authority, e.g. postgresql://yuzu:yuzu@127.0.0.1:5433/db ->
# postgresql://***@127.0.0.1:5433/db, AND redacts a keyword-form `password=`
# value (path 1 accepts both forms, including whitespace around `=` and a
# single-quoted value that may itself contain whitespace or an escaped
# quote — libpq's conninfo_parse accepts all of these). The URI-authority
# strip is greedy (`://.*@`, taking the LAST '@' in the string) so a raw '@'
# inside the password itself does not leak a fragment after it — this can
# over-redact a literal '@' in a query string, which is an acceptable
# trade-off next to a leaked credential. Unchanged when there is no '@' and
# no `password=`.
pg_dsn_redact() {
  local dsn="$1"
  printf '%s' "$dsn" | sed -E 's#://.*@#://***@#; s/password[[:space:]]*=[[:space:]]*('"'"'([^'"'"'\\]|\\.)*'"'"'|[^[:space:]]*)/password=***/g'
}

# pg_dsn_target_provable <dsn> — returns 0 only when a URI-form DSN's
# AUTHORITY (the substring between "://" and the first following '/', per
# RFC 3986) is a RELIABLE statement of where libpq actually connects, i.e.
# it is safe input to pg_heal_allowed's loopback check. This is a stricter,
# independent shape check than pg_dsn_host_port's — that function's
# host-capture group is GREEDY (`.*@`, anchored on the LAST '@' anywhere in
# the whole string, including past the first '/'), which is exactly what
# let `postgresql://%2Fsock/x@127.0.0.1:5433/db` read as host:port
# 127.0.0.1:5433 although libpq itself ends the host at the FIRST '/' after
# "://" and so actually dials the Unix-socket directory "%2Fsock" — a
# provability check built on the same greedy regex cannot catch that
# shape, so this function re-derives the authority boundary from scratch:
#   - the whole string matches a scheme + "://" + authority (+ optional
#     "/rest") shape, with the authority captured as everything up to the
#     first '/' after "://" — never past it;
#   - the authority contains no '?': a URI-form DSN's query string is
#     itself a bag of libpq keyword=value parameters (RFC 3986-style
#     `key=value[&...]`) — `postgresql://yuzu@127.0.0.1:56551/postgres
#     ?port=56552` parses its authority as host=127.0.0.1 port=56551, but
#     libpq's own conninfo parser applies the query string's `port=56552`
#     on top, so the connection actually lands on 56552. Any query string
#     could carry a hidden `host=`/`hostaddr=`/`port=` override, so its
#     mere presence disqualifies the DSN, regardless of what it happens to
#     contain today (checked on the whole DSN, not just the authority — a
#     '?' could in principle appear before the authority too);
#   - the authority contains exactly one '@' and matches `<userinfo>@
#     <host>:<port>` with no '/' or '@' inside the host (userinfo MAY
#     contain ':', e.g. `user:password@host:port`) — a userinfo-free
#     authority, a second '@' inside it, or a non-numeric/missing port all
#     mean this function cannot derive a trustworthy host:port from it.
# Returns 1 (not provable) on any of the above; 0 only when all hold.
pg_dsn_target_provable() {
  local dsn="$1"
  case "$dsn" in *'?'*) return 1 ;; esac
  [[ "$dsn" =~ ^[A-Za-z][A-Za-z0-9+.-]*://([^/]*)(/.*)?$ ]] || return 1
  local authority="${BASH_REMATCH[1]}"
  local at_count=0 rest="$authority"
  while [[ "$rest" == *"@"* ]]; do
    at_count=$((at_count + 1))
    rest="${rest#*@}"
  done
  [[ "$at_count" -eq 1 ]] || return 1
  [[ "$authority" =~ ^[^@]+@[^:/@]+:[0-9]+$ ]] || return 1
  return 0
}

# pg_psql_path_from_env <value> — backslash -> forward-slash (Windows-form
# manifest paths, e.g. D:\ci\pgbin\agent-1\bin\psql.exe, must be
# forward-slashed for MSYS2 bash to exec them); empty in, empty out.
pg_psql_path_from_env() {
  local value="$1"
  printf '%s' "${value//\\//}"
}

# ── selftest ─────────────────────────────────────────────────────────────
# pg_durability_check <name> <expected> <actual> — one `  ok:`/`  FAIL:` line
# per case (check-plugin-readme-touch.sh's own selftest prints only on
# failure; this one always names the passing case too, for an easy tally)
# and returns 1 on mismatch, else 0. Increments PGD_FAILURES on mismatch
# (initialised by the caller — nounset-safe).
pg_durability_check() {
  local name="$1" expected="$2" actual="$3"
  if [[ "$actual" == "$expected" ]]; then
    echo "  ok: $name"
    return 0
  fi
  echo "  FAIL: $name expected=[$expected] actual=[$actual]" >&2
  PGD_FAILURES=$((PGD_FAILURES + 1))
  return 1
}

pg_durability_selftest() {
  set -u
  local PGD_FAILURES=0
  local out='' rc=0

  local cap_default=$'fsync|on|default\nfull_page_writes|on|default\nsynchronous_commit|on|default'
  local cap_off=$'fsync|off|configuration file\nfull_page_writes|off|configuration file\nsynchronous_commit|off|configuration file'
  local cap_local=$'fsync|off|configuration file\nfull_page_writes|off|configuration file\nsynchronous_commit|local|configuration file'
  local cap_off_crlf=''
  cap_off_crlf="$(printf '%s\r\n' 'fsync|off|configuration file' 'full_page_writes|off|configuration file' 'synchronous_commit|off|configuration file')"
  local cap_missing_sc=$'fsync|on|default\nfull_page_writes|on|default'
  local cap_refused=$'psql: error: connection to server at "127.0.0.1", port 54319 failed: Connection refused\n\tIs the server running on that host and accepting TCP/IP connections?'
  local cap_nosuper='ERROR:  permission denied to set parameter "fsync"'

  out="$(pg_durability_decide 1 "$cap_default")"; pg_durability_check "decide 1 default -> heal" "heal fsync full_page_writes synchronous_commit" "$out"
  out="$(pg_durability_decide 0 "$cap_default")"; pg_durability_check "decide 0 default -> drift" "drift fsync full_page_writes synchronous_commit" "$out"
  out="$(pg_durability_decide 1 "$cap_off")"; pg_durability_check "decide 1 off -> ok" "ok" "$out"
  out="$(pg_durability_decide 0 "$cap_off")"; pg_durability_check "decide 0 off -> ok" "ok" "$out"
  out="$(pg_durability_decide 1 "$cap_local")"; pg_durability_check "decide 1 local -> heal synchronous_commit" "heal synchronous_commit" "$out"
  out="$(pg_durability_decide 1 "$cap_off_crlf")"; pg_durability_check "decide 1 off CRLF -> ok" "ok" "$out"
  rc=0; out="$(pg_durability_decide 1 "$cap_missing_sc")" || rc=$?
  pg_durability_check "decide 1 missing sc -> fail missing" "fail missing:synchronous_commit" "$out"
  pg_durability_check "decide 1 missing sc -> rc 1" "1" "$rc"
  rc=0; out="$(pg_durability_decide 1 "$cap_refused")" || rc=$?
  pg_durability_check "decide 1 conn-refused -> fail unparseable" "fail unparseable" "$out"
  pg_durability_check "decide 1 conn-refused -> rc 1" "1" "$rc"
  rc=0; out="$(pg_durability_decide 1 '')" || rc=$?
  pg_durability_check "decide 1 empty -> fail unparseable" "fail unparseable" "$out"
  pg_durability_check "decide 1 empty -> rc 1" "1" "$rc"
  rc=0; out="$(pg_durability_decide 1 "$cap_nosuper")" || rc=$?
  pg_durability_check "decide 1 permission-denied -> fail unparseable" "fail unparseable" "$out"

  # Malformed row shapes are REJECTED (treated as no row seen
  # for that setting), not misparsed into a false ok/heal.
  local cap_2field=$'fsync|off\nfull_page_writes|off|configuration file\nsynchronous_commit|off|configuration file'
  rc=0; out="$(pg_durability_decide 1 "$cap_2field")" || rc=$?
  pg_durability_check "decide 1 2-field row rejected -> fail missing" "fail missing:fsync" "$out"
  pg_durability_check "decide 1 2-field row rejected -> rc 1" "1" "$rc"
  local cap_4field=$'fsync|off|configuration file|extra\nfull_page_writes|off|configuration file\nsynchronous_commit|off|configuration file'
  rc=0; out="$(pg_durability_decide 1 "$cap_4field")" || rc=$?
  pg_durability_check "decide 1 4-field row rejected -> fail missing" "fail missing:fsync" "$out"
  pg_durability_check "decide 1 4-field row rejected -> rc 1" "1" "$rc"

  rc=0; pg_heal_allowed true 127.0.0.1 manifest 1 || rc=$?; pg_durability_check "heal_allowed true 127.0.0.1 manifest provable" "0" "$rc"
  rc=0; pg_heal_allowed true localhost manifest 1 || rc=$?; pg_durability_check "heal_allowed true localhost manifest provable" "0" "$rc"
  rc=0; pg_heal_allowed true 127.0.0.1 path 1 || rc=$?; pg_durability_check "heal_allowed true 127.0.0.1 path provable" "1" "$rc"
  rc=0; pg_heal_allowed true 127.0.0.1 none 1 || rc=$?; pg_durability_check "heal_allowed true 127.0.0.1 none provable" "1" "$rc"
  rc=0; pg_heal_allowed true 10.0.0.5 manifest 1 || rc=$?; pg_durability_check "heal_allowed true 10.0.0.5 manifest provable" "1" "$rc"
  rc=0; pg_heal_allowed true '?' manifest 1 || rc=$?; pg_durability_check "heal_allowed true ? manifest provable" "1" "$rc"
  rc=0; pg_heal_allowed '' 127.0.0.1 manifest 1 || rc=$?; pg_durability_check "heal_allowed '' 127.0.0.1 manifest provable" "1" "$rc"
  rc=0; pg_heal_allowed false 127.0.0.1 manifest 1 || rc=$?; pg_durability_check "heal_allowed false 127.0.0.1 manifest provable" "1" "$rc"
  # Adversarial host-string and truthiness negative fixtures.
  rc=0; pg_heal_allowed true '127.0.0.1.evil.example' manifest 1 || rc=$?
  pg_durability_check "heal_allowed adversarial host suffix rejected" "1" "$rc"
  rc=0; pg_heal_allowed True 127.0.0.1 manifest 1 || rc=$?
  pg_durability_check "heal_allowed truthy-but-not-true GITHUB_ACTIONS rejected" "1" "$rc"
  rc=0; pg_heal_allowed 1 127.0.0.1 manifest 1 || rc=$?
  pg_durability_check "heal_allowed numeric-truthy GITHUB_ACTIONS rejected" "1" "$rc"
  # pg_heal_allowed's own provable gate — a manifest/loopback/Actions DSN
  # that pg_dsn_target_provable refuses must still be refused here.
  rc=0; pg_heal_allowed true 127.0.0.1 manifest 0 || rc=$?
  pg_durability_check "heal_allowed true 127.0.0.1 manifest not-provable" "1" "$rc"

  # pg_dsn_target_provable — plain-URI-only bound.
  rc=0; pg_dsn_target_provable 'postgresql://yuzu:yuzu@127.0.0.1:5433/yuzu_test' || rc=$?
  pg_durability_check "dsn_target_provable plain uri" "0" "$rc"
  rc=0; pg_dsn_target_provable 'postgresql://yuzu@127.0.0.1:56551/postgres?port=56552' || rc=$?
  pg_durability_check "dsn_target_provable query-string port override not provable" "1" "$rc"
  rc=0; pg_dsn_target_provable 'postgresql://yuzu@127.0.0.1:5433/db?x=1' || rc=$?
  pg_durability_check "dsn_target_provable any query string not provable" "1" "$rc"
  rc=0; pg_dsn_target_provable 'postgresql://a@b@127.0.0.1:5433/db' || rc=$?
  pg_durability_check "dsn_target_provable double-@ not provable" "1" "$rc"
  rc=0; pg_dsn_target_provable 'postgresql://yuzu@[::1]:5433/db' || rc=$?
  pg_durability_check "dsn_target_provable unparseable host not provable" "1" "$rc"
  # A '@' inside the PATH (after the first '/' following "://") is not part
  # of the authority at all — libpq ends the host at that first '/', so a
  # naive "exactly one '@' anywhere in the string" check (the bug this
  # replaces) misreads the path's '@...host:port' tail as the authority.
  # postgresql://%2Fsock/x@127.0.0.1:5433/db: libpq treats "%2Fsock" as the
  # (percent-decoded "/sock") host up to the first '/', so it actually
  # dials a Unix-socket directory, not 127.0.0.1:5433.
  rc=0; pg_dsn_target_provable 'postgresql://%2Fsock/x@127.0.0.1:5433/db' || rc=$?
  pg_durability_check "dsn_target_provable path-embedded host@port not provable" "1" "$rc"
  rc=0; pg_dsn_target_provable 'postgresql://foo/x@127.0.0.1:5433/db' || rc=$?
  pg_durability_check "dsn_target_provable no-userinfo path '@' not provable" "1" "$rc"

  out="$(pg_dsn_host_port 'postgresql://yuzu:yuzu@127.0.0.1:5433/yuzu_test')"; pg_durability_check "dsn_host_port uri" "127.0.0.1:5433" "$out"
  out="$(pg_dsn_host_port 'host=127.0.0.1 port=5433 user=yuzu')"; pg_durability_check "dsn_host_port keyword-form" "?" "$out"
  out="$(pg_dsn_host_port 'postgresql://yuzu@[::1]:5433/db')"; pg_durability_check "dsn_host_port ipv6" "?" "$out"

  out="$(pg_dsn_redact 'postgresql://yuzu:yuzu@127.0.0.1:5433/yuzu_test')"
  pg_durability_check "dsn_redact uri" "postgresql://***@127.0.0.1:5433/yuzu_test" "$out"
  case "$out" in
    *yuzu:yuzu*) echo "  FAIL: dsn_redact leaked credentials: $out" >&2; PGD_FAILURES=$((PGD_FAILURES + 1)) ;;
    *) echo "  ok: dsn_redact does not leak credentials" ;;
  esac
  out="$(pg_dsn_redact 'postgresql://127.0.0.1:5433/yuzu_test')"
  pg_durability_check "dsn_redact no-@ unchanged" "postgresql://127.0.0.1:5433/yuzu_test" "$out"

  out="$(pg_dsn_redact 'postgresql://yuzu:p@ss@127.0.0.1:5433/db')"
  pg_durability_check "dsn_redact uri password containing @" "postgresql://***@127.0.0.1:5433/db" "$out"
  case "$out" in
    *ss@*) echo "  FAIL: dsn_redact leaked a password fragment: $out" >&2; PGD_FAILURES=$((PGD_FAILURES + 1)) ;;
    *) echo "  ok: dsn_redact does not leak a password fragment after an embedded @" ;;
  esac

  out="$(pg_dsn_redact 'host=127.0.0.1 port=5433 user=yuzu password=s3cret dbname=yuzu_test')"
  pg_durability_check "dsn_redact keyword-form" "host=127.0.0.1 port=5433 user=yuzu password=*** dbname=yuzu_test" "$out"
  case "$out" in
    *s3cret*) echo "  FAIL: dsn_redact leaked a keyword-form password: $out" >&2; PGD_FAILURES=$((PGD_FAILURES + 1)) ;;
    *) echo "  ok: dsn_redact does not leak a keyword-form password" ;;
  esac

  out="$(pg_dsn_redact 'host=127.0.0.1 password = s3cret dbname=x')"
  pg_durability_check "dsn_redact keyword-form spaced =" "host=127.0.0.1 password=*** dbname=x" "$out"
  case "$out" in
    *s3*|*cret*) echo "  FAIL: dsn_redact leaked a spaced keyword-form password: $out" >&2; PGD_FAILURES=$((PGD_FAILURES + 1)) ;;
    *) echo "  ok: dsn_redact does not leak a spaced keyword-form password" ;;
  esac

  out="$(pg_dsn_redact "password='s3 cret' dbname=x")"
  pg_durability_check "dsn_redact keyword-form quoted value" "password=*** dbname=x" "$out"
  case "$out" in
    *s3*|*cret*) echo "  FAIL: dsn_redact leaked a quoted keyword-form password: $out" >&2; PGD_FAILURES=$((PGD_FAILURES + 1)) ;;
    *) echo "  ok: dsn_redact does not leak a quoted keyword-form password" ;;
  esac

  out="$(pg_psql_path_from_env 'D:\ci\pgbin\agent-1\bin\psql.exe')"; pg_durability_check "psql_path_from_env backslash" "D:/ci/pgbin/agent-1/bin/psql.exe" "$out"
  out="$(pg_psql_path_from_env '')"; pg_durability_check "psql_path_from_env empty" "" "$out"
  out="$(pg_psql_path_from_env '/usr/bin/psql')"; pg_durability_check "psql_path_from_env unix unchanged" "/usr/bin/psql" "$out"

  if [[ "$PGD_FAILURES" -eq 0 ]]; then
    echo "pg-durability selftest: all checks ok"
    return 0
  fi
  echo "pg-durability selftest: $PGD_FAILURES check(s) FAILED" >&2
  return 1
}

if [[ "${BASH_SOURCE[0]}" == "$0" && "${1:-}" == "--selftest" ]]; then
  pg_durability_selftest
  exit $?
fi
