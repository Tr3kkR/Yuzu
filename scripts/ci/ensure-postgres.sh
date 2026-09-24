#!/usr/bin/env bash
# ensure-postgres.sh — idempotent "a PostgreSQL is reachable for server
# tests" step for every CI tier (ADR-0006 decision 8, #1318). The shipped
# substrate is PostgreSQL 18 (deploy/docker/Dockerfile.postgres); the server
# SQL is version-agnostic (13+), so a runner-native cluster on an older major
# still exercises the suites correctly.
#
# Exports YUZU_TEST_POSTGRES_DSN via $GITHUB_ENV (or prints it when run
# outside Actions, e.g. by the /test skill or a dev shell). Resolution
# order:
#
#   1. Pre-set YUZU_TEST_POSTGRES_DSN — runner-level/env override (the
#      documented hook for a self-hosted box with a bespoke native install;
#      see docs/ci-architecture.md "Postgres for server tests"). On a
#      multi-agent box (runner name ending "-<n>", e.g. the 4-runner
#      yuzu-weetam-windows pool) the pre-set DSN names the agent-0 cluster
#      and agent <n> uses port+<n> when that per-agent cluster answers —
#      one instance per agent, no cross-job contention (#2094). Falls back
#      to the shared pre-set DSN (with a ::warning) until the box is
#      provisioned with the extra clusters.
#
#      Durability conformance (#2167 follow-up): before exporting the DSN
#      (agent 0's cluster included — it was not probed at all before this),
#      path 1 reads fsync/synchronous_commit/full_page_writes from the
#      cluster (see pg_durability_decide in pg-durability.sh) and, only
#      under GitHub Actions against a loopback host PROVABLE from a plain
#      URI DSN (pg_dsn_target_provable — no query string, and its authority
#      alone contains at most one '@' and a bare host:port), with no
#      PGHOST/PGHOSTADDR/PGSERVICE/PGPORT override in the job/
#      runner environment, and with a toolchain-manifest-vouched psql
#      (YUZU_CI_PSQL, exported by deploy/windows/Assert-Toolchain.ps1
#      -ExportCiEnv), attempts a heal. The heal session's own first two
#      statements are in-session identity/config-parse DO-block guards that
#      RAISE before any ALTER SYSTEM if the server it is actually talking
#      to isn't loopback:port, or if pg_file_settings already has a parse
#      error — only past both does it run ALTER SYSTEM + pg_reload_conf(),
#      then re-read with a bounded retry. Elsewhere, drift is reported,
#      never healed. A manifest-vouched SELECT 1 probe failure (agent 0/
#      base cluster or any further agent) is retried then fails the job —
#      it never falls back to the shared agent-0 cluster. Without any
#      psql, conformance is UNVERIFIED (a warning, not a failure). A raw
#      psql failure's diagnostic text from the FIRST read (which can echo a
#      malformed DSN's password verbatim) is withheld under GitHub Actions
#      rather than republished in a public ::error::/::warning:: annotation
#      — see p1_diag; a POST-read failure (heal, post-heal re-read) prints
#      only the server's own ERROR/FATAL/WARNING/DETAIL/HINT lines, plus a
#      line carrying this guard's own "yuzu-heal-" marker or a connection-
#      phase "connection to server ... failed:" line (neither can newly
#      carry a credential on a DSN already proven to parse) — see
#      p1_server_diag.
#      Test seam: YUZU_CI_PG_SLEEP_SCALE scales the guard's bounded sleeps
#      (defaults to 1; the docs-suite selftest sets 0 so every scenario
#      runs in milliseconds).
#   2. Docker available -> idempotent `yuzu-ci-postgres` container on
#      127.0.0.1:15432 (self-hosted Linux — the same boxes run the
#      docker-publish jobs, so docker is a given). Port 15432 deliberately
#      avoids colliding with any native cluster or UAT rig on 5432.
#      `--restart unless-stopped` + `docker start` makes this a one-time
#      cost per runner. Multi-agent boxes (yuzu-bigtam-linux pool) get a
#      container PER AGENT — `yuzu-ci-postgres-<n>` on 127.0.0.1:15440+<n>,
#      self-created on the agent's first job (#2094).
#   3. macOS (GHA-hosted, no docker): brew postgresql@18, throwaway
#      trust-auth cluster under $RUNNER_TEMP on port 15432.
#   4. Native cluster on 127.0.0.1:5432 (self-hosted Windows precondition —
#      PostgreSQL 16+ installed as a service with role yuzu / password yuzu
#      / database yuzu_test; bootstrap once per runner, see
#      docs/ci-architecture.md).
#   5. Nothing found -> ::error + exit 1.
#
# FATAL since #1320 PR 1: the pg substrate test suites ([pg] tags in the
# server suite) consume YUZU_TEST_POSTGRES_DSN and skip when it is unset —
# so a runner without a database would silently skip that coverage. A
# missing/unready Postgres now fails the job instead.
set -euo pipefail

SOFT_EXIT=1   # flipped 0->1 when #1320 PR 1 shipped the [pg] test suites

# Same pinned multi-arch image as deploy/docker/Dockerfile.postgres's base.
PG_IMAGE="postgres:18.4-bookworm@sha256:efef99e1558f86089bc84bece29208c0777a185ff717ec7fa288a652ce2d0adf"
CONTAINER="yuzu-ci-postgres"
DOCKER_PORT=15432
# Bump when the durability/-c tuning below changes: the docker container is
# persistent (--restart unless-stopped), so a container born before a tuning
# change keeps the OLD flags until recreated. The image-drift guard already
# recreates on a PG_IMAGE bump; this label makes a tuning bump recreate too,
# so fsync=off actually reaches runners that already have a container.
PG_TUNE_LABEL="v1-durability-off"

# ── Per-agent instance selection (#2094) ─────────────────────────────────
# Both self-hosted pools run 4 runner agents on ONE box (CLAUDE.md standing
# invariant), and a single shared Postgres is a cross-job contention
# multiplier: the WAL/fsync-heavy [pg] fixture traffic of concurrent jobs
# mutually DoSes their server suites (the 2026-07-12 Wee Tam 900 s
# server-suite timeouts). Pool runner names carry the agent index as a
# trailing "-<n>" (yuzu-weetam-windows-2, yuzu-bigtam-linux-0); derive it
# and give every agent its OWN instance — the database-shaped case of the
# fixed-port/named-object cross-JOB collision pattern (#1871). Single-agent
# boxes (yuzu-wsl2-linux) and GHA-hosted runners have no such suffix and
# keep the shared-instance behaviour.
AGENT_IDX=""
if [[ "${RUNNER_NAME:-}" =~ -([0-9]+)$ ]]; then
  AGENT_IDX=$((10#${BASH_REMATCH[1]}))
  if (( AGENT_IDX > 9 )); then
    # Pool agent indexes are single-digit; a larger trailing number (some
    # hosted-runner naming schemes) is not an agent index.
    AGENT_IDX=""
  fi
fi
# Disposable CI cluster -> durability OFF (fsync/synchronous_commit/
# full_page_writes). Every [pg] test does CREATE DATABASE ... TEMPLATE + DROP
# DATABASE WITH (FORCE) per case (~72 cases) — both fsync-heavy — so full
# durability makes the [pg] shard the slowest-scaling part of the suite,
# ~20x worse on Windows where fsync is dominant (the 2026-07-14 600s Windows
# TIMEOUTs). The DBs are throwaway; a crash just re-runs the job. fsync and
# full_page_writes are sighup-context (server-level only); synchronous_commit
# is user-context (also settable per session/role/database — why the
# post-heal re-read in p1_conform points at pg_settings.source). All three
# are applied server-side here — postgresql.conf / ALTER SYSTEM +
# pg_reload_conf(), or the -c flags — never via the DSN (see the options=
# NOTE below).
DOCKER_PG_ARGS=(-c fsync=off -c synchronous_commit=off -c full_page_writes=off)
if [[ -n "$AGENT_IDX" ]]; then
  # Container-per-agent on 15440+<n>: base deliberately OFF 15432/15433 so
  # agent 0 collides with neither a legacy shared container (15432) nor the
  # UAT postgres sidecar (15433) — port map in scripts/start-UAT.sh.
  CONTAINER="yuzu-ci-postgres-${AGENT_IDX}"
  DOCKER_PORT=$((15440 + AGENT_IDX))
  # Wee-Tam-parity connection headroom (#2096): the server suite's PgPool
  # fan-out can exhaust the postgres default of 100 (the CH-9 flake).
  DOCKER_PG_ARGS+=(-c max_connections=400)
fi

# NOTE: durability-off is applied SERVER-SIDE only (docker/brew `-c` flags
# below; the native Windows service via deploy/windows/Provision-Windows-Runner
# .ps1 or a one-off `ALTER SYSTEM SET fsync/synchronous_commit/full_page_writes
# = off` + reload). Do NOT inject it into the emitted DSN via the libpq
# `options` keyword: PgPool only injects its statement_timeout/lock_timeout
# GUCs "unless the conninfo sets its own `options`" (pg_pool.hpp), so a DSN-level
# `options=` silently disables those safety bounds — the [pg][hardening] test
# "PgPool injects statement_timeout and lock_timeout GUCs" catches it.
emit_dsn() {
  local dsn="$1" how="$2"
  if [[ -n "${GITHUB_ENV:-}" ]]; then
    echo "YUZU_TEST_POSTGRES_DSN=${dsn}" >> "$GITHUB_ENV"
  fi
  # Always echo too — local invocations eval/grep this.
  echo "YUZU_TEST_POSTGRES_DSN=${dsn}"
  echo "ensure-postgres: ready (${how})" >&2
}

tcp_probe() { # host port — pure-bash, works in MSYS2 too
  local host="$1" port="$2"
  (exec 3<>"/dev/tcp/${host}/${port}") >/dev/null 2>&1
}

# p1_env_is_set <NAME-alternation> — true if a variable matching
# NAME-alternation (e.g. "PGHOST|PGHOSTADDR") is EXPORTED in this process,
# case-INSENSITIVELY and regardless of value — a set-but-empty
# PGSERVICE="" still matches libpq's own `[]` service section, and
# MSYS2 bash only upper-cases 10 variable names at startup, so a
# lower-case copy invisible to bash's own ${VAR:-} test is still visible
# to psql.exe's case-insensitive Windows getenv. Pure bash/builtins
# only (compgen -e, nocasematch) — no external tr/grep pipeline, which the
# stripped-PATH docs-suite selftest harness cannot supply. On a match, sets
# P1_ENV_MATCH to the variable's ACTUAL (case-preserved) name, so a caller
# that also cares about the value can read it via `${!P1_ENV_MATCH}` — the
# PGOPTIONS gate below is the one caller that does; a caller that (like the
# PGHOST-family gate) treats "set" as fatal regardless of value ignores it.
p1_env_is_set() {
  local name='' nocase_was_on=1
  shopt -q nocasematch || nocase_was_on=0
  shopt -s nocasematch
  local found=1
  P1_ENV_MATCH=''
  while IFS= read -r name; do
    if [[ "$name" =~ ^($1)$ ]]; then
      found=0
      P1_ENV_MATCH="$name"
      break
    fi
  done < <(compgen -e)
  [[ "$nocase_was_on" == "0" ]] && shopt -u nocasematch
  return "$found"
}

# p1_rc_hint <rc> — names three exit codes a shell/wrapper uses for
# something other than a normal psql query result: 124 (the P1_TIMEOUT
# wrapper killed a blocked/hung call), 126 (found but not executable — a
# permissions/MSYS2 wrapper problem) and 127 (not found at all — a stale
# manifest path, or a DLL psql.exe depends on failed to load, which MSYS2
# also surfaces as "not found"). Anything else is a normal psql exit code
# (a real connection/auth/query failure) and gets no extra hint.
p1_rc_hint() {
  case "$1" in
    124) echo " — timed out after 30s (/usr/bin/timeout wrapper): blocked or hung backend; check pg_stat_activity/pg_locks" ;;
    126) echo " — psql failed to execute (found but not runnable: permissions or an MSYS2 wrapper problem)" ;;
    127) echo " — psql failed to execute (not found, or a DLL it depends on failed to load: MSYS2/PATH problem)" ;;
    *) echo "" ;;
  esac
}

# p1_probe_manifest <dsn> — SELECT 1 against <dsn>, with a bounded retry
# (3 x 2s, test-scaled by P1_SLEEP_SCALE) only when P1_PSQL_SRC=manifest:
# Assert-Toolchain has already proven this exact psql.exe against this
# exact cluster with SELECT 1 earlier in the same job, so a failure here is
# a real cluster fault or a transient (an exec failure — rc 126/127, named
# by p1_rc_hint — is possible too, though unlikely for a psql Assert-
# Toolchain just ran successfully) and is worth a short retry rather than
# an instant fail. A PATH-sourced
# psql (an unprovisioned box) gets no retry: that caller already has its
# own warn-and-fall-back arm, and retrying would only slow down the common
# not-yet-provisioned case. Sets P1_PROBE_RC to the LAST attempt's exit
# code so a caller reporting failure can name it, and returns
# 0/1 to match.
p1_probe_manifest() {
  local dsn="$1"
  P1_PROBE_RC=0
  p1_psql "$dsn" -tA -c 'SELECT 1' >/dev/null 2>&1 && return 0
  P1_PROBE_RC=$?
  if [[ "$P1_PSQL_SRC" == "manifest" ]]; then
    local _try
    for _try in 1 2 3; do
      sleep $((2 * P1_SLEEP_SCALE))
      P1_PROBE_RC=0
      p1_psql "$dsn" -tA -c 'SELECT 1' >/dev/null 2>&1 && return 0
      P1_PROBE_RC=$?
    done
  fi
  return 1
}

# Bounds psql itself, not just the connect: PGCONNECT_TIMEOUT (below) only
# covers the initial connection, and a hung/wedged backend after that would
# otherwise block the step indefinitely. /usr/bin/timeout by ABSOLUTE
# PATH is load-bearing on Wee Tam — Start-PinnedRunner.ps1 prepends MSYS2's
# usr/bin ahead of C:\Windows\system32 in today's runner PATH, but the
# absolute path is what guards a runner started WITHOUT that PATH order
# (sweep-test-databases.sh:53-58 makes the same pre-existing, now-stale
# "system32 is first" claim) — there, a bare `timeout` would resolve to
# Windows' timeout.exe instead, which takes different arguments and would
# silently no-op or error. macOS has no /usr/bin/timeout and stays
# unbounded there (dev shells only, never CI).
# 30s per call, not 60s: PGCONNECT_TIMEOUT=10 already bounds the connect,
# and every query this guard issues (a pg_settings SELECT, three ALTER
# SYSTEMs, a reload) completes in milliseconds on a loopback cluster — 30s
# is still generous headroom for a loaded runner. This value and the
# step's own `timeout-minutes` (ci.yml) are reconciled against the script's
# own worst case: 4 attempts + 3 retry sleeps of the per-agent
# probe, the read, the heal, and 5 re-read attempts of 1s each, all capped
# at 30s per call, bound the script under 6 minutes — comfortably inside
# the step's 8-minute timeout, so a hung psql is killed by THIS wrapper and
# reported with this script's own specific ::error:: before the step-level
# timeout would otherwise kill the whole job with a generic message.
P1_TIMEOUT=()
[[ -x /usr/bin/timeout ]] && P1_TIMEOUT=(/usr/bin/timeout 30)

# p1_psql <dsn> [psql-args...] — the only psql invocation path 1's
# conformance guard uses. --dbname="$dsn" rather than a positional
# DSN argument: a DSN beginning with '-' would otherwise be parsed by psql
# as its own options (reproduced: `-cALTER SYSTEM …` wrote auto.conf with
# the heal gate closed). -X (no psqlrc) / -w (never prompt: the check now
# runs for ANY pre-set DSN, including a password-less local/test shell that
# would otherwise hang the job on a tty prompt); PGCONNECT_TIMEOUT bounds a
# hung listener; the P1_TIMEOUT wrapper bounds the whole call;
# MSYS2_ARG_CONV_EXCL='*' stops MSYS2 rewriting the DSN/SQL argv before
# native psql.exe sees them (precedent
# scripts/ci/verify-healthcheck-invariants.sh:79; inert on Linux/macOS).
p1_psql() {
  local dsn="$1"
  shift
  PGCONNECT_TIMEOUT=10 MSYS2_ARG_CONV_EXCL='*' "${P1_TIMEOUT[@]+"${P1_TIMEOUT[@]}"}" "$P1_PSQL" -X -w --dbname="$dsn" "$@"
}

# p1_hp_disp <dsn> — pg_dsn_host_port's "?" is the correct MACHINE value
# for a DSN this guard cannot parse (keyword-form, IPv6, multi-host, a
# query string, or any other shape pg_dsn_parse_authority's grammar
# excludes), but a bare "?" reads as a broken interpolation in an
# operator-facing message ("... not off on ?"). Every message arm in
# p1_conform, and the agent-0/base-cluster probe-failure message below,
# prints this instead.
p1_hp_disp() {
  local hp
  hp="$(pg_dsn_host_port "$1")"
  if [[ "$hp" == "?" ]]; then
    echo "host unparsed (keyword-form, IPv6, multi-host, or query-string DSNs are report-only)"
  else
    echo "$hp"
  fi
}

# p1_flatten <text> — CRLF-strip then newline-and-tab-flatten psql/error
# output for a single-line GitHub Actions ::error::/::warning:: annotation,
# which stops rendering at the first newline (a multi-line $rows embedded
# raw truncates the annotation after the first row). psql's own connection-
# refused text continues onto a second line with a leading TAB ("\tIs the
# server running..."); left unflattened that TAB survives mid-line inside
# an otherwise single-line annotation.
p1_flatten() {
  local text="${1//$'\r'/}"
  text="${text//$'\n'/ }"
  echo "${text//$'\t'/ }"
}

# p1_diag <rc> <text> [force_untrusted] — like p1_flatten, but withholds RAW
# psql diagnostic text under GitHub Actions when it cannot be trusted to be
# well-formed pg_settings rows: rc != 0 (the psql invocation itself failed —
# a malformed/mistyped DSN password can make psql echo the credential
# verbatim in its own client-side error text, e.g. "invalid percent-encoded
# token: \"codex_secret_%ZZ\"") or force_untrusted is set (the caller
# already knows the text isn't a clean pg_settings read, e.g. p1_conform's
# "fail unparseable" arm). GitHub Actions' ::error::/::warning:: annotations
# are PUBLIC and its secret masking is exact-value-only, so a credential
# substring that isn't byte-for-byte the configured secret leaks in the
# clear; p1_flatten alone only makes that single-line-safe, it does not
# remove it. rc == 0 and no force (the read succeeded and the caller knows
# the text is a real pg_settings/ALTER SYSTEM result, which cannot contain a
# DSN) is flattened and printed as before, on or off Actions.
p1_diag() {
  local rc="$1" text="$2" force="${3:-}"
  if [[ "$rc" == "0" && -z "$force" ]]; then
    p1_flatten "$text"
    return
  fi
  # The rc hint (124/126/127) names only the exit code itself, never DSN
  # content, so it is safe to show even under Actions' withholding branch.
  if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
    echo "psql rc=${rc}$(p1_rc_hint "$rc") (diagnostic withheld under Actions: psql may echo DSN credential material)"
  else
    echo "psql rc=${rc}$(p1_rc_hint "$rc"): $(p1_flatten "$text")"
  fi
}

# p1_server_diag <text> — like p1_diag, but for POST-READ arms only: a
# psql call made after the top-of-p1_conform read has already proven the
# SAME DSN parses and connects in this same process (the heal call and the
# post-heal re-read). A client-side, credential-echoing parse error — the
# whole reason p1_diag withholds — cannot newly occur on a DSN already
# proven to parse; what CAN appear is a genuine SERVER-originated error
# (e.g. `ERROR:  permission denied to set parameter "fsync"`, or the
# in-session loopback/config-parse guards in the heal call's DO blocks
# firing), which is exactly what an operator needs to diagnose a failed
# heal, and withholding it serves no credential purpose. Prints only the
# lines that start with one of psql's own server-message prefixes —
# ERROR/FATAL/WARNING/DETAIL/HINT — OR carry this guard's own "yuzu-heal-"
# RAISE marker (so a non-English lc_messages, which translates the plain
# prefixes, still surfaces the guard's own English marker text) OR a
# connection-phase "connection to server ... failed:" line (safe here for
# the same already-proven-to-parse reason) — flattened and space-joined;
# anything else (a stray sentinel, connection-banner noise, or simply no
# output at all) prints a fixed "no ERROR/FATAL/WARNING/DETAIL/HINT line in
# psql output" instead of echoing raw text. This takes only the text, never an
# <rc> — every caller already prefixes its own message with
# "(psql rc=${rc})", so passing rc through here used to double it up as
# "(psql rc=2): psql rc=2" when there was no server line to print.
p1_server_diag() {
  local text="${1//$'\r'/}"
  local line='' out=''
  while IFS= read -r line; do
    case "$line" in
      # The plain prefix match is a fast path only, not the sole guard: a
      # non-English lc_messages translates these labels (e.g. German
      # "FEHLER:"), so also keep any line carrying our OWN "yuzu-heal-"
      # RAISE marker regardless of language, and a connection-phase
      # failure's "psql: error: connection to server ... failed: FATAL: ..."
      # line — safe here because every caller
      # of this function already proved the SAME DSN parses in this same
      # process (p1_diag's doc comment), so no credential can newly appear.
      ERROR:*|FATAL:*|WARNING:*|DETAIL:*|HINT:*|*'yuzu-heal-'*|*'connection to server'*'failed:'*)
        out="${out}${out:+ }$(p1_flatten "$line")"
        ;;
    esac
  done <<<"$text"
  if [[ -n "$out" ]]; then
    echo "$out"
  else
    echo "no ERROR/FATAL/WARNING/DETAIL/HINT line in psql output"
  fi
}

# p1_conform <dsn> — read -> decide -> heal -> bounded re-read the
# durability-off settings on the cluster this job is about to export.
# Returns 0 (proceed to emit_dsn) or 1 (caller must SOFT_EXIT). Read-only
# when psql is unavailable or the settings already read 'ok'; heals only
# when pg_heal_allowed permits it (GitHub Actions, loopback host,
# manifest-vouched psql, a plain-URI DSN pg_dsn_target_provable can vouch
# for, and no PGHOST/PGHOSTADDR/PGSERVICE/PGPORT override in the process
# environment — never a developer's pre-set DSN, a bespoke remote DB, or
# any other self-hosted box with a machine-level loopback DSN). Never
# prints $dsn unredacted.
#
# The DSN string alone is advisory, not authoritative, for where libpq
# actually connects (pg_dsn_target_provable's doc comment; a PGHOST-family
# env var wins over a URI's own authority too) — so on TOP of that string
# check, the heal session's own FIRST statement is an in-session DO block
# that RAISEs unless the server it is actually talking to is loopback on
# the exact port this DSN claims. That in-session check is the
# authoritative bound; the provable/env-override gates below only decide
# whether we attempt a heal at all, so a refusal there is reported as
# "cannot prove the target" rather than the generic not-manifest/not-
# loopback wording.
p1_conform() {
  local dsn="$1" hp='' dsn_redacted='' rows='' rc=0 decision='' allow=0 attempt=0
  local q="SELECT name, setting, source FROM pg_catalog.pg_settings WHERE name IN ('fsync','synchronous_commit','full_page_writes') ORDER BY name"
  local heal_refusal_reason='' final_decision='' hp_disp=''
  hp="$(pg_dsn_host_port "$dsn")"
  hp_disp="$hp"
  [[ "$hp_disp" == "?" ]] && hp_disp="host unparsed (keyword-form, IPv6, multi-host, or query-string DSNs are report-only)"
  dsn_redacted="$(pg_dsn_redact "$dsn")"

  if [[ "$P1_PSQL_SRC" == "none" ]]; then
    echo "::warning::ensure-postgres: durability conformance UNVERIFIED on ${hp_disp} — no psql (pass -ExportCiEnv to deploy/windows/Assert-Toolchain.ps1, which exports YUZU_CI_PSQL from the manifest — never set it by hand, it authorises the heal — or put psql on PATH for a report-only check). See docs/ci-architecture.md 'Postgres for server tests'." >&2
    return 0
  fi

  rc=0
  rows="$(p1_psql "$dsn" -tA -c "$q" 2>&1)" || rc=$?
  if [[ "$rc" != "0" ]]; then
    # No DSN-derived string beyond ${hp_disp} in the Actions arm — the two
    # redaction gaps in pg_dsn_redact (a backslash-escaped space, a
    # percent-encoded keyword) both reproduce against a real libpq DSN, and
    # the root fix is not printing a redacted DSN in a public annotation at
    # all, not chasing more regex gaps. A developer shell (no Actions) still
    # gets it — useful, and not a public leak.
    if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
      echo "::error::ensure-postgres: durability read failed on ${hp_disp}: $(p1_diag "$rc" "$rows")" >&2
    else
      echo "::error::ensure-postgres: durability read failed on ${hp_disp} (${dsn_redacted}): $(p1_diag "$rc" "$rows")" >&2
    fi
    return 1
  fi

  allow=0
  heal_refusal_reason=''
  if p1_env_is_set 'PG(HOST|HOSTADDR|SERVICE|PORT)'; then
    # PGHOSTADDR, and a PGSERVICE section carrying hostaddr=, fill libpq's
    # hostaddr, which a URI DSN never sets. libpq then dials hostaddr
    # instead of resolving the URI's host (probed live against psql 18.6).
    # PGHOST and PGPORT are only DEFAULTS libpq applies when the DSN
    # itself sets no host/port — a URI DSN always sets both, so in practice
    # they do NOT redirect it — but refusing on their mere presence too is
    # cheap and keeps this gate from depending on proving libpq's exact
    # precedence rules for every DSN shape this script might ever emit.
    # Non-fatal either way: drift is still reported below, the job still
    # proceeds — same posture as the PGOPTIONS gate above.
    heal_refusal_reason="cannot prove the target (PGHOST/PGHOSTADDR/PGSERVICE/PGPORT is set in the job/runner environment; PGHOSTADDR, or a PGSERVICE entry carrying hostaddr, redirects even a plain URI DSN, and PGHOST/PGPORT are refused conservatively)"
  elif ! pg_dsn_target_provable "$dsn"; then
    heal_refusal_reason="cannot prove the target (the DSN is not a plain postgresql://user@host:port/db URI — a query string, an '@' outside the authority, or a keyword-form, IPv6 or multi-host DSN can shift or hide where libpq actually connects)"
  elif pg_heal_allowed "${GITHUB_ACTIONS:-}" "${hp%%:*}" "$P1_PSQL_SRC" "1"; then
    allow=1
  fi
  decision="$(pg_durability_decide "$allow" "$rows" || true)"

  case "$decision" in
    ok)
      echo "ensure-postgres: durability conformance ok on ${hp_disp} ($(p1_flatten "$rows"))" >&2
      return 0
      ;;
    drift*)
      # The per-agent derivation (pg_dsn_rebuild_port) and pg_dsn_host_port
      # only ever yield a real host:port for a URI-form DSN with a literal
      # loopback host — a keyword-form, IPv6, multi-host, or query-string
      # DSN reads as "?" (hp_disp, computed above) and is drift-only by
      # construction (pg_heal_allowed can never see a loopback host for
      # one). Say so plainly rather than printing the confusing literal
      # "on ?".
      if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
        if [[ -n "$heal_refusal_reason" ]]; then
          echo "::warning::ensure-postgres: ${decision#drift } not off on ${hp_disp} — NOT healing (${heal_refusal_reason})." >&2
        else
          echo "::warning::ensure-postgres: ${decision#drift } not off on ${hp_disp} — NOT healing (heal runs only under GitHub Actions, against a loopback host, with the manifest-vouched YUZU_CI_PSQL); for a disposable CI cluster tune it via ALTER SYSTEM ... = off + SELECT pg_reload_conf(). (psql source: ${P1_PSQL_SRC}, host: ${hp%%:*})" >&2
        fi
      else
        echo "ensure-postgres: note — ${decision#drift } not off on ${hp_disp}; the [pg] shard runs against this cluster's own current durability settings (expected for a non-CI cluster; not healing)." >&2
      fi
      return 0
      ;;
    heal*)
      echo "::warning::ensure-postgres: ${hp_disp} had ${decision#heal } not off ($(p1_flatten "$rows")) — healing with ALTER SYSTEM SET ... = off + pg_reload_conf(). This persists in postgresql.auto.conf; if it recurs, the printed pg_settings.source will name the cause." >&2
      rc=0
      # The heal session's first two statements are in-session DO-block
      # guards, run BEFORE any ALTER SYSTEM under ON_ERROR_STOP=1 (either
      # RAISEing aborts the whole call with no ALTER issued): (1) an
      # identity guard binding what the heal actually MUTATES to loopback
      # on this DSN's exact port ${hp} — explicit IS NULL disjuncts so a
      # Unix-socket session's NULL inet_server_addr()/port() RAISEs
      # directly rather than falling through PL/pgSQL's three-valued `IF
      # NULL`; (2) a config-parse guard that refuses a RELOAD-ABORTING
      # pg_file_settings error (which would make pg_reload_conf() apply
      # NOTHING) but is fail-open on an APPLY-PHASE row (Postgres applies
      # every other change on those regardless). Full rationale, including
      # the non-English lc_messages caveat, is in docs/ci-architecture.md
      # "Postgres for server tests".
      # The session's FIRST statement pins search_path so a planted
      # public.string_agg/inet-operator function (the yuzu role is
      # SUPERUSER) can never intercept this session's unqualified calls —
      # belt alongside the explicit pg_catalog. qualifications below, which
      # stay for readability. -q suppresses the SET's own status line.
      rows="$(p1_psql "$dsn" -q -v ON_ERROR_STOP=1 -tA \
        -c 'SET search_path = pg_catalog, pg_temp' \
        -c "DO \$\$ BEGIN IF pg_catalog.inet_server_addr() IS NULL OR pg_catalog.inet_server_port() IS NULL OR NOT ((pg_catalog.inet_server_addr() << '127.0.0.0/8' OR pg_catalog.inet_server_addr() = '::1') AND pg_catalog.inet_server_port() = ${hp##*:}) THEN RAISE EXCEPTION 'yuzu-heal-identity-guard: connected server % port % is not loopback:${hp##*:}', pg_catalog.inet_server_addr(), pg_catalog.inet_server_port(); END IF; END \$\$" \
        -c "DO \$\$ DECLARE bad_errors text; BEGIN SELECT string_agg(DISTINCT error, '; ') INTO bad_errors FROM pg_catalog.pg_file_settings WHERE error IS NOT NULL AND error <> 'setting could not be applied' AND error NOT LIKE '%cannot be changed without restarting the server'; IF bad_errors IS NOT NULL THEN RAISE EXCEPTION 'yuzu-heal-config-parse-guard: pg_file_settings has reload-aborting error(s) - pg_reload_conf() would apply nothing and may leave an unrelated staged change (e.g. pg_hba.conf) live; check pg_file_settings and the server log: %', bad_errors; END IF; END \$\$" \
        -c 'ALTER SYSTEM SET fsync = off' \
        -c 'ALTER SYSTEM SET synchronous_commit = off' \
        -c 'ALTER SYSTEM SET full_page_writes = off' \
        -c 'SELECT pg_catalog.pg_reload_conf()' 2>&1)" || rc=$?
      if [[ "$rc" != "0" ]]; then
        echo "::error::ensure-postgres: heal failed on ${hp_disp} (psql rc=${rc}$(p1_rc_hint "$rc"); this includes the in-session loopback/target identity guard and the config-parse guard, either of which fails closed here): $(p1_server_diag "$rows")" >&2
        return 1
      fi
      # pg_reload_conf() only signals the postmaster; SIGHUP handling (and,
      # on Windows EXEC_BACKEND, a new backend's GUC state at spawn) is
      # asynchronous, so the re-read is bounded rather than trusted once.
      for attempt in 1 2 3 4 5; do
        rc=0
        rows="$(p1_psql "$dsn" -tA -c "$q" 2>&1)" || rc=$?
        if [[ "$rc" == "0" ]] && [[ "$(pg_durability_decide 0 "$rows")" == "ok" ]]; then
          echo "ensure-postgres: durability healed on ${hp_disp} (attempt ${attempt})" >&2
          return 0
        fi
        sleep $((1 * P1_SLEEP_SCALE))
      done
      # Branch on the ACTUAL last outcome rather than always
      # citing pg_settings.source, which only explains the "not off" case.
      if [[ "$rc" != "0" ]]; then
        echo "::error::ensure-postgres: could not re-read after heal on ${hp_disp} (psql rc=${rc}$(p1_rc_hint "$rc")): $(p1_server_diag "$rows")" >&2
        return 1
      fi
      final_decision="$(pg_durability_decide 0 "$rows" || true)"
      case "$final_decision" in
        fail*)
          echo "::error::ensure-postgres: durability settings unreadable on ${hp_disp} after heal (${final_decision#fail }): $(p1_diag "$rc" "$rows" 1)" >&2
          return 1
          ;;
        *)
          echo "::error::ensure-postgres: ${hp_disp} still not durability-off 5s after heal (${final_decision#drift } $(p1_flatten "$rows")) — check pg_file_settings and the server log first (a postgresql.conf parse error means the reload applied nothing), then remove the override (ImagePath -c, or ALTER ROLE/DATABASE ... RESET) — a per-role/per-database override or a command-line -c beats ALTER SYSTEM." >&2
          return 1
          ;;
      esac
      ;;
    fail*)
      # rc is guaranteed 0 here (a non-zero initial read already returned
      # above) but the text is by definition NOT a well-formed pg_settings
      # read (that is why decide classified it "fail") — force the same
      # Actions-gated withholding p1_diag applies to a genuine psql failure,
      # rather than trusting rc==0 to mean "safe to print raw". This is the
      # READ arm: unchanged, still withheld under Actions.
      echo "::error::ensure-postgres: durability settings unreadable on ${hp_disp} (${decision#fail }): $(p1_diag "$rc" "$rows" 1)" >&2
      return 1
      ;;
    *)
      echo "::error::ensure-postgres: durability decision unrecognised on ${hp_disp}: ${decision}" >&2
      return 1
      ;;
  esac
}

# PGOPTIONS is process-environment-level, not DSN content: pg_pool.cpp's
# conninfo_has_options_ gate checks getenv("PGOPTIONS") unconditionally,
# regardless of which of the 4 paths below built the connection string.
# A set, NON-EMPTY PGOPTIONS would silently disable PgPool's
# statement_timeout/lock_timeout safety bounds even on the docker/brew/
# native paths, which never see a caller-supplied DSN - so this runs
# unconditionally, before path selection, not only inside the pre-set-DSN
# branch (path 1 below). Matched case-insensitively via p1_env_is_set (see
# its doc comment) — deliberate for MSYS2/Windows psql.exe's
# case-insensitive getenv; real POSIX getenv is case-sensitive, so a
# non-canonical-case match there is a harmless, merely conservative false
# trigger, never a false negative. An EMPTY value is exempt either way:
# pg_pool.cpp/leader_elector.cpp only read PGOPTIONS when it is non-empty
# (`env_options[0] != '\0'`), so a set-but-empty PGOPTIONS disables
# nothing and must not be fatal.
if p1_env_is_set 'PGOPTIONS' && [[ -n "${!P1_ENV_MATCH}" ]]; then
  echo "::error::ensure-postgres: PGOPTIONS must not be set to a non-empty value in the job or runner machine environment (disables PgPool statement_timeout/lock_timeout safety bounds) - put durability settings in postgresql.conf via ALTER SYSTEM instead. See docs/ci-architecture.md 'Postgres for server tests'." >&2
  exit "$SOFT_EXIT"
fi

# ── 1. Pre-set DSN wins ──────────────────────────────────────────────────
if [[ -n "${YUZU_TEST_POSTGRES_DSN:-}" ]]; then
  # Test seam for the two bounded sleeps below (per-agent probe retry,
  # post-heal re-read) — 1 in production, 0 in the docs-suite selftest so
  # every scenario there runs in milliseconds instead of real seconds. Not a
  # production knob: a non-integer value (a typo in a workflow env) falls
  # back to 1 rather than aborting the step shell on the arithmetic below.
  P1_SLEEP_SCALE="${YUZU_CI_PG_SLEEP_SCALE:-1}"
  # A leading-zero value (e.g. "08") is rejected too: bash arithmetic below
  # treats a 0-prefixed literal as octal, and "08"/"09" are invalid octal
  # digits — under this sourced script's `set -e`, $((1 * P1_SLEEP_SCALE))
  # would abort the whole path-1 block and fall through to paths 2-5,
  # silently bypassing the durability guard.
  if ! [[ "$P1_SLEEP_SCALE" =~ ^(0|[1-9][0-9]*)$ ]]; then
    echo "ensure-postgres: note — YUZU_CI_PG_SLEEP_SCALE='${P1_SLEEP_SCALE}' is not a non-negative integer; using 1" >&2
    P1_SLEEP_SCALE=1
  fi

  # PgPool (pg_pool.cpp) only injects its statement_timeout/lock_timeout
  # safety-bound GUCs when PQconninfoParse finds no `options` keyword (the
  # PGOPTIONS half of that same gate is checked unconditionally above). An
  # `options=` in a pre-set DSN (URI query form OR keyword form) silently
  # disables those bounds (the [pg][hardening] test "PgPool injects
  # statement_timeout and lock_timeout GUCs"). This is the one path that
  # takes a caller-supplied DSN (paths 2-4 build DSNs from constants), so
  # gate it before the per-agent derivation below, which would otherwise
  # carry an unsafe `options=` straight into PA_DSN. DSN-literal match
  # only - an indirect `service=` naming a pg_service.conf section that
  # itself sets `options=` is out of scope for this string check. Case-
  # sensitive is intentional: libpq's conninfo_storeval (fe-connect.c)
  # matches keywords via a case-sensitive strcmp, so an "OPTIONS=" variant
  # isn't honored as the `options` keyword by libpq either. Keyword-form
  # conninfo allows whitespace around `=` (`options = -c ...` is valid
  # per libpq's conninfo_parse), so the `=` is matched with `[[:space:]]*`
  # in front, not a bare `=` - adversarial review v2 F1', reproduced
  # empirically against `options = '-c statement_timeout=0'`.
  if [[ "${YUZU_TEST_POSTGRES_DSN}" =~ (^|[?&[:space:]])options[[:space:]]*= ]]; then
    echo "::error::ensure-postgres: pre-set YUZU_TEST_POSTGRES_DSN must not set options= (disables PgPool statement_timeout/lock_timeout safety bounds) - put durability settings in postgresql.conf via ALTER SYSTEM instead. See docs/ci-architecture.md 'Postgres for server tests'." >&2
    exit "$SOFT_EXIT"
  fi

  # Durability conformance guard (Wee Tam Windows CI, #2167 follow-up):
  # sourced HERE, inside path 1 only — paths 2-3 apply durability-off once
  # via -c flags at container-creation time and never drift (path 4 exports
  # a conventional, self-hosted-Windows native cluster it never tunes at
  # all), so they stay byte-for-byte unaffected by this source, including
  # under `set -euo pipefail` if this library ever failed to parse.
  # p1_psql/p1_conform above resolve pg_durability_decide et al. at CALL
  # time (bash looks up
  # function names when they run, not when they are defined), so they can
  # stay defined above path 1 while the source itself waits until here. See
  # docs/ci-architecture.md "Postgres for server tests".
  # shellcheck source=./pg-durability.sh
  source "$(dirname "${BASH_SOURCE[0]}")/pg-durability.sh"

  # psql resolution for the durability conformance guard below: prefer the
  # toolchain-manifest-vouched psql (YUZU_CI_PSQL, exported only by
  # deploy/windows/Assert-Toolchain.ps1 -ExportCiEnv from a
  # Provision-Windows-Runner.ps1 manifest — Assert-Toolchain has already
  # proven this exact psql.exe against this exact cluster with SELECT 1,
  # earlier in this same job), else whatever is on PATH. Never set
  # YUZU_CI_PSQL by hand (a dev shell, a runner-level env override, ...): a
  # manifest-vouched psql is exactly what authorises this script's heal and
  # its manifest-vouched-probe no-fallback rule (pg_heal_allowed's
  # psql_src="manifest" check) — hand-setting it to a psql this job hasn't
  # actually proven against the target cluster would claim a vouch that was
  # never earned.
  P1_PSQL="$(pg_psql_path_from_env "${YUZU_CI_PSQL:-}")"
  P1_PSQL_SRC=manifest
  if [[ -z "$P1_PSQL" || ! -x "$P1_PSQL" ]]; then
    if [[ -n "${YUZU_CI_PSQL:-}" ]]; then
      # A set-but-unusable YUZU_CI_PSQL must not silently demote to a PATH
      # psql with no message — that would quietly switch off both the heal
      # and the manifest no-fallback rule (an empty/unset manifest path, or
      # one whose file mode isn't executable — this -x check catches only
      # those two; a path that IS marked executable but fails to actually
      # run, e.g. a missing DLL, is not caught here and instead surfaces
      # later as psql's own rc 126/127, named by p1_rc_hint), the exact
      # failure class this guard exists to surface loudly.
      echo "::warning::ensure-postgres: YUZU_CI_PSQL is set but not executable (${P1_PSQL:-$YUZU_CI_PSQL}) — ignoring it (durability heal and the manifest no-fallback rule are OFF this job); check Assert-Toolchain.ps1 -ExportCiEnv / the toolchain manifest." >&2
    fi
    P1_PSQL="$(command -v psql 2>/dev/null || true)"
    P1_PSQL_SRC=path
  fi
  [[ -n "$P1_PSQL" ]] || P1_PSQL_SRC=none

  # Per-agent derivation (#2094): on a multi-agent box the pre-set DSN
  # (machine env on Wee Tam) names the agent-0 cluster; agent <n> shifts
  # the port by <n> (Wee Tam: 5433 -> 5434..5436, provisioned by
  # deploy/windows/Provision-Windows-Runner.ps1). Probe before switching
  # and fall back LOUDLY to the shared DSN while a box has not been
  # provisioned with per-agent clusters yet — the cutover needs no flag
  # day, and the warning is the provisioning reminder. That fallback is for
  # an UNPROVISIONED box only (P1_PSQL_SRC=path/none): once the manifest
  # vouches for this agent's psql, a failed SELECT 1 is a real cluster
  # fault or a transient (or, less likely, an exec failure named by
  # p1_rc_hint), so it is retried briefly then fails hard — never a silent
  # fallback onto the shared agent-0 cluster (that recreates the #2094
  # cross-job contention and contaminates the timing determination this
  # guard exists to make).
  #
  # The derived DSN is trusted only when pg_dsn_parse_authority accepts
  # the pre-set DSN (called DIRECTLY here, not via its pg_dsn_target_provable
  # alias, since this call site needs the PG_DSN_HOST/PG_DSN_PORT fields the
  # parse sets as its documented side channel — pg_dsn_target_provable's own
  # doc comment is silent on that channel), then rebuilt via
  # pg_dsn_rebuild_port — see that function's own doc comment for why. A
  # DSN this cannot derive from is the same no-fallback contract as a
  # failed probe below: fatal with a manifest-vouched psql, a loud warning
  # otherwise — never a silent export of the shared DSN.
  if [[ -n "$AGENT_IDX" && "$AGENT_IDX" != "0" ]]; then
    if pg_dsn_parse_authority "$YUZU_TEST_POSTGRES_DSN"; then
      PA_HOST="$PG_DSN_HOST"
      # 10# forces base-10: a leading-zero port (e.g. "08") would otherwise
      # read as invalid octal under `set -e` and abort path 1 (the same
      # trap documented at :99 for YUZU_CI_PG_SLEEP_SCALE).
      PA_PORT=$((10#$PG_DSN_PORT + AGENT_IDX))
      PA_DSN="$(pg_dsn_rebuild_port "$YUZU_TEST_POSTGRES_DSN" "$PA_PORT")"
      PA_HOW=""
      if [[ -n "$P1_PSQL" ]]; then
        # Authenticate the exact DSN we are about to export (same rationale
        # as path 4's SELECT 1 gate, PR #1334 S5).
        if p1_probe_manifest "$PA_DSN"; then
          PA_HOW="psql SELECT 1 verified"
        elif [[ "$P1_PSQL_SRC" == "manifest" ]]; then
          echo "::error::ensure-postgres: per-agent Postgres on ${PA_HOST}:${PA_PORT} for ${RUNNER_NAME} failed 'psql SELECT 1' (psql rc=${P1_PROBE_RC}$(p1_rc_hint "$P1_PROBE_RC")) although the toolchain manifest declares it (Assert-Toolchain proved it earlier in this same job) — NOT falling back to the shared agent-0 cluster (cross-job contention, #2094). Check the service/orphaned backends; see docs/ci-architecture.md 'Postgres for server tests'." >&2
          exit "$SOFT_EXIT"
        fi
      elif tcp_probe "$PA_HOST" "$PA_PORT"; then
        PA_HOW="TCP probe only — psql unavailable, credential unverified"
      fi
      if [[ -n "$PA_HOW" ]]; then
        P1_DSN="$PA_DSN"
        P1_HOW="pre-set runner env, per-agent port ${PA_PORT} for ${RUNNER_NAME} (${PA_HOW}; #2094)"
        p1_conform "$P1_DSN" || exit "$SOFT_EXIT"
        emit_dsn "$P1_DSN" "$P1_HOW"
        exit 0
      fi
      echo "::warning::ensure-postgres: no per-agent Postgres on ${PA_HOST}:${PA_PORT} for ${RUNNER_NAME} — falling back to the SHARED pre-set DSN (cross-job contention multiplier, #2094). Provision the per-agent clusters (deploy/windows/Provision-Windows-Runner.ps1) to remove it." >&2
    elif [[ "$P1_PSQL_SRC" == "manifest" ]]; then
      echo "::error::ensure-postgres: cannot derive a per-agent DSN for ${RUNNER_NAME} — the pre-set YUZU_TEST_POSTGRES_DSN is not a plain postgresql://user@host:port/db URI (keyword-form, IPv6, multi-host or query-string DSNs cannot be shifted safely), and this job's psql is manifest-vouched, so falling back to the shared DSN would silently defeat #2094 isolation with no way to verify it. See docs/ci-architecture.md 'Postgres for server tests'." >&2
      exit "$SOFT_EXIT"
    else
      echo "::warning::ensure-postgres: cannot derive a per-agent DSN for ${RUNNER_NAME} — the pre-set YUZU_TEST_POSTGRES_DSN is not a plain postgresql://user@host:port/db URI; using the shared pre-set DSN (cross-job contention multiplier, #2094)." >&2
    fi
  fi
  P1_DSN="$YUZU_TEST_POSTGRES_DSN"
  P1_HOW="pre-set runner env"
  # Agent 0 (or a single-agent box) had NO probe-with-retry at
  # all before this — its first contact with the cluster was the
  # conformance read itself. Give it the same bounded retry + no-fallback
  # rule the per-agent branch above has, so a manifest-vouched transient
  # gets the same short grace and a genuine fault fails with the same
  # loud, specific wording instead of surfacing only as a generic read
  # failure inside p1_conform.
  if [[ "$P1_PSQL_SRC" == "manifest" ]] && ! p1_probe_manifest "$P1_DSN"; then
    echo "::error::ensure-postgres: Postgres on $(p1_hp_disp "$P1_DSN") (agent 0 / base cluster for ${RUNNER_NAME:-this runner}) failed 'psql SELECT 1' (psql rc=${P1_PROBE_RC}$(p1_rc_hint "$P1_PROBE_RC")) although the toolchain manifest declares it (Assert-Toolchain proved it earlier in this same job) — refusing to proceed. Check the service/orphaned backends; see docs/ci-architecture.md 'Postgres for server tests'." >&2
    exit "$SOFT_EXIT"
  fi
  p1_conform "$P1_DSN" || exit "$SOFT_EXIT"
  emit_dsn "$P1_DSN" "$P1_HOW"
  exit 0
fi

# ── 2. Docker (self-hosted Linux) ────────────────────────────────────────
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  if command -v flock >/dev/null 2>&1; then
    # Lock name embeds the (possibly per-agent) container name, so agents
    # managing their own containers never serialize on each other (#2094).
    exec 9>"/tmp/${CONTAINER}.lock"
    if ! flock -w 120 9; then
      echo "::error::ensure-postgres: timed out waiting for /tmp/${CONTAINER}.lock — another runner may be stuck managing ${CONTAINER}" >&2
      exit "$SOFT_EXIT"
    fi
  else
    echo "::warning::ensure-postgres: flock not available; shared docker container lifecycle is not serialized" >&2
  fi
  # Digest-drift guard: the container is persistent (--restart
  # unless-stopped), so a PG_IMAGE pin bump would otherwise never reach
  # runners that already have one — tests would silently keep running the
  # old Postgres. Recreate when the recorded image differs.
  EXISTING_IMAGE="$(docker inspect -f '{{.Config.Image}}' "$CONTAINER" 2>/dev/null || true)"
  EXISTING_TUNE="$(docker inspect -f '{{index .Config.Labels "yuzu-pgtune"}}' "$CONTAINER" 2>/dev/null || true)"
  if [[ -n "$EXISTING_IMAGE" && ( "$EXISTING_IMAGE" != "$PG_IMAGE" || "$EXISTING_TUNE" != "$PG_TUNE_LABEL" ) ]]; then
    echo "ensure-postgres: ${CONTAINER} drift (image ${EXISTING_IMAGE} vs ${PG_IMAGE}, tune ${EXISTING_TUNE:-none} vs ${PG_TUNE_LABEL}) — recreating" >&2
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    if docker inspect "$CONTAINER" >/dev/null 2>&1; then
      echo "::error::ensure-postgres: failed to remove stale ${CONTAINER} - old tuning still active. See docs/ci-architecture.md 'Postgres for server tests'." >&2
      exit "$SOFT_EXIT"
    fi
  fi
  if [[ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null || true)" != "true" ]]; then
    # ${arr[@]+...} guarded expansion: empty-array-safe under `set -u` on
    # bash 3.2 (macOS /bin/bash) too.
    docker start "$CONTAINER" >/dev/null 2>&1 || docker run -d \
      --name "$CONTAINER" \
      --label "yuzu-pgtune=${PG_TUNE_LABEL}" \
      --restart unless-stopped \
      -e POSTGRES_USER=yuzu -e POSTGRES_PASSWORD=yuzu -e POSTGRES_DB=yuzu_test \
      -p "127.0.0.1:${DOCKER_PORT}:5432" \
      "$PG_IMAGE" ${DOCKER_PG_ARGS[@]+"${DOCKER_PG_ARGS[@]}"} >/dev/null
  fi
  # 120 s budget (60 × 2 s): a cold PG18 first boot runs the init scripts +
  # pgvector extension install, which on a loaded self-hosted runner can take
  # longer than the old 60 s (gov fjarvis).
  for _ in $(seq 1 60); do
    # -h 127.0.0.1: the init-phase temporary server is unix-socket-only,
    # so a TCP probe can't false-positive mid-init.
    if docker exec "$CONTAINER" pg_isready -h 127.0.0.1 -U yuzu -d yuzu_test >/dev/null 2>&1; then
      emit_dsn "postgresql://yuzu:yuzu@127.0.0.1:${DOCKER_PORT}/yuzu_test" "docker container ${CONTAINER}"
      exit 0
    fi
    sleep 2
  done
  echo "::error::ensure-postgres: ${CONTAINER} container did not become ready in 120s — failing the job (SOFT_EXIT=1 since #1320 PR 1)" >&2
  exit "$SOFT_EXIT"
fi

# ── 3. GHA-hosted macOS — brew + throwaway cluster ───────────────────────
if [[ "$(uname -s)" == "Darwin" ]] && command -v brew >/dev/null 2>&1; then
  # Without a valid locale the macOS postmaster aborts with "postmaster
  # became multithreaded during startup" (CoreFoundation locale lookup
  # spawns a thread). Pin LC_ALL/LANG defensively — minimal shells (and
  # this script's own CI smoke test under `env -i`) hit it.
  export LC_ALL="${LC_ALL:-C}" LANG="${LANG:-C}"
  brew list postgresql@18 >/dev/null 2>&1 || brew install --quiet postgresql@18
  PGBIN="$(brew --prefix postgresql@18)/bin"
  PGDATA="${RUNNER_TEMP:-/tmp}/yuzu-ci-pgdata"
  PGLOG="${PGDATA}.log"
  if [[ ! -s "${PGDATA}/PG_VERSION" ]]; then
    # trust auth: throwaway per-job cluster on an ephemeral runner, bound
    # to loopback only.
    "$PGBIN/initdb" --username=yuzu --auth=trust --no-instructions -D "$PGDATA" >/dev/null
  fi
  if ! "$PGBIN/pg_ctl" -D "$PGDATA" status >/dev/null 2>&1; then
    # Durability off — throwaway per-job cluster (see DOCKER_PG_ARGS rationale).
    "$PGBIN/pg_ctl" -D "$PGDATA" -l "$PGLOG" \
      -o "-p ${DOCKER_PORT} -c listen_addresses=127.0.0.1 -c fsync=off -c synchronous_commit=off -c full_page_writes=off" start >/dev/null
  fi
  for _ in $(seq 1 15); do
    if "$PGBIN/pg_isready" -h 127.0.0.1 -p "$DOCKER_PORT" -U yuzu >/dev/null 2>&1; then
      "$PGBIN/createdb" -h 127.0.0.1 -p "$DOCKER_PORT" -U yuzu yuzu_test 2>/dev/null || true
      emit_dsn "postgresql://yuzu@127.0.0.1:${DOCKER_PORT}/yuzu_test" "brew postgresql@18 cluster"
      exit 0
    fi
    sleep 2
  done
  echo "::error::ensure-postgres: brew postgresql@18 cluster did not become ready (log: ${PGLOG}) — failing the job (SOFT_EXIT=1 since #1320 PR 1)" >&2
  exit "$SOFT_EXIT"
fi

# ── 4. Native cluster on the conventional port (self-hosted Windows) ─────
if tcp_probe 127.0.0.1 5432; then
  # Convention documented in docs/ci-architecture.md: role yuzu / password
  # yuzu / db yuzu_test, created once at runner bootstrap. A bespoke setup
  # overrides via the pre-set-DSN path (1).
  NATIVE_DSN="postgresql://yuzu:yuzu@127.0.0.1:5432/yuzu_test"
  # A TCP listener alone proves nothing about the app credential — when
  # psql is on PATH, authenticate the exact DSN we are about to export
  # (PR #1334 review, S5). Fall back to the bare TCP probe + warning when
  # psql is unavailable.
  if command -v psql >/dev/null 2>&1; then
    if psql "$NATIVE_DSN" -tA -c 'SELECT 1' >/dev/null 2>&1; then
      emit_dsn "$NATIVE_DSN" "native cluster on 5432 (psql SELECT 1 verified)"
      exit 0
    fi
    echo "::error::ensure-postgres: something listens on 127.0.0.1:5432 but the conventional DSN failed 'psql SELECT 1' — failing the job. Fix the runner bootstrap (role yuzu / password yuzu / db yuzu_test) or pre-set YUZU_TEST_POSTGRES_DSN." >&2
    exit "$SOFT_EXIT"
  fi
  echo "::warning::ensure-postgres: psql not on PATH — exporting the conventional DSN on a TCP probe only (credential UNVERIFIED). Install psql on the runner for an authenticated readiness check." >&2
  emit_dsn "$NATIVE_DSN" "native cluster on 5432 (TCP probe only — psql unavailable)"
  exit 0
fi

# ── 5. Nothing available ─────────────────────────────────────────────────
echo "::error::ensure-postgres: no Postgres available (no docker, no brew, nothing on 127.0.0.1:5432) — failing the job: the [pg] server tests require a database (SOFT_EXIT=1 since #1320 PR 1). See docs/ci-architecture.md 'Postgres for server tests'." >&2
exit "$SOFT_EXIT"
