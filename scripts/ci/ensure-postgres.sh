#!/usr/bin/env bash
# ensure-postgres.sh — idempotent "a PostgreSQL 16 is reachable for server
# tests" step for every CI tier (ADR-0006 decision 8, #1318).
#
# Exports YUZU_TEST_POSTGRES_DSN via $GITHUB_ENV (or prints it when run
# outside Actions, e.g. by the /test skill or a dev shell). Resolution
# order:
#
#   1. Pre-set YUZU_TEST_POSTGRES_DSN — runner-level/env override, trusted
#      as-is (the documented hook for a self-hosted box with a bespoke
#      native install; see docs/ci-architecture.md "Postgres for server
#      tests").
#   2. Docker available -> idempotent `yuzu-ci-postgres` container on
#      127.0.0.1:15432 (self-hosted Linux: yuzu-wsl2-linux / yuzu-shulgi —
#      the same boxes run the docker-publish jobs, so docker is a given).
#      Port 15432 deliberately avoids colliding with any native cluster or
#      UAT rig on 5432. `--restart unless-stopped` + `docker start` makes
#      this a one-time cost per runner.
#   3. macOS (GHA-hosted, no docker): brew postgresql@16, throwaway
#      trust-auth cluster under $RUNNER_TEMP on port 15432.
#   4. Native cluster on 127.0.0.1:5432 (self-hosted Windows precondition —
#      PostgreSQL 16 installed as a service with role yuzu / password yuzu
#      / database yuzu_test; bootstrap once per runner, see
#      docs/ci-architecture.md).
#   5. Nothing found -> ::warning + exit 0.
#
# NON-FATAL (path 5) on purpose: no test consumes the DSN until #1320 lands
# the server-side Postgres substrate. When the first Postgres-backed store
# test ships, flip SOFT_EXIT to 1 so a missing database fails the job
# instead of silently skipping coverage.
set -euo pipefail

SOFT_EXIT=0   # flip to 1 when #1320's tests consume YUZU_TEST_POSTGRES_DSN

# Same pinned multi-arch image as deploy/docker/Dockerfile.postgres's base.
PG_IMAGE="postgres:16.14-bookworm@sha256:da514b7d293c5e9126503f85ecd835f4fb0942a77e012fe74f016c114c3e25b8"
CONTAINER="yuzu-ci-postgres"
DOCKER_PORT=15432

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

# ── 1. Pre-set DSN wins ──────────────────────────────────────────────────
if [[ -n "${YUZU_TEST_POSTGRES_DSN:-}" ]]; then
  emit_dsn "$YUZU_TEST_POSTGRES_DSN" "pre-set runner env"
  exit 0
fi

# ── 2. Docker (self-hosted Linux) ────────────────────────────────────────
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  if [[ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null || true)" != "true" ]]; then
    docker start "$CONTAINER" >/dev/null 2>&1 || docker run -d \
      --name "$CONTAINER" \
      --restart unless-stopped \
      -e POSTGRES_USER=yuzu -e POSTGRES_PASSWORD=yuzu -e POSTGRES_DB=yuzu_test \
      -p "127.0.0.1:${DOCKER_PORT}:5432" \
      "$PG_IMAGE" >/dev/null
  fi
  for _ in $(seq 1 30); do
    # -h 127.0.0.1: the init-phase temporary server is unix-socket-only,
    # so a TCP probe can't false-positive mid-init.
    if docker exec "$CONTAINER" pg_isready -h 127.0.0.1 -U yuzu -d yuzu_test >/dev/null 2>&1; then
      emit_dsn "postgresql://yuzu:yuzu@127.0.0.1:${DOCKER_PORT}/yuzu_test" "docker container ${CONTAINER}"
      exit 0
    fi
    sleep 2
  done
  echo "::warning::ensure-postgres: ${CONTAINER} container did not become ready in 60s" >&2
  exit "$SOFT_EXIT"
fi

# ── 3. GHA-hosted macOS — brew + throwaway cluster ───────────────────────
if [[ "$(uname -s)" == "Darwin" ]] && command -v brew >/dev/null 2>&1; then
  # Without a valid locale the macOS postmaster aborts with "postmaster
  # became multithreaded during startup" (CoreFoundation locale lookup
  # spawns a thread). Pin LC_ALL/LANG defensively — minimal shells (and
  # this script's own CI smoke test under `env -i`) hit it.
  export LC_ALL="${LC_ALL:-C}" LANG="${LANG:-C}"
  brew list postgresql@16 >/dev/null 2>&1 || brew install --quiet postgresql@16
  PGBIN="$(brew --prefix postgresql@16)/bin"
  PGDATA="${RUNNER_TEMP:-/tmp}/yuzu-ci-pgdata"
  PGLOG="${PGDATA}.log"
  if [[ ! -s "${PGDATA}/PG_VERSION" ]]; then
    # trust auth: throwaway per-job cluster on an ephemeral runner, bound
    # to loopback only.
    "$PGBIN/initdb" --username=yuzu --auth=trust --no-instructions -D "$PGDATA" >/dev/null
  fi
  if ! "$PGBIN/pg_ctl" -D "$PGDATA" status >/dev/null 2>&1; then
    "$PGBIN/pg_ctl" -D "$PGDATA" -l "$PGLOG" \
      -o "-p ${DOCKER_PORT} -c listen_addresses=127.0.0.1" start >/dev/null
  fi
  for _ in $(seq 1 15); do
    if "$PGBIN/pg_isready" -h 127.0.0.1 -p "$DOCKER_PORT" -U yuzu >/dev/null 2>&1; then
      "$PGBIN/createdb" -h 127.0.0.1 -p "$DOCKER_PORT" -U yuzu yuzu_test 2>/dev/null || true
      emit_dsn "postgresql://yuzu@127.0.0.1:${DOCKER_PORT}/yuzu_test" "brew postgresql@16 cluster"
      exit 0
    fi
    sleep 2
  done
  echo "::warning::ensure-postgres: brew postgresql@16 cluster did not become ready (log: ${PGLOG})" >&2
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
    echo "::warning::ensure-postgres: something listens on 127.0.0.1:5432 but the conventional DSN failed 'psql SELECT 1' — not exporting YUZU_TEST_POSTGRES_DSN. Fix the runner bootstrap (role yuzu / password yuzu / db yuzu_test) or pre-set YUZU_TEST_POSTGRES_DSN." >&2
    exit "$SOFT_EXIT"
  fi
  echo "::warning::ensure-postgres: psql not on PATH — exporting the conventional DSN on a TCP probe only (credential UNVERIFIED). Install psql on the runner for an authenticated readiness check." >&2
  emit_dsn "$NATIVE_DSN" "native cluster on 5432 (TCP probe only — psql unavailable)"
  exit 0
fi

# ── 5. Nothing available ─────────────────────────────────────────────────
echo "::warning::ensure-postgres: no Postgres available (no docker, no brew, nothing on 127.0.0.1:5432) — YUZU_TEST_POSTGRES_DSN not set. Non-fatal until #1320; see docs/ci-architecture.md 'Postgres for server tests'." >&2
exit "$SOFT_EXIT"
