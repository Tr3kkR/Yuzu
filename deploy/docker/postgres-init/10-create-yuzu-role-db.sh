#!/bin/bash
# 10-create-yuzu-role-db.sh — first-boot init for the yuzu-postgres image.
#
# Creates the Yuzu application role and database, and installs the pgvector
# extension into the app database (extension creation needs superuser; doing
# it here means the app role never needs elevated rights).
#
# Per-store SCHEMAs and all tables are created at runtime by the server's
# migration runner (ADR-0008) — deliberately NOT here.
#
# Runs under the upstream postgres entrypoint (docker-entrypoint-initdb.d),
# i.e. only when the data directory is empty. Guarded with WHERE NOT EXISTS
# so a custom POSTGRES_USER/POSTGRES_DB that collides with the Yuzu defaults
# cannot abort initdb — but a pre-existing role/db is then VALIDATED
# (non-superuser, login-capable, correct db owner) so the collision cannot
# silently hand the app DSN superuser rights (PR #1334 review, S4).
#
# Env contract (see Dockerfile.postgres header):
#   YUZU_DB_USER      app role      (default: yuzu)
#   YUZU_DB_NAME      app database  (default: yuzu)
#   YUZU_DB_PASSWORD  app password  REQUIRED — must differ from
#                     POSTGRES_PASSWORD. There is deliberately no fallback
#                     to the superuser password: a leaked app DSN must never
#                     disclose superuser credentials (PR #1334 review, S1).
set -euo pipefail

YUZU_DB_USER="${YUZU_DB_USER:-yuzu}"
YUZU_DB_NAME="${YUZU_DB_NAME:-yuzu}"

# ── Credential / identity guards (S1 + S4) ───────────────────────────────
if [[ -z "${YUZU_DB_PASSWORD:-}" ]]; then
    echo "yuzu-postgres init: ERROR — YUZU_DB_PASSWORD is not set." >&2
    echo "  The app role password must be provided explicitly and must" >&2
    echo "  differ from POSTGRES_PASSWORD (the superuser password)." >&2
    echo "  Generate one:  openssl rand -hex 24" >&2
    exit 1
fi
if [[ "${YUZU_DB_PASSWORD}" == "${POSTGRES_PASSWORD:?POSTGRES_PASSWORD must be set (upstream image contract)}" ]]; then
    echo "yuzu-postgres init: ERROR — YUZU_DB_PASSWORD equals POSTGRES_PASSWORD." >&2
    echo "  The app role and the superuser must not share a password: a" >&2
    echo "  leaked app DSN would disclose superuser credentials." >&2
    exit 1
fi
if [[ "${YUZU_DB_USER}" == "${POSTGRES_USER}" ]]; then
    echo "yuzu-postgres init: ERROR — YUZU_DB_USER ('${YUZU_DB_USER}') equals POSTGRES_USER." >&2
    echo "  The app role must not be the bootstrap superuser. Pick a" >&2
    echo "  different YUZU_DB_USER (or POSTGRES_USER)." >&2
    exit 1
fi

# psql variable substitution (:'var' literal / :"var" identifier) + format()
# with %I/%L handles quoting safely — role/db names and the password are
# never spliced into SQL by the shell.
psql -v ON_ERROR_STOP=1 \
     -v yuzu_user="${YUZU_DB_USER}" \
     -v yuzu_pass="${YUZU_DB_PASSWORD}" \
     -v yuzu_db="${YUZU_DB_NAME}" \
     --username "${POSTGRES_USER}" --dbname postgres <<'EOSQL'
SELECT format('CREATE ROLE %I LOGIN PASSWORD %L', :'yuzu_user', :'yuzu_pass')
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = :'yuzu_user')
\gexec

SELECT format('CREATE DATABASE %I OWNER %I', :'yuzu_db', :'yuzu_user')
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = :'yuzu_db')
\gexec
EOSQL

# ── Post-create validation (S4) ──────────────────────────────────────────
# Whether we just created them or a custom POSTGRES_USER/POSTGRES_DB
# collided with the Yuzu names, the end state must be: non-superuser
# login-capable app role, app database owned by it. Fail the boot loudly
# otherwise — a silently-superuser app role is worse than no database.
role_attrs=$(psql -At -v ON_ERROR_STOP=1 -v yuzu_user="${YUZU_DB_USER}" \
    --username "${POSTGRES_USER}" --dbname postgres <<'EOSQL'
SELECT CASE
         WHEN NOT rolsuper AND rolcanlogin THEN 'ok'
         ELSE 'rolsuper=' || rolsuper::text || ',rolcanlogin=' || rolcanlogin::text
       END
  FROM pg_roles WHERE rolname = :'yuzu_user'
EOSQL
)
if [[ "${role_attrs}" != "ok" ]]; then
    echo "yuzu-postgres init: ERROR — role '${YUZU_DB_USER}' exists but is not a plain login role" >&2
    echo "  (${role_attrs:-role missing}; expected rolsuper=false, rolcanlogin=true)." >&2
    echo "  Refusing to hand the app DSN to this role. Drop/fix it or choose" >&2
    echo "  a different YUZU_DB_USER." >&2
    exit 1
fi

db_owner=$(psql -At -v ON_ERROR_STOP=1 -v yuzu_db="${YUZU_DB_NAME}" \
    --username "${POSTGRES_USER}" --dbname postgres <<'EOSQL'
SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = :'yuzu_db'
EOSQL
)
if [[ "${db_owner}" != "${YUZU_DB_USER}" ]]; then
    echo "yuzu-postgres init: ERROR — database '${YUZU_DB_NAME}' is owned by '${db_owner:-<missing>}'," >&2
    echo "  expected '${YUZU_DB_USER}'. Refusing to continue with wrong ownership." >&2
    exit 1
fi

# ── Extension + schema hardening inside the app database ─────────────────
# REVOKE CREATE: PG15+ already restricts the public schema, but be explicit
# — non-owner roles must not be able to create objects in public. The app
# role keeps create rights via database/schema ownership.
psql -v ON_ERROR_STOP=1 \
     --username "${POSTGRES_USER}" --dbname "${YUZU_DB_NAME}" <<'EOSQL'
CREATE EXTENSION IF NOT EXISTS vector;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
EOSQL

echo "yuzu-postgres init: role '${YUZU_DB_USER}' + database '${YUZU_DB_NAME}' ready (pgvector installed)"
