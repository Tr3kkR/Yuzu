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
# anyway so a custom POSTGRES_USER/POSTGRES_DB that collides with the Yuzu
# defaults cannot abort initdb.
#
# Env contract (see Dockerfile.postgres header):
#   YUZU_DB_USER      app role      (default: yuzu)
#   YUZU_DB_NAME      app database  (default: yuzu)
#   YUZU_DB_PASSWORD  app password  (default: POSTGRES_PASSWORD)
set -euo pipefail

YUZU_DB_USER="${YUZU_DB_USER:-yuzu}"
YUZU_DB_NAME="${YUZU_DB_NAME:-yuzu}"
YUZU_DB_PASSWORD="${YUZU_DB_PASSWORD:-${POSTGRES_PASSWORD:?POSTGRES_PASSWORD must be set (upstream image contract)}}"

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

\connect :"yuzu_db"
CREATE EXTENSION IF NOT EXISTS vector;
EOSQL

echo "yuzu-postgres init: role '${YUZU_DB_USER}' + database '${YUZU_DB_NAME}' ready (pgvector installed)"
