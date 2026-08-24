#!/bin/bash
# patroni-entrypoint.sh — render Patroni config from the container environment
# and launch Patroni as the `postgres` OS user (WS-7, ADR-2002 §11).
#
# Generates the config here (rather than shipping a static file) so the
# durability profile and per-node identity are driven entirely by env vars —
# the same image is every node in the cluster.
#
# Env contract (compose supplies these):
#   PATRONI_SCOPE            cluster name (all nodes share it)          [required]
#   PATRONI_NAME             this node's unique name (e.g. pg1)         [required]
#   PATRONI_CONNECT_HOST     hostname other nodes/HAProxy reach us on   [default: $PATRONI_NAME]
#   ETCD_HOSTS               comma-list host:port of the etcd cluster   [required]
#   POSTGRES_USER            bootstrap superuser name                   [default: postgres]
#   POSTGRES_PASSWORD        bootstrap superuser password               [required]
#   YUZU_PG_REPLICATION_PASSWORD  replication-role password             [required]
#   YUZU_DB_USER/NAME/PASSWORD    app role/db/password — consumed by the
#                            inherited post_init init script, NOT here  [required]
#   YUZU_PG_DURABILITY       quorum3 (default) | sync2 | async          [default: quorum3]
set -euo pipefail

: "${PATRONI_SCOPE:?PATRONI_SCOPE is required}"
: "${PATRONI_NAME:?PATRONI_NAME is required}"
: "${ETCD_HOSTS:?ETCD_HOSTS is required}"
: "${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is required}"
: "${YUZU_PG_REPLICATION_PASSWORD:?YUZU_PG_REPLICATION_PASSWORD is required}"
POSTGRES_USER="${POSTGRES_USER:-postgres}"
PATRONI_CONNECT_HOST="${PATRONI_CONNECT_HOST:-$PATRONI_NAME}"
YUZU_PG_DURABILITY="${YUZU_PG_DURABILITY:-quorum3}"

# PGDATA at the base image's version-pinned subdir; the PARENT is the mounted
# volume (never mount .../data — PG18 reads it as an un-migrated upgrade).
PGDATA_DIR="/var/lib/postgresql/18/docker"
PG_BIN_DIR="/usr/lib/postgresql/18/bin"

# ── Durability profile → Patroni synchronous settings (ADR-2002 §11) ──────
# quorum3 (default): ANY 1 of the standbys must confirm → RPO=0 while ≥1 up,
#   writes stall only if BOTH standbys are lost. (Patroni quorum commit.)
# sync2: FIRST 1 — one designated sync standby; single-standby loss stalls
#   writes (the §11 footgun; offered, not default).
# async: no synchronous standby — max availability, bounded data loss.
case "${YUZU_PG_DURABILITY}" in
  quorum3) SYNC_MODE="quorum"; SYNC_COUNT=1 ;;
  sync2)   SYNC_MODE="true";   SYNC_COUNT=1 ;;
  async)   SYNC_MODE="false";  SYNC_COUNT=0 ;;
  *) echo "patroni-entrypoint: unknown YUZU_PG_DURABILITY='${YUZU_PG_DURABILITY}' (want quorum3|sync2|async)" >&2; exit 1 ;;
esac

# Build the etcd3 hosts YAML list from the comma-separated env.
ETCD_HOSTS_YAML=""
IFS=',' read -ra _hosts <<< "${ETCD_HOSTS}"
for h in "${_hosts[@]}"; do
  ETCD_HOSTS_YAML+="    - ${h}"$'\n'
done

CONFIG=/run/patroni/patroni.yml
mkdir -p /run/patroni

cat > "${CONFIG}" <<EOF
scope: ${PATRONI_SCOPE}
name: ${PATRONI_NAME}

restapi:
  listen: 0.0.0.0:8008
  connect_address: ${PATRONI_CONNECT_HOST}:8008

etcd3:
  hosts:
$(printf '%s' "${ETCD_HOSTS_YAML}")

bootstrap:
  dcs:
    ttl: 30
    loop_wait: 10
    retry_timeout: 10
    maximum_lag_on_failover: 1048576
    synchronous_mode: ${SYNC_MODE}
    synchronous_node_count: ${SYNC_COUNT}
    postgresql:
      use_pg_rewind: true
      parameters:
        # Keep aligned with the single-node substrate's operational envelope.
        max_connections: 200
        wal_level: replica
        hot_standby: "on"
        max_wal_senders: 10
        max_replication_slots: 10
        wal_keep_size: 512MB
        password_encryption: scram-sha-256
  # initdb options — data checksums are non-negotiable for an HA store (torn-page
  # / corruption detection across replicas).
  initdb:
    - encoding: UTF8
    - data-checksums
  # pg_hba the cluster bootstraps with. local trust lets the post_init hook run
  # the inherited app-init over the unix socket (container-internal only);
  # TCP always requires scram.
  pg_hba:
    - local all all trust
    - host replication replicator 0.0.0.0/0 scram-sha-256
    - host all all 0.0.0.0/0 scram-sha-256
  # Re-invoke the SHIPPED first-boot init (same script as the single-node
  # image) on the bootstrap primary — creates the app role/db + pgvector with
  # the byte-identical two-password contract. Runs once, cluster-wide.
  post_init: /docker-entrypoint-initdb.d/10-create-yuzu-role-db.sh

postgresql:
  listen: 0.0.0.0:5432
  connect_address: ${PATRONI_CONNECT_HOST}:5432
  data_dir: ${PGDATA_DIR}
  bin_dir: ${PG_BIN_DIR}
  pgpass: /tmp/pgpass
  authentication:
    superuser:
      username: ${POSTGRES_USER}
      password: ${POSTGRES_PASSWORD}
    replication:
      username: replicator
      password: ${YUZU_PG_REPLICATION_PASSWORD}
    rewind:
      username: ${POSTGRES_USER}
      password: ${POSTGRES_PASSWORD}
  parameters:
    unix_socket_directories: /var/run/postgresql

tags:
  nofailover: false
  noloadbalance: false
  clonefrom: false
  nosync: false
EOF

# Ownership: the mounted volume parent + runtime dirs must be writable by the
# postgres OS user that Patroni (and PG) run as.
mkdir -p "$(dirname "${PGDATA_DIR}")" /var/run/postgresql
chown -R postgres:postgres /var/lib/postgresql /var/run/postgresql /run/patroni
chmod 700 "$(dirname "${PGDATA_DIR}")" || true

echo "patroni-entrypoint: node '${PATRONI_NAME}' scope '${PATRONI_SCOPE}' durability '${YUZU_PG_DURABILITY}' (sync_mode=${SYNC_MODE}, count=${SYNC_COUNT})"
exec gosu postgres patroni "${CONFIG}"
