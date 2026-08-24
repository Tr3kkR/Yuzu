# High-Availability PostgreSQL

Yuzu stores all server state in PostgreSQL (ADR-0006/0007) and **fails closed** if it cannot reach
it. A single Postgres is a fully supported deployment, but it is a single point of failure: if that
one database is lost, the server stops. This page describes Yuzu's **opt-in High-Availability
Postgres** profile, which removes that single point of failure with automatic failover.

> HA-Postgres is the **storage** availability axis. It is independent of server-tier HA (running
> multiple server replicas). You can run either without the other. See ADR-2002 for the whole
> picture.

## What you get

- **Automatic failover.** Three PostgreSQL nodes are managed by [Patroni](https://patroni.readthedocs.io/),
  which elects a primary and promotes a standby automatically if the primary is lost. End-to-end
  recovery time (RTO) — from the primary dying to writes flowing again through the endpoint — is
  **~30–40 seconds** with the shipped defaults (Patroni's 30 s leader-lock TTL plus HAProxy
  re-routing). This is measured by the failover smoke test, not just claimed. It is tunable lower by
  reducing Patroni's `ttl`/`loop_wait`, at the cost of sensitivity to transient network blips.
- **No acknowledged-write loss (RPO = 0) while a synchronous quorum holds.** The default profile
  keeps two synchronous standbys and requires at least one to confirm every commit, so a primary
  loss cannot lose an acknowledged write.
- **No server change.** The server connects to the cluster through the same DSN it always used — the
  HA layer is transparent to it.

## Two ways to run it

### 1. Shipped profile (Patroni + etcd + HAProxy)

Yuzu ships a containerised cluster you can select at deploy time:
`deploy/docker/docker-compose.ha-postgres.yml`. It runs:

- **3 × PostgreSQL** nodes (the `yuzu-postgres` substrate + Patroni), replicating synchronously.
- **etcd**, the distributed configuration store Patroni uses for leader election.
- **HAProxy**, which routes the server's connections to whichever node is currently the primary. It
  presents the network alias **`postgres:5432`**, so the server's existing
  `YUZU_POSTGRES_DSN: postgresql://…@postgres:5432/yuzu` is **unchanged**.

Bring it up and prove failover end-to-end:

```bash
bash scripts/ha/ha-pg-smoke.sh
```

The smoke test forms the cluster, writes committed rows through the server-facing endpoint, kills the
primary, and verifies every acknowledged write survives the failover.

### 2. Bring your own (managed service or existing Patroni)

If you run PostgreSQL HA already — a managed service (RDS/Cloud SQL/Azure), your own Patroni, or any
primary-following router — point Yuzu at it with **no shipped cluster**. Two DSN shapes work, both
transparent to the server:

- **A single VIP / endpoint** that always resolves to the current primary (a managed endpoint, or
  your own HAProxy): `YUZU_POSTGRES_DSN=postgresql://user:pw@your-endpoint:5432/yuzu`.
- **A libpq multi-host DSN** with client-side primary discovery:
  `YUZU_POSTGRES_DSN="postgresql://user:pw@n1:5432,n2:5432,n3:5432/yuzu?target_session_attrs=read-write"`.
  libpq tries each host and selects the read-write one; on failover it re-resolves on reconnect.

## Durability profiles

Selected with `YUZU_PG_DURABILITY` on the Postgres nodes:

| Profile | Meaning | Write availability | Data loss on primary failure |
|---|---|---|---|
| **`quorum3`** *(default)* | 1 primary + 2 sync standbys; **any 1** standby must confirm each commit | Writes continue while **at least one** standby is up | **None** (RPO = 0) while a standby is up |
| `sync2` | 1 primary + 1 designated sync standby | Writes **stall** if that one standby is lost | None while the standby is up |
| `async` | No synchronous standby | Maximum — writes never wait on a standby | Up to the replication lag at the moment of failure |

**Why `quorum3` is the default:** it gives RPO = 0 without the `sync2` footgun, where losing the
single standby stalls *all* writes. With `quorum3`, writes only stall if **both** standbys are lost —
at which point the cluster deliberately blocks writes rather than risk acknowledging a write it
cannot protect (fail-closed, consistent with ADR-0007). **Losing quorum blocks writes; it never
loses acknowledged data.**

## Production requirements (read before deploying)

The shipped Compose profile is convenient but Compose alone cannot make a deployment
production-grade. You **must**:

1. **Run a 3-node etcd cluster**, not the single etcd node the dev profile starts. A single etcd is
   itself a single point of failure for leader election.
2. **Place the three Postgres nodes on distinct hosts / failure domains.** Compose pins containers,
   not hosts — co-locating all three on one machine voids the whole guarantee. On a single Docker
   host the profile is for testing only.
3. **Supply real, distinct secrets** for all three roles: the superuser password
   (`YUZU_SUPERUSER_PASSWORD`), the application role password (`YUZU_DB_PASSWORD`), and the
   replication password (`YUZU_PG_REPLICATION_PASSWORD`). The application-role init **refuses to run**
   if the app password equals the superuser password.

## What the server experiences during a failover

- **Bounded, not instant.** In-flight queries against the lost primary fail; the server's connection
  pool bounds this (10 s connect / 30 s statement timeouts, TCP keepalives) and does not hang. Once
  HAProxy re-points at the new primary — within one health-check interval — new connections succeed.
- **A brief burst of errors.** Until the connection-pool failover-hardening (WS-7 slice 2) lands, the
  first request on each stale-cached connection after a failover returns an error before the pool
  reconnects. These are transient — a retry succeeds — and are bounded by the RTO above. Operators
  running behind the agentic/REST API should expect a short window of 5xx responses during the
  ~30–40 s failover, not a sustained outage.

## Backup and disaster recovery

Point-in-time recovery (PITR) and WAL archiving under HA-Postgres are delivered separately (WS-12).
This profile provides **availability** (automatic failover), which is not a substitute for backups —
a logical error (a bad migration, an accidental delete) replicates to every node. Until the WS-12
runbook lands, continue to take backups per your existing disaster-recovery process.

## Monitoring

- **HAProxy stats** are exposed inside the cluster network on port `7000` (which node is primary,
  backend up/down).
- **Patroni REST API** on each node's port `8008`: `GET /primary` (200 on the leader), `GET /replica`
  (200 on a running replica), `GET /health`, `GET /cluster` (full topology).
- Prometheus metrics for leader identity, replica lag, and quorum state are delivered separately
  (WS-11).
