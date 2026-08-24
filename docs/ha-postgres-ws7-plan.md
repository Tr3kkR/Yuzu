# WS-7 — HA-Postgres delivery: implementation plan

> **Status:** kickoff (discovery complete, build starting).
> **Workstream:** WS-7 in `docs/ha-delivery-matrix.md`; realises ADR-2002 §11/§13/§14.
> **Branch:** `feat/ha-pg-ws7` off `dev`.
> **Why this workstream first:** it is the *storage* axis — orthogonal to the server-tier
> active-active work (WS-0/1/3/4/5/6/10) and to the in-flight SQLite→Postgres store migrations.
> WS-7 **does not gate the second server replica** (a single Postgres is safe against two servers);
> it gates the storage-HA / RPO=0 claim. It can therefore land in parallel with the store-migration
> ladder without touching store code.

## 1. Goal

Ship an **opt-in, containerised High-Availability Postgres profile** that a Yuzu operator can select
at deploy time, giving:

- **No storage SPOF** — automatic primary failover (Patroni), RTO ≈ 10–30 s (ADR-2002 §13).
- **RPO = 0 while a synchronous-commit quorum holds** — default **3-node quorum** (1 primary + 2 sync
  standbys, `synchronous_standby_names = ANY 1 (s1,s2)`), selectable down to async/2-node profiles
  (ADR-2002 §11). Quorum loss blocks writes by design (fail-closed, consistent with ADR-0007).
- **Transparent to the server binary** — the server reaches the cluster through a stable endpoint;
  **no server code change** is required (see §3).

Yuzu *ships* Postgres, so HA-PG is a delivery artifact (a Compose profile + an image) plus a test
harness, not an application-code change.

## 2. Two slices — and why the split matters

Discovery (the `PgPool` failover audit) established that the split is real and load-bearing:

### Slice 1 — pure delivery (this plan; zero server-code change, fully migration-orthogonal)
The shipped Patroni+etcd+HAProxy stack, durability profiles, DSN wiring, operator docs, and the
failover smoke harness. **This works against the pool exactly as it is today**, because `PgPool`
already: bounds every failover stall (10 s connect / 30 s statement / 10 s lock timeouts +
keepalives + `tcp_user_timeout`), detects a dead connection on lease-return and discards it
(`PGstatus != CONNECTION_OK`), refuses a connect-storm via its circuit breaker, and **lazily
reconnects to whatever the DSN names** — so once HAProxy re-points at the promoted primary, recovery
happens on its own. Failover today is *recoverable*, just not *graceful*.

### Slice 2 — graceful-failover pool hardening (separate PR, sequenced around Dave, NOT in this plan)
Two `PgPool` gaps make a failover surface a burst of one-shot errors to REST/MCP callers:
- **No validation-on-acquire** — right after failover `acquire()` hands out stale-dead connections;
  each fails once on first use.
- **No transaction retry** — the pool's own header assumes "one connection-level retry" per store,
  but that is implemented in *zero* stores, so the error reaches the caller as a 500/503.

Fixing these in `PgPool` (validate-or-`PQreset` on checkout + a retry-once-on-broken-connection
wrapper) fixes failover UX for **every** server store at once — but `PgPool` is the single
shared chokepoint every store sits on, so it is **catastrophic-blast-radius** and goes through the
full governance pipeline (`security-guardian` + `cpp-safety` + `architect` per the routed-concern
rows). It is the one place WS-7 touches Dave's migration seam, so it is deliberately deferred to its
own PR and coordinated, not bundled here.

> **Held session advisory-lock loss on failover** (a failover silently releases a held session lock
> with no signal) is a **WS-3** concern (fenced leader election), not WS-7 — noted here only so it is
> not mistaken for a slice-2 item. The current guard is leak-safe; it is the *notification* that WS-3
> owns.

## 3. Why the server needs no code change (verified)

The DSN is parsed at `server/core/src/main.cpp` (`--postgres-dsn` / `YUZU_POSTGRES_DSN`) and handed
to `pg::PgPool::Options.conninfo` **verbatim** (`server.cpp`), as libpq `dbname` with
`expand_dbname=1`. Two transparent failover-discovery options, both requiring zero server change
(ADR-2002 §11):

1. **HAProxy VIP (shipped default).** Keep the service name `postgres:5432` pointing at HAProxy,
   which routes to the current primary (selected via each node's Patroni REST health check). The
   server's existing `YUZU_POSTGRES_DSN: postgresql://…@postgres:5432/yuzu` is **unchanged**.
2. **Multi-host DSN** (`host=n1,n2,n3 … target_session_attrs=read-write`) — libpq already parses it;
   nothing in Yuzu strips it. Offered as an alternative in docs for operators who prefer client-side
   failover discovery over an HAProxy hop.

Slice 1 ships option 1 as the default (keeps the DSN and the fail-closed boot probe untouched) and
documents option 2.

## 4. Stack design

```
          server  (YUZU_POSTGRES_DSN → postgres:5432, unchanged)
             │
        ┌────▼─────┐   HAProxy: routes :5432 → whichever backend Patroni reports primary
        │ haproxy  │            (health check GET /primary on each node's :8008 Patroni REST)
        └──┬───┬───┬┘   optional :5433 → replicas (read-only fan-out, later)
           │   │   │
      ┌────▼┐ ┌▼───┐ ┌▼────┐   3 × Patroni-managed Postgres (yuzu-postgres image + Patroni)
      │ pg1 │ │pg2 │ │ pg3 │   synchronous_standby_names = ANY 1 (pg2,pg3) by default
      └──┬──┘ └─┬──┘ └──┬──┘
         └───────┼──────┘
             ┌───▼────┐   etcd: the DCS (leader lock + cluster state). 3-node for prod
             │  etcd  │        quorum; 1-node acceptable only for the dev/test profile.
             └────────┘
```

### Image strategy — Patroni **over** `yuzu-postgres`, never a stock Spilo/Patroni image
The substrate **requires pgvector 0.8.2** and the two-password first-boot init
(`deploy/docker/postgres-init/`). A stock Patroni/Spilo image carries neither. So the HA image is a
thin layer: `FROM ghcr.io/<owner>/yuzu-postgres:<version>` + Patroni (pinned) + a Patroni bootstrap
that runs our init SQL. This keeps the HA nodes byte-identical to the single-node substrate
(same PG 18.4, same pgvector commit, same app-role/db creation) — the alternative (re-implementing
init inside a Spilo template) would drift the two apart.

### Conventions that MUST be preserved on every HA node (from discovery)
- **Volume mount = the PARENT `/var/lib/postgresql`**, never `.../data` (PG 18 entrypoint reads the
  legacy path as an un-migrated upgrade and refuses to boot — docker-library/postgres#1259).
- **Two-password model**: `POSTGRES_PASSWORD` (superuser) ≠ `YUZU_DB_PASSWORD` (app role in the DSN);
  first-boot init refuses if equal/unset. Patroni also needs a **replication** credential — a third
  distinct secret, `YUZU_PG_REPLICATION_PASSWORD`.
- **Healthcheck** stays the `pg_isready -h 127.0.0.1 && psql SELECT 1` shape at the compose level
  (the probe tooling exists in the base image). The **HAProxy** health check is separate and probes
  the Patroni REST API (`/primary`, `/replica`).

### Durability profiles (selectable — ADR-2002 §11)
| Profile | `synchronous_standby_names` | RPO | Notes |
|---|---|---|---|
| `quorum3` (**default**) | `ANY 1 (pg2,pg3)` | 0 while ≥1 standby up | writes stall only if **both** standbys lost |
| `sync2` | `FIRST 1 (pg2)` | 0 while the one standby up | single standby loss stalls writes (the §11 footgun — offered, not default) |
| `async` | *(empty)* | > 0 (bounded by replication lag) | max availability, accepts bounded data loss |

Selected via an env var on the Patroni nodes; the failure-domain placement (distinct hosts) is an
**operator** responsibility that Compose cannot enforce — documented loudly (ADR-2002 §11: Compose
pins containers, not hosts; co-locating all three voids the RPO=0-across-host-failure guarantee).

## 5. Release-gate compliance (verified requirements)
- **`scripts/check-compose-versions.sh` auto-discovery is OFF.** The new standalone compose file must
  be added to its `FILES` array, and every `ghcr.io/<owner>/yuzu-postgres:<tag>` reference must be
  parameterised `${YUZU_VERSION:-X.Y.Z}` (bare-numeric tags are rejected; default must equal the
  released version).
- **Third-party images (Patroni layer base if any, etcd, HAProxy) are not version-gated** by that
  script (only `yuzu-*` images match its regex) — **pin them by digest** ourselves for supply-chain
  hygiene (repo convention).
- **`verify-healthcheck-invariants.sh` does not cover `yuzu-postgres`** (PG is `FROM postgres:*`, its
  healthcheck tooling is the image's reason to exist) — so **no new verify-role** is needed for the
  PG/Patroni/etcd/HAProxy containers. BUT adding/editing any `deploy/docker/docker-compose*.yml`
  **triggers** that workflow's server/gateway matrix — safe as long as we do not alter the
  server/gateway healthcheck command *strings* (which are hard-copied into the verify script).
- **New release image?** If we publish the Patroni-over-yuzu-postgres layer as its own
  `ghcr.io/<owner>/yuzu-postgres-ha` image, it needs a `docker-publish-*` job in `release.yml`
  (cosign + SLSA + SBOM, mirroring `docker-publish-postgres`). Decision recorded in §7.

## 6. File inventory (slice 1)
```
deploy/docker/ha-postgres/Dockerfile.postgres-ha      # FROM yuzu-postgres + pinned Patroni
deploy/docker/ha-postgres/patroni.yml.tmpl            # Patroni config (env-templated bootstrap)
deploy/docker/ha-postgres/patroni-entrypoint.sh       # renders config, runs our init on bootstrap
deploy/docker/ha-postgres/haproxy.cfg                 # :5432 → primary (Patroni REST health check)
deploy/docker/docker-compose.ha-postgres.yml          # the opt-in profile: 3×pg + etcd + haproxy
scripts/ha/ha-pg-smoke.sh                             # WS-9 seed: bring up, kill primary, prove
                                                      #   failover + zero acknowledged-write loss
docs/user-manual/ha-postgres.md                       # operator setup + BYO-vs-shipped + failure domains
docs/ha-postgres-ws7-plan.md                          # this plan
changelog.d/<PR#>-ha-postgres-profile.added.md        # fragment
scripts/check-compose-versions.sh                     # add the new compose to FILES
```

## 7. Explicitly deferred / out of scope for this plan
- **Slice 2 pool hardening** (validation-on-acquire + retry-once) — separate PR, coordinated with the
  store-migration owner; catastrophic-blast-radius, full governance.
- **WS-9 multi-node CI rig** — `scripts/ci/ensure-postgres.sh` provisions exactly one single-node PG
  per agent and actively rejects replication-oriented `options=`/`PGOPTIONS`; a failover CI job needs
  a *new* rig built on this compose, not an extension of that script. The `ha-pg-smoke.sh` here is
  the local seed it will grow from.
- **WS-12 DR/PITR** — `docs/operations/disaster-recovery.md` still exists and is still referenced by
  the user manual despite ADR-2002 declaring it superseded; backup/PITR/WAL under HA-PG is WS-12, not
  WS-7. This plan does not delete or replace it.
- **WS-11 HA-state observability** (leader identity/epoch, replica lag, quorum state metrics) — its
  own workstream.
- **The two routed-concern moves ADR-2002 §14 flags** (AuthDB in-memory sessions; the clock-guard
  `auth_db`-sweep single-writer rule → shared PG rows under an ADR-0012 advisory lock) — these are
  server-tier / coordination concerns, not storage delivery.

## 8. Validation (kickoff — live, on this machine)

The stack was brought up and failover proven end-to-end with `scripts/ha/ha-pg-smoke.sh` and
`scripts/ha/ha-pg-failover-cycles.sh` (Docker 29.1 / Compose v5.1):

- **Cluster forms** — 3 Patroni nodes, quorum sync replication (`synchronous_standby_names = ANY 1
  (…)`), both standbys streaming with lag 0; the shipped two-password/pgvector init runs via
  Patroni's `post_init` hook (byte-identical to the single-node image).
- **Single failover** — kill the primary → a caught-up standby is promoted, and writes resume through
  the **unchanged** HAProxy endpoint. **RTO ≈ 36 s, RPO = 0** (all pre-kill committed rows survived).
- **Repeated-failover soak** — 3 consecutive failovers, each killing a *different* primary, with a
  full pg_rewind rejoin between cycles: **RTOs 36.5 / 29.6 / 36.4 s, RPO = 0 throughout**.

Three harness bugs were found and fixed during validation (recorded so the WS-9 harness carries the
lessons): (1) the failover test must wait for a **caught-up sync standby** before killing the primary
— killing mid-`pg_basebackup` leaves no promotable node; (2) **static IPs are load-bearing** — Docker
purges a stopped container's DNS record, turning Patroni's leader-race probe into a resolution
failure that deadlocks promotion in quorum mode; real deployments (stable addresses) don't hit this,
and static IPs mirror them; (3) every DB probe needs a hard `timeout` — a connection opened during the
brief "HAProxy has no backend" window can stall on a backend that died mid-handshake.

The measured ~36 s end-to-end RTO is Patroni's default 30 s `ttl` plus HAProxy convergence; it is
tunable lower (§4 / operator manual). This exceeds the ADR's "~10–30 s" Patroni-internal figure
because it is the *operator-visible, through-HAProxy* number, which the ADR's §13 estimate did not
include — the manual now states the end-to-end figure.

## 9. Open decision for review
**Publish the Patroni-over-yuzu-postgres image to GHCR, or build it locally in the profile?**
Publishing gives release-pinned, provenance-signed HA nodes (consistent with the other four images)
but adds a `docker-publish` job and a supply-chain surface. Building locally in the Compose profile
keeps the release matrix unchanged but ships a Dockerfile the customer builds. **Recommendation:**
publish it (`yuzu-postgres-ha`) for parity with the shipped-image model — flagged for
`release-deploy` + `build-ci`.
