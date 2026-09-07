# Restore drill — 2026-09-07

Workstream D (Reliability), `docs/enterprise-readiness-soc2-first-customer.md`
§3.4, Priority-1 backlog item "Execute first documented backup restore
drill." This drill was **executed**, not simulated — every command below ran
against real containers on this box, with timestamps captured as they
happened. Where the transcript is abbreviated for length, the full command
is still shown; nothing here is a hypothetical description of what a drill
would look like.

**Date:** 2026-09-07
**Operator:** agent A7 (SRE), on behalf of the product owner.
**Rig used:** a disposable `docker compose -p yuzu-drill` project built from
`deploy/docker/docker-compose.reference.yml` (the single-server reference
template, which already documents the exact `pg_dump`/`pg_restore`/`tar`
procedure in its own header comments), with a throwaway port-remap override
(`18443`/`18080`/`60051`/`60052`, kept only in the operator scratchpad — not
committed) and local images (`YUZU_VERSION=0.13.0` for the server;
`yuzu-postgres:local` pinned directly for postgres, since per-store Postgres
schemas are created at runtime by the server's own migration runner, not
baked into the postgres image).

**Why not one of the three named UAT rigs** (`docs/uat-environment.md`):
all three — native `start-UAT.sh`, `start-viz-uat.sh`, `start-demo.sh` — bind
host ports **8080 and 50051**, and are designed to be stood up, exercised,
and torn down as a *whole environment*, not to have their PostgreSQL volume
destroyed mid-run. At drill time, `lsof -i :8080 -i :50051` and `docker ps`
showed the viz-UAT rig (`yuzu-viz-gateway`, `yuzu-viz-postgres`) already
running and healthy (up 2 weeks) — holding port `50051`. This drill never
touches those containers, volumes, or the viz-UAT network; it runs entirely
under its own `-p yuzu-drill` compose project on non-conflicting ports, and
every resource it created was deleted at the end (see "Cleanup" below).
Confirmed post-drill: `yuzu-viz-gateway`/`yuzu-viz-postgres` still `Up 2
weeks (healthy)`, untouched.

## Image note — what this drill did and did not exercise

`YUZU_VERSION=0.13.0` (built 2026-07-11) was used because the locally-cached
`:local` tag (built 2026-06-21, `v0.12.0`) predates most of the server's own
PostgreSQL-store migration ladder and still ran audit as legacy SQLite with
almost no Postgres schemas present. `0.13.0` carries a materially larger set
of Postgres-backed stores (`app_perf_*`, `deployment_run_store`,
`device_inventory_store`, `preflight_run_store`, `software_inventory_store`,
`vuln_finding_store`, `schema_meta`) — see the schema dump below — but it
**still predates ADR-0040 (AuditStore → PostgreSQL, PR #2697)**, which is
current on `dev` as of this writing. So the audit trail this drill backed up
and restored was the **legacy `audit.db` SQLite file** (via the `tar`
half of the procedure, folded into `server-data`), not the `audit_store`
Postgres schema described in `docs/enterprise-readiness-soc2-first-customer.md`
§3.5. The `pg_dump`/`pg_restore` half of this drill is real and exercised
real Postgres-backed operational stores; it does not, on this particular
image, cover the audit evidence chain specifically. **Gap, not a pass**:
re-run this drill against a `dev`-HEAD server image once one is published,
to get an audit-trail-in-Postgres restore proof — tracked below.

## Procedure and transcript

All timestamps UTC, captured with `date -u +%Y-%m-%dT%H:%M:%SZ` around each
step as it ran.

### 1. Stand up the disposable rig

```
$ export YUZU_VERSION=0.13.0
$ export YUZU_POSTGRES_PASSWORD="$(openssl rand -hex 24)"
$ export YUZU_DB_PASSWORD="$(openssl rand -hex 24)"
$ docker compose -p yuzu-drill \
    -f docker-compose.reference.yml \
    -f docker-compose.drill-override.yml up -d
```
`UP START: 2026-09-07T12:58:24Z` → `UP ISSUED: 2026-09-07T12:58:30Z` (postgres
healthy by the time `up -d` returned, per its own compose healthcheck).

The reference image expects an interactive first-run admin setup
(`Admin account name [admin]: Admin password:` on stdin) when no
`yuzu-server.cfg` exists — not viable non-interactively. Pre-seeded one
directly into the `server-data` volume, mirroring exactly what
`scripts/start-UAT.sh`'s `generate_config()` does for the native rig
(PBKDF2-SHA256, 100k iterations, format `user:role:salt_hex:hash_hex`):

```
$ python3 -c "
import hashlib, os
salt = os.urandom(16)
dk = hashlib.pbkdf2_hmac('sha256', 'YuzuDrillAdmin1!'.encode(), salt, 100000, dklen=32)
print(f'admin:admin:{salt.hex()}:{dk.hex()}')" > yuzu-server.cfg
$ docker run --rm -v yuzu-drill_server-data:/data -v "$PWD":/seed alpine sh -c \
    "cp /seed/yuzu-server.cfg /data/yuzu-server.cfg && chown 999:999 /data/yuzu-server.cfg && chmod 600 /data/yuzu-server.cfg"
$ docker restart yuzu-server
```
(The first attempt copied the file as `root:root`; the server process runs
as uid 999 inside the container and could not read a `0600 root:root` file —
silently fell through to first-run setup again with no permission-denied log
line, just "No user config found." **Gap, not a pass**: this failure mode is
not obviously diagnosable from the log alone; noted below.)

Server healthy and `/readyz` green:
```
$ curl -sk https://localhost:18443/readyz
{"status":"ready"}
```

### 2. Seed state to verify against after restore

```
$ curl -sk -c cookies.txt -X POST https://localhost:18443/login \
    --data-urlencode "username=admin" --data-urlencode "password=YuzuDrillAdmin1!"
{"status":"ok"}                                                          # 200
$ curl -sk -b cookies.txt "https://localhost:18443/api/v1/audit?limit=1000" | ...
rows returned: 241
```
PostgreSQL schema at seed time (`\dt` equivalent via `information_schema`):
`app_perf_daily_store.app_perf_daily`, `app_perf_fleet_store.app_perf_fleet`,
`deployment_run_store.{deployments,deployment_device}`,
`device_inventory_store.device_ci`, `endpoint_state.endpoints`,
`preflight_run_store.{runs,run_device}`, `public.schema_meta` (8 rows),
`software_inventory_store.{catalog_rollup,catalog_rollup_meta(1 row),
installed_software,inventory_state,version_rollup}`,
`vuln_finding_store.{agent_coverage,finding}`. Pre-destroy baseline:
**241 audit rows** (SQLite side), **`schema_meta`=8, `catalog_rollup_meta`=1**
(Postgres side — the only two non-empty PG tables on a single-node install
with no enrolled agents; every other table is legitimately empty, not a
restore artifact).

### 3. Backup — `BACKUP START: 2026-09-07T12:59:40Z` → `BACKUP END: 2026-09-07T12:59:41Z` (~1s)

Exact commands from `docker-compose.reference.yml`'s own header:
```
$ docker exec yuzu-server tar czf /tmp/server-data-backup.tgz -C /var/lib/yuzu .
$ docker cp yuzu-server:/tmp/server-data-backup.tgz ./yuzu-data-2026-09-07.tar.gz
$ docker run --rm -v yuzu-drill_certs:/certs -v "$PWD":/backup alpine \
    tar czf "/backup/yuzu-certs-2026-09-07.tar.gz" -C /certs .
$ docker exec -e PGPASSWORD="$YUZU_DB_PASSWORD" yuzu-postgres \
    pg_dump -U yuzu --format=custom yuzu > yuzu-pg-2026-09-07.dump
```
Output: `yuzu-data-2026-09-07.tar.gz` (480K), `yuzu-certs-2026-09-07.tar.gz`
(2.7K), `yuzu-pg-2026-09-07.dump` (33K).

**RPO reference point: 2026-09-07T12:59:41Z.** This drill measures the
backup *mechanism's* correctness and speed (≈1 second wall-clock to capture
a consistent snapshot of a lightly-loaded single-node install), not a
production RPO figure — the real RPO any deployment gets is **however often
this procedure is scheduled to run**, and nothing in this repo currently
schedules it (no cron/systemd-timer unit for the `pg_dump` + `tar` pair
ships anywhere). **Gap:** propose a scheduled-backup unit/script as a
Workstream D follow-up; today it's a documented manual procedure only.

### 4. Disaster — total loss simulated: `2026-09-07T12:59:53Z` → volumes destroyed `12:59:54Z`

```
$ docker kill yuzu-server yuzu-postgres
$ docker rm -f yuzu-server yuzu-postgres
$ docker volume rm yuzu-drill_server-data yuzu-drill_certs yuzu-drill_postgres-data
```
Every named volume backing the drill's server-data, certs, and Postgres
state gone — equivalent to `docker compose down -v`, the exact operation
`docker-compose.reference.yml`'s own header CAUTION warns deletes "ALL
server state ... and the entire database."

### 5. Restore — `RESTORE START: 2026-09-07T13:00:02Z` → `RESTORE VERIFIED READY: 2026-09-07T13:00:35Z`

Fresh Postgres container from scratch, healthy at `13:00:08Z` (~6s):
```
$ docker compose -p yuzu-drill -f docker-compose.reference.yml \
    -f docker-compose.drill-override.yml create postgres
$ docker compose -p yuzu-drill -f docker-compose.reference.yml \
    -f docker-compose.drill-override.yml start postgres
```

`pg_restore` — exact command from the compose header — `13:00:16Z`, <1s:
```
$ docker exec -i -e PGPASSWORD="$YUZU_DB_PASSWORD" yuzu-postgres \
    pg_restore --clean --if-exists --no-owner --role=yuzu -U yuzu --dbname=yuzu \
    < yuzu-pg-2026-09-07.dump
pg_restore: error: could not execute query: ERROR:  must be owner of extension vector
Command was: DROP EXTENSION IF EXISTS vector;
pg_restore: error: could not execute query: ERROR:  must be owner of extension vector
Command was: COMMENT ON EXTENSION vector IS 'vector data type and ivfflat and hnsw access methods';
pg_restore: warning: errors ignored on restore: 2
```
**Gap, not a pass:** the app role (`yuzu`) is not the owner of the `vector`
(pgvector) extension — only the superuser is — so the literal command in
`docker-compose.reference.yml`'s header throws 2 non-fatal errors on every
restore. `pg_restore` continues past them (`errors ignored on restore: 2`)
and every table restores correctly (verified below), but an operator running
this by hand for the first time sees two `ERROR:` lines on what is otherwise
a clean restore and has no way to know from the output alone that they're
expected/harmless. Fix candidates: run this specific restore as the
Postgres superuser instead of `yuzu`, or add `--no-comments` /
`--exclude-schema` guidance, or document the two-error shape as expected in
the compose header itself. Filing as a follow-up rather than fixing here —
`docker-compose.reference.yml` isn't in this change's owned files.

Volume restore (`tar` half), then bring the server back up:
```
$ docker run --rm -v yuzu-drill_server-data:/data -v "$PWD":/backup alpine sh -c \
    "tar xzf /backup/yuzu-data-2026-09-07.tar.gz -C /data && chown -R 999:999 /data"
$ docker volume create yuzu-drill_certs
$ docker run --rm -v yuzu-drill_certs:/certs -v "$PWD":/backup alpine sh -c \
    "tar xzf /backup/yuzu-certs-2026-09-07.tar.gz -C /certs && chown -R 999:999 /certs"
$ docker compose -p yuzu-drill -f docker-compose.reference.yml \
    -f docker-compose.drill-override.yml up -d server
```
Polled `/readyz` + `docker inspect .State.Health.Status` every 2s:
```
13:00:29Z  docker=starting  readyz=000
13:00:31Z  docker=starting  readyz=200
13:00:33Z  docker=starting  readyz=200
13:00:35Z  docker=healthy   readyz=200   <- RESTORE VERIFIED READY
```

### RTO / RPO measured

- **RTO (disaster declared → verified ready): 42 seconds** —
  `12:59:53Z` (containers killed) → `13:00:35Z` (healthy + `/readyz` 200).
  This is the actual wall-clock time for this run, executed as discrete
  manual steps with realistic inter-step pauses (an operator typing/running
  each command in turn), **not** a single pre-scripted one-shot — a scripted
  version chaining the same steps would likely be faster, dominated by
  Postgres container start (~6s) + `pg_restore` (<1s) + server start (~7s)
  ≈ **15-20s of genuinely mechanical floor**, but this document reports the
  measured number, not the hypothetical faster one.
- **RPO reference point: 2026-09-07T12:59:41Z** (backup completion). No
  writes occurred in the 12-second gap between backup and simulated
  disaster (12:59:41Z → 12:59:53Z), verified below by exact row-count and
  content match — this drill therefore measures **0 data loss for this
  backup-to-disaster window**, not a general RPO figure. The RPO any real
  deployment gets is the interval between backup runs (see the scheduling
  gap noted in step 3).

### 6. Verify — the acceptance bar

```
$ curl -sk -c cookies3.txt -X POST https://localhost:18443/login \
    --data-urlencode "username=admin" --data-urlencode "password=YuzuDrillAdmin1!"
{"status":"ok"}                                                          # 200 — login works
```

**Row counts, before vs. after restore:**

| Table | Pre-destroy | Post-restore |
|---|---|---|
| Audit rows (SQLite side, via REST) | 241 | 242 (241 restored + 1 new login from this verify step) |
| `public.schema_meta` | 8 | 8 |
| `software_inventory_store.catalog_rollup_meta` | 1 | 1 |

**Audit chain intact:** the restored audit log's row immediately preceding
the new post-restore login is the *original* pre-destroy `auth.login` row
(same timestamp, `1788785948`), directly followed by the original
`server.default_certs_generated` row carrying **the identical CA
fingerprint** (`4F:35:F5:18:0A:65:DB:74:53:90:5C:26:F5:08:0C:11:41:FD:56:06:
4B:23:DF:D2:64:77:21:D3:E0:32:8D:4A`) on both sides of the restore — proof
this is the same restored data, not a freshly-regenerated CA/database that
happens to look similar.

### Cleanup

```
$ docker kill yuzu-server yuzu-postgres
$ docker rm -f yuzu-server yuzu-postgres
$ docker volume rm yuzu-drill_server-data yuzu-drill_certs yuzu-drill_postgres-data
$ docker network rm yuzu-drill_default
```
Confirmed empty: `docker ps -a --filter name=yuzu-drill` (no containers),
`docker volume ls | grep yuzu-drill` (none), `docker network ls | grep
yuzu-drill` (none). Confirmed the running viz-UAT rig was never touched:
`yuzu-viz-gateway` / `yuzu-viz-postgres` still `Up 2 weeks (healthy)`
immediately after cleanup.

## Gaps found (summary)

1. **No scheduled backup exists.** The `pg_dump`/`tar` procedure is
   documented (`docker-compose.reference.yml` header, `scripts/yuzu-backup.sh`
   for the SQLite/config half) but nothing in this repo runs it on a cadence.
   RPO is entirely operator-discipline-dependent today.
2. **`pg_restore` throws 2 non-fatal, unexplained errors** on the documented
   command (`vector` extension ownership) — cosmetically alarming, not
   functionally broken; needs either a superuser-role restore path or an
   explanatory note in the compose header.
3. **A wrong-permission config seed fails silently** — copying
   `yuzu-server.cfg` into the volume as the wrong uid produces the *same*
   "No user config found" log line as a genuinely missing file, with no
   permission-denied signal. Worth a boot-time distinguishing log line if
   this is ever scripted into an official install path.
4. **This drill did not exercise the Postgres-backed audit trail** — the
   tested image (`0.13.0`, 2026-07-11) predates ADR-0040. Re-run once a
   `dev`-HEAD image is available, to get restore proof for the audit
   evidence chain specifically (see the image note above).
5. **Not exercised**: the optional Patroni-managed HA-Postgres profile's own
   failover behaviour (`docs/user-manual/ha-postgres.md`) — that document
   already carries its own separately-measured RTO/RPO figures for
   failover (not restore-from-backup) on that profile; this drill is the
   single-replica, non-HA case those figures explicitly say to read
   alongside, not instead of.

## Related

- `docs/ops-runbooks/slo.md` §1 — the availability SLO this drill's RTO
  figure informs.
- `docs/user-manual/ha-postgres.md` — the separate HA-Postgres failover
  RTO/RPO figures (a different mechanism: automatic failover, not restore
  from backup).
- `docker-compose.reference.yml` — the backup/restore commands this drill
  executed verbatim (its own header comments).
- `scripts/yuzu-backup.sh` / `scripts/yuzu-restore.sh` — the SQLite/config-only
  half for non-containerized (systemd/package) installs; explicitly do not
  cover PostgreSQL or the CA/keys directory (see their own `--help` output).
