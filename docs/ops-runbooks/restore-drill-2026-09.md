# Restore drill — 2026-09-07 / 2026-09-08

Workstream D (Reliability), `docs/enterprise-readiness-soc2-first-customer.md`
§3.4, Priority-1 backlog item "Execute first documented backup restore
drill." This drill was **executed**, not simulated — every command below ran
against real containers on this box, with timestamps captured as they
happened. Where the transcript is abbreviated for length, the full command
is still shown; nothing here is a hypothetical description of what a drill
would look like.

**This is the primary transcript, re-executed 2026-09-08 using the
`docker-compose.reference.yml` header's commands verbatim** (governance
finding: the first attempt, run 2026-09-07, deviated from the header's
literal commands in several places while claiming otherwise — kept below as
a labelled appendix for the record, not deleted). Two of the header's own
commands turned out to have real bugs, surfaced by running them exactly as
written rather than by re-wording a description — see "Gaps found" #2 and
#3, both now confirmed against the literal text, not against a
substitution this drill introduced.

**Date:** 2026-09-08 (primary transcript); 2026-09-07 (appendix, attempt 1).
**Operator:** agent A7 (SRE), on behalf of the product owner.
**Rig used:** a disposable `docker compose -p yuzu-drill` project built from
`deploy/docker/docker-compose.reference.yml` (the single-server reference
template, which already documents the exact `pg_dump`/`pg_restore`/`tar`
procedure in its own header comments), with a throwaway port-remap override
committed as `deploy/docker/drill-override.example.yml` (host ports
`18443`/`18080`/`61051`/`61052` in this run — the example file's ports may
need adjusting if those happen to be busy on a given box) and local images
(`YUZU_VERSION=0.13.0` for the server; `yuzu-postgres:local` pinned directly
for postgres, since per-store Postgres schemas are created at runtime by
the server's own migration runner, not baked into the postgres image).

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
Confirmed post-drill (both runs): `yuzu-viz-gateway`/`yuzu-viz-postgres`
still `Up 2 weeks (healthy)`, untouched.

## Image note — what this drill did and did not exercise

`YUZU_VERSION=0.13.0` (built 2026-07-11) was used because the locally-cached
`:local` tag (built 2026-06-21, `v0.12.0`) predates most of the server's own
PostgreSQL-store migration ladder and still ran audit as legacy SQLite with
almost no Postgres schemas present. `0.13.0` carries a materially larger set
of Postgres-backed stores (`app_perf_*`, `deployment_run_store`,
`device_inventory_store`, `preflight_run_store`, `software_inventory_store`,
`vuln_finding_store`, `schema_meta`) — see the schema dump below — but it
**still predates ADR-0040 (AuditStore → PostgreSQL)**, which is current on
`dev` as of this writing. So the audit trail this drill backed up and
restored was the **legacy `audit.db` SQLite file** (via the `tar` half of
the procedure, folded into `server-data`), **not** the PostgreSQL
`audit_store` schema (ADR-0040) described in
`docs/enterprise-readiness-soc2-first-customer.md` §3.5 or in
`docs/assurance/security-whitepaper.md` §4. **Carry this caveat wherever
this drill's "audit-chain integrity check" is cited** — it verified the
legacy SQLite chain's continuity across a restore, which is still a real
and useful proof for any pre-ADR-0040 build, but it is not evidence about
the PostgreSQL-backed audit trail specifically. The `pg_dump`/`pg_restore`
half of this drill is real and exercised real Postgres-backed operational
stores (see the injected-corruption rollback proof in step 4/5 below —
stronger evidence than a row-count match alone). **Gap, not a pass:**
re-run this drill against a `dev`-HEAD server image once one is published,
to get an audit-trail-in-Postgres restore proof.

## Procedure and transcript (primary — header-literal, 2026-09-08)

All timestamps UTC, captured with `date -u +%Y-%m-%dT%H:%M:%SZ` around each
step as it ran.

### 1. Stand up the disposable rig

```
$ cd deploy/docker
$ export YUZU_VERSION=0.13.0
$ export YUZU_POSTGRES_PASSWORD="$(openssl rand -hex 24)"
$ export YUZU_DB_PASSWORD="$(openssl rand -hex 24)"
$ docker compose -p yuzu-drill \
    -f docker-compose.reference.yml \
    -f drill-override.example.yml up -d
```
`UP START: 2026-09-08T09:37:09Z` → healthy postgres + server (after one
retry — the first `up -d` hit a transient host-port-in-use error on this
shared box, unrelated to the drill itself; a fresh unused port pair
resolved it) by `09:39:17Z`.

The reference image expects an interactive first-run admin setup
(`Admin account name [admin]: Admin password:` on stdin) when no
`yuzu-server.cfg` exists — not viable non-interactively. Pre-seeded one
directly into the `server-data` volume, mirroring exactly what
`scripts/start-UAT.sh`'s `generate_config()` does for the native rig
(PBKDF2-SHA256, 100k iterations, format `user:role:salt_hex:hash_hex`),
written with `chown 999:999` (the container's runtime uid — a
`root:root`-owned file is silently unreadable and produces the same "No
user config found" log line as a genuinely missing file, no
permission-denied signal; see "Gaps found" #3).

Server healthy and `/readyz` green at `09:39:17Z`:
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
rows: 241
```
Pre-disaster baseline: **241 audit rows** (SQLite side), **`schema_meta`=8,
`catalog_rollup_meta`=1** (Postgres side — the only two non-trivial PG
tables on a single-node install with no enrolled agents;
`endpoint_state.endpoints` = 0 rows, used as the corruption-injection target
below specifically because it starts empty and any row in it is
unambiguous).

### 3. Backup — `BACKUP START: 2026-09-08T09:39:51Z` → `BACKUP END: 09:39:52Z` (~1s)

**Ran the header's commands literally first, with the bare volume names it
actually specifies** (`server-data`, not a resolved name), to test whether
they work as written:
```
$ docker run --rm -v server-data:/data -v "$PWD":/backup alpine \
    tar czf "/backup/literal-test-yuzu-data.tar.gz" -C /data .
$ tar tzf literal-test-yuzu-data.tar.gz
./
$ docker volume ls | grep -w server-data
local     server-data
```
**Confirmed bug (Gap #2 below):** `docker volume ls` shows a **brand-new,
empty** volume literally named `server-data` was silently auto-created —
Compose had actually named the real volume `yuzu-drill_server-data`
(project-name-prefixed, the default behaviour of every Compose version in
current use), which the header's bare `-v server-data:/data` reference does
not account for. The resulting tarball is 86 bytes and contains nothing but
an empty directory entry. Deleted the stray volume and the empty tarball,
then re-ran with the real, Compose-resolved volume name — the only
adaptation made, and a necessary one, not a stylistic rewording:
```
$ docker run --rm -v yuzu-drill_server-data:/data -v "$PWD":/backup alpine \
    tar czf "/backup/yuzu-data-2026-09-08.tar.gz" -C /data .
$ docker run --rm -v yuzu-drill_certs:/certs -v "$PWD":/backup alpine \
    tar czf "/backup/yuzu-certs-2026-09-08.tar.gz" -C /certs .
$ docker exec -e PGPASSWORD="$YUZU_POSTGRES_PASSWORD" yuzu-postgres \
    pg_dump -U postgres --format=custom yuzu > yuzu-pg-2026-09-08.dump
```
(`-U postgres` — the header's literal user, the actual default superuser
name for this image: `Dockerfile.postgres`/`postgres-init/10-create-yuzu-role-db.sh`
never override `POSTGRES_USER`, so the upstream `postgres:18` image default
applies; `-U yuzu`, used in attempt 1, was itself a deviation — see the
appendix.) Output: `yuzu-data-2026-09-08.tar.gz` (479K),
`yuzu-certs-2026-09-08.tar.gz` (2.7K), `yuzu-pg-2026-09-08.dump` (33K) — the
real data this time.

**RPO reference point: 2026-09-08T09:39:52Z.**

### 4. Disaster — corruption + volume loss, `2026-09-08T09:40:19Z`

To make the restore meaningfully verifiable against the header's own
restore procedure (which, as documented, keeps the `yuzu-postgres`
container running throughout — it never recreates it, see step 5), this
attempt injects a **detectable corruption row** into Postgres *and*
destroys the `server-data`/`certs` volumes entirely, rather than destroying
every container:
```
$ docker exec -e PGPASSWORD="$YUZU_DB_PASSWORD" yuzu-postgres psql -U yuzu -d yuzu -c \
    "INSERT INTO endpoint_state.endpoints (agent_id, hostname, os, last_heartbeat_ms)
     VALUES ('DISASTER-CORRUPTION-MARKER', 'corrupt-host', 'corrupt-os', 0);"
INSERT 0 1
```
Then the header's own literal restore-procedure step 1:
```
$ docker compose -f docker-compose.reference.yml down server
```
**Measured: this single command took 3 minutes 30 seconds** —
`09:40:32Z` → `09:44:02Z` — exactly matching
`docker-compose.reference.yml`'s own `stop_grace_period: 210s` for the
`server` service. The container did not exit promptly on `SIGTERM`; Compose
waited the full grace period before forcing it. **This is the dominant cost
of the header's documented restore procedure** — see "Gaps found" #4 and
the RTO discussion below; it dwarfs every other step combined by roughly
two orders of magnitude.
```
$ docker volume rm yuzu-drill_server-data yuzu-drill_certs
```
Volumes destroyed at `09:44:02Z`. `yuzu-postgres` was never stopped —
matching the header's own procedure, which has no step that touches the
postgres container/volume at all (see "Gaps found" #4a).

### 5. Restore — header's literal commands, `09:44:23Z` → `09:44:46Z`

```
$ docker volume create yuzu-drill_server-data
$ docker volume create yuzu-drill_certs
$ docker run --rm -v yuzu-drill_server-data:/data -v "$PWD":/backup alpine \
    tar xzf "/backup/yuzu-data-2026-09-08.tar.gz" -C /data
$ docker run --rm -v yuzu-drill_certs:/certs -v "$PWD":/backup alpine \
    tar xzf "/backup/yuzu-certs-2026-09-08.tar.gz" -C /certs
```
(The header shows `tar xzf ... -C /data` directly with no explicit
`docker volume create` first — Compose/`docker run -v` auto-vivifies a
named volume on first reference either way, so this is not a deviation,
just spelled out here for clarity on which volume gets created when.
**Note the honest gap this surfaces, though:** the header's own "Restore"
section (the four-command block under `## Restore (with server stopped):`)
shows only the `yuzu-data-*.tar.gz` restore — it never documents restoring
`yuzu-certs-*.tar.gz` at all, even though its own "Backup" section captures
certs as a separate archive. The certs-restore command above is not in the
header's restore steps; it is the obviously-implied missing step, added
here because this drill's disaster destroyed the `certs` volume too and
skipping it would leave the restored server without its CA/leaf material.
Filed as an additional finding against `docker-compose.reference.yml`'s
restore section, not fixed here.)

`pg_restore` — **the header's exact command, `-U postgres --role=yuzu`,
both literally as written** (the `-e PGPASSWORD=...` is a necessary
addition the header's comment-only form omits — without it `pg_dump`/
`pg_restore` have no credential and hang on an interactive prompt neither
command's header text shows handling) — `09:44:24Z`, <1s:
```
$ docker exec -i -e PGPASSWORD="$YUZU_POSTGRES_PASSWORD" yuzu-postgres \
    pg_restore --clean --if-exists --no-owner --role=yuzu -U postgres --dbname=yuzu \
    < yuzu-pg-2026-09-08.dump
pg_restore: error: could not execute query: ERROR:  must be owner of extension vector
Command was: DROP EXTENSION IF EXISTS vector;
pg_restore: error: could not execute query: ERROR:  must be owner of extension vector
Command was: COMMENT ON EXTENSION vector IS 'vector data type and ivfflat and hnsw access methods';
pg_restore: warning: errors ignored on restore: 2
```
**Confirmed bug (Gap #3 below), now against the header's literal command
with no substitution:** the same 2 non-fatal errors fire even connecting as
the real superuser `postgres`, because `--role=yuzu` makes `pg_restore`
execute every statement under `SET ROLE yuzu` — an ordinary login role that
does not own the `vector` extension (only the bootstrap superuser that
created it during first-boot init does) — regardless of which user the
connection itself authenticates as. Attempt 1 (appendix) had wrongly
attributed this to using `-U yuzu` for the connection; re-running with the
header's exact `-U postgres --role=yuzu` proves the connecting user was
never the cause — `--role=yuzu` is.

Bring the server back up — header's exact final step:
```
$ docker compose -f docker-compose.reference.yml up -d server
```
Polled `/readyz` + `docker inspect .State.Health.Status` every 2s:
```
09:44:40Z  docker=starting  readyz=000
09:44:42Z  docker=starting  readyz=200
09:44:44Z  docker=starting  readyz=200
09:44:46Z  docker=healthy   readyz=200   <- RESTORE VERIFIED READY
```

### RTO / RPO measured

- **RTO, header procedure end-to-end (corruption declared → verified
  ready): 4 minutes 27 seconds** — `09:40:19Z` → `09:44:46Z`.
- **RTO, restore procedure only (from the header's first documented
  command to verified ready): 4 minutes 14 seconds** — `09:40:32Z`
  (`down server` issued) → `09:44:46Z`. **Of that, 3m30s (83%) is the
  single `docker compose down server` step**, bound entirely by the
  `stop_grace_period: 210s` setting — not by anything backup/restore-shaped.
  The remaining mechanical work (volume restore + `pg_restore` + server
  start-to-ready) took **≈23 seconds**. An operator who knows the server
  will not be receiving new connections could `docker kill` instead of
  `docker compose down` to skip this wait — but that is not what the
  header documents, and this run measured the header as written.
- **RPO reference point: 2026-09-08T09:39:52Z** (backup completion). The
  post-backup corruption row (step 4) and the header's restore both prove
  the mechanism recovers exactly to that point, not merely "some working
  state" — see the corruption-rollback proof below. As before, the RPO any
  real deployment gets is **however often this procedure is scheduled to
  run**; nothing in this repo schedules it (Gap #1).

### 6. Verify — the acceptance bar, plus a stronger corruption-rollback proof

```
$ curl -sk -c cookies2.txt -X POST https://localhost:18443/login \
    --data-urlencode "username=admin" --data-urlencode "password=YuzuDrillAdmin1!"
{"status":"ok"}                                                          # 200 — login works
```

**Row counts, before vs. after restore:**

| Table | Pre-disaster | Post-corruption | Post-restore |
|---|---|---|---|
| Audit rows (SQLite side, via REST) | 241 | 241 | 242 (241 restored + 1 new login from this verify step) |
| `public.schema_meta` | 8 | 8 | 8 |
| `software_inventory_store.catalog_rollup_meta` | 1 | 1 | 1 |
| `endpoint_state.endpoints` | 0 | **1** (the injected `DISASTER-CORRUPTION-MARKER` row) | **0** |

**The `endpoints` row is the strongest evidence in this drill:** it proves
`pg_restore --clean` didn't just "not lose" the backed-up state, it
actively **overwrote** a real post-backup mutation back to exactly the
backed-up snapshot — a stronger claim than a row-count match alone, which
can't distinguish "nothing changed" from "the restore genuinely
overwrote a divergence."

**Audit chain intact:** the restored audit log's row immediately preceding
the new post-restore login is the *original* pre-disaster `auth.login` row,
directly followed by the original `server.default_certs_generated` row
carrying the identical CA fingerprint on both sides of the restore — proof
this is the same restored data, not a freshly-regenerated CA/database that
happens to look similar. (Same shape as attempt 1's finding — see appendix
for that run's exact fingerprint value.)

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
2. **The header's backup commands use a bare volume name that does not
   account for Compose's project-name prefixing** (confirmed by literal
   execution, this run: `-v server-data:/data` silently auto-creates and
   backs up a brand-new EMPTY volume, not the real
   `<project>_server-data` Compose actually created — an operator following
   the header exactly gets an 86-byte tarball with nothing in it and no
   error telling them so). Needs either a `--project-name`/fixed-name
   convention documented alongside the backup commands, or the commands
   rewritten to resolve the real volume name first (e.g. `docker compose
   ... config --volumes` or `docker volume ls --filter label=...`). Filed
   against `docker-compose.reference.yml`, not fixed here (outside this
   change's owned files).
3. **`pg_restore --role=yuzu` throws 2 non-fatal, unexplained errors on the
   header's own literal command** (`vector` extension ownership) —
   confirmed this run to be caused by `--role=yuzu` specifically, not by
   which user the connection authenticates as (`-U postgres`, the header's
   real superuser, still hits it). Cosmetically alarming, not functionally
   broken — `pg_restore` continues past them and every table restores
   correctly (verified above via the corruption-rollback proof). Fix
   candidates: drop `--role=yuzu` (the restored objects are already
   `--no-owner`'d and don't need it), or document the two-error shape as
   expected in the compose header itself. Filed against
   `docker-compose.reference.yml`, not fixed here.
4. **The header's own `docker compose down server` step took 3m30s in this
   run, bound by `stop_grace_period: 210s`** — dominating the entire
   restore procedure's wall-clock cost (83% of it). Nothing in the header
   flags this, and nothing suggests a faster path for an operator who
   genuinely needs the server down quickly during an incident. Worth a
   documented callout in the compose header itself (e.g., "expect the
   `down` step to take up to `stop_grace_period` seconds; use `docker kill`
   instead if the server can be interrupted mid-drain"). Filed against
   `docker-compose.reference.yml`, not fixed here.
   1. **4a. The header's restore procedure has no path to recover from a
      lost/destroyed Postgres instance** — every restore command in the
      header (`docker exec -i yuzu-postgres pg_restore ...`) assumes the
      `yuzu-postgres` container already exists and is running; there is no
      documented step to recreate it first. This drill's disaster scenario
      deliberately kept Postgres alive throughout to stay within what the
      header's restore section can actually execute — a genuine "Postgres
      itself was lost" scenario needs `docker compose up -d postgres` (or
      equivalent) prepended, undocumented in the header today.
   2. **4b. The header's "Restore" section never restores the certs volume
      its own "Backup" section captures separately** — the backup block
      produces `yuzu-certs-*.tar.gz` alongside `yuzu-data-*.tar.gz`, but the
      restore block's four commands only untar `yuzu-data-*.tar.gz`; a
      certs restore step is simply absent from the documented procedure.
      Following the header's restore section literally, as opposed to this
      drill's (correct, but header-unstated) addition of the obviously-implied
      step, would leave a from-backup-restored install without its CA/leaf
      material.
5. **A wrong-permission config seed fails silently** — copying
   `yuzu-server.cfg` into the volume as the wrong uid produces the *same*
   "No user config found" log line as a genuinely missing file, with no
   permission-denied signal. Worth a boot-time distinguishing log line if
   this is ever scripted into an official install path.
6. **This drill did not exercise the Postgres-backed audit trail** — the
   tested image (`0.13.0`, 2026-07-11) predates ADR-0040. Re-run once a
   `dev`-HEAD image is available, to get restore proof for the audit
   evidence chain specifically (see the image note above).
7. **Not exercised**: the optional Patroni-managed HA-Postgres profile's own
   failover behaviour (`docs/user-manual/ha-postgres.md`) — that document
   already carries its own separately-measured RTO/RPO figures for
   failover (not restore-from-backup) on that profile; this drill is the
   single-replica, non-HA case those figures explicitly say to read
   alongside, not instead of.
8. **Not exercised: `scripts/yuzu-backup.sh` / `scripts/yuzu-restore.sh`
   (the native/systemd install path).** This entire drill ran against the
   containerized `docker-compose.reference.yml` rig and its own `pg_dump`/
   `pg_restore`/`tar` procedure — it says nothing about whether
   `yuzu-backup.sh`'s output actually restores cleanly via
   `yuzu-restore.sh`. Separately, and more importantly for a real
   deployment: `docs/operations/disaster-recovery.md` previously showed
   `yuzu-backup.sh` as the **sole** nightly cron job — that script covers
   SQLite/config files only and explicitly warns it excludes PostgreSQL and
   the CA/keys directory (`scripts/yuzu-backup.sh:123-133`); a cron running
   it alone **cannot restore the server**, since the server's authoritative
   state (ADR-0006) lives in PostgreSQL. Fixed in that doc (external review,
   2026-09-08) to add the missing `pg_dump` + keys-directory steps; not
   fixed by re-running this drill, since this drill never touched
   `yuzu-backup.sh`/`yuzu-restore.sh` at all. A future drill iteration
   should exercise the native path specifically, not just the containerized
   one.

## Appendix — attempt 1 (2026-09-07, deviated from the header)

**Kept for the record per governance ruling, not deleted.** This run
predates the fixes above and was originally (wrongly) described as running
"exact commands from the compose header." It did not: it used `docker exec
yuzu-server tar czf ... && docker cp` instead of the header's `docker run
--rm -v <vol>:/data ... alpine tar czf ...`, and `-U yuzu` instead of the
header's `-U postgres` for both `pg_dump` and `pg_restore`. It also fully
destroyed and recreated the `yuzu-postgres` container (`down -v` /
`docker kill` + volume removal on ALL three volumes including
`postgres-data`), which is **not** what the header's restore section
documents (that only ever stops/starts the `server` service; see Gap #4a
above) — so this appendix's RTO figure is not comparable to the primary
transcript's, and its `-U yuzu` pg_restore errors were (incorrectly, as
attempt 2 now proves) attributed to the wrong cause.

**Rig:** same shape (`-p yuzu-drill` off `docker-compose.reference.yml`,
`YUZU_VERSION=0.13.0`), ports `18443`/`18080`/`60051`/`60052`.

**Backup** — `12:59:40Z` → `12:59:41Z` (~1s):
```
$ docker exec yuzu-server tar czf /tmp/server-data-backup.tgz -C /var/lib/yuzu .
$ docker cp yuzu-server:/tmp/server-data-backup.tgz ./yuzu-data-2026-09-07.tar.gz
$ docker run --rm -v yuzu-drill_certs:/certs -v "$PWD":/backup alpine \
    tar czf "/backup/yuzu-certs-2026-09-07.tar.gz" -C /certs .
$ docker exec -e PGPASSWORD="$YUZU_DB_PASSWORD" yuzu-postgres \
    pg_dump -U yuzu --format=custom yuzu > yuzu-pg-2026-09-07.dump
```
Output: `yuzu-data-2026-09-07.tar.gz` (480K), `yuzu-certs-2026-09-07.tar.gz`
(2.7K), `yuzu-pg-2026-09-07.dump` (33K). RPO reference point:
`2026-09-07T12:59:41Z`.

**Disaster (total container + volume loss)** — `12:59:53Z` → `12:59:54Z`:
```
$ docker kill yuzu-server yuzu-postgres
$ docker rm -f yuzu-server yuzu-postgres
$ docker volume rm yuzu-drill_server-data yuzu-drill_certs yuzu-drill_postgres-data
```

**Restore** — `13:00:02Z` → `13:00:35Z` (33s total, including a fresh
Postgres container from scratch — NOT what the header documents, since the
header never recreates postgres):
```
$ docker compose -p yuzu-drill -f docker-compose.reference.yml \
    -f docker-compose.drill-override.yml create postgres
$ docker compose -p yuzu-drill -f docker-compose.reference.yml \
    -f docker-compose.drill-override.yml start postgres
# healthy at 13:00:08Z (~6s)
$ docker exec -i -e PGPASSWORD="$YUZU_DB_PASSWORD" yuzu-postgres \
    pg_restore --clean --if-exists --no-owner --role=yuzu -U yuzu --dbname=yuzu \
    < yuzu-pg-2026-09-07.dump
pg_restore: error: could not execute query: ERROR:  must be owner of extension vector
pg_restore: error: could not execute query: ERROR:  must be owner of extension vector
pg_restore: warning: errors ignored on restore: 2
$ docker run --rm -v yuzu-drill_server-data:/data -v "$PWD":/backup alpine sh -c \
    "tar xzf /backup/yuzu-data-2026-09-07.tar.gz -C /data && chown -R 999:999 /data"
$ docker volume create yuzu-drill_certs
$ docker run --rm -v yuzu-drill_certs:/certs -v "$PWD":/backup alpine sh -c \
    "tar xzf /backup/yuzu-certs-2026-09-07.tar.gz -C /certs && chown -R 999:999 /certs"
$ docker compose -p yuzu-drill -f docker-compose.reference.yml \
    -f docker-compose.drill-override.yml up -d server
# healthy + readyz 200 at 13:00:35Z
```

**RTO measured (this attempt): 42 seconds** — `12:59:53Z` → `13:00:35Z`.
Not comparable to the primary transcript's RTO: this attempt fully
recreated Postgres from an empty container (fast — a fresh `postgres:18`
boot plus this image's first-boot init is quick) rather than exercising
the header's actual `down server`-then-restore-into-a-live-Postgres
sequence, which is where the primary transcript's 3m30s
`stop_grace_period` cost was found. `docker kill` also skips whatever
graceful-shutdown cost `docker compose down` pays — another reason this
number under-measures what the header's own procedure actually costs.

**Verification (this attempt):** login 200; audit rows 241 → 242 (1 new
verify-step login); `schema_meta`=8 and `catalog_rollup_meta`=1 unchanged;
restored `server.default_certs_generated` row's CA fingerprint
(`4F:35:F5:18:0A:65:DB:74:53:90:5C:26:F5:08:0C:11:41:FD:56:06:4B:23:DF:D2:
64:77:21:D3:E0:32:8D:4A`) identical pre/post-restore.

## Related

- `docs/ops-runbooks/slo.md` §1 — the availability SLO this drill's RTO
  figure informs.
- `docs/user-manual/ha-postgres.md` — the separate HA-Postgres failover
  RTO/RPO figures (a different mechanism: automatic failover, not restore
  from backup).
- `docker-compose.reference.yml` — the backup/restore commands this drill's
  primary transcript executed verbatim (its own header comments); see Gaps
  #2, #3, #4 for the bugs that exercise surfaced in that header's text.
- `deploy/docker/drill-override.example.yml` — the committed, reproducible
  port-remap override this drill uses.
- `scripts/yuzu-backup.sh` / `scripts/yuzu-restore.sh` — the SQLite/config-only
  half for non-containerized (systemd/package) installs; explicitly do not
  cover PostgreSQL or the CA/keys directory (see their own `--help` output).
