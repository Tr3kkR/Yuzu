# Restore drill — 2026-09-07 / 2026-09-08

> **Branch-split note (2026-09-10, PO decision).** This file's attempts 1-3
> below are kept as **evidence** — they are what found the reference-header
> defects (Gaps #2-4b) and the `docs/operations/disaster-recovery.md`
> defects this file's own "Image note"/"Gaps found" sections describe. They
> are **not** re-executed or corrected here. The corrected
> `disaster-recovery.md` procedure, the corrected `scripts/yuzu-backup.sh`/
> `yuzu-restore.sh`, and a new attempt-4 drill that executes the corrected
> procedure end to end all live on a **separate branch/PR**,
> `po/dr-procedure` (new file
> `docs/ops-runbooks/dr-procedure-drill-2026-09.md` there). **Every
> reference below to `docs/operations/disaster-recovery.md` describes the
> PRE-FIX version of that document** — this file's own copy of that doc was
> reverted to `origin/dev` as part of the branch split (this PR does not
> ship a DR-procedure fix; that is `po/dr-procedure`'s job). Read
> `po/dr-procedure`'s drill for the corrected procedure and its measured
> timings; read this file for the evidence that a fix was needed.
> Also disclosed here (governance C4-1/co3-1, found against attempt 3): the
> "real MFA login" attempt 3's Image note does not mention as a
> substitution — the login exercised was a plain single-factor password
> login, MFA was never enrolled on the drill's admin account. Attempt 4 (on
> `po/dr-procedure`) discloses this and every other substitution explicitly
> in its own "Disclosed substitutions" section; treat that section, not
> this note, as the template for what full disclosure looks like.

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
(PBKDF2-SHA256, 100k iterations, format `user:role:salt_hex:hash_hex`).
**Exact commands** (this is where `YuzuDrillAdmin1!`, the password step 2
logs in with below, comes from — it is chosen here, in plaintext, by this
step; nowhere else):

```
$ docker stop yuzu-server
$ python3 -c "
import hashlib, os
salt = os.urandom(16)
dk = hashlib.pbkdf2_hmac('sha256', 'YuzuDrillAdmin1!'.encode(), salt, 100000, dklen=32)
print(f'admin:admin:{salt.hex()}:{dk.hex()}')" > yuzu-server.cfg
$ docker run --rm -v yuzu-drill_server-data:/data -v "$PWD":/seed alpine sh -c \
    "cp /seed/yuzu-server.cfg /data/yuzu-server.cfg && chown 999:999 /data/yuzu-server.cfg && chmod 600 /data/yuzu-server.cfg"
$ docker start yuzu-server
```
`chown 999:999` sets the container's runtime uid (a `root:root`-owned file
— the default of a plain `docker run` write — is silently unreadable and
produces the same "No user config found" log line as a genuinely missing
file, no permission-denied signal; see "Gaps found" #3, which this exact
sequence is what surfaced).

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
Then the header's own literal restore-procedure step 1 — **transcribed here
exactly as it was actually run in this drill**, i.e. against the disposable
project (`-p yuzu-drill`) and with the port-remap override
(`-f drill-override.example.yml`) both still supplied. **The header's own
text shows the bare form** (`docker compose -f docker-compose.reference.yml
down server`, no `-p`, no override) **— running it literally as printed
there is itself one of the header's defects (#4135, governance-confirmed
CA-1/rd2-7/UP2-7):** a bare invocation targets whatever Compose project
name the operator's shell/directory defaults to, which is a DIFFERENT
project from the one `up` was run under in step 1 above — it would be a
no-op against this drill's actual containers (Compose reports "no such
service" or silently matches nothing, depending on version), and if it
somehow did match, `up -d server` in the header's final step would publish
the BASE ports (8443/8080/50051/50052) since the override wouldn't be
layered in, which is exactly the port set this drill deliberately avoided
to not collide with the concurrently-running viz-UAT rig. Every command
below carries the same `-p`/`-f` flags used throughout this transcript;
treat the header's own bare form as something to correct when you copy it,
not something to run as printed:
```
$ docker compose -p yuzu-drill -f docker-compose.reference.yml \
    -f drill-override.example.yml down server
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

Bring the server back up — header's final step, same `-p`/`-f` correction
as above (see the callout before step 4's `down server`):
```
$ docker compose -p yuzu-drill -f docker-compose.reference.yml \
    -f drill-override.example.yml up -d server
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
   `pg_restore`/`tar` procedure — it originally said nothing about whether
   `yuzu-backup.sh`'s output actually restores cleanly via
   `yuzu-restore.sh`. Separately, and more importantly for a real
   deployment: `docs/operations/disaster-recovery.md` previously showed
   `yuzu-backup.sh` as the **sole** nightly cron job — that script covers
   SQLite/config files only and explicitly warns it excludes PostgreSQL and
   the CA/keys directory (`scripts/yuzu-backup.sh:123-133`); a cron running
   it alone **cannot restore the server**, since the server's authoritative
   state (ADR-0006) lives in PostgreSQL. Fixed in that doc (external review,
   2026-09-08) to add the missing `pg_dump` + keys-directory steps.
   **UPDATE (2026-09-10, attempt 3 below): now executed, not just fixed on
   paper.** `yuzu-backup.sh`/`yuzu-restore.sh` were run for real (inside the
   containerized rig's server container, since that's the only running
   Yuzu filesystem available to this drill), a real `yuzu-backup.sh` bug
   was found and fixed (see Gap #9), and the corrected
   `docs/operations/disaster-recovery.md` procedure — all seven restore
   steps, including the corrected PostgreSQL superuser recipe — was
   exercised end to end. See "Attempt 3" below.
9. **`scripts/yuzu-backup.sh`'s SHA256 manifest was self-referentially
   broken** (found in attempt 3, fixed 2026-09-10): `... > "$OUTPUT/SHA256SUMS"`
   opens/truncates that file before the `*` glob inside the subshell
   expands, so the glob picks up the now-existing zero-byte SHA256SUMS,
   hashes its own empty self, and ships a manifest with one entry that is
   wrong the instant the real content lands — `yuzu-restore.sh`'s
   `sha256sum -c` then fails "backup may be corrupted" on an otherwise
   intact backup. Fixed: compute into a dotfile-named temp path the glob
   does not match, then rename into place. Verified fixed by a real
   backup→restore roundtrip in attempt 3 below (88 files, manifest verified
   clean) and by a minimal roundtrip test beforehand.
10. **A naive fix to Gap #3 (dropping `--role=yuzu`, adding
    `--exit-on-error`) is not sufficient on its own — reproduced live in
    attempt 3.** Restoring via the app-role DSN, even without `--role=yuzu`,
    still fails on the `vector` extension (the app role never owned it
    either — only the connecting SUPERUSER can touch `CREATE`/`DROP
    EXTENSION`, unrelated to `--role`), and with `--exit-on-error` that
    failure now ABORTS the restore instead of continuing past it — but
    `--clean --if-exists` had already DROPPED objects before hitting that
    error, so the aborted run left the database with `public.schema_meta`
    dropped and never recreated: measurably **worse than before the
    restore started**, not merely "unchanged." The actual fix needs two
    changes together, not one: (a) restore as the cluster's real
    PostgreSQL superuser (peer-auth `sudo -u postgres` for a
    locally-provisioned cluster; an external admin credential for managed
    Postgres) — never the app-role DSN, regardless of flags; and (b) do
    **not** pass `--no-owner` when restoring as superuser, or every
    restored object ends up owned by the superuser instead of the app
    role, and the server's own runtime DSN gets "permission denied" on its
    own tables post-restore (also reproduced live). Both fixes are in
    `docs/operations/disaster-recovery.md`'s Restore Procedure step 3 now.

## Attempt 3 — the disaster-recovery.md procedure, executed end to end (2026-09-10)

**Rig:** the same disposable `-p yuzu-drill` project as attempts 1/2
(`docker-compose.reference.yml` + `drill-override.example.yml`,
`YUZU_VERSION=0.13.0`), fresh containers. `disaster-recovery.md` is written
for a native/systemd install (`/etc/yuzu`, `/var/lib/yuzu`, `systemctl`);
this containerized rig is the only running Yuzu filesystem available to
this drill, so every native-shaped command below ran **inside** the
`yuzu-server`/`yuzu-postgres` containers (`docker exec`/`docker cp`) against
their real `/var/lib/yuzu`, `/etc/yuzu/certs`, and the containerized
Postgres — a deliberate, documented substitution of *where* the commands
run, never of *what* they are. `systemctl stop/start` → `docker
stop`/`docker compose up -d server` (the closest analogue available); no
`/etc/yuzu/yuzu-server.env` exists in this container shape (env vars are
injected directly, not via file), so the DSN was supplied to each command
directly instead of via `. /etc/yuzu/yuzu-server.env` — same effective
value, different delivery mechanism.

**Image note:** this build (0.13.0) predates both ADR-0040 (audit→PG) and
ADR-0041 (RBAC→PG) — confirmed directly this run:
`rbac_store.rbac_meta` does not exist (`relation "rbac_store.rbac_meta"
does not exist`), and neither does `audit_store.audit_events`. Both `rbac.db`
and `audit.db` are still real SQLite files at `/var/lib/yuzu/` on this
build, which `yuzu-backup.sh` captures directly — so this run's SQLite half
genuinely round-trips real RBAC + audit data, just not through the
Postgres-schema checks `disaster-recovery.md`'s step 7 names for a
current/dev-HEAD deployment. The `rbac_enabled`/`audit_store.audit_events`
checks in that doc's step 7 are written for the schema names a **current**
deployment has; against this specific pre-migration image they were
substituted below for the SQLite-side equivalents (REST audit row count;
`rbac.db` restored + login succeeding is the practical proof RBAC config
round-tripped, since this build's `/readyz` already gates on `rbac_store`
being open — SQLite here, not the PG schema).

### Backup — `09:26:22Z` → `09:26:39Z` (~17s total, three jobs)

Job 1 — `yuzu-backup.sh` (the **fixed** version), run inside the server
container against its real paths, then tarred to match the canonical
layout:
```
$ docker cp scripts/yuzu-backup.sh yuzu-server:/tmp/yuzu-backup.sh
$ docker exec yuzu-server bash /tmp/yuzu-backup.sh --data-dir /var/lib/yuzu \
    --config-dir /etc/yuzu --output /tmp/server-data --no-color
=== Backup Complete ===
Files:  88
Size:   13243 KB
$ docker exec yuzu-server tar czf /tmp/server-data.tar.gz -C /tmp/server-data .
$ docker cp yuzu-server:/tmp/server-data.tar.gz "$D/server-data.tar.gz"
```
**Manifest self-reference check (Gap #9's fix, verified):**
```
$ docker exec yuzu-server sh -c "grep -c SHA256SUMS /tmp/server-data/SHA256SUMS; wc -l /tmp/server-data/SHA256SUMS"
0
88 /tmp/server-data/SHA256SUMS
```
Zero self-references, 88 entries for 88 files — the bug this drill found
and fixed does not reproduce against the fixed script.

Job 2 — `pg_dump`, DSN passed straight through, no `sed`:
```
$ docker exec yuzu-postgres sh -c "pg_dump --format=custom --file=/tmp/postgres.dump \
    'postgresql://yuzu:${YUZU_DB_PASSWORD}@localhost:5432/yuzu'"
$ docker cp yuzu-postgres:/tmp/postgres.dump "$D/postgres.dump"
```
Job 3 — certs:
```
$ docker run --rm -v yuzu-drill_certs:/certs -v "$D":/backup alpine \
    tar czf "/backup/certs.tar.gz" -C /certs .
```
All three completed in under a second each (`09:26:22Z`→`09:26:25Z` for job
1's backup step, `09:26:39Z` for jobs 2-3). **RPO reference point:
2026-09-10T09:26:39Z.**

### Pre-disaster baseline + corruption injection

Same corruption-injection technique as attempt 2, for the same reason (a
stronger post-restore proof than a row count alone):
```
$ docker exec yuzu-postgres psql -U yuzu -d yuzu -c \
    "INSERT INTO endpoint_state.endpoints (agent_id, hostname, os, last_heartbeat_ms)
     VALUES ('DISASTER-CORRUPTION-MARKER', 'corrupt-host', 'corrupt-os', 0);"
INSERT 0 1
```
Baseline: `schema_meta`=8, `catalog_rollup_meta`=1, `endpoints`=1 (the
marker), 241 audit rows (SQLite, via REST), 88-file SHA256SUMS manifest.

### Disaster — `09:26:53Z` (stop issued) → `09:30:23Z` (volumes destroyed)

```
$ docker stop yuzu-server
```
**Measured: 3 minutes 30 seconds** (`09:26:53Z`→`09:30:23Z`) — the identical
`stop_grace_period: 210s` cost attempt 2 measured against the same compose
file's `down server`. `docker stop` alone pays it too, since the container
was created carrying that same stop-timeout setting.
```
$ docker rm yuzu-server
$ docker volume rm yuzu-drill_server-data yuzu-drill_certs
```
`yuzu-postgres` untouched throughout — matching `disaster-recovery.md`'s
own Restore Procedure, which never stops/recreates PostgreSQL.

### Restore — steps 2-7, `09:30:46Z` → `09:33:02Z`

**Step 2** (SQLite/config, via the fixed `yuzu-restore.sh`) —
`09:30:46Z`→`09:30:48Z` (2s):
```
$ docker volume create yuzu-drill_server-data && docker volume create yuzu-drill_certs
$ docker run --rm --entrypoint bash -v yuzu-drill_server-data:/var/lib/yuzu \
    -v "$D":/backup -v ./scripts:/scripts:ro ghcr.io/tr3kkr/yuzu-server:0.13.0 -c "
      mkdir -p /tmp/staging && tar xzf /backup/server-data.tar.gz -C /tmp/staging &&
      bash /scripts/yuzu-restore.sh /tmp/staging --data-dir /var/lib/yuzu \
        --config-dir /var/lib/yuzu --yes --no-color &&
      chown -R 999:999 /var/lib/yuzu"
--- Verifying manifest ---
[... 88 lines, all "OK" ...]
Manifest verification passed
=== Restore Complete ===
Files restored: 88
```
Clean pass — no self-reference failure, confirming Gap #9's fix under a
real restore, not just the isolated roundtrip test.

**Step 3** (PostgreSQL) — **this is where Gap #10 was found live.** First,
the naive fix (drop `--role=yuzu`, add `--exit-on-error`, keep the
app-role DSN + `--no-owner`) — `09:30:58Z`:
```
$ docker exec yuzu-postgres sh -c "pg_restore --exit-on-error --clean --if-exists \
    --no-owner --dbname='postgresql://yuzu:${YUZU_DB_PASSWORD}@localhost:5432/yuzu' \
    /tmp/postgres.dump"
pg_restore: error: could not execute query: ERROR:  must be owner of extension vector
Command was: DROP EXTENSION IF EXISTS vector;
exit code: 1
```
Checked what that aborted run left behind, **before** attempting any fix —
this is the finding:
```
$ psql ... -c "select count(*) from public.schema_meta;"
ERROR:  relation "public.schema_meta" does not exist
```
`--clean` had already dropped `schema_meta`; `--exit-on-error` stopped
before it was recreated. The database was now in a **worse** state than
before this restore attempt began. Retried as the cluster superuser,
keeping `--no-owner` — `09:31:23Z`, exit code 0, but:
```
$ psql -U yuzu -d yuzu -c "select count(*) from endpoint_state.endpoints;"
ERROR:  permission denied for schema endpoint_state
```
Every object now owned by `postgres` (the connecting user, since
`--no-owner` skipped the ownership handoff) — the app role locked out of
its own tables. Retried a third time, superuser connection, **without**
`--no-owner` — `09:31:47Z`, exit code 0:
```
$ docker exec yuzu-postgres sh -c "pg_restore --exit-on-error --clean --if-exists \
    --dbname='postgresql://postgres:${YUZU_POSTGRES_PASSWORD}@localhost:5432/yuzu' \
    /tmp/postgres.dump"
$ psql -U yuzu -d yuzu -tA -c "select 'schema_meta',count(*) from public.schema_meta
    union all select 'endpoints',count(*) from endpoint_state.endpoints
    union all select 'catalog_rollup_meta',count(*) from software_inventory_store.catalog_rollup_meta;"
schema_meta|8
endpoints|0
catalog_rollup_meta|1
```
Clean: `schema_meta` back to 8 rows, the app role can query its own tables
again, and — the strongest proof — `endpoints` is back to **0**, the
injected corruption marker gone, restored exactly to the backup snapshot.
This third form (superuser connection, no `--no-owner`, `--exit-on-error`)
is what `docs/operations/disaster-recovery.md`'s Restore Procedure step 3
now documents.

**Step 4** (certs) — `09:32:54Z`→`09:32:55Z` (1s):
```
$ docker run --rm -v yuzu-drill_certs:/certs -v "$D":/backup alpine sh -c \
    "tar xzf /backup/certs.tar.gz -C /certs && chown -R 999:999 /certs"
```

**Step 6** (start server) — `09:32:55Z`→`09:33:02Z` (7s), polled the same
way as attempts 1/2:
```
09:32:56Z  docker=starting  readyz=000
09:32:58Z  docker=starting  readyz=200
09:33:00Z  docker=starting  readyz=200
09:33:02Z  docker=healthy   readyz=200   <- RESTORE VERIFIED READY
```

**Step 7** (verify — the checks that replace the false readyz/KEK-only
claim, adapted for this image per the "Image note" above):
```
$ curl -sk -c cookies2.txt -X POST https://localhost:18443/login \
    --data-urlencode "username=admin" --data-urlencode "password=YuzuDrillAdmin1!"
{"status":"ok"}                                                          # 200
$ curl -sk -b cookies2.txt "https://localhost:18443/api/v1/audit?limit=1000" | ...
rows: 242                                                                # 241 restored + 1 new login
$ psql -U yuzu -d yuzu -tA -c "select 'schema_meta',count(*) ... ;"
schema_meta|8
catalog_rollup_meta|1
endpoints|0
```

### RTO / RPO measured (attempt 3)

- **RTO, as actually measured this run (disaster declared → verified
  ready): 6 minutes 9 seconds** — `09:26:53Z`→`09:33:02Z`. This figure
  **includes** the live diagnosis of Gap #10 (two wrong pg_restore forms
  tried and rejected, ~49s of iteration) — it is not the number a corrected
  recipe produces, and is reported honestly rather than cleaned up after
  the fact.
- **RTO, projected for the now-corrected recipe** (skip straight to the
  superuser-without-`--no-owner` form): `stop_grace_period` 3m30s + SQLite
  restore 2s + `pg_restore` <1s + certs 1s + server start-to-ready 7s ≈
  **3 minutes 40 seconds**. Same order of magnitude as attempt 2's 4m14s
  restore-only figure (the two procedures share the dominant
  `stop_grace_period`/`down server` cost) — consistent, not coincidental,
  since both are fundamentally "stop the one container, restore data,
  start it again" shapes.
- **RPO reference point: 2026-09-10T09:26:39Z** (last backup artifact
  written). Zero data loss verified via the corruption-rollback proof
  above, same method as attempt 2.

### Cleanup

```
$ docker kill yuzu-server yuzu-postgres && docker rm -f yuzu-server yuzu-postgres
$ docker volume rm yuzu-drill_server-data yuzu-drill_certs yuzu-drill_postgres-data
$ docker network rm yuzu-drill_default
```
Confirmed empty afterward; `yuzu-viz-gateway`/`yuzu-viz-postgres` confirmed
still running and untouched throughout (same check as attempts 1/2).

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
  Both fixed 2026-09-10 (Gap #9) — see "Attempt 3" above for the
  reproduced bug and the fix, verified by that attempt's real
  backup→restore roundtrip.
- `docs/operations/disaster-recovery.md` — the native-install procedure
  "Attempt 3" above executes end to end; that doc's Restore Procedure step
  3 carries the corrected PostgreSQL superuser recipe Gap #10 found.
- `docs/ops-runbooks/auth-db-recovery.md` — auth-specific recovery
  scenarios and the "Post-restore verification" checklist that
  `disaster-recovery.md`'s Restore Procedure step 7 points at as the
  stronger, can't-lie-as-easily check beyond a raw row count.
