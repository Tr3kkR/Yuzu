# Disaster Recovery

> **Correction (2026-09-08, external review, Codex Astra — verified against
> code).** The "Automated Daily Backup" cron below was previously shown with
> `yuzu-backup.sh` as the SOLE nightly job. That script covers SQLite files
> and config only — it explicitly **excludes PostgreSQL and the CA/keys
> directory** and prints a warning saying so on every run
> (`scripts/yuzu-backup.sh:123-133`). Since ADR-0006, the server's
> authoritative state (audit trail, RBAC, CA inventory, most operational
> stores) lives in **PostgreSQL**, not SQLite — a cron running
> `yuzu-backup.sh` alone **cannot restore the server**; it recovers only the
> config/token files, not the database. See "What to Back Up" and
> "Automated Daily Backup" below for the corrected, complete procedure.

## What to Back Up

| File | Location | Critical |
|------|----------|----------|
| `yuzu-server.cfg` | `/etc/yuzu/` | Yes — contains user credentials |
| `enrollment-tokens.cfg` | `/etc/yuzu/` | Yes — active enrollment tokens |
| `pending-agents.cfg` | `/etc/yuzu/` | Yes — pending approval queue |
| `*.db` (remaining SQLite databases, if any) | `/var/lib/yuzu/` | Yes — see note below |
| TLS certificates + CA/KEK key material | `/etc/yuzu/certs/` (`--ca-dir`) | **Yes — critical, and NOT covered by `yuzu-backup.sh`** — mTLS identity, the CA root key, and the KEK file that decrypts every envelope-encrypted secret column in PostgreSQL (ADR-0010). Losing this directory without a paired backup makes a PostgreSQL restore **unusable** for any secret-bearing store. |
| **PostgreSQL database** | wherever `--postgres-dsn`/`YUZU_POSTGRES_DSN` points | **Yes — critical, and NOT covered by `yuzu-backup.sh`.** The server's authoritative state as of ADR-0006 (audit trail, RBAC, CA inventory, most operational stores). Back up via `pg_dump` — see below. |

**A database backup and a keys-directory backup are a pair — always take
and restore them together (ADR-0010 restore-pairing invariant).** A
`pg_dump` alone recovers ciphertext and wrapped DEKs, never plaintext
secrets; a keys-directory backup alone has nothing to decrypt without its
matching database. Full detail: `docs/user-manual/server-admin.md`
"Backing up PostgreSQL state" and "Key management (secrets KEK)".

> Shipped InstructionDefinitions live inside the `yuzu-server` binary
> (embedded at build time by `server/core/scripts/embed_content.py`)
> and are reseeded on every boot into the PostgreSQL `instruction_store`
> schema (ADR-0058) — not `instructions.db`, which this store no longer
> reads or writes. Operator edits to definitions persist in Postgres;
> back them up via the `pg_dump`/`pg_restore` procedure covered
> elsewhere in this document for the server's Postgres substrate.

## Backup Strategy

### Path convention

Every command below writes to (or reads from) exactly one layout — do not
mix others you may have seen in earlier revisions of this document:

```
$BACKUP_ROOT/<date>/server-data.tar.gz   # yuzu-backup.sh's own output dir, tarred
                                          #   (SQLite files + .cfg/.conf files +
                                          #   yuzu-server.env + its own SHA256SUMS —
                                          #   yuzu-backup.sh captures yuzu-server.env
                                          #   itself since 2026-09-10, hp2-2, so it
                                          #   travels inside this archive, not as a
                                          #   separate top-level file)
$BACKUP_ROOT/<date>/postgres.dump        # pg_dump --format=custom
$BACKUP_ROOT/<date>/certs.tar.gz         # tar of --ca-dir
```
`$BACKUP_ROOT` defaults to `/backup/yuzu` in the examples below.

### Automated Daily Backup

**`yuzu-backup.sh` alone is not a complete backup** — it covers the
SQLite/config files only. A complete nightly backup needs three things on
the same schedule: this script (tarred into `server-data.tar.gz`), a
`pg_dump` of the PostgreSQL database, and the `--ca-dir` keys directory
(paired with the database dump per the restore-pairing invariant above).

```bash
# Add to crontab (root) — three jobs, same schedule, same $BACKUP_ROOT/<date>:

BACKUP_ROOT=/backup/yuzu

# 1. SQLite/config files (yuzu-backup.sh's actual scope, includes
#    yuzu-server.env since 2026-09-10) — tarred to match the one-convention
#    layout above; yuzu-backup.sh's own manifest (SHA256SUMS) travels inside.
0 2 * * * D="$BACKUP_ROOT/$(date +\%F)"; mkdir -p "$D/server-data" && /usr/local/bin/yuzu-backup.sh --data-dir /var/lib/yuzu --config-dir /etc/yuzu --output "$D/server-data" --no-color && tar czf "$D/server-data.tar.gz" -C "$D/server-data" . && rm -rf "$D/server-data"

# 2. PostgreSQL database. Pass the DSN straight to pg_dump — libpq parses a
#    URI or keyword/value conninfo string natively, so there is no reason
#    to hand-parse it (a prior revision tried to `sed` the password out
#    into $PGPASSWORD and got it wrong for percent-encoded passwords,
#    passwordless DSNs, the keyword-conninfo form, and any password
#    containing `@` — governance-reproduced, UP2-3). The trade-off: the DSN
#    (including any password) is visible in this process's argv for the
#    command's duration (`ps`/`/proc/<pid>/cmdline` are world-readable). If
#    that is unacceptable in your environment, use a `~/.pgpass` file or
#    `PGSERVICE`/`PGSERVICEFILE` instead of a password-bearing DSN — both
#    keep the credential out of argv without regex-parsing anything; not
#    used here to keep this recipe to one documented path.
0 2 * * * D="$BACKUP_ROOT/$(date +\%F)"; mkdir -p "$D" && . /etc/yuzu/yuzu-server.env && pg_dump --format=custom --file="$D/postgres.dump" "$YUZU_POSTGRES_DSN"

# 3. CA/keys directory — MUST be captured on the same schedule as #2, or a
#    database restore has no matching keys and cannot decrypt any secret.
0 2 * * * D="$BACKUP_ROOT/$(date +\%F)"; mkdir -p "$D" && tar czf "$D/certs.tar.gz" -C /etc/yuzu/certs .
```

Running a Docker Compose deployment instead of a native/systemd install?
Use the equivalent `pg_dump`/`tar` commands from
`deploy/docker/docker-compose.reference.yml`'s own header comments — note
that header's documented restore procedure has **known gaps**
(`docs/ops-runbooks/restore-drill-2026-09.md` "Gaps found" #2-4b, tracked
#4135): a bare volume-name reference that doesn't account for Compose's
project-name prefixing, `pg_restore --role=yuzu` throwing two non-fatal
ownership errors, an undocumented multi-minute `stop_grace_period` cost on
`docker compose down server`, and a restore section that never restores
the certs volume its own backup section captures. Read that runbook before
relying on the compose-header procedure as written.

### Pre-Upgrade Backup

Always back up before upgrading — **and this is a database-schema-migrating
event, so include the PostgreSQL dump + keys directory, not just this
script** (same three-artifact layout as "Automated Daily Backup" above):
```bash
D="/backup/yuzu-pre-upgrade-$(date +%Y%m%d)"; mkdir -p "$D/server-data"
yuzu-backup.sh --output "$D/server-data" --no-color
tar czf "$D/server-data.tar.gz" -C "$D/server-data" . && rm -rf "$D/server-data"
# plus pg_dump + keys-directory tar — see "Automated Daily Backup" above
```

### Using the Backup Script

```bash
# Default paths
./scripts/yuzu-backup.sh

# Custom paths
./scripts/yuzu-backup.sh --data-dir /var/lib/yuzu --config-dir /etc/yuzu --output /backup/yuzu
```

The script:
1. Flushes SQLite WAL files (`PRAGMA wal_checkpoint(TRUNCATE)`)
2. Copies all `.db` and `.cfg` files
3. Generates a SHA256 manifest for integrity verification

## Restore Procedure

**`yuzu-restore.sh` alone restores SQLite/config only — the same scope gap
as its backup counterpart.** A restore that must recover authoritative
state (audit trail, RBAC, CA inventory, most operational stores — ADR-0006)
needs the PostgreSQL + keys-directory halves too. `D` below is the
`$BACKUP_ROOT/<date>` directory from the "Path convention" section — set it
once and every step below is copy-pasteable:

```bash
D=/backup/yuzu/20260321

# 1. Stop the server
systemctl stop yuzu-server

# 2. Restore SQLite/config files — untar server-data.tar.gz first
#    (yuzu-restore.sh takes a directory, not an archive).
mkdir -p /tmp/yuzu-restore-staging && tar xzf "$D/server-data.tar.gz" -C /tmp/yuzu-restore-staging
./scripts/yuzu-restore.sh /tmp/yuzu-restore-staging --yes
rm -rf /tmp/yuzu-restore-staging

# 3. Restore the PostgreSQL database — AS THE CLUSTER SUPERUSER, not the
#    app-role DSN the server runs on. Verified empirically (attempt-3 drill,
#    docs/ops-runbooks/restore-drill-2026-09.md): CREATE/DROP EXTENSION
#    vector (which pg_dump captures alongside your data) is always
#    superuser-only in PostgreSQL — connecting as the app role fails on it
#    regardless of --role/--no-owner tricks. Two things must BOTH hold, not
#    just one:
#      - Connect as the actual superuser for this one step — `sudo -u
#        postgres pg_restore ...` for a locally-provisioned cluster (peer
#        auth, no password needed), or your managed-PG admin credential for
#        an external instance. A prior revision instead added --role=yuzu
#        to the app-role connection, which makes every statement execute
#        under an ordinary login role via SET ROLE — same failure, just
#        indirected (governance #4135/UP2-1/UP2-8).
#      - Do NOT pass --no-owner when restoring as superuser. pg_dump
#        captured every object as owned by the app role; --no-owner skips
#        the ALTER ... OWNER TO statements that hand ownership back to it,
#        so restoring as superuser WITH --no-owner leaves every object
#        owned by the superuser instead — the server's own app-role DSN
#        then gets "permission denied" on its own tables post-restore
#        (empirically reproduced in the same drill run). Omit --no-owner
#        entirely; pg_restore's owner-reassignment statements run fine
#        under superuser privilege and correctly return ownership to the
#        app role.
#    --exit-on-error is still required either way: it turns what pg_restore
#    used to treat as "2 ignorable errors, everything else still applies"
#    into a hard stop on the FIRST error — silently continuing past an
#    error is exactly how a restore can boot green while actually
#    half-empty (see step 7). **Also empirically reproduced this run:** an
#    --exit-on-error restore that DOES hit that first error (the
#    wrong-connection-user case above) doesn't just "stop before doing
#    anything" — `--clean --if-exists` drops objects before recreating
#    them, so aborting mid-clean can leave the database with tables DROPPED
#    and never recreated, a database in a WORSE state than before the
#    restore started. Get the connection right the first time; do not
#    "just retry" an aborted run without checking what it already dropped.
# Locally-provisioned cluster (peer auth — no password, no DSN needed):
sudo -u postgres pg_restore --exit-on-error --clean --if-exists -d yuzu \
  "$D/postgres.dump"
# External/managed Postgres — supply your own admin credential's DSN
# (there is no YUZU_POSTGRES_DSN-derived shortcut: the app role's
# credential is a separate, unprivileged one by design, so a superuser
# DSN is not something to construct from it — get it from wherever you
# provisioned the managed instance):
# pg_restore --exit-on-error --clean --if-exists \
#   --dbname="postgresql://<admin-user>:<admin-password>@<host>:<port>/yuzu" \
#   "$D/postgres.dump"

# 4. Restore the keys directory — MUST be the backup paired with the same
#    database dump restored in step 3 (ADR-0010 restore-pairing invariant);
#    mismatched pairs fail closed at boot (kek_unresolvable) rather than
#    serving with unreadable secrets.
tar xzf "$D/certs.tar.gz" -C /etc/yuzu/certs

# 5. Verify manifest
# (yuzu-restore.sh does this automatically for the SQLite/config half —
#  step 2 above already failed loudly if it didn't pass)

# 6. Start the server — the migration runner reconciles PostgreSQL schema
#    versions at boot.
systemctl start yuzu-server

# 7. Verify — and do NOT stop at /readyz/healthz. Both check that each
#    store's CONNECTION/SCHEMA is open (`is_open()`), never that it holds
#    the data you expect — a restore that silently skipped step 3 (wrong
#    path, empty dump, a swallowed error pre-fix) boots GREEN on both
#    endpoints with an empty audit trail and RBAC reset to its
#    default-off seed, and neither probe will tell you (sre6b-1: the
#    earlier claim that readyz covers this was false — corrected here).
#    Check the data itself:
curl -fsS http://localhost:8080/livez
curl -fsS http://localhost:8080/readyz
psql "$YUZU_POSTGRES_DSN" -c "SELECT store, version FROM public.schema_meta;"
psql "$YUZU_POSTGRES_DSN" -c "SELECT value FROM rbac_store.rbac_meta WHERE key = 'rbac_enabled';"
psql "$YUZU_POSTGRES_DSN" -c "SELECT count(*) FROM audit_store.audit_events;"
# A real MFA login (see docs/ops-runbooks/auth-db-recovery.md
# "Post-restore verification" for why this is the one check that can't lie).
```

> **Restoring a backup taken before the OIDC-secret redaction fix?** Rotate the OIDC client
> secret. Earlier versions recorded it in the clear in the server log, `GET /api/config` and the
> `config.update` audit detail. The current server no longer discloses it - including for audit
> rows written before the fix, which are redacted when read - but **a restored backup still
> contains the plaintext bytes on disk**, and anything that read it while it was exposed still
> holds a working credential. See
> [Security hardening -> OIDC](../user-manual/security-hardening.md#oidc-hardening).

## Recovery Time

| Scenario | Data at Risk | Recovery Time |
|----------|-------------|---------------|
| Config file loss | Credentials, tokens | Minutes (restore from backup) |
| Database corruption | Responses, audit, policies | Minutes (restore + migration) |
| Full server loss | Everything | 15-30 minutes (new server + restore) |
| Agent data loss | Agent state, TAR history | Agent re-enrolls, TAR rebuilds |

## Failover Architecture

For high availability:

1. **Active-passive**: Two servers with shared storage (NFS/CIFS). Standby takes over on failure.
2. **Gateway multi-site**: Deploy gateways in each site. If one server goes down, re-point gateways.
3. **Database replication**: Use Litestream or sqlite3 backup API for continuous replication to object storage.

## Data Loss Mitigation

- **WAL mode**: SQLite WAL provides crash recovery — incomplete transactions are rolled back on restart
- **Retention policies**: Response and audit data have configurable retention (90/365 days default)
- **Agent resilience**: Agents buffer commands locally and retry on reconnection

## Related

- `docs/ops-runbooks/auth-db-recovery.md` — auth-specific recovery scenarios
  (KEK unresolvable, `auth`/`scim_store` schema migration failure, MFA
  lockout, break-glass) and the "Post-restore verification" checklist this
  doc's Restore Procedure step 7 points at; run this doc's restore first,
  that page's checks second.
- `docs/ops-runbooks/restore-drill-2026-09.md` — this procedure, and the
  separate containerized `docker-compose.reference.yml` procedure, both
  **executed** (not merely described) against a disposable rig with
  measured timings and every defect found along the way.
