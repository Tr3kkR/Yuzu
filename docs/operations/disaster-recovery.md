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

### Automated Daily Backup

**`yuzu-backup.sh` alone is not a complete backup** — it covers the
remaining SQLite/config files only. A complete nightly backup needs three
things on the same schedule: this script, a `pg_dump` of the PostgreSQL
database, and the `--ca-dir` keys directory (paired with the database dump
per the restore-pairing invariant above).

```bash
# Add to crontab (root) — three jobs, same schedule, same output dir:

# 1. SQLite/config files (yuzu-backup.sh's actual scope)
0 2 * * * /usr/local/bin/yuzu-backup.sh --data-dir /var/lib/yuzu --config-dir /etc/yuzu --output /backup/yuzu/$(date +\%F)

# 2. PostgreSQL database — see docs/user-manual/server-admin.md "Backing up
#    PostgreSQL state" for the full native-install DSN/PGPASSWORD preamble
#    this one-liner assumes (loads /etc/yuzu/yuzu-server.env, splits the
#    password out of the DSN so it never lands in argv/shell history).
#    mkdir -p first — unlike yuzu-backup.sh, pg_dump --file does not create
#    its parent directory.
0 2 * * * mkdir -p "/backup/yuzu/$(date +\%F)" && . /etc/yuzu/yuzu-server.env && export PGPASSWORD="$(printf '%s\n' "$YUZU_POSTGRES_DSN" | sed -E 's!^[a-z]+://[^:/@]*:([^@]*)@.*$!\1!')" && pg_dump --format=custom --file="/backup/yuzu/$(date +\%F)/yuzu-pg.dump" "$(printf '%s\n' "$YUZU_POSTGRES_DSN" | sed -E 's!^([a-z]+://[^:/@]*):[^@]*@!\1@!')"

# 3. CA/keys directory — MUST be captured on the same schedule as #2, or a
#    database restore has no matching keys and cannot decrypt any secret.
0 2 * * * mkdir -p "/backup/yuzu/$(date +\%F)" && tar czf "/backup/yuzu/$(date +\%F)/yuzu-certs.tar.gz" -C /etc/yuzu/certs .
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
script** (same three-job shape as "Automated Daily Backup" above):
```bash
yuzu-backup.sh --output /backup/yuzu-pre-upgrade-$(date +%Y%m%d)
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
needs the PostgreSQL + keys-directory halves too:

```bash
# 1. Stop the server
systemctl stop yuzu-server

# 2. Restore SQLite/config files
./scripts/yuzu-restore.sh /backup/yuzu-backup-20260321-020000

# 3. Restore the PostgreSQL database — full native-install DSN/PGPASSWORD
#    preamble in docs/user-manual/server-admin.md "Backing up PostgreSQL
#    state"; on a fresh DR target the app role + database must exist first
#    (run install-server-postgres.sh, or your managed-DB provisioning).
. /etc/yuzu/yuzu-server.env
export PGPASSWORD="$(printf '%s\n' "$YUZU_POSTGRES_DSN" | sed -E 's!^[a-z]+://[^:/@]*:([^@]*)@.*$!\1!')"
DSN_NOPASS="$(printf '%s\n' "$YUZU_POSTGRES_DSN" | sed -E 's!^([a-z]+://[^:/@]*):[^@]*@!\1@!')"
pg_restore --clean --if-exists --no-owner --role=yuzu --dbname="$DSN_NOPASS" \
  "/backup/yuzu/20260321/yuzu-pg.dump"

# 4. Restore the keys directory — MUST be the backup paired with the same
#    database dump restored in step 3 (ADR-0010 restore-pairing invariant);
#    mismatched pairs fail closed at boot (kek_unresolvable) rather than
#    serving with unreadable secrets.
tar xzf "/backup/yuzu/20260321/yuzu-certs.tar.gz" -C /etc/yuzu/certs

# 5. Verify manifest
# (yuzu-restore.sh does this automatically for the SQLite/config half)

# 6. Start the server — the migration runner reconciles PostgreSQL schema
#    versions at boot.
systemctl start yuzu-server

# 7. Verify — /readyz and /healthz cover store-open + KEK-fingerprint
#    checks; the drill runbook's login + row-count + audit-chain checks
#    (docs/ops-runbooks/restore-drill-2026-09.md) are the stronger proof.
curl http://localhost:8080/livez
curl http://localhost:8080/readyz
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
