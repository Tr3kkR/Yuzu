# Upgrading Yuzu

This guide covers upgrading Yuzu components (server, agent, gateway) between versions.

## Version Compatibility

| Server Version | Min Agent Version | Min Gateway Version | Notes |
|---|---|---|---|
| 0.1.x | 0.1.0 | 0.1.0 | Initial release family |
| 0.5.x | 0.5.0 | 0.5.0 | Compiler hardening flags (`-fstack-protector-strong`, `_FORTIFY_SOURCE=2`, full RELRO), config file permission enforcement (`0600` on Unix), SRI integrity attributes on CDN scripts, configurable trigger limit (default 2000), git-derived version strings, chargen instruction definitions. |
| 0.6.x – 0.9.x | same as 0.5.x | same as 0.5.x | No on-disk format changes from 0.5.x; upgrade directly to 0.10.x. |
| 0.10.x | 0.10.0 | 0.10.0 | Server-side schema migration runner wired into every SQLite store. Upgrading from 0.9.x or earlier is data-preserving: the first 0.10.x startup stamps each database at schema v1 and runs a one-time legacy compatibility shim for stores that historically added columns via silent `ALTER TABLE` (`api_token_store`, `instruction_store`, `patch_manager`, `policy_store`, `product_pack_store`, `response_store`). Failed migrations close the affected store's DB handle and are reported via `/readyz` with the failed store name — **check `/readyz`, not `/livez`, to confirm upgrade success**. |
| 0.12.x (next) | 0.12.0 | 0.12.0 | **Build-time content auto-import.** All YAML files in `content/definitions/` (217 InstructionDefinitions) and `content/packs/` (10 InstructionSets at this version) are now embedded in the server binary and auto-imported on every startup. Existing operator-customised definitions with matching IDs are NEVER overwritten — conflicts are silently skipped. **Behaviour change for upgrades:** definitions that an operator previously DELETED via the REST API or dashboard will reappear after upgrade because the auto-import treats a missing row as "needs creation". To permanently suppress a shipped definition, set `enabled: false` via the dashboard or `PATCH /api/v1/definitions/{id}` rather than DELETE-ing the row. Each auto-import write emits an `audit_events.action="content.bundled_import"` row with `principal=system` so operators can audit which definitions were inserted at boot. **Yuzu dark navy palette + Inter webfont** (visual change every operator sees) and **Apache ECharts chart renderer** (replaces bespoke SVG; same payload contract — no operator migration required) ship in the same release. |

**Rule of thumb:** agents and gateway should be the same minor version as the server, or one minor version behind. The server is always upgraded first.

## Upgrade Order

Always upgrade in this order:

1. **Server** -- new server versions accept connections from older agents
2. **Gateway** -- updated to match server protocol changes
3. **Agents** -- can be upgraded via OTA or manually, in batches

Never upgrade agents before the server -- the server must understand the agent's protocol version.

## Pre-Upgrade Checklist

Before upgrading any component:

- [ ] Back up all data (see [Server Administration](server-administration.md))
  - `yuzu-server.cfg`, `enrollment-tokens.cfg`, `pending-agents.cfg`
  - All `.db` files (response store, audit, policies, **auth.db**, etc.) — use `sqlite3 <path> ".backup ..."` rather than `cp` against live WAL databases
- [ ] Check the [CHANGELOG](../../CHANGELOG.md) for breaking changes
- [ ] Verify disk space (at least 500 MB free for migration)
- [ ] Note current version: `yuzu-server --version` / `yuzu-agent --version`
- [ ] Plan a maintenance window (upgrades take < 5 minutes per component)

## Upgrading the Server

### Linux (systemd)

```bash
# 1. Stop the server
sudo systemctl stop yuzu-server

# 2. Back up data
sudo cp /var/lib/yuzu/*.db /var/lib/yuzu/backup/
sudo cp /etc/yuzu/*.cfg /var/lib/yuzu/backup/

# 3. Replace the binary
sudo cp yuzu-server /usr/local/bin/yuzu-server
sudo chmod +x /usr/local/bin/yuzu-server

# 4. Start the server (schema migrations run automatically)
sudo systemctl start yuzu-server

# 5. Verify
sudo systemctl status yuzu-server
curl -s http://localhost:8080/livez
```

### Docker

The reference deployment template lives at `deploy/docker/docker-compose.reference.yml` — copy it into your deployment directory next to a `.env` file, set `YUZU_VERSION`, and harden per the inline TLS checklist in the file header **before** exposing the stack to any untrusted network. The compose file declares a named volume (`server-data`) that survives container replacement and holds every piece of mutable state: `yuzu-server.cfg`, all SQLite databases, `enrollment-tokens.cfg`, `pending-agents.cfg`, `auto-approve.cfg`, and OTA binaries.

An upgrade is a pull-and-restart:

```bash
# 1. Back up first (see below) — the old data is the only recovery path
#    if a migration fails on your specific DB.

# 2. Pick the new release tag (use an .env file or export)
export YUZU_VERSION=0.10.1

# 3. Pull the new image and recreate the container
docker compose -f docker-compose.reference.yml pull server
docker compose -f docker-compose.reference.yml up -d server

# 4. Verify the new version came up and schema migrations ran
docker compose -f docker-compose.reference.yml logs server | tail -40
docker compose -f docker-compose.reference.yml ps server    # should be "healthy"
```

Schema migrations execute automatically during the first `up` with the new image — look for `MigrationRunner: <store> migrated to v<N>` lines in the log (one per store on first upgrade, silent on subsequent restarts). The healthcheck used by `depends_on: service_healthy` probes `/readyz`, which returns 200 only after every store in the readiness conjunction has successfully migrated — so a healthy server container genuinely reflects migration success, not just liveness.

**Back up before upgrading** (run from a dedicated backup directory so `$PWD` is predictable):

```bash
mkdir -p ~/yuzu-backups && cd ~/yuzu-backups
docker run --rm -v server-data:/data -v "$PWD":/backup alpine \
  tar czf "/backup/yuzu-data-$(date +%F).tar.gz" -C /data .
```

> **Note:** this recipe is a cold-ish backup — SQLite is running in WAL mode and a filesystem-level `tar` of a live database may capture a torn snapshot. For strong consistency, `docker compose -f docker-compose.reference.yml stop server` before backup (seconds of downtime) and `start` after. A fully hot backup via SQLite's online-backup API is tracked in the roadmap.

**Rollback if a migration fails** (Docker):

```bash
# 1. Stop the new server (KEEPING the named volume — do NOT use -v)
docker compose -f docker-compose.reference.yml down server

# 2. Restore the previous backup over the existing volume
docker run --rm -v server-data:/data -v "$PWD":/backup alpine \
  sh -c 'rm -rf /data/* && tar xzf /backup/yuzu-data-YYYY-MM-DD.tar.gz -C /data'

# 3. Pin the previous release
export YUZU_VERSION=0.9.0

# 4. Start the previous version
docker compose -f docker-compose.reference.yml up -d server
```

**Never** run `docker compose down -v` unless you intend to delete `server-data` and every bit of server state. `down` alone is safe; the `-v` flag removes named volumes.

### Windows

```powershell
# 1. Stop the service (if running as service) or kill the process
Stop-Service yuzu-server  # or: taskkill /IM yuzu-server.exe /F

# 2. Back up data
Copy-Item C:\ProgramData\Yuzu\*.db C:\ProgramData\Yuzu\backup\
Copy-Item C:\ProgramData\Yuzu\*.cfg C:\ProgramData\Yuzu\backup\

# 3. Replace the binary
Copy-Item yuzu-server.exe "C:\Program Files\Yuzu\yuzu-server.exe"

# 4. Start
Start-Service yuzu-server  # or start manually
```

## Upgrading the Gateway

### Linux (systemd)

```bash
sudo systemctl stop yuzu-gateway
# Replace the release directory
sudo rm -rf /opt/yuzu_gw
sudo tar xzf yuzu-gateway-linux-x64.tar.gz -C /opt/
sudo systemctl start yuzu-gateway
```

### Docker

```bash
docker pull ghcr.io/<owner>/yuzu-gateway:v0.1.1
docker compose up -d yuzu-gateway
```

## Upgrading Agents

### OTA (Recommended)

If the server has OTA updates enabled (`--update-dir`):

1. Place the new agent binary in the server's update directory
2. Agents will check for updates on their configured interval (default: 6 hours)
3. Monitor the fleet dashboard for version rollout progress

### Manual

Follow the same stop/replace/start pattern as the server, per platform.

### Batch Rollout

For large fleets, upgrade in stages:
1. Upgrade a pilot group (5-10 agents) first
2. Monitor for 24 hours
3. Roll out to remaining agents in batches of 10-20%

## Plugin Code Signing (vNEXT, #80)

A new operator-managed plugin trust bundle ships in this release. **Default behaviour is unchanged**: agents that don't pass `--plugin-trust-bundle` and operators that don't upload a bundle through Settings → Plugin Code Signing see identical behaviour to prior releases.

If you turn the feature on, three things change:

1. **New on-disk artifact at `<cert-dir>/plugin-trust-bundle.pem`.** Linux/macOS: `/etc/yuzu/certs/plugin-trust-bundle.pem`; Windows: `C:\ProgramData\Yuzu\certs\plugin-trust-bundle.pem`. **Add this path to your backup procedure** alongside the SQLite databases. A backup that captures the DBs but not the cert dir restores `plugin_signing_required=true` (in `runtime_config`) without the bundle, and require-mode agents reject every plugin until the bundle is restored. The Docker reference `docker-compose.reference.yml` mounts only `server-data`; if your cert dir is outside that volume you must add a separate bind-mount or named volume and include it in the backup script.

2. **Cert-dir filename collision check.** The server now treats `plugin-trust-bundle.pem` in the cert dir as authoritative. The filename was unused in prior releases, but if any deployment placed an unrelated PEM at that exact path for another purpose, it will be interpreted as the plugin trust bundle on first read after upgrade. Run `ls <cert-dir>/plugin-trust-bundle.pem` on every server host before upgrading and rename any pre-existing file.

3. **DO NOT enable "Require signed plugins" yet.** The Yuzu release pipeline does not currently sign the 44 in-tree plugins under `agents/plugins/`. Enabling Require with an operator-only trust bundle will reject every Yuzu-shipped plugin on next agent restart — fleet-wide outage. Use the transitional mode (bundle uploaded, Require off) until you have signed every plugin your fleet uses, including the in-tree ones. The Settings card displays this warning inline.

The new audit actions (`plugin_signing.bundle.uploaded` / `.cleared` / `.require.changed`) and metric labels on `yuzu_agent_plugin_rejected_total` (`signature_missing` / `signature_invalid` / `signature_untrusted_chain`) are documented in `audit-log.md` and `metrics.md` respectively. SIEM and alert rules already filtering on the existing `success`/`failure`/`denied` audit vocabulary pick these up unchanged — no new vocabulary tokens were introduced.

## Schema Migrations

Starting with **v0.10.0**, every server-side SQLite store is wired through a single `MigrationRunner` that tracks schema version per store and applies pending migrations in a transaction. Prior releases relied on `CREATE TABLE IF NOT EXISTS` plus silent `ALTER TABLE ADD COLUMN` statements, which made rollbacks opaque and left no audit trail of what had been applied.

How it works:

- Each store declares an ordered `std::vector<Migration>` where each entry is `{version, sql}`.
- On startup, the runner creates the `schema_meta` table if missing, reads the current version for the store, and runs any migration with a higher version number inside a `BEGIN IMMEDIATE` / `COMMIT` transaction.
- If a migration SQL statement fails, the transaction rolls back and the store stays at its previous version — the server logs `MigrationRunner: migration v<N> failed for <store>: <sqlite error>` and the corresponding store constructor logs `<Store>: schema migration failed`.
- Already-applied migrations are skipped; running the same server binary twice against the same database is a no-op.
- Multiple stores share one database connection but keep independent version counters.

**Upgrading from v0.9.x or earlier** is data-preserving: the first 0.10.x startup stamps every database at schema v1. A small set of stores (`api_token_store`, `instruction_store`, `patch_manager`, `policy_store`, `product_pack_store`, `response_store`) also runs a one-time legacy compatibility shim that re-applies the historical `ALTER TABLE` statements before stamping, so databases from very old releases that never received those columns still converge to the latest schema. These shims are kept in code for one release cycle and can be removed after v0.11.

**No manual migration steps are required.** Just replace the binary (or pull the new image and `up -d`) and start the server. Migration progress is logged at `info` level as:

```
[info] MigrationRunner: audit_store migrated to v1
[info] MigrationRunner: rbac_store migrated to v1
...
```

**Expect a log burst on first startup after upgrade.** 30+ `MigrationRunner: <store> migrated to v1` info lines appear on the first run against a pre-v0.10 database — one per store. On every subsequent restart the runner is silent at info level. If your log-shipping pipeline has per-second rate limits, widen them for the upgrade window or filter this single line pattern.

**Verifying migration state after startup**, query the per-store audit trail directly:

```bash
docker exec -i yuzu-server sqlite3 /var/lib/yuzu/audit.db \
  "SELECT store, version, datetime(upgraded_at, 'unixepoch') FROM schema_meta ORDER BY upgraded_at;"
```

Every store that has ever run through the migration runner has a row here with its current version and the wall-clock timestamp of the last stamp. This is the operator-side audit trail for schema evolution.

If a migration fails:

1. Check the log for `MigrationRunner: migration v<N> failed for <store>: <sqlite error>` and note both the store name and the SQLite error.
2. The server will have **closed the failing store's database handle**, so `/readyz` returns 503 with the failed store name in the `failed_stores` body field — the probe accurately reflects degraded state. Don't rely on `/livez` for readiness; it only checks process liveness, not schema integrity.
3. Stop the server and restore the **affected** database file from backup — not the whole data directory. Restoring all databases to fix one broken store wipes in-flight approvals, pending agents, and enrollment tokens.
4. Start the previous server version against the restored data.
5. Open an issue with the full error line, the source/target version numbers, and the output of the `schema_meta` query above.

## Upgrade notes by release

### Executions-history PR 2 — `responses.execution_id` exact correlation

PR 2 of the executions-history ladder closes a forensic-data correctness
gap (UP-8) where two concurrent executions of the same definition to
overlapping agent sets could show each other's responses in the
Instructions → Executions detail drawer. Operators upgrading to a
release that includes PR 2 should expect the following:

**Schema migration v2 on `response_store`.** The migration adds an
`execution_id TEXT NOT NULL DEFAULT ''` column to the `responses` table
plus a partial index `idx_resp_execution_ts ON responses(execution_id,
timestamp) WHERE execution_id != ''`. The migration is automatic and
data-preserving — `MigrationRunner::run` wraps the ALTER + CREATE INDEX
in a single transaction. Pre-upgrade rows are NOT deleted; they receive
the empty-string sentinel value `''`. The migration is idempotent: a
pre-stamp probe at startup detects an already-altered DB and skips the
duplicate ALTER (mirrors the precedent at `instruction_store.cpp` v2).

Observable after upgrade:

```sql
SELECT execution_id, COUNT(*) FROM responses GROUP BY execution_id;
```

will show ALL pre-upgrade rows under the empty string `''`. This is
expected — there's no way to retroactively attribute pre-upgrade
responses to executions because the dispatch path didn't record the
linkage. The Executions drawer detects empty-`execution_id` rows and
falls back to the legacy timestamp-window-plus-agent-set join so they
render correctly without operator action. **No operator action
required** for the migration itself.

**Dispatch-path coverage gap (PR 2.x follow-ups).** Only executions
dispatched via `POST /api/instructions/:id/execute` (the dashboard's
Execute Instruction form goes through this path) get exact correlation
in PR 2. Three dispatch surfaces continue to write rows with
`execution_id=''` until follow-up PRs close them:

- **MCP `execute_instruction`** — agent dispatches issued through the
  MCP protocol.
- **Workflow steps** (`POST /api/workflows/:id/execute` step dispatch
  via `cmd_dispatch` callback) — multi-step workflows.
- **Scheduled / approval-triggered dispatches** — the dispatch path
  inside `schedule_engine` / approval-fired execution.
- **Reruns** (`/api/executions/:id/rerun`) — `create_rerun` creates
  the execution row but does not dispatch; the operator-triggered
  follow-up dispatch will be wired in PR 2.x.

For runs from these surfaces, the drawer's responses section uses the
legacy timestamp-window join. Cross-execution contamination (UP-8) is
still possible if two such runs overlap on the same definition + agent
set. Track via the executions-history follow-up issues.

**Mixed-mode detail drawer behaviour.** During an upgrade transition
window (executions in flight at restart time, or in-progress executions
that started pre-upgrade and finished post-upgrade), some responses for
a single execution may carry `execution_id=''` while others are
correctly tagged. The drawer prefers exact-correlation rows when they
exist and only falls back to the legacy join when zero exact rows are
returned — this means **mixed-mode runs may show only the
post-upgrade subset of their responses** in the drawer. Pre-upgrade
responses for those runs remain in the database and are queryable via
SQL; the upcoming admin backfill CLI (PR 2.1) will stamp them with
their correct execution_id once it ships.

**Server restart caveat.** The dispatch-time `command_id → execution_id`
mapping is held in memory inside `AgentServiceImpl`. If the server is
restarted while a command is in flight, the mapping is lost and any
agent responses arriving post-restart will be tagged `execution_id=''`
and use the legacy fallback. Avoid restarting the server during active
executions where possible, or accept that the affected runs will use
legacy correlation.

**Admin backfill (planned in PR 2.1, not in this release).** A
`yuzu-server admin backfill-responses` CLI is filed as a follow-up. It
will walk the executions table cross-store and stamp pre-upgrade
responses with their best-effort execution_id (timestamp + agent set
heuristic). Until it ships, pre-upgrade rows remain queryable via the
legacy fallback in the drawer; no operator action is required.

**Verifying the migration.** After upgrade, the server log should
contain `MigrationRunner: response_store migrated to v2`. To verify the
column directly:

```bash
sqlite3 /var/lib/yuzu/responses.db ".schema responses"
# Expected: execution_id TEXT NOT NULL DEFAULT ''
sqlite3 /var/lib/yuzu/responses.db ".schema idx_resp_execution_ts"
# Expected: CREATE INDEX idx_resp_execution_ts ON responses(...) WHERE execution_id != ''
```

### v0.12.0 — AuthDB persistent authentication (#618)

v0.12.0 replaces the in-memory + on-config-flush authentication model
with a SQLite-backed `auth.db` that holds user accounts, sessions, and
enrollment tokens.

**First boot after upgrade:**

- The server probes `--data-dir` for `auth.db`. If absent, it creates
  the file with mode `0600` (Linux) or restricted ACL (Windows), runs
  the initial schema migration via `MigrationRunner`, then seeds users
  from `yuzu-server.cfg`. Subsequent boots read from `auth.db`
  directly; the config file is no longer the live source of truth.
- The seed is one-shot. Editing `yuzu-server.cfg` after first boot
  does NOT re-seed users into `auth.db` — use the dashboard or
  `POST /api/settings/users` instead.
- Existing in-flight sessions are NOT preserved across the upgrade
  (sessions live in memory before this release; `auth.db` starts fresh
  on first boot). Operators must log in again.

**`role` parameter ignored on `POST /api/settings/users`.** New users
are always created as `user` (security finding C1). To assign or
change a role, use the dedicated `POST
/api/settings/users/{username}/role` endpoint introduced in v0.12.0
(see [REST API → Settings → User Management](rest-api.md#settings--user-management)).
The dashboard exposes a **Change Role** button on each user row that
calls the new endpoint.

**Live drawer updates via SSE.** The Executions tab opens an
`EventSource` to `/sse/executions/{id}` for in-progress runs. Reverse
proxies in the request path must NOT buffer SSE — the server emits
`X-Accel-Buffering: no` and `Cache-Control: no-cache` but a poorly-
configured proxy can still chunk the stream. Verify with
`curl -N https://<server>/sse/executions/<id>` from inside your
network if the drawer freezes mid-execution.

**`LimitNOFILE=65536` on systemd units.** v0.12.0 raises the systemd
file-descriptor limit from the default 1024 to 65536. SSE
connections + agent gRPC streams + SQLite WAL handles can saturate
the default soft limit on busy fleets. The new value matches Docker
compose's `ulimits.nofile` so containerised and bare-metal deployments
behave identically.

**Restart-loop guard.** `StartLimitIntervalSec=60` +
`StartLimitBurst=3` in the systemd `[Unit]` section so a corrupt
`auth.db` failing the integrity check at startup puts the unit
cleanly into `failed` instead of spinning. Recovery procedure:
[`docs/ops-runbooks/auth-db-recovery.md`](../ops-runbooks/auth-db-recovery.md).

**Rollback to a pre-AuthDB release** (only if you have not yet
written user state via the new dashboard):

1. Stop the v0.12.0 server.
2. Move `auth.db` aside (`mv auth.db auth.db.v0.12.0`).
3. Restore `yuzu-server.cfg` from your pre-upgrade backup.
4. Reinstall the prior release binary.
5. Start the server. It reads `yuzu-server.cfg` as before.

If you HAVE written user state via v0.12.0's dashboard, that state
is in `auth.db` only — rolling back loses it. Export users via
`GET /api/v1/settings/users` first if rollback is required.

### v0.12.0 — Guardian PR 2

Guardian PR 2 ships the Guaranteed State control plane + agent skeleton. Two items require operator awareness on upgrade:

**Stale `*:Push` RBAC grants on deployments that ran pre-hardening Guardian PR 2 code.** Between commits `7c83911` and `1f39401`, the RBAC seed granted the `Push` operation to `Administrator` and `ITServiceOwner` on **every** securable type, not just `GuaranteedState`. The H-4 fix (commit `21c0ba4`, hardening round 2) restricted the seed to `GuaranteedState` only going forward — but because `seed_defaults()` uses `INSERT OR IGNORE`, the stale cross-type grants already written to `role_permissions` are not removed on upgrade. These grants are semantically inert today (only the Guardian REST handlers consult `Push`), but become a latent privilege for any future release that adds a non-Guardian handler checking `perm_fn(..., "Push")`.

Manual remediation until the auto-migration in issue #485 lands. **Run each step in order:**

1. **Back up the RBAC database first.** Destructive SQL with no rollback.

   ```bash
   docker exec yuzu-server cp /var/lib/yuzu/rbac.db /var/lib/yuzu/rbac.db.bak.$(date +%Y%m%d)
   # or for a systemd install:
   cp /var/lib/yuzu/rbac.db /var/lib/yuzu/rbac.db.bak.$(date +%Y%m%d)
   ```

2. **Preview the rows that will be deleted.** This should return only `Administrator` and `ITServiceOwner` rows on a fresh Guardian PR 2 upgrade. If it returns rows for any other principal_id, you have custom RBAC grants that the bulk `DELETE` below would silently wipe — in that case stop and prune by hand.

   ```bash
   docker exec -i yuzu-server sqlite3 /var/lib/yuzu/rbac.db \
     "SELECT principal_id, securable_type FROM role_permissions \
       WHERE operation = 'Push' AND securable_type != 'GuaranteedState' \
       ORDER BY principal_id, securable_type;"
   ```

3. **Delete the stale grants.** Scoped to the two seeded roles so custom grants are left alone:

   ```bash
   docker exec -i yuzu-server sqlite3 /var/lib/yuzu/rbac.db \
     "DELETE FROM role_permissions \
       WHERE operation = 'Push' \
         AND securable_type != 'GuaranteedState' \
         AND principal_id IN ('Administrator', 'ITServiceOwner');"
   ```

4. **Confirm cleanup:** re-run the preview query from step 2 — zero rows expected.

Safe on fresh installs (no matching rows). If you are upgrading **from** a v0.11.x release directly **to** v0.12.0 or later, skip this entire sub-section — your RBAC database never carried the stale grants.

**Retention changes take effect on restart, not on runtime PUT.** BL-2 wired `--guardian-event-retention-days` (default 30) through `RuntimeConfigStore` + `PUT /api/v1/config/guardian_event_retention_days`, matching the existing `response_retention_days` and `audit_retention_days` pattern. However, all three retention-bearing stores (`AuditStore`, `ResponseStore`, `GuaranteedStateStore`) capture their retention value at construction time and never re-read it — the runtime PUT mutates `cfg_` and `RuntimeConfigStore` but the running reaper continues using the startup value. An operator who PUTs a new retention value sees `200 {"applied": true}` but the store behaviour does not change until the next server restart. This is a systemic limitation shared across all three stores, not a Guardian-specific bug; it is tracked as issue #483.

**Runtime config PUT now rejects non-numeric and negative integer values with HTTP 400.** Hardening round 4 (UP-R5) added `std::from_chars` validation to `PUT /api/v1/config/<key>` for `heartbeat_timeout`, `response_retention_days`, `audit_retention_days`, and `guardian_event_retention_days`. The previous handler silently wrote invalid strings to `RuntimeConfigStore` and swallowed the `stoi` error, leaving `cfg_` unchanged. If your automation relied on setting retention to a **negative** value (e.g., `"-1"`) to disable retention — which the store then treated as "never reap" via the `<= 0` sentinel — that automation will now receive `400 {"error":{"code":400,"message":"value must be a non-negative integer"}}`. Use `"0"` instead; it preserves the same disable-retention semantic and passes validation. Automation that previously set non-numeric strings (anything other than a base-10 integer) was silently a no-op before this release — the 400 now surfaces the configuration error that had been hidden.

## Rollback

If an upgrade causes issues:

1. Stop the new version
2. Restore the backed-up `.db` and `.cfg` files
3. Start the previous version binary

**Important:** Rolling back after a schema migration requires restoring the database files from backup. The old binary cannot read the new schema.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Server won't start after upgrade | Schema migration failure | Check logs, restore backup, report issue |
| Agents can't connect | Protocol version mismatch | Ensure server was upgraded first |
| Dashboard shows errors | Browser cache | Clear browser cache, hard refresh |
| Gateway disconnects | Version mismatch with server | Upgrade gateway to match server version |
| Slow startup | Large database migration | Normal for first start; wait for migration to complete |
