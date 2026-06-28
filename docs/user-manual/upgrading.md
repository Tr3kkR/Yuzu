# Upgrading Yuzu

This guide covers upgrading Yuzu components (server, agent, gateway) between versions.

## Version Compatibility

| Server Version | Min Agent Version | Min Gateway Version | Notes |
|---|---|---|---|
| 0.1.x | 0.1.0 | 0.1.0 | Initial release family |
| 0.5.x | 0.5.0 | 0.5.0 | Compiler hardening flags (`-fstack-protector-strong`, `_FORTIFY_SOURCE=2`, full RELRO), config file permission enforcement (`0600` on Unix), SRI integrity attributes on CDN scripts, configurable trigger limit (default 2000), git-derived version strings, chargen instruction definitions. |
| 0.6.x – 0.9.x | same as 0.5.x | same as 0.5.x | No on-disk format changes from 0.5.x; upgrade directly to 0.10.x. |
| 0.10.x | 0.10.0 | 0.10.0 | Server-side schema migration runner wired into every SQLite store. Upgrading from 0.9.x or earlier is data-preserving: the first 0.10.x startup stamps each database at schema v1 and runs a one-time legacy compatibility shim for stores that historically added columns via silent `ALTER TABLE` (`api_token_store`, `instruction_store`, `patch_manager`, `policy_store`, `product_pack_store`, `response_store`). Failed migrations close the affected store's DB handle and are reported via `/readyz` with the failed store name — **check `/readyz`, not `/livez`, to confirm upgrade success**. |
| 0.15.x (next) | 0.12.0 | 0.12.0 | **Fleet visualization three-tier layout + talking sockets + curved tube wires (PR 12).** `/viz/fleet` no longer renders machines on a single flat grid. Cubes now stack into three architectural tiers: frontend on the top Y plane, applications in the middle, databases on the bottom. Classification is heuristic — `classifyTier` reads listener-port hints (DB/web port sets) and process category, priority `db > web > app`. **Behavioural break for automation consumers:** if you scripted SIEM rules or dashboards that filter by "where a cube falls in the canvas", expect tier reassignments after upgrade. The wire change is *additive* — `schema_minor` bumps `3 → 4` with a new optional `local_addr` field on `ListenerSocket` carrying the kernel-reported bind address (server-side bounded at 64 bytes per field). Strict-validating consumers pinned to `schema_minor == 3` should relax their validator to `minimum: 3`. **Loopback-only listeners (`127.x`, `::1`, `[::1]`, `::ffff:127.x`) no longer appear on cube surfaces** — they're not reachable from other instances. **New talking-socket primitive:** each cube grows a ring of cool-blue dots on its BOTTOM face, one per unique outbound `(proto, dst_ip, dst_port)`; hover surfaces `talking: tcp → ip:port`. **Wire geometry changed:** cross-machine connections render as `THREE.TubeGeometry` along a `CubicBezierCurve3` with vertical end-tangents instead of 1px `THREE.Line` — wires drop straight down out of the source cube floor, run mostly-straight through space, and dock straight up into the destination's listener sphere. Screen-scrapers that parsed wire colour or geometry need updating. **Origin RGB `AxesHelper` removed** from the empty-scene scaffold — the three tier planes replace it as the orientation cue. **Default camera reframed** to `(45, 60, 45)` looking at the middle tier (was `(35, 30, 35)` looking at origin); bookmarked URLs will land on the new framing. Bundle size ~70 → ~84 KB. **Known limitation:** databases on non-standard ports (Postgres on 5431, etc.) misclassify as `app` tier unless their process is identified as `database` by the agent's process classifier. **Rolling-upgrade behaviour:** during a staged agent rollout, agents on a build older than the `tar.fleet_snapshot` action have no topology to push and appear in `/viz/fleet` as dimmed `stale` cubes until their agent is upgraded — this is expected, not a regression (previously such agents vanished from the visualization entirely once any agent pushed). **Kill-switch change:** `--viz-disable` now also `503`s the `/viz/fleet` and `/viz/host/<id>` page shells, not just the REST endpoints — an operator who sets the flag no longer sees a half-working page; it also writes a `server.viz_disabled` audit event at boot. **Governance Gate 7 hardening (no operator action required):** parser field caps on all agent-controlled strings, an IP-claim reclaim window so a crashed agent no longer strands its IPs forever, CAP-1 eviction keyed on the server clock, per-entry isolation in gateway `BatchHeartbeat` ingest, and a fix for a registration-replay storm under upstream flapping. **Scope-walking YAML `fromResultSet:` DSL (PR-E).** Policies whose `spec.scope:` used a `selector:` mapping block previously stored an empty scope (matched all devices — the selector was silently ignored). Existing rows are not migrated, but **re-creating or re-importing** such a policy after upgrade applies the selector as a real predicate and may narrow targeting — review the intended scope before re-import. Inline flow-mapping scope (`scope: {fromResultSet: x}`) is now rejected; use the block form. Result-set aliases referenced from `fromResultSet:` must be drawn from the `[A-Za-z0-9_.:*-]` charset (no spaces/quotes). **Inventory freshness gauge now server-clock-stamped (#1685).** `yuzu_inventory_stale_agents` keys on the server's receipt time, not the agent-supplied `collected_at`. A one-time migration (v3) at first 0.15.x startup clamps any `inventory_state` row whose `last_seen`/`first_seen` was stamped from a future-skewed agent clock back down to now. **Operator-visible:** if any agents had future-skewed clocks, the gauge may show a one-time *increase* post-upgrade as previously-hidden endpoints re-enter the staleness window with a fresh ~48h grace — genuinely active agents fall back out within two daily sync cycles; this is the intended security correction, not an incident. No operator action required (the `YuzuInventoryStaleAgents` alert ships disabled). **Rollback note:** downgrading the server below 0.15.x after v3 has run is data-safe (schema unchanged) but new inventory syncs revert to stamping `last_seen` from agent time, silently re-opening the clock-skew gap for those rows. **DEX application performance over time (opt-in).** New per-app, per-version CPU/working-set trend views (DEX → Performance → "Application performance over time"; REST `/api/v1/dex/perf/{apps,app,group}` + the `list_dex_perf_apps`/`get_dex_app_perf`/`get_dex_group_app_perf` MCP tools; per-device drill `GET /api/v1/dex/devices/{id}/app-perf`). **No action is required to upgrade, but the views are EMPTY until you opt in:** per-application sampling ships **off by default** (`procperf_enabled=false`) because it is usage-class telemetry (works-council-relevant). Enable `procperf_enabled=true` on the target devices via `tar.configure` (and leave the daily-sync master switch `--inventory-disable` unset). Data appears **after the first completed UTC midnight** on each opted-in device (the agent ships a daily summary, not immediately), and the trends lengthen as days accumulate (fleet ≤180 days, group ≤31 days). A freshly-enrolled or non-opted-in device shows an honest empty state ("no application performance history yet"), not a bug. The per-device drill is also reachable from a dashboard panel on the `/device` DEX lens ("Application performance over time" — same retained data, no live query, no `Execute` permission; no upgrade action needed). The per-device drill is behavioural PII — scoped + audited (`dex.device.app_perf.view`, fail-closed); the fleet and group aggregates suppress any app/version on fewer than 10 devices to a count only (no singling-out). |
| 0.14.x | 0.12.0 | 0.12.0 | **Fleet visualization intra-cube edges (PR 8).** `/viz/fleet` now draws faint white lines (opacity `0.3`) inside each machine cube connecting process dots that are reciprocal ends of a loopback TCP socket (127.0.0.1 / ::1). Two operator-visible changes: (a) **wire shape** — `/api/v1/viz/fleet/topology` `schema_minor` bumps `1 → 2` and a new optional `dst_pid` field appears on `scope: local` connection edges. Renderers that ignore unknown keys per the contract see no break; strict-validating consumers pinned to `schema_minor == 1` should relax their validator to `minimum: 1`. (b) **dropped unmatched halves** — unpaired Local-scope edges (kernel snapshot race during teardown, agent's 4096-connection cap cutting a partner) are now dropped server-side before serialisation. Integrations counting `connections` array length per machine as a proxy for active IPC pairs should re-baseline after upgrade; the count trends marginally lower. Lines appear only when the host has active loopback flows (e.g. Prometheus scraping node_exporter, a client talking to local Redis / Postgres); a fresh agent with no inter-process loopback shows process dots but no lines — expected, not a regression. |
| 0.13.x | 0.12.0 | 0.12.0 | **Fleet visualization process layer.** `/viz/fleet` now renders interior process dots inside each machine cube, coloured by category (system/browser/database/web/runtime/other) — no operator action required, but operators upgrading from a 0.12.x build will see the dashboard suddenly populated with thousands of small spheres on next page load. Process data was already collected via `tar.fleet_snapshot` since 0.12.x; PR 7 only renders it. To suppress process visibility for specific agents (privacy-sensitive hosts, regulated workloads), set `process_enabled=false` on those agents via `tar.configure` — this also suppresses their dots on the visualization. Hover a dot to see pid/name/user/category; agent-controlled string fields are HTML-escaped and length-clamped before render. Per-cube dot count is soft-capped at 1000 for graceful degradation on heavily-threaded hosts; the cube tooltip still shows the true reported count. |
| 0.12.x | 0.12.0 | 0.12.0 | **Build-time content auto-import.** All YAML files in `content/definitions/` (217 InstructionDefinitions) and `content/packs/` (10 InstructionSets at this version) are now embedded in the server binary and auto-imported on every startup. Existing operator-customised definitions with matching IDs are NEVER overwritten — conflicts are silently skipped. **Behaviour change for upgrades:** definitions that an operator previously DELETED via the REST API or dashboard will reappear after upgrade because the auto-import treats a missing row as "needs creation". To permanently suppress a shipped definition, set `enabled: false` via the dashboard or `PATCH /api/v1/definitions/{id}` rather than DELETE-ing the row. Each auto-import write emits an `audit_events.action="content.bundled_import"` row with `principal=system` so operators can audit which definitions were inserted at boot. **Yuzu dark navy palette + Inter webfont** (visual change every operator sees) and **Apache ECharts chart renderer** (replaces bespoke SVG; same payload contract — no operator migration required) ship in the same release. |

**Rule of thumb:** agents and gateway should be the same minor version as the server, or one minor version behind. The server is always upgraded first.

## ⚠️ Breaking: account lockout is ON by default

This release adds account lockout for failed **local-password** logins (SOC 2
CC6.3) and it is **active by default** (`--auth-lockout-threshold=5`,
`--auth-lockout-window-secs=900`) **on any deployment that runs with a
persistent auth database** — i.e. one started with `--data-dir`.

> **⚠️ `--data-dir` is required.** Lockout state lives in the persistent
> `auth.db`, which only exists when the server is started with `--data-dir`.
> The shipped **container images and compose files** pass `--data-dir
> /var/lib/yuzu`, so lockout genuinely is on by default there. The
> **systemd/.deb** unit now also passes `--data-dir /var/lib/yuzu` (added in
> this release) — but if you run a **custom invocation** without `--data-dir`,
> the server falls back to in-memory auth and lockout (and session persistence)
> is silently **off**. The server logs a loud startup `WARN` in that state.
> Set `--data-dir` to make the control active.

No further config change is required to opt in — a deployment that already runs
with `--data-dir` gains the behavior the instant you start the new build.

What changes on upgrade:

- After **5 consecutive failed `POST /login` attempts** a local-password account
  is locked for **15 minutes**. While locked, every login attempt — *including
  one with the correct password* — returns the **same generic 401 as a bad
  password** (no `Retry-After`, no "you are locked" message; this is deliberate,
  to avoid a username-enumeration / lock-state oracle).
- The lock **auto-expires** after the window — it is never permanent — and a
  user who waits it out regains a full attempt budget.
- Scope is **local-password only**. SSO/OIDC logins (throttled by your IdP) and
  API/automation tokens are **unaffected** — no automation breakage.

**Highest-risk targets** on upgrade: shared or service accounts that log in with
a password, and any password-rotation / monitoring automation that may submit a
stale password in a loop — these can now lock themselves out where previously
nothing happened.

**Before upgrading, do ONE of:**

1. Accept the default (recommended for most) — it closes a real
   credential-stuffing surface. Make sure operators know the recovery path
   below.
2. Raise the threshold if you also rate-limit at the network layer
   (NIST 800-63B §5.2.2 suggests ≥10): `--auth-lockout-threshold=10`.
3. Disable it (not recommended; constitutes a deviation from the CC6.3 hardened
   baseline): `--auth-lockout-threshold=0` (the server logs a startup `WARN`).

**Recovery if an account is locked out:**

- Another admin can clear it immediately:
  `POST /api/v1/users/{username}/unlock` (`UserManagement:Write`, MFA step-up).
- Or wait out the window (default 15 min).
- **Single-admin deployments:** there is no self-service unlock for the *only*
  admin (the unlock endpoint requires a second privileged principal), so either
  wait out the window or use the offline recovery procedure in
  `docs/ops-runbooks/auth-db-recovery.md` § Account lockout recovery.
## Behaviour change: operator/API tags now beat agent self-report (#1411)

An agent's self-reported tags (`scopable_tags`, synced on every Register) can no
longer overwrite an operator- or API-set tag for the same `(agent_id, key)` — the
operator/API value is now authoritative. This closes a path where a rogue or
misconfigured agent could self-assign into an operator-declared benchmark cohort.

**Who this affects:** only an operator who *deliberately* relied on agent-reported
values winning over an operator/API-set tag for the same key. After upgrade those
agent values stop overriding — silently (no error, no log line); an affected device
simply drops out of the cohort the operator-set value defines.

**Verify:** audit the `source` column — `GET /api/v1/tags?agent_id=<id>` shows whether
each key is `server`- (operator/API) or `agent`-sourced.

**Remediate:** if an agent-reported value was the *intended* one, re-set it explicitly
via the REST API or MCP `set_tag` (which writes `source=server`, authoritative). Keys
the agent reports that the operator never set are unaffected.

## Behaviour change: MCP approval-gated calls now return -32004, not -32006 (#1470)

Supervised-tier MCP tokens that attempt an approval-gated operation now receive
JSON-RPC error code `-32004` (`TierDenied`) instead of `-32006` (`ApprovalRequired`).
The A4 contract reserves `-32006` for a response that carries a pollable `approval_id`
+ `status_url`; because approval re-dispatch (Phase 2) is not yet implemented,
returning `-32006` would violate that contract. The operation is still denied and
audited; the `error.data.remediation` field points to the REST API / dashboard
approval workflow.

**Who this affects:** any MCP client that explicitly matched on `-32006` to detect an
approval-required state. After upgrade those handlers receive `-32004` instead; update
the match to `-32004` and leave `-32006` reserved for the future Phase 2 envelope (see
`docs/user-manual/mcp.md` → "-32004: Tier denied (including approval-gated operations)").
`operator`-tier executions are auto-approved and are unaffected.

## ⚠️ Breaking: `--mfa-enforcement` now enforces

Releases before this one accepted `--mfa-enforcement=admin-only` and
`--mfa-enforcement=required` but treated them as **no-ops** (the parser
accepted the value for forward-compat and the server emitted a startup
`WARN`). **This release makes them enforce.** If you staged the flag based
on that prior documentation, enforcement goes live the instant you start
the new build.

What changes on upgrade if the flag is set to `admin-only` or `required`:

- An **un-enrolled** user covered by the mode can no longer log in directly.
  `POST /login` returns a 202 `mfa_enrollment_required` challenge and the
  user must complete TOTP enrollment (scan QR → enter first code at
  `POST /login/mfa/enroll`) before a session is minted. This is a no-lockout
  bootstrap, **but** it requires the user to enroll at their next login.
- The startup log line for non-default modes changes from `WARN` (no-op) to
  `INFO` (enforcement active).
- An operator can no longer disable their own MFA while the mode protects
  their role.

**Before upgrading with the flag set, do ONE of:**

1. **Recommended:** leave the flag at `optional`, upgrade, have all affected
   users enroll (Settings → Multi-Factor Authentication), *then* set
   `admin-only`/`required` and restart. or
2. Upgrade with the flag set and accept that affected un-enrolled users will
   be walked through enrollment on their next login.

**SSO / OIDC pre-flight (required reading if you use SSO):** under
`required` (and `admin-only` for admin SSO users), OIDC sessions are
MFA-gated by the IdP's `amr` claim — an SSO login the IdP did **not** MFA
is blocked from high-risk endpoints (it must re-authenticate via SSO),
symmetric with a local user being forced to enrol. Yuzu cannot mint a
second factor for an external identity, so **before enabling
`required`/`admin-only` with SSO you MUST verify your IdP asserts an `amr`
claim containing a recognized MFA method** (Entra: `mfa`; others:
`otp`/`hwk`/etc., RFC 8176). If it does not, affected SSO users will be
unable to reach high-risk endpoints — recoverable by restarting in
`optional` (see `docs/ops-runbooks/auth-db-recovery.md`). Under `optional`,
no IdP `amr` configuration is required (SSO sessions pass the gate).

**Single-admin deployments:** do not first-boot a fresh single-admin
deployment straight into `required`. Enroll the admin under `optional` first,
then switch. If you do start with `required`, the admin must complete
login-time enrollment within `--mfa-login-pending-secs` (default 120s); if
the token expires, restart with `optional`, log in, enroll, then re-enable.

**Recovery if you get locked out** (IdP doesn't assert `amr`, or the sole
admin can't enroll): restart the server with `--mfa-enforcement=optional`
(this re-seeds the in-memory config), log in, resolve enrollment, then
re-enable. See `docs/ops-runbooks/auth-db-recovery.md`.

## ⚠️ Breaking: server generates default TLS certificates on first boot (v0.13.0)

Before v0.13.0 the server **refused to start** without operator-provided certs
(or `--no-tls`/`--no-https`). From v0.13.0, when a TLS surface has no certs the
server **auto-generates a per-install ECDSA CA + leaf certs** on first boot and
serves encrypted with no operator action.

Impact by prior configuration:

| Prior startup flags | After upgrade |
|---|---|
| `--cert`/`--key` (+ `--https-cert`/`--https-key`) supplied | No change — operator certs always win; defaults are never generated for a supplied surface. |
| `--no-tls --no-https` (plaintext dev) | No change — both surfaces disabled; no certs generated. |
| `--no-tls` only (HTTPS previously errored without certs) | **HTTPS now serves an auto-generated default cert** instead of failing. The agent surface stays plaintext. |
| No cert flags (previously refused to start) | **Now starts, encrypted, on default certs**, with a loud banner. |

What to expect / do:

- **Browsers show an untrusted-issuer warning** for the dashboard until you trust
  the per-install CA (`<ca-dir>/default-ca.pem`, default `/etc/yuzu/certs`) or
  replace the cert with `--https-cert`/`--https-key`. The connection is encrypted;
  only issuer verification is missing.
- **Agents:** while on default certs the agent listener is encrypted but does
  **not require** client certs (per-agent mTLS arrives in a later release).
  Agents that previously connected over plaintext must switch to TLS — point them
  at the CA with `--ca-cert <ca-dir>/default-ca.pem`.
- **To keep the legacy refuse-to-start behaviour**, pass `--no-default-certs`.
- **Back up `<ca-dir>/default-ca.key` (0600) and the new `ca.db`** in `--data-dir`
  — losing the CA key forces a full fleet re-enrollment.
- Relocate the cert directory with `--ca-dir` (e.g. a dedicated container volume).

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
  - The **PostgreSQL database**, once your deployment carries one (ADR-0006 — bundled in the composes; provisioned natively by `install-server-postgres.sh`) — use `pg_dump --format=custom`; see [Server Administration § PostgreSQL Substrate](server-admin.md#postgresql-substrate) for the full backup/restore procedure and the ADR-0010 restore-pairing invariant (DB and `KeyProvider` keys-dir backups restore **together**)
- [ ] Check the [CHANGELOG](../../CHANGELOG.md) for breaking changes
- [ ] Verify disk space (at least 500 MB free for migration)
- [ ] Note current version: `yuzu-server --version` / `yuzu-agent --version`
- [ ] Plan a maintenance window (upgrades take < 5 minutes per component)
- [ ] **Review new opt-in telemetry:** this release adds DEX per-application
  performance sampling (`procperf`), a new usage-class data category. It is
  **off by default** (no action needed to keep it off) — but if you intend to
  enable it for an EU workforce, treat it as a works-council co-determination
  trigger. See the *DEX per-application sampling* upgrade note in
  [Server Administration](server-admin.md#upgrade-notes).
- [ ] **New network telemetry on Windows:** this release makes **Windows** agents
  emit device-aggregate network facts (throughput + interval retransmit rate) on
  the heartbeat, automatically on agent upgrade — gated by the existing
  `--dex-disable` / `YUZU_AGENT_DEX_DISABLE` flag (no separate opt-in). These
  carry no per-user or per-application identity (lighter than `procperf`), but the
  project treats the *capability to observe* as the works-council co-determination
  trigger, so EU deployments should note the new Windows coverage as they did for
  the DEX signals. See [Network Quality](network.md) → Collection & privacy.
- [ ] **New daily installed-software sync (ADR-0016):** on agent upgrade, agents
  begin syncing their **machine-wide installed-software** inventory to the server
  once per ~24 h over the existing gRPC channel (hash-skip keeps unchanged hosts
  to a tiny hash, not the full list). Three operator-visible effects: (a) new daily
  outbound `ReportInventory` traffic per agent — adjust egress baselines/firewall
  expectations; (b) the data lands in a **new Postgres schema**
  (`software_inventory_store`, auto-migrated at boot, fail-closed); (c) it requires
  the `installed_apps` plugin to be loaded — a build with `-Dbuild_examples=false`
  (or a plugin dir missing it) collects **nothing**, silently (agent logs only at
  debug). Machine-scope only, no end-user PII (no username collection) — but the
  data is device-attributable, and on **personally-assigned devices** installed-
  software enumeration may be **works-council co-determination-relevant** (see the
  works-council note in [Installed-Software Inventory](inventory.md)). To suppress
  collection entirely, pass **`--inventory-disable`** / set
  `YUZU_AGENT_INVENTORY_DISABLE` on the agent (deploy-time opt-out). Reads are
  gated on the new `Inventory:Read` RBAC securable; today the data is queryable via
  direct SQL (see [Installed-Software Inventory](inventory.md)). On a **non-English
  fleet**, upgrading across #1662 changes stored names: app/publisher names that
  earlier builds mangled to `?` (cp1252) are rewritten to correct UTF-8 on each
  agent's next daily sync, so any query automation that matched the corrupted `?`
  strings will return nothing afterward — see the non-ASCII troubleshooting note in
  [Installed-Software Inventory](inventory.md) for the force-resync path.
- **Non-English fleets — additional plugins (#1682).** The same `Reg*A` → `Reg*W`
  encoding fix was extended to four more Windows plugins: `vuln_scan` (app
  DisplayName/Publisher/Version in vulnerability findings), `os_info` (OS
  ProductName / edition), `sccm` (client version), and `windows_updates` (the WSUS
  `WUServer` URL). Unlike `installed_apps`, these produce **transient** response
  data — no stored names are rewritten; each call simply delivers correct UTF-8
  immediately after the agent upgrade. Any operator automation that matched
  previously-mangled non-ASCII strings in those plugins' responses (e.g. a vuln
  finding filtered on `title == "Caf?"`) will need updating.

## Upgrading the Server

### Linux (systemd)

```bash
# 1. Stop the server
sudo systemctl stop yuzu-server

# 2. Back up data
sudo cp /var/lib/yuzu/*.db /var/lib/yuzu/backup/
sudo cp /etc/yuzu/*.cfg /var/lib/yuzu/backup/
# ... and the Postgres database, if provisioned. The DSN lives only in the
# root-only env file (NOT in interactive shells) — load it, and keep the
# password off the argv via PGPASSWORD. Full recipe + restore procedure:
# server-admin.md § PostgreSQL Substrate.
sudo sh -c '. /etc/yuzu/yuzu-server.env
  export PGPASSWORD="$(printf "%s\n" "$YUZU_POSTGRES_DSN" | sed -E "s!^[a-z]+://[^:/@]*:([^@]*)@.*\$!\1!")"
  pg_dump --format=custom --file=/var/lib/yuzu/backup/yuzu-pg.dump \
    "$(printf "%s\n" "$YUZU_POSTGRES_DSN" | sed -E "s!^([a-z]+://[^:/@]*):[^@]*@!\1@!")"'

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

# PostgreSQL state (the postgres-data volume) — pg_dump is consistent
# against a LIVE database, no stop required:
docker exec yuzu-postgres pg_dump -U postgres --format=custom yuzu \
  > "yuzu-pg-$(date +%F).dump"
```

> **Note:** this recipe is a cold-ish backup — SQLite is running in WAL mode and a filesystem-level `tar` of a live database may capture a torn snapshot. For strong consistency, `docker compose -f docker-compose.reference.yml stop server` before backup (seconds of downtime) and `start` after. A fully hot backup via SQLite's online-backup API is tracked in the roadmap. The `pg_dump` half has no such caveat — logical dumps are transactionally consistent by construction. **Never** back up Postgres by `tar`-ing the `postgres-data` volume while the database is running; a torn copy of `pg_wal/` is unrecoverable, which is why the procedure above dumps through the database instead.

> **Restore-pairing (ADR-0010 — forward reference):** once envelope-encrypted secrets land, the Postgres dump contains ciphertext + wrapped DEKs only and is unusable without the matching `KeyProvider` keys directory. Back up and restore the two **as a pair** — full procedure in [Server Administration § PostgreSQL Substrate](server-admin.md#postgresql-substrate), key-management runbook tracked in #1341.

**Rollback if a migration fails** (Docker):

```bash
# 1. Stop the new server (KEEPING the named volume — do NOT use -v)
docker compose -f docker-compose.reference.yml down server

# 2. Restore the previous backup over the existing volume
docker run --rm -v server-data:/data -v "$PWD":/backup alpine \
  sh -c 'rm -rf /data/* && tar xzf /backup/yuzu-data-YYYY-MM-DD.tar.gz -C /data'

# 2b. Restore the Postgres dump (postgres container still running)
docker exec -i yuzu-postgres pg_restore --clean --if-exists --no-owner \
  --role=yuzu -U postgres --dbname=yuzu < "yuzu-pg-YYYY-MM-DD.dump"

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

> **Breaking (#659):** the gateway refuses to start without a non-default Erlang
> distribution cookie. `.deb`/`.rpm` installs auto-generate `/etc/yuzu/gateway.env`;
> for tarball/manual installs create it once (see "Gateway distribution cookie now
> required" under *Upgrade notes by release* below) before the restart step.

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

### Gateway distribution cookie now required (#659) — **BREAKING**

The Erlang gateway shipped a hardcoded default distribution cookie
(`yuzu_gw_secret_change_me`). The cookie is the sole authentication for
inter-node RPC, so a publicly-known value is unauthenticated remote code
execution for anyone who can reach EPMD (TCP 4369). The gateway now **refuses to
boot** with the default (or an empty/unsubstituted) cookie unless explicitly
overridden.

**Before upgrading:**

- **`.deb` / `.rpm` installs** auto-generate a unique cookie into
  `/etc/yuzu/gateway.env` (mode `0640`, `root:yuzu-gw`) on first install and
  never clobber it on upgrade — no action needed for a single node.
- **Tarball / manual systemd installs** must create the env file once:
  ```bash
  sudo install -d -m 0755 /etc/yuzu
  printf 'YUZU_GW_COOKIE=%s\n' "$(openssl rand -hex 32)" | sudo tee /etc/yuzu/gateway.env >/dev/null
  sudo chown root:yuzu-gw /etc/yuzu/gateway.env && sudo chmod 0640 /etc/yuzu/gateway.env
  ```
  The systemd unit loads it via `EnvironmentFile=-/etc/yuzu/gateway.env`.
- **Docker / Compose** deployments must set `YUZU_GW_COOKIE` in the gateway
  service environment (e.g. `export YUZU_GW_COOKIE=$(openssl rand -hex 32)` then
  reference it). Dev/CI may instead set `YUZU_GW_ALLOW_DEFAULT_COOKIE=1`.
- **Multi-node clusters:** every node must share the **same** cookie — set an
  identical `YUZU_GW_COOKIE` (or write the same `/etc/yuzu/gateway.env`) on all
  nodes; the per-host auto-generated value will NOT match across hosts.

**Recovery — gateway won't start after upgrade:**

| Symptom | Diagnose | Fix |
|---|---|---|
| `systemctl status yuzu-gateway` shows `start-limit-hit` / `failed` | `journalctl -t yuzu-gateway \| grep -i cookie` shows "insecure distribution cookie" (for manual/`foreground` or container runs, check stdout / `gateway.log` instead) | Create `/etc/yuzu/gateway.env` with `YUZU_GW_COOKIE=$(openssl rand -hex 32)` (see above), then `systemctl reset-failed yuzu-gateway && systemctl start yuzu-gateway`. **Do not** use `YUZU_GW_ALLOW_DEFAULT_COOKIE=1` in production. |

> The generated `/etc/yuzu/gateway.env` is intentionally **preserved across
> `apt purge` / `rpm -e`** (the `/etc/yuzu` directory may be shared with other
> Yuzu packages). To remove the cookie after uninstall: `sudo shred -u /etc/yuzu/gateway.env`.

> **Never set `YUZU_GW_ALLOW_DEFAULT_COOKIE=1` in production** — it disables the
> guard and restores the unauthenticated-RPC surface. It exists only for
> ephemeral dev/CI stacks.

### InstructionDefinition import signature enforcement now on-by-default (#1073 / W7.4 sibling-gap) — **BREAKING**

`InstructionStore::import_definition_json` (the storage path behind
`POST /api/instructions/import`) previously accepted unsigned JSON
envelopes without verification. After upgrade, unsigned imports are
rejected with:

```
instruction-import is unsigned and signature enforcement is enabled (set --allow-unsigned-definitions / YUZU_ALLOW_UNSIGNED_DEFINITIONS=1 to bypass)
```

This is intentional and closes the sibling-gap to #802. Without the
gate, any operator with `InstructionDefinition:Write` permission can
import a definition that dispatches an arbitrary plugin invocation on
every targeted agent — same fleet-RCE blast radius the pack-signing
default closed.

**Two migration paths, in order of preference:**

1. **Sign your imports.** Generate an Ed25519 keypair, sign the
   `yaml_source` field's bytes with the private key, and wrap the
   envelope with `signature: <hex>` + `publicKey: <hex>` top-level
   fields. The wire format mirrors ProductPack: signature is hex-
   encoded over the verbatim `yaml_source` bytes; `publicKey` is the
   hex-encoded raw Ed25519 public key (32 bytes / 64 hex chars).
   Until the dedicated helper script lands (tracked as a follow-up
   issue covering both pack-signing and definition-signing tooling),
   use the raw `openssl` recipe directly:

   ```bash
   # One-time: generate a keypair (rotate periodically per your policy).
   openssl genpkey -algorithm Ed25519 -out yuzu-signing.pem
   openssl pkey -in yuzu-signing.pem -pubout -outform DER \
       | tail -c 32 | xxd -p -c 64    # → 64-hex publicKey

   # Per definition: sign yaml_source bytes, hex-encode the output.
   echo -n "$YAML_SOURCE" \
       | openssl pkeyutl -sign -inkey yuzu-signing.pem -rawin \
       | xxd -p -c 128                # → 128-hex signature
   ```

   Inject `signature` and `publicKey` as top-level string fields in
   the JSON envelope POSTed to `/api/instructions/import`. See the
   REST API reference (`docs/user-manual/rest-api.md` →
   `POST /api/instructions/import`) for the full signing-rules table
   and per-rejection error strings.

2. **Opt out temporarily** (legacy environments only). Pass
   `--allow-unsigned-definitions` to `yuzu-server` or set
   `YUZU_ALLOW_UNSIGNED_DEFINITIONS=1` in the service environment. The
   server emits an `InstructionStore: signature enforcement DISABLED
   by configuration` warning on every start AND a
   `server.unsigned_definitions_allowed` audit row at boot, so the
   relaxed posture is recoverable from both operator logs and the
   audit store. **Remove the flag** as soon as the signing migration
   completes.

**Pre-existing imported definitions are unaffected.** The gate fires
only on the public import path. The bundled-content boot seed (the
`kBundledDefinitions` baked into `yuzu-server` at build time) routes
through an internal `import_definition_json_trusted` variant that
bypasses the gate; its authenticity comes from binary linkage, not
runtime signature.

**Authoring surfaces are NOT gated.** `POST /api/instructions`,
`POST /api/instructions/yaml`, and `PUT /api/instructions/{id}` — the
dashboard and CLI surfaces where operators author definitions in-
session — continue to trust `InstructionDefinition:Write` as the
author trust boundary (the operator IS the source; there is no
supply chain to authenticate). The `--allow-unsigned-definitions`
flag does NOT affect those surfaces; they have always accepted
unsigned author-time input and continue to. The architectural
question of whether authoring surfaces should ALSO require signed
envelopes is tracked as a follow-up issue with operator-decision-
required framing (UX trade-off: gating authoring would break in-
browser definition authoring).

**Audit-trail evidence chain.** Every rejection emits an
`instruction.import / denied` audit row with the store error string
in `detail` (stable SIEM-keyable tokens listed in the
`audit-log.md` reference). If the audit-store write itself fails
(locked DB, disk full), the response carries `Sec-Audit-Failed: true`
header AND `audit_emitted: false` in the JSON body, surfacing the
SOC 2 CC7.2 evidence gap to the operator immediately rather than
silently dropping the event.

### Product pack signature enforcement now on-by-default (#802 / W7.4) — **BREAKING**

The `ProductPackStore` previously shipped with signature enforcement
**disabled** by default and the setter to enable it was never wired to
any operator-facing flag — the protection was effectively unreachable.
After upgrade, calls to install a `ProductPack` without a `signature:`
field are rejected with:

```
pack '<name>' is unsigned and signature enforcement is enabled (set --allow-unsigned-packs / YUZU_ALLOW_UNSIGNED_PACKS=1 to bypass)
```

This is intentional. Unsigned packs are a fleet-wide arbitrary-code-
execution surface: any operator with `Pack:Install` permission, or a
MITM on pack delivery, could install a pack containing
`InstructionDefinition` or plugin payloads that would then execute on
every enrolled agent.

**Two migration paths, in order of preference:**

1. **Sign your packs.** Generate an Ed25519 keypair, sign each pack's
   non-metadata YAML content with the private key, and add
   `signature: <hex>` + `publicKey: <hex>` fields to each pack's
   `ProductPack` metadata document. The existing verify path
   (`ProductPackStore::verify_signature`) accepts the result. Pack
   install then succeeds and the `verified` column in the store is set
   to true so a future "show only verified packs" query has the data
   it needs.

2. **Opt out temporarily** (legacy environments only). Pass
   `--allow-unsigned-packs` to `yuzu-server` or set
   `YUZU_ALLOW_UNSIGNED_PACKS=1` in the service environment. The
   server emits a `[SECURITY] product pack signature enforcement
   DISABLED by configuration` warning on every start and writes a
   `server.unsigned_packs_allowed` audit row, so the relaxed posture
   is recoverable from both operator logs and the audit store.
   **Remove the flag** as soon as the pack-signing migration completes;
   it is not intended as a permanent configuration.

**Pre-existing installed packs are unaffected.** The check fires only
on the install path (`POST /api/product-packs`). List, get, and
uninstall paths do not re-verify, so already-installed unsigned packs
remain queryable and uninstallable after upgrade.

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

### v0.12.0 — A3 UX ladder (#620, #622, #624)

Three operator-visible behaviour changes ship in the v0.12.0 A3 ladder. None require code changes on the operator side, but two of them require **action if you maintain a local compose override**:

**1. Container healthchecks now pass (#622).** The shipped `docker-compose.uat.yml` healthcheck blocks were updated to use tools available in each runtime image (`bash` + `/dev/tcp` for the server; busybox `wget --spider` for the gateway). After upgrade, `docker compose ps` reports `(healthy)` instead of `(unhealthy)`.

> **If you maintain a local copy of the compose file** (e.g. `docker-compose.local.yml` or a pinned vendored copy), your override still uses the broken pre-fix healthcheck pattern and will continue showing `(unhealthy)` until you sync the change. Replace your server-service healthcheck stanza with:
>
> ```yaml
>     healthcheck:
>       test:
>         - "CMD"
>         - "bash"
>         - "-c"
>         - "exec 3<>/dev/tcp/localhost/8080 && printf 'GET /livez HTTP/1.0\\r\\nHost: localhost\\r\\n\\r\\n' >&3 && grep -q '200 OK' <&3 ; rc=$? ; exec 3>&- ; exit $rc"
> ```
>
> And the gateway-service healthcheck stanza with:
>
> ```yaml
>     healthcheck:
>       test: ["CMD", "wget", "--spider", "-q", "http://localhost:8081/healthz"]
> ```

**2. `/api/health` is restored as an alias of `/health` (#620).** The pre-#401 endpoint path is back. Monitoring integrations that point at `/api/health` work without reconfiguration; both URLs serve identical JSON. Both are exempt from rate limiting (a follow-up hardening over the bare `/health` behaviour). For load-balancer probes that should drain in-flight traffic before stopping, continue using `/readyz` — `/health` and `/api/health` are intentionally not draining-aware (Kubernetes pattern: liveness/health probes are not draining-aware).

**3. File-logger boot messages are now quieter (#624).** The previous `WARN: Could not create log directory /var/log/yuzu` + `ERROR: file logger setup failed` pair on every container boot is replaced by a single INFO-level line when the default path cannot be created. The Docker server image now pre-creates `/var/log/yuzu` (mode 0750, owned by `yuzu`) so the path is writable out of the box. **If your monitoring previously alerted on the WARN/ERROR lines as a misconfig signal, those signals will no longer fire** — the failure mode is now a single INFO line. Operators who require explicit on-disk logs should pass `--log-file <path>`; explicit-path failures still log at ERROR and are not silently degraded.

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
