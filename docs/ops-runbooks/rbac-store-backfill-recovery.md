# Runbook: RbacStore backfill refusals and recovery

Covers boot-time refusals from the mandatory legacy `rbac.db` → PostgreSQL
`rbac_store` backfill (ADR-0041). If the server is refusing to start because
of this backfill, this is the page.

Background: [Upgrading § RBAC store moves to PostgreSQL](../user-manual/upgrading.md),
ADR-0041, `docs/postgres-store-playbook.md` "Local source absence never
creates terminal migration state on its own" (#2697).

## Two different holder-side verification refusals

The `backfill_complete` marker is already set when this replica boots, and
this replica still holds a legacy `rbac.db` at its configured path. Rather
than trust a marker it cannot vouch for, this replica verifies that ITS
file's content is what got migrated, and refuses to serve if it cannot. The
log line tells you which of two genuinely different situations you're in —
read it before doing anything:

### "backfill_complete is already set with NO recorded source fingerprint"

This marker predates the fingerprint-verification mechanism (any migration
completed before this version). Its provenance was never recorded, so the
server genuinely cannot tell apart two different histories:

- **This replica's own migration, from before fingerprints existed.** This
  file is redundant — the data already reached PostgreSQL, under this same
  replica's own earlier boot. Move or remove it and restart; with no file
  at the configured path the ordinary "already migrated" check applies and
  boot proceeds normally.
- **A different replica's completion**, and this replica's own legacy data
  was never migrated. Do NOT move the file without first confirming which
  case you're in — moving it here would silently discard real,
  never-migrated operator config (roles, grants, groups, and possibly
  `rbac_enabled=true`).

**How to tell them apart:** check deployment history. Did this specific
replica (this host/container identity, not just "the fleet") complete a
migration before the fingerprint mechanism shipped? If you have deploy logs
or a prior "RbacStore: migrate_from_sqlite: reconciled" line from this
replica's own history, that settles it. If you cannot tell from deployment
history alone, treat it as the second case and engage engineering before
moving anything — unlike AuditStore's equivalent evidence trail, this file
holds live authorization config a fleet may currently depend on.

### "HOLDER-SIDE VERIFICATION FAILED ... a DIFFERENT recorded source fingerprint"

Unambiguous: a different replica's legacy `rbac.db` was migrated, and this
replica's own file was never part of it. This is the accepted residual of
an ordinary mixed-fleet first boot — whichever replica's stamp lands first
wins, and if that's a replica that turned out to hold different content
than this one, the loser lands here. **To make this rare rather than
routine, boot the replica holding the real, authoritative `rbac.db` FIRST**
on any fresh multi-replica rollout.

Resolve the same way as AuditStore's equivalent case: confirm which
replica's content is authoritative (usually: the one an operator actually
edited RBAC config on before cutover), move aside every OTHER replica's
`rbac.db`, and restart them — they'll find no local file and trust the
already-established marker. If this replica's OWN file is the authoritative
one and a different (wrong) replica's content already won the marker,
engage engineering: recovering the correct config back into `rbac_store`
after a wrong replica has already migrated is a case-specific DBA task, not
scripted here.

## Note: no "sourceless" refusal, and no abandon procedure

Two things AuditStore's equivalent runbook covers that RbacStore's mechanism
does not need:

- **A stored `"sourceless"` value never causes a refusal here.** No real
  migration has happened yet in that case (the same safety class as a fresh
  install), so a replica holding real content proceeds with a normal
  migration instead of refusing — it will succeed and correctly claim the
  marker. If you see an `info`-level "proceeding with a normal migration"
  log line rather than an error, that is this case; no operator action
  needed.
- **There is no "rows present, marker absent, abandon by hand" procedure.**
  RbacStore's backfill is a single, small, one-shot transaction (not
  AuditStore's resumable streaming design) — the marker is stamped only
  after that one transaction, its reconciliation, and re-deriving the
  fingerprint all succeed. If the process is interrupted between the data
  commit and the marker stamp, the next boot simply finds the marker absent
  and retries the whole migration from scratch; every insert is `ON
  CONFLICT DO NOTHING`/`DO UPDATE` against the same legacy content, so the
  retry is a clean no-op over already-migrated rows, not a duplicate or a
  stuck state. Nothing to abandon by hand.

**Not affected:** the RBAC data model, REST/MCP surface, and
`check_permission`/`authorize_list_read` behavior are unchanged by any of
this — these refusals are exclusively about whether the ONE-TIME backfill
is allowed to complete, not about ongoing authorization decisions.
