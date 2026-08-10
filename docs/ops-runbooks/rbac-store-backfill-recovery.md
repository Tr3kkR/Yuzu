# Runbook: RbacStore backfill refusals and recovery

Covers boot-time refusals from the mandatory legacy `rbac.db` → PostgreSQL
`rbac_store` backfill (ADR-0041). If the server is refusing to start because
of this backfill, this is the page.

Background: [Upgrading § RBAC store moves to PostgreSQL](../user-manual/upgrading.md),
ADR-0041, `docs/postgres-store-playbook.md` "Local source absence never
creates terminal migration state on its own" (#2697).

## Holder-side verification refusals

The `backfill_complete` marker is already set when this replica boots, and
this replica still holds a legacy `rbac.db` at its configured path. Rather
than trust a marker it cannot vouch for, this replica verifies that ITS
file's content is what got migrated, and refuses to serve if it cannot. The
log line tells you which of four situations you're in — read it before
doing anything. Stored/logged fingerprint values look like `v2:<64 hex
characters>` (the `v2:` names the encoding scheme, so a future scheme change
is diagnosable rather than an unexplained mismatch); the literal unprefixed
string `sourceless` is a distinct sentinel, not a scheme-versioned hash.

### "legacy db ... exists but is unreadable/corrupt while being fingerprint-verified"

This replica's own legacy file could not be opened or read as a valid
`rbac.db` (corrupt, truncated, or not a SQLite file at all). Fails closed —
an unreadable file is never silently treated as "nothing to protect." Fix
the file's readability (restore from backup if the corruption is genuine) or
confirm it's safe to discard, then retry.

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

### "backfill_complete is already set with a sourceless source fingerprint"

No real legacy data has been migrated for this fleet yet — a fileless
sibling merely stamped `backfill_complete` first, from a boot that found no
local `rbac.db` at all. This replica's own file holds real content, but
this refuses rather than proceeding with a normal migration, because a
fileless sibling's stamp makes `rbac_store` operational (seeded defaults
only) and this replica cannot bound what live post-cutover state has
accumulated since — in particular, a live IdP login can run
`reconcile_idp_memberships`, which deletes a stale `group_members` row that
this replica's own (older) legacy file still records; migrating that file
would silently reinsert the row `reconcile_idp_memberships` correctly
removed, restoring a role grant to a user already de-provisioned from an
IdP group.

**To make this rare rather than routine, boot the replica holding the real,
authoritative `rbac.db` FIRST** on any fresh multi-replica rollout — the
same guidance as the different-fingerprint case below, and for the same
reason: whichever replica's stamp lands first wins.

**To recover:** confirm no live RBAC-affecting activity has happened on this
fleet since the sourceless stamp — check the server/audit log for role,
grant, or group changes, and specifically for `reconcile_idp_memberships`
activity, from that time forward. If genuinely nothing has: engage
engineering to clear the `backfill_complete` and `backfill_source_fingerprint`
rows from `rbac_meta` and restart this replica, which will then find the
marker absent and complete a normal migration. If you cannot confirm the
fleet is clean, treat it like the different-fingerprint case below and
engage engineering before touching anything.

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

## Note: no "abandon by hand" procedure

One thing AuditStore's equivalent runbook covers that RbacStore's mechanism
does not need:

- **There is no "rows present, marker absent, abandon by hand" procedure.**
  RbacStore's backfill is a single boot-time pass made of a few small
  transactions (not AuditStore's resumable streaming design) — the marker is
  stamped only after the data commits, its reconciliation, and re-deriving
  the fingerprint all succeed. If the process is interrupted at any point
  before the marker stamp, the next boot simply finds the marker absent and
  retries the whole migration from scratch; every insert is `ON CONFLICT DO
  NOTHING`/`DO UPDATE` against the same legacy content, so the retry is a
  clean no-op over already-migrated rows, not a duplicate or a stuck state.
  Nothing to abandon by hand.
- **A previously-failed move-aside retries automatically.** If an earlier
  boot's migration succeeded but renaming the legacy file aside failed
  (e.g. a permissions issue), a later boot that verifies the file still
  matches (the "fingerprint verified, skipping" case) retries the move —
  you do not need to move it aside by hand once the underlying problem is
  fixed, though it's still safe to do so.

**Not affected:** the RBAC data model, REST/MCP surface, and
`check_permission`/`authorize_list_read` behavior are unchanged by any of
this — these refusals are exclusively about whether the ONE-TIME backfill
is allowed to complete, not about ongoing authorization decisions.
