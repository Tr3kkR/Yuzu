# Runbook: CustomPropertiesStore backfill refusals and recovery

Covers boot-time refusals from the mandatory legacy `custom-properties.db` →
PostgreSQL `custom_properties_store` backfill (ADR-0043). If the server is
refusing to start because of this backfill, this is the page.

Background: ADR-0043, `docs/postgres-store-playbook.md` "Local source
absence never creates terminal migration state on its own" (#2697); this
store's mechanism mirrors `RbacStore`'s recovery shape
(`rbac-store-backfill-recovery.md`) unmodified for the fingerprint machinery,
sized down for a two-table, no-revoke data model.

## Holder-side verification refusals

The `backfill_complete` marker is already set when this replica boots, and
this replica still holds a legacy `custom-properties.db` at its configured
path. Rather than trust a marker it cannot vouch for, this replica verifies
that ITS file's content is what got migrated, and refuses to serve if it
cannot. The log line tells you which situation you're in. Stored/logged
fingerprint values look like `v1:<64 hex characters>`; the literal
unprefixed string `sourceless` is a distinct sentinel, not a scheme-versioned
hash.

### "legacy db ... is unreadable/corrupt while being fingerprint-verified"

This replica's own legacy file could not be opened or read as a valid
`custom-properties.db` (corrupt, truncated, or not a SQLite file at all).
Fails closed — an unreadable file is never silently treated as "nothing to
protect." Fix the file's readability (restore from backup if the corruption
is genuine) or confirm it's safe to discard, then retry.

### "HOLDER-SIDE VERIFICATION FAILED ... a DIFFERENT recorded source fingerprint"

A different replica's `custom-properties.db` was migrated, and this
replica's own file was never part of it. **This should be rare for this
store specifically**: unlike `rbac.db`, `custom-properties.db` is ordinarily
a single server's local operator-authored asset-tagging data, not something
expected to diverge legitimately across replicas of the same logical
deployment — if you're seeing this, it usually means either (a) two
independently-seeded pre-cutover servers are being merged into one Postgres
deployment for the first time, or (b) an operator edited custom properties
on more than one replica before the cutover completed.

To make this rare rather than routine, boot the replica holding the real,
authoritative `custom-properties.db` FIRST on any fresh multi-replica
rollout — whichever replica's stamp lands first wins.

Resolve the same way as `RbacStore`'s equivalent case: confirm which
replica's content is authoritative (usually the one an operator actually
edited custom properties on before cutover), move aside every OTHER
replica's `custom-properties.db`, and restart them — they'll find no local
file and trust the already-established marker. If this replica's OWN file is
the authoritative one and a different (wrong) replica's content already won
the marker, engage engineering: recovering the correct properties/schemas
back into `custom_properties_store` after a wrong replica has already
migrated is a case-specific DBA task, not scripted here (re-applying the
correct properties via `PUT /api/agents/:id/properties/:key` /
`POST /api/property-schemas` is often simpler than a DB-level reconciliation,
since this store's data is small and operator-editable through the normal
API).

## Note: no "abandon by hand" procedure

This store's backfill is a single boot-time pass made of a few small
transactions — the marker is stamped only after the data commits. If the
process is interrupted before the marker stamp, the next boot simply finds
the marker absent and retries the whole migration from scratch; every insert
is `ON CONFLICT DO NOTHING` against the same legacy content, so the retry is
a clean no-op over already-migrated rows. Nothing to abandon by hand. A
previously-failed move-aside (legacy file still present after a verified,
already-completed migration) retries automatically on the next boot.

**Not affected:** the `props.<key>` scope-DSL surface and REST API are
unchanged by any of this — these refusals are exclusively about whether the
ONE-TIME backfill is allowed to complete, not about ongoing reads/writes.
