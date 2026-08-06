# Runbook: audit-store backfill refusals and recovery

Covers boot- and one-shot-time refusals from the mandatory legacy
`audit.db` → PostgreSQL `audit_store` backfill (ADR-0040). If the server or a
one-shot (`--mfa-reset`, `--break-glass-arm`) is refusing to start/run because
of the backfill, this is the page — not the retention clock guard (that's
[audit-store-clock-guard.md](audit-store-clock-guard.md), a different
mechanism entirely: retention runs AFTER a completed backfill, not instead of
one).

Background: [Upgrading § Audit trail migrates to Postgres](../user-manual/upgrading.md),
ADR-0040.

## This host's trail was never proven migrated (holder-side verification refusal)

The `backfill_complete` marker is already set when this host boots — by a
`"sourceless"` stamp (no legacy file was ever read before it was set) or by a
DIFFERENT file's fingerprint — and this host still holds a legacy `audit.db`
at its configured path. Rather than trust a marker it cannot vouch for, this
host tries to verify that ITS file's content is what got migrated, and
refuses to serve if it cannot: the log line names which of five things
happened —

- the fingerprints did not match (`"refusing to serve — legacy ... was NEVER
  proven migrated"`),
- the file could not be opened,
- the file could not be read as a valid `audit_events` table,
- its fingerprint could not be computed, or
- the legacy path could not be stat'd at all (`"cannot stat legacy path ...
  to verify a completed backfill"`) — a permissions problem or filesystem
  error distinct from the file being genuinely absent.

All five land you here. The file is untouched at its original path in every
case — nothing has been lost, but this host refuses to serve until an
operator resolves which of two things is true:

- **This file's content already reached PostgreSQL** — a sibling replica on
  the same underlying storage streamed it and stamped the marker first. Move
  or remove this copy of `audit.db` (it is redundant) and restart; with no
  file at the configured path the ordinary "already migrated" check applies
  and boot proceeds normally.
- **This file is the only copy, and its content was never migrated** — the
  marker was set sourcelessly by a fileless peer (see
  [Upgrading's scale-out note](../user-manual/upgrading.md)) or by an
  unrelated backfill, and this host's evidence is genuinely still only here.
  Two options: engage engineering to manually stream this file's rows into
  `audit_store.audit_events` (a case-specific DBA task, not scripted here —
  the schema is in ADR-0040), or, if the trail is accepted as lost, move
  `audit.db` aside yourself and restart — the marker is already set, so
  (unlike the abandon procedure below) no SQL step is needed here; a future
  boot finds no file at the configured path and proceeds normally. Record the
  loss in change management either way — this is the same explicit
  acceptance the abandon procedure below asks for, just without its SQL
  because there is nothing left for this host to stamp.

If you cannot tell which is true from deployment history alone, treat it as
the second case — engineering can restore the file from the operator-managed
backup either way.

## Abandoning an unrecoverable legacy trail

If the legacy `audit.db` is genuinely lost or corrupt and the server is
refusing to start because PostgreSQL holds rows with no completion marker
(rows-present + marker-absent, a different refusal from the one above), you
can declare the migration finished by hand. **This is an explicit acceptance
that the pre-cutover trail is incomplete — record it in change management.**
With the server stopped:

```sql
BEGIN;
-- Both statements are required. The identity sequence MUST be advanced past the
-- backfilled ids, or the first live write collides with one and fails.
SELECT setval(pg_get_serial_sequence('audit_store.audit_events','id'),
              GREATEST((SELECT COALESCE(MAX(id),0) FROM audit_store.audit_events), 1),
              (SELECT COUNT(*) FROM audit_store.audit_events) > 0);
INSERT INTO audit_store.audit_retention_meta (key, value)
VALUES ('backfill_complete', EXTRACT(EPOCH FROM now())::bigint::text)
ON CONFLICT (key) DO NOTHING;
COMMIT;
```

(That is the same pair the server itself runs on a successful backfill —
`stamp_complete` in `server/core/src/audit_store.cpp`.) Start the server
afterwards; it will see a completed migration and serve.

**This procedure does NOT apply to the holder-side verification refusal
above** — that refusal happens with the marker ALREADY set, so the `INSERT
... ON CONFLICT (key) DO NOTHING` above is a no-op for it. See that section
for the correct recovery instead.

**Not affected:** the audit event vocabulary and REST/MCP query surface are
unchanged; SIEM export recipes keep working. One deliberate behaviour change: on
a multi-replica deployment an identical-magnitude repeat clock step no longer
re-emits `yuzu_server_audit_clock_anomaly_skips_total` on every pass (only a
distinct anomaly does) — if you alerted on that counter's *cadence*, alert on a
sustained increase instead. See
[Audit Log](../user-manual/audit-log.md#the-retention-clock-guard).
