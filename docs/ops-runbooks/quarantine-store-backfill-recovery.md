# Runbook: QuarantineStore backfill refusals and recovery

Covers boot-time refusals from the mandatory legacy `quarantine.db` →
PostgreSQL `quarantine_store` backfill (ADR-0047). If the server is refusing
to start because of this backfill, this is the page. Background: ADR-0047,
`docs/postgres-store-playbook.md`; the fingerprint machinery mirrors
`RbacStore`'s recovery shape (`rbac-store-backfill-recovery.md`) and
`CustomPropertiesStore`'s (`custom-properties-store-backfill-recovery.md`),
sized for a single-table, unbounded-retention security-containment record
instead of operator-editable asset-tagging data.

## Data-integrity refusals (before any row reaches Postgres)

These all name the offending file, row, or count in the log line — the fix
is always to repair or replace the named legacy content, then restart. None
of these require engineering escalation on their own.

- **`legacy db ... exists but is 0 bytes`** — SQLite treats a 0-byte file as
  a valid empty database, indistinguishable from "never used" without an
  explicit check; a genuine fresh install has no file at this path at all.
  Either delete the empty file (if the store was created but never used) or
  restore the real file from backup (if it was truncated).
- **`legacy db ... is unreadable/corrupt`** — the file could not be opened as
  a valid SQLite database at all. Restore from backup, or confirm it is safe
  to discard.
- **`legacy db ... could not be probed for a quarantine_records table`** — the
  file opened, but the schema probe itself failed (distinct from the file
  genuinely having no such table, which is the normal "nothing to migrate"
  case and proceeds without refusing). Restore from backup.
- **`legacy read failed`** — the file opened and has the table, but a row
  read failed mid-scan. Restore from backup.
- **`holds N quarantine records, exceeding the 5000 sanity cap`** — the cap
  is sized against the single backfill transaction's own time budget (the
  row-insert loop is one round-trip per row under an exclusive cross-replica
  lock, so an oversized backfill would otherwise block every OTHER replica's
  boot for its full duration). The cap counts every legacy record, active
  **and released** — this store's retention is unbounded by design, so a
  long-lived fleet's full history could plausibly approach this over years.
  Two ways forward: (a) prune released records you no longer need evidence
  for out of the legacy `quarantine.db` directly with a SQLite client before
  retrying (multi-replica caveat: do this on every replica's own legacy file
  identically, or the replicas will fingerprint-diverge — see below); or (b)
  raise `kMaxBackfillRows` in `quarantine_store.cpp` and rebuild — this is a
  compile-time constant, there is no runtime flag. Engage engineering for
  (b); do not raise it without re-checking it stays inside
  `kBackfillTxnTimeout`'s budget.
- **`has an unrecognised status 'X'`** — the `status` column is only ever
  `active` or `released`; something else (hand-edited row, external tooling)
  needs correcting to one of those two values in the legacy file before
  retrying.
- **`has more than one 'active' record for agent_id='X'`** — the legacy
  SQLite schema never enforced "at most one active record per agent" at the
  database level (only an in-process mutex the server no longer runs did),
  so this is pre-existing data corruption or a hand-edited file. Release or
  delete the duplicate row(s) in the legacy file, keeping the one that
  reflects reality, before retrying.

## Holder-side verification refusals

The `backfill_complete` marker is already set when this replica boots, and
this replica still holds a legacy `quarantine.db` at its configured path.
Rather than trust a marker it cannot vouch for, this replica verifies that
ITS file's content is what got migrated, and refuses to serve if it cannot.
Stored/logged fingerprint values look like `v1:<64 hex characters>`; the
literal unprefixed string `sourceless` is a distinct sentinel, not a
scheme-versioned hash.

### "HOLDER-SIDE VERIFICATION FAILED ... a DIFFERENT recorded source fingerprint"

This ONE log message covers **two distinct causes** — read the surrounding
context (is this a multi-replica deployment? was this specific server
recently rolled back?) before picking a recovery path, since they diverge:

**Cause 1 — multi-replica divergence.** A different replica's real
`quarantine.db` was migrated, and this replica's own file was never part of
it. Resolve the same way as `RbacStore`'s equivalent case: confirm which
replica's content is authoritative (usually whichever one actually received
live `quarantine_device`/`release_device` traffic before cutover), move
aside every OTHER replica's `quarantine.db`, and restart them — they'll find
no local file and trust the already-established marker. To make this rare
rather than routine, boot the replica holding the authoritative
`quarantine.db` FIRST on any fresh multi-replica rollout. If this replica's
OWN file is the authoritative one and a different (wrong) replica's content
already won the marker, engage engineering — recovering the correct
quarantine history back into `quarantine_store` after a wrong replica has
already migrated is a case-specific DBA task, not scripted here.

**Cause 2 — single-replica rollback-then-reupgrade.** This server was rolled
back to a pre-ADR-0047 build **after** the backfill had already completed,
and is now being re-upgraded. **Two variants, both sufficient on their own —
gov-fix(architect, Gate 8):**

- **(2a) Activity happened.** The old binary ran against a restored/backed-up
  `quarantine.db` (or one it recreated at the vacated original path — see
  2b) for a while, creating new quarantine/release activity in that file.
- **(2b) Zero activity is ALSO sufficient — do not assume "nothing happened,
  so this shouldn't trigger."** The old binary's constructor unconditionally
  runs `CREATE TABLE IF NOT EXISTS` at the original `quarantine.db` path
  every boot, regardless of whether any quarantine/release action ever
  happens. Since the real data was renamed aside during the original
  migration (`quarantine.db.migrated-<epoch>`), the old binary finds no file
  there and creates a fresh, EMPTY `quarantine_records` table — and a
  present-but-empty table fingerprints as real content, not `sourceless`
  (that sentinel is reserved for a wholly-ABSENT table). Merely booting the
  old binary against the vacated path is enough to produce a permanent
  mismatch on re-upgrade, with no restore and no live quarantine/release
  calls required.

Either way, the file the old binary touched no longer matches what was
already migrated into Postgres, so this looks identical to Cause 1 to the
verification check even though only one replica is involved. **This is the
reachable case if you followed the generic top-level [Rollback](
../user-manual/upgrading.md#rollback) procedure** ("restore the backed-up
`.db` files, start the previous version binary") against a server that had
already completed this backfill — see the Rollback note in this store's
upgrading.md section, which is the authoritative guidance for this
situation. To recover: the Postgres `quarantine_store` data (from the
original backfill, plus anything written there directly since re-upgrading
was last attempted) is authoritative for anything after the original
cutover; the legacy file only has value for whatever quarantine/release
activity happened **during the rollback window**, which must be
reconciled by hand — engage engineering. Move the legacy file aside
manually (do not restart repeatedly hoping it self-resolves; it will not,
since the fingerprint mismatch is now a fact) once reconciliation is
complete, then restart.

### "legacy db ... still holds real content" (no recorded fingerprint / sourceless marker)

Two narrower variants, both requiring manual reconciliation before
restarting:

- **No recorded fingerprint at all** — the marker predates the
  fingerprint-verification mechanism. Confirm this replica's content is
  safe to discard (it should already be reflected in Postgres from whatever
  migration set that marker), then move the legacy file aside and restart.
- **Sourceless marker** — no replica has ever migrated real content for this
  fleet, but a live `quarantine_device`/`release_device` call may already
  have landed against the sourceless-stamped store. Confirm no such calls
  happened before deciding whether the legacy content is safe to discard or
  needs manual merging; engage engineering if unsure.

## Not a refusal: same-boot race between two first-time replicas

If two replicas reach the backfill within the same narrow window on a fresh
rollout, one waits on the other under an internal database lock (bounded by
the same timeout as the backfill transaction itself) rather than both
attempting the insert; the loser then re-verifies by fingerprint as
described above and proceeds normally. This is expected, self-resolving
behavior and does not need operator action or a runbook entry of its own —
listed here only so it isn't mistaken for one of the refusals above.

## Note: no "abandon by hand" procedure for a clean retry

If the backfill process is interrupted before the marker stamp (crash,
`SIGKILL`, host loss mid-transaction), the next boot simply finds the marker
absent and retries the whole migration from scratch. **gov-fix(compliance-
officer + docs-writer, Gate 8):** unlike `RbacStore`/`CustomPropertiesStore`,
this is NOT per-row `ON CONFLICT` idempotency — `quarantine_records` has no
natural per-row key (see ADR-0047 "Backfill"), so its INSERT carries no
`ON CONFLICT` clause at all. What actually makes the retry clean is
**whole-transaction atomicity**: the row inserts and the `backfill_complete`/
`backfill_row_count`/`backfill_source_fingerprint` marker stamps all commit
together in ONE transaction, so an interruption before that commit leaves
**zero** rows in Postgres from the failed attempt — the next boot doesn't
skip already-migrated rows via per-row dedup, it redoes the entire migration
because nothing from the interrupted attempt persisted. Nothing to abandon
by hand either way. A previously-failed move-aside (legacy file still
present after a verified, already-completed migration) also retries
automatically on the next boot.

**Not affected:** `GET`/`POST`/`DELETE /api/v1/quarantine*` and the MCP
`quarantine_device` tool are unchanged by any of this once the server is up
— these refusals are exclusively about whether the ONE-TIME backfill is
allowed to complete at boot.
