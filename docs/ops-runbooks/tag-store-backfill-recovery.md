# Runbook: TagStore backfill refusals and recovery

Covers boot-time refusals from the mandatory legacy `tags.db` → PostgreSQL
`tag_store` backfill (ADR-0050). If the server is refusing to start because
of this backfill, this is the page.

Background: ADR-0050, `docs/postgres-store-playbook.md` "Local source
absence never creates terminal migration state on its own" (#2697); the
fingerprint machinery mirrors `custom-properties-store-backfill-recovery.md`
(ADR-0045) unmodified. What is DIFFERENT here: row conflicts are
direction-aware on `updated_at`, so this store can also refuse over a
row-level conflict, not only over a fingerprint mismatch — see the last
section.

## Holder-side verification refusals

The `backfill_complete` marker is already set when this replica boots, and
this replica still holds a legacy `tags.db` at its configured path. Rather
than trust a marker it cannot vouch for, this replica verifies that ITS
file's content is what got migrated, and refuses to serve if it cannot.
Stored/logged fingerprint values look like `v1:<64 hex characters>`; the
literal unprefixed string `sourceless` is a distinct sentinel, not a
scheme-versioned hash.

### "legacy db ... is unreadable/corrupt while being fingerprint-verified"

This replica's own legacy file could not be opened or read as a valid
`tags.db` (corrupt, truncated, or not a SQLite file at all). Fails closed —
an unreadable file is never silently treated as "nothing to protect." Fix
the file's readability (restore from backup if the corruption is genuine)
or confirm it's safe to discard, then retry.

### "HOLDER-SIDE VERIFICATION FAILED"

Read the quoted `fingerprint '{stored}'` value in the log line before
acting:

**If the stored fingerprint is a real hash (`v1:<64 hex chars>`):** a
different replica's real `tags.db` was migrated, and this replica's own file
was never part of it — typically two independently-operated pre-cutover
servers being merged into one Postgres deployment, or tags edited on more
than one replica before the cutover completed. NOTE: if this replica raced
the winner on the SAME first boot and their contents were row-disjoint (no
direction conflicts), this replica's rows were already committed BEFORE it
lost the fingerprint race — Postgres is then serving a MIX of both replicas'
tags while this replica refuses to boot; compare Postgres's row count
against both legacy files before deciding which side to keep. Confirm which replica's
content is authoritative, move aside every OTHER replica's `tags.db`, and
restart them — they'll find no local file and trust the established marker.
If the WRONG replica's content won the marker, re-applying the correct tags
through the normal API (`PUT /api/v1/tags`, or the dashboard) is usually
simpler than DB-level reconciliation — tag data is small and fully
operator-editable; agent-sourced tags additionally re-sync themselves on
each agent's next Register.

**If the stored fingerprint is the literal word `sourceless`:** a fileless
sibling replica booted first and stamped the marker before any replica
migrated real data. Nothing has been backfilled yet; this replica's real
file is refused because the marker's presence means this is not a fresh
install it can just proceed with. Confirm no tag activity has happened
through the API since the stamp; if clean, engage engineering to clear the
`backfill_complete` and `backfill_source_fingerprint` rows from
`tag_store.tag_store_meta` and restart this replica — it will find the
marker absent and complete a normal migration.

To make both cases rare: boot the replica holding the real, authoritative
`tags.db` FIRST on any fresh multi-replica rollout.

## Direction-aware row-conflict refusals (this store's addition)

Log line: `legacy row (<agent>, <key>) shows MORE progress than / contradicts
... Postgres's current value`. The backfill found Postgres already holding a
row for the same `(agent_id, key)` whose `updated_at` is OLDER than the
legacy file's (or tied with different content). That is the ADR-0009
rollback-then-roll-forward shape: a pre-migration binary ran against this
`tags.db` after Postgres last saw it, and genuinely progressed the tag.
Refusing protects the LATER write from being silently discarded.

**Classify this as a data-integrity incident, not an availability one**: the
refusal means the currently-served tag data may be the wrong side of an
operator-authored-data race, so triage it as "verify which side is
authoritative", never as "restart failed". There is no scrapeable metric for
a refused boot (the process exits before `/metrics` serves) — alert on the
refusal log line itself if you run a log pipeline, and on
`YuzuTagStoreBackfillNotCompleted` (absent-success shape) otherwise.

One benign-looking cause worth ruling out first: **forward clock skew**. A
legacy row stamped by a skewed-ahead clock compares as "legacy ahead" even
when the Postgres write is genuinely newer — if the named row's legacy
`updated_at` is in the future relative to when that server last ran, suspect
the clock, not a real progress race.

The refusing transaction rolls back — nothing from this pass is committed,
the legacy file is not consumed. Recovery: decide which side is
authoritative for the named row(s). If the legacy side is right, fix the
Postgres row through the normal API (or clear it) and restart — the re-run
compares directions again and now no-ops or inserts cleanly. If the
Postgres side is right, update the legacy file's row (or move the file
aside if NOTHING in it is newer-and-wanted) and restart. The log names the
exact row and both sides' value/source/updated_at, so the comparison is
mechanical.

A conflict where Postgres is strictly AHEAD of the legacy row does not
refuse — it WARNs and keeps Postgres's value (the ordinary "this replica's
legacy snapshot predates live progress" case).

## After a runtime degrade window ends

Reads recover immediately once the store answers again, but two derived
states do NOT self-heal on recovery alone:

- **Auto-created service management groups** whose membership refresh was
  skipped during the degrade stay at their prior membership. There is no
  automatic repopulation pass — membership refreshes on the next `service`
  tag write. To force it, re-save any device's `service` tag
  (`PUT /api/v1/tags`).
- **Agent-side cached category tags** whose push was skipped stay stale on
  the device until the next category-tag write for that agent triggers a
  push (or the agent re-Registers, which re-syncs its own reported tags).

Pool-saturation triage: `/readyz` stays green under pure saturation (the
`tag_store` row latches construction success) — pair
`yuzu_server_tag_store_read_degrade_total{reason="pool_acquire_timeout"}`
with `yuzu_pg_pool_waiters` / `yuzu_pg_acquire_*` to distinguish substrate
saturation from a store-level failure.

## Note: no "abandon by hand" procedure

The marker is stamped only after the data commits. An interrupted backfill
retries whole on the next boot; identical already-migrated rows compare as
benign no-ops. A previously-failed move-aside retries automatically once
verification passes.

**Not affected:** `tag:<key>` scope resolution, the REST/MCP tag surfaces,
and agent tag sync are unchanged by any of this — these refusals are
exclusively about whether the ONE-TIME backfill may complete.
