# Runbook: InstructionStore backfill refusals and recovery

Covers boot-time refusals from the mandatory legacy `instructions.db` →
PostgreSQL `instruction_store` backfill (ADR-0058). If the server is refusing
to start and the log shows `InstructionStore::migrate_from_sqlite: ...` above
a `[PG] Refusing to start: instruction legacy-SQLite backfill failed` line,
this is the page.

Background: `docs/adr/0058-instruction-store-postgres-migration.md`
("Backfill" section, including the two documented pre-merge corrections).
InstructionStore is AUTHORITATIVE (ADR-0012 §1) for `InstructionDefinition`/
`InstructionSet` rows; a failed or incomplete backfill is fatal at boot
(`server.cpp`: `migrate_from_sqlite` failure sets `startup_failed_`), the same
posture every migrated store on this ladder uses. Unlike `PolicyStore`'s
whole-file fingerprint gate, InstructionStore's backfill runs **per legacy
row** — the whole file's insert loop is one transaction, so any single row's
refusal rolls back and fails the entire pass, but the trigger is always one
specific `id`, not the file as a whole.

## IDENTITY mismatch (`created_by` differs)

Log line: `InstructionStore::migrate_from_sqlite: legacy definition id='<id>':
IDENTITY mismatch against existing row (created_by differs) — refusing to
guess which is correct` (same shape for `legacy set id='<id>'`).

`created_by` is write-once IDENTITY — this replica's legacy file and the
already-landed Postgres row disagree on who created the row at all, not just
its content. This is a genuine data-integrity conflict (a corrupted/hand-edited
legacy file, or a real id collision between two unrelated authoring events)
and is refused rather than guessed at.

**Recovery:** compare the legacy file's row against the live Postgres row for
that id (`GET /api/instructions/{id}` / `GET /api/instruction-sets/{id}`).
Decide which side is authoritative, then either fix the legacy file's
`created_by` to match before retrying, or move the legacy file aside (see
"Move it aside" below) and re-create the row through the normal API if the
legacy side turns out to be the one that should have won.

## Content divergence on a non-sentinel `created_by` (operator-authored conflict)

Log line: `InstructionStore::migrate_from_sqlite: legacy definition id='<id>':
IDENTITY mismatch against existing row (created_by='<name>' matches but
yaml_source differs) — two independently-authored rows share this id,
refusing to guess which is correct` (sets: `name/description differ`).

`created_by` matches, but the content doesn't — and `created_by` is NOT the
bundled-content sentinel (`"system"`), so this isn't benign bundle-vintage
drift. This is the realistic multi-replica case: hand-synced YAML across
pre-Postgres replicas that drifted, or the same login shared across
replicas, each independently authoring different content under the same id.

**This is NOT the same as a bundled definition/set's content differing** —
if the log line instead reads `is bundled (created_by is the seed sentinel)
and its yaml_source differs ... treating as bundle-vintage drift` at `warn`
level, that is expected and does not fail the boot; see "Bundle-vintage
drift" below.

**Recovery:** same as the IDENTITY-mismatch case above — compare both sides,
decide which is authoritative, fix the legacy file or move it aside and
re-create through the API.

## Bundle-vintage drift — logged, not a refusal

Log line (`warn`-level, not a refusal): `InstructionStore::migrate_from_sqlite:
legacy definition id='<id>' is bundled (created_by is the seed sentinel) and
its yaml_source differs from the already-live row — treating as bundle-vintage
drift, Postgres's existing row wins and the legacy content is discarded`
(sets: `name/description differ`).

This does NOT fail the boot. A bundled (build-time-embedded) definition/set
has no discriminator separating it from operator content in the legacy
schema, and its content legitimately differs across replicas/releases whose
bundle vintage diverged — this is expected on a staged multi-replica rolling
upgrade (see `docs/user-manual/upgrading.md`'s note on the WARN burst this
can produce). Postgres's existing row wins; the legacy side is discarded. No
operator action required.

## Tombstone check failure

Log line: `InstructionStore::migrate_from_sqlite: legacy definition id='<id>':
tombstone check failed: <PG error>` (sets: `legacy set id='<id>': tombstone
check failed`).

Not a conflict — a plain connectivity/DB problem reading
`deleted_seed_content` under the seed-coordination lock. Treat as any other
Postgres reachability incident.

## "Move it aside" — what it does and doesn't recover

Moving `instructions.db` aside (or deleting it) makes the next boot see "no
legacy file" — the backfill marks itself complete with a sourceless
fingerprint and skips entirely, so the replica boots clean. **Content in the
moved-aside file does NOT carry over automatically.** If the legacy side held
real operator-authored content that should be kept, re-create it through the
normal API (`POST /api/instructions`, `POST /api/instruction-sets`) once the
server is up — instruction authoring is small and fully operator-editable,
unlike a bulk DB-level merge. There is currently no per-row skip option that
keeps the rest of the legacy file's content — it's "resolve the specific
row" or "discard the whole file".

## After the backfill succeeds

The `sqlite_backfill_source` fingerprint marker is correctly idempotent — a
repeat boot against the same file (or no file) is always a clean no-op.
Backfill runs strictly BEFORE the `kBundledDefinitions`/`kBundledSets` reseed
loop on every boot (load-bearing ordering — see the ADR's "Boot ordering"
section); there is no separate "abandon by hand" procedure needed for an
interrupted-then-retried backfill.

**Not affected:** the compliance/dispatch-adjacent read paths
(`PolicyEvaluator`, `schedule_runner`, MCP `list_definitions`/`get_definition`)
are unchanged by any of this — these refusals are exclusively about whether
the ONE-TIME legacy backfill may complete.
