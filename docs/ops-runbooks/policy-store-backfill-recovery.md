# Runbook: PolicyStore backfill refusals and recovery

Covers boot-time refusals from the mandatory legacy `policies.db` →
PostgreSQL `policy_store` backfill (ADR-0056). If the server is refusing to
start and the log shows `PolicyStore: migrate_from_sqlite: ...`, this is the
page.

Background: `docs/adr/0056-policy-store-postgres-migration.md` ("Backfill
(ADR-0009)" and the Second/Third correction sections). PolicyStore is
AUTHORITATIVE (ADR-0012 §1) for its five operator-authored IDENTITY tables
(`policy_fragments`, `policies`, `policy_inputs`, `policy_triggers`,
`policy_groups`) and treats `policy_status` as a sixth, LIFECYCLE table with
direction-aware merge — a failed or incomplete backfill of either half is
fatal at boot (`server.cpp`: `PolicyStore` construction / `migrate_from_sqlite`
failure both set `startup_failed_`), the same posture every born-on-PG store
uses.

## Holder-side verification refusal (divergent legacy file)

Log line: `PolicyStore: migrate_from_sqlite: legacy file at <path>
(fingerprint <F1>) diverges from an already-landed legacy backfill
(fingerprint <F2>) — refusing`.

The `policy_store.sqlite_backfill_source` table already records a landed
backfill under a DIFFERENT fingerprint than this replica's own legacy
`policies.db` hashes to (a raw SHA-256 hex digest over the five IDENTITY
tables' canonicalized content — no `sourceless` sentinel is ever landed
under this path, since it's write-once content). This is refused rather
than silently merged because every IDENTITY table is write-once with no
legitimate reason for two *different* legacy files to both need migrating —
`policy_triggers` in particular has no conflict target at all, so blindly
running the identity-insert loop against a second unrelated file would
silently append duplicate trigger rows.

**Recovery:** confirm which replica's legacy file is authoritative (typically
whichever one actually ran the pre-cutover server). Move the OTHER
replica(s)' `policies.db` aside and restart them — an absent legacy file
sets `sourceless=true`, which skips both the fingerprint check and the
identity-table backfill entirely, so a moved-aside replica boots clean and
simply relies on the already-landed Postgres data. If policy definitions
were independently authored on the losing replica before cutover, re-author
them through the normal API (`POST /api/policies`) once the server is up —
policy authoring is small and fully operator-editable, unlike a bulk DB-level
merge.

A holder-side verification QUERY failure (not a fingerprint mismatch — the
query itself erroring) logs `holder-side verification query failed` and
refuses the same way; that's a plain connectivity/DB problem, not a
divergent-file case — treat it as any other Postgres reachability incident.

## Legacy-ahead `policy_status` refusal

Log line: `PolicyStore: migrate_from_sqlite: status (<policy_id>,<agent_id>)
legacy last_check_at <T1> is ahead of Postgres's <T2> — refusing`.

Unlike the five IDENTITY tables, `policy_status` is copied (not
fingerprint-gated) and this comparison **runs on every boot for as long as
the legacy file exists at its configured path** — not just the first
post-cutover boot. Postgres-ahead-or-tied is a benign no-op; a legacy row
strictly ahead of Postgres's value fails the WHOLE backfill closed, because
an independently-advanced or restored legacy snapshot must never silently
overwrite live post-cutover compliance status.

**This means leaving the legacy `policies.db` in place "as a backup" after a
successful cutover is not inert.** If that file is ever restored from an
older backup, or a pre-cutover binary is ever pointed at it again and allowed
to write, the NEXT restart of a server still configured to read it reproduces
this refusal — under `systemd Restart=`, that's a boot-refusal crash loop
whose only log line names one status row, not the underlying cause. Rule out
**forward clock skew** on the reporting agent as a first check (a
skew-ahead `last_check_at` compares as "legacy ahead" even when the actual
event was older).

**Recovery:** decide which side is authoritative for the named
`(policy_id, agent_id)` row. If Postgres is right (the common case post-cutover), archive
or delete the legacy `policies.db` once cutover is confirmed — do not leave
it in place — and restart; an absent file skips this check entirely. If the
legacy row is genuinely right (rare — would mean a real compliance event was
recorded pre-cutover and never reached Postgres), reconcile the Postgres row
directly through `update_agent_status`'s effect (re-run the check via
`POST /api/policies/:id/evaluate`, or fix the row with engineering support)
before removing the legacy file.

**"Move it aside" also drops status history, not just definitions.** Moving
the file aside sets `sourceless=true`, which empties `legacy_status` too —
any per-agent compliance status history that only exists in the legacy file
(not yet reflected in Postgres) is dropped along with the definitions, not
just the definitions. The server's own boot-refusal log line already says so
("policy definitions AND per-agent status history in it will NOT carry
over") — this section spells out why, for an operator who wants the
mechanism, not just the warning.

## Orphan `policy_status` rows — discarded, not a refusal

Log line (info-level, not a refusal): `PolicyStore: migrate_from_sqlite: N of
M legacy policy_status rows were orphan debris (no matching policy in the
legacy file) and were discarded, not migrated`.

Unlike the legacy-ahead case above, this does NOT fail the boot. A
`policy_status` row whose `policy_id` isn't in the legacy file's own
`policies` table (the SQLite original never enforced this FK) has no valid
target under the new Postgres FK and no source of truth to reconcile against
— it is legacy debris, not a data-integrity conflict. It is silently
discarded rather than migrated. If you see a nonzero count here and want to
know which rows were dropped, the individual `spdlog::warn` line above the
summary names each skipped `policy_id`. No operator action is required.

## After the backfill succeeds

The `sqlite_backfill_source` fingerprint marker and the `policy_status` merge
are both correctly idempotent — a repeat boot against the same file (or no
file) is always a clean no-op. There is no separate "abandon by hand"
procedure needed for an interrupted-then-retried backfill.

**Not affected:** the compliance evaluation pipeline (`PolicyEvaluator`),
the durable dispatch claim (`claim_due_policies`/`policy_dispatch_state`),
and the REST/MCP policy surfaces are unchanged by any of this — these
refusals are exclusively about whether the ONE-TIME legacy backfill may
complete.
