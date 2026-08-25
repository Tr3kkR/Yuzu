---
status: accepted
date: 2026-08-24
owner: platform (Postgres substrate migration program)
deciders: parallel Wave 2 batch-7 migration worker, following the ladder assignment in
  `docs/postgres-migration-ladder.md` (Wave 2); seed-vs-live design independently reviewed by
  Codex (`gpt-5.6-sol`, opine-only consult) before being locked in by Dave
scope: server — `InstructionStore` (`InstructionDefinition`/`InstructionSet` content catalog),
  its cutover from SQLite to PostgreSQL, its ADR-0009 backfill, and the boot-time bundled-content
  reseed loop's multi-replica seed-vs-live design
builds-on: ADR-0006 (Postgres substrate), ADR-0007 (single-backend, no SQLite fallback),
  ADR-0008 (substrate architecture), ADR-0009 (per-store first-boot backfill cutover, whose
  Context paragraph already names this store's class: "build-time-seeded — instructions,
  re-seeded from embedded content, plus operator additions"), ADR-0012 (server Postgres store
  contract), ADR-0036 (authoritative-read type-distinguishability)
related: docs/postgres-migration-ladder.md (Wave 2 -> Done); docs/adr/0054-product-pack-store-postgres-migration.md
  (closest structural precedent — two-table content catalog, signing gate, erasure-consistency
  tombstone shape); docs/adr/0052-device-token-store-postgres-migration.md (IDENTITY/LIFECYCLE
  backfill-conflict precedent for a store whose rows mutate post-insert); `rbac_store.cpp`'s
  `kRevokeCoordLockSql`/`revoked_seed_defaults` (the reseed-suppression coordination-lock
  precedent this store's seed design extends from RBAC grants to content); `docs/postgres-store-playbook.md`
  lines 286-329 (the named "hard DELETE + unconditional reseed resurrects it" anti-pattern)
---

# 0058 — `InstructionStore` Postgres migration (authoritative, with backfill; first every-boot
reseed loop on the ladder)

## Context

`InstructionStore` (`server/core/src/instruction_store.{hpp,cpp}`) persists the content-plane
catalog `docs/Instruction-Engine.md` describes: `InstructionDefinition -> InstructionSet ->
ProductPack` (`ProductPackStore`, ADR-0054, is the layer above; it references only
`ProductPackStore::verify_signature`, a static/storage-independent method — no store-to-store
coupling). Two tables, no FK between them (`instruction_set_id` is a soft TEXT reference;
`delete_set` explicitly unsets it on referencing definitions rather than relying on a cascade).
It is a Wave 2 store on `docs/postgres-migration-ladder.md`. Previously SQLite
(`instructions.db`), guarded by a `shared_mutex`.

**Security-shaped invariant preserved unchanged**: `import_definition_json` enforces an Ed25519
signature gate (#1073/W7.4) with five documented rejection modes; `import_definition_json_trusted`
bypasses it ONLY for build-time-baked content, with no REST/MCP/network surface reaching it. Both
paths stay byte-identical in behaviour; the gate itself is pure/storage-independent
(`ProductPackStore::verify_signature`) and unaffected by this migration.

**The genuinely new problem this store introduces to the ladder**: every other migrated
content-catalog store either (a) has no boot-time reseed loop at all (`ProductPackStore`:
packs are purely operator-installed), or (b) has a reseed loop but rows that are write-once after
insert (`RbacStore`'s built-in role/permission defaults). `InstructionStore` has **both** an
unconditional every-boot reseed loop (`server.cpp:4703-4859` walks build-time-embedded
`kBundledDefinitions`/`kBundledSets`, calling `import_definition_json_trusted`/`create_set` for
each entry on **every** boot) **and** rows that mutate after insert (`update_definition` — no
analogous `update_set` exists). That combination is what this ADR's Decision section works
through: a straight port of the reseed loop's current SQLite behaviour, taken literally, contains
a defect (documented and pinned below); the backfill can't reuse `ProductPackStore`'s
full-row-equality-or-fail-closed rule wholesale because most of an `InstructionDefinition`'s
columns are legitimately mutable.

### Pinned current-SQLite behaviour (the contract to preserve, or deliberately diverge from)

Four Catch2 tests (`tests/unit/server/test_instruction_store.cpp`, tag `[instruction_store][seed]`,
commits `bb8b334ac`/`1f518fe4c` on this branch) empirically pinned the pre-migration SQLite
store's boot-reseed contract before any porting began, per this migration's kickoff instructions.
`import_definition_json_trusted`'s pre-INSERT existence check is keyed ONLY on `id` — content is
never compared:

1. Untouched bundled definition: reseed = conflict-skip (no-op).
2. Operator-edited bundled definition: reseed does NOT clobber the edit (still skip, because
   `id` exists).
3. Operator-**deleted** bundled definition: reseed **RESURRECTS** it — a deleted `id` is
   indistinguishable from a never-seeded `id`, so the next boot's replay re-inserts the original
   bundled content.
4. A later release shipping **changed** bundled content for an existing `id` — untouched or
   operator-edited — still just conflict-skips; the row is frozen at first-seed vintage forever.
   Confirmed (read of the full `server.cpp:4703-4859` boot-content block) that no other path
   writes into `InstructionStore` at boot — no packs loop, no `ProductPackStore`-mediated upsert.

Finding 4 makes finding 3 load-bearing rather than cosmetic: **delete-then-reboot is currently
the only way an existing bundled id ever picks up newer bundled content.** The kickoff doc that
scoped this migration states, in one place, "an operator-modified or operator-deleted definition
must NOT be clobbered or resurrected by a later replica boot or a release upgrade re-seed," and a
few lines later, "the existing behaviour is the contract, whatever it is" — those two lines
conflict specifically on the delete case.

### Independent-model consult (Codex/Sol) + primary-source verification

Before locking in a direction, Codex (`gpt-5.6-sol`, opine mode, read-only) reviewed the fork and
recommended **against** preserving resurrection-on-delete, citing `docs/postgres-store-playbook.md`
by name. That citation was verified against the actual file rather than trusted at face value
(claim-discipline): playbook lines 286-329 name this **exact** failure mode — hard DELETE +
unconditional reseed silently reversing an operator revocation on ordinary restart — as a
documented anti-pattern, with `RbacStore::remove_permission` (#2703) as the reference case. That
reference case is real, shipped code, not aspirational doc narrative: `rbac_store.cpp` has
`kRevokeCoordLockSql` (line ~93) and table `revoked_seed_defaults` (line ~430), used at three
separate writer call sites. RbacStore's own three-round history (bare DELETE -> resurrection bug;
explicit `deny` row -> wrong, not read-neutral, vetoed unrelated grants; dedicated suppression
table consulted only by the reseed helper -> shipped) plus a fourth bug found on top (the
check-then-insert-against-the-bookkeeping-table race, needing a `pg_advisory_xact_lock` taken as
its own statement strictly before the check-and-mutate) is the exact shape this store's seed
design reuses. Dave's decision, made with this evidence in hand: **do not port
resurrection-on-delete forward** — deletion becomes an intentional suppression that survives
future reseeds.

## Decision

### Schema

`instruction_store`, per ADR-0008's `snake_case(FullClassName)` rule.

```sql
CREATE TABLE instruction_definitions (
  id                      TEXT PRIMARY KEY,
  name                    TEXT NOT NULL,
  version                 TEXT NOT NULL DEFAULT '1.0',
  type                    TEXT NOT NULL,
  plugin                  TEXT NOT NULL,
  action                  TEXT NOT NULL DEFAULT '',
  description             TEXT NOT NULL DEFAULT '',
  enabled                 BOOLEAN NOT NULL DEFAULT TRUE,
  instruction_set_id      TEXT NOT NULL DEFAULT '',
  gather_ttl_seconds      INTEGER NOT NULL DEFAULT 300,
  response_ttl_days       INTEGER NOT NULL DEFAULT 90,
  created_by              TEXT NOT NULL DEFAULT '',
  created_at              BIGINT NOT NULL DEFAULT 0,
  updated_at              BIGINT NOT NULL DEFAULT 0,
  yaml_source             TEXT NOT NULL DEFAULT '',
  parameter_schema        TEXT NOT NULL DEFAULT '{}',
  result_schema           TEXT NOT NULL DEFAULT '{}',
  approval_mode           TEXT NOT NULL DEFAULT 'auto',
  concurrency_mode        TEXT NOT NULL DEFAULT 'per-device',
  platforms               TEXT NOT NULL DEFAULT '',
  min_agent_version       TEXT NOT NULL DEFAULT '',
  required_plugins        TEXT NOT NULL DEFAULT '',
  readable_payload        TEXT NOT NULL DEFAULT '',
  visualization_spec      TEXT NOT NULL DEFAULT '{}',
  response_templates_spec TEXT NOT NULL DEFAULT '[]');
CREATE TABLE instruction_sets (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  created_by  TEXT NOT NULL DEFAULT '',
  created_at  BIGINT NOT NULL DEFAULT 0);
-- ADR-0009 backfill idempotency (content-fingerprinted, not a fleet-wide flag).
CREATE TABLE sqlite_backfill_source (fingerprint TEXT PRIMARY KEY, completed_at BIGINT NOT NULL);
-- ADR-0009 erasure consistency / reseed suppression (the headline decision — see below).
CREATE TABLE deleted_seed_content (
  kind       TEXT NOT NULL,  -- 'definition' | 'set'
  id         TEXT NOT NULL,
  deleted_at BIGINT NOT NULL,
  PRIMARY KEY (kind, id));
```

The pre-migration SQLite constructor's ~9 `legacy_alters[]` compat `ALTER TABLE` statements plus
its v2/v3 `MigrationRunner` steps (`visualization_spec`, `response_templates_spec`) are all folded
into this single v1 — the Postgres schema is born fresh, matching every other migrated store's
"no ALTER-wart machinery on PG" precedent (`ProductPackStore`'s `verified` column,
`docs/postgres-store-playbook.md`'s worked recipe). No index beyond the two primary keys — the
pre-migration SQLite store had none either (not even on `instruction_set_id`, despite
`delete_set`'s `UPDATE ... WHERE instruction_set_id=?` full-table-scan); adding one is a
straightforward follow-up, out of scope for a faithful port.

**`open_with_migrations` does not exist.** The playbook (line 92) and ADR-0008/ADR-0012 name a
thin construction helper by that name as mandatory; it is not implemented anywhere in the tree —
verified by grep. Every existing store, including the playbook's own worked reference
(`offline_endpoint_store.cpp`) and the most recently merged content-catalog store
(`product_pack_store.cpp`), hand-rolls the acquire/`PgMigrationRunner::run`/smoke-read sequence
directly; `plugin_config_store.cpp:145-158` documents this exact discrepancy in its own
constructor comment. This store follows the same hand-rolled, actually-shipped precedent rather
than a helper that would not compile.

### Secrets (ADR-0010)

None. Verified against `docs/Instruction-Engine.md`/`docs/yaml-dsl-spec.md`: neither defines a
secret-typed/credential-bearing YAML field, matching `ProductPackStore`'s identical
self-assessment for its structurally similar `yaml_source` column. `yaml_source`/`parameter_schema`
are not flagged anywhere in the codebase as secret-bearing; ADR-0010's queued secret-bearing list
(webhooks, offload-targets, runtime-config) does not name this store.

### Posture

AUTHORITATIVE / fail-hard (ADR-0012 §1), both construction and runtime — explicitly required by
this migration's kickoff doc: "a silent-empty definition read breaks dispatch (`execute_instruction`
resolves definitions here); degrade must error, never empty-resolve." `create_definition`,
`update_definition`, `import_definition_json`, `import_definition_json_trusted`, `create_set`
already returned `std::expected` pre-migration and keep that shape. Widened to `std::expected`
here (ADR-0036 typed-read policy, matching `ProductPackStore`'s `list`/`get` widening):

- `query_definitions` -> `std::expected<std::vector<InstructionDefinition>, std::string>`
- `get_definition` -> `std::expected<std::optional<InstructionDefinition>, std::string>`
  (matches `ProductPackStore::get`'s exact shape)
- `list_sets` -> `std::expected<std::vector<InstructionSet>, std::string>`
- `delete_definition` -> `std::expected<void, std::string>`, `"not_found: "`-prefixed on a
  missing id (mirrors `ProductPackStore::uninstall`)
- `delete_set` -> `std::expected<void, std::string>`, same `"not_found: "` convention
- `export_definition_json` -> `std::expected<std::string, std::string>` (widened for
  consistency with every other read on this store rather than left as the one silent-`"{}"`
  exception; its only callers are a REST export handler and a dashboard preview — no
  authorization/targeting decision reads it, so this is a lower-stakes widening than the others,
  recorded here rather than left to infer)

`kInstructionStoreDbErrorPrefix` classifies genuine DB/lease failures (503); `"not_found: "`
classifies missing-id (404); caller-input validation errors stay unprefixed (400) — mirrors
`ProductPackStore::kProductPackDbErrorPrefix`'s three-way split.

### Seed-vs-live semantics (the headline decision)

Definitions and sets stay **conflict-skip on id existence for every already-live row** — findings
1/2/4 above are preserved exactly: no content comparison, an operator's edit is never clobbered,
and an untouched-but-stale bundled row does not auto-update on a release upgrade (that gap is
explicitly out of scope — see Consequences).

**Deletion becomes an intentional suppression, not a plain DELETE.** `deleted_seed_content(kind,
id)` is `RbacStore`'s `revoked_seed_defaults` shape extended with a `kind` discriminator (the same
technique `revoked_seed_defaults` itself uses via its `securable_type` column) rather than two
separate tables — one lock, one table, both content kinds. Consulted **only** by the trusted-reseed
insert path and the backfill's tombstone check; never by any read path, any normal
`create_definition`/`create_set` call, or any authorization/targeting decision — the playbook's
general rule ("don't represent 'suppress the next reseed' as a fact your read path can see").

**Discriminator, reusing an existing signal.** `import_definition_json_impl`'s existing
`check_signature` parameter already identifies "boot-time trusted content" exactly:
`check_signature=false` is `import_definition_json_trusted`, whose own contract states "there is
no REST/MCP/network surface for this method by design" — i.e. `!check_signature` is already,
today, a sound proxy for "this call originates from the every-boot reseed loop, nowhere else." No
new flag is introduced for definitions; `import_definition_json_impl` routes to a new private
seed-aware insert path when `!check_signature`, and to the plain insert path (unchanged, no
tombstone consultation) when `check_signature` is true (operator signed-import).

Sets have no signature concept at all — `"trusted"` would misleadingly imply one. A **new** public
method, `create_set_seed(const InstructionSet&)`, is the seed-aware entry point
(`server.cpp`'s `kBundledSets` loop calls it instead of plain `create_set`); the existing
`create_set` stays exactly as it is today — no lock, no tombstone consultation, used by the
REST-facing "create a custom instruction set" route (`server.cpp:15408`) exactly as before.
Mirrors `import_definition_json`/`import_definition_json_trusted`'s "two named entry points make
the trust boundary explicit at every call site" pattern, extended by name to match what's actually
being distinguished here (reseed vs. operator-authored), not signature verification.

**Locking.** Every writer that touches BOTH `instruction_definitions`/`instruction_sets` AND
`deleted_seed_content` takes `kSeedCoordLockSql` — `SELECT pg_advisory_xact_lock(2037545589,
hashtext('instruction_store:seed_coordination'))` (`2037545589` is the shared cross-store
namespace constant `rbac_store.cpp`/`product_pack_store.cpp` already use; the hashtext string is
this store's own key) — as the **first statement**, in an explicit transaction, strictly before
the statement that checks-and-mutates (embedding it via CTE in the same statement does not work —
a statement's READ COMMITTED snapshot is fixed before any of its own function calls run,
`docs/postgres-store-playbook.md` lines 309-329). Four writers take it: the trusted-reseed insert
path (checks the tombstone, then inserts), `create_set_seed` (same), `delete_definition` (deletes,
then stamps the tombstone), `delete_set` (unsets `instruction_set_id` on referencing definitions,
deletes, then stamps the tombstone) — all four in one transaction each. Plain `create_definition`,
`update_definition`, `create_set`, and the signed `import_definition_json` path never touch
`deleted_seed_content` and take **no** lock, matching `ProductPackStore::install`'s identical
lock-free shape (only `uninstall`/`migrate_from_sqlite` take `kErasureCoordLockSql` there).

A bundled `id` an operator has NOT deleted needs no lock for the insert's own correctness — a
plain `INSERT ... ON CONFLICT (id) DO NOTHING RETURNING id` is already correctly arbitrated by
Postgres's unique index across any number of racing replicas — but every writer in this class
takes the lock unconditionally anyway (rather than branching on "have I ever seen a tombstone")
for the same reason `RbacStore`/`ProductPackStore` do: coarse-grained, store-wide serialization
of operator-driven content-catalog management is cheap, this is never a hot path, and a
conditional lock would reintroduce exactly the check-then-act race the lock exists to prevent.
232 bundled definitions therefore serialize through one advisory-lock transaction each at boot —
boot-time only, not a steady-state cost, and not a new latency class this ladder hasn't already
accepted for `RbacStore`'s seed pass.

**Result classification.** `PGRES_COMMAND_OK` on `ON CONFLICT DO NOTHING` only proves the
statement executed, not that this writer's row won — every insert uses `RETURNING id` +
`PQntuples()`, never `PQcmdTuples()`/bare status (`docs/postgres-store-playbook.md`'s named
anti-pattern). A tombstoned id and an already-existing id both resolve to the same
`kConflictPrefix`-prefixed `unexpected()` from the seed-aware insert path — `server.cpp`'s boot
loop classification (`is_conflict_error` -> "skip, already accounted for") needs no change; it
cannot distinguish "already there" from "deliberately suppressed," and does not need to.

### Backfill (ADR-0009)

Mandatory — instruction definitions/sets are irreducible operator intent (explicitly named by
ADR-0009's own Context paragraph as this store's class). Content-fingerprinted (SHA-256 over both
tables' canonicalized, sorted, length-prefixed rows — `ProductPackStore`'s two-section shape,
`sqlite_backfill_source`), not a single fleet-wide completion flag.

**Conflict handling does NOT copy `ProductPackStore`'s full-row-equality-or-fail-closed rule for
definitions.** That rule is only correct when every column is write-once; `InstructionDefinition`
rows are not (`update_definition` mutates everything except `id`/`created_by`/`created_at`), and
each replica boots from its **own** `instructions.db` — a normal multi-replica cutover has
replica B's legacy snapshot legitimately diverge from a row replica A already backfilled and an
operator then edited live on Postgres. Fail-closed-on-any-mismatch would brick replica B's boot on
an ordinary condition, not corruption — this is exactly kickoff lesson 1's "IDENTITY vs LIFECYCLE
per column," and `DeviceTokenStore`'s ADR-0052 backfill is the applicable precedent (a store whose
rows also mutate post-insert), scaled down since `InstructionDefinition` has no monotonic
security-sensitive field like `revoked` needing a direction-aware rule:

- **IDENTITY** (write-once — no runtime method mutates these after INSERT): `id` (the `ON
  CONFLICT` target itself) and `created_by` only. A mismatch fails the backfill closed, naming
  both sides — the only plausible cause is a corrupted/hand-edited legacy file or two genuinely
  different definitions sharing an id, either of which deserves a halt, not a silent pick.
- **LIFECYCLE** (everything else, including `created_at` — see below —
  `name`/`version`/`type`/`plugin`/`action`/`description`/
  `enabled`/`instruction_set_id`/`gather_ttl_seconds`/`response_ttl_days`/`updated_at`/
  `yaml_source`/`parameter_schema`/`result_schema`/`approval_mode`/`concurrency_mode`/`platforms`/
  `min_agent_version`/`required_plugins`/`readable_payload`/`visualization_spec`/
  `response_templates_spec`): on a conflict with matching IDENTITY, Postgres's existing value
  **always wins silently**, regardless of which side is numerically newer or which fields differ
  — the backfill never `UPDATE`s an existing row. No direction-aware special case is needed
  (unlike `DeviceTokenStore`'s `revoked`): nothing in this column set is a security control whose
  legacy-side truth must override a stale live value, so "PG already has a live value, keep it" is
  correct unconditionally. This is the SAME rule the pinned seed-vs-live test 2 already
  established for the reseed loop ("operator edit is never clobbered"), extended to the backfill
  path for the identical reason.

**`created_at` was originally classified as IDENTITY (write-once); this was wrong, and was
corrected during Gate 4 governance review before merge.** The legacy `instruction_definitions`
table has no column distinguishing a bundled (build-time-embedded) row from an operator-authored
one — both pass through the same `insert_definition_row`, and a bundled row's `created_at` is
stamped `now()` the first time *this specific replica* seeds it into its own pre-migration
`instructions.db`, not authored content. Two independently-provisioned replicas' legacy files
therefore legitimately hold *different* `created_at` for the exact same bundled id — the same
"replica B's legacy snapshot legitimately diverges" reasoning already used above to justify
excluding LIFECYCLE columns from the conflict check applies to `created_at` too, and was not
originally applied to it. With `created_at` in IDENTITY, backfill bricked the boot of every
replica after the first to backfill any given bundled id — not a corner case, since every replica
independently seeds all ~232 bundled definitions / 10 bundled sets during normal operation.
`created_by` remains safe as IDENTITY: bundled content always gets the same value —
`embed_content.py`'s `def_envelope()`/`set_envelope()` both unconditionally set
`"created_by": "system"` on every generated envelope (verified: every entry in the built
`bundled_content.cpp` carries it) — so it resolves deterministically to `"system"` across every
replica and every release vintage; a real corrupted/hand-edited file or a genuine id collision
would still typically differ on `created_by` too. Pinned by the two-replica-divergence regression
tests in `test_instruction_store.cpp` (`[instruction_store][backfill][pg]`).

**Correction (Gate 8 re-review, second pass):** an earlier revision of this paragraph, and the
`kBundledDefinitionCreator` constant below, claimed the definitions sentinel was `""` — reasoning
that `embed_content.py` "never emits the `created_by` field" and the parser's own `""` fallback
would apply. That premise was wrong: `def_envelope()` DOES emit the field, always set to
`"system"`, so the `""` fallback never fires for real bundled content and the sentinel-match
branch below was dead code for definitions — reintroducing the exact boot-brick this section
exists to prevent. Fixed before merge; caught by an independent re-verify of the fix commit, not
by the tests (the existing definitions regression test happens not to exercise `yaml_source`
divergence at all, only `created_at`, which the LIFECYCLE rule already ignored either way — a new
test exercising `yaml_source` divergence under the `"system"` sentinel was added alongside this
correction, mirroring the sets test that already covered the equivalent case and would have
caught this).

**`created_by`-only IDENTITY (the paragraph above) was itself over-corrected; fixed during Gate 8
re-review, before merge.** Narrowing IDENTITY to `id`/`created_by` fixed the bundled-content brick
above, but removed protection against a DIFFERENT scenario the original full-row check caught: two
**operator-authored** rows sharing an id AND a `created_by` (e.g. a shared login used across
pre-Postgres replicas, or hand-synced YAML that drifted) whose content genuinely differs. Under the
`created_by`-only rule, that silently discards one replica's real content with no log line naming
which — the exact silent-loss failure mode this store's backfill design otherwise refuses to
produce. The corrected rule is conditional on `created_by`, not a blanket comparison:

- `created_by` equal to the code-default bundled sentinel (`"system"` for both definitions —
  `kBundledDefinitionCreator` — and sets — `kBundledSetCreator`, `instruction_store.cpp`):
  content divergence (`yaml_source` for definitions; `name`/`description` for sets) stays benign —
  bundle-vintage drift, Postgres's existing row wins — but is now logged at WARN naming the id, so
  the discard is visible instead of silent.
- Any other `created_by`: content divergence fails the backfill closed, naming both the id and the
  shared `created_by`, exactly like the pre-narrowing full-row check did — but WITHOUT reintroducing
  the `created_at` comparison that caused the original bundled-content brick, since `created_at`
  stays LIFECYCLE-only regardless of `created_by`. This also fixes a latent false-brick the
  ORIGINAL (pre-Gate-4) full-row design carried for operator content: two replicas hand-synced from
  the *same* file, imported at different times, differ only on `created_at` and would have failed
  closed on that alone. The corrected rule compares content, not import time, so a clean hand-sync
  is benign on both sides of this split.

Known residual, not fixed here: **an earlier revision of this paragraph named the wrong trigger**
(`create_definition`'s REST route under RBAC-off/unauthenticated create) — traced during Gate 8
re-review and found not reachable: `require_permission`/`resolve_session`'s RBAC-off fallback
still requires a valid session, and every session-synthesis path sets a non-empty username, so
`def.created_by = session->username` never lands on `""` via that route. The actually-reachable
residual is different and needs no RBAC-off at all: `POST /api/instructions/import` calls
`import_definition_json` directly on the request body with **no session-based `created_by`
override** (unlike the create route), so any caller holding the ordinary
`InstructionDefinition:Write` permission — the normal way to import definitions — can set
`created_by` to `"system"` just by supplying it (or omitting it, since the parser's own fallback
is `""`, not `"system"` — only the code-generated envelope path forces `"system"`) in the import
body, and have that row treated leniently (WARN, not fail-closed) on any future content
divergence, same as real bundled content. This field being caller-controlled is pre-existing
behaviour, unchanged by this migration; what changes here is that it gains security significance
(sentinel-spoofing to bypass the fail-closed content-divergence check). Whether
`/api/instructions/import`'s untrusted path should reject or override a caller-supplied
`created_by` is tracked as a separate follow-up, not resolved by this ADR. This is the same class
of residual as "no retroactive tombstone reconstruction" below — narrower than the general case,
stated so this ADR does not overclaim. Pinned by the additional two-replica regression tests in
`test_instruction_store.cpp`
(non-sentinel `created_by`, both the drifted-content-fails-closed and
identical-content-stays-benign cases, for both definitions and sets).

`instruction_sets` has **no analogous mutation path at all** (`update_set` does not exist), which
was originally read as "every column is write-once by construction, so any conflict must be
full-row-equality-or-fail-closed, per `ProductPackStore`'s simpler rule." That reasoning is also
wrong for the same reason as `created_at` above: a bundled set's `name`/`description` can
legitimately differ across two replicas' legacy files whose *release vintage* diverged (pinned
test 4's "changed bundled content across releases" finding applies to sets exactly as it does to
definitions), and `created_at` is replica-local seed time either way. `instruction_sets` therefore
uses the SAME IDENTITY/LIFECYCLE split as definitions, including the `created_by`-conditional
content check corrected above: `id`/`created_by` are IDENTITY (write-once, fail-closed on
mismatch); `created_at` is LIFECYCLE (never compared, Postgres's existing value always wins);
`name`/`description` are content — benign-with-WARN divergence for the `"system"` bundled
sentinel, fail-closed divergence for any other `created_by`. `ProductPackStore`'s full-row-equality
rule remains correct for
`ProductPackStore` itself: it has no build-time-embedded/bundled-pack concept at all (verified —
no `kBundledPacks`/seed-insert path exists), so every row it backfills is genuinely
operator-authored and write-once end to end; the rule does not generalize to a store that also
seeds build-time content through the same table.

**All-vintage column handling.** A legacy file may predate any of the ~9 compat-`ALTER`-only
columns (`yaml_source`/`parameter_schema`/`result_schema`/`approval_mode`/`concurrency_mode`/
`platforms`/`min_agent_version`/`required_plugins`/`readable_payload`) or the v2/v3
`MigrationRunner` columns (`visualization_spec`/`response_templates_spec`) — probed via
`pragma_table_info` before each is selected, generalizing `ProductPackStore`'s single
pre-7.13-`verified`-column probe to all eleven; a missing column defaults to the same value the
pre-migration `ALTER ... DEFAULT` clause / v2/v3 migration would have produced (`''`/`'{}'`/
`'auto'`/`'per-device'`/`'[]'` per column, matching the Decision → Schema block above exactly),
so an old and a fully-migrated vintage of otherwise-identical data fingerprint identically.

**Reseed-suppression tombstone consulted during backfill too**, not just the reseed loop — closes
the same resurrection hazard `ProductPackStore`'s `migrate_from_sqlite` closes for
`deleted_pack_ids`: a redeployed/stale-image replica's own untouched legacy file must not
resurrect a definition or set this store has already reported erased into Postgres. Under the
same `kSeedCoordLockSql` as the reseed path's writers, every legacy row's id is checked against
`deleted_seed_content` before being treated as fresh content; a tombstoned definition and every
item that would otherwise reference it are skipped together (there is no FK to violate here,
unlike `ProductPackStore`'s parent/child case, but the skip is still applied uniformly so a
tombstoned definition's `instruction_set_id` never gets backfilled as if it were live).

**Boot ordering — backfill runs strictly BEFORE the seed loop.** Trace the alternative
(seed-first) on an empty-Postgres cutover: the seed loop inserts pristine bundled content for id
X, THEN backfill reads the legacy file's operator-edited copy of X and finds a LIFECYCLE conflict
against the row the seed loop *just* inserted — under the LIFECYCLE rule above, Postgres's
(pristine, un-edited) value silently wins, discarding the operator's edit. That is exactly what
the pinned seed-vs-live test 2 exists to prevent; backfill-first (the shipped ordering) makes the
operator's edited row land first, so the seed loop's later conflict-skip preserves it correctly.
`server.cpp`'s construction sequence is: construct `InstructionStore` (PG) -> `migrate_from_sqlite`
(reads the legacy `instructions.db`, still in place) -> THEN the `kBundledDefinitions`/
`kBundledSets` reseed loop. This ordering is load-bearing, not incidental — a future refactor that
reorders it silently reintroduces the discard.

**The physical `instructions.db` file is not retired by this migration** — `InstructionDbPool`
(a separate SQLite pool onto the SAME file, backing the still-unmigrated `ExecutionTracker`/
`ApprovalManager`/`ScheduleEngine`) keeps reading and writing it after this migration lands; only
the `instruction_definitions`/`instruction_sets` tables within it become dead weight, never
written to again post-cutover. `server.cpp` still constructs `instr_db_pool_` after a successful
`InstructionStore` open+backfill, structurally unchanged from the pre-migration nesting — under
the AUTHORITATIVE/fail-hard posture above, an `InstructionStore` open or backfill failure already
sets `startup_failed_` and refuses the whole boot (ADR-0007: the server requires Postgres
unconditionally, no serving happens on any failure path), so `instr_db_pool_`'s construction
being nested under `instruction_store_`'s success path has no behavioral consequence to decouple
— there is no scenario where PG fails but the server still serves `instr_db_pool_`'s consumers.

**No retroactive tombstone reconstruction.** `deleted_seed_content` is a new Postgres-only table
with no SQLite-side history — a definition deleted under the pre-migration SQLite binary, before
this migration ever shipped, is not distinguishable from "never seeded" by anything this store's
state retains, and cannot be. Only deletes issued after a given replica's cutover to this version
get suppression protection. This is stated here so the ADR does not overclaim what the fix covers
— the same class of residual ADR-0009's `ProductPackStore` update note (2026-08-23) already
accepted as store-scoped, not a general precedent.

### Testing

Three of the four instruction test files construct a store and move to `PostgresTestDb`/
`PgTestTemplate` (`docs/postgres-store-playbook.md`); `test_sensitive_instruction_params.cpp`
tests pure functions with no store construction and is untouched. The seed-vs-live pinning suite
(tag `[instruction_store][seed]`) is **not** ported unchanged — Dave's Option B decision means
test 3 ("trusted reseed RESURRECTS an operator-deleted bundled definition") must now assert the
OPPOSITE against the Postgres store (deletion survives reseed); this is the one deliberate,
ADR-recorded behaviour change this migration makes, not a silent test rewrite to chase green.

## Considered and rejected

- **Option A — preserve resurrection-on-delete exactly, per-definition `ON CONFLICT DO NOTHING`
  advisory-lock-guarded, no suppression table.** Rejected on Codex's independent read, verified
  against `docs/postgres-store-playbook.md`'s named anti-pattern and `RbacStore`'s real shipped
  fix for the identical shape (see Context above). On a shared Postgres substrate the defect is
  materially worse than on per-instance SQLite: any sibling replica boot or rolling restart can
  undo another replica's operator-authored delete, not just that one process's own restart.
- **Hash-based auto-refresh of untouched-but-stale bundled content** (compare a recorded
  last-seeded-hash per id; update only when live content still matches it). A legitimate third
  design, but not a lightweight alternative to a tombstone — the states "never seeded" / "seeded,
  untouched" / "seeded, operator-modified" / "seeded, operator-deleted" still need persistent
  state surviving deletion, which is a tombstone/seed-provenance ledger by another name, plus
  further undesigned decisions (compare-and-swap against a concurrent operator edit, mixed-version
  replica behaviour, rollback/downgrade semantics, audit treatment of an automatic content
  change). Deferred to a follow-up ADR — this migration is a substrate port, not a new content
  lifecycle feature.
- **Two separate tombstone tables** (`deleted_seed_definitions`/`deleted_seed_sets`) instead of
  one `deleted_seed_content(kind, id)`. Rejected for no material benefit — `RbacStore`'s
  `revoked_seed_defaults` already establishes the single-table-plus-discriminator-column shape in
  this codebase; one lock and one table to reason about is simpler than two of each.
- **A LIFECYCLE rank/direction model for definitions, mirroring `DeviceTokenStore`'s `revoked`
  handling.** Rejected — nothing in `InstructionDefinition`'s mutable columns is a security
  control whose legacy-side truth must ever override a live Postgres value (unlike `revoked`,
  which gates authentication); "Postgres's existing value always wins on a LIFECYCLE conflict" is
  simpler and already matches the seed-vs-live rule the reseed loop itself enforces.

## Consequences

- `delete_definition`/`delete_set` gain a `"not_found: "` REST-visible contract (400 -> 404 on a
  missing id, mirroring `ProductPackStore::uninstall`'s identical change) — callers in
  `rest_api_v1.cpp`/`workflow_routes.cpp` must classify it.
- `query_definitions`/`get_definition`/`list_sets`/`export_definition_json` callers across
  `dashboard_routes.cpp`, `discover_routes.cpp`, `mcp_server.cpp`, `policy_evaluator.cpp`,
  `rest_api_v1.cpp`, `schedule_runner.cpp`, `workflow_routes.cpp` now handle a
  `std::expected` and must 503 on a genuine DB error rather than silently treating it as "no
  definitions" — the exact fail-open ADR-0036 exists to close, and the one this migration's
  kickoff called out by name for `execute_instruction`'s definition resolution.
  (`legacy_shim.cpp` only calls `create_definition`, already `std::expected` pre-migration — not
  an affected caller; corrected here after Gate 3 review flagged the original overclaim.)
- **Breaking, deliberate**: resurrection-on-delete of a bundled definition/set is REMOVED.
  Post-migration, an operator-deleted bundled id stays deleted across every future boot and
  release upgrade, on every replica, indefinitely — recorded in a changelog fragment as an
  intentional behaviour change, not a defect fix framed as invisible.
- The untouched-but-stale bundled-content refresh gap (finding 4) is NOT solved by this
  migration — an existing bundled row, touched or not, never picks up newer bundled content
  short of an operator deleting and losing the row (which the tombstone above no longer even
  allows to come back automatically). Tracked in #2555 (pre-existing issue covering the same
  underlying problem), not solved here.
- **Multi-replica backfill correctness (fixed pre-merge, Gate 4 governance finding, further
  corrected at Gate 8):** the backfill's original conflict-comparison over-scoped IDENTITY to
  include `created_at` (definitions) and the full row (sets), both of which legitimately diverge
  across independently-provisioned replicas for bundled content — see "Backfill" above. This
  bricked the boot of every replica after the first to backfill a given bundled id,
  unconditionally, on any real multi-replica fleet. The first fix (`created_by`-only IDENTITY) was
  itself over-corrected — it removed protection against two operator-authored rows sharing an id
  and `created_by` with genuinely different content — and was narrowed further to a
  `created_by`-conditional content check (sentinel = lenient+WARN, non-sentinel = fail-closed) at
  Gate 8 re-review. Both rounds fixed before merge; no release ever shipped either broken version.
- **A later fix round (fixing the Gate 4 backfill finding above) touched code outside the
  Backfill section and is recorded here rather than there:**
  - `schedule_runner.cpp`'s `fire()` no longer calls `advance_schedule` on an InstructionStore
    DB-error branch — a transient failure now retries the occurrence next tick instead of
    permanently losing it (independently found by both `security-guardian` and `sre` at Gate 3).
  - `policy_evaluator.cpp`'s `dispatch_due`/`evaluate_now` throttle-restore-on-store-unavailable
    is CAS-guarded (was an unconditional overwrite that could clobber a concurrent claim); a
    second gap where `evaluate_now` had no restore logic at all is closed; `verdict_for` now
    returns `"error"` on a genuine DB error instead of silently degrading to an empty schema.
  - Seven new `audit_log`/`audit_fn_` calls cover previously-unaudited denial paths:
    `instruction.create`/`.update`/`.delete` on `db_error`, `.delete` on `not_found`, and
    `policy.evaluate` on `store_unavailable` (`compliance_routes.cpp`).
  - `rest_api_v1.cpp`'s `persist_templates` and `workflow_routes.cpp`'s product-pack uninstall
    `instruction_store`-unavailable branch are reclassified from a bare `"not_found: "` to the
    `kInstructionStoreDbErrorPrefix`/`kProductPackDbErrorPrefix` convention (both now alias a
    shared `kDbErrorPrefix` in `store_errors.hpp`), so a genuine DB error 503s instead of 404ing.
- **This fix round's own diff was re-reviewed at Gate 8 and found two further gaps, both closed
  before merge:**
  - `PUT /api/instructions/{id}` fell through to a bare 400 for an unknown id (indistinguishable
    from a validation error) instead of the 404 every sibling route in this migration uses;
    fixed to classify `update_definition`'s `"not_found: "` prefix the same way `DELETE` does.
  - `policy_evaluator.cpp`'s throttle-restore CAS token was the claim timestamp itself — two
    claims on the same policy within the same wall-clock second are indistinguishable, so a
    concurrent claim's restore could in theory clobber a different claim. Replaced with a
    monotonic per-policy `generation` counter (`EvalClaim` in `policy_evaluator.hpp`), captured
    locally at claim time and compared instead of the timestamp.
- **Superseded post-merge, not by this ADR:** the `EvalClaim` generation-counter fix immediately
  above no longer exists. Merging `origin/dev` (PolicyStore's own PG migration, ADR-0056) pulled
  in a durable, fleet-wide `PolicyStore::claim_due_policies` dispatch claim that replaces the
  entire in-memory `last_eval_` throttle map this fix was patching — the ABA hazard is
  structurally absent from a durable atomic claim the way it never can be from a local timestamp
  comparison, so there was nothing to re-apply the fix onto. `dispatch_instruction`/
  `kickoff_check`'s `DispatchOutcome`/`DispatchResult` enum (this ADR's own addition, propagating
  a genuine InstructionStore DB error distinctly from a not-found id) was similarly retired in
  favor of ADR-0056's `std::expected`-based idiom already used throughout that file — the
  InstructionStore DB/lease-failure distinction itself is preserved (grafted onto
  `dispatch_instruction`'s new `std::expected<std::string, std::string>` return, propagated
  through `kickoff_check`/`evaluate_now`/`remediate` the same way those functions propagate their
  own other degrade paths), just no longer via a bespoke enum. See ADR-0056 for the durable-claim
  design and `governance.d/instructionstore-adr0058-gov.4uLptn.jsonl`'s superseding rows for the
  merge-time re-verify.
- No change to the #1073/W7.4 signed-import enforcement semantics, the Ed25519 verify path, or
  the `--allow-unsigned-definitions` operator flag — all pure/storage-independent, ported
  unchanged.
