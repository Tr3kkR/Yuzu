# Postgres store playbook — adding (or migrating) a server store

This is the step-by-step recipe for putting a store into the server's PostgreSQL substrate.
It is the *how*; the *why* lives in the ADRs — **read these first**:

| ADR | What it fixes |
|---|---|
| [0006](adr/0006-server-postgresql-substrate.md) | Postgres is the server substrate; **every** server store migrates (2026-06-22 Update) — none stays SQLite. Agent stays SQLite. |
| [0007](adr/0007-server-single-backend-no-sqlite-fallback.md) | Single backend, **fail closed** — no SQLite fallback. |
| [0008](adr/0008-postgres-substrate-architecture.md) | libpq + in-house RAII, one shared `PgPool`, schema-per-store, `PgMigrationRunner`; **schema naming**, non-transactional-migration rule, thin helper (2026-06-22 Update). |
| [0009](adr/0009-per-store-first-boot-backfill-cutover.md) | How a *migrated* store backfills its legacy SQLite data (one-time, idempotent, fail-closed). |
| [0010](adr/0010-secrets-at-rest-envelope-encryption.md) | Secret-bearing stores use `SecretCodec`, never plain columns. |
| [0012](adr/0012-server-postgres-store-contract.md) | The author-facing **contract**: failure posture, lease discipline, cross-store seam. |

The substrate code is `server/core/src/pg/`: `pg_raii.hpp` (`PgConn`/`PgResult`/`PgTxn`),
`pg_pool.{hpp,cpp}` (`PgPool`, `Lease`, `with_txn`, `Observer`), `pg_migration_runner.{hpp,cpp}`,
`pg_exec.hpp` (`exec_params`). `offline_endpoint_store.{hpp,cpp}` is the reference store.

---

## Decisions you must make up front

1. **Posture** (ADR-0012 §1) — is the store **authoritative** (the DB is the source of truth;
   a runtime error is *surfaced*, never a silent empty result) or **durability-on-top**
   (an in-memory layer is authoritative; a DB blip returns empty/`false` and degrades only
   durability)? Most stores are authoritative. State it in the header comment and the per-store
   ADR.
2. **Schema name** (ADR-0008 Update) — `snake_case(FullClassName)`, the `Store` suffix
   **included**: `WidgetStore` → `widget_store`, `ApiTokenStore` → `api_token_store`. Acronyms
   are one word (`RbacStore` → `rbac_store`); do not give a store class an all-caps acronym.
3. **Secrets?** (ADR-0010) — if any column holds secret material, it is verify-only hash or
   `SecretCodec` envelope-encrypted blob, never plaintext. `api_token`/`ca`/`scim_store` are
   hash-/key_ref-only; `webhooks`, `offload_targets`, `runtime_config` are queued as
   codec-requiring. **`auth` (`auth_db.{hpp,cpp}`) shipped as `SecretCodec`'s first production
   consumer (2026-07-16)** — read it as the worked example. Its actual construction order is
   the opposite of a naive "`init()` before the store opens" reading: `SecretCodec` is
   *constructed* first, but `AuthDB`'s own constructor is what **registers**
   `mfa_totp_secret` as a secret column (schema+table+column+PK-column tuple), and
   `SecretCodec::init(conn)` runs **after** that — `init()` verifies/generates the KEK-wrapped
   DEK for whatever is registered at that point.

   **Instance model — one `SecretCodec` per consuming store, not a shared/fleet-wide
   instance.** `server.cpp`'s construction order is `FileKeyProvider → SecretCodec
   (`auth_secret_codec_`, ctor only) → AuthDB (ctor registers `mfa_totp_secret`) →
   SecretCodec::init() → ScimStore`. `ScimStore` is constructed *after* but takes **no
   `SecretCodec` reference** — it has no secret columns (SCIM tokens stay verify-only hashes),
   so it is never a registrant. A new store with its own secret column(s) should give itself
   its **own** `SecretCodec` instance and follow the same three-step shape end-to-end: construct
   the codec → your store's constructor registers its column(s) → your store's own `init()`
   call runs immediately after (register-before-init, scoped to that one store). Sharing a
   single codec instance across multiple stores is possible in principle, but it requires
   sequencing *every* registrant's construction ahead of one deferred `init()` call — don't
   reach for it without a specific reason; the per-store model is the one this ADR/playbook
   actually prescribes and the one `AuthDB` demonstrates. See ADR-0010's "Instance model" note
   for the full rationale.

   **Two lessons from `WebhookStore` (ADR-0057, `SecretCodec`'s second production consumer)
   for `OffloadTargetStore`/`RuntimeConfigStore` — only the second still applies as written
   under ADR-0009's 2026-08-25 fresh-start-by-default amendment (see the Backfill bullet
   above): those two stores skip `migrate_from_sqlite()` by default, so the first lesson
   below — WebhookStore's backfill-fingerprint design — is not a template to copy unless you
   land in that bullet's documented-exception case. Kept here, not deleted, because it's still
   the right answer IF that exception applies:**
   - **(Only if you build a backfill under the documented-exception case.) A backfill
     idempotency fingerprint over a secret-bearing legacy table must hash only a has-secret
     bit, never the plaintext or a hash of it.** A stored hash of the secret would be a
     SQL-insider brute-force oracle against every legacy signing secret; ADR-0057's fingerprint
     deliberately excludes the secret bytes entirely from what gets hashed for fingerprint-set
     idempotency, while the per-row IDENTITY/LIFECYCLE conflict rule (unaffected by this) still
     protects the row itself.
   - **A secret-bearing store's `KeyProvider`/`SecretCodec` reset in `stop()` must run only
     AFTER that store's own delivery/worker-pool drain completes** — not at the shared top of
     the teardown block alongside every other store's reset. `WebhookStore`'s first fix-round
     attempt got this wrong (the codec reset ran before the delivery-pool drain, silently
     dropping in-flight decrypt-failure audit events during shutdown); the corrected ordering is
     `server.cpp`'s webhook teardown block. Copy that block's *shape*, not necessarily its
     literal position — a store with no worker-pool/background-delivery surface may not need
     this reordering at all.
4. **Authoritative reads must be type-distinguishable (2026-07-25 program policy, ADR-0036).**
   On an **authoritative** store, every read whose result can feed a grant/target/enforce/skip
   decision MUST make a runtime DB error TYPE-DISTINGUISHABLE from "no rows" at the call site —
   `std::expected<T, YourStoreError>` (an `unexpected` for the DB-error case), or
   `std::optional<Container>` where `nullopt` means "degraded, could not read" and an
   empty container means "read fine, genuinely nothing here". **Logging the error is never a
   substitute** — the caller still sees the same empty/false value either way. The store exposes
   the typed channel unconditionally; the *caller* then applies the reviewer test: **"if this
   value were silently empty/false, could any downstream branch grant / target / enforce / skip
   / invert (`NOT`) / report success? If yes, treat a DB error as fail-closed (abort the
   operation / return 503) — never as an empty result."** Pure render/telemetry callers (a
   dashboard preview, a metrics gauge) may legitimately render degraded with the error in hand —
   they don't feed a decision. The concrete motivating bug (`ResultSetStore::member_set_owned`,
   ADR-0036): a `NOT from_result_set:<id>` scope resolves a missing preload entry to "no match",
   and `NOT` inverts "no match" to "matches every agent" — so a transient Postgres blip that used
   to come back as a silently-empty membership set turned into a fleet-wide command-dispatch
   fail-open, not a theoretical one. Reads whose failure mode is deny-or-benign (a sidebar list
   comes back empty, a lineage breadcrumb trail is short) may defer widening to a follow-up — but
   say so explicitly in the PR/issue, don't just leave it unstated.

---

## Recipe — a new (greenfield) store

1. **Header** declares the substrate contract (copy `offline_endpoint_store.hpp`): the store
   holds a `pg::PgPool&` (not a `sqlite3*`), runs its migration at construction on a pinned
   lease, schema-qualifies every runtime statement, and uses `RETURNING` for mutate-and-return.
   State the posture in the doc comment.

2. **Migrations** — a `static const std::vector<pg::PgMigration>` of `{version, sql}`. DDL is
   **unqualified** (the runner sets `search_path` to your schema for the migration txn). One
   schema per store; `CREATE TABLE foo (...)` lands in your schema. See the
   non-transactional-migration rule below before adding an index to a table that will be large.

3. **Construct** via the thin helper (do not hand-roll): acquire a lease, run
   `PgMigrationRunner::run(lease.get(), "<schema>", migrations())`, set `open_`. The helper
   (`open_with_migrations`) makes this one call; `is_open()` is false if the lease was empty or
   the migration failed.

4. **Runtime statements** schema-qualify the table (`SELECT ... FROM widget_store.widgets`) —
   pooled connections carry **no** per-store `search_path`. Bind parameters with
   `pg::exec_params` (`$1..$N`); never string-concat SQL. Mutate-and-return uses `RETURNING`
   (the #1033-banning idiom), never `sqlite3_changes()`.

5. **Lease discipline** (ADR-0012 §2): every runtime acquire is **bounded**
   (`try_acquire_for(deadline)`) — pick the deadline from posture (hot-path fail-soft: short,
   e.g. 250 ms; user-facing authoritative: longer, e.g. 2 s). Unbounded `acquire()` is
   construction-only. Never hold a lease across network/disk/external work. Never call another
   store while holding a lease (one lease per logical operation).

   *Caching an authoritative read?* Do not invent the rules — **ADR-0012 §4** ("Read caching on
   an authoritative store") encodes the five that this seam demands: positive-only, invalidate
   synchronously on your own writes under a generation guard, report provenance, never serve a
   fresh authorization decision from cache, and bound every map on its own insert path.
   `EnginePrincipalStore`'s liveness cache (#2367) is the worked example.

6. **Wire into `server.cpp`** via the construction helper, after the `PgPool` probe and inside
   the `if (pg_pool_ && !startup_failed_)` guard. A Postgres store that cannot open is a **fatal
   startup error** — the helper flips `startup_failed_` on `!is_open()`. Member-declare the
   store so it destructs *before* the pool (declaration order governs destruction order; the
   pool resets last in `stop()`).

7. **Tests** use `PostgresTestDb` + `YUZU_REQUIRE_PG_DB(var)` (behind `YUZU_TEST_ENABLE_PG`,
   server suite only). Skip-vs-fail contract: env unset → skip cleanly; env set but broken →
   fail. Local: `docker run -d -e POSTGRES_USER=yuzu -e POSTGRES_PASSWORD=yuzu -e
   POSTGRES_DB=yuzu -p 5433:5432 postgres:18` then
   `export YUZU_TEST_POSTGRES_DSN=postgresql://yuzu:yuzu@localhost:5433/yuzu`.

   **Store-behaviour tests must use the pre-migrated template variant** — declare a
   `PgTestTemplate` per file whose setup constructs the store(s) under test (files needing the
   exact same store set may share a template key — the registry builds each key once, and every
   additional setup attaching to the key is replay-verified against a fresh scratch database —
   a structurally divergent setup, additive OR subset, fails its tests loudly instead of
   inheriting the wrong template), and open each test with `YUZU_REQUIRE_PG_DB_TPL(var, tpl)`: the ephemeral database is then cloned
   (`CREATE DATABASE … TEMPLATE`) with every migration already applied, instead of re-running
   the store's migration DDL per test — per-test migrations were the dominant, worst-scaling
   cost of the `[pg]` set on the contended Windows runners (2026-07-12 server-suite timeout).
   Keep plain `YUZU_REQUIRE_PG_DB` only for tests that exercise migration, fresh/empty-
   database, or pg-substrate behaviour itself (pg_pool/pg_raii/pg_hardening need no
   migrations, so a template buys them nothing). Full contract: the `PgTestTemplate` doc
   comment in `tests/unit/test_helpers.hpp`.

   High-volume store-behaviour files may instead keep one template clone and pool for the
   file, then completely reset its rows with `TRUNCATE … RESTART IDENTITY CASCADE` before
   each case. The fixture owns the pool in `std::optional<PgPool>` and passes a non-throwing
   reset callback to `PostgresTestDb::keep_until_run_end()`; the Catch2 run-end listener
   drains that pool before dropping the clone while libpq is still alive. Use this only when
   the reset names every mutable table and no state escapes through a lease or background
   thread. Tests that alter DDL or `public.schema_meta`, retain session/advisory-lock state,
   or otherwise cannot be restored by `TRUNCATE` remain on their own per-test clone. Filtered
   and randomized runs must pass, and the lifecycle regression in
   `test_pg_template_cleanup.cpp` must continue to prove drain-before-drop ordering.

8. **`meson.build`** — add the new `.cpp` to the server target (and the test). `libpq_dep` is
   already gated on `build_server`.

9. **Docs** — per-store ADR (schema + posture + secrets), user-manual touch if operator-facing,
   and tick the store off `docs/postgres-migration-ladder.md` (greenfield stores are added to
   the ladder as "born-on-Pg, no backfill").

## Extra steps when migrating an existing SQLite store

- **Backfill — fresh-start-by-default (ADR-0009, amended 2026-08-25): do NOT build
  `migrate_from_sqlite()` for a new migration unless you have a specific, documented reason to.**
  No production fleet has ever run a pre-Postgres build of any Yuzu store, so the original
  "mandatory for config/reference and audit" default assumed real legacy data that has never
  existed — skip the legacy-file *copy* entirely, the same unconditional way `ResponseStore`
  already does (no flag, no `migrate_from_sqlite()`, no legacy-file read; note `ResponseStore`
  does NOT log anything beyond its generic "initialized" line — there is no distinct fresh-start
  log anywhere in this codebase today to model a new one on). **New requirement, not inherited
  from that precedent: for a store holding real operator-authored config or secrets (this bites
  hardest for the two Wave 3 stores below), skip the data copy but do NOT skip detection** — check
  whether the legacy file exists and is non-empty, and if so `spdlog::warn` a row/key count
  before proceeding fresh-started, so an environment where the "no production fleet" premise
  turns out to be locally wrong gets a loud signal instead of the silent loss `ResponseStore`'s
  actual (undetected) behavior would otherwise reproduce for stateful config. This default
  holds only while "no production fleet" stays true — if a real external deployment exists or
  is committed to before your store migrates, re-derive whether backfill is actually needed for
  THIS store in its own per-store ADR; don't cite this bullet as blanket cover once the premise
  has changed. (Historical note: the original mandatory-backfill mechanism this bullet used to
  describe — a one-time, idempotent `migrate_from_sqlite()` running at startup, before serving,
  failing closed on any error — is still what every already-migrated store built, and stays in
  place for those stores. See ADR-0009's amendment for the full rationale.)
- **Secret columns transform, never copy** (ADR-0010): applies only if you DO build a backfill
  under the documented-exception case above — a backfill that touches secret material
  encrypts/hashes on the way in, a plain column copy of a secret is forbidden. For the
  skip-by-default case, this bullet doesn't apply (there's no column copy to transform); see the
  detect-and-warn requirement above instead for that case's own obligation on secret-bearing
  legacy files.
- **Rollback window**: retain the legacy `<name>.db` for exactly one release, then remove it.
  Backfill opens it read-only; a wired subject/device erasure path must delete that identity
  from the rollback copy so rollback cannot resurrect erased data. The upgrade-test
  (`scripts/test/docker-compose.upgrade-test.yml`) must assert the
  config/reference/audit data survives previous-release-SQLite → new-release-Postgres.
- **Port the transaction owner**: `SqliteTxn`/`SqliteStmt` → `pool.with_txn` (multi-statement
  invariants) or a single autocommit statement (single-statement mutate-and-return).
- **Local source absence never creates terminal migration state on its own** (ADR-0040 round 3,
  Sol's diagnosis, #2697). A process that finds no legacy SQLite file at its configured path
  cannot distinguish "this is a genuine fresh install" from "this replica just doesn't hold the
  file — a sibling does." Marking a migration COMPLETE from that observation alone is silently
  unsound: it forecloses the real migration for whichever host does hold the file, and no
  amount of guarding on the sourceless side closes the gap, because the sourceless process is
  telling the truth about what IT knows, not about the fleet. The fix has two parts, and the
  first alone is insufficient: (1) restrict *which* callers may declare "no source, nothing to
  migrate" — a one-shot CLI is never trusted to, only a full boot; (2) **on the HOLDER side**, a
  process that finds the completion marker already set but still holds its own legacy file must
  not trust that marker blindly — verify the file's content was actually what got migrated
  (`AuditStore` does this by fingerprint: a durable hash-shaped value written in the SAME
  transaction as the completion marker, re-derived from the file and compared at every later
  boot that still finds it) and refuse to serve on a mismatch, rather than silently reporting
  success over a trail nobody streamed. `ManagementGroupStore` and `ResultSetStore` share the
  first-generation `if (!legacy_exists) → mark complete` shape this closes; porting the
  holder-side check to them is tracked, not yet done. `RbacStore` independently discovered and
  fixed the identical shape (#2703, git-blamed to its original migration commit, not caught by
  that migration's own governance pass or two rounds of external review — only surfaced by a
  wider-scope adversarial review) — it is now a SECOND reference implementation, right-sized for
  a small, non-resumable, single-transaction legacy dataset rather than `AuditStore`'s larger
  resumable-streaming one. **Trap a future port hits if it works from this paragraph's prose
  instead of the actual code:** `AuditStore::stamp_complete` has two exemptions this description
  doesn't spell out and `RbacStore`'s own first port missed both — (1) a **sourceless** writer
  losing the trust-anchor race is NOT an error (it has no evidence worth protecting, so whichever
  writer's `"sourceless"` value won is fine); (2) a **real** writer's content that fingerprints as
  having nothing to protect (an empty/schema-less local file) should trust the marker rather than
  refuse. Port the REFERENCE CODE (`audit_store.cpp`'s `stamp_complete`, or `rbac_store.cpp`'s
  post-#2703 version) and diff your port against it line by line — not this summary.
- **Long-lived migration branches accumulate test-file drift against the pre-migration API —
  budget for it on every `dev`-merge, not just the first.** Any test file that constructs the
  store via its old constructor fails to compile once the branch merges current `origin/dev` —
  whether that file already existed and gained new cases in `dev` while the migration branch was
  in flight, or is brand new, added by an unrelated, already-merged PR that forked before the
  migration branch did. The CI merge-ref build fails on all platforms either way; this is not a
  defect in the migrating branch's own work, and it recurred twice within `AuditStore`'s own
  migration (#2697): once against an existing file gaining cases in `dev`, once against a
  brand-new file from an unrelated already-merged PR. The fix is always the same mechanical
  shape: migrate the test's construction to `PgTestTemplate`/`PgPool` following an established
  Harness in the same directory, reconcile any call site relying on the old return type (the
  previous bullet's decision on authoritative-read typing), give the migrated fixture its own
  explicit `if (pg_admin_dsn_env() == nullptr) SKIP(...)` guard if it has no earlier-constructed
  PG member to inherit one from (copying a Harness's SKIP-via-earlier-member shape onto a
  fixture that lacks that earlier member silently turns "skip locally" into "hard-fail
  locally"), and tag `[pg]` on exactly the `TEST_CASE`s whose bodies construct the migrated
  fixture — verified per case, never blanket-applied to the file. A branch expected to outlive a
  single `dev`-sync cycle should re-sync frequently: a smaller delta is easier to triage for
  which changed test file touches the store's old constructor.

## Anti-patterns reviewers reject

- An **authoritative** store that returns an empty result on a DB error (fail-open). Surface it.
- Unbounded `acquire()` on a runtime path. Bound it.
- Holding a lease across an HTTP call, file I/O, or a second store call (deadlock / starvation).
- Unqualified runtime table names (works in a migration, breaks on a pooled connection).
- `sqlite3_changes()`-style mutate-then-count. Use `RETURNING`.
- Trusting `PQresultStatus() == PGRES_COMMAND_OK` on an `INSERT ... ON CONFLICT DO NOTHING` to mean
  YOUR value won. It only means the statement executed — true whether the row inserted or silently
  no-opped on conflict. A "first writer wins" contract (a completion marker, a trust-anchor
  fingerprint, an idempotency key) needs `PQcmdTuples()` (`"0"` = lost the race) or `RETURNING` +
  `PQntuples()` to actually answer "did MY write land". `AuditStore::stamp_complete` (ADR-0040,
  #2697) is the worked example: checking only statement status let a real backfill that lost this
  exact race report success while a different writer's value sat at the trust anchor — the same
  silent-discard shape as the `sqlite3_changes()` pitfall above, just on `ON CONFLICT DO NOTHING`
  rather than a mutate-then-count. **When "first writer wins" is too strict** — some values carry
  no evidence worth protecting (a sourceless placeholder) or two writers can legitimately agree
  (identical content from a shared volume) — plain `DO NOTHING` can't express that; use `DO
  UPDATE ... WHERE <promotable-condition> RETURNING <col>` instead, and read success via
  `PQntuples() == 1` (the WHERE matched: fresh insert, a promotion, or an already-equal value),
  never `PQcmdTuples()` on a `DO UPDATE` (it reports rows affected by the WHOLE statement,
  conflating "this row was promoted" with "this row already held my value" — both fine, but
  neither is a `DO NOTHING`'s simple insert/no-op binary). `RbacStore::stamp_complete` (#2703) is
  the worked example: a real fingerprint may promote a stored `"sourceless"` value; a stored real
  value is never overwritten by anyone; a writer whose value already equals what's stored counts
  as success rather than a spurious lost-race failure. Verify the exact upsert against a live
  Postgres instance before shipping it — `ON CONFLICT ... DO UPDATE ... WHERE` semantics are easy
  to get subtly wrong by reasoning alone.
- A plaintext secret column. Use `SecretCodec` / verify-only hash.
- A new server **SQLite** store (ADR-0006 forbids it without an exception ADR).
- A `CREATE INDEX CONCURRENTLY` / `VACUUM` / `ALTER TYPE ADD VALUE` smuggled into a
  `PgMigration` — it cannot run in the runner's transaction (see below).
- A **counting aggregate** (`count(*)`, `count(*) FILTER (...)`) where the question is only
  "does at least one row exist?" (`AuditStore`'s retention probe, ADR-0040). A count with no
  statement-level `WHERE` visits every row before either count is known, including rows that sit
  outside a partial index built for the "any?" question — full-scanning the one table designed
  to grow without bound, on every pass. Use `EXISTS(SELECT 1 FROM t WHERE cond)` (or, when the
  predicate is a range and the planner's selectivity estimate for that range cannot be trusted —
  a wide window with real matches sparse and clustered at one end — `ORDER BY <indexed column>
  LIMIT 1 ... IS NOT NULL`, which is plan-independent: a Seq Scan would need a full sort before
  applying the `LIMIT`, so the index-ordered path wins regardless of the estimate).
- A **fixed re-arm interval** on a capped, paced background pass (a retention sweep, a rollup, a
  reconciliation loop) that never shortens when the cap keeps binding. If a pass hits its cap AND
  a genuine backlog remains, the NEXT pass should re-arm on a short floor (seconds, not the full
  interval) and keep doing so until a pass clears the backlog — otherwise the cap silently
  becomes a permanent drain ceiling far below what the pass could actually sustain (`AuditStore`
  measured this at ~700x: a docs section that quoted only the full-interval cadence as "the"
  sustained ceiling was off by roughly three orders of magnitude once the re-arm floor was
  accounted for). Document BOTH cadences wherever a "ceiling" figure is quoted — the quiet-
  operation rate and the backlog-recovery rate are different numbers with different meanings,
  and quoting only the first as a hard limit understates real capacity.
- Assuming a per-operation `timeout` parameter (a `with_txn_for(kFooTimeout, ...)` call, or any
  similarly-named constant) bounds **statement execution**. It only bounds the pool-ACQUIRE wait
  (see "Pool connection setup†" below) — every connection the pool hands out carries the same
  fixed, pool-wide `statement_timeout` GUC for actual query execution regardless of what the
  caller's own timeout constant is named or documented to mean. An unqualified long-running query
  (a full-table scan, an unindexed aggregate) needs its OWN explicit `SET LOCAL statement_timeout
  = '<ms>'` as the first statement inside a `pool.with_txn`/`with_txn_for` callback — never a bare
  `SET`, which leaks the widened deadline onto the connection's next, unrelated caller once it's
  returned to the pool. This mismatch has recurred twice in this codebase without ever being
  written down here: #2530 (a metrics sampler assuming a bounded-`acquire()` deadline also bounded
  its query) and `AuditStore::migrate_from_sqlite`'s whole-file reconciliation scan (ADR-0040,
  #2697 round 3) — the second one initially repeated the first's mistake even while citing it as
  precedent, and initially hand-rolled `BEGIN`/`SET LOCAL`/`COMMIT`/`ROLLBACK` instead of using the
  already-available `pool.with_txn` + `pg::PgTxn` RAII guard before a second review round caught
  it. `SoftwareLicensingStore::count_stale_agents` is the clean reference implementation of the
  correct shape.
- A hard `DELETE` to revoke a row that an unconditional reseed pass (a `seed_defaults()`-style
  step re-run on every construction, `ON CONFLICT DO NOTHING`) can silently reinsert. A deleted
  row leaves nothing for the reseed's conflict target to match, so the very next restart
  resurrects the seeded default — the operator's revocation is undone on ordinary
  restart/redeploy, no attacker required. `RbacStore::remove_permission` (#2703, fjarvis) is the
  reference case, and it took THREE rounds to land correctly — the wrong two are as instructive as
  the right one. Round 1 (bare `DELETE`) had exactly this bug. Round 2 upserted an explicit `deny`
  row instead, on the theory that "the authorization outcome is identical either way (no matching
  allow → deny)" — **false when the row's table feeds anything beyond a single positive/negative
  check.** `RbacStore`'s reader applies "deny overrides everything, across ALL of a principal's
  held roles" (a pre-existing invariant, not new), so a real deny row from the revoked role vetoed
  an allow the SAME principal held via a DIFFERENT role — an authorization change nobody
  authorized, on both the global check and a management-group-scoped visibility read. Round 3
  (shipped): DELETE the row (so the read path sees exactly what the operator authored — absence,
  same as if the grant never existed) and record the revocation SEPARATELY, in a dedicated
  bookkeeping table (`revoked_seed_defaults`) consulted ONLY by the reseed step's own grant
  helper — never by anything that makes an authorization decision. **The general rule: don't
  represent "suppress the next reseed" as a fact your read path can see.** A tombstone using the
  same effect/value the read path already interprets is only safe if that value is neutral
  everywhere it can be read — verify this for every reader (a scoped/confinement path is easy to
  miss when the store also has a "global" check), not just the one you're staring at. When in
  doubt, a separate table costs one migration and guarantees it structurally.

  Round 3 shipped a FOURTH bug on top, chaos-tested and closed the same week: `INSERT ... SELECT
  ... WHERE NOT EXISTS (marker) ... ON CONFLICT DO NOTHING` — a reseed step checking the
  bookkeeping table above before granting — is **not safe against a concurrent writer of that
  bookkeeping table** without an explicit lock. A statement's READ COMMITTED snapshot is fixed
  ONCE, at that statement's start, before any of its own function calls run. If the reseed's
  snapshot is taken before a concurrent revoke's marker-insert commits, but the reseed's `INSERT`
  then blocks on the `ON CONFLICT` arbiter waiting for that SAME revoke's uncommitted `DELETE` of
  the conflicting row, Postgres — once the revoke commits — only re-checks the CONFLICT TARGET
  (now gone); it does NOT re-evaluate the `WHERE NOT EXISTS` subquery, which is still reading the
  pre-revoke snapshot. The reseed's already-computed row lands anyway: the marker AND the
  resurrected row both end up present, permanently — nothing ever re-syncs the data table against
  the bookkeeping table. Verified empirically (two real connections, one held open uncommitted,
  the other genuinely blocked and measured). **The lock must be its own statement, in an explicit
  transaction, strictly BEFORE the statement that checks-and-mutates** — a `pg_advisory_xact_lock`
  embedded via a CTE in the SAME statement as the check does NOT work, for the identical
  fixed-snapshot reason: blocking mid-statement never refreshes that statement's snapshot. Fix
  shape: `BEGIN; SELECT pg_advisory_xact_lock(...); <check-and-mutate>; COMMIT;` in every writer of
  both the data table and the bookkeeping table, all keyed to the same lock (a fixed/coarse key is
  fine — this class of write is never a hot path). `RbacStore`'s three writers
  (`seed_defaults()`'s grant, `remove_permission`, the backfill's revoke block) are the reference
  case (`kRevokeCoordLockSql`).

## Non-transactional migrations (the deferred kind)

`PgMigrationRunner` runs every migration in a transaction (`SET LOCAL search_path` requires it),
so statements that cannot run in a transaction block — `CREATE INDEX CONCURRENTLY`, `VACUUM`,
`ALTER TYPE ... ADD VALUE` — **cannot** be a `PgMigration` today. The non-transactional migration
kind is **deliberately not built yet** (no store needs it). The rule:

- Initial DDL on a **new/empty** table uses normal transactional migrations — a plain
  `CREATE INDEX` on an empty table takes a trivial lock and is fine.
- An index/DDL added to an **already-large** table during a live rolling upgrade would take a
  multi-minute `ACCESS EXCLUSIVE` lock with a plain `CREATE INDEX`. That requires the
  non-transactional kind, which **must be built** (self-schema-qualifying, runs outside a txn)
  *before* such a migration ships. Do not weaken the transactional default to sneak one in.

## Substrate quick facts (pool / runner / helpers)

Design facts every store author inherits (previously recorded only in CLAUDE.md and the
2026-06-18 conformance register; #1368 readiness items marked †):

- **Pool connection setup†**: `statement_timeout`/`lock_timeout` GUCs injected on every pooled
  connection; TCP keepalives enabled.
- **Connect-failure circuit breaker†**: exponential backoff + jitter; while open, acquires
  fail fast (no connection storm against a down Postgres).
- **Observability†**: `PgPool::Observer` hooks feed `yuzu_pg_pool_{in_use,open,size}` gauges,
  `yuzu_pg_{connect_failed,acquire_timeout,unhealthy_discard}_total` counters, and the
  `yuzu_pg_acquire_wait_seconds` histogram. Pool live-probe + every store's `is_open()` join
  the `/readyz` conjunction. Chaos coverage: CH-9/10/11 (pool exhaustion, PG down at boot,
  PG lost at runtime).
- **Runner guards**: schema-drift guard — a schema at version 0 that already contains tables is
  refused (never blindly re-run migration 1). Concurrent runners (multi-process boot) are
  serialized by a cluster-wide `pg_advisory_xact_lock`. Store/schema names must match
  `[a-z_][a-z0-9_]{0,62}` and must not be `public`/`information_schema`/`pg_*`. **Duplicate/
  non-monotonic version guard (#3013, #2961/#2964):** `run()` checks a store's own
  `migrations()` vector up front — strictly increasing by `version`, first version `> 0` —
  and refuses the WHOLE call (nothing applied) on a duplicate, a descending pair, or a
  non-positive first version, rather than letting the apply loop's `version <= current` skip
  silently swallow whichever migration collided. This catches a collision baked into the
  CALLING binary's own vector; it cannot see a version already recorded in `schema_meta` by a
  DIFFERENT binary that shipped before the guard existed — a second, independent line of
  defence for that case is a post-migration projection smoke-read at the store's own
  construction site (a `LIMIT 0` SELECT of every column the store's runtime queries actually
  select, including any column masked to `''` in read-only projections — see
  `ApiTokenStore`'s constructor for the reference shape), which fails the store closed
  (`!is_open()`) rather than surfacing an `undefined column` on whichever request runs first.
- **Error/RAII hygiene**: malformed-conninfo errors are reported as a fixed string (never
  libpq's token-quoting parse error, which can echo credential fragments); libpq-allocated
  buffers are freed only with `PQfreemem`/`PQconninfoFree`.
- **`pg/pg_array.hpp` `pg::to_text_array`**: serialises a string sequence to a Postgres
  text-array literal for `unnest()`-style batched inserts. Always-quotes, escapes `\` and `"`,
  and **drops `0x00`** — NUL is not transmittable in libpq text format, so callers must not
  rely on NUL surviving the round-trip.
