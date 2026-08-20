# ADR-0056: PolicyStore → PostgreSQL (Wave 2, batch 6)

- **Status:** Accepted
- **Date:** 2026-08-20
- **Deciders:** pg workstream (kickoff `.claude/plans/pg-migrate-policy-store-KICKOFF.md`); the
  multi-replica evaluator design below is the "genuinely new PG problem" the kickoff assigned this
  ADR to settle.
- **Parents:** ADR-0006/0007/0008(+Correction), ADR-0009, ADR-0012, ADR-0036 (typed reads).
  Closest posture precedent: `RbacStore`/`TagStore`/`CustomPropertiesStore` (authoritative,
  dispatch/compliance-feeding reads must be degrade-distinguishable). Closest backfill-shape
  precedent: `SoftwareDeploymentStore`/ADR-0051 (multi-table-with-FKs, single fingerprint over all
  tables, IDENTITY/LIFECYCLE partition). Advisory-lease precedent: `AuditStore`/ADR-0040 (single
  reap sweeper) and `AnalyticsEventStore`/ADR-0049 (3-phase CLAIM/SEND/REVERT when a lease can't
  span external I/O) — this store needs a third variant, below.

## Context

`PolicyStore` (`server/core/src/policy_store.{hpp,cpp}`, ~190+1308 lines) is the compliance
engine's definition + status store: **six tables** — `policy_fragments` (a check/fix/postCheck
instruction bundle + CEL compliance expressions, authored as `PolicyFragment` YAML),
`policies` (binds a fragment to a scope, authored as `Policy` YAML), `policy_inputs`,
`policy_triggers`, `policy_groups` (fan-out detail tables for a policy, `ON DELETE CASCADE`), and
`policy_status` (one row per `(policy_id, agent_id)`, the evaluator's only write target).

**A load-bearing fact this migration's design leans on**: `policy_fragments` and `policies` (and
their three detail tables) have **no update path** — `store_inputs`/`store_triggers`/
`store_groups` are called exactly once, from `create_policy`. Only `policies.enabled`/
`updated_at` (via `enable_policy`/`disable_policy`) and the entire `policy_status` table mutate
after creation. This makes the backfill IDENTITY/LIFECYCLE partition unusually clean (see
Backfill below).

`PolicyEvaluator` (`policy_evaluator.{hpp,cpp}`) drives check→verdict→status on a background
thread: `tick()` = `collect_ready()` then `dispatch_due()`, cadence 10s (`server.cpp:15825`,
`for (2) sleep(5s)`), grace 15s (`Deps::grace_seconds`), an operator-interval floor of 60s
(`dispatch_due()`, `policy_evaluator.cpp:340`), default interval 3600s
(`Deps::default_interval_seconds`). `polchk-*` execution ids are minted by the evaluator and
skipped by `notify_exec_tracker` (unchanged by this migration).

### The multi-replica problem, precisely

On SQLite there is exactly one server process, so exactly one `PolicyEvaluator`. Moving
`PolicyStore`'s *data* onto a shared Postgres substrate does not, by itself, make N server
replicas' evaluators safe to run concurrently, because **`PolicyEvaluator`'s dispatch/collect
coordination state is entirely in-process memory, not in `PolicyStore` at all**:

- `last_eval_` (an `unordered_map<policy_id, int64_t>`) is the *sole* due-ness source —
  `dispatch_due()` reads and claims it under `mu_`, then dispatches lock-free. Nothing durable
  records "when was this policy last dispatched."
- `in_flight_` (a `vector<InFlight>`) is the *sole* record of "a check/fix was dispatched and is
  awaiting a response." `collect_ready()` only ever looks at this replica's own `in_flight_`.
- The constructor unconditionally resets every `policy_status` row with `status == "fixing"` to
  `"unknown"` on every construction (`policy_evaluator.cpp:206-232`, comment "gov REC-1/UP-4") —
  a boot-time-only reconciliation for the single-process case ("a restart stranded this").

Ported unmodified onto N replicas, three failures follow: (1) each replica's `last_eval_` is
independent, so N replicas each conclude a policy is due at the same tick → N× dispatch of the
same check to the same agents (the kickoff's "N× dispatch of `polchk-*` checks"). (2) Whichever
replica dispatches is the *only* replica whose `in_flight_` holds that check — if a different
replica later wins any per-tick coordination, or the dispatching replica restarts, that check's
response sits in `response_store` forever uncollected: the policy's compliance for those agents
never resolves. (3) A replica restarting (a normal rolling-deploy event, not a crash) would stomp
**every** `fixing` row fleet-wide, including ones another replica is legitimately mid-remediation
on — turning a routine deploy into spurious remediation resets.

### Design considered and rejected: session-scoped leader election

A single long-held `pg_advisory_lock` (session-scoped, not `_xact_`) electing one replica as "the"
evaluator for its entire process lifetime would preserve `in_flight_`'s validity (the same process
stays leader across many ticks). Rejected: it is a new locking primitive with no precedent in this
codebase (all 6 existing `pg_try_advisory_xact_lock` call sites are transaction-scoped, stateless,
one-shot sweeps); it needs a dedicated connection held outside the bounded-lease pool with its own
liveness/split-brain handling to build and test from scratch; and it does not even fully solve the
stranded-`in_flight_` problem — a rolling deploy still kills the leader eventually, and whatever
replica wins next still starts with an empty `in_flight_`, orphaning anything the old leader had
outstanding. Also rejected: promoting `in_flight_` itself to a durable table (a new "dispatch
ledger" tracking every outstanding check). That does fully solve the problem, but in-flight state
is inherently re-derivable — losing it costs one interval's delay on the affected agents' verdicts
(a window the system already tolerates via the crash-recovery path), so building and testing a
durable ledger is scope this migration (already the largest store in the wave) does not need.

## Decision

**Split the fix by phase, matching the two things that actually differ**: dispatch decisions need
fleet-wide dedup (single-sweeper lease, now durable in `PolicyStore`); collect/verdict-write stays
per-replica and at-least-once, made safe by `update_agent_status`'s existing UPSERT idempotency.

### Schema: `policy_store`, seven tables

The original six, migrated as-is (see per-table notes below), plus one new **operational, non-
backfilled** table:

```sql
CREATE TABLE policy_fragments (
    id                     TEXT PRIMARY KEY,
    name                   TEXT NOT NULL,
    description            TEXT NOT NULL DEFAULT '',
    yaml_source            TEXT NOT NULL,
    check_instruction      TEXT,
    check_compliance       TEXT,
    check_parameters       TEXT NOT NULL DEFAULT '{}',
    fix_instruction        TEXT,
    fix_parameters         TEXT NOT NULL DEFAULT '{}',
    post_check_instruction TEXT,
    post_check_compliance  TEXT,
    post_check_parameters  TEXT NOT NULL DEFAULT '{}',
    created_at             BIGINT NOT NULL DEFAULT 0,
    updated_at             BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE policies (
    id               TEXT PRIMARY KEY,
    name             TEXT NOT NULL,
    description      TEXT NOT NULL DEFAULT '',
    yaml_source      TEXT NOT NULL,
    fragment_id      TEXT NOT NULL REFERENCES policy_fragments(id),
    scope_expression TEXT,
    enabled          BOOLEAN NOT NULL DEFAULT TRUE,
    created_at       BIGINT NOT NULL DEFAULT 0,
    updated_at       BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE policy_inputs (
    policy_id TEXT NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    key       TEXT NOT NULL,
    value     TEXT NOT NULL,
    PRIMARY KEY (policy_id, key)
);

CREATE TABLE policy_triggers (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    policy_id    TEXT NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    trigger_type TEXT NOT NULL,
    config_json  TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE policy_groups (
    policy_id TEXT NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    group_id  TEXT NOT NULL,
    PRIMARY KEY (policy_id, group_id)
);

CREATE TABLE policy_status (
    policy_id         TEXT NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    agent_id          TEXT NOT NULL,
    status            TEXT NOT NULL DEFAULT 'unknown',
    last_check_at     BIGINT NOT NULL DEFAULT 0,
    last_fix_at       BIGINT NOT NULL DEFAULT 0,
    check_result      TEXT NOT NULL DEFAULT '',
    fix_attempt_count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (policy_id, agent_id)
);
CREATE INDEX policy_status_status_idx ON policy_status (status);

-- Operational only — NOT backfilled, NOT operator intent (see Backfill).
CREATE TABLE policy_dispatch_state (
    policy_id          TEXT PRIMARY KEY REFERENCES policies(id) ON DELETE CASCADE,
    last_dispatched_at BIGINT NOT NULL DEFAULT 0
);
```

Changes from the SQLite v1+ALTER original, each deliberate:

1. **The ALTER-wart (`fix_attempt_count`, G4-UHP-POL-003) folds straight into `policy_status`'s
   v1 `CREATE TABLE`** — PG v1 ≡ SQLite v1+ALTER. There is no PG-side equivalent of the wart
   (a fresh PG schema has no pre-v0.10 legacy state to reconcile), but the **backfill** must still
   tolerate a legacy SQLite file predating the wart (missing the column) — see Backfill.
2. **`policy_status` gains a real FK + `ON DELETE CASCADE` to `policies`** (it had none in
   SQLite — the only one of the five detail/status tables without one; `delete_policy` cleaned it
   up with a hand-written `DELETE` whose prepare/step failure was silently swallowed). The FK
   makes that cleanup declarative and unconditional; `delete_policy`'s manual second delete is
   removed.
3. **`policies.enabled`**: `INTEGER` (SQLite bool-as-int) → `BOOLEAN` (the C++ field is already
   `bool`).
4. **`policy_triggers.id`**: `AUTOINCREMENT` → `GENERATED ALWAYS AS IDENTITY` (nothing external
   references this id; safe to remap, same as `LicenseStore::license_alerts.id`).
5. **`policy_dispatch_state` is new** — see Decision below.

### Posture (ADR-0012 §1) — split by table class, not one blanket rule

- **`policy_fragments`/`policies`/`policy_inputs`/`policy_triggers`/`policy_groups`
  (operator-authored intent): AUTHORITATIVE/fail-hard.** Every mutator already returns
  `std::expected` in the SQLite original and keeps that discipline; a DB error surfaces, never a
  silent no-op. `query_fragments`/`get_fragment`/`query_policies`/`get_policy` (currently
  empty/`nullopt`-on-prepare-failure, indistinguishable from "not found") become
  degrade-distinguishable per ADR-0036: **`PolicyEvaluator::dispatch_due()`'s claim path is the
  concrete grant/skip decision these reads feed** — a degraded read must not silently resolve to
  "no policies exist," which would read as "fleet compliant" on the dashboard. REST/dashboard
  reads (`ComplianceRoutes`) 503 on a degraded read rather than rendering an empty policy list
  (matches `DiscoveryStore`/`CustomPropertiesStore`'s "an operator asking must not be told
  'nothing' when the real answer is 'could not ask'").
- **`policy_status` (evaluator-written verdicts): AUTHORITATIVE for the write path** (an
  evaluator tick that cannot write a verdict must not silently succeed — `update_agent_status`
  keeps its `std::expected` and the evaluator now logs+counts every failure, closing the
  ~11-call-site swallow inventory below), **degrade-distinguishable for reads that feed
  `get_fleet_compliance`/`get_compliance_summary`** (an operator-visible compliance percentage
  computed from a degraded read must not silently render as if every unscored agent were simply
  absent from the denominator).
- **`policy_dispatch_state` (this migration's new operational table): fail-soft, entirely
  internal.** Never read or written by anything outside `PolicyStore::claim_due_policies` (below);
  no external caller, no REST surface, no backfill obligation.

### Backfill (ADR-0009) — MANDATORY for five tables, EXCLUDED for the sixth and the new seventh

ADR-0009's own Context paragraph names "policies" explicitly as irreducible operator intent.
`policy_fragments`/`policies`/`policy_inputs`/`policy_triggers`/`policy_groups`: **mandatory**,
using the `SoftwareDeploymentStore`/ADR-0051 shape (closest sibling: multi-table with internal
FKs) — one SHA-256 fingerprint over all five tables' canonicalized+sorted rows
(`sqlite_backfill_source`), holder-side verification against a possibly-fleet-wide-stamped
sourceless marker (the `RbacStore`/post-#2703 shape every table-fingerprinted store in this wave
uses), `RETURNING id` + `PQntuples()==1` per-row landed-verification. The legacy-file-predates-
the-ALTER-wart case is handled by reading `fix_attempt_count` with a column-existence check
(`PRAGMA table_info`) before the backfill SELECT on `policy_status`, defaulting missing values to
`0` — the same value the wart's `ADD COLUMN ... DEFAULT 0` would have produced.

**`policy_status` — copied, not fresh-started.** The kickoff left this open; the default
evaluation interval is 3600s, so a fresh-empty status table is not a "brief all-unknown window" —
it is up to an hour of an operator-visible dashboard reporting 0% or "unknown" fleet compliance
immediately after an upgrade, for policies that were fully scored five minutes before. Copied with
a direction-aware LIFECYCLE merge (status/last_check_at/last_fix_at/check_result/
fix_attempt_count): Postgres-ahead-or-tied-by-`last_check_at` is a benign no-op (only possible on
an idempotent backfill re-run after PG has already accumulated fresh evaluator writes — at the
actual cutover boot PG starts empty, so this is always a straight copy then); legacy-ahead fails
closed the same as `DeploymentStore`'s IDENTITY mismatch handling.

**`policy_dispatch_state`: excluded from backfill entirely, by design.** It is pure claim-tracking
state, invented by this migration — there is no legacy value to carry forward. Starting empty
means every policy looks immediately due on the first post-cutover tick, which is the same
"re-evaluate everything once, promptly" behavior the SQLite original already had on every process
restart (nothing in the original throttled across a restart either — `last_eval_` was a fresh
in-memory map every boot).

### Secrets — none found; flagged for a security-guardian read-time-redaction pass

`policy_fragments.yaml_source`/`check_parameters`/`fix_parameters`/`post_check_parameters` and
`policy_inputs.value` are free-form operator-authored text (up to 1 MiB) with no schema
constraint distinguishing a secret from any other parameter — an operator *could* paste a
credential into a policy's `inputs:` block. Nothing in the current code treats these fields as
secret-bearing, and no `SecretCodec`/hash is applied. Not fixed here (no evidence of the pattern
`AuditStore`'s ADR-0040 found and fixed for `detail` — this is a "nothing observed" finding, not
a "found and declined" one); flagged as a follow-up for a `security-guardian` pass on whether
`policy_inputs`/`policy_fragments` need read-time redaction akin to `AuditStore::sanitized_detail`.

### The headline decision: dispatch is single-sweeper and durable; collect stays per-replica and idempotent

**CLAIM (new `PolicyStore::claim_due_policies`, one Postgres transaction, DB-only — no external
I/O, so the AuditStore/ResultSetStore single-phase lease pattern applies directly, not
AnalyticsEventStore's 3-phase split):**

```cpp
std::expected<std::vector<Policy>, std::string>
PolicyStore::claim_due_policies(int64_t now, int64_t default_interval_seconds,
                                int64_t fixing_stale_seconds);
```

1. `pg_try_advisory_xact_lock(hashtextextended('policy_store:dispatch', 0))`. Not acquired →
   `return {}` (empty, `Ok` — another replica is claiming this tick; this is the normal skip, not
   a degrade, matching every other lease call site in the codebase).
2. Acquired, same transaction:
   a. **Stranded-`fixing` staleness sweep** (replaces the evaluator constructor's unconditional
      reset — see "Design considered and rejected" and Consequences): `UPDATE policy_status SET
      status = 'unknown' WHERE status = 'fixing' AND last_fix_at < $now - $fixing_stale_seconds`.
      Runs every winning tick, not just at boot — strictly better coverage (catches a stranded fix
      whenever it happens, not just at the next restart) and, being durably last-write-time-gated
      rather than "every row, unconditionally, on construction," no longer stomps a fixing row
      that belongs to another replica's still-live remediation.
   b. **Due-policy claim**: for every enabled policy, compute
      `interval = max(60, interval_for(triggers, default_interval_seconds))` — `interval_for`'s
      trigger-parsing logic moves from `policy_evaluator.cpp`'s anonymous namespace into
      `policy_store.cpp` (nothing outside `claim_due_policies` needs it once due-ness is fully
      internal to the store) — then `UPSERT policy_dispatch_state (policy_id, last_dispatched_at)
      VALUES ($id, $now) ON CONFLICT (policy_id) DO UPDATE SET last_dispatched_at = $now WHERE
      policy_dispatch_state.last_dispatched_at <= $now - $interval RETURNING policy_id`. The
      `WHERE` on the conflict branch is the atomic check-and-claim: a policy not yet due simply
      doesn't appear in the `RETURNING` set, no separate pre-read needed.
3. Commit (releases the lock). Return the claimed policies (loaded via the same query path
   `query_policies`/`load_policy_details` already uses, inside the same transaction, so the
   caller gets full `Policy` objects — no second round trip).

**SEND**, unchanged from today, no lease held: `PolicyEvaluator::dispatch_due()` becomes

```cpp
void PolicyEvaluator::dispatch_due() {
    if (!d_.policy_store) return;
    auto claimed = d_.policy_store->claim_due_policies(now(), d_.default_interval_seconds,
                                                        d_.fixing_stale_seconds);
    if (!claimed) {
        spdlog::warn("policy_evaluator: claim_due_policies degraded: {}", claimed.error());
        return; // ADR-0036: degraded ≠ zero due — skip the tick, retry next tick, never dispatch
    }
    for (const auto& p : *claimed)
        kickoff_check(p); // unchanged: resolve targets, dispatch, record in-flight
}
```

`last_eval_` is deleted entirely (superseded by the durable claim). `Deps` gains
`fixing_stale_seconds{1800}` (30 min default — long enough that a real, slow fix instruction
(e.g. a `content_dist` software install, which can genuinely run minutes) is not false-positive
reset mid-flight; short enough that a truly stranded fix does not sit invisible indefinitely).

**COLLECT stays exactly where it is: per-replica, in-memory `in_flight_`, unconditional every
tick, no lease.** Only the replica that dispatched a check ever has an `in_flight_` entry for it,
so only that replica ever collects it — there is nothing to coordinate. `update_agent_status`'s
`ON CONFLICT ... DO UPDATE` UPSERT is naturally idempotent: a manual operator `remediate()`/
`evaluate_now()` call on one replica racing an automatic tick's collect on another can both write
a verdict for the same `(policy_id, agent_id)` with no corruption — last-write-wins, and since
both derive the verdict from the same underlying `response_store` data, they agree. This is the
"at-least-once with idempotent status writes" half of the kickoff's two named options, scoped
narrowly to the one path (manual operator actions) that still has no durable coordination — an
accepted, bounded residual, not a compromise on the dispatch-dedup guarantee above.

**`update_agent_status`'s retry-cap check folds into the UPSERT itself**, closing a TOCTOU the
SQLite original only avoided by accident (a single process-wide `mtx_` serializing all calls —
gone once calls arrive from a pooled connection across replicas): the separate pre-check
`SELECT fix_attempt_count ...` is removed; the cap decision (`fixing` requested but
`fix_attempt_count >= 3` → force `error` instead) is expressed inside the `ON CONFLICT DO UPDATE
SET` clause, reading `policy_status.fix_attempt_count` (the row's pre-update value, which Postgres
resolves under the conflicting row's lock — concurrent UPSERTs on the same key serialize, so the
second one's CASE sees the first one's already-committed count, never a stale pre-fetched value).

**Correction (found running the multi-instance regression test, 2026-08-20):** two gaps in the
first cut of `update_agent_status`/`evaluate_now`, both caught before merge, neither visible from
reading the SQL — only from running the actual claim/staleness-sweep sequence against live
Postgres.

1. **`last_fix_at` on the fresh-INSERT branch was a bare `0`**, ported unchanged from the SQLite
   original (`VALUES (?, ?, ?, ?, 0, ?, 0)`) — harmless there, because the old stranded-`fixing`
   reset was unconditional and never read `last_fix_at` to decide anything. It is not harmless
   here: `claim_due_policies`'s staleness sweep is the first consumer that relies on `last_fix_at`
   meaning "when did this row last become `fixing`." A `fixing` status landing as the very
   first-ever write for a `(policy_id, agent_id)` pair — reachable via `remediate()` naming an
   agent never checked before — got `last_fix_at = 0`, which the very next staleness sweep read as
   infinitely stale and immediately reset to `unknown`, before the FixWait's own grace window ever
   ran. Fixed: the VALUES clause now computes `last_fix_at` the same way the `ON CONFLICT`
   branch's own `CASE` does — `CASE WHEN $3 = 'fixing' THEN $4::bigint ELSE 0::bigint END` (the
   explicit `::bigint` casts are load-bearing: Postgres could not otherwise unify `$4`'s type
   between this CASE and its other use as the plain `last_check_at` value in the same statement —
   "inconsistent types deduced for parameter" — since the bare literal `0` on its own defaults to
   `integer`, not `bigint`).
2. **`evaluate_now()` never touched `policy_dispatch_state`.** The SQLite original stamped
   `last_eval_[policy_id] = now()` in-memory on every manual dispatch specifically so the
   *following* automatic tick's throttle check would see it and skip re-dispatching within the
   interval. Deleting `last_eval_` (superseded by the durable claim, per the Decision above)
   silently dropped that side effect too — `evaluate_now()` still dispatched correctly on its own,
   but left no record in `policy_dispatch_state`, so the next `claim_due_policies` call found no
   row for that policy (the fresh-INSERT branch, which always succeeds regardless of the `WHERE`
   guard) and re-claimed it immediately, producing a duplicate check seconds after the manual one
   even though the interval had not elapsed. Fixed with a new store method,
   `PolicyStore::record_dispatch(policy_id, now)` — an unconditional upsert of
   `last_dispatched_at` with no lock and no `WHERE` guard (this is a single explicit dispatch
   action, not a competing claim). Stamped from `evaluate_now()` **before** calling
   `kickoff_check`, not after — `kickoff_check`'s `dispatch_fn` is blocking gRPC/gateway I/O, and
   a real network-duration window existed between "check dispatched" and "claim recorded" during
   which a concurrent tick (this replica's own background thread, or a sibling replica) could still
   observe no row and duplicate-dispatch before the manual call's network round-trip even returned.
   Stamping unconditionally before dispatch, regardless of whether `kickoff_check` itself succeeds,
   matches the original `last_eval_` semantics: a failed manual check still consumed the interval
   slot in the pre-ADR-0056 code, by the same claim-before-dispatch ordering `claim_due_policies`
   already uses for the automatic path.

Both gaps were caught by the two-instance regression test this ADR's Consequences section
promises, not by code review — the first surfaced as a claim-staleness test flipping a `fixing`
row to `unknown` inside its own "within window" assertion; the second as a flaky-looking
dispatch-count mismatch that turned out to be fully deterministic once traced (a pre-existing
`evaluate_now()` + immediate-tick sequence in the *unrelated* `interval throttles re-dispatch`
test, not the new test itself).

### Construction — fail-closed (this store lacked it even on SQLite)

`server.cpp:4979-4986` constructs `PolicyStore` and only logs on failure today — unlike
`ResultSetStore`/`GuaranteedStateStore` right below it, nothing sets `startup_failed_`. Given the
Wave 2 "authoritative config/reference" posture this store's ladder row already carries, this was
a pre-existing gap, not a decision — closed here: `!is_open()` → `startup_failed_ = true`, matching
every other authoritative store on the ladder.

### Teardown — `policy_store_.reset()` must now run before `pg_pool_.reset()`

Today `policy_store_` owns a standalone `sqlite3*` with no shared dependency, so implicit
declaration-order destruction in `~ServerImpl` was safe. Once it borrows `pg_pool_`, that stops
being true — the same reasoning `server.cpp:7472-7490`'s `custom_properties_store_` comment
documents (a sibling store the evaluator also holds a raw pointer to on its background thread) now
extends to `policy_store_` itself: `stop()` already joins `policy_eval_thread_` early
(`server.cpp:7149-7153`, ahead of every store teardown, unchanged by PR #3339's shutdown-watcher
rework — verified against the current `stop()` sequence on this branch, not assumed from memory),
so by the time any store is torn down the evaluator thread is provably not running. An explicit
`policy_store_.reset()` is added immediately before `pg_pool_.reset()`, matching sibling discipline
(belt-and-braces, not risk-bearing — the thread-join ordering already made this safe; the explicit
reset just stops relying on declaration order to prove it).

## Considered and rejected

- **Session-scoped leader election** and **a durable in-flight ledger** — see "Design considered
  and rejected" above.
- **Naive at-least-once dispatch (no lease at all)**: rejected — technically idempotent-safe
  (duplicate verdicts converge), but multiplies real agent-side work N-fold per tick (every
  duplicate dispatch re-runs the check plugin on every targeted endpoint), which the kickoff names
  explicitly as the failure mode to avoid.
- **Moving the stranded-`fixing` sweep to a separate standalone lease/reap pass**: rejected in
  favor of folding it into the same `claim_due_policies` transaction — it is cheap, DB-only, and
  keeping it inside the existing single-sweeper section avoids introducing a second advisory-lock
  key for no operational benefit.

## Consequences

- `PolicyEvaluator::Deps` gains `fixing_stale_seconds{1800}`; `last_eval_` and the anonymous-
  namespace `interval_for()` are deleted from `policy_evaluator.cpp` (moved into `policy_store.cpp`
  as the sole due-ness computation).
- The evaluator constructor's stranded-`fixing` reset is deleted — superseded by the per-tick
  staleness sweep inside `claim_due_policies`, which runs continuously rather than only at boot
  (strictly better coverage) and no longer stomps another replica's live remediation.
- `delete_policy` no longer hand-writes a `policy_status` cleanup `DELETE` — the new FK cascades
  it, closing the prepare-failure swallow the SQLite original had there.
- `update_agent_status`'s retry-cap check becomes race-safe under concurrent replicas (previously
  safe only by accident, via a process-wide mutex that no longer serializes cross-replica calls).
- `ComplianceRoutes` reads (fragment/policy list, fleet/policy compliance summary) 503 on a
  degraded store read instead of silently rendering an empty/zero result.
- Construction gains a fail-closed guard it never had on SQLite — a genuine (small) behavior
  change: a PolicyStore that fails to open now fails the whole server's startup, where before it
  silently ran with policy evaluation permanently broken.
- Tests move to `PostgresTestDb`/`YUZU_REQUIRE_PG_DB_TPL`; `test_policy_evaluator.cpp`'s
  `PolicyStore` construction (currently plain SQLite alongside an already-PG `ResponseStore`)
  becomes PG too, and gains the multi-instance coverage neither test file had before (two
  `PolicyEvaluator` instances sharing one `PolicyStore`/DB, asserting exactly one dispatch per
  policy per interval, and that a check dispatched by instance A is collected correctly by
  instance A while instance B's own tick claims nothing for it) — this is the concrete regression
  test for the header decision.

## Follow-ups

- `policy_inputs`/`policy_fragments` free-form-text secret exposure — flagged, not fixed (see
  Secrets above); needs a `security-guardian` assessment of whether read-time redaction is
  warranted.
- Manual `evaluate_now()`/`remediate()` calls still have no durable in-flight coordination — if
  the replica that received the REST call crashes before its own `collect_ready()` runs, that
  specific operator-triggered check/fix strands (no verdict ever recorded) until the operator
  retries. Accepted: narrow (operator-triggered only, not the routine tick path), and the operator
  already has a natural retry action (re-click evaluate/remediate).
