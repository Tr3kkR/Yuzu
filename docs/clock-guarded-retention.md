# Clock-guarded retention

Routed doc for the **clock-guarded retention** concern in `.claude/routed-concerns.md`.
Loaded by `cpp-safety` + `sre` + `compliance-officer` on any new or modified retention/reaper/prune pass.

**The rule:** any bulk delete whose cutoff comes from a wall clock (`now - window`) must be guarded and
capped, never a bare `DELETE ... WHERE ts < cutoff`.

The rule exists because a wrong clock turns a routine retention pass into silent, unrecoverable data
loss, and every detector below was added after a real failure. **What makes any store's choices
correct is the RECORDED reasoning, not the answer — copying one without deciding is the defect.**

## The seven parts — all load-bearing

### 1. Probe by OUTCOME

Would this pass expire EVERY datable row? Exclude rows stamped implausibly far ahead — one
forward-skewed row otherwise disarms the guard forever.

The implausibility bound is **PER-STORE**, must exceed that store's own max legitimate TTL horizon,
and must **NEVER** be copied from another store's constant. A short bound copied from a short-TTL
store into a long-retention one misclassifies honest fresh TTLs as implausible and flips partial
expiry into a false would-wipe decline (ADR-0038, found in review).

### 2. Compare against a PERSISTED clock reading

The reading must survive restarts. An in-process reading is inert on the pass that matters — the
first after a boot with an already-wrong clock.

### 3. SANITISE that reading

Ahead-of-now, negative, or unparseable is an anomaly, **never a quiet reset**. On an endpoint the
user controls, a quiet reset IS the bypass.

### 4. SUPPRESS only a repeat of the SAME anomaly

Compare the **FULL FACT SET** — never a latch bool, and never a classified enum — so a legitimately
all-expired table still ages out.

A bool cannot carry anomaly IDENTITY: a DIFFERENT anomaly arriving while it is set is neither
declined nor reported, and the pass deletes. MEASURED on the pre-hardening `audit_store`: an
implausible-reading decline latched, a would-wipe arrived on the next pass, and it was swallowed —
deleted with no decline, no counter and only a routine info line. The bool design needed three
separate hand-patches for instances of this same identity problem before a fourth was found, which
is why the fix is the fact set rather than a fourth patch.

### 5. Cap every accepted pass UNCONDITIONALLY

The cap is the half that always applies; the detectors are best-effort.

### 6. Decide DELIBERATELY what a missing anchor means — and record which way you went

The retention guards that face this question **each answer it differently, ON PURPOSE.**

- **TAR** treats no-stored-reading as a decline trigger in its own right (the first pass against an
  existing store would otherwise delete under an already-wrong clock with every detector silent).
- **`audit_store`** does too since #2579, gated the SAME way — TAR short-circuits on `!has_expired`
  before it computes `no_anchor`, and `classify` returns `None` on `!has_expired` before testing it,
  so neither fires on a fresh install with nothing to lose. *(Do not describe either as narrower than
  the other: that claim was made and was false.)*

  The two differ in **SCOPE and ACCOUNTING, not in trigger**. TAR decides per warehouse table and
  deliberately never RECORDS a bootstrap NoAnchor fact set into its dedup map (#2573 TAR half) —
  unlike `audit_store`, whose durable bootstrap-settled marker commits in the SAME transaction as its
  verdict, TAR's anchor persist is a plain `set_config` independent of that map, so recording
  NoAnchor would let a persistent persist-failure turn every later identical pass into a silently
  suppressed drain. `audit_store` decides per database and gets the same non-latching property free
  from fact-set dedup; the pass declines ONCE, anchors, and counts to its own
  `..._retention_bootstrap_declines_total`, never the clock-anomaly series, because it asserts only
  that nothing can yet be ruled out and must not fire an alert that says the clock moved.

  (It formerly declined only when the pass would ALSO expire every datable row, which is exactly the
  hole #2579 closed — a forward-skewed host whose post-skew rows still survive defeats that test.)
- **`ResultSetStore::gc_sweep`** deliberately does NOT adopt it: one TTL window of scratch result sets
  is regenerable, so a decline would buy nothing.
- **`GuaranteedStateStore`** (ADR-0038) records a fourth answer at its `Facts` site: decline,
  `audit_store`'s answer — a mis-timed pass would destroy non-regenerable Guardian/DEX compliance
  evidence, not `ResultSetStore`'s reproducible scratch data.

### 7. Elapsed-time thresholds are ABSOLUTE

Never scaled to the retention window: `max(window, floor)` puts the threshold a year out on a
365-day default and the check never fires (#2360/#2361, found post-review).

## SINGLE-WRITER ONLY as written

On a Postgres store the reading and the dedup state must become SHARED rows under an ADR-0012
advisory lock, because process-local state paces at N × cap across replicas and one skewed replica
can put every replica into permanent mutual decline.

## Per-store adoption register

Siblings become compliant store-by-store as they migrate to Postgres.

### Using the guarded shape

| Store | Notes |
|---|---|
| `result_set_store` | ADR-0036; shape only: ADR-0040 |
| `guaranteed_state_store` | ADR-0038, compliant #2663 |
| `api_token_store` T12 rotation sweep | #2964 |
| `response_store` | ADR-0039, compliant #2691 — full Facts/classify + `kMaxPlausibleNow` clamp + PG-clock read via the shared `gc_meta` anchor |
| `ExecutionTracker::concurrency_claims` stale-claim reconciler | ADR-1007 — a persisted anchor + dedup fact-set in `retention_meta` survive restarts, and the whole probe-decide-act sequence is wrapped in one transaction. `would_wipe` is a DELIBERATE non-adoption of part 1 for this small ephemeral table, same reasoning as `api_token_store`'s own DELIBERATE NON-ADOPTION comment. **NOT yet fully seven-part compliant** — part 3 is floors-only (no ahead-of-now clause) and the shared-CLOCK rule is unmet (see the caveat), so it is classed **DisabledUntilFixed** in `background_jobs.hpp`, NOT ReplicaSafe. **SINGLE-WRITER as of WS-10** — a `pg_try_advisory_xact_lock('execution_tracker:concurrency_reconcile')` is now the first in-txn statement (try-and-skip; a lost race skips without advancing the liveness gauge), closing the concurrent-double-reconcile half of the shared gap the note below describes. **Clock-authority caveat (still open):** this pass's `now` is the caller's replica `system_clock`, not PG `now()` in-SQL — and the `concurrency_claims` `expires_at` it compares against is likewise written from `now_epoch()` (replica `system_clock`). So the shared-CLOCK half of the SINGLE-WRITER rule is NOT yet met for this store; a `concurrency_claims` DB-clock-authority migration (WS-1 class, #3715 shape, spanning claim write + extend + reconcile) is a prerequisite before a 2nd replica. Its part-3 sanitiser also floors-only (no ahead-of-now clause) — the same gap WS-10 fixed in the shared `pg::run_clock_guarded_prune`, tracked for this store alongside the clock-authority migration |
| `app_perf_fleet_store`, `preflight_run_store`, `deployment_run_store` retention prunes | **WS-10 (#2508)** — the three formerly-bare wall-clock deletes now run through the shared `pg::run_clock_guarded_prune` helper (`server/core/src/pg/pg_retention_guard.{hpp,cpp}`): all seven parts + a `pg_try_advisory_xact_lock` (SINGLE-WRITER), reading Postgres `now()` in-SQL (shared clock, #3715). Constants are per-store parameters (`ClockGuardedPruneSpec`), part-6 = **Decline** at each call site (non-regenerable operator/analytics history). ONE reviewed impl parameterised per store, not three hand-copies — the "copy the SHAPE, never the numbers" rule made mechanical |

### Still issuing bare wall-clock deletes

The three tracked **#2508** background sweeps (`app_perf_fleet_store`,
`PreflightRunStore`, `DeploymentRunStore`) adopted the guarded shape via
`pg::run_clock_guarded_prune` in WS-10 — see the register entry above.

One lower-exposure bare wall-clock delete remains, OUT of the #2508 background-sweep
scope: `app_perf_daily_store.cpp`'s `apply_daily` does a per-agent
`DELETE ... WHERE agent_id=$1 AND day < cutoff` (cutoff from `system_clock::now()`)
INLINE during that agent's own daily-perf ingest — not a background bulk sweep. Its
blast radius is one agent's own rows, bounded by the retention window, and it is
driven by that agent's data arriving rather than a timer, so a wrong server clock
cannot wipe the fleet's history in one pass. Whether to bring it under the guard (or
a bounded per-agent variant) is a tracked follow-up, not part of WS-10's
background-sweep scope.

### `api_token_store` — first store to DECLINE part 1's would-wipe half

It declines outright rather than adopting or re-tuning it: its eligible population reaches 100%
expiry as routine drain behaviour (unlike a long-lived time series, where that can only mean the
cutoff moved), so a would-wipe verdict cannot separate a true and a false positive there at any
population size. See `api_token_store.cpp`'s DELIBERATE NON-ADOPTION comment for the recorded part-6
reasoning — not a silent omission.

Its part-6 answer for a missing anchor is `audit_store`'s (decline). Its constants (3'600s big-step
floor, 200-per-tick cap, 60s tick cadence) are substrate-tuned like every sibling's — **copy the
SHAPE from it, never the numbers, in either direction.**

### `SessionStore::reap_expired` (HA WS-1/1a, ADR-2002 §4)

The former `auth_db` in-memory-monotonic session sweep is GONE — operator sessions are now durable
Postgres rows in `SessionStore`, so its `reap_expired` IS a wall-clock retention pass and JOINS this
guarded set with parts (2)/(3) persisted+sanitised anchor, (5) unconditional cap, (6) recorded
missing-anchor decision (**PROCEED** — sessions are re-mintable via re-login, `ResultSetStore`'s
answer), plus the advisory-lock own-statement AND a backward-anomaly decline (`now < anchor`).

Since **#3715** (DB-clock authority) `reap_expired()` reads Postgres `now()` ITSELF — one in-SQL
reading for cutoff + anchor-compare + anchor-update, the same clock that authors `expires_at` — so
`clock_anomaly` is the **DB-PRIMARY** signal (`yuzu_auth_session_reap_clock_anomaly_total`),
DISTINCT from the local host-clock drift counter (`yuzu_auth_local_clock_backward_total`). **Never
split the two clock domains, and never re-add a caller-supplied `now_ms`.**

It DELIBERATELY carves out parts (1) and (4), the `api_token_store` precedent:
1. **NO would-wipe probe** — sessions reach 100% expiry as routine drain, so a would-wipe verdict
   cannot separate a true from a false positive.
4. **NO fact-set anomaly dedup** — a declined pass is `spdlog::warn`'d AND surfaced as
   `yuzu_auth_session_reap_clock_anomaly_total` (the ADR-2002 §4 mitigation-(a) monitor) rather than
   deduped by fact identity.

These two carve-outs are recorded here per part (6)'s "record which way you went" requirement, NOT
the full 7. SINGLE-WRITER today (the one server); becomes PG-shared-state under the ADR-0012
advisory lock when a 2nd replica lands.

### `GatewayRouteStore::reap_stale_routes` (HA WS-4 slice 4.2a, hardened PR #4299)

JOINS this guarded set on the `SessionStore::reap_expired` shape (advisory-lock own-statement
`gateway_route_store:reap`, in-SQL DB `now()` read once for both cutoffs + anchor-compare +
anchor-update, persisted+sanitised `route_meta` anchor, forward/backward-anomaly decline,
unconditional per-predicate cap):

1. **NO would-wipe probe** (DELIBERATE carve-out, the `api_token_store`/`SessionStore` precedent) —
   the `agent_routes` table legitimately drains toward "every lease expired" as ROUTINE behaviour (a
   fleet going offline overnight expires every lease), so a would-wipe verdict cannot separate a true
   from a false positive here.
4. **Fact-set anomaly dedup is ADOPTED** (PR #4299 review; an earlier revision carved this out too,
   the way `SessionStore` does — that was the defect this fix closes), in a form simplified for this
   store's small state: **decline-once / drain-on-repeat, keyed on the declined `reap_anchor_ms`
   value** rather than the full multi-field `Facts` struct `audit_store.cpp` uses. A forward- or
   backward-skew anomaly persists `route_meta.reap_declined_anchor_ms = reap_anchor_ms` and declines;
   an IDENTICAL repeat (the anchor still unmoved, because a decline never advances it) RECOVERS —
   runs both sweeps under the cap, advances `reap_anchor_ms` to `now_ms` UNCONDITIONALLY (never
   `max(anchor, now_ms)`, which would leave a forward-skew-poisoned anchor stuck forever), and clears
   the declined-anchor marker. A normal (non-anomalous) accepted pass also clears the marker, so a
   later transient glitch is judged fresh against the new anchor rather than free-riding on a stale
   recovery. **Why this mattered**: the carved-out version wedged PERMANENTLY after any routine >24h
   gap (weekend shutdown, DR failover, extended maintenance) — `now - anchor` only grows while
   declined, so every subsequent pass declined forever with no recovery path; a persistent clock
   problem (never resolving) correctly never recovers on its own by the same logic, and needs an
   **operator re-anchor**: reset `route_meta.reap_anchor_ms` (and, for cleanliness,
   `route_meta.reap_declined_anchor_ms`) to the corrected current epoch-ms once the underlying clock
   is fixed — see the code comment at `gateway_route_store.cpp`'s anomaly-detection site. Every
   decline is `spdlog::warn`'d AND counted:
   `yuzu_server_gateway_route_reap_total{outcome="declined"}` (incremented at the reap call site in
   `server.cpp`, pre-seeded across `ok`/`declined`/`error` since PR #4299). This is a DEDICATED
   reap-outcome counter, distinct from `yuzu_server_gateway_route_desync_total`/`_write_failed_total`,
   which cover the WRITE path (`register_fresh`/`announce_connected`/`deregister`/`renew_leases`), not
   a reap pass's own outcome. A reap pass that fails outright (pool/query degradation, distinct from a
   clock-anomaly decline) is counted the same way under `outcome="error"`; a clean accepted OR
   recovered pass is `outcome="ok"`.

Part (6)'s missing-anchor decision is **PROCEED** (`ResultSetStore`'s answer): a route is
regenerable by the agent's next heartbeat/`ProxyRegister`, so a from-boot skewed clock reaping a
batch of already-stale routes on the first pass is an acceptable worst case, never non-reproducible
evidence loss.

Two predicates sweep in the same pass, both capped independently (`kReapCap = 5000`, matching
`SessionStore`'s shape — never its number): (a) `lease_until` past a grace window of `2x` the 90s
lease TTL (`kStaleLeaseGraceSecs = 180`) — TOMBSTONES the row (same shape as `deregister`, retaining
`connection_epoch`) rather than deleting it, because the associated session may still be alive and
merely stopped renewing; (b) a NULL-lease row (a real tombstone, or a row stuck since
`register_fresh` that never got an `announce_connected`) whose `updated_at` is past a SHORT purge age
(`kTombstonePurgeAgeSecs = 300`) — hard-DELETEs it, since by that age a late CONNECTED/DISCONNECTED
resurrecting it is not a realistic risk and a genuine later `register_fresh` works identically
whether the row exists or not. The implausible-forward-skew bound (part 1) is this store's own,
NEVER copied from a sibling: `kMaxPlausibleSkewMs = 1 day`, sized against this store's own
sub-ten-minute liveness horizon (grace + purge-age ≈ 480s), not `SessionStore`'s 366-day bound (sized
to a human session's plausible lifetime).

SINGLE-WRITER today (one dedicated advisory-lock key, `gateway_route_store:reap`); becomes
PG-shared-state under the same ADR-0012 lock when a 2nd replica lands, matching every sibling in this
register. See `gateway_route_store.hpp`'s `reap_stale_routes` doc comment for the full record.

### `ExecutionTracker::reap_command_execution_mappings` (HA WS-1(1b))

JOINS this guarded set on the identical shape (advisory-lock own-statement, in-SQL DB `now()` read
once for cutoff/anchor-compare/anchor-update, persisted+sanitised `reap_meta` anchor,
forward/backward-anomaly decline, unconditional cap) and makes the SAME two carve-out choices
`SessionStore` made, for the SAME reason:
1. **NO would-wipe probe** — the `command_execution` table drains to 100% expiry as routine behaviour
   (every mapping is consumed once, response-side, well before the 24h window), so a would-wipe
   verdict cannot separate a true from a false positive.
4. **NO fact-set anomaly dedup** — a declined pass is `spdlog::warn`'d and surfaced via
   `yuzu_exec_correlation_reap_clock_anomaly_total` rather than deduped by fact identity.

Part (6)'s missing-anchor decision is **PROCEED** (`ResultSetStore`'s answer): a mapping is a
regenerable observability aid, not compliance evidence, so a from-boot skewed clock deleting a batch
of already-consumed mappings is an acceptable worst case.

### `guardian_lifecycle_journal.cpp`

Satisfies parts **1/3/4/5 ONLY** — its reading is in-process and deliberately NOT persisted, so **do
not copy it for part (2)**.

## Reference implementations

**Decision rule:** `common/include/yuzu/audit_retention_rules.hpp::classify` (extracted to a shared
include root #2549 so agent stores can adopt it without a fork) + `audit_store.cpp::cleanup_once`
(fact-set).

`tar_aggregator.cpp::run_retention` adopted the shared `classify` + fact-set dedup (#2573 TAR half).
`guardian_lifecycle_journal.cpp::prune_locked_` adopted it too (#2573 GJ half, closed) —
`Facts::no_anchor` and `Facts::prev_unusable` are always false there (GJ persists no anchor across
restarts by design, and its comparison reading is never read back from an untrusted store); see the
field-mapping comment at the `prune_locked_` call site.

**The three reference impls deliberately use DIFFERENT constants** (server 2 d slack / 25 000 cap /
7 d step; agent 1 d / 5 000-per-table / 30 d) — they are substrate-tuned, so **copy the SHAPE, never
the numbers.**

## Related

- Rule and tests: #2360 / #2361 / #2549, `common/include/yuzu/audit_retention_rules.hpp` (`classify`),
  `AuditStore::cleanup_once`, `tests/unit/server/test_audit_store.cpp`
- `docs/user-manual/audit-log.md` and `docs/user-manual/tar.md` "The retention clock guard" are
  operator **RUNBOOKS** and deliberately do not state this rule.
