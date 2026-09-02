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
| `ExecutionTracker::concurrency_claims` stale-claim reconciler | ADR-1007 — compliant on all seven parts, including a persisted anchor + dedup fact-set in `retention_meta` surviving restarts, and the whole probe-decide-act sequence wrapped in one transaction. `would_wipe` is a DELIBERATE non-adoption of part 1 for this small ephemeral table, same reasoning as `api_token_store`'s own DELIBERATE NON-ADOPTION comment — sharing the SINGLE-WRITER gap above with every other store in this list, not a worse one |

### Still issuing bare wall-clock deletes

`app_perf_*`, `PreflightRunStore`, `DeploymentRunStore` — tracked as **#2508**.

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
