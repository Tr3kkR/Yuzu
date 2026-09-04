# Spark / legacy Guardian detection: intentional delta registry

Captured against `origin/dev @ b16e5836d` (2026-08-23). Authority: ADR-0021 Decision 11
amendment ("incremental per-consumer cutover... with the three gates applied per rung");
`docs/spark-stage2-guardian-consumer-design.md` §R2 consequence 2 (origin ruling, quoted
below); `docs/user-manual/guaranteed-state.md` "Per-rung default posture" table.

## Why this doc exists

> "Parity needs an intentional-delta registry. Legacy silently no-ops where spark
> reports `unsupported`. Zero-tolerance parity cannot be literal across that dimension;
> rung 10's gate artifact must carry the documented delta list, or the gate fails
> spuriously and gets quietly weakened until it means nothing."
> — `spark-stage2-guardian-consumer-design.md`, §R2 consequence 2

The design doc's PR-2 ("thin cutover") and rung-10 ladder entries both list this
registry as a named flip-gating deliverable (R2 consequence 2, pulled forward from
rung 10 because 7.7b changes the behavior it classifies): §PR-2 (`spark-stage2-guardian-
consumer-design.md`, and the 7.7b bullet list restating it) calls it "shipped ahead of
the flip, F12/#3386: `docs/spark-legacy-delta-registry.md`"; the numbered rung-10 ladder
item phrases the same fact as "shipped ahead of schedule, F12/#3386: ..." — different
wording, same claim. The intent both sites express: every observed difference between a
legacy-detection run and a spark-detection run at parity-capture time must classify as
either a row in this table ("expected, already decided") or a genuine regression ("new,
investigate"). This is that table.

**A third bucket exists and must not be silently folded into the first: a row whose
Epistemic status is `open-question`.** Such a row documents a real, observed difference
that has NOT been ruled deliberate — it is tracked, not dismissed. A diff line may be
classified "expected" against a `verified`/`likely` row; it may **not** be waved through
against an `open-question` row. Treat a diff matching an open row the same as a genuine
regression: it blocks the parity gate until the linked issue resolves and the row is
re-stamped `verified`/`likely`. (D3 held this status until 2026-08-23, when #3388 was
**ruled**, and until 2026-08-26 when the ruling's fix merged (PR #3518) — see D3's own
Ruling and Epistemic cells. No row currently carries `open-question` status.)

**Every row below is an at-the-flip delta, not a live one.** `GuardianEngine`'s
`prefer_spark` constructor parameter defaults `false` (`guardian_engine.hpp`), and the
sole production call site (`agent.cpp`, `std::make_unique<GuardianEngine>(kv_store_.get(),
cfg_.agent_id)`) omits it, taking the default. `reconcile_rule_locked` only reaches a
spark placement decision when `prefer_spark_ && spark_availability_ == Available`. So
today, fleet-wide, every row's "Spark" column is dormant and every row's "Legacy" column
is what every agent actually does.

**The only production lever once `prefer_spark` flips is `--spark-disable`**
(`YUZU_AGENT_SPARK_DISABLE`, boot-time only). It does not touch `prefer_spark` itself —
it sets `SparkAvailability::SparkDisabled`, which `guardian_backend_from_state()` maps to
the `legacy` backend label regardless of `prefer_spark`, restoring the full legacy path.

**Re-verification obligation.** Every row's `verified <SHA>` stamp is a point-in-time fact
about code that is still under active development, not a durable guarantee. `verified
<SHA>` records that a claim was checked, not that it stays true. **F14's first step is
re-verifying every row against flip-time HEAD and re-stamping the SHA** — treat this as a
precondition of the flip, not an optional refresh. A row whose cited symbol no longer
exists or no longer behaves as described is itself a flip blocker until corrected.

**Not this doc:**
- `docs/enterprise-parity-plan.md` — competitor feature parity, unrelated.
- `docs/capability-registries/spark_mechanisms.tsv` — per-OS mechanism capability
  registry (a *different* "registry"; this doc cites it, doesn't duplicate it).
- `docs/user-manual/guaranteed-state.md` "Upgrading from a detect-only build" —
  `enforcement_mode` defaulting to `enforce` + Baseline gating; not spark-related despite
  the name collision.

## How to add a row

One row per **deliberate** legacy-vs-spark behavioral difference, only after re-verifying
the current code (cite the symbol, not a line number — line refs drift, verified twice
already in this subsystem's own history). Each row is an `### <ID> — <one-line title>`
heading followed by a table with columns **Delta** (the heading itself) | **Legacy** |
**Spark** | **Why deliberate** | **Operator symptom** | **Verify at** | **Epistemic**.
Epistemic values: `verified <SHA>` (I read the code myself, this date), `likely`
(inferred from adjacent verified facts, not directly re-read), `open-question` (found
during this pass, no existing ruling covers it — flag, don't invent a rationale; may be
combined with a verification stamp, e.g. `open-question, verified <SHA>`, when the
*difference* is confirmed but its *disposition* isn't ruled — no row currently
illustrates this combined form; D3 carried it until its 2026-08-23 ruling, see its
Ruling/Epistemic cells).

Placement: pick the lettered section (A backend selection, B enforcement, C
placement/platform, D event streams, E cadence/resource) whose description above fits;
IDs are sequential within that letter (the next row after D9 is D10, not D1a or
E-something). Insert the new `### <ID> — ...` block right after the last existing row in
that section, ahead of that section's one closing `---` — there is a single `---` per
section, not one between every row, so do not add a separator between rows.

Two permitted variants: a row gating on a still-open flip-ladder decision (e.g. flip-ladder
decision D4 — a numbering tracked in the operator's local flip-ladder plan, distinct from
this doc's own row IDs; disambiguated as "flip-ladder decision Dn" everywhere it's cited)
may
add an 8th **Ruling** field instead of leaving "Why deliberate" empty; a row describing a
multi-OS delta (e.g. C2) may replace the single Legacy/Spark pair with a platform matrix
table. Both stay within the same intent — state what's known, cite where to verify,
never invent a rationale for what isn't ruled yet.

---

## A. Backend selection (agent-wide)

### A1 — `spark_failed` / `unwired` refuse the legacy fallback

| | |
|---|---|
| **Legacy** | N/A — this state only exists when `prefer_spark=true` |
| **Spark** | Every rule is withdrawn from legacy and left unarmed. Nothing enforces, nothing detects, for the whole agent, until the operator intervenes. |
| **Why deliberate** | "SparkFailed and Unwired NEVER fall back to legacy - a failure must be visible (errored), never silently absorbed (mutual exclusion)." Ruling R1 (design doc, backend-selection table + correlated-outage note). |
| **Operator symptom** | `yuzu.guardian_backend` heartbeat tag reads `spark_failed` or `unwired` for the affected agent. **No fleet-level Prometheus gauge exists for this today** — `yuzu_fleet_spark_failed{os}` is adjacent but not identical (it tracks SparkEngine boot failure only, not a post-boot wiring failure or `Unwired`). A fleet-wide SparkEngine boot throw is a correlated-outage tail: every agent in the cohort loses enforcement simultaneously until `--spark-disable` is set. |
| **Verify at** | `GuardianEngine::reconcile_rule_locked`'s `SparkFailed`/`Unwired` guard (withdraws legacy, `unsupported_rules_.erase`, returns false); `GuardianEngine::wire_spark_engine()`'s `!engine` branch ("spark path unavailable... never silently substituted"); `guardian_backend_from_state()` / `guardian_backend_label()` in `guardian_backend.hpp`. |
| **Epistemic** | verified b16e5836d |

### A2 — Mutual exclusion is per-rule; a spark arm failure never falls through

| | |
|---|---|
| **Legacy** | Arm failure (invalid config, platform mismatch) → warn-logged, rule stays unarmed. No distinct state, no counter. |
| **Spark** | `withdraw_legacy_guard_locked()` runs *before* the arm attempt. On `attach_rule` failure: warn-logged (`"Guardian: spark arm failed for rule '{}': {}"`), rule armed by **neither** backend. |
| **Why deliberate** | Routed-concerns Spark row: "a rule is armed in at most one of legacy `guards_` or `spark_runtime_`, never both; an arm failure is errored, never a silent fallback." |
| **Operator symptom** | A rule that fails to arm under spark reports `errored` via `get_status()` (same fail-closed bucket as everything else — see §F). No per-rule reason surfaced yet (rung 4). |
| **Verify at** | `reconcile_rule_locked`'s `RulePlacement::Arm` branch (`guardian_engine.cpp`). |
| **Epistemic** | verified b16e5836d |

---

## B. Enforcement

### B1 — Detect-only window: spark never remediates

| | |
|---|---|
| **Legacy** | Enforces on exactly two mechanisms, both Windows-only: **Registry** (`RegSetValueExW`/`RegCreateKeyExW`) and **Windows Service** (`StartServiceW`/`ControlService`). File is detection-only *by design* on every platform. Linux systemd Service is **observe-only in v1** even under `enforcement_mode=enforce` (explicit runtime warn: "enforce-mode not yet supported on Linux"). |
| **Spark** | Detect-only, unconditionally, every mechanism, every platform. `RuleAssertion` carries no enforce/remediation field; `ResilienceConfig`'s remediation mode is read and discarded; `cfg.enforce` is consulted only on legacy branches. |
| **Why deliberate** | Rung-2 posture table (`guaranteed-state.md`): "2 (later): drives detection, observe-only (the default path) ... nothing [enforces] — a deliberate spark detect-only burn-in." Enforcement lands rung 3. |
| **Operator symptom, stated precisely** | The flip's enforcement regression is: **Windows enforce-mode Registry/Service rules become observe-only until rung 3.** Linux and macOS enforcement posture is **unchanged** by the flip — legacy never enforced there either (Linux Service was already observe-only; File/Registry were never supported on Linux or macOS at all — see C2). |
| **Ruling** | **Flip-ladder decision D4 RULED (Dave, 2026-08-23):** the gap is accepted as temporary, with no fixed budgeted duration — rung 3 is not gated on a deadline, and `--spark-disable` remains the per-box escape hatch for any operator who needs continued Windows Registry/Service enforcement during the gap. The flip proceeds as a **hard cutover** (every agent flips `prefer_spark_` at once via version bump, matching the 7.7b design already described above), not a staged/canary rollout. |
| **Verify at** | `guardian_spark_bridge.hpp` (RuleAssertion has no enforce field; ResilienceConfig discard comment); `guard_registry.cpp`/`guard_service.cpp` `cfg_.enforce` branches; `guard_systemd.cpp`'s Linux enforce-mode warn; `guard_file.cpp`'s "Detection-only: a FileGuard never writes" comment. |
| **Epistemic** | verified b16e5836d |

---

## C. Placement / platform

### C1 — `unsupported` is a distinct, per-rule terminal state (not a legacy fallthrough)

| | |
|---|---|
| **Legacy** | A guard whose mechanism doesn't exist on this platform is a compile-time stub returning `false` from `start()`. No distinct state, no per-rule tracking, no heartbeat surface, no counter — just an unarmed rule and a warn log blending "unsupported platform" with "authoring fault" into one string. |
| **Spark** | `RulePlacement::Unsupported` (a recognized spark type with no *registered-and-functional* mechanism on this host) is a terminal state distinct from both `Arm` and agent-wide `SparkFailed`/`Unwired`. Withdraws from both backends, records the rule_id in `unsupported_rules_` (erased on every other outcome, so the map is exact), edge-logs only on a genuine transition ("new, or a different type than before"). |
| **Why deliberate** | Ruling R2 + F7 (#3321): "Legacy already no-ops there; what changes is reporting" — since rung 5 deletes the legacy backend entirely, there is no fallthrough target left, so building the fallthrough once at rung 2 is building it twice. |
| **Operator symptom** | `yuzu.spark_<mechanism>_unsupported` per-agent heartbeat tag → `yuzu_fleet_spark_unsupported{os,mechanism}` fleet gauge (a live, current-value gauge — it can legally decrease). **Caveat, not a universal guarantee:** `classify()` keys off registered-AND-non-inert capability, so a mechanism that started but couldn't bind its OS facility (no systemd bus in a container, `OpenSCManager` access denied) lands a rule in `Unsupported` on a platform where legacy might otherwise have worked. Cross-check `yuzu_fleet_spark_mechanisms{os,mechanism}` + that mechanism's boot logs before assuming "routine cross-platform gap." |
| **Verify at** | `reconcile_rule_locked`'s `RulePlacement::Unsupported` branch; `classify()` in `guardian_spark_bridge.hpp`; `guardian_unsupported_heartbeat.hpp`; `agent_registry.cpp`'s `yuzu_fleet_spark_unsupported` gauge set. |
| **Epistemic** | verified b16e5836d |

### C2 — Platform coverage matrix

| OS | Spark | Legacy | Delta |
|---|---|---|---|
| Windows | File + Registry + Service (all real mechanisms) | File + Registry + Service (all real guards) | Coverage parity. The delta is enforcement (B1) and event streams (D1/D2), not detection coverage. |
| Linux | Service only, and only when built with `YUZU_HAVE_LIBSYSTEMD` | Service only (systemd, same libsystemd gate — **both paths go dark for Service simultaneously** on a build without it), observe-only even in enforce mode | File/Registry: `unsupported` under spark, silent `return false` stub under legacy — **spark's only change is that an already-absent capability becomes named and counted, not that anything newly fails to detect.** |
| macOS | Zero mechanisms — all three factories return `nullptr` | Zero — all four legacy guards are stubs on macOS (`make_service_guard()` routes to the non-Linux `ServiceGuard` stub) | **Zero-vs-zero today.** The flip does not create macOS zero-detection — macOS already has zero detection under legacy. What the flip changes is **visibility**: a macOS rule goes from silently-unarmed-with-no-signal (legacy) to `unsupported`-with-a-counted-gauge (spark). This corrects a broader D4/flip-ladder framing that stated "flip day makes macOS zero-detection" — the detection state doesn't change, the observability of it does. |
| **Ruling** | **Flip-ladder decision D4 RULED (Dave, 2026-08-23):** confirmed as this row states it — the macOS delta is visibility-only, not a detection regression, and flip-ladder decision D4's original "flip day makes macOS zero-detection" framing is retired. Nothing further to accept here; this row's finding stood as the correction. | | |
| **Verify at** | `spark_file.cpp`/`spark_registry.cpp`/`spark_service.cpp` factory `#else` branches; `guard_file.cpp`'s `FileGuard::start()`, `guard_registry.cpp`'s `RegistryGuard::start()`, `guard_service.cpp`'s `ServiceGuard::start()`, and `guard_systemd.cpp`'s non-Linux stub — all `return false` unconditionally; `docs/capability-registries/spark_mechanisms.tsv` (independently agrees). |
| **Epistemic** | verified b16e5836d |

---

## D. Event streams (wire-visible — where a parity diff will actually show up)

### D1 — Health stream (`guard.healthy`/`guard.unhealthy`) is spark-only

| | |
|---|---|
| **Legacy** | Emits no health stream at all. Its only emission point is `GuardianEngine::emit_guard_event`, called from exactly the three legacy guard sinks (file, service, registry); the shared event-type vocabulary it builds from (`guardian_drift_event.cpp`) contains `drift.detected`/`drift.remediated`/`remediation.failed`/`guard.compliant` — no health token exists in that set. |
| **Spark** | Edge-only + bounded periodic refresh. Emits `guard.unhealthy` on the false→true "unknown" edge; a persisting Unknown is suppressed and counted (`unhealthy_suppressed_`) rather than re-emitted, except a slow refresh every `errored_refresh_ms` (default 300 000 ms) that re-emits with the *current* error detail so a lost edge doesn't leave the server's view stale forever (counted separately as `unhealthy_refreshed_`). A rule stuck Unknown for `pending_demote_sweeps` (12) committed Convergence-reason evals or `pending_demote_ms` (120 000 ms), whichever first, is demoted off the 5 s priority lane onto its normal 60 s/600 s type-lane cadence (`priority_demoted_`). |
| **Why deliberate** | M1 finding (design doc): unconditional per-sweep health emission was a **cutover-blocking flood** (~17k/day/rule pre-fix) — "Legacy has no health stream, so this traffic class switches on at the flip." Fixed in two parts: edge-guard (`b30e93cfd`), then F5 (#3005) added the bounded refresh + demotion back on top of the edge-only silence as a deliberate, budgeted non-zero ceiling (a lost-edge backstop, not free). |
| **Operator symptom** | Measured steady-state ceiling, F11 (#3267): **1 edge + 288 refreshes/day/rule/agent** on the 60 s lane, **1 edge + 180/day** on the 600 s file lane — full derivation (jitter accounting, the corrected 144-vs-180 figure) in `docs/spark-rebuild-baselines/f11-flood-measurement-run.md`. **Epistemic note:** per F11's own PR scope note, these are "a derived bound, mechanism empirically pinned" — no test asserts a per-day count directly; the mechanism constants (`errored_refresh_ms`, demotion thresholds, lane cadences) are pinned by Catch2, the per-day figure is arithmetic derived from them. Sparse heartbeat tags: `yuzu.guardian_unhealthy_suppressed`/`_refreshed`, `yuzu.guardian_priority_demoted` → fleet gauges `yuzu_fleet_guardian_unhealthy_suppressed`/`_refreshed`, `_priority_demoted` (monitor-only, per-sweep fleet sums). |
| **Verify at** | `guardian_rule_eval.cpp` (`unhealthy_edge`), `guardian_spark_runtime.cpp` (`refresh_due`, `unhealthy_suppressed_`/`_refreshed_`/`priority_demoted_`), `guardian_spark_runtime.hpp` `Config::errored_refresh_ms`/`pending_demote_sweeps`/`pending_demote_ms`; `docs/spark-rebuild-baselines/f11-flood-measurement-run.md`. |
| **Epistemic** | verified b16e5836d |

### D2 — Lifecycle stream (`guard.armed`/`guard.disarmed`) is spark-only, durable, bounded-retry, duplicate-tolerant

| | |
|---|---|
| **Legacy** | Emits no lifecycle events. |
| **Spark** | Durable KV-backed journal (`__guardian_journal__` namespace, keys `lc:<ts13>:<nonce>:<seq12>`). Replayed on boot (first pass runs unconditionally), on reconnect (a kick, not a page — sets the drain worker's `force_page_`), and on a headroom-refill re-arm. An ordinary (non-forced) pass **skips** any batch already carrying a durable sent-label — so steady state does not re-offer delivered batches; only a forced pass (boot/reconnect/refill) re-offers them, and the sent-label gates re-paging, never deletion. Bounds: 0.1 batch/s refill, burst 5, ≤128 batches/pass, 7-day / 1000-batch / 32 MiB retention, 30 s page / 120 s prune cadence. `guard.errored` is a declared-but-unproduced lifecycle kind; `unsupported` is **not** a lifecycle kind at all (it's the C1 heartbeat gauge instead). |
| **Why deliberate** | #2297: "honest process-crash-durable, duplicate-tolerant, bounded-retry — not audit-grade at-least-once. Every loss channel is a counted metric, never silent." #2448 (batch-key timestamp) made the maintenance passes O(work) instead of O(journal size). |
| **Operator symptom** | Server absorbs duplicates silently and cheaply: `insert_event_classified` runs the row insert under its own `SAVEPOINT`; on SQLSTATE `23505` it rolls back to the savepoint (un-aborting the whole transaction, a Postgres-specific need) and byte-compares 13 agent-supplied columns. A match → `Redelivered` (debug-logged, no new row, DEX/blast-radius observers deliberately NOT re-fired — a redelivery must not re-trigger them); a mismatch → `Conflict` (warn-logged, dropped). Nothing is returned to the agent either way — the agent never sees a rejection for a legitimate replay. The batch insert path (`insert_events`) is explicitly forbidden for replays — it aborts the whole batch on any collision, unlike the one-at-a-time path. Traffic bounds: `yuzu_fleet_guardian_journal_*` — `_pages` (activity denominator), `_records_paged`, `_evicted_no_send_evidence` (the CC7.3-relevant integrity-gap counter), `_page_stale_seconds_max` (expect ~30 s), `_prune_stale_seconds_max` (expect ~120 s) — all absent while `prefer_spark` is off. |
| **Verify at** | `guardian_lifecycle_journal.hpp` `page_into_window`/`replay_sent`; `guardian_outbox_drain_worker.cpp` `force_page_` triggers; `guaranteed_state_store.cpp` `insert_event_classified` (SAVEPOINT + `23505` + `stored_event_matches`) and `insert_events`' header comment forbidding batch-path replay; `docs/user-manual/guaranteed-state.md` "Reconnect replay traffic". |
| **Epistemic** | verified b16e5836d |

### D3 — Drift re-emission's per-sweep debounce guard is now sweep-cadence-aware (#3388, merged)

| | |
|---|---|
| **Legacy** | No sweep to re-emit on: File/Registry/Windows-Service are kernel-notification-driven (`ReadDirectoryChangesW`/`RegNotifyChangeKeyValue`/SCM APC) with an `INFINITE` healthy-wait — no further FS/registry event, no further emission. systemd is D-Bus-signal-driven with a terminal-state dedup (`systemd_decide_emit`: identical terminal state → `NoChange`) — its 60 s "healthy reconcile" safety poll re-emits nothing for an unchanged state. **One asymmetry inside legacy itself:** Windows Service has *no* terminal-state dedup on the drift branch, and its 30 s absent-retry timer re-emits `drift.detected` every ~30 s while the service stays absent — this is a pre-existing legacy behavior, not spark-introduced. |
| **Spark** | `guardian_emit_decider.hpp`'s shared `decide_emit` has **no last-terminal-state dedup** ("unlike systemd_decide_emit... not needed at the consumer" — reasoned from File/Registry's own re-read-on-change + debounce-fold behavior, and Service's one-event-per-edge behavior). Its only suppression is a debounce window (`RuleAssertion::debounce_ms`) measured from the last **emit**, not from attach or from a terminal-state hash. Convergence sweeps run every 60 s (service/registry) or 600 s (file). **As of #3388 (merged, PR #3518), `debounce_ms`'s default is no longer the flat legacy 1000 ms for a spark rule**: `rule_assertion_from_rule` (`guardian_spark_bridge.hpp`) now defaults it per spark type to that lane's cadence plus the convergence scheduler's own jitter span (`guardian_jitter_span_ms`, `spark.hpp`) — **72,000 ms** for the 60 s service/registry lanes, **720,000 ms** for the 600 s file lane (from `kGuardianServiceLaneCadenceMs`/`kGuardianRegistryLaneCadenceMs` = 60,000 ms, `kGuardianFileLaneCadenceMs` = 600,000 ms, `kGuardianLaneJitterPct` = 20). Unlike D1's health refresh, the Drift branch still has no `errored_refresh_ms`-style floor — the bound here is the debounce window itself, sized against sweep cadence rather than being a fixed constant unrelated to it. **Net, recomputed directly from the shipped constants (not the pre-merge "roughly halved" estimate):** at the lanes' nominal (unjittered) cadence the 72 s/720 s window survives exactly one sweep but not two, so a persistently-drifted rule emits every OTHER sweep — **`86,400 / (60×2) = 720/day`** (60 s lanes), **`86,400 / (600×2) = 72/day`** (file lane), exactly half the pre-fix naive 1440/144, matching the fix's own "roughly halves" framing. The jitter-adjusted **worst case is higher, not the same fraction**: because the debounce window and the scheduler's jitter span share the same formula and constants, a sweep sequence that sustains the jitter-lengthened extreme (`cadence×(1+jitter_pct/100)` between sweeps — exactly the debounce window's own value) satisfies the debounce test on every single sweep, giving **`86,400 / 72 = 1200/day`** (60 s lanes) and **`86,400 / 720 = 120/day`** (file lane) — two-thirds of the pre-fix worst case (1800/180), not half. |
| **Ruling** | **D3 RULED (Dave, 2026-08-23), interim fix — option 2 of 3 offered** (accepted-delta / raise-the-default / full M1-shaped edge+refresh redesign): raise the default, not the full redesign, which stays open for later reconsideration. **The decision is settled AND merged.** The fix landed via PR #3518 (`fix/2298-3388-drift-debounce-default`, merge SHA `fdc34edbb3ac26f148491406b52f6fefb1fd1814`, 2026-08-26) — verified reachable from `origin/dev` (`git merge-base --is-ancestor fdc34edbb3ac26f148491406b52f6fefb1fd1814 origin/dev` succeeds). Issue #3388 carries both the ruling and a correction comment (the initial rate figures were the naive no-jitter calculation; a follow-up comment corrected them to the jitter-adjusted worst case). The shipped shape matches what was drafted: `parse_resilience_params` gained a defaulted `default_event_debounce_ms` parameter (legacy call sites unaffected, still get the implicit 1000 ms), and spark's call site (`rule_assertion_from_rule`) computes its own default per rule type from lane cadence + the scheduler's own `guardian_jitter_span_ms` — single-sourced with the convergence scheduler's own jitter arithmetic so the two can't silently drift apart (a real duplicate-formula divergence was caught and fixed during this PR's own review, governance ledger finding `3388-ce-1`). Issue #3388 stays **open**: this interim fix does not resolve the full M1-shaped edge+refresh redesign question, which remains open for later reconsideration per the ruling. |
| **Why deliberate** | M1 (the design doc's cutover-blocking finding) scoped its flood analysis and fix explicitly to the **health** (Unknown) stream — its own text never mentions the Known/drift path, and no test in `test_guardian_spark_runtime.cpp` pins repeated-drift-sweep behavior (the "M1 flood guard"/"F11 flood" test cases are all Unknown/demotion cases). The `decide_emit` header comment's stated rationale ("not needed at the consumer... File/Registry re-read on each change... so a plain compliant-bool suffices") describes the *legacy-parity* reasoning for skipping terminal-state dedup, but does not address the convergence-scheduler sweep cadence being the trigger for repeat evaluation in the first place — that trigger doesn't exist for legacy (no sweep) and does for spark. The shared 1000 ms default couldn't simply be raised across the board: legacy's notification-driven model (no scheduled re-sweep) genuinely needs a short window, so raising the SHARED default would have changed the currently-running production legacy path's behavior too — hence a spark-specific default rather than a shared-constant bump. |
| **Operator symptom** | A rule left persistently drifted under spark (e.g. an enforce-mode rule now observe-only per B1, with nobody fixing the underlying drift) generates a `drift.detected` stream **today, in this tree, bounded by the debounce window rather than raw sweep cadence**: nominally 720/day (60 s lanes) or 72/day (file lane), jitter-adjusted worst case 1200/day or 120/day respectively (see the Spark cell above for the derivation) — down from the pre-fix worst case of 1800/day and 180/day, and much smaller than the pre-fix health flood (~17k/day), but the re-emission itself is NOT eliminated — it is reduced and bounded. The full M1-shaped redesign (terminal-state dedup on the Drift branch) remains the option for whoever revisits this; #3388 stays open to track it. |
| **Verify at** | `guardian_emit_decider.hpp::decide_emit` (no `last_compliant`-driven terminal dedup on the Drift branch — unaffected by this fix, still a candidate for the deferred M1-shaped redesign); `guardian_spark_bridge.hpp`'s `rule_assertion_from_rule` (the per-spark-type `switch` computing `default_debounce_ms` from lane cadence + jitter span, immediately before its `parse_resilience_params` call); `resilience_strategy.hpp`'s `parse_resilience_params` (defaulted `default_event_debounce_ms` = `kGuardianLegacyDebounceMs`, 1000 ms; legacy call sites still get it implicitly); `spark.hpp` (`kGuardianServiceLaneCadenceMs`/`kGuardianRegistryLaneCadenceMs`/`kGuardianFileLaneCadenceMs`/`kGuardianLaneJitterPct` and the `guardian_jitter_span_ms` formula itself, plus its `static_assert(kGuardianLaneJitterPct < 34, ...)` guarding the margin this fix relies on); `guardian_convergence_scheduler.cpp`'s `jittered()` (the scheduler's own call site for the SAME `guardian_jitter_span_ms` formula — single-sourced, not a duplicate, per governance ledger `3388-ce-1`); `tests/unit/test_guardian_spark_bridge.cpp` (pins the per-lane defaults); `guard_systemd.cpp` `systemd_decide_emit` (contrast: has terminal-state dedup, unrelated). |
| **Epistemic** | **verified 71cb8b6708b681436a312b57be075c4dcc4a05f6** — the merge SHA `fdc34edbb3ac26f148491406b52f6fefb1fd1814` and every symbol/constant cited above (`guardian_spark_bridge.hpp`, `spark.hpp`, `guardian_convergence_scheduler.cpp`, `resilience_strategy.hpp`) confirmed present at this `origin/dev` tip, and the nominal/worst-case rate figures recomputed directly from the shipped constants rather than reused from the pre-merge estimate. |

**Possible tension with the parity gate's own zero-tolerance clause (flagged during Gate 3
architect review, not yet resolved):** the design doc states event-stream equivalence
checks use tolerance bands "**only for observe/debounce noise**"; "enforce-class and
dangerous-drift `event_type`s require zero-tolerance exact match — a tolerance band would
let a real enforce divergence pass." D3's bounded-but-nonzero re-emission is a genuine
event-*count* divergence, not timing noise — and if a rule can be both dangerous-classified and
persistently drifted (nothing in B1/C1 rules that combination out), a scripted parity
capture on such a rule would show exactly the count mismatch that clause exists to catch.
Whether "dangerous-drift" is scoped to cover count/frequency, and if so whether D3 blocks
F14 on those rules specifically, is an open question for #3388 to resolve — not decided
here.

### D4 — Compliant-edge emission is unified across types (a spark-side legacy-parity fix)

| | |
|---|---|
| **Legacy** | File, Registry and Windows-Service all emitted `guard.compliant` on the edge into compliant (`guard_registry.cpp`'s compliant-edge branch behaves identically to File/Service — confirmed by direct read, not inferred); systemd never did (v1 legacy design; `guardian_emit_decider.hpp`'s own `emit_compliant_edge` doc comment names "File / Registry / Windows-Service behaviour" as the precedent this unifies onto, so Registry's inclusion was cited by the source this row already relies on, just previously omitted here). |
| **Spark** | `emit_compliant_edge=true` is hardcoded at the sole production `attach_rule` call site — every type gets a compliant edge, including Linux Service. |
| **Why deliberate** | `decide_emit`'s header comment: "unifies the compliant-census signal across platforms: legacy Windows-Service emitted it, legacy systemd did not." A caller may pass `false` to preserve exact legacy-systemd silence (pinned in parity tests), but production doesn't. |
| **Operator symptom** | A Linux Service rule under spark reports one `guard.compliant` census event on arm/recovery that the equivalent legacy systemd guard never sent. |
| **Verify at** | `guardian_emit_decider.hpp` (`emit_compliant_edge` doc comment); `guardian_engine.cpp`'s `attach_rule` call (`/*emit_compliant_edge=*/true`). |
| **Epistemic** | verified b16e5836d |

### D5 — Restart re-arms both backends' compliant edge pre-network, but only spark's boot-time edge reliably reaches the server

| | |
|---|---|
| **Legacy** | File/Registry/Windows-Service **do** re-fire `guard.compliant` in-process on every restart: `guard_registry.cpp`/`guard_file.cpp`/`guard_service.cpp` each carry an identical per-guard-instance `last_compliant` (`std::optional<bool>`) that starts `nullopt`; `start_local()`'s restart re-arm loop spawns a **fresh** guard thread per cached enabled rule (arming a legacy guard spawns a `std::thread`), so `last_compliant` resets and the guard fires `guard.compliant` on the first reconcile again. But `start_local()` runs pre-network, before the event sink is wired (`agent.cpp`'s "Phase-1 pre-network startup" comment; `set_event_sink` isn't called until after the Subscribe stream opens) — and `emit_guard_event` unconditionally **drops** the event when no sink is wired yet, uncounted, no buffering (`if (!sink) return; // sink not wired yet ... drop; durable buffering is A3` — A3 is not built). So on an ordinary restart with no pending server-side policy change, this in-process re-fire is designed to be dropped before it reaches the server — the outbox header comment names exactly this pre-network window as the gap legacy's synchronous, unbuffered send has no equivalent fix for. In practice the server generally sees zero new compliant rows from this path; a guard whose first reconcile is still in flight (e.g. mid-hash on a large file) when the sink wires is the one exception, and there is no code-level timeout bounding it — `start_local()`'s reconcile loop runs to completion with no deadline, so the exception's actual size is however long the slowest cold-start reconcile takes. Do not wave through a nonzero legacy compliant count on this clause alone: cross-check the rule's own arm/first-reconcile timestamp against the agent's Subscribe-stream-open timestamp (both are locally observable — `start_local()`'s call site and `agent.cpp`'s post-Subscribe `set_event_sink` call site) before attributing a nonzero count to this exception rather than to a genuine regression. Linux Service (systemd) never even mints the in-process edge to begin with (D4: legacy systemd never emitted `guard.compliant`, any type). The one case legacy DOES eventually deliver a new compliant row: a post-connect server-side reconcile push, gated on `agent_gen < current` (`server.cpp`) — i.e. only when the agent's policy generation is stale relative to the server, not on a routine no-change restart; `sync_with_server()` itself is a no-op log line, not a re-push trigger. |
| **Spark** | Also re-fires the compliant edge in-process on restart, for **every** type including Linux Service (D4: spark unifies `emit_compliant_edge=true` across all types) — via a fresh random `boot_nonce_` folded into `make_event_id`, and a fresh `RuleGeneration` built on every attach. The same pre-network timing applies (`start_local` also runs before the sink is wired for spark), but the outcome differs: `GuardianOutbox` exists specifically to close this gap — its own header comment states the scenario verbatim: "GuardianEngine arms and does its initial eval BEFORE the server sink is published... Emitting straight to the sink there DROPS the event... The consumer instead enqueues here and drains when the sink is live." So spark's boot-time compliant edge is buffered, not dropped, and is reliably delivered once the connection comes up — on an ordinary restart with N armed rules, the server reliably sees N new `guard.compliant` rows. |
| **Why deliberate** | Consequence of the outbox design (#2233 hardening, same root cause as D9) rather than a dedicated ruling for this specific row: buffering across the pre-network gap was built for spark's async/batched send model; legacy's synchronous, unbuffered `emit_guard_event` predates that model and was never retrofitted with equivalent buffering (A3 remains unbuilt for legacy). Not itself a spark-only *design intent* to differ — it's an *inherited* gap in legacy's older delivery path that spark's newer one happens to close. |
| **Operator symptom** | Opposite of the row's own earlier framing: on a routine restart with N armed rules and no pending policy-generation lag, **spark reliably produces N new `guard.compliant` server rows** (a real restart-storm, sizing input for F14's 3-OS matrix / resource baseline) while **legacy generally produces zero** — its boot-time compliant edges are silently lost, and Linux Service never had one to lose. This is a genuine parity-gate-relevant delta, not the "shared, not itself a delta" framing this row previously (incorrectly) settled on. Fleet-wide, this compounds with B1's Ruling: the flip is a **hard cutover** (every agent flips at once via version bump, not staged/canary), so this restart-storm class isn't the only synchronized burst F14 needs to size — a fleet-wide flip itself produces the same `fleet_size × armed_rules` compliant-edge burst on day one, landing all at once rather than trickling in per-agent-restart. **#1603** (open) already flags this exact class of synchronized ingest burst for the original compliant-edge rollout (item 2: "confirm the guardian ingest path absorbs a synchronized N×M burst... a large burst can starve concurrent drift ingest past `busy_timeout`") — this row's finding makes that question more pressing for F14 than it was when #1603 was filed, since legacy previously masked how much volume a synchronized re-arm produces. |
| **Verify at** | `guard_registry.cpp`, `guard_file.cpp`, `guard_service.cpp` (identical `last_compliant` pattern, confirmed directly in all three); `guardian_engine.cpp::start_local()` (pre-network restart re-arm) and `::emit_guard_event` (`if (!sink) return` unconditional drop, uncounted); `agent.cpp` ("Phase-1 pre-network startup" comment, `set_event_sink` call site after Subscribe opens); `guardian_outbox.hpp`'s header comment (the pre-network/A3 gap it closes, spark-only); `guardian_spark_runtime.cpp` (`make_boot_nonce`/`boot_nonce_`, fresh `RuleGeneration` on attach); `server.cpp`'s `agent_gen >= current` reconcile gate and `guardian_engine.cpp::sync_with_server()` (confirmed a no-op log line); D4 (Linux Service never had a legacy compliant edge to lose). |
| **Epistemic** | verified b16e5836d |

### D6 — Transient vs. persistent read failure (file hash/read only): legacy conflates, spark splits

| | |
|---|---|
| **Legacy** | Scoped to **file** hash/read failures only — this is `FileSnapshot::readable`'s own concept (`guardian_rule_eval.hpp`'s comment ties `<unreadable>` explicitly to files), not a fleet-wide legacy behavior. For files: one `<unreadable>` token for both a transient read glitch and a persistent drift-causing failure — both land as Known drift. Registry and Service do **not** share this conflation: legacy registry returns distinct `<absent>`/`<unsupported-type>` tokens (`guard_registry.cpp`) rather than a generic unreadable token, and legacy systemd distinguishes `NoSuchUnit` (genuine absence) from a bare D-Bus transport failure via `systemd_error_name_is_absence` (`guard_systemd.cpp`) rather than conflating the two. |
| **Spark** | For files: splits them — a persistent failure is Known drift (goes through D3's drift path); a transient failure is Unknown (goes through D1's health stream instead). The recovery leg of that transient-Unknown path has its own forced-re-emit behavior — see D11. Whether spark's registry/service readers make an equivalent transient-vs-persistent split has not been separately verified for this row — do not assume it from the file case. |
| **Why deliberate** | `guardian_rule_eval.hpp` preamble: legacy's **file** reader conflated the two into one token; spark's file path splits persistent (Known drift) from transient (Unknown) deliberately. |
| **Operator symptom** | A flaky **file** read source produces health-stream traffic under spark where it would have produced drift-stream traffic under legacy — different wire event types for the same underlying condition. A registry/service transient-fault capture should **not** be waved through against this row — legacy registry/systemd don't share the file-specific conflation this row documents, so there is no equivalent "expected" baseline here for those mechanisms without separate verification. |
| **Verify at** | `guardian_rule_eval.hpp`'s `FileSnapshot::readable` comment (file-scoped) and `guardian_rule_eval.cpp` Unknown-vs-Known-drift classification; `guard_registry.cpp` (`<absent>`/`<unsupported-type>` tokens, contrast); `guard_systemd.cpp::systemd_error_name_is_absence` (contrast). |
| **Epistemic** | verified b16e5836d |

### D7 — File hash-mode `settle_ms` coalescing is not honoured under spark

| | |
|---|---|
| **Legacy** | `guard_file.hpp`'s `settle_ms` (default 750 ms) coalesces a burst of kernel file-change notifications before hashing, since writes aren't atomic — waits out the write before computing a hash, to avoid a torn read. This is a bounded heuristic, not an unconditional guarantee: `max_settle_defer_ms` (default 5000 ms) caps the total defer, so under a write storm longer than that cap legacy hashes anyway and can still land a torn read. |
| **Spark** | No equivalent field on `RuleAssertion` or `FileSparkParams`. Spark's convergence scheduler instead dead-reckons via a size+mtime skip before re-hash plus a forced periodic re-hash (both **deferred to rung 5** — see E1; at rung 2 there is only the plain convergence sweep, no coalescing and no skip-optimization yet). |
| **Why deliberate** | `guardian_spark_bridge.hpp` header comment states this explicitly: "an ACCEPTED behavioral delta from legacy... flagged here for the rung-9 design-doc rewrite and the rung-10 parity/durability matrix" — i.e. this doc is that flagged destination. |
| **Operator symptom** | A file rule under active mid-write churn may see a spark hash read land mid-write (a torn read) where legacy's coalescing window would have waited it out — until rung 5's size+mtime skip + forced re-hash lands. Spark does hedge this at the reader, not just leave it torn: `guardian_state_reader.cpp` retries the hash read up to `kHashAttempts` (3) times on a mutating file, and only if all three still land mid-write does it give up and report Unknown (`read_unknown<FileSnapshot>("file mutating during hash, retries exhausted")`) rather than a torn Known value — so the observable failure mode on a genuinely fast-churning file is D1's health stream, not a silently-wrong drift verdict. This is a detector, not a replacement: it narrows the torn-read window, it doesn't provide `settle_ms`'s bounded coalescing heuristic (750 ms settle, 5000 ms cap), which spark never had to begin with — and that heuristic was never an unconditional guarantee under legacy either (see Legacy cell). |
| **Verify at** | `guard_file.hpp` `Config::settle_ms`/`Config::max_settle_defer_ms`; `guardian_spark_bridge.hpp` header comment (immediately above `RuleAssertion`/`FileSparkParams`); `guardian_state_reader.cpp` `kHashAttempts` retry loop + its `read_unknown<FileSnapshot>("file mutating during hash, retries exhausted")` exhaustion path. |
| **Epistemic** | verified b16e5836d |

### D8 — Deleted-service wire token: legacy `Absent`, spark folds into `Stopped`

| | |
|---|---|
| **Legacy** | Reports a distinct `Absent`/`<unreadable>`-class token for a service that no longer exists on the host. |
| **Spark** | A deleted service folds into `ServiceState::Stopped` at the reader — there is no `Absent` verdict; only the shared `ReadResult<ServiceRunState>::known` gate (`eval_service`'s `if (!read.known) return unhealthy(...)`, the same generic Unknown/Known mechanism `eval_file`/`eval_registry` also use) distinguishes "can't tell" from "definitely not running." D6 documents a further, *file-specific* transient-vs-persistent split layered on top of this generic gate — Service does not carry that additional split, so don't cite D6 here. |
| **Why deliberate** | Code comment (R5, accepted): "a deleted service folds into Stopped at the reader — the compliance VERDICT is identical, only `detected_value` differs from legacy." The enforcement/compliance outcome doesn't change; the wire-visible token does. |
| **Operator symptom** | An F14 event-field parity capture comparing `detected_value` for a deleted-service rule will show `Absent` (legacy) vs `Stopped` (spark) — an expected, ruled diff, not a regression, but it WILL show up in a byte-level field diff even though the compliance verdict matches. |
| **Verify at** | `guardian_rule_eval.cpp`/`guardian_rule_eval.hpp` "R5, accepted" comment on the deleted-service reader mapping into `ServiceState::Stopped`. |
| **Epistemic** | verified b16e5836d |

### D9 — Send-path drop semantics: legacy silent/unbounded, spark counted/bounded

| | |
|---|---|
| **Legacy** | `emit_guard_event` calls the event sink directly and synchronously from the guard worker thread — no buffering, no capacity bound. Three distinct silent, uncounted failure modes, not two: (1) pre-Register, no sink wired yet — the event is dropped (comment: "sink not wired yet (pre-network arm) — drop; durable buffering is A3"); (2) post-Register but mid-reconnect, `agent.cpp`'s `emit_guardian_event` finds `guardian_sink_stream_` null and drops the write (comment: "Drops the event if the link is down between reconnects... durable buffering is A3" — same A3 residual, a second call site); (3) post-Register, stream non-null but the transport is already broken — `emit_guardian_event` calls `guardian_sink_stream_->Write(resp, grpc::WriteOptions())` and discards the return value (`agent.cpp`), so a failed write in the window between "transport breaks" and "the Subscribe loop detects it and resets `guardian_sink_stream_`" is also silently dropped, uncounted, with no retry — contrast spark's `send_guardian_outbox_entry`, which checks that identical `Write()` call's return value and returns `SendResult::Retain` on failure so the drain worker retries. None of the three is counted. When a sink IS wired and the write succeeds, the call does not drop under overload — it *blocks* the guard worker thread on the network send instead ("the (potentially blocking) network send" per `emit_guard_event`'s own header comment), which is a different failure mode than "nothing to overflow": there is no overflow because there is no bound, but a slow/stalled send stalls detection on that thread rather than losing the event. |
| **Spark** | Compliance/health entries route through `GuardianOutbox`, a FIFO, per-(domain,rule_id)-coalesced, **capacity-bounded** buffer. A push that would exceed capacity is dropped and **counted** (`outbox_backpressure_drops()`), never silent — routed to the agent heartbeat as `yuzu.guardian_outbox_backpressure_drops` and rolled up fleet-wide as `yuzu_fleet_guardian_outbox_backpressure_drops` (#2993, closed and wired end-to-end). |
| **Why deliberate** | Consequence of the outbox design (#2233 hardening) rather than a single cited ruling — buffering was necessary once sends became asynchronous/batched (spark decouples eval from send; legacy doesn't). Shared drift/compliance fields stay byte-identical (§F) — this row is about drop/backpressure behavior, not event content. |
| **Operator symptom** | Three independent, link-state-conditioned gaps (not overload-conditioned): legacy silently loses events with no signal whenever no sink is wired yet, the reconnect gap is open, or a write fails on a transport that's broken but not yet detected as such — regardless of load. Overload itself only matters once a sink IS wired: there, legacy doesn't drop, it stalls its guard worker thread on a blocking send. Spark surfaces its own drop class — capacity-bounded, under sustained overload — as a counted, observable metric instead. Not a regression — an observability improvement — but a real behavioral difference in what "the agent tried to send N events" means, and in what backpressure looks like, on each backend. |
| **Verify at** | `guardian_engine.cpp::emit_guard_event` (sink-not-wired drop, no counter; the blocking `sink(ev)` send when wired); `agent.cpp::emit_guardian_event` (`guardian_sink_stream_` null mid-reconnect drop, no counter, AND its unchecked `->Write(...)` return value for the transport-already-broken case — contrast `send_guardian_outbox_entry`'s checked `Write()` on the same call, a few lines below in the same file; `emit_guardian_event`'s own comment notes it's "Shared by the GuardianEngine drift sink and the (ruleless) DEX signal observer," so this same silent gap also affects DEX crash-recorder observations, not just Guardian compliance/drift events); `guardian_outbox.hpp` `GuardianOutbox` capacity check + `outbox_backpressure_drops()`; `GuardianEngine::outbox_backpressure_drops()` + the `yuzu.guardian_outbox_backpressure_drops` heartbeat tag (#2993, closed). |
| **Epistemic** | verified b16e5836d |

### D10 — Spark reads go through a bounded, bulkheaded I/O admission layer; legacy reads have none

| | |
|---|---|
| **Legacy** | Each guard runs its own read on its own thread, unbounded — no admission control, no per-class concurrency cap, no deadline. A wedged read (a stalled network/FUSE mount, a hung SCM call, a wedged sd-bus broker) blocks that guard's thread indefinitely; there is no shared quota across guards to protect one type from starving another. |
| **Spark** | Every read is dispatched through `GuardianIoExecutor`, a per-type bulkhead with a process-wide ceiling. Default class quotas: File 4, Registry 3, Service 3 (`kMaxProcessIoWorkers = 10`, derived as the exact sum so no class can starve another — a class cap always binds before the process bound can). Each class also carries its own absolute deadline (file-hash ~15s, file-metadata-only/registry/service 5s). A read that can't get an admission slot (`CapacityExhausted`), that's already in flight for the same key (`AlreadyRunning`, single-flighted), or that exceeds its deadline (`Timeout`) degrades to Unknown rather than blocking or hanging — the wedged worker is decoupled (a D-state syscall can't be cancelled or joined), not force-killed, and its liveness feeds the F3 orphan-exit obligation (see E2). **#3816 (exactly-once delivery):** `run()` delivers every result to exactly one of its return value or an optional `on_abandoned(T&&)` callback invoked when the caller already gave up — never both, never neither. `GuardianSparkRuntime`'s arm consumer uses this to disarm a late-succeeding arm instead of leaking the subscription (the state reader's reads need no callback: a late read is pure wasted work, nothing escapes to clean up). |
| **Why deliberate** | R3 (design doc rung-9a decision record): a bulkhead is necessary once reads are dispatched from a shared scheduler across many rules/keys concurrently, which legacy's one-guard-one-thread model never needed. See R3 for the full starvation derivation and the `total_quota{8}`-vs-`sum(10)` history; the shipped design makes cross-class starvation structurally impossible rather than merely less likely. |
| **Operator symptom** | Under read contention (many rules, a slow mechanism, a stalled filesystem) spark can produce `guard.unhealthy` traffic (via the Unknown→health-stream path, D1/D6) that has no legacy analog — a purely spark-introduced fault *source*, not just a different classification of a fault legacy would also have hit. Counted via `GuardianIoExecutor::Counters` (`timed_out`, `rejected_capacity`, `rejected_key`, `launch_failures`, `worker_exceptions`, and `abandoned`/`abandonment_cleanup_failures` since #3816) per class — not yet routed to a heartbeat tag or fleet gauge as of this writing (#3415, OPEN); verify current wiring before relying on fleet-level visibility into this specific fault class. |
| **Verify at** | `guardian_io_executor.hpp` (`GuardianIoExecutor::Config` defaults, `kMaxProcessIoWorkers`, `IoFailure` enum); `guardian_state_reader.hpp` header comment (per-class deadlines, single-flight, decouple-not-cancel contract) confirming production wiring. |
| **Epistemic** | verified b16e5836d |

### D11 — Recovery from Unknown force-emits a compliance event even when the value didn't change

| | |
|---|---|
| **Legacy** | No comparable concept: legacy has no Unknown/health state at all (D1, D6), so there is no "recovery from Unknown" transition to force anything on. A legacy compliance event fires only on a genuine compliant/drifted value transition. |
| **Spark** | `guardian_rule_eval.cpp`'s `pack()` resets `state.emit.last_compliant`/`last_emit`/`suppressed` on every Unknown→Known recovery, with its own header comment stating the intent plainly: "reset the decider's edge/debounce so the verdict is FORCED to emit even if the value equals its pre-error value." `decide_emit()` then runs against that cleared state, so a rule that was compliant, went Unknown (a transient read glitch, D6), and reads compliant again emits a **new** `guard.compliant` census event even though the compliance verdict never actually changed. `guardian_spark_runtime.cpp`'s push site (the sole call site building the outbox batch) confirms this lands on the wire, not just internally: `out.recovered` unconditionally pushes a `health(true)` entry, and — independently — `out.status == EvalStatus::Emit` (which `pack()`'s reset guarantees on recovery) pushes a `compliance` entry in the same batch. Both land atomically; the pinning test `"recovery to a drifted state emits BOTH guard.healthy and the drift verdict"` (`tests/unit/test_guardian_spark_runtime.cpp`) exercises the drifted-recovery case, but the identical mechanism fires on an *unchanged-value* recovery too — a case that test does not name or assert on separately. |
| **Why deliberate** | Not incidental — the design doc's **M2 ("one-legged recovery")** ruling (§"Two decisions settled 2026-07-18") is the reason this is forced, not a bug, and the mapping M2 cites still holds in current code: `guaranteed_state_store.cpp`'s `event_state_from_type` maps `guard.unhealthy`→`errored` but falls through to `nullptr` for `guard.healthy` (no branch matches it), so the server-side `errored` flag clears **only** via a paired *compliance* event — never via the health event alone. If the compliance value happened to be unchanged and `decide_emit` were allowed to debounce-fold it away, the server would see the health-recovery event, still map to `nullptr`, and leave the rule stuck `errored` with no compliance event ever arriving to clear it. Forcing the compliance emit on every recovery — value-changed or not — is the mechanism that keeps that server-side flag from wedging, at the cost of an occasional unchanged-value re-emit. This is genuinely conditional, not universal: the pinning test `"Unknown->Known recovery emits guard.healthy even when the verdict is Silent"` shows that with `emit_compliant_edge=false` (the systemd-parity option, D4), only the health entry fires on recovery — no forced compliance re-emit, because there's no compliant-edge signal to force in the first place. Production always calls with `emit_compliant_edge=true` (D4's sole production `attach_rule` call site), so this row's force-emit behavior is the production case. **This protection is specific to `emit_compliant_edge=true`**: a future caller using `false` would reintroduce exactly the wedge this row exists to prevent, but only for a recovery-to-**unchanged-compliant** transition specifically — `decide_emit`'s Drift branch never consults `emit_compliant_edge` (only its `if (compliant)` branch does), so a recovery-to-**drifted** transition still clears via `drift.detected` (which `event_state_from_type` maps to `"drifted"`) regardless of the flag. |
| **Operator symptom** | An F14 byte-level parity capture across a transient-Unknown-then-recovery episode will show spark emitting a `guard.compliant` event that legacy has no equivalent transition to produce at all (legacy never enters Unknown in the first place) — not just a differing field, a whole extra event on spark's side, on a case that is easy to trigger by design (any D6 transient read glitch) rather than requiring an actual compliance-value change. |
| **Verify at** | `guardian_rule_eval.cpp::pack()` (the recovery reset + its header comment); `guardian_spark_runtime.cpp` outbox-batch push site (`out.recovered` → `health(true)`, `out.status == EvalStatus::Emit` → `compliance`, both unconditional on recovery); `spark-stage2-guardian-consumer-design.md` §"Two decisions settled 2026-07-18" M2; `guaranteed_state_store.cpp`'s `event_state_from_type` (`guard.healthy` falls through to `nullptr`). `tests/unit/test_guardian_spark_runtime.cpp` has four recovery-tagged cases as of this pass — `"a configured capacity below two is floored so a recovery pair can never be lost"`, `"M1 refresh: recovery after a refresh still emits guard.healthy and re-arms the edge (F5 6b)"`, `"Unknown->Known recovery emits guard.healthy even when the verdict is Silent"`, and `"recovery to a drifted state emits BOTH guard.healthy and the drift verdict"` — none set up a stable known-compliant value, drive it through a transient Unknown, and assert on the unchanged-value recovery case this row describes; re-check this list before relying on the absence claim. |
| **Epistemic** | verified b16e5836d |

---

## E. Cadence / resource

### E1 — Spark runs a scheduled convergence sweep across every rule; legacy is mostly notification-driven

| | |
|---|---|
| **Legacy** | No **compliance-detection** polling loop for any of the four guards — File/Registry/Service block on kernel notification primitives with an `INFINITE` healthy-wait. Not purely notification-driven overall, though: degraded-path retries run on a timer regardless (30 s arm-fail/absent retry across the Windows guards and systemd's absent retry), and legacy systemd **already** runs a steady 60 s healthy-reconcile safety poll (`kHealthyReconcileMs`) independent of `prefer_spark` — that cadence exists today and is not a cost the flip introduces; exclude it from any flip-attributed resource delta for Linux Service. |
| **Spark** | `ConvergenceScheduler` runs one thread per type lane plus a priority lane, each on its own cadence with ±20% jitter: service 60 s, registry 60 s, file 600 s, priority (pending-initial backstop) 5 s. A file-lane byte-level token bucket (size+mtime skip before re-hash) is explicitly **deferred to rung 5** — "against rung 4's fake instant reader there is nothing to budget, so wiring them here would be untested theatre." The journal replay path has its own separate, active token bucket (0.1 batch/s, burst 5 — see D2), not to be confused with the deferred file-lane one. |
| **Why deliberate** | Spark's mechanisms don't all carry native change-notification for every read path (e.g. dead-reckoning a file's compliance without a kernel event on every convergence tick); the scheduled sweep is how it converges independent of notification delivery. Ruling: flip-ladder decision D2 (distinct from this doc's own row D2) — token bucket formally deferred to rung 5, confirmed at F11. |
| **Operator symptom** | Periodic reads themselves are a resource delta the flip introduces (CPU/IO wake-ups on 60 s/600 s/5 s cadences per agent, independent of whether anything is actually drifted) — sized against `docs/spark-rebuild-baselines/stage0-resource-baseline.md` as part of F14's evidence, not restated here. For Linux Service specifically, subtract legacy systemd's pre-existing 60 s reconcile cadence from that delta — it's already incurred today, so attributing it to the flip would overstate the new cost. |
| **Verify at** | `guardian_convergence_scheduler.hpp` `Config` (`service_cadence_ms`, `registry_cadence_ms`, `file_cadence_ms`, `priority_poll_ms`, `jitter_pct`); its header comment on the deferred token bucket. |
| **Epistemic** | verified b16e5836d |

### E2 — Shutdown: spark may force a hard, nonzero-code process exit; legacy joins its threads

| | |
|---|---|
| **Legacy** | Each guard thread is stopped and `.join()`-ed cleanly (`guard_file.cpp`, `guard_registry.cpp`, `guard_service.cpp`, `guard_systemd.cpp` all join their worker thread on `stop()`). |
| **Spark** | A detached Guardian I/O worker cannot always be joined within a bounded grace (`kOrphanDrainGrace`, 3 s). When that grace expires, `main.cpp`/`service_win.cpp` call `hard_exit()` (`TerminateProcess` on Windows to avoid the loader lock, `::_exit()` on POSIX for async-signal-safety) with a nonzero code, rather than race normal C++ teardown against a worker that may still be executing library code. |
| **Why deliberate** | F3 (`hard_exit.hpp`): callers must pass a nonzero code specifically so systemd/SCM observe a real failure exit rather than a clean shutdown — an intentional signal to the service supervisor, not a bug being papered over. |
| **Operator symptom** | Under spark, a slow/stuck drain can make agent shutdown/restart look like a **crash** to systemd/SCM (nonzero exit) where the equivalent legacy shutdown would report clean. Cross-platform crash-loop backstop parity (Windows SCM / macOS launchd / Docker restart policy vs Linux's `StartLimitIntervalSec`/`StartLimitBurst`) is tracked separately (#2241, Linux-only today). |
| **Verify at** | `hard_exit.hpp` (`kOrphanDrainGrace`, nonzero-code contract); `main.cpp`'s `on_signal_hard_exit` signal handler and its orphan-worker grace-expiry check in the main shutdown path; `service_win.cpp`'s SCM stop handler; contrast `guard_file.cpp`/`guard_registry.cpp`/`guard_service.cpp`/`guard_systemd.cpp`, each of which `.join()`s its worker thread on `stop()`. |
| **Epistemic** | verified b16e5836d |

---

## F. Expected parity (not deltas — listed so an F14 reviewer doesn't misflag these)

- **Compliance/drift event fields are byte-identical** between legacy and spark via the
  shared `apply_drift_to_event` builder — only `event_id`/`timestamp` differ, by design
  (stamped at enqueue, not at send).
- **`get_status()` is universally fail-closed for both backends** — every rule reports
  `status="errored"`, `guard_healthy=false` regardless of backend or actual per-rule
  state ("under-reporting here is fail-closed; the prior 'armed ⇒ compliant/healthy' was
  the silently-deaf failure class"). There is no `unsupported`/`armed`/`pending` status
  token on REST/MCP yet — `status_for_rule()` exists but is deliberately unwired
  (rung 4).
- **Linux without `YUZU_HAVE_LIBSYSTEMD`:** both backends go dark for Service
  simultaneously — the same build flag gates both `spark_service.cpp` and
  `guard_systemd.cpp`. Not an independent spark-vs-legacy gap.
- **macOS: zero detection under both backends today** — see C2. The flip does not
  create this; it only makes it visible via `unsupported`.
- **Registry hive-root validation** is equally lax on both backends (spark's stricter
  early version was corrected to match legacy's laxity — only `hive` required).

---

## G. #2299 dispositions (journal perf/scale follow-ups)

Issue #2299 tracks five non-blocking follow-ups against the durable lifecycle journal
(§D2). Current dispositions, verified this pass:

| Item | Disposition |
|---|---|
| perf-P-1 (durable metadata cache — O(work) not O(journal size)) | **DONE**, PR #2448: batch-key now embeds `ts_ms`, ~180× cheaper prune / ~15× page / ~11× less peak memory. |
| UP-5 (re-send-all low-water suppression) | **Likely stale**: the sent-label mechanism (§D2) means an ordinary pass no longer re-offers a delivered batch; the residual case (server accepted but never ingested, agent neither reboots nor reconnects) is the deferred server-ack, not a low-water refill. |
| UP-4 (token-bucket tail-latency SLO) | **Open.** At 0.1 batch/s refill, a ~1000-batch backlog's never-sent tail waits on the order of 10⁴ s for first delivery. By-design anti-storm behavior; no SLO has been documented or budgeted. |
| LIKE-escape helper extraction | **Done** — both new #2448 methods route through the existing shared `escape_like_prefix`. |
| `KvStore::clear()` cosmetic migration to `DELETE ... RETURNING` | **Unmigrated**, correctness-neutral (whole op is under `lock_guard`), low priority. Historically tracked under issue #1033 (systemic `sqlite3_changes()`-after-`step()` race, 24 stores) — that issue was itself closed 2026-07-14 in an unverified backlog reset ("not individually verified... if it is still live, please reopen"), so #1033's closed state is not evidence this specific item shipped; it remains a real, minor, open item regardless of that issue's tracker status. |

A sync comment recording this table's dispositions (all five rows, including UP-4, which
#2299's existing 2026-07-24 comment did not cover) has been posted:
[#2299 comment](https://github.com/Tr3kkR/Yuzu/issues/2299#issuecomment-5369485845) — so
the issue's stale checkboxes no longer contradict this doc.

---

## H. Prose that goes stale at the flip (F14's job, recorded here so it isn't lost)

Not deltas — statements in the tree that are true only because `prefer_spark` defaults
`false` today, and become false the moment F14 flips it. F14 owns fixing these; this
doc just makes sure they're findable rather than rediscovered from scratch.

- **`agents/core/src/agent.cpp`, two SparkEngine-instantiation-failure catch blocks**
  (the known-exception and unknown-exception handlers around SparkEngine construction):
  both log `"...legacy IGuard detection is unaffected"`. True today (legacy IS the sole
  enforcing path at `prefer_spark=false`); false post-flip (`guardian_engine.cpp`'s
  `SparkFailed`/`Unwired` guard withdraws legacy entirely once `prefer_spark=true` — see
  A1). There are two further `"Guardian detection path = legacy IGuard (enforcing)"`
  boot-log strings nearby, and they do **not** share this property uniformly — they sit
  in different branches with different post-flip truth values, so F14 must not sweep
  them as one pair: the line inside the `if (cfg_.spark_disable)` branch stays **true**
  post-flip (`--spark-disable` forces `SparkAvailability::SparkDisabled`, which
  `guardian_backend_from_state()` maps to the `legacy` backend regardless of
  `prefer_spark` — see the doc-header note on `--spark-disable`), and only the sibling
  line inside the successful-instantiation OBSERVE-ONLY branch goes stale (it asserts
  legacy is enforcing unconditionally, which stops being true the moment `prefer_spark`
  is honored there instead of ignored).
- **`agents/core/include/yuzu/agent/guardian_engine.hpp`, `GuardianEngine` constructor
  doc comment**: currently reads "...rung 7 ships with every production agent.cpp call
  site passing the literal `false`... rung 12's 'default flip' changes that one
  literal." This is **already inaccurate as written**, independent of the flip: the
  actual production call site (`agent.cpp`) is a 2-argument call that omits
  `prefer_spark` entirely, taking it from the constructor's **default parameter value**
  — there is no literal `false` at the call site to change. F14 (or a sooner drive-by
  fix, since this is stale now, not just stale-at-flip) should correct the comment to
  describe a default-value change, not a call-site literal edit.
- **`docs/user-manual/guaranteed-state.md`'s Events-table definition of `guard.compliant`**
  states "The Linux systemd service guard is still observe-only on the compliant
  edge... does not yet emit `guard.compliant`... until that parity gap closes." True
  today (D4); false post-flip — spark hardcodes `emit_compliant_edge=true` for every
  type including Linux Service, so this parity gap closes at the flip, not later.
- **`docs/user-manual/guaranteed-state.md`'s intro banner** states "A restarted agent
  re-arms enforce guards from its local cache and enforces pre-network (heal-on-restart)."
  True today under legacy; false for any rule spark has taken over post-flip — spark is
  detect-only, unconditionally, until rung 3 (B1), so nothing enforces pre-network (or
  at all) for those rules once the flip lands.
- **This PR's own edit to `.claude/routed-concerns.md`'s Spark row** states "`prefer_spark_`
  defaults `false`... so legacy `IGuard` remains the sole live detection path
  (`reconcile`'s spark branch is unreachable at `prefer_spark_=false`)" and "the
  convergence scheduler + drain worker are constructed but their threads start only under
  `prefer_spark_`." Both clauses are true today and become false at the flip — the row
  that loads governance agents onto Spark-touching changes goes stale in the exact same
  way this doc exists to track, and it's higher-stakes than the items above since
  CLAUDE.md imports this row as standing authority for every `/governance` run.

---

## Related documentation

- [Design v1.1](yuzu-guardian-design-v1.1.md) — authoritative architecture, §24 invariants.
- [Spark Stage 2 design](spark-stage2-guardian-consumer-design.md) — R1–R4 decision
  record, PR ladder; this doc fulfills that design's R2-consequence-2 / rung-10 obligation.
- [ADR-0021](adr/0021-spark-reflex-architecture.md) — incremental per-consumer cutover.
- [guaranteed-state.md](user-manual/guaranteed-state.md) — operator-facing SparkEngine
  section, per-rung posture table, `yuzu.guardian_backend`, reconnect replay traffic.
- [F11 flood measurement run](spark-rebuild-baselines/f11-flood-measurement-run.md) —
  full derivation behind D1's ceiling numbers.
