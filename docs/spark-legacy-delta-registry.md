# Spark / legacy Guardian detection: intentional delta registry

Captured against `origin/dev @ 7b449e589` (2026-08-21). Authority: ADR-0021 Decision 11
amendment ("incremental per-consumer cutover... with the three gates applied per rung");
`docs/spark-stage2-guardian-consumer-design.md` §R2 consequence 2 (origin ruling, quoted
below); `docs/user-manual/guaranteed-state.md` "Per-rung default posture" table.

## Why this doc exists

> "Parity needs an intentional-delta registry. Legacy silently no-ops where spark
> reports `unsupported`. Zero-tolerance parity cannot be literal across that dimension;
> rung 10's gate artifact must carry the documented delta list, or the gate fails
> spuriously and gets quietly weakened until it means nothing."
> — `spark-stage2-guardian-consumer-design.md`, §R2 consequence 2

The `prefer_spark` flip's flip-green criteria require a legacy-vs-spark parity capture
whose diff is "fully explained by [this] delta registry" — i.e. every observed
difference between a legacy-detection run and a spark-detection run must classify as
either a row in this table ("expected, already decided") or a genuine regression
("new, investigate"). This is that table.

**A third bucket exists and must not be silently folded into the first: a row whose
Epistemic status is `open-question`.** Such a row (currently only D3) documents a real,
observed difference that has NOT been ruled deliberate — it is tracked, not dismissed. A
diff line may be classified "expected" against a `verified`/`likely` row; it may **not**
be waved through against an `open-question` row. Treat a diff matching an open row the
same as a genuine regression: it blocks the parity gate until the linked issue resolves
and the row is re-stamped `verified`/`likely`.

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
*difference* is confirmed but its *disposition* isn't ruled — see D3).

Placement: pick the lettered section (A backend selection, B enforcement, C
placement/platform, D event streams, E cadence/resource) whose description above fits;
IDs are sequential within that letter (the next File row after D9 is D10, not D1a or
E-something). Insert the new `### <ID> — ...` block, with its own `---` separator
immediately after it, right after the last existing row in that section and before that
section's closing `---`.

Two permitted variants: a row gating on a still-open flip-ladder decision (e.g. D4) may
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
| **Epistemic** | verified 7b449e589 |

### A2 — Mutual exclusion is per-rule; a spark arm failure never falls through

| | |
|---|---|
| **Legacy** | Arm failure (invalid config, platform mismatch) → warn-logged, rule stays unarmed. No distinct state, no counter. |
| **Spark** | `withdraw_legacy_guard_locked()` runs *before* the arm attempt. On `attach_rule` failure: warn-logged (`"Guardian: spark arm failed for rule '{}': {}"`), rule armed by **neither** backend. |
| **Why deliberate** | Routed-concerns Spark row: "a rule is armed in at most one of legacy `guards_` or `spark_runtime_`, never both; an arm failure is errored, never a silent fallback." |
| **Operator symptom** | A rule that fails to arm under spark reports `errored` via `get_status()` (same fail-closed bucket as everything else — see §F). No per-rule reason surfaced yet (rung 4). |
| **Verify at** | `reconcile_rule_locked`'s `RulePlacement::Arm` branch (`guardian_engine.cpp`). |
| **Epistemic** | verified 7b449e589 |

---

## B. Enforcement

### B1 — Detect-only window: spark never remediates

| | |
|---|---|
| **Legacy** | Enforces on exactly two mechanisms, both Windows-only: **Registry** (`RegSetValueExW`/`RegCreateKeyExW`) and **Windows Service** (`StartServiceW`/`ControlService`). File is detection-only *by design* on every platform. Linux systemd Service is **observe-only in v1** even under `enforcement_mode=enforce` (explicit runtime warn: "enforce-mode not yet supported on Linux"). |
| **Spark** | Detect-only, unconditionally, every mechanism, every platform. `RuleAssertion` carries no enforce/remediation field; `ResilienceConfig`'s remediation mode is read and discarded; `cfg.enforce` is consulted only on legacy branches. |
| **Why deliberate** | Rung-2 posture table (`guaranteed-state.md`): "2 (later): drives detection, observe-only (the default path) ... nothing [enforces] — a deliberate spark detect-only burn-in." Enforcement lands rung 3. |
| **Operator symptom, stated precisely** | The flip's enforcement regression is: **Windows enforce-mode Registry/Service rules become observe-only until rung 3.** Linux and macOS enforcement posture is **unchanged** by the flip — legacy never enforced there either (Linux Service was already observe-only; File/Registry were never supported on Linux or macOS at all — see C2). |
| **Ruling** | **D4 pending** (spark-flip ladder decision: enforcement gap budget / detect-only window length). This row states the mechanism; it does not yet carry a budgeted duration because D4 has not been ruled. Update this row when D4 lands. |
| **Verify at** | `guardian_spark_bridge.hpp` (RuleAssertion has no enforce field; ResilienceConfig discard comment); `guard_registry.cpp`/`guard_service.cpp` `cfg_.enforce` branches; `guard_systemd.cpp`'s Linux enforce-mode warn; `guard_file.cpp`'s "Detection-only: a FileGuard never writes" comment. |
| **Epistemic** | verified 7b449e589 |

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
| **Epistemic** | verified 7b449e589 |

### C2 — Platform coverage matrix

| OS | Spark | Legacy | Delta |
|---|---|---|---|
| Windows | File + Registry + Service (all real mechanisms) | File + Registry + Service (all real guards) | Coverage parity. The delta is enforcement (B1) and event streams (D1/D2), not detection coverage. |
| Linux | Service only, and only when built with `YUZU_HAVE_LIBSYSTEMD` | Service only (systemd, same libsystemd gate — **both paths go dark for Service simultaneously** on a build without it), observe-only even in enforce mode | File/Registry: `unsupported` under spark, silent `return false` stub under legacy — **spark's only change is that an already-absent capability becomes named and counted, not that anything newly fails to detect.** |
| macOS | Zero mechanisms — all three factories return `nullptr` | Zero — all four legacy guards are stubs on macOS (`make_service_guard()` routes to the non-Linux `ServiceGuard` stub) | **Zero-vs-zero today.** The flip does not create macOS zero-detection — macOS already has zero detection under legacy. What the flip changes is **visibility**: a macOS rule goes from silently-unarmed-with-no-signal (legacy) to `unsupported`-with-a-counted-gauge (spark). This corrects a broader D4/flip-ladder framing that stated "flip day makes macOS zero-detection" — the detection state doesn't change, the observability of it does. |
| **Ruling** | **D4 pending** — this row's macOS finding (visibility, not detection, changes) is an input to D4, not yet a ruling. | | |
| **Verify at** | `spark_file.cpp`/`spark_registry.cpp`/`spark_service.cpp` factory `#else` branches; `guard_file.cpp`'s `FileGuard::start()`, `guard_registry.cpp`'s `RegistryGuard::start()`, `guard_service.cpp`'s `ServiceGuard::start()`, and `guard_systemd.cpp`'s non-Linux stub — all `return false` unconditionally; `docs/capability-registries/spark_mechanisms.tsv` (independently agrees). |
| **Epistemic** | verified 7b449e589 |

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
| **Epistemic** | verified 7b449e589 |

### D2 — Lifecycle stream (`guard.armed`/`guard.disarmed`) is spark-only, durable, at-least-once

| | |
|---|---|
| **Legacy** | Emits no lifecycle events. |
| **Spark** | Durable KV-backed journal (`__guardian_journal__` namespace, keys `lc:<ts13>:<nonce>:<seq12>`). Replayed on boot (first pass runs unconditionally), on reconnect (a kick, not a page — sets the drain worker's `force_page_`), and on a headroom-refill re-arm. An ordinary (non-forced) pass **skips** any batch already carrying a durable sent-label — so steady state does not re-offer delivered batches; only a forced pass (boot/reconnect/refill) re-offers them, and the sent-label gates re-paging, never deletion. Bounds: 0.1 batch/s refill, burst 5, ≤128 batches/pass, 7-day / 1000-batch / 32 MiB retention, 30 s page / 120 s prune cadence. `guard.errored` is a declared-but-unproduced lifecycle kind; `unsupported` is **not** a lifecycle kind at all (it's the C1 heartbeat gauge instead). |
| **Why deliberate** | #2297: "honest process-crash-durable, duplicate-tolerant, bounded-retry — not audit-grade at-least-once. Every loss channel is a counted metric, never silent." #2448 (batch-key timestamp) made the maintenance passes O(work) instead of O(journal size). |
| **Operator symptom** | Server absorbs duplicates silently and cheaply: `insert_event_classified` runs the row insert under its own `SAVEPOINT`; on SQLSTATE `23505` it rolls back to the savepoint (un-aborting the whole transaction, a Postgres-specific need) and byte-compares 13 agent-supplied columns. A match → `Redelivered` (debug-logged, no new row, DEX/blast-radius observers deliberately NOT re-fired — a redelivery must not re-trigger them); a mismatch → `Conflict` (warn-logged, dropped). Nothing is returned to the agent either way — the agent never sees a rejection for a legitimate replay. The batch insert path (`insert_events`) is explicitly forbidden for replays — it aborts the whole batch on any collision, unlike the one-at-a-time path. Traffic bounds: `yuzu_fleet_guardian_journal_*` — `_pages` (activity denominator), `_records_paged`, `_evicted_no_send_evidence` (the CC7.3-relevant integrity-gap counter), `_page_stale_seconds_max` (expect ~30 s), `_prune_stale_seconds_max` (expect ~120 s) — all absent while `prefer_spark` is off. |
| **Verify at** | `guardian_lifecycle_journal.hpp` `page_into_window`/`replay_sent`; `guardian_outbox_drain_worker.cpp` `force_page_` triggers; `guaranteed_state_store.cpp` `insert_event_classified` (SAVEPOINT + `23505` + `stored_event_matches`) and `insert_events`' header comment forbidding batch-path replay; `docs/user-manual/guaranteed-state.md` "Reconnect replay traffic". |
| **Epistemic** | verified 7b449e589 |

### D3 — Drift re-emission has no per-sweep debounce guard (open question — not yet ruled)

| | |
|---|---|
| **Legacy** | No sweep to re-emit on: File/Registry/Windows-Service are kernel-notification-driven (`ReadDirectoryChangesW`/`RegNotifyChangeKeyValue`/SCM APC) with an `INFINITE` healthy-wait — no further FS/registry event, no further emission. systemd is D-Bus-signal-driven with a terminal-state dedup (`systemd_decide_emit`: identical terminal state → `NoChange`) — its 60 s "healthy reconcile" safety poll re-emits nothing for an unchanged state. **One asymmetry inside legacy itself:** Windows Service has *no* terminal-state dedup on the drift branch, and its 30 s absent-retry timer re-emits `drift.detected` every ~30 s while the service stays absent — this is a pre-existing legacy behavior, not spark-introduced. |
| **Spark** | `guardian_emit_decider.hpp`'s shared `decide_emit` has **no last-terminal-state dedup** ("unlike systemd_decide_emit... not needed at the consumer" — reasoned from File/Registry's own re-read-on-change + debounce-fold behavior, and Service's one-event-per-edge behavior). Its only suppression is a debounce window (`RuleAssertion::debounce_ms`, default 1000 ms) measured from the last **emit**, not from attach or from a terminal-state hash. Convergence sweeps run every 60 s (service/registry) or 600 s (file) — both vastly exceed the 1000 ms default debounce. **Net: a persistently-drifted rule re-emits `drift.detected` on every convergence sweep of its lane** — roughly 1440/day/rule on the 60 s lanes, ~144/day on the 600 s file lane, absent any author-configured larger `debounce_ms`. |
| **Why deliberate** | **No ruling found.** M1 (the design doc's cutover-blocking finding) scoped its flood analysis and fix explicitly to the **health** (Unknown) stream — its own text never mentions the Known/drift path, and no test in `test_guardian_spark_runtime.cpp` pins repeated-drift-sweep behavior (the "M1 flood guard"/"F11 flood" test cases are all Unknown/demotion cases). The `decide_emit` header comment's stated rationale ("not needed at the consumer... File/Registry re-read on each change... so a plain compliant-bool suffices") describes the *legacy-parity* reasoning for skipping terminal-state dedup, but does not address the convergence-scheduler sweep cadence being the trigger for repeat evaluation in the first place — that trigger doesn't exist for legacy (no sweep) and does for spark. |
| **Operator symptom** | A rule left persistently drifted under spark (e.g. an enforce-mode rule now observe-only per B1, with nobody fixing the underlying drift) generates a steady ~1440/day (60 s lanes) or ~144/day (600 s lane) `drift.detected` stream — smaller than the pre-fix health flood (~17k/day) but structurally the same class of gap M1 was written to close, left open on the sibling stream. |
| **Verify at** | `guardian_emit_decider.hpp::decide_emit` (no `last_compliant`-driven terminal dedup on the Drift branch); `guardian_rule_eval.cpp`'s sole `decide_emit` call site (passes `a.debounce_ms`); `guardian_rule_eval.hpp` (`debounce_ms{1000}` default on `RuleAssertion`); `guard_systemd.cpp` `systemd_decide_emit` (contrast: has terminal-state dedup). |
| **Epistemic** | **open-question, verified 7b449e589** — this row documents a finding from this pass, not a pre-existing ruling. Tracked in **#3388**; update this row once that issue resolves. |

**Possible tension with the parity gate's own zero-tolerance clause (flagged during Gate 3
architect review, not yet resolved):** the design doc states event-stream equivalence
checks use tolerance bands "**only for observe/debounce noise**"; "enforce-class and
dangerous-drift `event_type`s require zero-tolerance exact match — a tolerance band would
let a real enforce divergence pass." D3's per-sweep re-emission is a genuine event-*count*
divergence, not timing noise — and if a rule can be both dangerous-classified and
persistently drifted (nothing in B1/C1 rules that combination out), a scripted parity
capture on such a rule would show exactly the count mismatch that clause exists to catch.
Whether "dangerous-drift" is scoped to cover count/frequency, and if so whether D3 blocks
F14 on those rules specifically, is an open question for #3388 to resolve — not decided
here.

### D4 — Compliant-edge emission is unified across types (a spark-side legacy-parity fix)

| | |
|---|---|
| **Legacy** | File and Windows-Service emitted `guard.compliant` on the edge into compliant; systemd never did (v1 legacy design). |
| **Spark** | `emit_compliant_edge=true` is hardcoded at the sole production `attach_rule` call site — every type gets a compliant edge, including Linux Service. |
| **Why deliberate** | `decide_emit`'s header comment: "unifies the compliant-census signal across platforms: legacy Windows-Service emitted it, legacy systemd did not." A caller may pass `false` to preserve exact legacy-systemd silence (pinned in parity tests), but production doesn't. |
| **Operator symptom** | A Linux Service rule under spark reports one `guard.compliant` census event on arm/recovery that the equivalent legacy systemd guard never sent. |
| **Verify at** | `guardian_emit_decider.hpp` (`emit_compliant_edge` doc comment); `guardian_engine.cpp`'s `attach_rule` call (`/*emit_compliant_edge=*/true`). |
| **Epistemic** | verified 7b449e589 |

### D5 — Restart re-emits the initial compliant edge, as a genuinely new server row

| | |
|---|---|
| **Legacy** | No comparable concept — legacy guards don't carry a cross-restart identity token in their events. |
| **Spark** | Every restart mints a fresh random `boot_nonce_`, folded into `make_event_id` (`agent_id-boot_nonce-rule_id-wall_ms-seq`). A fresh `RuleGeneration` is built on every attach (identical re-push included — "there is no diff-skip that preserves it"), and the boot re-arm loop (`start_local`) calls `attach_rule` with `emit_compliant_edge=true` for every cached enabled rule. Because the nonce changed, the resulting compliant-edge event has a genuinely new `event_id` and is **not** absorbed by the server's PK-based redelivery dedup (D2) — it is a real new row. |
| **Why deliberate** | Code comment (consistency-auditor Gate 4 finding): "matches the legacy path's own tear-down-and-rebuild-every-push behavior, so this is not a regression." |
| **Operator symptom** | Every agent restart with N armed spark rules produces N new `guard.compliant` server rows (not deduped, not suppressed) — a restart-storm across a fleet scales as rules × restarting agents. Sizing this is a fair F14 evidence-gathering input (3-OS matrix / resource baseline), not something this doc rules on. |
| **Verify at** | `guardian_spark_runtime.cpp` (`make_boot_nonce`/`boot_nonce_`, `detach_rule_locked` + fresh `RuleGeneration` on attach, `make_event_id`); `guardian_engine.cpp` `start_local()` boot re-arm loop. |
| **Epistemic** | verified 7b449e589 |

### D6 — Transient vs. persistent read failure: legacy conflates, spark splits

| | |
|---|---|
| **Legacy** | One `<unreadable>` token for both a transient read glitch and a persistent drift-causing failure — both land as Known drift. |
| **Spark** | Splits them: a persistent failure is Known drift (goes through D3/D4's normal drift path); a transient failure is Unknown (goes through D1's health stream instead). |
| **Why deliberate** | `guardian_rule_eval.hpp` preamble: legacy conflated the two into one token; spark splits persistent (Known drift) from transient (Unknown) deliberately. |
| **Operator symptom** | A flaky read source produces health-stream traffic under spark where it would have produced drift-stream traffic under legacy — different wire event types for the same underlying condition. |
| **Verify at** | `guardian_rule_eval.hpp`/`guardian_rule_eval.cpp` Unknown-vs-Known-drift classification. |
| **Epistemic** | verified 7b449e589 |

### D7 — File hash-mode `settle_ms` coalescing is not honoured under spark

| | |
|---|---|
| **Legacy** | `guard_file.hpp`'s `settle_ms` (default 750 ms) coalesces a burst of kernel file-change notifications before hashing, since writes aren't atomic — waits out the write before computing a hash, avoiding a torn read. |
| **Spark** | No equivalent field on `RuleAssertion` or `FileSparkParams`. Spark's convergence scheduler instead dead-reckons via a size+mtime skip before re-hash plus a forced periodic re-hash (both **deferred to rung 5** — see E1; at rung 2 there is only the plain convergence sweep, no coalescing and no skip-optimization yet). |
| **Why deliberate** | `guardian_spark_bridge.hpp` header comment states this explicitly: "an ACCEPTED behavioral delta from legacy... flagged here for the rung-9 design-doc rewrite and the rung-10 parity/durability matrix" — i.e. this doc is that flagged destination. |
| **Operator symptom** | A file rule under active mid-write churn may see a spark hash read land mid-write (a torn read) where legacy's coalescing window would have waited it out — until rung 5's size+mtime skip + forced re-hash lands. |
| **Verify at** | `guard_file.hpp` `Config::settle_ms`; `guardian_spark_bridge.hpp` header comment (immediately above `RuleAssertion`/`FileSparkParams`). |
| **Epistemic** | verified 7b449e589 |

### D8 — Deleted-service wire token: legacy `Absent`, spark folds into `Stopped`

| | |
|---|---|
| **Legacy** | Reports a distinct `Absent`/`<unreadable>`-class token for a service that no longer exists on the host. |
| **Spark** | A deleted service folds into `ServiceState::Stopped` at the reader — there is no `Absent` verdict; only the Unknown-vs-Known split of D6 distinguishes "can't tell" from "definitely not running." |
| **Why deliberate** | Code comment (R5, accepted): "a deleted service folds into Stopped at the reader — the compliance VERDICT is identical, only `detected_value` differs from legacy." The enforcement/compliance outcome doesn't change; the wire-visible token does. |
| **Operator symptom** | An F14 event-field parity capture comparing `detected_value` for a deleted-service rule will show `Absent` (legacy) vs `Stopped` (spark) — an expected, ruled diff, not a regression, but it WILL show up in a byte-level field diff even though the compliance verdict matches. |
| **Verify at** | `guardian_rule_eval.cpp`/`guardian_rule_eval.hpp` "R5, accepted" comment on the deleted-service reader mapping into `ServiceState::Stopped`. |
| **Epistemic** | verified 7b449e589 |

### D9 — Send-path drop semantics: legacy silent/unbounded, spark counted/bounded

| | |
|---|---|
| **Legacy** | `emit_guard_event` calls the event sink directly and synchronously from the guard worker thread (a potentially-blocking network send, no buffering). If no sink is wired yet (pre-Register), the event is silently dropped — no counter (comment: "sink not wired yet (pre-network arm) — drop; durable buffering is A3"). No capacity bound; nothing to overflow. |
| **Spark** | Compliance/health entries route through `GuardianOutbox`, a FIFO, per-(domain,rule_id)-coalesced, **capacity-bounded** buffer. A push that would exceed capacity is dropped and **counted** (`backpressure_drops_`), never silent. |
| **Why deliberate** | Consequence of the outbox design (#2233 hardening) rather than a single cited ruling — buffering was necessary once sends became asynchronous/batched (spark decouples eval from send; legacy doesn't). Shared drift/compliance fields stay byte-identical (§F) — this row is about drop/backpressure behavior, not event content. |
| **Operator symptom** | Under sustained overload, legacy silently loses pre-Register events with no signal; spark surfaces the same class of loss as a counted, observable metric. Not a regression — an observability improvement — but a real behavioral difference in what "the agent tried to send N events" means on each backend. |
| **Verify at** | `guardian_engine.cpp::emit_guard_event` (sink-not-wired drop, no counter); `guardian_outbox.hpp` `GuardianOutbox` capacity check + `backpressure_drops_`. |
| **Epistemic** | verified 7b449e589 |

### D10 — Spark reads go through a bounded, bulkheaded I/O admission layer; legacy reads have none

| | |
|---|---|
| **Legacy** | Each guard runs its own read on its own thread, unbounded — no admission control, no per-class concurrency cap, no deadline. A wedged read (a stalled network/FUSE mount, a hung SCM call, a wedged sd-bus broker) blocks that guard's thread indefinitely; there is no shared quota across guards to protect one type from starving another. |
| **Spark** | Every read is dispatched through `GuardianIoExecutor`, a per-type bulkhead with a process-wide ceiling. Default class quotas: File 4, Registry 3, Service 3 (`kMaxProcessIoWorkers = 10`, derived as the exact sum so no class can starve another — a class cap always binds before the process bound can). Each class also carries its own absolute deadline (file-hash ~15s, file-metadata-only/registry/service 5s). A read that can't get an admission slot (`CapacityExhausted`), that's already in flight for the same key (`AlreadyRunning`, single-flighted), or that exceeds its deadline (`Timeout`) degrades to Unknown rather than blocking or hanging — the wedged worker is decoupled (a D-state syscall can't be cancelled or joined), not force-killed, and its liveness feeds the F3 orphan-exit obligation (see E2). |
| **Why deliberate** | R3 (design doc rung-9a decision record): a bulkhead is necessary once reads are dispatched from a shared scheduler across many rules/keys concurrently, which legacy's one-guard-one-thread model never needed. See R3 for the full starvation derivation and the `total_quota{8}`-vs-`sum(10)` history; the shipped design makes cross-class starvation structurally impossible rather than merely less likely. |
| **Operator symptom** | Under read contention (many rules, a slow mechanism, a stalled filesystem) spark can produce `guard.unhealthy` traffic (via the Unknown→health-stream path, D1/D6) that has no legacy analog — a purely spark-introduced fault *source*, not just a different classification of a fault legacy would also have hit. Counted via `GuardianIoExecutor::Counters` (`timed_out`, `rejected_capacity`, `rejected_key`, `launch_failures`, `worker_exceptions`) per class — not yet routed to a heartbeat tag or fleet gauge as of this writing; verify current wiring before relying on fleet-level visibility into this specific fault class. |
| **Verify at** | `guardian_io_executor.hpp` (`GuardianIoExecutor::Config` defaults, `kMaxProcessIoWorkers`, `IoFailure` enum); `guardian_state_reader.hpp` header comment (per-class deadlines, single-flight, decouple-not-cancel contract) confirming production wiring. |
| **Epistemic** | verified 7b449e589 |

---

## E. Cadence / resource

### E1 — Spark runs a scheduled convergence sweep; legacy is purely notification-driven

| | |
|---|---|
| **Legacy** | No polling loop for any of the four guards. File/Registry/Service block on kernel notification primitives with an `INFINITE` healthy-wait; only degraded-path retries run on a timer (30 s arm-fail/absent retry across the Windows guards and systemd's absent retry; systemd additionally has a 60 s healthy-reconcile safety poll). |
| **Spark** | `ConvergenceScheduler` runs one thread per type lane plus a priority lane, each on its own cadence with ±20% jitter: service 60 s, registry 60 s, file 600 s, priority (pending-initial backstop) 5 s. A file-lane byte-level token bucket (size+mtime skip before re-hash) is explicitly **deferred to rung 5** — "against rung 4's fake instant reader there is nothing to budget, so wiring them here would be untested theatre." The journal replay path has its own separate, active token bucket (0.1 batch/s, burst 5 — see D2), not to be confused with the deferred file-lane one. |
| **Why deliberate** | Spark's mechanisms don't all carry native change-notification for every read path (e.g. dead-reckoning a file's compliance without a kernel event on every convergence tick); the scheduled sweep is how it converges independent of notification delivery. Ruling: D2 (spark-flip ladder) — token bucket formally deferred to rung 5, confirmed at F11. |
| **Operator symptom** | Periodic reads themselves are a resource delta the flip introduces (CPU/IO wake-ups on 60 s/600 s/5 s cadences per agent, independent of whether anything is actually drifted) — sized against `docs/spark-rebuild-baselines/stage0-resource-baseline.md` as part of F14's evidence, not restated here. |
| **Verify at** | `guardian_convergence_scheduler.hpp` `Config` (`service_cadence_ms`, `registry_cadence_ms`, `file_cadence_ms`, `priority_poll_ms`, `jitter_pct`); its header comment on the deferred token bucket. |
| **Epistemic** | verified 7b449e589 |

### E2 — Shutdown: spark may force a hard, nonzero-code process exit; legacy joins its threads

| | |
|---|---|
| **Legacy** | Each guard thread is stopped and `.join()`-ed cleanly (`guard_file.cpp`, `guard_registry.cpp`, `guard_service.cpp`, `guard_systemd.cpp` all join their worker thread on `stop()`). |
| **Spark** | A detached Guardian I/O worker cannot always be joined within a bounded grace (`kOrphanDrainGrace`, 3 s). When that grace expires, `main.cpp`/`service_win.cpp` call `hard_exit()` (`TerminateProcess` on Windows to avoid the loader lock, `::_exit()` on POSIX for async-signal-safety) with a nonzero code, rather than race normal C++ teardown against a worker that may still be executing library code. |
| **Why deliberate** | F3 (`hard_exit.hpp`): callers must pass a nonzero code specifically so systemd/SCM observe a real failure exit rather than a clean shutdown — an intentional signal to the service supervisor, not a bug being papered over. |
| **Operator symptom** | Under spark, a slow/stuck drain can make agent shutdown/restart look like a **crash** to systemd/SCM (nonzero exit) where the equivalent legacy shutdown would report clean. Cross-platform crash-loop backstop parity (Windows SCM / macOS launchd / Docker restart policy vs Linux's `StartLimitIntervalSec`/`StartLimitBurst`) is tracked separately (#2241, Linux-only today). |
| **Verify at** | `hard_exit.hpp` (`kOrphanDrainGrace`, nonzero-code contract); `main.cpp`'s `on_signal_hard_exit` signal handler and its orphan-worker grace-expiry check in the main shutdown path; `service_win.cpp`'s SCM stop handler; contrast `guard_file.cpp`/`guard_registry.cpp`/`guard_service.cpp`/`guard_systemd.cpp`, each of which `.join()`s its worker thread on `stop()`. |
| **Epistemic** | verified 7b449e589 |

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
#2299's existing 2026-07-24 comment does not cover) should be posted to #2299 when this
PR merges, so the issue's stale checkboxes stop contradicting this doc.

---

## H. Prose that goes stale at the flip (F14's job, recorded here so it isn't lost)

Not deltas — statements in the tree that are true only because `prefer_spark` defaults
`false` today, and become false the moment F14 flips it. F14 owns fixing these; this
doc just makes sure they're findable rather than rediscovered from scratch.

- **`agents/core/src/agent.cpp`, two SparkEngine-instantiation-failure catch blocks**
  (the known-exception and unknown-exception handlers around SparkEngine construction):
  both log `"...legacy IGuard detection is unaffected"`. True today
  (legacy IS the sole enforcing path at `prefer_spark=false`); false post-flip
  (`guardian_engine.cpp`'s `SparkFailed`/`Unwired` guard withdraws legacy entirely — see
  A1). Two sibling `"Guardian detection path = legacy IGuard (enforcing)"` boot-log
  strings carry the same property.
- **`agents/core/include/yuzu/agent/guardian_engine.hpp`, `GuardianEngine` constructor
  doc comment**: currently reads "...rung 7 ships with every production agent.cpp call
  site passing the literal `false`... rung 12's 'default flip' changes that one
  literal." This is **already inaccurate as written**, independent of the flip: the
  actual production call site (`agent.cpp`) is a 2-argument call that omits
  `prefer_spark` entirely, taking it from the constructor's **default parameter value**
  — there is no literal `false` at the call site to change. F14 (or a sooner drive-by
  fix, since this is stale now, not just stale-at-flip) should correct the comment to
  describe a default-value change, not a call-site literal edit.

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
