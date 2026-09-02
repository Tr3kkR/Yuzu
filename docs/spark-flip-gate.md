# Spark flip gate - `prefer_spark` cutover readiness (ADR-0021 rung 7.7)

This is the canonical, committed record of what gates flipping `prefer_spark` true
(`agents/core/src/agent.cpp:834`). It supersedes #2298 (closed 2026-08-11 with stale
checkboxes, not backfilled) and retires the local-only plan file that stranded these
criteria outside the repo - #3438's exact complaint. Do not maintain a parallel
local plan once this doc exists; update this file instead.

**A structural warning up front, discovered while writing this doc**: #2233 (the
rung-7.7 activation-readiness checklist this document's §2 tracks) was
auto-closed on 2026-09-02 by the repo's `close-linked-issues` workflow because
PR #3821's body said "closes #2233" - but PR #3821 only completed item 3 of the
issue's 10-item checklist. Items 1, 4, 5, 6, 7, 8, 9, 10 are still literally
unchecked `[ ]` in the issue body at time of writing. This is the identical
failure mode #2298 suffered and that this gate doc exists to stop repeating,
now reproduced by automation on its successor issue. §3 below tracks the real
state from the checklist content, not the issue's `CLOSED` state. **Action
needed**: reopen #2233 or replace it with a fresh tracking issue - not this
PR's call to make unilaterally, flagged for the operator.

## 1. Status header

| | |
|---|---|
| Gate state | **OPEN** - 0 of 9 flip-green criteria evidenced |
| Evidence commit | _(placeholder - filled by PR-6, the evidence closeout PR)_ |
| Sign-off | _(blank - filled by PR-6 once every criterion below is green)_ |
| This PR | PR-1 of 7 in the operator's local delivery-plan draft for the spark flip (uncommitted, superseded by this doc going forward; was 8, PR-2b dropped per §3 row 5 - confirmed by the operator 2026-09-02) |
| Re-verified against | `origin/dev @ bd387afec` (2026-09-02); the kickoff plan's citations were pinned to `880900f1e1` - every file:line citation below was re-checked against the newer HEAD, not copied blind. Drift is called out inline where found. |

## 2. Flip-green criteria (1)–(9)

All start unchecked. Each gets its evidence link recorded here by PR-6.

- [ ] **1. Full `/test`, including previous-release upgrade, with `prefer_spark` active post-upgrade.**
- [ ] **2. TSan/ASan clean** - the item-9 focused rerun (§3 row 9) plus PR-2c's per-issue
      fault-injection scenario matrix (§5).
- [ ] **3. 3-OS matrix**, written concretely: per-OS `yuzu.guardian_backend` heartbeat tag +
      `spark_running`/`spark_disabled` posture-key evidence captured, for:
      - Linux - Service mechanism on spark; File/Registry unsupported (left unregistered, per
        `agent.cpp`'s per-mechanism factory pattern).
      - Windows - all three mechanisms armed (File/Registry/Service).
      - macOS - all-unsupported, agent healthy (this is a tested pass state, not a skip).

      Evidence source, re-verified current: the backend-derivation log block is
      `agents/core/src/agent.cpp:1260–1286` (the `switch (avail)` over
      `GuardianEngine::SparkAvailability`, deriving the log line from the same function the
      `yuzu.guardian_backend` heartbeat tag uses - F7's anti-drift fix). `spark_failed_os`
      is computed at `server/core/src/agent_registry.cpp:2124` (incremented) /
      `:2296` (rolled up per-OS); its map is declared at `:1799`. (The kickoff plan cited a
      single line, `:1799` - that's the declaration; the actual per-event increment and
      rollup are at the two lines above it, added here for precision.)
- [ ] **4. Gateway path evidence** - spark detection/heartbeat data surviving a gateway-proxied
      agent, not just direct-connect.
- [ ] **5. UAT smoke**: arm on spark → induced drift → dashboard edge; `--spark-disable` rollback
      drill restores legacy enforcement (procedure in §6); journal gauges live; `/status`
      reports real `errored_rules` (this is PR #3175's fix - confirmed shipped, see "#2298
      sub-item confirmation" below).
- [ ] **6. Legacy-vs-spark parity capture**, any diff fully explained by
      `docs/spark-legacy-delta-registry.md`.
- [ ] **7. Resource evidence** vs `docs/spark-rebuild-baselines/`.
- [ ] **8. External gates green**: #2340 CH-2 + CH-5-PROM (promtool, PR-4) + CH-5-UAT (UAT rig,
      Rig A - §8). CH-11 does **not** gate this criterion (ruled 2026-09-01 - see §4).
- [ ] **9. Rung-3-implementation-ready sign-off** + D4 gap-budget recorded. D4 already ruled
      2026-08-23: the enforcement gap is temporary, no fixed budget - cited here, not
      re-litigated.

## 3. #2233 item table

Re-pulled live (`gh issue view 2233 --json body`) on 2026-09-02, not transcribed blind from
the kickoff plan. The issue is `CLOSED` (auto-closed by PR #3821's "closes #2233", see the
warning at the top of this doc) but its checklist body is the source of truth here, and 8 of
10 items are still unchecked in that body. Every citation below was re-grepped against
`origin/dev @ bd387afec` - several of the issue's own citations have drifted (the file has
grown substantially, largely from PR #3821's rework); drift is called out per row.

| # | Item | State | Evidence (re-verified 2026-09-02) |
|---|---|---|---|
| 1 | Boot ordering | Code fixed, **test still missing** | `guardian_->start_local()` runs at `agent.cpp:1292`, after `wire_spark_engine()` (call at `:1254`) and after `SparkEngine` construction (`:1207`) + `start()` (`:1225`) - ordering confirmed correct. (The issue's checklist body carries no line citations for this item; these are freshly pulled against `origin/dev @ bd387afec`.) The issue's own bar also requires "test a non-empty cached KV policy armed during pre-network startup" - that test doesn't exist yet. Tracked fresh as **#3847** (PR-2a scope). |
| 2 | Enforcement posture | **RULED, closed** | Dave, 2026-08-28 (issue comment): hard flip, no enforcement preservation, no operator warning required, no `spark_enforce_active` signal required. |
| 3 | Arm/disarm liveness | **DONE** | PR #3821, merged 2026-09-02. Routes File/Registry/Service arm/disarm off `registry_mu_` onto `GuardianIoExecutor`; fixes a `policy_generation_` undercount via a new 3-state `ReconcileOutcome`. A scoped Gate-8 re-review on the PR itself found and fixed 2 more guard-arming gaps of the same shape; one more (`arming_rollback`) deliberately deferred as **#3831** (OPEN, confirmed via `gh issue view 3831` - title: "attach_rule's arming_rollback is armed after its own protected mutation"). #3831 slots into PR-2a per ruling 5/9 of the delivery plan (fix approach: promote `arming_rollback` to function scope, same idiom as `prior_disarm_rollback`). |
| 4 | Stalled sink cannot freeze the runtime | **Open - citations drifted, mechanism partially improved** | The issue cites `guardian_spark_runtime.cpp:441–445` for "`drain()` holds `outbox_mu_` across the injected send callback" - that region no longer contains `drain()` (now at `:1242`, calling `drain_bounded()` at `:1257`). Re-checked the actual current shape: `drain_bounded()` takes `drain_mu_` (`lock_guard`, held for the whole function) and calls `drain_log_unlocked(lifecycle_log_, outbox_mu_, send, ...)` at `:1349`. A comment at `:1134–1135` confirms `outbox_mu_` specifically **is now released across each send** inside `drain_log_unlocked` - that half of the original concern looks fixed. But `drain_mu_` is still held for the entire `drain_bounded()` call, including the nested `send()`. `drain_mu_` has exactly one acquisition site in the file (`:1260`, `drain_bounded()`'s own `lock_guard`) and exactly one production caller chain (`GuardianOutboxDrainWorker::drain_once()`/`drain_bounded()` in `guardian_outbox_drain_worker.cpp:186-197`, called from the worker's own loop at `:277`) - so today this does not create cross-caller lock contention the way the issue's original `outbox_mu_` framing implied. What it does mean, unchanged from the issue's actual hazard: the drain worker thread itself is wedged for the duration of a stalled send, with no other path progressing that work until it unwedges - same shape as the original concern, just self-contained within the worker rather than blocking a second lock-holder. The sync gRPC `Write()` that can block is `agent.cpp:3364–3383`'s `send_guardian_outbox_entry()` (`guardian_sink_stream_->Write(resp, ...)`, under `stream_write_mu_`) - the issue's cited `agent.cpp:2576–2585` is stale (that range is now unrelated heartbeat-tag code). Still needs a bounded/nonblocking sink contract + a stall-during-evaluation/withdrawal/shutdown test. Tracked fresh as **#3847** (PR-2a scope). |
| 5 | Firewall both teardown scope guards, make them noncopyable | **DONE - confirmed via commit archaeology, PR-2b can drop from the delivery plan** | The issue cites two copyable guards with implicitly-noexcept destructors at `guardian_engine.cpp:66–79` / `guardian_spark_runtime.cpp:31–44`. `git show 25f73e231` (2026-07-18, part of **PR #2283**, "Guardian spark PR-1a: send-path + exception-safety + drain hardening, items 1-4", merged 2026-07-18 - a full 6 weeks before #3821) deletes the identical `struct ScopeExit { std::function<void()> fn; bool committed{false}; ~ScopeExit() { if (!committed && fn) fn(); } };` from each of `guardian_engine.cpp` (old hunk `@@ -64,20 +65,11 @@`, struct at old lines ~67-79, matching the issue's `66-79` citation almost exactly) and `guardian_spark_runtime.cpp` (old hunk `@@ -28,21 +29,6 @@`, struct within old lines 28-48, containing the issue's `31-44` citation) - copyable, implicitly-noexcept destructor invoking a throwing `std::function`, the exact shape item 5 describes, at the exact lines item 5 cites. The commit's own body states it explicitly: "B3: the two Guardian ScopeExit guards are replaced by one terminate-safe GuardianRollback (guardian_scope_guard.*): its dtor swallows a cleanup throw (which would std::terminate the agent mid-unwind) and counts it." `GuardianRollback` (`agents/core/src/guardian_scope_guard.hpp`) is noncopyable (copy/assign deleted) and its destructor never propagates (`try { fn(); } catch (...) { count + best-effort log }`) - now used 5× in `guardian_engine.cpp` and 9× in `guardian_spark_runtime.cpp`. Confirmed as part of **PR #2283** (`gh pr view 2283 --json mergeCommit` + `git merge-base --is-ancestor 25f73e231 <that commit>` both check out), merged 2026-07-18 - one day after #2233's creation timestamp (2026-07-17), and a full 6 weeks before #3821. Because the issue's own citations match the pre-fix code exactly, item 5's text was accurate at the time it was written and simply never updated once PR #2283 landed - not a case of speculative or drifted citations. **PR-2b in the delivery plan (item 5, "teardown-path-specific, merges immediately before item 9 runs") had no remaining work and is dropped** - confirmed by the operator 2026-09-02; the delivery plan's Lane A now runs PR-1 → PR-2a → PR-2c directly. No successor tracking issue needed. |
| 6 | Hard agent-side file-hash maximum | **Open, confirmed current** | Unclamped `max_bytes` on both spark (`guardian_spark_bridge.hpp:275–289`, drifted slightly from the issue's `:211–225`) and legacy (`guardian_engine.cpp:1036–1043`, drifted from `:622–629`) paths; only a `0` input normalizes to the 64 MiB default (`guardian_rule_eval.hpp:86`, `max_bytes{64ull * 1024 * 1024}`). No server-side clamp found. The issue's own note - a prior review's claimed "512 MiB cap" does not exist anywhere in these files - re-confirmed: `git grep -n "512"` over `guardian_spark_bridge.hpp` / `guardian_engine.cpp` / `guardian_rule_eval.hpp` is empty. Treat that prior review's other claims with extra scrutiny. Tracked fresh as **#3847** (PR-2a scope). |
| 7 | Backpressure-drop surfacing (=#2993) | **Open, confirmed current** | The lifecycle-log outbox capacity default is 4096 (`guardian_spark_runtime.hpp:170`, `outbox_capacity{4096}`; issue didn't cite a line). Rejects on full; the drop counter's only consumers are tests (`outbox_backpressure_drops()` per #3005's own follow-up list, which explicitly filed this as #2993). PR-2a. |
| 8 | Multi-rule mixed-capability selection | **Moved to P3 lane** | Ruled 2026-09-02 (delivery-plan ruling 4): the issue's own text says "harmless while spark cannot enforce ... must be enforced before spark gains enforcement" - item 2's no-enforcement-at-flip ruling removes the pre-flip premise. Now a P3 (enforce-cutover) prerequisite, not flip-gating. |
| 9 | Focused TSan + shutdown/fault-injection | **Open - citations drifted, scope re-confirmed, not narrowed** | The issue cites a single "instantaneous fake backend" TSan test at `test_guardian_spark_runtime.cpp:598–643`. The file has grown to 3551 lines and that range no longer holds a TSan test. There are now **three** TSan-checkpoint test cases (`grep TEST_CASE.*tsan`): `:1530` ("concurrent attach/detach/evaluate/drain do not race"), `:3061` ("concurrent pagers + a drainer do not race"), `:3293` ("concurrent persist + page + prune + drain do not race, QE-1"). None of the three arms `FakeBackend`'s `hang_next_arm`/`hang_next_disarm` gate (added for item 3's own fix, confirmed present and used at `:1744` onward across 10 distinct deterministic single-scenario `TEST_CASE`s) - so the issue's core finding still holds under the current code: concurrency is proven race-free only against an instantaneous fake, not against a backend that can actually block. This is the literal scope #2224's approval was conditioned on. Tracked fresh as **#3848** (PR-2c scope). PR-2c builds the deterministic per-issue scenario seams first (§5), then this rerun executes against that tree. |
| 10 | Doc drift | **Fixed in this PR** | `docs/spark-stage2-guardian-consumer-design.md` - the issue cited line 500; the actual current line (file has grown) was 949, still reading "observe rung (2) defaults to the spark path", stale against the re-sequenced ladder (this is impl-rung-7 in current terminology). Corrected as part of this PR - see the diff on that file. |

## 4. #2340 scenario contract

Canonical home for this contract as of this PR - a local (uncommitted) delivery-plan draft
(Sol draft + Fable corrections, 2026-08-31/09-01) is now superseded by this section and can be
discarded once this doc lands.

**Veto semantics (resolved 2026-09-01)**: CH-11 vetoes **alert-enablement only, not the flip**.
The flip gates on CH-2 + CH-5-PROM + CH-5-UAT only. CH-11, its 500-agent rig requirement, and
#2336 (per-agent attribution axis) move to the post-flip P11 lane (§7). This resolves the
ambiguity the delivery-plan draft flagged: Sol's original reading ("the flip may proceed only
after the veto scenarios pass," all three) would have transitively gated the flip on #2336 -
weeks of prerequisite work. The issue's own veto sentence is alert-scoped ("if any fails, the
alert group stays commented out and the counters stay monitor-only"), the rules file's own
REASON 2 already plans for loss alerts staying disabled post-flip pending #2336, and
`docs/guardian-c0-thread-reloc-design.md` item 7 singles out CH-5-UAT alone as "the flip's
genuine go/no-go." Against: the issue's own title/body do say "cutover gates" (plural,
unscoped) - genuine internal ambiguity in the source issue, not a clean misreading. This
doc's ruling stands regardless.

**CH-2 verdict (resolved 2026-09-02): fires-then-resolves.** The issue's literal wording
("assert zero alerts") reads as inverted against the rule's own design intent.
`YuzuGuardianJournalIntegrityGap`'s doc comment states: "No `for:` clause on purpose - the 90s
staleness window means an agent that reports a loss then dies is visible for less than one
`for:` period" - i.e. the rule is deliberately built to **fire** in exactly CH-2's scenario.
The strongest CH-2 test therefore asserts **both**: (a) the rule fires once while the loss
series is present (proving the no-`for:` design works - a future accidental `for:` addition
should turn this red), and (b) it resolves once the reporting agent goes stale, **while the
underlying loss stays unhealed**. That gap - healthy-looking alert state hiding an unhealed
loss - is the actual characterized defect CH-2 exists to demonstrate, not literal "zero
alerts, ever." This unblocks PR-4.

**CH-5-PROM vs CH-5-UAT - same scenario ID, two different documents, two different meanings.
Do not conflate them:**
- **CH-5-PROM** (this doc + PR-4): promtool synthetic time-series proving the currently-shipped
  metric-family set (needs a fresh code-level count before PR-4 scopes - the #2340 issue's
  claimed "22 metric families" is known-stale, having grown via
  `docs/spark-stage2-guardian-consumer-design.md` items 3/4/5/6/9 landing since; "six batch-unit
  counters" also doesn't obviously map to the current table) is absent for 7 days, and
  `YuzuGuardianJournalTelemetryDark` fires within 15 minutes while nothing else does.
- **CH-5-UAT** (design-doc item 7, `docs/guardian-c0-thread-reloc-design.md`): a live UAT-rig
  load/timing gate holding the journal at its hard ceiling (2000 batches / 64 MiB - resolved
  2026-08-18, not reopened here), measuring live-event latency under KV contention, including a
  forced-blocking sanity stage (`headroom_blocked_seconds` has never fired outside unit tests -
  a 0 reading is ambiguous without this stage).

Both gate the flip independently; neither substitutes for the other.

**PR sequence for this track** (from the delivery plan, unchanged): PR-1 (this doc, scenario
contract) → PR-4 (promtool CH-2 + CH-5-PROM, generalizing `run_promtool_tests.py` to
marker-extract the commented `yuzu-guardian-journal` rule group without enabling the
production group; per-case mutation-red evidence required, not whole-suite) → the CH-5-UAT
driver (Rig A, §8) → cutover evidence record (compact Markdown, hashed/artifact-ID raw data,
not raw logs inline).

## 5. Risk-accept register

Every deferred defect below is recorded with a compensating control AND the fields Sol's
review required - detection signal, operator action, owner, milestone, revisit condition -
so "restart acceptable with no fleet" never stands alone as if it were a control by itself.
Where the source material (issues, the delivery plan) does not specify one of these fields,
that is stated explicitly rather than inferred or invented.

**#2469 + #2278 + #2279** (drain death / retry churn / poison head - one package)
- Detection signal: staleness gauges (already live) going stale/alerting.
- Operator action: not specified in source beyond "restart acceptable with no production
  fleet" - read as "operator restarts the affected agent"; not confirmed as a documented
  runbook step.
- Compensating control: staleness gauges live; restart is acceptable **only** because there is
  no production fleet today. **Explicit: the fix must land before ANY production fleet, not
  deferred indefinitely.**
- Owner: not assigned in source material - needs an owner before hardening package 1 starts.
- Milestone: hardening package 1, immediately post-P3.
- Revisit trigger: before alert-enablement AND before any production fleet.

**#2815 + #2818 + #2833 + #2839** (teardown UAF-class; #2797's legacy half and #2012/#2011
tracked separately below)
- Detection signal: not specified in source for a production occurrence - the compensating
  control here is chiefly *pre-flip verification* (below), not fleet-side detection. A
  production occurrence would most plausibly surface as an unexplained agent crash/restart
  with no dedicated telemetry pointing at these specifically today.
- Operator action: not specified in source.
- Compensating control: item 9's literal TSan rerun **plus** a per-issue deterministic
  fault-injection scenario matrix (PR-2c, real engineering, not "run TSan and see") - parked
  in-flight-teardown entrance for #2815, deterministic shared-key-kill for #2818,
  `bad_alloc`-at-allocation injection for #2839; #2833 needs code inspection first, no repo
  evidence located yet. TSan is secondary for #2818 specifically - that's a logic gap, not
  necessarily a race.
- Owner: not assigned in source material.
- Milestone: PR-2c (pre-flip verification); contingency PR-2d if anything is demonstrated;
  teardown package post-flip if genuinely undemonstrated after the matrix.
- Revisit trigger: any that reproduce/are demonstrated escalate to a contingency PR before
  PR-5.

**#2012 + #2011 + #3840** (+#2014, confirm at execution)
- Detection signal: **none today**, named explicitly in the source ruling - a stuck
  `arm_ancestor` walk (File, #2012) or a stuck `CreateThreadpoolWait`/`RegNotifyChangeKeyValue`
  (Registry) / `OpenSCManagerW`/SCM query (Service, Windows half) has no fleet-visible symptom
  until it starves the owning mechanism type's arm/disarm queue.
- Operator action: none today (no detection signal to act on); would require a restart once
  discovered by other means (e.g. operator-reported unresponsiveness) - not a documented
  runbook step yet.
- Compensating control: ruling 3/7, with the gap recorded honestly - the shutdown watchdog
  (#3737) bounds hang-**at-exit** only; it does **not** bound an unbounded stall **during
  normal operation**, which is #2012's actual hazard class (Sol opine, verified - confirmed
  untouched by PR #3821, a different layer: #3821 bounds Guardian's synchronous wait on
  SparkEngine, not the File mechanism's own internal unbounded walk under its own lock).
  Legacy-twin #2189 parity (no regression vs. what runs today) is the real basis for
  deferring, not the watchdog. #3840 (filed 2026-09-02, `spark_engine.hpp:536–548`) is the
  identical "walk-off-`mu_`" hazard shape for Registry's `TP_WAIT` / Service's Windows SCM
  query - folded into this same mechanism-hardening package.
- Owner: the mechanism-hardening package (File + Registry + Service together, one restructure,
  reviewed once) - no individual named in source.
- Milestone: early post-flip, named package.
- Revisit trigger: **escalate to flip-gating if a production fleet materializes before this
  lands.**

**#2570 + #2578** (macOS spark-test flakes)
- Detection signal: CI red on the macOS leg for these two specific named tests.
- Operator action: not yet defined - building the "explicit rerun rule" the source calls for
  is itself part of the test-debt package's job, not something that exists today.
- Compensating control: narrowly scoped - **not** a blanket "don't chase to green." The design
  doc mandates the full agent suite green on Linux/Windows/macOS as a real cutover path
  (all-unsupported is a tested pass state, §2 criterion 3). Only these two named flakes get
  the (to-be-built) explicit rerun rule + tracking; the mandatory 3-OS-green gate stays in
  force for everything else.
- Owner: test-debt package - no individual named in source.
- Milestone: test-debt package post-flip, for these two specifically.
- Revisit trigger: N/A beyond the milestone above - these do not gate the flip or escalate.

**#3360 + #3392** (test gaps)
- Detection signal: N/A - coverage gaps, not a runtime hazard.
- Operator action: N/A.
- Compensating control: manual UAT rollback drill (§6) provides equivalent flip evidence for
  what automated coverage here would otherwise show.
- Owner / milestone: test-debt package post-flip.
- Revisit trigger: N/A.

**#3416** (+#3415, #3485, #3486)
- Detection signal: already shipped and live - per-OS `yuzu.guardian_backend` heartbeat tag +
  posture keys (`agent_registry.cpp:2124`/`:2296` computes `spark_failed_os`, confirmed in §2
  criterion 3).
- Operator action: N/A - already mitigated by the above.
- Compensating control: the shipped heartbeat/posture-key surface itself.
- Owner / milestone: P4 lane; recheck cost at P4 start.
- Revisit trigger: N/A - not currently expected to need escalation.

**Pulled out entirely, not risk-accepted here**: #2797's legacy-branch half (ruling 6) - a live
defect in currently-shipping legacy `IGuard` code, unrelated to whether the flip happens.
Needs its own fix + timeline, tracked separately. Only #2797's spark-branch half (fixed by PR
#3821) was ever flip-relevant.

## 6. `--spark-disable` rollback drill procedure

`--spark-disable` is the sole rollback lever (D7, standing ruling - not re-litigated here). It
is **boot-time, restart-required** - accepted with that limitation.

1. Confirm current state: agent running with `prefer_spark` active, spark armed on at least one
   rule, drift/heartbeat evidence flowing (criterion 5's UAT smoke precondition).
2. Flip the flag: set `--spark-disable` (or the equivalent config/env toggle feeding
   `cfg_.spark_disable`) and restart the agent process. The boot-time branch at
   `agent.cpp:1195–1197` short-circuits `SparkEngine` instantiation entirely when this is set -
   `spark_engine_` stays null, and the boot log records
   `"SparkEngine: disabled by --spark-disable - not instantiated; Guardian detection path =
   legacy IGuard (enforcing)"`.
3. Confirm legacy enforcement resumed: the same-boot `wire_spark_engine()` call
   (`agent.cpp:1254`) records `SparkAvailability::SparkDisabled`, and the `SparkDisabled` case
   of the backend-derivation log switch (`:1269–1272`) reports `detection backend = legacy
   IGuard` regardless of `prefer_spark`'s compiled-in value - SparkDisabled always means legacy,
   unconditionally. Verify via the `yuzu.guardian_backend` heartbeat tag on the next beat.
4. Confirm no spark state leaks: no armed spark subscriptions, no spark outbox entries draining,
   `spark_running`/`spark_disabled` posture keys reflect the disabled state fleet-side.
5. Record the drill's timing (boot-to-legacy-enforcing latency) and any anomaly as this
   criterion's evidence (§2 criterion 5).

## 7. Post-flip programme order

1. **P3 - enforce cutover** (now includes #2233 item 8 as a prerequisite, ruling 4). Runs
   immediately after the flip: the enforcement gap was accepted as temporary (D4) on the
   premise it stays temporary, and P11 has no fleet to observe yet.
2. **Hardening package 1** - #2469/#2278/#2279 (drain-death/retry-churn/poison-head), P11's own
   precondition, slots right after P3.
3. **P11 - alert chain** - #2335/#2336/#2337/#2339/#2083/#2389/#2390/#2415/#2416-runbook/#2417/
   #2418/#2338 + the CH-11 campaign + its 500-agent rig. #2336 (per-agent attribution) can start
   in parallel once P3 is staffed.
4. **P4 - health surface** - #3416 first (already has a compensating control, §5).
5. **Docs** (#2991/#3439/#2966) + test debt (the #3360/#3392/#2570/#2578 rows from §5).
6. **P5 - legacy deletion, LAST** - structural: `--spark-disable` boots legacy, so legacy code
   cannot be deleted before that lever is retired on its own separate timeline. Closes #2189 by
   deletion, not by fix.

Umbrellas #2299/#2300/#2453: residuals swept into this doc's risk register (§5); close as they
drain.

## 8. Rig-assignment decision

Two dedicated parallel rigs on BigColin, run concurrently rather than serialized - verified
live capacity 2026-09-02: 16 cores, ~37 GB available RAM, 1.1 TB free disk (direct check, not
estimate).

| Rig | Purpose | Ports | Duration |
|---|---|---|---|
| **Rig A** | CH-5-UAT - holds the journal at the hard ceiling (2000 batches / 64 MiB) under KV-contention load | `8110` (HTTP) / `50061` (gRPC) | 4–7 days (long pole) |
| **Rig B** | UAT smoke (§2 criterion 5) + `--spark-disable` rollback drill (§6) | `8120` (HTTP) / `50071` (gRPC) | Shorter-lived |

Same port-pair shape as the existing dev-pair setup (`8090`/`8100`), just two more instances.
Each rig gets its own build dir, own local Postgres DB, own `kv_store.db`/journal path. Both
are well clear of the hands-off homeserver at `100.74.176.116:8080`/`:50051`
(Tailscale-bound - **never touch**; `start-UAT.sh`-style scripts default to those ports and
have killed it before).

**Setup timing**: this is prep work, not started by this PR - begins once PR-2a/PR-2c are
close to merging (PR-2b is dropped per §3 row 5, confirmed by the operator), i.e. when the
rig-dependent evidence collection
(Lane C in the delivery plan)
is actually about to begin.

## Also closed out by this PR

### F2 / #2237 verify-only close-out

Checked the D6 journal-authoritative retirement shape for full conformance (not assumed from
"substantially landed"):

- **Sent-label written only after `Sent` on a batch's last entry** - confirmed at
  `guardian_engine.cpp:1429–1432` (drifted from an earlier `:1408–1414` citation, same content):
  `if (r == SendResult::Sent && e.journal_last_in_batch && !e.journal_batch_key.empty() &&
  journal) journal->mark_batch_sent(e.journal_batch_key);`. **Conformant.**
- **Replay skips only sent-labelled batches** - confirmed at exactly
  `guardian_lifecycle_journal.cpp:1284–1285` (this citation did not drift), with a second,
  identical-shape check at `:1379–1380` for a different candidate set. **Conformant.**
- **Live-entry path (non-batched, no `journal_batch_key`) sent-label participation** - not
  previously checked; verified now. The wrapping comment at `guardian_engine.cpp:1420–1421`
  states explicitly: "Live / compliance / health entries carry no batch key → no-op." Confirmed
  by the guard condition above (`!e.journal_batch_key.empty()`) - a live entry's empty batch key
  means the `mark_batch_sent` branch never fires for it, by construction. This is deliberate, not
  an oversight: live entries were never part of the paged-batch journal in the first place, so
  they have no sent-label bookkeeping to conform to. **Conformant on this specific point.**
  **Stamp semantics themselves (how a live entry's `event_id`/timestamp are constructed vs. a
  replayed batch entry's, and whether the server dedups identically across both paths) were
  *not* examined this pass** - `guardian_spark_runtime.cpp`'s boot-nonce comment (~line 42,
  `make_boot_nonce()`) is the right starting point for that check, still open.

**Overall: F2/#2237's D6 sent-label write/skip/live-entry-participation shape is conformant**
for the three points checked above. Stamp-semantics equivalence is a separate, narrower claim
not yet examined and should not be read as covered by "conformant" here.

### #2298 sub-item confirmation

Checked, not assumed:

- **M1 sub-items 2/3** → **PR #3005** (merged 2026-08-11). Confirmed: implements 6b
  (errored-refresh backstop) and 6c (priority-lane demotion) - the two still-open items from
  #2298's "into-unknown flood" 3-part gate. PR's own text: "Closes #2298 items (a) and (b);
  item (c) (server-side rollup) remains open, tracked in the parent issue." **Confirmed closed.**
- **Sub-item 4 (suppressed rollup + real `/status.errored_rules`)** → **PR #3175** (merged
  2026-08-17). Confirmed: "M1 health-stream fleet gauge rollup; real
  `errored_rules`/`total_rules` on the guaranteed-state status routes (previously
  placeholder/approximate)." This is #2298 item (c), the piece #3005 left open. **Confirmed
  closed** - together, #3005 + #3175 close all of #2298's M1 checklist.
- **Item 5 (loss-table doc)** → **PR #2937** (merged 2026-08-10). Sol flagged this as the least
  self-evident of the three; looked closer. PR commits §25 of
  `docs/yuzu-guardian-design-v1.1.md` (loss-channel guarantee table) and the SOC2 data-inventory
  registration. **Confirmed closed for its stated scope**, but the PR's own body records 5
  items deliberately left open (not missed): two doc-truth disagreements between §25 and
  `docs/enterprise-readiness-soc2-first-customer.md:387`, a sign-off-status-not-in-repo gap, a
  consolidated risk-register residual, and the enterprise-readiness half of a pipeline-health
  signals gap. None of these block #2298's item 5 as scoped, but they are open follow-up debt
  worth a line in the docs/test-debt lane (§7) if not already tracked elsewhere.

### Item 10's doc-drift fix

Applied - see the accompanying diff to `docs/spark-stage2-guardian-consumer-design.md`. The
paragraph's rung 2/3/5 numbering is left as originally written (it's internally consistent
within that paragraph, and rewriting every occurrence risked introducing a new drift); a
single italic note now precedes it, mapping "rung 2" to impl-rung-7 and "rung 3"/"rung 5" to
P3/P5 in the current ladder, and pointing at this document for the live gate state.
