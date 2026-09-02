# Spark flip gate - `prefer_spark` cutover readiness (ADR-0021 rung 7.7)

This is the canonical, committed record of what gates flipping `prefer_spark` true
(`agents/core/src/agent.cpp:835`). It supersedes #2298 (closed 2026-08-11 with stale
checkboxes, not backfilled) and retires the local-only plan file that stranded these
criteria outside the repo - #3438's exact complaint. Do not maintain a parallel
local plan once this doc exists; update this file instead.

**A structural warning up front, discovered while writing this doc**: #2233 (the
rung-7.7 activation-readiness checklist this document's §2 tracks) was
auto-closed on 2026-09-02 by the repo's `close-linked-issues` workflow because
PR #3821's body said "closes #2233" - but PR #3821 only completed item 3 of the
issue's 10-item checklist. Items 1, 4, 5, 6, 7, 8, 9, 10 were still literally
unchecked `[ ]` in the issue body at time of writing. This is the identical
failure mode #2298 suffered and that this gate doc exists to stop repeating,
now reproduced by automation on its successor issue. §3 below tracks the real
state from the checklist content, not the issue's `CLOSED` state.

**Resolved (Dave, 2026-09-02):** #2233 is replaced, not reopened. Its genuinely
open items are re-filed fresh as **#3847** (items 1/4/6) and **#3848** (item 9)
- every one of §3's 10 rows below carries its actual disposition. #2233 itself
stays closed; recorded on #3438. The underlying automation gap (a checklist
issue auto-closing on a partial-scope PR) is tracked separately as **#3849**.

## 1. Status header

| | |
|---|---|
| Gate state | **OPEN** - 0 of 9 flip-green criteria evidenced |
| Shipped posture today | `prefer_spark=false`: legacy `IGuard` is the sole live *detection/enforcement* path. Spark itself is **not** dormant - `SparkEngine` is constructed and runs observe-only from boot (`agent.cpp:1207/1225-1226`, logging "instantiated OBSERVE-ONLY"), attempting to register all three mechanisms (`:1222-1224`), though registration is platform-gated and silently no-ops off-platform (`spark_mechanism.hpp:25-31`): all three succeed on Windows, only Service succeeds on Linux-with-libsystemd, and none succeed on macOS or Linux without libsystemd. A Guardian consumer (`guardian-spark`) **is** registered with `SparkEngine` at every boot that instantiates it (not under `--spark-disable`, §6, nor after a boot-time construction failure), independent of `prefer_spark_` (`guardian_engine.cpp:1406`) - what's actually absent is any *armed* rule: `reconcile_rule_locked`'s `try_spark = prefer_spark_ && spark_availability_ == Available` gate (`guardian_engine.cpp:1244`) is always false in production, so the registered consumer's handler is never invoked. This is the fact that determines today's blast radius if `prefer_spark_` were ever flipped outside the documented process: the consumer plumbing is already live, so such a flip would take effect immediately with no additional wiring step in the way - not a safety margin. (Three pre-existing code sites - `agent.cpp:1194/1226`, `:3935-3936` - still say "no consumer at rung 1" in comments/log text; that's now stale relative to the corrected claim above, tracked as a separate doc/code drift, not fixed in this PR.) Nothing in this doc describes current production *enforcement* behavior - it is a readiness gate for a future flip (PR-5, not yet written). |
| Evidence commit | _(placeholder - filled by PR-6, the evidence closeout PR)_ |
| Sign-off | _(blank - filled by PR-6 once every §2 criterion is green **AND** every §3 row not at a terminal disposition (RULED closed / DONE with no residual / Moved to P3 / Fixed) is itself resolved or explicitly risk-accepted - §2 alone is not the whole gate. As of this PR that's rows 1/4/6 (#3847), row 7 (#2993), row 9 (#3848), and row 3's #3816 residual - checked here, not folded into a 10th criterion)_ |
| This PR | PR-1 of 7 (+ 1 unscheduled, see below): PR-1 (this doc) → PR-2a (#2233 items 1/4/6 → #3847; item 7 → #2993; + #3831 batch) → PR-2c (fault-injection seams + item-9 TSan rerun, #3848) → [PR-2d, contingency only, if PR-2c's seams demonstrate a real defect - resolves before PR-5, per §5's risk register] → **PR-4 (promtool CH-2/CH-5-PROM) - DONE, merged as #3858, 2026-09-02T13:00:49Z** → [**#3816's design PR, unscheduled** - `GuardianIoExecutor` abandonment-signal API, shared by `GuardianSparkRuntime` + `GuardianStateReader`, no slot assigned; filed 2026-09-01, predating this doc, missing from this doc's first draft and added only after a PR review caught the omission (see §3 row 3); gates PR-5 only, per #3816's own filed text - OR an explicit risk-accept ruling in its place, see §3 row 3] → PR-5 (the flip) → PR-6 (evidence closeout). Sequencing note for §8: PR-4 landed independently of #3816 (neither blocked the other), so Rig A/B provisioning (which follows PR-2a/PR-2c per §8) is not itself delayed by #3816 being unscheduled - only PR-5 is. PR-3 (#2233 item 8) was dropped before this doc was written - item 8 moved to the P3 lane (§3 row 8). PR-2b (item 5) is dropped by this doc (§3 row 5). |
| Re-verified against | `origin/dev @ bd387afec` (2026-09-02); the kickoff plan's citations were pinned to `880900f1e1` - every file:line citation below was re-checked against the newer HEAD, not copied blind. Drift is called out inline where found. |
| Last full re-verification | 2026-09-02, this PR, against `origin/dev @ e333b6cb2` post-rebase (no cited file changed between `bd387afec` and `e333b6cb2` - checked directly). Two later fix rounds (same date) added content re-verified against the same base: #3816 itself (§3 row 3, citing `guardian_spark_runtime.cpp:379-389`, `guardian_io_executor.hpp:376-388`, and `guardian_state_reader.cpp:59-71`), plus independent review nits folded into the same rounds (the "Shipped posture" rewrite citing `agent.cpp:1207/1222-1226`, `guardian_engine.cpp:1244/1406`, `spark_mechanism.hpp:25-31`; the §6 em-dash fix at `agent.cpp:1196`; the §5 "unbounded" addition at `spark_engine.hpp:540-543`). A third round, this PR's own PR-4-merged update, re-based this branch on `origin/dev` post-#3857-merge and re-verified its new citations (`tests/prometheus/yuzu-guardian-journal-extracted.test.yml`'s CH-2a/b/c and CH-5-PROM cases 1-6, `docs/prometheus/yuzu-alerts.yml`'s `TelemetryDark` rule expression) directly against `origin/dev` at that later point, not against `e333b6cb2`. A future reader should treat any citation as unverified past this point until re-run; there is no automated staleness check on this doc. |

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
      rollup happen later in the same file, at `:2124`/`:2296` already cited just above -
      added here for precision.)
- [ ] **4. Gateway path evidence** - spark detection/heartbeat data surviving a gateway-proxied
      agent, not just direct-connect.
- [ ] **5. UAT smoke**: arm on spark → induced drift → dashboard edge; `--spark-disable` rollback
      drill restores legacy enforcement (procedure in §6); journal gauges live; `/status`
      reports real `errored_rules` (this is PR #3175's fix - confirmed shipped, see "#2298
      sub-item confirmation" below).
- [ ] **6. Legacy-vs-spark parity capture**, any diff fully explained by
      `docs/spark-legacy-delta-registry.md`.
- [ ] **7. Resource evidence** vs `docs/spark-rebuild-baselines/`.
- [ ] **8. External gates green**: #2340 CH-2 + CH-5-PROM (promtool) - **done**, PR-4 merged as
      **#3858** (2026-09-02T13:00:49Z), still needs CH-5-UAT (UAT rig, Rig A - §8) before this
      criterion is fully green. CH-11 does **not** gate this criterion (ruled 2026-09-01 - see
      §4).
- [ ] **9. Rung-3-implementation-ready sign-off** + the enforcement-gap budget recorded. Already
      ruled 2026-08-23: the flip's enforcement gap (§3 row 2) is temporary with no fixed
      remediation budget attached - stated here, not re-litigated. (This ruling is recorded
      only in the delivery-plan draft this doc supersedes, not restated in any other committed
      doc - the substance is inlined here rather than cited by a bare decision label, to avoid
      colliding with `docs/spark-legacy-delta-registry.md`'s own differently-scoped decision
      labels of the same shape.)

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
| 3 | Arm/disarm liveness | **DONE for the liveness wedge; two residuals deferred - #3816 needs its own pre-PR-5 gate, #3831 is already covered by PR-2a's scope** | PR #3821, merged 2026-09-02. Routes File/Registry/Service arm/disarm off `registry_mu_` onto `GuardianIoExecutor`; fixes a `policy_generation_` undercount via a new 3-state `ReconcileOutcome`. A scoped Gate-8 re-review on the PR itself found and fixed 2 more guard-arming gaps of the same shape; one more (`arming_rollback`) deliberately deferred as **#3831** (OPEN, confirmed via `gh issue view 3831` - title: "attach_rule's arming_rollback is armed after its own protected mutation"). #3831 slots into PR-2a (§1) - already on the critical path to PR-5 via ordinary sequencing, unlike #3816 below. The ruled fix approach (delivery plan, 2026-09-02) is to promote `arming_rollback` to function scope, the same idiom PR #3821 already used for the other three guards it fixed, mirroring `prior_disarm_rollback`. **A second, distinct residual is #3816** (OPEN - "GuardianIoExecutor has no abandonment-signal API - a late-succeeding arm/read ... can leak a live subscription/handle"; this row narrows that title-level framing - see below): a backend arm that succeeds just after its caller has timed out and abandoned it can leak a live subscription. `attach_rule`'s generation-based self-check (`guardian_spark_runtime.cpp:379-389`) narrows this to a rare scheduling race on the caller's bounded-timeout path, but the code's own comment states plainly "this is NOT airtight." A second, distinct trigger for the same leak was found later (`FortitudeEtc`, #3816 comment, 2026-09-02, during the #3831-batch Gate 8 review): `GuardianIoExecutor::run()`'s post-launch `cv.wait_until` wait (`guardian_io_executor.hpp:376-388`) sits outside `run()`'s own try/catch (which covers only admission/launch, `:294-372`); if that lock construction throws (a rare `std::mutex::lock()` failure, not a timeout - derived SHOULD/MEDIUM, E5 rare/near-E6), the caller-side exception can unwind before the erase that would make `still_wanted` return false, so the same leak can fire without any caller timeout at all. Neither trigger is fixed today. `submit_disarm_off_lock` (the disarm side) and `GuardianStateReader` (state reads) have no equivalent self-check at all - but their late-completion cost is narrower than a leak: a disarm or a state read that lands late simply completes with no caller left to consume it (`GuardianStateReader`'s blocking read helpers return by value with their OS handles - `FdGuard`/`HandleGuard`/`RegKeyGuard`/etc. - scoped as function-locals that close before return, per `guardian_state_reader.cpp:59-71`'s own comment: "the reader opens and closes within one call; nothing escapes") - wasted work, not a leaked handle. This narrows #3816's own title ("arm/read ... can leak a live subscription/handle") to arm-only; the issue's body agrees with this row, only the title is broader. The abandonment-signal API gap is shared by all three call sites; only the arm case actually leaks. Different defect class from #3831 (a mutation-ordering bug in the rollback path) - not subsumed by it or by anything else in this row. **Detection signal: none today** - `GuardianIoExecutor::Stats.counters[..].timed_out` (incremented at `guardian_io_executor.hpp:386`, one line before the discard-comment return at `:387`) and `GuardianSparkRuntime::backend_op_timeouts()` are both read only by unit tests, never wired to a heartbeat tag, log line, or metric; a real occurrence would be invisible fleet-side. #3816's own filed text states it "should gate the `prefer_spark_` flip (F14)", per the governance disposition that raised it (`ent-1`, `governance.d/2233-arm-disarm-liveness-M.4BNt5t.jsonl`); no ruling exists overriding that, so this doc treats it as **gating PR-5 only** (not PR-4, which is independent - see §1). A fully airtight fix needs `GuardianIoExecutor` extended with an abandonment-signal API shared by both `GuardianSparkRuntime` and `GuardianStateReader` - a design change, not a line-count fix, so it does not fit PR-2a's mechanical batch alongside #3831/#3847; no PR slot is assigned yet (§1). PR-5 cannot proceed until #3816 is either fixed or explicitly risk-accepted by a future ruling - it is deliberately NOT added to §5's risk-accept register here, since #3816's own text asks not to "silently ride along unaddressed." **Siblings, not ruled on here**: #2233 item 3's governance run (`governance.d/2233-arm-disarm-liveness-M.4BNt5t.jsonl`) produced seven open follow-up issues in total - #3816 and #3831 (both discussed above) plus five more, all confirmed OPEN: #3810 (backend-op-deadline config override, self-described as "dormant today ... becomes live at the F14 flip" - not a self-declared gate), #3811 (`rollback_spark_wiring_locked()` doesn't wait for `active_backend_op_workers()==0`, shares #3816's orphaned-worker shape, its own text corrects an earlier "fully dormant" assumption since `wire_spark_engine()`'s wiring/rollback path runs at boot lifecycle-only - but does not itself claim to gate the flip), #3812/#3813/#3814 (status-visibility and counter-precision gaps, no gating language found in any of the three). Of the seven, only #3816 self-declares flip-gating; whether any of the other five (#3831 is already covered above, on-track via PR-2a) should is not this row's call - flagged here so the full set is visible rather than #3816 alone. |
| 4 | Stalled sink cannot freeze the runtime | **Open - citations drifted, mechanism partially improved** | The issue cites `guardian_spark_runtime.cpp:441–445` for "`drain()` holds `outbox_mu_` across the injected send callback" - that region no longer contains `drain()` (now at `:1242`, calling `drain_bounded()` at `:1254`). Re-checked the actual current shape: `drain_bounded()` (defined `:1257`) takes `drain_mu_` (`lock_guard`, held for the whole function) and calls `drain_log_unlocked(lifecycle_log_, outbox_mu_, send, ...)` at `:1349`. A comment at `:1134–1135` confirms `outbox_mu_` specifically **is now released across each send** inside `drain_log_unlocked` - that half of the original concern looks fixed. But `drain_mu_` is still held for the entire `drain_bounded()` call, including the nested `send()`. `drain_mu_` has exactly one acquisition site in the file (`:1260`, `drain_bounded()`'s own `lock_guard`) and exactly one production caller chain: `GuardianOutboxDrainWorker::drain_bounded()` (`guardian_outbox_drain_worker.cpp:188-197`), called from the worker's own loop at `:277`. (The sibling method `drain_once()`, `:186`, wraps the unbounded `rt_.drain()` and has zero production callers - test-only, do not read it as a second production path.) So today this does not create cross-caller lock contention the way the issue's original `outbox_mu_` framing implied. What it does mean, unchanged from the issue's actual hazard: the drain worker thread itself is wedged for the duration of a stalled send, with no other path progressing that work until it unwedges - same shape as the original concern, just self-contained within the worker rather than blocking a second lock-holder. The sync gRPC `Write()` that can block is `agent.cpp:3364–3383`'s `send_guardian_outbox_entry()` (`guardian_sink_stream_->Write(resp, ...)`, under `stream_write_mu_`) - the issue's cited `agent.cpp:2576–2585` is stale (that range is now unrelated heartbeat-tag code). Still needs a bounded/nonblocking sink contract + a stall-during-evaluation/withdrawal/shutdown test. Tracked fresh as **#3847** (PR-2a scope). |
| 5 | Firewall both teardown scope guards, make them noncopyable | **DONE - confirmed via commit archaeology; PR-2b is dropped from the delivery plan** | The issue cites two copyable guards with implicitly-noexcept destructors at `guardian_engine.cpp:66–79` / `guardian_spark_runtime.cpp:31–44`. `git show 25f73e231` (2026-07-18, part of **PR #2283**, "Guardian spark PR-1a: send-path + exception-safety + drain hardening, items 1-4", merged 2026-07-18 - a full 6 weeks before #3821) deletes the identical `struct ScopeExit { std::function<void()> fn; bool committed{false}; ~ScopeExit() { if (!committed && fn) fn(); } };` from each of `guardian_engine.cpp` (old hunk `@@ -64,20 +65,11 @@`, struct at old lines ~67-79, matching the issue's `66-79` citation almost exactly) and `guardian_spark_runtime.cpp` (old hunk `@@ -28,21 +29,6 @@`, struct within old lines 28-48, containing the issue's `31-44` citation) - copyable, implicitly-noexcept destructor invoking a throwing `std::function`, the exact shape item 5 describes, at the exact lines item 5 cites. The commit's own body states it explicitly: "B3: the two Guardian ScopeExit guards are replaced by one terminate-safe GuardianRollback (guardian_scope_guard.*): its dtor swallows a cleanup throw (which would std::terminate the agent mid-unwind) and counts it." `GuardianRollback` (`agents/core/src/guardian_scope_guard.hpp`) is noncopyable (copy/assign deleted) and its destructor never propagates (`try { fn(); } catch (...) { count + best-effort log }`) - now used 3× in `guardian_engine.cpp` (lines 242, 623, 1384) and 6× in `guardian_spark_runtime.cpp` (lines 216, 265, 288, 321, 424, 547) - counted by direct `grep -nE '^\s*GuardianRollback [a-z_]+;'`, cross-checked by two independent governance reviewers. Confirmed as part of **PR #2283** (`gh pr view 2283 --json mergeCommit` + `git merge-base --is-ancestor 25f73e231 <that commit>` both check out), merged 2026-07-18 - one day after #2233's creation timestamp (2026-07-17), and a full 6 weeks before #3821. Because the issue's own citations match the pre-fix code exactly, item 5's text was accurate at the time it was written and simply never updated once PR #2283 landed - not a case of speculative or drifted citations. **PR-2b in the delivery plan (item 5, "teardown-path-specific, merges immediately before item 9 runs") had no remaining work and is dropped** - confirmed by the operator 2026-09-02, recorded on #3438; the delivery plan's Lane A now runs PR-1 → PR-2a → PR-2c directly. No successor tracking issue needed. |
| 6 | Hard agent-side file-hash maximum | **Open, confirmed current** | Unclamped `max_bytes` on both spark (`guardian_spark_bridge.hpp:275–289`, drifted slightly from the issue's `:211–225`) and legacy (`guardian_engine.cpp:1036–1043`, drifted from `:622–629`) paths; only a `0` input normalizes to the 64 MiB default (`guardian_rule_eval.hpp:86`, `max_bytes{64ull * 1024 * 1024}`). No server-side clamp found. The issue's own note - a prior review's claimed "512 MiB cap" does not exist anywhere in these files - re-confirmed: `git grep -n "512"` over `guardian_spark_bridge.hpp` / `guardian_engine.cpp` / `guardian_rule_eval.hpp` is empty. (That grep only rules out the literal token `512` - an equivalent cap expressed a different way, e.g. `536870912` or a computed value, would not show up; no such expression was found either on inspection, but the search wasn't exhaustive against every possible spelling.) Treat that prior review's other claims with extra scrutiny. Tracked fresh as **#3847** (PR-2a scope). |
| 7 | Backpressure-drop surfacing (=#2993) | **Open, confirmed current** | The lifecycle-log outbox capacity default is 4096 (`guardian_spark_runtime.hpp:170`, `outbox_capacity{4096}`; issue didn't cite a line). Rejects on full; the drop counter's only consumers are tests (`outbox_backpressure_drops()` per #3005's own follow-up list, which explicitly filed this as #2993). PR-2a. |
| 8 | Multi-rule mixed-capability selection | **Moved to P3 lane** | Ruled 2026-09-02: the issue's own text says "harmless while spark cannot enforce ... must be enforced before spark gains enforcement" - item 2's no-enforcement-at-flip ruling removes the pre-flip premise. Now a P3 (enforce-cutover) prerequisite, not flip-gating. (This is what dropped PR-3, ~2-4 days, off the flip's critical path before this doc was even drafted.) |
| 9 | Focused TSan + shutdown/fault-injection | **Open - citations drifted, scope re-confirmed, not narrowed** | The issue cites a single "instantaneous fake backend" TSan test at `test_guardian_spark_runtime.cpp:598–643`. The file has grown to 3551 lines and that range no longer holds a TSan test. There are now **three** TSan-checkpoint test cases (`grep TEST_CASE.*tsan`): `:1530` ("concurrent attach/detach/evaluate/drain do not race"), `:3061` ("concurrent pagers + a drainer do not race"), `:3293` ("concurrent persist + page + prune + drain do not race, QE-1"). None of the three arms `FakeBackend`'s `hang_next_arm`/`hang_next_disarm` gate (added for item 3's own fix, confirmed present and used at `:1744` onward across 10 distinct deterministic single-scenario `TEST_CASE`s) - so the issue's core finding still holds under the current code: concurrency is proven race-free only against an instantaneous fake, not against a backend that can actually block. This is the literal scope #2224's approval was conditioned on. Tracked fresh as **#3848** (PR-2c scope). PR-2c builds the deterministic per-issue scenario seams first (§5), then this rerun executes against that tree. |
| 10 | Doc drift | **Fixed in this PR** | `docs/spark-stage2-guardian-consumer-design.md` - the issue cited line 500; the actual current line (file has grown) was 949, still reading "observe rung (2) defaults to the spark path", stale against the re-sequenced ladder (this is impl-rung-7 in current terminology). Corrected as part of this PR - see the diff on that file. |

## 4. #2340 scenario contract

Canonical home for this contract as of this PR - a local (uncommitted) delivery-plan draft
(Sol draft + Fable corrections, 2026-08-31/09-01) is now superseded by this section and can be
discarded once this doc lands.

**Veto semantics (ruled 2026-09-01; recorded Dave, 2026-09-02, #2340 comment)**: CH-11 vetoes **alert-enablement only, not the flip**.
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

**CH-2 verdict (Dave, 2026-09-02, #2340 comment): fires-then-resolves.** The issue's literal wording
("assert zero alerts") reads as inverted against the rule's own design intent.
`YuzuGuardianJournalIntegrityGap`'s doc comment states: "No `for:` clause on purpose - the 90s
staleness window means an agent that reports a loss then dies is visible for less than one
`for:` period" - i.e. the rule is deliberately built to **fire** in exactly CH-2's scenario.
The strongest CH-2 test therefore asserts **both**: (a) the rule fires once while the loss
series is present (proving the no-`for:` design works - a future accidental `for:` addition
should turn this red), and (b) it resolves once the reporting agent goes stale, **while the
underlying loss stays unhealed**. That gap - healthy-looking alert state hiding an unhealed
loss - is the actual characterized defect CH-2 exists to demonstrate, not literal "zero
alerts, ever." This unblocked PR-4 (now merged, see §1/§4 below).

**CH-5-PROM vs CH-5-UAT - same scenario ID, two different documents, two different meanings.
Do not conflate them:**
- **CH-5-PROM** (this doc + PR-4): promtool synthetic time-series proving the currently-shipped
  metric-family set is absent for 7 days, and `YuzuGuardianJournalTelemetryDark` fires within 15
  minutes while nothing else does. **DONE - PR-4 merged as #3858** (2026-09-02T13:00:49Z):
  `tests/prometheus/yuzu-guardian-journal-extracted.test.yml` implements 6 CH-5-PROM cases. The
  actual 7-day-metric-family-absent scenario this bullet describes is case 2 ("reporting dark
  sustained for 7 days stays firing" - `_reporting` modeled present-at-zero for 168h alongside a
  healthy fleet, the rest of the metric-family set absent by omission). Cases 1 ("reporting dark with a
  healthy fleet") and 3 ("reporting dark with zero healthy agents stays quiet") are a related but
  distinct property - the exact `_reporting`-exclusion scoping this doc flagged, exercising the
  two halves of the `yuzu_fleet_guardian_journal_reporting == 0 and on()
  yuzu_fleet_agents_healthy > 0` guard directly. Together the three confirm the "metric-family
  set absent" case does not mis-fire on `_reporting`'s own steady-state 0 reading. Per-case
  discrimination (this doc's original PR-4 scoping note: "mutation-red evidence required, not
  whole-suite") was verified manually at authorship time per the test file's own header comment
  (`:45-58`), not automated in CI - a scope decision, not a gap. CH-2 is also DONE in the same
  PR: cases CH-2a/CH-2b implement the ruled fires-then-resolves verdict (§4 above), plus a CH-2c
  refinement (a never-healing loss fires only within its first 15 minutes, found via adversarial
  review) not anticipated when this doc was first written.
- **CH-5-UAT** (design-doc item 7, `docs/guardian-c0-thread-reloc-design.md`): a live UAT-rig
  load/timing gate holding the journal at its hard ceiling (2000 batches / 64 MiB - resolved
  2026-08-18, not reopened here), measuring live-event latency under KV contention, including a
  forced-blocking sanity stage (`headroom_blocked_seconds` has never fired outside unit tests -
  a 0 reading is ambiguous without this stage). **OPEN: no latency pass/fail threshold is defined
  anywhere** - no percentile, sample-size, or platform-matrix target exists in the design doc or
  any other committed source, despite this being "the flip's genuine go/no-go" per that doc's
  own item 7. Tracked as **#3850** (filed while writing this doc); must be resolved before Rig A
  (§8) can produce an objective pass/fail result rather than a subjective call.

Both gate the flip independently; neither substitutes for the other.

**PR sequence for this track** (from the delivery plan): PR-1 (this doc, scenario contract) →
**PR-4 (promtool CH-2 + CH-5-PROM) - DONE, merged as #3858** → the CH-5-UAT driver (Rig A, §8,
still open, blocked on #3850's missing latency threshold) → cutover evidence record (compact
Markdown, hashed/artifact-ID raw data, not raw logs inline).

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
- Compensating control: the standing downgrade of this pair from a hard pre-Stage-2 gate to
  early-post-flip hardening, **with the gap recorded honestly** - the shutdown watchdog
  (#3737) bounds hang-**at-exit** only; it does **not** bound an unbounded stall **during
  normal operation**, which is #2012's actual hazard class (Sol opine, verified - confirmed
  untouched by PR #3821, a different layer: #3821 bounds Guardian's synchronous wait on
  SparkEngine, not the File mechanism's own internal unbounded walk under its own lock).
  **The basis for deferring is NOT "no regression vs. legacy" - direct code comparison shows
  the opposite for the File mechanism.** Legacy's own hang (`guard_file.cpp:96` launches the
  per-rule thread; the unbounded `fs::is_directory` walk itself is at `:288` and `:299`, inside
  that thread, with no shared lock) stalls exactly
  the one affected rule, permanently, but does not block any other rule. Under spark
  (`spark_engine.hpp:536-548`), the identical class of hang holds the File mechanism's
  per-type lock, stalling arm/disarm for **every** File-type rule for the hang's duration -
  and that duration is not meaningfully bounded either: the code's own comment calls it
  "unbounded" (`spark_engine.hpp:540-543`), the same class of hang as legacy's. The real
  difference is blast radius (one rule vs. every File-type rule), not duration - a broader
  blast radius than legacy's single-rule stall, held by a coarser per-type lock rather than
  legacy's per-rule isolation. The real basis for
  deferring is legacy-twin #2189 parity for the Service mechanism specifically (a macOS
  launchd whole-engine `mtx_` seizure, `stop_all_guards_locked`) plus the absence of any
  production fleet today - not a blanket "no regression" claim across all three mechanisms.
  #3840 (filed 2026-09-02, `spark_engine.hpp:536–548`) is the identical "walk-off-`mu_`"
  hazard shape for Registry's `TP_WAIT` / Service's Windows SCM query - folded into this same
  mechanism-hardening package.
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

**Pulled out entirely, not risk-accepted here**: #2797's legacy-branch half (ruled 2026-09-02 to be tracked outside this plan) - a live
defect in currently-shipping legacy `IGuard` code, unrelated to whether the flip happens.
Needs its own fix + timeline, tracked separately. Only #2797's spark-branch half (fixed by PR
#3821) was ever flip-relevant.

## 6. `--spark-disable` rollback drill procedure

`--spark-disable` is the sole rollback lever (a standing ruling, not re-litigated here). It
is **boot-time, restart-required** - accepted with that limitation. **Scope note**: this
procedure is a UAT-drill spec, written against zero production fleet. It is single-agent
(one restart at a time) with no fleet-wide orchestration story - flipping this on N agents
during a real incident is N individual restarts, not covered here. It also has no persistence
mechanism wired into the shipped `yuzu-agent.service` unit today (tracked as #3851). Treat
this as the drill procedure for evidence collection, not yet a production incident runbook.

1. Confirm current state: agent running with `prefer_spark` active, spark armed on at least one
   rule, drift/heartbeat evidence flowing (criterion 5's UAT smoke precondition).
2. Flip the flag: set `--spark-disable` (or the equivalent config/env toggle feeding
   `cfg_.spark_disable`) and restart the agent process. The boot-time branch at
   `agent.cpp:1195–1197` short-circuits `SparkEngine` instantiation entirely when this is set -
   `spark_engine_` stays null, and the boot log records the literal string (note: an em dash,
   not a hyphen, at `agent.cpp:1196` - a plain-hyphen grep will not match it)
   `"SparkEngine: disabled by --spark-disable — not instantiated; Guardian detection path =
   legacy IGuard (enforcing)"`.
3. Confirm legacy enforcement resumed: the same-boot `wire_spark_engine()` call
   (`agent.cpp:1254`) records `SparkAvailability::SparkDisabled`, and the `SparkDisabled` case
   of the backend-derivation log switch (`:1269–1272`) reports `detection backend = legacy`
   regardless of `prefer_spark`'s compiled-in value - SparkDisabled always means legacy,
   unconditionally. Verify via the `yuzu.guardian_backend` heartbeat tag on the next beat.
4. Confirm no spark state leaks: both sub-checks follow directly from step 2's
   `spark_engine_` staying null - with no `SparkEngine` instance, there is nothing to hold an
   armed subscription and nothing to drain an outbox from, by construction, not by a separate
   runtime check. What IS an independent observable: `spark_running`/`spark_disabled` posture
   keys reflect the disabled state fleet-side.
5. Record the drill's timing (boot-to-legacy-enforcing latency) and any anomaly as this
   criterion's evidence (§2 criterion 5). **If legacy enforcement does NOT resume after the
   restart** (step 3's checks fail): this is not currently a documented failure path - escalate
   rather than retry silently, and treat it as a §5 risk-register candidate in its own right.

## 7. Post-flip programme order

**PR-5's own deliverable, before this programme starts**: `docs/user-manual/guaranteed-state.md:352`
already makes an operator-facing promise that spark's default posture is documented "ahead of
that flag flipping so a pilot's network monitoring is not surprised by it later; see Behaviour
changes (upgrading.md) for how you'll be told when that flag actually flips." PR-5 (the flip
itself) must close that loop: update `guaranteed-state.md`'s posture table, add the
`upgrading.md` Behaviour-changes entry, and add a `changelog.d` fragment - none of which are
named anywhere else in this doc's PR sequencing, and the promise is already live in a shipped
doc today, so it cannot be silently missed when PR-5 lands.

1. **P3 - enforce cutover** (now includes #2233 item 8 as a prerequisite, ruled 2026-09-02 per
   §3 row 8). Runs
   immediately after the flip: the enforcement gap was accepted as temporary (§2 criterion 9) on the
   premise it stays temporary, and P11 has no fleet to observe yet.
2. **Hardening package 1** - #2469/#2278/#2279 (drain-death/retry-churn/poison-head), P11's own
   precondition, slots right after P3.
3. **P11 - alert chain** - #2335/#2336/#2337/#2339/#2083/#2389/#2390/#2415/#2416-runbook/#2417/
   #2418/#2338 + the CH-11 campaign + its 500-agent rig. #2336 (per-agent attribution) can start
   in parallel once P3 is staffed.
4. **P4 - health surface** - #3416 first (already has a compensating control, §5).
5. **Docs** (#2991/#3439/#2966/#3852) + test debt (the #3360/#3392/#2570/#2578 rows from §5).
6. **P5 - legacy deletion, LAST** - structural: `--spark-disable` boots legacy, so legacy code
   cannot be deleted before that lever is retired on its own separate timeline. Closes #2189 by
   deletion, not by fix.

Umbrellas #2299 ("PR-Ag lifecycle journal: perf + scale follow-ups"), #2300 ("... resilience +
test-coverage follow-ups"), #2453 ("Guardian journal: deferred findings from the #2299 O(work)
governance run"): several of §5's individually-named issues are plausibly their children, but
the umbrella numbers themselves are not cross-referenced from §5's rows. Close each umbrella as
its own children drain; do not treat §5 as already accounting for them by number.

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

**Contamination risk (not yet mitigated)**: Rig A's 4-7 day measurement window is the flip's
primary latency evidence source (once #3850's threshold is defined), sharing BigColin with the
hands-off homeserver, the existing dev-pair, and ad hoc build/CI-style load from other
sessions on the same box. A noisy neighbor during the measurement window inflates exactly the
metric the gate depends on, and no isolation (cgroup/`nice`) or concurrent-load recording
alongside samples is planned. Record this as a real gap before Rig A runs, not just a rig
capacity concern.

**Setup timing**: this is prep work, not started by this PR - begins once PR-2a/PR-2c are
close to merging (PR-2b is dropped per §3 row 5, confirmed by the operator 2026-09-02), i.e.
when this rig-dependent evidence-collection phase is actually about to begin. The capacity
numbers above are a 2026-09-02 point-in-time reading; re-verify immediately before
provisioning rather than trusting this reading weeks later.

## Also closed out by this PR

### F2 / #2237 verify-only close-out

Checked the journal-authoritative retirement shape - the design ruling that made the lifecycle
journal, not the legacy in-process compliant-edge re-fire, the sole replay authority for outbox
delivery - for full conformance (not assumed from "substantially landed"). (This ruling itself
is recorded only in the delivery-plan draft this doc supersedes, not restated in any other
committed doc; the substance is inlined here rather than cited by a bare decision label.)

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

**Overall: F2/#2237's journal-authoritative sent-label write/skip/live-entry-participation shape is conformant**
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
  signals gap. None of these block #2298's item 5 as scoped, but they are open follow-up debt;
  the §25 vs. SOC2-doc pair is now tracked as **#3852** and listed in the docs lane (§7).

### Item 10's doc-drift fix

Applied - see the accompanying diff to `docs/spark-stage2-guardian-consumer-design.md`. The
paragraph's rung 2/3/5 numbering is left as originally written (it's internally consistent
within that paragraph, and rewriting every occurrence risked introducing a new drift); a
single italic note now precedes it, mapping "rung 2" to impl-rung-7 and "rung 3"/"rung 5" to
P3/P5 in the current ladder, and pointing at this document for the live gate state.
