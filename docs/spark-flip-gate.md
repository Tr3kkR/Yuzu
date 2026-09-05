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
open items were re-filed fresh as **#3847** (items 1/4/6 - items 1 and 6 DONE via
#3884, merged 2026-09-03; item 4 DONE via #3961, merged 2026-09-04T15:20:25Z -
**#3847 itself is now CLOSED**, its residuals tracked at #3953/#3966, see §3 row 4)
and **#3848** (item 9) - every one of §3's 10 rows below carries its
actual disposition. #2233 itself stays closed; recorded on #3438. The underlying
automation gap (a checklist issue auto-closing on a partial-scope PR) is tracked
separately as **#3849**.

## 1. Status header

| | |
|---|---|
| Gate state | **OPEN** - 0 of 9 flip-green criteria evidenced |
| Shipped posture today | `prefer_spark=false`: legacy `IGuard` is the sole live *detection/enforcement* path. Spark itself is **not** dormant - `SparkEngine` is constructed and runs observe-only from boot (`agent.cpp:1207/1225-1226`, logging "instantiated OBSERVE-ONLY"), attempting to register all three mechanisms (`:1222-1224`), though registration is platform-gated and silently no-ops off-platform (`spark_mechanism.hpp:25-31`): all three succeed on Windows, only Service succeeds on Linux-with-libsystemd, and none succeed on macOS or Linux without libsystemd. A Guardian consumer (`guardian-spark`) **is** registered with `SparkEngine` at every boot that instantiates it (not under `--spark-disable`, §6, nor after a boot-time construction failure), independent of `prefer_spark_` (`guardian_engine.cpp:1406`) - what's actually absent is any *armed* rule: `reconcile_rule_locked`'s `try_spark = prefer_spark_ && spark_availability_ == Available` gate (`guardian_engine.cpp:1244`) is always false in production, so the registered consumer's handler is never invoked. This is the fact that determines today's blast radius if `prefer_spark_` were ever flipped outside the documented process: the consumer plumbing is already live, so such a flip would take effect immediately with no additional wiring step in the way - not a safety margin. (Three pre-existing code sites - `agent.cpp:1194/1226`, `:3935-3936` - still say "no consumer at rung 1" in comments/log text; that's now stale relative to the corrected claim above, tracked as a separate doc/code drift, not fixed in this PR.) Nothing in this doc describes current production *enforcement* behavior - it is a readiness gate for a future flip (PR-5, not yet written). |
| Evidence commit | _(placeholder - filled by PR-6, the evidence closeout PR)_ |
| Sign-off | _(blank - filled by PR-6 once every §2 criterion is green **AND** every §3 row not at a terminal disposition (RULED closed / DONE with no residual / Moved to P3 / Fixed) is itself resolved or explicitly risk-accepted - §2 alone is not the whole gate. Row 4 (#3847) is now fully DONE (items 1/6 via #3884, item 4 via #3961) - superseded by its own residuals, **#3953** (deferred LOW/INFO findings from #3961's review rounds - see the issue for the current count, not a number restated here; forcing function: `p3-audit-classification-note` in `governance.d/3847-outbox-send-executor.rGvKq2.jsonl` says a related finding re-derives HIGH->CRITICAL once this path goes live) and **#3966** (a post-merge adversarial-review finding, not yet folded into #3953). As of this PR that's #3953, #3966, and row 9 (#3848) - row 3's #3816 residual is now DONE via PR-2e (both #3816 and #3831, row 3's other residual, are fixed) - checked here, not folded into a 10th criterion)_ |
| This PR | PR-1 of 7: PR-1 (this doc) → **PR-2a (#2233 items 1/6/7 → #3847's original 1/6 slice + #2993; + #3831 batch) - DONE, merged as #3884, 2026-09-03** → **#2233 item 4, #3847 narrowed to this alone - DONE, merged as #3961, 2026-09-04T15:20:25Z - fixed the drain worker's stalled-sink hazard: `drain_bounded()`'s injected `send` now runs on a detached `GuardianOutboxSendExecutor` (guardian_outbox_send_executor.hpp) - one single-flight instance per lane (lifecycle, compliance/health) - instead of the worker's own joined thread, so a stalled sink no longer wedges journal maintenance or the next drain tick; covered by the orphan-exit contract (`GuardianEngine::active_io_workers()`), same as the existing state-reader/arm-disarm executors** → **PR-2c (fault-injection seams + item-9 TSan rerun, #3848) - DONE for #2815/#2833/#2839, this branch** → **PR-2d (the #2818 fix) - CONFIRMED-NEEDED, not contingency: PR-2c's matrix demonstrated the defect, so this is now a hard pre-PR-5 prerequisite, not yet started - see §5** → **PR-4 (promtool CH-2/CH-5-PROM) - DONE, merged as #3858, 2026-09-02T13:00:49Z** → **PR-2e (#3816's design PR) - `GuardianIoExecutor` abandonment-signal API, shared by `GuardianSparkRuntime` + `GuardianStateReader` - DONE, this branch** (filed 2026-09-01, predating this doc, missing from this doc's first draft and added only after a PR review caught the omission; see §3 row 3 for the fix itself) → PR-5 (the flip) → PR-6 (evidence closeout). Sequencing note for §8: PR-4 landed independently of #3816 (neither blocked the other), so Rig A/B provisioning (which follows PR-2a/PR-2c per §8) was never delayed by #3816. PR-3 (#2233 item 8) was dropped before this doc was written - item 8 moved to the P3 lane (§3 row 8). PR-2b (item 5) is dropped by this doc (§3 row 5). |
| Re-verified against | `origin/dev @ bd387afec` (2026-09-02); the kickoff plan's citations were pinned to `880900f1e1` - every file:line citation below was re-checked against the newer HEAD, not copied blind. Drift is called out inline where found. |
| Last full re-verification | 2026-09-02, this PR, against `origin/dev @ e333b6cb2` post-rebase (no cited file changed between `bd387afec` and `e333b6cb2` - checked directly). Two later fix rounds (same date) added content re-verified against the same base: #3816 itself (§3 row 3, citing `guardian_spark_runtime.cpp:379-389`, `guardian_io_executor.hpp:376-388`, and `guardian_state_reader.cpp:59-71`), plus independent review nits folded into the same rounds (the "Shipped posture" rewrite citing `agent.cpp:1207/1222-1226`, `guardian_engine.cpp:1244/1406`, `spark_mechanism.hpp:25-31`; the §6 em-dash fix at `agent.cpp:1196`; the §5 "unbounded" addition at `spark_engine.hpp:540-543`). A third round, this PR's own PR-4-merged update, re-based this branch on `origin/dev` post-#3857-merge and re-verified its new citations (`tests/prometheus/yuzu-guardian-journal-extracted.test.yml`'s CH-2a/b/c and CH-5-PROM cases 1-6, `docs/prometheus/yuzu-alerts.yml`'s `TelemetryDark` rule expression) directly against `origin/dev` at that later point, not against `e333b6cb2`. A future reader should treat any citation as unverified past this point until re-run; there is no automated staleness check on this doc. A fourth round, this PR's own item-4 fix, re-based this branch on `origin/dev` post-#3884-merge (`c7febf76a`) and re-verified §3 rows 1/6/7 and row 3's #3831 sub-clause against #3884's actual merged content (`gh pr view 3884`, merge commit `282c3b58a`) rather than the peer-session summary that first reported it - directly, not by re-derivation from the earlier citations above. A fifth round, this PR's own governance fix-up (two BLOCKING concurrency defects found independently by two Gate 2/3 reviewers in the fix's first draft, both fixed; a new direct-coverage test file added), re-based this branch a SECOND time onto `origin/dev` at `e2f745606` (an unrelated ccache/CI PR, #3917, had merged in between) and re-verified every row-4 file:line citation against the post-fix-round tree directly. A sixth round, a fresh doc-only follow-up PR after #3961 merged (`acd83bd48`, 2026-09-04), fixed row 4's stale "awaiting merge" status, its `wrapped_send()` line-number drift (`:389`→`:408`), a self-contradiction where the row still stated a residual count the same PR's own synthesis doc claimed had been dropped, updated the §1 Sign-off row to point at #3953 and #3966 (superseding row 4/#3847 as the gating items, item 4 now DONE), and folded #3966 (a post-merge external adversarial review's admission-race finding, not fixed by anything in this branch) into row 4's own body text as well. This round went through its OWN governance (Gate 2 security-guardian+docs-writer, Gate 4 happy-path+unhappy-path+consistency-auditor, Gate 6 compliance-officer+sre+enterprise-readiness) after an earlier ungoverned push of the same PR was caught and corrected; that review found and fixed three more instances of the identical staleness class in locations the first pass missed - §1's "This PR" ladder row (still framed item 4 as in-flight), a §0 intro-paragraph clause with the same problem, and an overstated "same bounded-by-join reasoning" claim about #3966 relative to the row's other, dormancy-bounded residuals - plus a #3966/#3953 scope-conflation defect the first commit introduced and a markdown bold-span break caught before commit via a bold-marker-count check. Verified directly against `origin/dev @ acd83bd48` - the merge commit itself, not a peer-session summary. **Separately, PR-2e** (a later, distinct PR on branch `fix/3816-guardian-io-executor-abandonment-signal`, built off `origin/dev @ 6d40b3993`) re-verified and fixed row 3's stale `#3816` citations (`guardian_spark_runtime.cpp:379-389` had drifted to `:487-506` pre-fix; row 3's `guardian_io_executor.hpp:376-388`/`:386`/`:387` citations were rewritten to describe the post-fix code, which no longer has that structure) and shipped the fix those citations were tracking - see row 3's own closing paragraph. |

## 2. Flip-green criteria (1)–(9)

All start unchecked. Each gets its evidence link recorded here by PR-6.

- [ ] **1. Full `/test`, including previous-release upgrade, with `prefer_spark` active post-upgrade.**
- [ ] **2. TSan/ASan clean** - the item-9 focused rerun (§3 row 9) plus PR-2c's per-issue
      fault-injection scenario matrix (§5). **Both halves BUILT in PR-2c (#3848)**; the
      checkbox stays open until PR-6 records the run against the flip tree.
      **EVIDENCE SOURCE IS A LOCAL TSan BUILD, and must be stated as such wherever this
      criterion is signed off.** The new checkpoint is tagged `[tsan-heavy]`, which
      `tests/meson.build` filters out whenever `b_sanitize == none` - so it runs on NO PR
      and NO push CI leg - and the nightly TSan job runs against `main`, not `dev`. There
      is therefore no CI artefact for this criterion and there will not be one before the
      flip: whoever signs it off must run
      `meson setup build-linux-tsan -Db_sanitize=thread` themselves and paste the output,
      not link a workflow. The ASan half has the same shape with one extra step - the
      stock `x64-linux` vcpkg tree cannot run ASan at all (abseil poisons unused
      flat_hash_map slots at protobuf static-init time and trips a spurious
      `use-after-poison` before any test runs), so it needs the `x64-linux-asan` triplet
      built first; `triplets/x64-linux-asan.cmake`'s own header documents this.
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
| 1 | Boot ordering | **DONE - both halves of the issue's bar now tested** | `guardian_->start_local()` runs at `agent.cpp:1292`, after `wire_spark_engine()` (call at `:1254`) and after `SparkEngine` construction (`:1207`) + `start()` (`:1225`) - ordering confirmed correct. #3884 (merged 2026-09-03, `282c3b58a`) added two tests in `test_guardian_engine_spark_reconcile.cpp`: `"PRODUCTION boot order: wire_spark_engine before start_local"` (`:1431`) proves the behavioral half - the issue's own bar verbatim, "test a non-empty cached KV policy armed during pre-network startup" - in the real production call order; `"source tripwire: Agent::run() calls guardian start_local() before opening the Subscribe stream (#2233 item 1, the pre-network property)"` (`:1558`) closes the half the behavioral test cannot reach (there is no Agent-level mocked-gRPC test harness): it asserts, by reading `agent.cpp`'s own source text, that `guardian_->start_local()` appears before `stub->Subscribe(&sub_ctx)` - a textual ordering guarantee, not a runtime one, but one that fails loudly if a future edit reorders them. Line numbers verified against THIS PR's own tree (this PR's own edits to the same file - the item-4 death-test rewrite and a comment fix, both in §3 row 4's scope - net to the same line count as #3884's original `282c3b58a`, so the citations happen to match both, but that is this tree's state, not a claim about `282c3b58a` in isolation), not from #3884's own PR description alone. |
| 2 | Enforcement posture | **RULED, closed** | Dave, 2026-08-28 (issue comment): hard flip, no enforcement preservation, no operator warning required, no `spark_enforce_active` signal required. |
| 3 | Arm/disarm liveness | **DONE - the liveness wedge, the #3831 residual, and #3816 are all fixed (#3816 by PR-2e, this branch)** | PR #3821, merged 2026-09-02. Routes File/Registry/Service arm/disarm off `registry_mu_` onto `GuardianIoExecutor`; fixes a `policy_generation_` undercount via a new 3-state `ReconcileOutcome`. A scoped Gate-8 re-review on the PR itself found and fixed 2 more guard-arming gaps of the same shape; one more (`arming_rollback`) deferred as **#3831** (title: "attach_rule's arming_rollback is armed after its own protected mutation"). **Fixed in code by #3884** (merged 2026-09-03, `282c3b58a`): `arming_rollback` is now promoted to function scope (`guardian_spark_runtime.cpp:225`, `.committed = true` at `:503`) - the same idiom PR #3821 already used for the other three guards it fixed, mirroring `prior_disarm_rollback` - relying on C++ stack-unwind ordering as the safety argument. Verified directly against `origin/dev @ 282c3b58a`, not from #3884's own PR description alone. **Tracking gap, not a code gap**: `gh issue view 3831` still reports **OPEN** as of this PR's re-verification - #3884's body lists #3831 among what it addressed but did not use a closing keyword, and nothing has closed it since; a future PR or a manual close should reconcile this, but the fix itself is confirmed shipped. *(Pre-PR-2e history, kept for context only - every claim in this paragraph through "flagged here so the full set is visible rather than #3816 alone" below describes code this branch has since removed; see the "#3816 fixed by PR-2e" paragraph at the end of this cell for the current state.)* A second, distinct residual was #3816 (filed OPEN - "GuardianIoExecutor has no abandonment-signal API - a late-succeeding arm/read ... can leak a live subscription/handle"; this row narrows that title-level framing - see below): a backend arm that succeeds just after its caller has timed out and abandoned it could leak a live subscription. `attach_rule`'s generation-based self-check (formerly `guardian_spark_runtime.cpp:379-389` pre-PR-2e; that self-check no longer exists on this tree, see below) narrowed this to a rare scheduling race on the caller's bounded-timeout path, but the code's own comment stated plainly "this is NOT airtight." A second, distinct trigger for the same leak was found later (`FortitudeEtc`, #3816 comment, 2026-09-02, during the #3831-batch Gate 8 review): `GuardianIoExecutor::run()`'s post-launch `cv.wait_until` wait (`guardian_io_executor.hpp:376-388`) sits outside `run()`'s own try/catch (which covers only admission/launch, `:294-372`); if that lock construction throws (a rare `std::mutex::lock()` failure, not a timeout - derived SHOULD/MEDIUM, E5 rare/near-E6), the caller-side exception can unwind before the erase that would make `still_wanted` return false, so the same leak can fire without any caller timeout at all. Neither trigger is fixed today. `submit_disarm_off_lock` (the disarm side) and `GuardianStateReader` (state reads) have no equivalent self-check at all - but their late-completion cost is narrower than a leak: a disarm or a state read that lands late simply completes with no caller left to consume it (`GuardianStateReader`'s blocking read helpers return by value with their OS handles - `FdGuard`/`HandleGuard`/`RegKeyGuard`/etc. - scoped as function-locals that close before return, per `guardian_state_reader.cpp:59-71`'s own comment: "the reader opens and closes within one call; nothing escapes") - wasted work, not a leaked handle. This narrows #3816's own title ("arm/read ... can leak a live subscription/handle") to arm-only; the issue's body agrees with this row, only the title is broader. The abandonment-signal API gap is shared by all three call sites; only the arm case actually leaks. Different defect class from #3831 (a mutation-ordering bug in the rollback path) - not subsumed by it or by anything else in this row. **Detection signal: none today** - `GuardianIoExecutor::Stats.counters[..].timed_out` (incremented at `guardian_io_executor.hpp:386`, one line before the discard-comment return at `:387`) and `GuardianSparkRuntime::backend_op_timeouts()` are both read only by unit tests, never wired to a heartbeat tag, log line, or metric; a real occurrence would be invisible fleet-side. #3816's own filed text states it "should gate the `prefer_spark_` flip (F14)", per the governance disposition that raised it (`ent-1`, `governance.d/2233-arm-disarm-liveness-M.4BNt5t.jsonl`); no ruling exists overriding that, so this doc treats it as **gating PR-5 only** (not PR-4, which is independent - see §1). A fully airtight fix needs `GuardianIoExecutor` extended with an abandonment-signal API shared by both `GuardianSparkRuntime` and `GuardianStateReader` - a design change, not a line-count fix, so it does not fit PR-2a's mechanical batch alongside #3831/#3847; no PR slot is assigned yet (§1). PR-5 cannot proceed until #3816 is either fixed or explicitly risk-accepted by a future ruling - it is deliberately NOT added to §5's risk-accept register here, since #3816's own text asks not to "silently ride along unaddressed." **Siblings, not ruled on here**: #2233 item 3's governance run (`governance.d/2233-arm-disarm-liveness-M.4BNt5t.jsonl`) produced seven open follow-up issues in total - #3816 and #3831 (both discussed above) plus five more, all confirmed OPEN: #3810 (backend-op-deadline config override, self-described as "dormant today ... becomes live at the F14 flip" - not a self-declared gate), #3811 (`rollback_spark_wiring_locked()` doesn't wait for `active_backend_op_workers()==0`, shares #3816's orphaned-worker shape, its own text corrects an earlier "fully dormant" assumption since `wire_spark_engine()`'s wiring/rollback path runs at boot lifecycle-only - but does not itself claim to gate the flip), #3812/#3813/#3814 (status-visibility and counter-precision gaps, no gating language found in any of the three). Of the seven, only #3816 self-declares flip-gating; whether any of the other five (#3831 is DONE in code, per above) should is not this row's call - flagged here so the full set is visible rather than #3816 alone. **#3816 fixed by PR-2e** (branch `fix/3816-guardian-io-executor-abandonment-signal`, this doc's own tree): `GuardianIoExecutor::run()` now delivers every result `fn()` returns normally exactly once - either to the caller's return value, or (if the caller already decided Timeout/Stopped) to a new `on_abandoned(T&&)` callback (a thrown `fn()`/`WorkerThrew` has no `T` to deliver and correctly reaches neither destination), both decisions serialized on the SAME wait-side lock (constructed once, held across `spawn_detached`, reused for `cv.wait_until` - no lock is ever constructed after launch). `attach_rule`'s old `still_wanted` self-check against `arming_keys_` (the "NOT airtight" mitigation this row previously described) is removed entirely - the executor itself now owns the decision, closing both triggers named above: the caller-timeout race (trigger 1) is closed architecturally by the exactly-once contract, and the wait-path exception (trigger 2, `FortitudeEtc`'s finding) no longer has a catchable post-launch failure to speak of - a `std::mutex::lock()` failure on the wait-side lock now happens strictly pre-launch and folds into the existing `IoFailure::LaunchFailed` (no new enumerator; `set_throw_before_wait_lock_for_test` is the regression seam, closing `#saf3821-5`). `attach_rule`'s `on_abandoned` disarms a late-succeeding arm and counts it separately (`GuardianSparkRuntime::backend_op_late_arms()`, #3813's distinction kept at the source); `submit_disarm_off_lock` and `GuardianStateReader` are unchanged (a late disarm/read still costs nothing to discard, per this row's own earlier analysis). Mutation-verified: the rewritten regression test (`test_guardian_spark_runtime.cpp`, formerly "C1/c1") asserts `FakeBackend`'s exact armed/disarmed id vectors match, not just balanced counts, and goes red when the `on_abandoned` wiring is removed. **Detection signal: still none today** - the new `Counters::abandoned` (executor) and `backend_op_late_arms_` (runtime) counters exist and are test-asserted, but neither is wired to a heartbeat tag; #3415 (OPEN) already owns that egress and should point at these new counters rather than a new issue being filed. Deliberately does not overlap #2818's engine-level "subscription death" gap (a related but separable defect the sibling `#3848` fault-injection work owns) - #3816's fix touches only the executor/runtime abandonment contract, not `SparkEngine`'s whole-key teardown. |
| 4 | Stalled sink cannot freeze the runtime | **DONE - PR #3961, merged 2026-09-04T15:20:25Z (`acd83bd48`); residuals tracked at #3953, #3966** | Confirmed the hazard exactly as the previous re-verification narrowed it: `drain_mu_` (`guardian_spark_runtime.cpp:1353`, `lock_guard` held for the whole `drain_bounded()` call) has one production caller chain, `GuardianOutboxDrainWorker::drain_bounded()`, and the worker thread was wedged for the duration of a stalled `send()` with nothing else progressing until it unwedged. #3847's own acceptance bar is explicit that dropping `drain_mu_` around `send()` is NOT sufficient (a no-op with one production caller - the worker thread is still inside `Write()` either way); it requires "the drain worker's next tick proceeds while a prior send is artificially stalled." Fixed by detaching the call: a new `GuardianOutboxSendExecutor` (`agents/core/src/guardian_outbox_send_executor.hpp`, new file) runs `send` on a single-flight detached worker (mirroring `guardian_io_executor.hpp`'s spawn-per-attempt shape, NOT its `run()` - `run()` discards a late result on timeout, which is correct for an idempotent read and wrong for a send: a discarded `Sent` would drop the entry without ever retrying it). `GuardianOutboxDrainWorker::wrapped_send()` (`guardian_outbox_drain_worker.hpp:408`) bounds the worker's own wait to `kGuardianSendOfferWait` (200ms) and retains the head if the real send hasn't finished by then, letting journal maintenance and the next tick proceed; the send itself keeps running detached until it completes. Single-flight by construction (one gRPC stream write in flight at a time), keyed on `OutboxEntry::event_id` (the existing wire-idempotency key) so a generation-supersede purge mid-send is detected rather than misapplied. Covered by the orphan-exit contract already established for the state-reader and arm/disarm executors: `active_send_workers()` (`guardian_outbox_drain_worker.hpp:380`) sums into `GuardianEngine::active_io_workers()` (`guardian_engine.cpp:1551`), so `send`'s capture of `AgentImpl` state stays safe under `hard_exit.hpp`'s existing grace-then-kill contract exactly as it did before, just via a different mechanism (previously: synchronous join; now: the orphan-exit sum). **Not fixed**: `stream_write_mu_` contention (`agent.cpp`) - a detached send still holds that mutex for the stall's duration, so another sender sharing the same stream (a response, a DEX signal) still blocks on it; this narrows the drain WORKER's own availability, not the shared stream's. The send path remains unreachable in production today (`prefer_spark_` is false at rung 7.7a), so this is pre-flip hardening, not a live-traffic fix. Tests: `test_guardian_outbox_drain_worker.cpp` gained two new cases proving journal maintenance keeps advancing and the send stays single-flight while artificially stalled (CV-gated, not a real network stall), plus a strengthened CH-1 proving `stop()` now decouples from an 800ms send entirely (previously only asserted a bound that happened to be looser than the send). The existing role-marker test and the `test_guardian_engine_spark_reconcile.cpp` mtx_-abort death test both needed updating: `send` no longer runs on the thread `stop()` joins, so `on_guardian_joined_thread()` correctly now reads false inside it - the death test's hostile call was moved to a directly-spawned thread wearing the same marker, since it no longer has a live vehicle through `send`. **Governance found and fixed FOUR BLOCKING concurrency defects across four review rounds before this PR was pushed** - BLOCKING and SHOULD findings are recorded here in full rather than only the final clean state, since that is what a future flip-readiness auditor needs (LOW/INFO residuals are NOT all repeated here - `governance.d/3847-outbox-send-executor.rGvKq2.jsonl` is the complete ledger; its deferred LOW/INFO residuals are consolidated and tracked at #3953, acceptance criteria: each resolved or explicitly risk-accepted before the F14 flip - see #3953 itself for the current count, not a number restated here; a later adversarial-review pass's own findings are in `governance.d/3847-adversarial-review-synthesis.md`): **(1)** `launch()` wrote its bookkeeping (`in_flight`/`done`) AFTER `spawn_detached()` instead of before, so a fast-completing send could have its published `done=true` clobbered back to `false` by the launcher's own write, silently wedging that one entry forever (cpp-expert, empirically reproduced ~1-in-1000 in a standalone harness). **(2)** `offer()`'s mismatch branch (the head changed under a stalled send - an ORDINARY coalesce/withdrawal, not a rare race) never reclaimed the slot once the orphaned worker finished, so `in_flight` stayed permanently true against an `event_id` that could never recur again - wedging the ENTIRE outbox for the life of the process, not just one entry (security-guardian and cpp-safety, independently). **(3)** A single shared `GuardianOutboxSendExecutor` instance served BOTH the lifecycle log and the compliance/health log (`drain_bounded()` calls `drain_log_unlocked` once per log, `guardian_spark_runtime.cpp:1442/1454`) - a merely-slow-but-succeeding lifecycle send made the compliance call hit the SAME executor's mismatch-orphan branch and return Retain WITHOUT the compliance send ever being invoked, silently starving an entire Guardian audit lane for as long as lifecycle stayed busy (unhappy-path finding UP-1; security-guardian separately flagged this as I1 audit-control-failure, not merely I5 availability). Fixed by giving each lane its OWN executor instance (`lifecycle_send_exec_` / `compliance_send_exec_`, `guardian_outbox_drain_worker.hpp:442-443`), routed by `OutboxEntry::domain` (`:409-410`). **(4)** Round (1)'s own fix placed the `in_flight_event_id` string-copy bookkeeping one statement BEFORE the try/catch meant to guard allocation failures, so a `bad_alloc` on that specific copy reopened defect (1)'s wedge class (cpp-safety, re-review). All four fixed and independently re-confirmed by follow-up governance passes; direct regression coverage added in `tests/unit/test_guardian_outbox_send_executor.cpp` (defect 2, mutation-verified RED) and `tests/unit/test_guardian_outbox_drain_worker.cpp`'s `"item 4 regression: a stalled lifecycle send does not starve compliance delivery"` test (defect 3, mutation-verified RED against the pre-fix single-executor code - a first draft of that test used a bounded 400ms stall and passed on BOTH pre- and post-fix code, since a bounded stall only DELAYS compliance rather than skipping it; the test had to stall lifecycle indefinitely to actually discriminate the two designs). **Two SHOULD-level optimizations were built, wired, and deliberately REVERTED**: waking a parked `offer()` call early on `stop()` (would have shaved up to `kGuardianSendOfferWait` off shutdown latency) and a completion-waker firing the drain worker's cadence on every finished send - each broke a different pre-existing, load-bearing timing test in this file (a `stop()`-join durability-ordering test; a refill-rearm-without-external-wake test) when tried; both were reverted rather than redesigning either pre-existing test under this PR's time budget. The second revert leaves a real cadence regression versus pre-fix behavior, not merely a missed optimization (sre finding): pre-fix, a 300ms send blocked the loop inline and the next tick started as soon as it returned; post-fix, a send that runs longer than `kGuardianSendOfferWait` (200ms) but still succeeds hits `offer()`'s Retain path and isn't re-checked until the next enqueue or the periodic backstop (`kDefaultPeriodicBoundMs`, 5s in production) - e.g. a 300ms send waits out roughly 16x its own duration before the next check, up to roughly 25x for a send finishing just past the 200ms threshold, shrinking toward 1x as it approaches the 5s backstop. Both trade-offs are left as documented notes on `GuardianOutboxSendExecutor::offer()`'s `wait_until` call and `stop()`. **Open, deliberately not fixed here** (sre, Gate 6): no heartbeat tag/counter/log exists for "a send has been stalled for N seconds" - a loud pre-fix hang traded for a silent post-fix slow-drain with no operator-visible signal once this ships live; tracked at #3953, recommended before the F14 flip, the same way row 3 tracks #3816's "Detection signal: none today." A TOCTOU fix landed in a later commit on this same branch closed a related admission-race defect inside `GuardianOutboxSendExecutor::launch()` (adversarial-review finding, `governance.d/3847-adversarial-review-synthesis.md`) and found a structurally identical, deeper residual one call frame out in `GuardianOutboxDrainWorker::stop()`'s own non-atomic shutdown sequencing - also tracked at #3953, not fixed in this row. **Post-merge**: an independent `/pr-review` adversarial pass (Kimi K2.7 + Codex, fully dynamic, dedicated 200k/30k-round race harnesses) found a THIRD, related admission-race that all prior review rounds on this row - including the PR's own author-run adversarial pass - missed: `launch()`'s `AliveTicket` (the sole source `active_worker_count()` reports) is armed in a second, independent lock acquisition released and re-acquired after the `stopping`-recheck block the TOCTOU fix added, so `stop()` can return with `stopping=true` already set while `active_worker_count()` still transiently reads 0, even though admission is already committed - deviates from `GuardianIoExecutor`'s own precedent of arming its ticket inside the single admission lock. Non-blocking today because `GuardianOutboxDrainWorker::stop()`'s unconditional `thread_.join()` plus `GuardianEngine`'s shared mutex between `stop()` and `active_io_workers()` means no caller can observe the gap - a DIFFERENT, more durable safety argument than the rest of this row's residuals, most of which are bounded only by `prefer_spark_=false` and stop being safe the moment F14 flips it: this one is a property of the call graph, independent of that flag (sre, Gate 6 re-review). Filed **#3966** with the fix already spelled out (arm the ticket inside the existing lock); tracked as a sibling to #3953, not yet folded into it. |
| 5 | Firewall both teardown scope guards, make them noncopyable | **DONE - confirmed via commit archaeology; PR-2b is dropped from the delivery plan** | The issue cites two copyable guards with implicitly-noexcept destructors at `guardian_engine.cpp:66–79` / `guardian_spark_runtime.cpp:31–44`. `git show 25f73e231` (2026-07-18, part of **PR #2283**, "Guardian spark PR-1a: send-path + exception-safety + drain hardening, items 1-4", merged 2026-07-18 - a full 6 weeks before #3821) deletes the identical `struct ScopeExit { std::function<void()> fn; bool committed{false}; ~ScopeExit() { if (!committed && fn) fn(); } };` from each of `guardian_engine.cpp` (old hunk `@@ -64,20 +65,11 @@`, struct at old lines ~67-79, matching the issue's `66-79` citation almost exactly) and `guardian_spark_runtime.cpp` (old hunk `@@ -28,21 +29,6 @@`, struct within old lines 28-48, containing the issue's `31-44` citation) - copyable, implicitly-noexcept destructor invoking a throwing `std::function`, the exact shape item 5 describes, at the exact lines item 5 cites. The commit's own body states it explicitly: "B3: the two Guardian ScopeExit guards are replaced by one terminate-safe GuardianRollback (guardian_scope_guard.*): its dtor swallows a cleanup throw (which would std::terminate the agent mid-unwind) and counts it." `GuardianRollback` (`agents/core/src/guardian_scope_guard.hpp`) is noncopyable (copy/assign deleted) and its destructor never propagates (`try { fn(); } catch (...) { count + best-effort log }`) - now used 3× in `guardian_engine.cpp` (lines 242, 623, 1384) and 6× in `guardian_spark_runtime.cpp` (lines 216, 265, 288, 321, 424, 547) - counted by direct `grep -nE '^\s*GuardianRollback [a-z_]+;'`, cross-checked by two independent governance reviewers. Confirmed as part of **PR #2283** (`gh pr view 2283 --json mergeCommit` + `git merge-base --is-ancestor 25f73e231 <that commit>` both check out), merged 2026-07-18 - one day after #2233's creation timestamp (2026-07-17), and a full 6 weeks before #3821. Because the issue's own citations match the pre-fix code exactly, item 5's text was accurate at the time it was written and simply never updated once PR #2283 landed - not a case of speculative or drifted citations. **PR-2b in the delivery plan (item 5, "teardown-path-specific, merges immediately before item 9 runs") had no remaining work and is dropped** - confirmed by the operator 2026-09-02, recorded on #3438; the delivery plan's Lane A now runs PR-1 → PR-2a → PR-2c directly. No successor tracking issue needed. |
| 6 | Hard agent-side file-hash maximum | **DONE - scope grew to a server-side reject, single-sourced** | #3884 (merged 2026-09-03, `282c3b58a`) landed a new shared header, `common/include/yuzu/guardian_file_hash_limits.hpp` (`kMaxFileHashBytes = 1073741824` / 1 GiB), consumed on BOTH sides: the agent clamps at `guardian_engine.cpp:1057` and `guardian_spark_bridge.hpp:295` (the legacy/spark paths this row originally flagged as unclamped), and the server now REJECTS an over-ceiling authored value at authoring time in `guardian_rule_spec.cpp:152/161`, with the ceiling also published into the JSON schema (`guardian_schema_registry.cpp:177`) - a `static_assert` at `guardian_rule_spec.cpp:25` pins a human-readable error string to the same constant so the two cannot drift textually either. One accepted residual, ruled by Dave 2026-09-02 (ledger commit `5ae6e05db`): a `file-hash-equals` rule authored ABOVE 1 GiB *before* this PR shows a false `<oversize>` drift on upgrade, since the new server-side reject cannot retroactively catch an already-stored rule - mitigated via `docs/user-manual/upgrading.md`'s Version Compatibility table (pointing at `GET /api/v1/guaranteed-state/rules` to find affected rows), not a startup-time enumeration. Verified directly against `origin/dev @ 282c3b58a`, not from #3884's own PR description alone. |
| 7 | Backpressure-drop surfacing (=#2993) | **DONE** | The lifecycle-log outbox capacity default is 4096 (`guardian_spark_runtime.hpp:170`, `outbox_capacity{4096}`; issue didn't cite a line). #3884 (merged 2026-09-03, `282c3b58a`) wired `outbox_backpressure_drops()` into fleet visibility: a new `uint64_t` counter field + accessor, no longer test-only-consumed. (Same PR also closed #2233 item 7, the sibling lifecycle-audit-log backpressure counter, `lifecycle_backpressure_log_fires_` - a separate counter for a separate log, not this row's own #2993 scope, but landed alongside it in the same batch.) Verified directly against `origin/dev @ 282c3b58a`, not from #3884's own PR description alone. |
| 8 | Multi-rule mixed-capability selection | **Moved to P3 lane** | Ruled 2026-09-02: the issue's own text says "harmless while spark cannot enforce ... must be enforced before spark gains enforcement" - item 2's no-enforcement-at-flip ruling removes the pre-flip premise. Now a P3 (enforce-cutover) prerequisite, not flip-gating. (This is what dropped PR-3, ~2-4 days, off the flip's critical path before this doc was even drafted.) |
| 9 | Focused TSan + shutdown/fault-injection | **Test BUILT in PR-2c (#3848); rerun still owed by PR-6** | The issue cites a single "instantaneous fake backend" TSan test at `test_guardian_spark_runtime.cpp:598–643`. The file has grown to 3551 lines and that range no longer holds a TSan test. There are now **three** TSan-checkpoint test cases (`grep TEST_CASE.*tsan`): `:1530` ("concurrent attach/detach/evaluate/drain do not race"), `:3061` ("concurrent pagers + a drainer do not race"), `:3293` ("concurrent persist + page + prune + drain do not race, QE-1"). None of the three arms `FakeBackend`'s `hang_next_arm`/`hang_next_disarm` gate (added for item 3's own fix, confirmed present and used at `:1744` onward across 10 distinct deterministic single-scenario `TEST_CASE`s) - so the issue's core finding still holds under the current code: concurrency is proven race-free only against an instantaneous fake, not against a backend that can actually block. This is the literal scope #2224's approval was conditioned on. Tracked fresh as **#3848** (PR-2c scope). PR-2c builds the deterministic per-issue scenario seams first (§5), then this rerun executes against that tree. **PR-2c status:** the missing test now exists - `"concurrent attach/detach/evaluate/drain do not race when the backend and the send callback BLOCK (TSan checkpoint, #3848)"`, tagged `[spark][runtime][liveness][tsan][tsan-heavy]`, which parks `FakeBackend`'s arm, its disarm AND the drain send callback via a `BlockingGate` built as an epoch/pulse extension of the very `hang_next_arm`/`hang_next_disarm` idiom this row names as unused by the other three. It reconciles every subscription id handed out against every id released, and requires the executor's `rejected_key`/`rejected_capacity` to be zero (via a new `GuardianSparkRuntime::io_executor_stats_for_test()`) so that reconciliation is a proof rather than a likelihood. **What it can and cannot show, stated because the framing changed under review:** `attach_rule`'s worker already self-disarms a late arm success via its `still_wanted` re-check, so a leaked subscription is NOT reachable on this tree - the census is a NO-REGRESSION check on that contract, not a leak detector. Verified by mutation: removing that self-disarm fails the census (27 live subscriptions against 6 armed keys). **This row does NOT close on PR-2c** - the criterion is the RERUN against the flip tree, and §2 criterion 2 records that its evidence can only ever be a local TSan build. |
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
  fault-injection scenario matrix (PR-2c, real engineering, not "run TSan and see").
  **THE MATRIX HAS NOW RUN (PR-2c, #3848), AND ALL FOUR WERE CONFIRMED.** None was ruled
  out; the risk acceptance recorded above is superseded per-issue below. TSan turned out
  to be secondary for all four, not only #2818: every one was demonstrated by a
  deterministic seam, and none needed a race to be caught.
- **#2815 - CONFIRMED and FIXED in PR-2c.** The engine had FOUR call sites that resolve a
  raw mechanism pointer under `mu_`, release `mu_`, then call into the mechanism
  (`disarm`, `teardown_arm_race`, `unregister_consumer`, and the live arm path in
  `arm_impl` - the fourth was missed by the original analysis and found in review).
  `stop()` waited on none of them and neither did `~SparkEngine`, so the engine could be
  freed under a parked caller. Demonstrated, not argued: a plain debug build SIGSEGVs, and
  ASan names it `heap-use-after-free ... in SparkEngine::disarm` at the
  `mech_ops_mu_by_type_.at()` dereference. Fixed with a function-scoped lease armed as the
  last statement of the same `mu_` block that resolves the mechanism; `stop()` waits
  BOUNDED and proceeds on expiry (counting a new `teardown_join_timeouts_total`),
  `~SparkEngine` waits UNBOUNDED - the unbounded one is what actually closes the UAF. Note
  the shipped agent was never exposed: F3's `OrphanExitGuard` `hard_exit()`s before
  `~Agent` while any Guardian I/O worker is live. Any other embedder, and every test, was.
- **#2818 - CONFIRMED, NOT FIXED. Escalates to its own PR-2d, a hard pre-PR-5
  prerequisite**, per this section's own revisit trigger. A second consumer that dedups
  onto a key whose watch is still in flight is handed a success id; when that watch fails,
  `drop_key_locked` erases every subscription on the key and tells nobody. Pinned at both
  layers in PR-2c (engine and Guardian). The Guardian pin is the one that matters: after
  the kill, nothing is armed and nothing is watched, Guardian still reports the rule armed,
  and the legacy path did not pick it up either - a genuine detection hole, not a fallback.
  **PR-2d is NOT gated on PR-2e (#3816) landing.** That dependency was an inference and is
  withdrawn: #3816 supplies an executor-level caller-abandonment signal, #2818 needs an
  engine-level consumer-death notification. Different primitives, different layers.
- **#2833 - CONFIRMED but DOMINATED; accepted by documentation, no code change.** The
  unwatch-failure counters do increment during shutdown, but nothing carries them off the
  box: the agent's heartbeat composer emits NOTHING once `stop_requested_` is set
  (`agent.cpp:2582` / `:3311`) — independently of whichever order the two shutdown
  paths' spark-stop and heartbeat-join calls happen to interleave in, since
  `emit_spark_heartbeat_tags()`'s own `!running` early-return suppresses it too. A
  `spark_heartbeat.hpp` change would be inert on the wire; the gate
  that would have to move is the agent's, and it is deliberate (STOPPED is not FAILED - a
  cleanly-stopping agent must not page on-call). **Operator consequence, and the reason
  this is written down rather than closed silently: shutdown-window increments are
  journal-only (`spdlog::error` at each increment site), never heartbeat-visible, so a
  zero reading for `yuzu.spark_arm_race_unwatch_failures` or
  `yuzu.spark_disarm_unwatch_failures` during a shutdown is NOT evidence that nothing was
  orphaned.** Pinned in PR-2c and disclosed on both counters and on
  `emit_spark_heartbeat_tags` itself.
- **#2839 - CONFIRMED and FIXED in PR-2c; Windows evidence CAPTURED (corrected
  2026-09-04).** `push_retiring` took the owning `unique_ptr` by value and pushed before
  allocating, so a `bad_alloc` destroyed a `DirWatch` whose `ReadDirectoryChangesW` was
  still outstanding. Review found three further gaps beyond the original reorder: the
  gauge-crossing log runs after the transfer and can itself throw, `release_ancestor` is a
  second call site with the identical pattern, and all THREE `stop()` cancel loops
  dereferenced their `unique_ptr` unguarded. All four fixed, with a
  `set_file_retire_fault_hook_for_test` seam to aim the allocation failure. **Verified on
  real Windows hardware (DGRHP, commit `95ca9f8e2`)**: the committed test's own
  discriminating power was checked on real MSVC-compiled code first - an earlier version
  had zero discriminating power (its "still not wedged" follow-up watch collided with the
  first watch's directory key and silently repaired the pre-fix corruption before `stop()`'s
  cancel loop ever ran, so it passed identically whether the fix was present or reverted) -
  then corrected (a genuine sibling directory) and re-verified: a real SIGSEGV
  (`0xC0000005 STATUS_ACCESS_VIOLATION`, in `mech->stop()`) pre-fix, a real clean pass
  post-fix, 4/4 stable. **MSVC `/fsanitize=address` was separately confirmed INFEASIBLE**
  under this repo's current toolchain (a real, general finding, not specific to this PR): an
  ASan-instrumented build compiles clean but fails to LINK, 1266 `LNK2038` mismatches,
  because vcpkg's binary-cache grpc/protobuf/abseil aren't ASan-instrumented and no triplet
  rebuilds them with matching instrumentation - a substantial, separate, not-yet-scoped
  prerequisite if Windows ASan is ever wanted. So the evidence above is real MSVC-compiled,
  real-kernel-I/O red/green verification, genuinely NOT ASan proof, described honestly as
  such.
- Owner: not assigned in source material.
- Milestone: PR-2c DONE for #2815 / #2833 / #2839; **PR-2d owed for #2818 before PR-5**.
- Revisit trigger: fired. #2818 escalated per the rule.

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
during a real incident is N individual restarts, not covered here. Persistence across restarts
is the unit's `EnvironmentFile=-/etc/yuzu-agent/yuzu-agent.env` (#3851) - Linux/systemd
packages; Windows and macOS service configuration is outside this issue, tracked at #3973.
Treat this as the
drill procedure for evidence collection, not yet a production incident runbook. **Path note**:
deliberately `/etc/yuzu-agent/`, not the shared `/etc/yuzu/` - a co-installed `yuzu-server`
package re-asserts `/etc/yuzu` as `0750 yuzu:yuzu` on every install/upgrade, and that
different service account can unlink/replace a file inside it regardless of the file's own
mode; `/etc/yuzu-agent/` has no such collision.

1. Confirm current state: agent running with `prefer_spark` active, spark armed on at least one
   rule, drift/heartbeat evidence flowing (criterion 5's UAT smoke precondition).
2. Flip the flag - persist it, then restart.

   **On Rig B (the §8 drill rig, foreground)** - this is the drill path, run this on the
   shared box, not the systemd form below:
   ```bash
   YUZU_AGENT_SPARK_DISABLE=1 ./yuzu-agent ...
   ```

   **Production systemd form** (recorded here for the eventual incident runbook - do not run
   this against a shared or hands-off host):
   ```bash
   sudo mkdir -p -m 0750 /etc/yuzu-agent
   sudo touch /etc/yuzu-agent/yuzu-agent.env
   sudo chown root:root /etc/yuzu-agent/yuzu-agent.env
   sudo chmod 0600 /etc/yuzu-agent/yuzu-agent.env
   sudoedit /etc/yuzu-agent/yuzu-agent.env   # replace any existing content with exactly one line: YUZU_AGENT_SPARK_DISABLE=1
   sudo systemctl restart yuzu-agent
   ```
   Exactly one `YUZU_AGENT_SPARK_DISABLE=1` line - `sudoedit` opens existing content, so
   replace it rather than appending on a repeat drill run; no `export`, no shell syntax, no
   trailing inline comment (systemd's `EnvironmentFile=` parser does NOT strip a trailing
   `# ...` the way a shell would; the whole rest of the line becomes part of the value, which
   then fails CLI11 parsing at boot - see the recovery note below). An empty file (e.g. from
   `touch` with no `sudoedit` yet) behaves exactly like a missing one - both apply zero
   variables. Drop-in alternative: `sudo systemctl edit yuzu-agent` with `[Service]`
   `Environment=YUZU_AGENT_SPARK_DISABLE=1` (`EnvironmentFile=` overrides `Environment=` when
   both exist; an `ExecStart` override is unaffected, since the variable binds via
   `->envname`, and a CLI flag always wins over the environment). Roll-forward: remove the
   assignment and restart - not `=0` (works today, per CLI11's source, but the runbook
   shouldn't couple to that implementation detail). **Package-upgrade note**: an `.rpm`
   upgrade auto-restarts the unit (`%systemd_postun_with_restart`) and so picks up a pending
   env-file change on its own; a `.deb` upgrade only reloads the unit definition (`systemctl
   daemon-reload`) and does NOT restart the process - the env change stays pending until an
   explicit or otherwise-triggered restart. **Recovery from a malformed value**: a bad value
   (not a missing file - see above) fails CLI11 parsing at boot, and `Restart=always` +
   `StartLimitBurst=5`/`StartLimitIntervalSec=300` (top of this unit) will crash-loop the
   agent into `failed` state within ~50s. Fix or remove the offending line, then
   `sudo systemctl reset-failed yuzu-agent` before `restart` - a plain `restart` alone does
   NOT clear a `failed` state once the burst limit trips. The actual parse-error text is not
   in yuzu's own logs (it fires before yuzu logging initializes) - it's in
   `journalctl -u yuzu-agent`. Evidence it took - run the redirection inside the privileged
   shell, not the calling one:
   ```bash
   pid="$(systemctl show -p MainPID --value yuzu-agent)"
   sudo sh -c 'tr "\0" "\n" < "/proc/$1/environ" | grep -Fx "YUZU_AGENT_SPARK_DISABLE=1"' sh "$pid"
   ```
   (`systemctl show -p Environment` does not list `EnvironmentFile=`-sourced vars.) On Rig B
   (foreground, no systemd unit), substitute the shell's own PID for `MainPID`: `pid=$!`
   right after backgrounding the foreground command, or `pgrep -f yuzu-agent` if it's already
   running - `systemctl show` has no unit to query for a bare foreground process. The
   boot-time branch at `agent.cpp:1195–1197` short-circuits `SparkEngine` instantiation
   entirely when this is set - `spark_engine_` stays null, and the boot log records the
   literal string (note: an em dash, not a hyphen, at `agent.cpp:1196` - a plain-hyphen grep
   will not match it) `"SparkEngine: disabled by --spark-disable — not instantiated; Guardian
   detection path = legacy IGuard (enforcing)"`.
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
