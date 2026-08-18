# F11 - flood measurement + token-bucket disposition, recorded run

Captured 2026-08-18, branch `feat/2298-f11-flood-measurement`. Initial measurement at
commit `fe69588ca`; **corrected after an adversarial review (Kimi + Codex, both
independently) found the original file-lane figure ignored production scheduler
jitter** - see "Adversarial review" below and the file-lane correction in Claims.
Authority: D1 ruling 2026-08-05 (port-lite: commit the harness, record
one worst-case run, replace the stale extrapolation) + `docs/adr/0021-spark-reflex-
architecture.md`. Companion doc: `stage11-resource-gate-runbook.md` (build/run
mechanics). Confirms/replaces the ~17k/day figure in
`docs/spark-stage2-guardian-consumer-design.md` (see that doc's 2026-08-18 superseding
addendum) and closes the D2 token-bucket disposition on the flip ladder
(`~/.claude/plans/carefully-look-at-the-frolicking-nova.md`).

## What was measured, and how

Two instruments, deliberately separated:

1. **THE NUMBER** - a committed, deterministic fake-clock Catch2 test
   (`tests/unit/test_guardian_spark_runtime.cpp`, cases prefixed `"F11 flood: ..."`) at
   PRODUCTION DEFAULT `GuardianSparkRuntime::Config` (no overrides): `errored_refresh_ms
   = 300'000`, `pending_demote_sweeps = 12`, `pending_demote_ms = 120'000`
   (`guardian_spark_runtime.hpp:162-184`); lane cadences `service_cadence_ms =
   registry_cadence_ms = 60'000`, `file_cadence_ms = 600'000`, `priority_poll_ms = 5'000`
   (`guardian_convergence_scheduler.hpp:68-75`). A test-driven clock advance per
   simulated scheduler tick stands in for `ConvergenceScheduler` itself, which received
   **zero code change** from F5 (`docs/spark-stage2-guardian-consumer-design.md:283-284`)
   - the real per-lane tick spacing is the scheduler's job, reproduced here by hand.
2. **A live DGRHP window** - spark forced active via a one-line, never-committed rig
   patch, real REST-armed errored load, real journal/outbox/heartbeat pipeline under
   wall clock. Confirms the pipeline moves the way the unit test says it should; it is
   **not** an independent measurement of the ceiling itself.

## Claims

Measured, at production Config defaults, once a never-Known rule is past demotion:

- **60s-cadence lane (service/registry): 1 edge + 288 refreshes/rule/agent/day.**
  Demotion off the 5s priority lane completes in exactly 12 committed Convergence
  sweeps (60s wall time), well inside the 300s refresh floor - so demotion contributes
  zero wire messages of its own. Once on the 60s type-lane cadence, refresh recurs
  exactly every `errored_refresh_ms` (measured: first refresh lands at t=300s post-edge,
  keyed off the LAST emission, not re-armed by demotion); 300s divides 86,400s evenly
  86,400 / 300 = 288 times/day.
- **600s-cadence lane (file): 1 edge + 144 refreshes/rule/agent/day AT EXACT
  600s CADENCE (no scheduler jitter) - NOT the production ceiling; see the correction
  below.** Same demotion timing (the priority lane is type-agnostic). Once on the
  600s file-lane cadence, EVERY post-demotion sweep refreshes - the lane's own cadence
  (600s) already exceeds the 300s refresh floor, so there is no suppression window at
  all on this lane; rate = 1/lane_period = 86,400 / 600 = 144/day.
- **CORRECTION (2026-08-18, adversarial review - Kimi + Codex both found this
  independently): the true production file-lane ceiling is 1 edge + 180
  refreshes/rule/agent/day, not 144.** `ConvergenceScheduler::Config` defaults
  `jitter_pct=20` and `jittered()` draws a SYMMETRIC `base_ms + uniform(-span, +span)`
  perturbation (`guardian_convergence_scheduler.cpp:59-69`) - an earlier version of
  this doc claimed jitter "only ever pushes a sweep LATER, never earlier," which is
  flatly false; the draw is symmetric and CAN shorten the interval. The minimum
  possible file-lane sweep spacing is therefore `600s x (1-0.20) = 480s`; since 480s
  still exceeds the 300s `errored_refresh_ms` floor, every such sweep still refreshes
  (proven empirically, not just derived - see the fourth F11 Catch2 case, "file lane
  at the scheduler-jitter floor (480s)"), giving a true worst-case rate of
  `86,400 / 480 = 180/day`. The 60s-lane figure (288/day) is UNAFFECTED by this
  correction: it is bounded by the 300s refresh floor itself, not by sweep cadence, so
  shortening the already-sub-floor 60s lane's spacing changes nothing. **Use 180/day,
  not 144/day, as the file-lane production ceiling in any downstream citation
  (changelog, flip PR, fleet-ingest capacity planning).**
- Both corrected figures (288/day, 180/day) are **roughly 60-95x below the pre-fix
  ~17k/day** extrapolation in
  `docs/spark-stage2-guardian-consumer-design.md`'s "cutover-blocking finding (Fable
  M1)" section - see that doc's 2026-08-18 addendum for the corrected attribution:
  edge emission (`b30e93cfd`, 2026-07-20) already reduced the flood to zero
  steady-state before F5 shipped; F5 (PR #3005) then added the above nonzero ceiling
  back, deliberately, as a lost/coalesced-edge backstop.
- **Red-then-green provenance:** each numeric assertion was verified to actually fail
  under a deliberately wrong pinned value before being set to the value the code
  produces (recorded below), then a full `[spark][runtime]` tag run (90 cases / 1610
  assertions) passed clean - this is not an extrapolation from the mechanism's
  documented behavior, it is the runtime's own measured output.

```
$ tests-build-agent-linux_x64/yuzu_agent_tests "F11*" --success
===============================================================================
All tests passed (39 assertions in 4 test cases)

$ tests-build-agent-linux_x64/yuzu_agent_tests "[spark][runtime]"
===============================================================================
All tests passed (1620 assertions in 91 test cases)
```

(Counts updated after the jitter-fix commit added a fourth `F11 flood:` case - re-run
verbatim against this branch's HEAD, not carried over from the pre-fix commit.)

Mutation-check (proves the assertions are not vacuous - a placeholder wrong value on
the demotion-sweep-count case, rebuilt and rerun):

```
F11 flood: production-default demotion completes in 12 sweeps @ 5s (60s) -
           before any refresh could fire (#2298)
../tests/unit/test_guardian_spark_runtime.cpp:1041: FAILED:
  CHECK( sweeps == 99 )
with expansion:
  12 == 99
```
- reverted to the correct assertion (`sweeps == 12`) immediately after, full tag rerun
green.

## D2 - file-lane token-bucket disposition

**Formally deferred to rung 5; measurement contradicts nothing.** No token bucket
exists in `guardian_convergence_scheduler.hpp` today - the code at :41-45 is a
deferral comment, not a mechanism:

> DEFERRED to rung 5 (where the real readers exist and there is a read cost to
> meter): size+mtime skip before re-hash, forced periodic full hash, and the
> file-lane byte token bucket. Against rung 4's fake instant reader there is
> nothing to budget, so wiring them here would be untested theatre; they live at
> the file StateReader / runtime boundary.

The measured post-demotion file-lane READ cadence (distinct from the wire cadence
above - `GuardianSparkRuntime::Config`'s own doc comment calls this out explicitly:
"the read flood, not the wire flood - errored_refresh_ms above already bounds the wire
side") is 1 read/600s/rule at steady state, once demoted off the 5s priority lane. That
is not a load a rate limiter would do anything useful against; nothing here motivates
building the bucket early. D2 stands as originally recommended (ladder plan,
2026-08-05): defer to rung 5, where a real file reader with a real read cost exists to
meter.

## Live DGRHP window

Rig-side patch (never committed - diff quoted here for the record, applied to
`/c/Users/daver/yuzu-pr3a` at pinned commit `0023efc33`, the same commit this
worktree's branch was cut from):

```diff
--- a/agents/core/src/agent.cpp
+++ b/agents/core/src/agent.cpp
@@ -717,7 +717,10 @@ public:
         // The engine persists rules into the KV store and answers __guard__
         // dispatches once the Subscribe stream is open. Construction is
         // safe even when KV failed to open (it degrades to in-memory only).
-        guardian_ = std::make_unique<GuardianEngine>(kv_store_.get(), cfg_.agent_id);
+        // F11 RIG PATCH - never commit. Forces spark active for the live
+        // flood-measurement window (docs/spark-rebuild-baselines/f11-flood-measurement-run.md).
+        guardian_ = std::make_unique<GuardianEngine>(kv_store_.get(), cfg_.agent_id,
+                                                     /*prefer_spark=*/true);
```

**Run executed 2026-08-18 on DGRHP.** Rig: `yuzu-pr3a` scratch worktree (detached at
`0023efc33`) + a throwaway `postgres:18` container on BigColin
(`100.74.176.116:5460`, removed after). Server and agent both ran locally on DGRHP
(loopback REST `:8080` / gRPC `:50051`), `--no-tls`/`--no-https`, seeded via the same
`yuzu-server.cfg` admin-user recipe `scripts/start-UAT.sh` uses.

**What was confirmed, with evidence:**
- **The agent boots and registers fine under `prefer_spark=true`.** An earlier
  same-session attempt looked hung (2 minutes with no new log lines, killed) - a
  controlled A/B against a rebuilt *unpatched* agent showed the SAME apparent pause
  (spdlog's file sink flushes in bursts, not per-line, so a quiet log window is not
  evidence of a stall by itself), and the retried patched agent registered
  successfully (confirmed via the `/fragments/devices/list` dashboard fragment) after
  ~4 minutes total boot-to-register. Not a defect - an artifact of an impatient first
  check, corrected before drawing any conclusion from it.
- **Spark activates.** Agent log: `SparkEngine started (0 spark(s) armed)` then
  `Guardian: spark path wired and available (consumer_id=1)`.
- **Found, in passing: a stale hardcoded log string.** The very next line,
  `Guardian: spark path WIRED (observe-only, prefer_spark=false); detection backend =
  legacy IGuard` (`agent.cpp:1115`), is a literal compile-time string, not a read of
  the actual `prefer_spark_`/backend state (`prefer_spark_` has no public getter -
  "deliberately not exposed" per `guardian_engine.hpp:189`) - so it now prints false
  information the first time this call site is ever exercised with `prefer_spark=true`
  in this codebase's history (rung 7.7a wires spark at boot but never with
  `prefer_spark_` true in any shipped build, per the routed-concerns Spark row). Minor
  (diagnostic text only, no functional effect), but worth a follow-up fix before F14
  ships this path for real - a boot log that lies about which detection backend is
  active is exactly the kind of thing an incident responder trusts.
- **The errored-load deny-ACL mechanics work as designed.** 20 deny-ACL files +
  20 deny-ACL HKLM registry keys created per the runbook's PowerShell recipe; read
  attempts AS the account actually running the agent (`daver`, an admin account on
  this rig - a `Deny Everyone` ACE blocks even an admin's ordinary read, verified
  empirically, not assumed) failed with `Access is denied` / `Requested registry
  access is not allowed` - exactly the Unknown-producing failure mode the errored
  profile needs.
- **The harness's `arm-errored` mode works end-to-end at the REST/server layer.**
  `generate_resgate_load.py arm-errored` reported `armed-errored 40/40 guards, pushed
  full_sync`; `GET /api/v1/guaranteed-state/rules` confirmed all 40 rows stored
  correctly (`os_target=windows`, correct `spec_json` paths/keys under
  `C:\YuzuResGateDenied\` and `HKLM\SOFTWARE\YuzuResGateDenied\`).

**What was NOT confirmed - a genuine gap, reported honestly rather than glossed
over:** the pushed rules never reached this agent's Guardian reconcile. Across two
`full_sync` pushes (the arm call's own, plus a manual re-push ~4 minutes into a stable
connection) and a combined ~5 minutes of polling both the agent's own log (zero
`attach_rule`/`reconcile`/`guard.unhealthy` lines - heartbeats and unrelated TAR/DEX
triggers kept firing normally throughout, so the process was not hung, just never
received the push) and the server's `/api/v1/guaranteed-state/status` route
(`errored_rules` stayed `0` throughout), no evidence surfaced that the 40 rules were
ever delivered to the agent side. Checked and ruled out as causes: OS-target mismatch
(rules say `windows`, agent reports `windows`, `os_target_matches` is case-insensitive
exact-match - fine) and scope-expression exclusion (`guardian_push_builder.cpp:119`:
an EMPTY `scope_expr`, which every generated rule has, skips the `in_scope` check
entirely - matches every agent by construction, not a targeting gap). Root cause not
isolated within the time budget spent on it - most likely something specific to this
throwaway single-box rig's setup (a fresh admin/agent pairing with no management-group
assignment, or a push-dispatch precondition this run didn't satisfy) rather than a
product defect, given the REST/storage layer and the deny-ACL mechanics both worked
correctly in isolation. **This gap does not affect the Claims section above** - that
section is entirely function of the committed Catch2 test, not this live run.
Flagged as a forward action item (below), not silently dropped.

Rig-side patch reverted, deny-ACL artifacts removed, agent/server processes stopped,
throwaway Postgres container removed. Nothing from this window was committed.

## Does NOT claim

- **No legacy-vs-spark resource A/B.** That gate stays blocked on the flip's
  `--spark-disable`, per `stage11-resource-gate-runbook.md`'s "Why not now" - this doc
  makes no resource-footprint claim (threads/handles/RSS/CPU/wakeups) of any kind.
- **No server-side ingest-cost claim.** The wire-message counts above are per-rule,
  per-agent, agent-side emission counts. What that costs a real Postgres-backed server
  at fleet scale (insert transaction cost, `guaranteed_state_store` row growth) is not
  measured here.
- **No fleet-aggregate claim.** The figures are per-rule-per-agent and linear in rule
  count (each rule tracks its own `last_unhealthy_emit`/demotion state independently,
  confirmed by the existing F5 "two rules sharing one key each refresh independently"
  test) - a fleet total is rule_count x agent_count x the per-rule daily figure, not
  measured directly at any scale here.
- **No claim about the service lane's errored path.** Per
  `agents/core/src/guardian_state_reader.cpp`, `ERROR_SERVICE_DOES_NOT_EXIST` resolves
  to `read_known(Stopped)`, not Unknown - a nonexistent service cannot enter the
  errored/flood path this doc measures at all. The service lane shares the
  registry lane's 60s cadence, so no coverage is lost by this omission, but no
  service-specific number was captured (there is nothing to capture).
- **Jitter IS now accounted for (corrected 2026-08-18, see the Claims section).** An
  earlier version of this bullet claimed jitter only stretches inter-sweep spacing
  later, never earlier - that was wrong: `jittered()`'s perturbation is symmetric
  (`base_ms + uniform(-span, +span)`), so it can shorten spacing too. 288/day (60s
  lanes) is unaffected - it is bounded by the 300s refresh floor regardless of sweep
  cadence. 180/day (file lane, corrected from the no-jitter 144/day) IS the honest
  ceiling once the symmetric jitter is accounted for, per the fourth Catch2 case.
- **No claim about the pre-demotion (0-60s) window's read cost**, only its (zero) wire
  cost. 12 priority-lane reads at 5s cadence happen regardless of lane; this doc only
  characterizes what reaches the wire.

## Adversarial review

Kimi + Codex, two-phase independent review + cross-examination, run 2026-08-18 against
this branch before push. Both converged on BLOCK. Verified findings, fixed in this
branch:

- **HIGH, found independently by both:** the file-lane "144/day" figure was presented
  as a production ceiling, but the doc's own "jitter only pushes sweeps later, never
  earlier" claim was false - `ConvergenceScheduler::jittered()` is symmetric. Fixed:
  a fourth Catch2 case (`tests/unit/test_guardian_spark_runtime.cpp`) empirically
  proves the jitter-floor (480s) case still refreshes every sweep, giving a true
  worst-case of 180/day; every doc/changelog citation of "144/day" as a ceiling is
  corrected to 180/day (144/day now stated only as the exact-no-jitter figure).
- **HIGH (Codex) / MEDIUM (Kimi), confirmed by both:** `resource_sampler.cpp` leaked
  the process `HANDLE` if `_wfopen_s` failed to open the output file (the acquire at
  `OpenProcess` preceded the fallible file-open, with `CloseHandle` only at the very
  end). Fixed: output-file open now happens before `OpenProcess`, so that failure
  path never holds an unreleased handle.
- **LOW, confirmed by both:** the runbook's 30-minute sanity-window table said "~5
  refreshes" without noting the inclusive t=1800s boundary can land a 6th, and didn't
  account for jitter on the file-lane count. Fixed: reworded.
- **LOW (Kimi only, rejected by Codex on cross-exam, I agree with the rejection):**
  `guardian-c0-thread-reloc-design.md`'s item 7/9 resolutions record an operator
  ruling without a paired code change. Not a defect - there was no code to change
  (the shipped caps already matched the derivation; only stale TEXT was wrong), and
  the doc is honest about being a recorded ruling, not a code-verified measurement.
- **Withdrawn by both (already tracked, out of this branch's scope):** the
  `agent.cpp:1115` hardcoded log string - this branch doesn't touch `agent.cpp`;
  stays forward action item 3 below.

Full transcripts: Kimi/Codex phase1+phase2 reports and this synthesis are not
committed (adversarial-review workflow output, not repo content) - reproducible via
`/adversarial-review` against this branch if needed again.

## Ready-to-paste F14 flip-changelog sentence

> Guardian's `guard.unhealthy` wire traffic for a stuck-Unknown rule is bounded at
> 1 edge + 288 refreshes/rule/agent/day on 60s-cadence lanes (service/registry) and
> 1 edge + 180/day on the 600s file lane, accounting for the scheduler's default
> +/-20% jitter (measured, `docs/spark-rebuild-baselines/f11-flood-measurement-run.md`),
> roughly 60-95x below an earlier ~17k/day
> pre-mitigation estimate.

## Forward action items

1. **F14's A/B** (legacy vs spark resource footprint) still needs the flip's
   `--spark-disable` - this doc's harness (`resource_sampler.cpp` +
   `generate_resgate_load.py`'s original `arm`/`teardown` profile) is ready to fire the
   moment that lands; see `stage11-resource-gate-runbook.md`.
2. **Server-side ingest cost** at the measured wire rate is unmeasured - worth a
   companion note (or its own doc) once a fleet-scale server test rig exists, if the
   #2298 checklist or an enterprise-readiness gate asks for it.
3. **Fix the stale `prefer_spark=false` / `detection backend = legacy IGuard` boot log
   text** at `agent.cpp:1115` - it hardcodes both facts as literals rather than reading
   `guardian_`'s actual state, and is now demonstrably wrong once `prefer_spark=true`
   is ever exercised (found live this run). Wording-only, no functional effect - a
   small fix, but worth landing before F14 ships this path for real, since it is
   exactly the log line an incident responder would trust post-flip.
4. **Isolate why the live-window `full_sync` push never reached the agent's Guardian
   reconcile** (this run's one open gap - see "Live DGRHP window" above for what was
   ruled out). Worth a fresh, focused rig session before F14's real A/B, which depends
   on push delivery actually working end-to-end.
5. Re-verify the F5 config defaults cited here (`errored_refresh_ms`,
   `pending_demote_sweeps`, `pending_demote_ms`) have not changed before reusing these
   numbers in a later doc - they are cited by value, not by reference, in the "Claims"
   section above, and a future retune would silently stale this doc exactly the way F5
   staled the ~17k/day figure.
