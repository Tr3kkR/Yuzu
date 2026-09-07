# #3990 - full_sync blackout diagnostic, recorded run

Captured 2026-09-06/07, rig DGRHP (`C:\yuzu-devrig2`, server + agent, data dir `C:\rigA`).
Authority: Dave's 2026-09-06 ruling on #3850 (the third comment on that issue) - CH-5-UAT
excludes rule-mutation churn from its own sampling windows, paired with a required,
non-gating diagnostic: "one baseline deploy on each backend, blackout duration recorded"
before #3990 can be cited in `docs/spark-flip-gate.md` §5 as accepted-neutral. The ruling
specifies nothing beyond that sentence - no measurand, sample size, or neutrality criterion.
Everything below that isn't a direct quote of the ruling is this run's own definition, stated
as such rather than attributed to source.

**Headline result, read this first, CORRECTED after this doc's own first draft overclaimed
it** (see "Retraction" below the fold in "The driver's T1-detection gap" section - kept
in-doc rather than silently edited away, since the wrong version was briefly the working
conclusion): the intended legacy-vs-spark comparison could not be completed at the
pre-registered sample size (K=5). The reason is a **bug in this run's own driver script's T1
(completion-marker) detection**, confirmed by correlating EVERY `full_sync` trigger in the
complete agent log (not a sample) against its own completion line: across the whole
~5.5-hour session, all 84 real triggers that ran to completion did so in **8.3 seconds or
less** - most in under 100ms at the clean 62-rule cohort, and a consistent ~7.5-7.9s at the
5652-rule leftover-catalogue scale (Phase A). There is no gap anywhere in the log approaching
even one minute, on either backend. The driver's own poll logic nonetheless recorded most
clean-cohort attempts as `t1_not_found` (timed out waiting) or `t0_not_found` (never saw the
trigger at all) - a tooling gap in THIS run's instrument, not a property of the system under
test. See "The driver's T1-detection gap" below for the full evidence and what remains
unexplained about the bug itself.

## What was measured, and how

**Measurand: B = T1 - T0, the synchronous `full_sync` apply-window proxy** - NOT a claim of
end-to-end detection blackout. T0 = `Guardian: full_sync cleared N prior rule(s)`
(`guardian_engine.cpp:658`, agent log, logged immediately before `stop_all_guards_locked()`/
`detach_all()`); T1 = `Guardian: apply_rules ok (applied=N, failed=0, full_sync=true, ...)`
(`guardian_engine.cpp:768`). `apply_rules` holds `mtx_` for the whole call and runs inline on
the agent's run() thread, so [T0,T1] is strictly all-guards-down-then-all-back-up on both
backends. Excluded from B: push transit, OS-watch re-establishment (legacy `FileGuard::start()`
returns before the watch exists; spark's `attach_rule` returns after the blocking
`GuardianIoExecutor::run`, so B is a closer approximation to spark's real blackout than to
legacy's - legacy's true blackout is understated by an unmeasured amount), first evaluation,
server ingest.

**Secondary, report-only: D**, the per-rule time to a fresh `guard.compliant` event after T0
(deadline = max(2B, 30s)). Used only as a functional-validity precondition for a repeat to
count - never an input to the numeric decision on B. In practice D could only be evaluated for
the handful of non-void repeats; not enough data to say anything general about it.

**Instrument**: `fullsync_blackout_diag.py` (this directory), a new committed driver reusing
`generate_resgate_load.py`'s HTTP/baseline helpers. Subcommands: `inventory`, `purge`,
`ensure`, `run`, `report`, `teardown-cohort`. See that file for the full mechanism; this doc is
the record of what it measured, not a restatement of how. The complete raw per-repeat output
is committed as `fullsync-blackout-results.jsonl` in this directory - every field this doc's
tables summarize, including the void repeats, is there in full; its `t0`/`t1` fields are the
driver's own raw timestamps and carry the UTC-mislabeling defect described in correction #2
below (harmless for the B values themselves, a same-host subtraction; do not trust their
absolute `+00:00` tag as real UTC).

**Build**: agent core AND all plugins rebuilt at `origin/dev@65f2938156a19` plus the single
flip one-liner at `agents/core/src/agent.cpp:836`:
```diff
-        guardian_ = std::make_unique<GuardianEngine>(kv_store_.get(), cfg_.agent_id);
+        guardian_ = std::make_unique<GuardianEngine>(kv_store_.get(), cfg_.agent_id,
+                                                     /*prefer_spark=*/!cfg_.spark_disable);
```
`yuzu-agent --version` = `0.13.1+7899 (65f2938156a19)`; `git diff` against the clean checkout
confirmed this is the ONLY local change. Server binary stayed at the pre-existing
`7c3c7d3fa`-era build (proto unchanged in that range) - accepted specifically because B is
agent-local (both T0 and T1 read the agent's own clock/log); the server side only matters for
the B2 trigger's reconcile audit-row cross-check, noted as a caveat there.

## Methodology corrections found live

Three real bugs were found and fixed DURING this run, all folded back into the plan
(`~/.claude/plans/let-s-pick-up-this-indexed-perlis.md`) and into `fullsync_blackout_diag.py`
itself. None of them invalidate the B values actually reported below (each B is a same-host,
same-clock subtraction that cancels out every one of these bugs) - they only affected which
repeats were correctly recognized as valid versus wrongly voided, which is exactly why the
early attempts under-counted valid samples so badly.

1. **Partial-plugin rebuild crash (rig ops, not a product defect).** The first rebuild
   compiled only the `yuzu-agent` target, leaving `agents/plugins/tar/tar.dll` at its stale
   pre-rebuild build. The mismatched core-vs-plugin vintage crashed the agent deterministically
   ~16s after boot - momentarily misdiagnosed as a regression in the just-merged PR #4017
   (power-capture source) before an empirical rebuild-and-retest (rebuilding `tar` too)
   disproved that and reproduced a stable agent past the crash point. No GitHub issue filed.
   Corrected instruction: a rebuild that moves to a new `origin/dev` tip must rebuild the FULL
   plugin set, not just the agent target.
2. **UTC mislabeling.** spdlog's `%Y-%m-%d %H:%M:%S.%e` pattern logs DGRHP's LOCAL time (BST,
   UTC+1 on the days this ran), but the driver's log parser tagged every timestamp
   `tzinfo=timezone.utc` for convenience. Harmless for any same-host comparison (B = T1-T0
   cancels the constant offset), but wrong for two cross-host uses: the driver's own
   "since-now" window-start marker, and the D-lookup's comparison against `event_id`'s embedded
   `system_clock` epoch ms (which IS real UTC, unaffected by display timezone). The first
   symptom was every early Phase B repeat falsely reporting a "second full_sync" (`
   double_full_sync`) that turned out to be the tool re-finding up to an hour of old history,
   not a genuine second trigger.
3. **Cross-host clock drift (the deeper bug once #2 was fixed).** The fix for #2 computed the
   window-start marker as "this driver host's true UTC now, plus DGRHP's known UTC offset" -
   correct only if the driver host's and DGRHP's system clocks are perfectly synchronized. They
   are not: measured ~0.2-1s of drift between the two machines, small in absolute terms but
   larger than a 62-rule `full_sync`'s own ~55ms duration. That was enough for a repeat's own
   window-start marker to occasionally land chronologically AFTER its own trigger's T0 line,
   making every fast, healthy repeat misreport as `t0_not_found`. Fixed by reading DGRHP's own
   clock directly for the window marker (one extra ssh round trip per repeat) instead of doing
   cross-host arithmetic - eliminates the drift by construction, at the cost of a small,
   deliberate backward safety margin (2s) to also absorb the round-trip itself.
4. **B2 rule-id collision across separate CLI invocations.** The `hbr_counter` used to name
   each Phase B2 trigger rule (`blackout-hbr-NN`) restarts at 1 on every fresh `run` invocation.
   Since legacy's B2 run and spark's B2 run were separate invocations, spark's run tried to
   recreate the SAME ten rule_ids legacy's run had already created - each `POST` hit a 409
   (already exists, correctly treated as idempotent success by `generate_resgate_load.py`'s
   convention) and so never bumped `policy_generation`, meaning the heartbeat-reconcile trigger
   Phase B2 depends on never fired at all. This produced spark B2's initial 0/3-with-all-
   `t0_not_found` result, which is a driver bug, not a backend defect - confirmed by re-running
   with deliberately-unique ids (`blackout-hbr-101`, `-110`, `-120`), which DID trigger
   correctly (see below). Not re-fixed in the script itself (a one-time run does not need
   cross-invocation counter persistence); flagged here so nobody re-runs this tool across two
   backends without knowing to bump the starting counter.

## Catalogue

- **Phase A (as-is, uncontrolled)**: the rig's pre-existing leftover catalogue from an earlier
  campaign - 8108 `riga-*` rules across 36 deployed baselines (~5652 armed at the time of
  measurement, after this session's own `ensure` had already added 61 rules on top of the
  original ~5591). No purge, no deliberate trigger.
- **Phase B / B2 (clean)**: after purging every `riga-*` rule/baseline (`dgrhp-drift-test-file`
  and baseline `0c953d48d94c` explicitly preserved throughout - both confirmed present before
  and after), a clean cohort: `blackout-cohort` baseline (20 file / 20 registry / 20 service
  rules, `enforcement_mode=audit`, `remediation=alert-only`) + a separate 1-rule
  `blackout-trigger` baseline (one file rule) whose re-deploy is the measured trigger for
  Phase B. **N=62, not 61** - the pre-existing `dgrhp-drift-test-file` rule (in its own
  permanently-deployed baseline `0c953d48d94c`) is also part of the deployed union and gets
  torn down/rearmed by every full_sync alongside the 61 cohort/trigger rules; the plan's
  original N=61 estimate didn't account for that always-present third baseline. Phase B2 uses
  a bare `POST /api/v1/guaranteed-state/rules` for a fresh rule in NO baseline as its trigger -
  `#3990`'s own literal shape (a rule-store mutation, amplified via heartbeat reconcile, not
  baseline-deploy's own protocol-necessary full_sync).

**Purge record**: pre-purge `riga_rules=8108`, `riga_baselines=36`. Both protected artifacts
(`dgrhp-drift-test-file` rule, `DGRHP File Drift Test` baseline `0c953d48d94c`) confirmed
present in a fresh inventory both immediately before and immediately after. `purge --apply`
took **14m14s** wall-clock (36 fragment-delete calls + 8108 individual REST DELETE calls, each
a synchronous local HTTP round-trip through the tunnel) with **zero failed deletes**; a
post-purge inventory confirmed `riga_rules=0`, `riga_baselines=0`, `clean=True`.

## Phase A - storm-observed, uncontrolled (context only, NOT verdict-bearing)

Passive observation: no deliberate trigger. `full_sync` windows recurred naturally on this
catalogue at an irregular cadence (roughly 5s-90s apart depending on how recently other
activity had occurred) via a mechanism this session did NOT fully diagnose - `failed=0` and
`applied=total` throughout every observed window, so this is NOT the "failed rules hold the
generation" mechanism the original plan text assumed (that assumption is corrected here: no
persistently-failing rule was present in this catalogue at measurement time). The likeliest
explanation is that this "ambient storm" was itself residue from this same session's own
preceding test activity (the `ensure` call and earlier smoke-test deploys, plus genuine
heartbeat-reconcile pushes - the server-side audit log for this window shows real
`guaranteed_state.reconcile` rows, not just deploy-triggered pushes) still draining, not a
truly independent, permanently-recurring mechanism - not confirmed either way, left as an
open question.

| Backend | window | B (ms) | applied | failed | total |
|---|---|---|---|---|---|
| spark  | 1 | 7583 | 5652 | 0 | 5652 |
| spark  | 2 | 7764 | 5652 | 0 | 5652 |
| spark  | 3 | 7492 | 5652 | 0 | 5652 |
| legacy | 1 | 7766 | 5652 | 0 | 5652 |
| legacy | 2 | 7636 | 5652 | 0 | 5652 |
| legacy | 3 | 7868 | 5652 | 0 | 5652 |

Both backends land in the same ~7.5-7.9s band at N=5652 - no material difference observed at
this uncontrolled scale, for this specific measurand.

**A separate, real effect found at this catalogue size, worth recording even though it isn't
part of B**: on restart into the **legacy** backend at N=5652, the agent registered with the
server successfully but then produced NO further log output (Guardian OR the unrelated TAR
triggers) for **~6 minutes**, while `(Get-Process yuzu-agent).CPU` grew by under 1.5s of CPU
time across that whole window (near-idle, not a busy spin) and the process held **~5683
threads / ~28,500 OS handles** - roughly one thread and five handles per armed legacy guard.
The server's own `yuzu_agents_connected` gauge read `1` throughout, so the heartbeat/Subscribe
path itself was not down - only the agent's own further activity was stalled. It recovered on
its own. This is the real-world shape of the risk the original plan's own "Risks/open" section
anticipated ("Phase A legacy at N~5800 may exhaust threads/handles ... that is itself a
recorded effect, not a void of Phase B") - recorded here as a genuine, if uncharacterized,
resource-contention effect specific to legacy's one-thread-per-guard design at this scale, not
present (by construction) under spark. **Correction**: an earlier draft of this doc speculated
this might be "a special case of the same broader phenomenon" as a clean-cohort pile-up effect
described further below - that downstream effect was retracted (see "The driver's
T1-detection gap"), so this N=5652 legacy silence stands as its own, separate, still-real
observation with no established connection to anything at the clean N=62 scale.

## The driver's T1-detection gap (why so few clean-cohort repeats counted)

**Retraction.** This section originally claimed a "queueing/pile-up effect" causing 80-90% of
clean-cohort triggers to take minutes to resolve on both backends, and framed that as this
diagnostic's real headline finding. That claim did not survive verification against the
complete evidence and is withdrawn. It is documented here, rather than silently deleted,
because the wrong conclusion was briefly the working state of this doc and a future reader
tracing history should be able to see what was claimed, why it looked plausible at the time,
and exactly what evidence disproved it.

**What the void reasons actually were**, from the driver's own raw per-repeat output
(`fullsync-blackout-results.jsonl`, committed alongside this doc):

| Phase | Backend | Attempts | Valid | `double_full_sync` | `t0_not_found` | `t1_not_found` |
|---|---|---|---|---|---|---|
| A  | spark  | 6  | 3 | 3  | 0  | 0 |
| A  | legacy | 3  | 3 | 0  | 0  | 0 |
| B  | legacy | 30 | 2 | 10 | 10 | 8 |
| B  | spark  | 10 | 1 | 0  | 0  | 9 |
| B2 | legacy | 10 | 2 | 0  | 0  | 8 |
| B2 | spark  | 14 | 0 | 0  | 11 | 3 |

(Phase B/legacy's 30 attempts are three separate `run` invocations - the driver was fixed and
re-run twice after its first two attempts came back 0/10 valid; corrections #2-#4 below explain
why. Phase B2/spark's 14 include the 10-attempt id-collision batch, correction #4.)

**Correlating every one of these against the complete agent log (not a sample) settles the
question.** `agent.log` for this session runs from 19:37:36 on 2026-09-06 (before this
diagnostic's own rebuild) through to teardown at ~01:14 on 2026-09-07, 345,343 lines,
containing every `full_sync` this agent process (across all its restarts) ever handled: **87
`Guardian: full_sync cleared` (T0) lines, 84 matching `Guardian: apply_rules ok ...
full_sync=true` (T1) completions.** Pairing each T0 with its next same-thread T1 gives a
**maximum observed gap of 8.261 seconds, and a median of 0.1ms**, across the ENTIRE session -
the large gaps (7.5-8.3s) are exclusively the six Phase A windows at N=5652; every clean-cohort
(N=62) pair completed in under 100ms. The 3 T0s with no matching T1 all fall exactly at the
three points this session restarted the agent to switch phase/backend - the in-flight request
died with the process, not with a stall. **There is no gap anywhere in the complete log
approaching even one minute**, on either backend, at any point in this session. The doc's
original claim of "several that took 3-6+ minutes" cannot be reproduced from the evidence that
was supposedly the basis for it, and is now believed to have been an unverified inference,
not a checked observation, despite being written as though it were checked.

**Conclusion: every `double_full_sync`, `t0_not_found`, and `t1_not_found` void in this run was
a false positive of the driver's own trigger-detection logic, not a real system delay.**
`double_full_sync` is already explained by correction #2 below (UTC-mislabeled timestamps
causing the tool to "re-find" up to an hour of old history as a spurious second trigger) - a
direct global scan for genuinely overlapping full_syncs (a second `full_sync cleared` with no
intervening completion, ANYWHERE in the whole log, any thread) found **zero** real
occurrences; the only three T0-after-T0 sequences found are the same three restart-boundary
artifacts already accounted for above. `t0_not_found`/`t1_not_found` persisting even in the
corrected (post-#2/#3/#4) runs means at least one further driver bug in the T0/T1 log-window
or polling logic was never identified - **this diagnostic does not have a root cause for the
residual detection gap**, only proof that it is a detection gap and not a system-side delay.

**The valid (non-void) B values, on both backends and both trigger kinds, are all in the same
tight 55-82ms band** - legacy 55, 56, 57, 63ms (4 samples); spark 82ms (1 sample). This is
consistent with, not evidence against, the "no real delay" conclusion above: a healthy trigger
was always fast, on both backends, every time one was correctly detected.

**Not established, explicitly**: the exact remaining driver bug behind the residual
`t0_not_found`/`t1_not_found` false voids; whether ruling-13's original rationale for excluding
rule-mutation churn from CH-5-UAT (a real, separately-confirmed mechanism - Phase A's own
ambient reconcile activity, and #3990's filed description) has any bearing on THIS specific
tooling gap, which does not exist beyond this one script. No GitHub issue filed for the driver
bug - it is local, uncommitted-elsewhere tooling, not a product defect; the committed script's
docstring should carry a known-issues note for whoever next reuses it.

## Phase B - clean cohort, baseline re-deploy trigger

See the combined table above. Legacy: 2/5 valid (56, 57ms; median 56.5ms). Spark: 1/5 valid
(82ms; no median - a single sample). Both phases are **inconclusive** against the K=5
pre-registration - not enough valid samples exist to compute a reliable median comparison, for
the reason documented above (a driver detection-logic gap, confirmed by the complete-log
correlation - not a difficulty measuring a completed trigger, and not any property of the
system under test).

## Phase B2 - clean cohort, bare rule-create trigger (#3990's literal shape)

Legacy: 2/3 valid (55, 63ms; median 59ms). Spark: 0/3 valid on the corrected (unique-id) runs -
voided `t1_not_found`/`t0_not_found` even after the id-collision bug was fixed. The
complete-log correlation (87 T0s total, 84 completions, max gap 8.3s, all attributable to
Phase A or restart boundaries) accounts for every full_sync this agent process ever logged
across the whole session - it does not distinguish, for any single spark B2 attempt, between
"the driver missed a T0 that really happened" and "the reconcile trigger never fired at all in
the observation window" (e.g. the rule-create's generation bump not yet being trailed by the
agent's heartbeat when the driver gave up) - both are plausible and this run doesn't have the
per-attempt detail to tell them apart. Either way this is a driver/timing gap in how the
trigger was observed, not evidence of a spark-specific completion failure - no case exists
anywhere in the log of a real T0 that took unusually long to complete. Create-to-T0 lag
(informational, cross-host, non-verdict-bearing per the plan) was not usably captured given
how few Phase B2 repeats completed at all.

## Decision rule and outcome

Pre-registered before the clean-cohort runs (this session's own choice, not derived from any
SLO): spark median B <= legacy median B + max(1000 ms, legacy median B); every counted repeat
independently satisfies `failed=0` and functional-validity (D observed for all 60 cohort
rules).

**Outcome: INCONCLUSIVE.** Neither backend reached the pre-registered K=5 valid-repeat floor
for Phase B (legacy 2/5, spark 1/5), so the decision rule cannot be honestly applied - a median
over 1-2 samples is not a basis for a non-inferiority claim at either backend, let alone a
comparison between them. This is not a "neutral" or "not neutral" verdict of any kind, in
either direction - it is a statement that the collected evidence is insufficient to conclude
anything comparative. The small samples that DID complete (4 legacy, 1 spark) all landed in
the same 55-82ms band with no visible separation, but that observation is far too thin to
promote to a finding.

**What this diagnostic DOES establish**: every full_sync actually observed to complete, on
either backend, at either scale tested (N=62 clean cohort or N=5652 leftover catalogue),
completed within 8.3 seconds, most within 100ms - directly contradicting this doc's own
earlier (retracted) claim of a multi-minute pile-up effect. The low Phase B/B2 valid-repeat
count is attributable to an unresolved bug in this run's own driver script, not to any
backend behavior. Whether the evidence actually collected here is sufficient for Dave to cite
#3990 in §5 as "accepted-neutral" per ruling-13's wording, or whether the diagnostic needs to
be re-run with a fixed driver to actually reach K=5, is his call - not asserted either way by
this document.

## Does NOT claim

- End-to-end detection blackout duration (B is a lower bound on legacy's, closer to spark's).
- Behavior at fleet scale, on non-Windows platforms, or under any mutation kind other than the
  two triggers exercised here.
- That the Phase A "as-is" catalogue matches the ORIGINAL campaign's leftover state exactly -
  this session's own `ensure` call added 61 always-passing rules to it before Phase A ran,
  disclosed above.
- That the recurring "ambient storm" observed passively in Phase A is mechanistically
  identical to #3990's own described trigger (a rule mutation amplified via heartbeat
  reconcile) - plausibly related (both involve reconcile-driven pushes), not confirmed either
  way.
- **A queueing/pile-up effect under repeated triggers - this was claimed in an earlier draft
  of this document and is explicitly retracted above, with the evidence that disproved it.**
  Do not cite this document as evidence of such an effect.
- A neutrality finding in the sense the original CH-5-UAT ruling text explicitly disclaimed
  ("NOT a finding that #3990 is neutral ... in effect, only in mechanism") - the sample sizes
  actually obtained are too small to support even the limited comparison this document set out
  to make, let alone a broader one.
- A root cause for the residual driver detection-logic gap in Phase B/B2's T0/T1 matching -
  not diagnosed in this session, and not a product-code question (the bug is in
  `fullsync_blackout_diag.py`, not in anything under `agents/` or `server/`).
- The N=5652 legacy-only ~6-minute silence observed in Phase A (see that section) as anything
  more than a single, unreplicated, uncharacterized observation - it was not investigated
  further and no connection to any other finding in this document is established.

## Teardown

`teardown-cohort` removed both baselines (`blackout-cohort`, `blackout-trigger`, fleet
reconciled on each delete) and all cohort/trigger rules; ten additional `blackout-hbr-*` rules
left over from the Phase B2 id-collision correction (ids 04-10, 101, 110, 120) were deleted
individually since the driver's own teardown loop only covers ids 1-3 by default. A final
inventory confirmed exactly one rule (`dgrhp-drift-test-file`) and one baseline (`DGRHP File
Drift Test`, `0c953d48d94c`, deployed) remain - the untouched protected artifacts, and nothing
else. Scratch files/registry keys under `C:\rigA\blackout-scratch` and
`HKCU:\SOFTWARE\YuzuBlackout` were removed by the same teardown call. The agent was left
running on **spark** (the pre-run default, no `--spark-disable`, launched via the box's own
unmodified `run_agent2.ps1` with `--log-file`) - PID confirmed alive at teardown time. devrig2
is left at `origin/dev@65f2938156a19` + the flip one-liner (not reverted) - this is now the
rig's new baseline state, recorded here rather than restored to the pre-diagnostic
`7c3c7d3fa`-era build. `run_agent_legacy.ps1` (a scratch copy used for the legacy-backend
phases) is left on-box alongside the pre-existing scratch scripts; not committed.
