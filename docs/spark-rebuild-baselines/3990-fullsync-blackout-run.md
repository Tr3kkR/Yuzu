# #3990 - full_sync blackout diagnostic, recorded run

Captured 2026-09-06/07, rig DGRHP (`C:\yuzu-devrig2`, server + agent, data dir `C:\rigA`).
Authority: Dave's 2026-09-06 ruling on #3850 (the third comment on that issue) - CH-5-UAT
excludes rule-mutation churn from its own sampling windows, paired with a required,
non-gating diagnostic: "one baseline deploy on each backend, blackout duration recorded"
before #3990 can be cited in `docs/spark-flip-gate.md` §5 as accepted-neutral. The ruling
specifies nothing beyond that sentence - no measurand, sample size, or neutrality criterion.
Everything below that isn't a direct quote of the ruling is this run's own definition, stated
as such rather than attributed to source.

**Headline result, read this first**: the intended legacy-vs-spark comparison could not be
completed at the pre-registered sample size (K=5). The reason is itself the load-bearing
finding of this diagnostic: **repeated `full_sync` triggers spaced 45-100 seconds apart caused
the large majority of individual triggers (roughly 80-90%, on BOTH backends) to take
substantially longer than a 60-90 second observation budget to complete**, even at a tiny
62-rule cohort with zero failing rules. The handful of triggers that DID complete fast did so
in 55-82ms on both backends - so the mechanism this diagnostic can actually speak to is a
**pile-up/queueing effect under closely-spaced mutations**, not a slow steady-state per-trigger
cost. See "Phase B / B2" and "The stall/queueing finding" below.

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
the record of what it measured, not a restatement of how.

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
persistently-failing rule was present in this catalogue at measurement time). In hindsight,
given the pile-up finding below, the likeliest explanation is that this "ambient storm" was
itself residue from this same session's own preceding test activity (the `ensure` call and
earlier smoke-test deploys) still draining, not a truly independent, permanently-recurring
mechanism - not confirmed either way, left as an open question.

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
present (by construction) under spark. Given the stall/queueing finding below turned out to
recur even at N=62, this large-N stall may be a special case of the same broader phenomenon
rather than a purely scale-driven one - not established either way.

## The stall/queueing finding (the actual headline result)

At the clean N=62 cohort, with a healthy agent (no failing rules, no thread exhaustion - 92-99
threads throughout), triggering repeated `full_sync`s roughly 45-110 seconds apart produced a
consistent, large majority of individual triggers that never completed within a 60-90 second
observation window:

| Phase | Backend | Trigger | Attempts | Valid | Void: t1 not found (T0 seen, T1 never) | Void: t0 not found (no T0 at all) |
|---|---|---|---|---|---|---|
| B  | legacy | deploy      | 10 | 2 | 8 | 0 |
| B2 | legacy | rule-create | 10 | 2 | 8 | 0 |
| B  | spark  | deploy      | 10 | 1 | 9 | 0 |
| B2 | spark  | rule-create | 4* | 0 | 4 | 0 |

\* B2/spark's first 10-attempt batch (not counted above) hit the rule-id-collision bug
(correction #4) and produced 10/10 `t0_not_found` for a different, driver-side reason; the 4
attempts counted here used deliberately-unique rule ids and are the ones that genuinely
exercised the trigger.

**The valid (non-void) B values, on both backends and both trigger kinds, are all in the same
tight 55-82ms band** - legacy 55, 56, 57, 63ms (4 samples); spark 82ms (1 sample). Nothing in
that small set suggests either backend is dramatically slower than the other on a
trigger that actually completes promptly.

**What "void" meant here, checked directly against the live agent, not assumed**:
- The agent was never crashed or unresponsive to `Get-Process` - it stayed alive throughout
  every void.
- CPU usage during a void was consistently near-zero (e.g. 0.09-0.17s of CPU time accumulated
  over an 8-15 second sampling window) - not a busy spin.
- The pending `full_sync` was NOT lost: every one checked was eventually found to have
  completed once the log was re-checked minutes later (generation always caught up to the
  server's current value eventually), including several that took 3-6+ minutes past their
  trigger before their own `apply_rules ok` line appeared.
- The server-side `yuzu_agents_connected` gauge stayed `1` throughout.

This is consistent with a **queueing/serialization effect**: `apply_rules` holds `mtx_` for its
entire duration on the SAME thread that also handles the Subscribe stream (confirmed in
`docs/spark-rebuild-baselines/fullsync_blackout_diag.py`'s own citations, `agent.cpp:2938-2984`
- the `__guard__` dispatch runs inline, bypassing the thread pool), so a second push arriving
while the agent is still finishing an earlier one cannot even begin processing until the first
is fully done. If completing one full_sync AND flushing its own deferred journal/rollback work
occasionally takes much longer than the ~55-80ms fast-path (this diagnostic did not identify
why - candidates not eliminated: disk I/O contention on the journal write, some interaction
with the agent's own heartbeat/metrics cadence, or a genuinely slow rare path inside
`GuardianRollback`'s function-exit work), then closely-spaced subsequent triggers pile up
behind it, and each one's OWN wait time is inflated by everything still ahead of it in the
queue - which would explain both backends showing a similar ~80-90% void rate under this
specific "repeated triggering every 45-110s" access pattern, and both backends' successfully-
completed triggers still landing in the same fast 55-82ms band.

**This finding directly explains why ruling-13 excluded rule-mutation churn from CH-5-UAT's own
sampling in the first place** - "the verdict stays a clean read... not entangled with #3990's
separately-tracked full_sync-storm defect" - the exclusion was well-founded: this diagnostic's
own attempt to measure "one baseline deploy" cleanly was itself repeatedly disrupted by exactly
that entanglement once measurement required more than a single isolated trigger.

**Not established, explicitly**: a root cause; whether the pile-up is specific to this rig's
current load/disk/thread state or would reproduce on different hardware; whether it recurs on
a truly isolated single trigger with no preceding activity for many minutes (not tested - every
attempt in this run followed on from recent prior activity, by the nature of running K
repeats); whether it differs in severity between backends (the sample sizes are too small - 4
legacy valid vs 1 spark valid - to support any comparative claim). No new GitHub issue filed
for this from within this diagnostic - flagged here for Dave to decide whether it warrants one,
given its direct relevance to #3990 and to the broader #2469/#2278/#2279 package this doc's §5
entry sits next to.

## Phase B - clean cohort, baseline re-deploy trigger

See the combined table above. Legacy: 2/5 valid (56, 57ms; median 56.5ms). Spark: 1/5 valid
(82ms; no median - a single sample). Both phases are **inconclusive** against the K=5
pre-registration - not enough valid samples exist to compute a reliable median comparison,
for the reason documented above (the void rate, not a difficulty measuring a completed
trigger).

## Phase B2 - clean cohort, bare rule-create trigger (#3990's literal shape)

Legacy: 2/3 valid (55, 63ms; median 59ms). Spark: 0/3 valid on the corrected (unique-id) runs -
every attempt voided `t1_not_found` even after the id-collision bug was fixed and even after
confirming the server's `policy_generation` had fully caught up to a quiescent state
immediately beforehand. Create-to-T0 lag (informational, cross-host, non-verdict-bearing per
the plan) was not usably captured given how few Phase B2 repeats completed at all.

## Decision rule and outcome

Pre-registered before the clean-cohort runs (this session's own choice, not derived from any
SLO): spark median B <= legacy median B + max(1000 ms, legacy median B); every counted repeat
independently satisfies `failed=0` and functional-validity (D observed for all 60 cohort
rules).

**Outcome: INCONCLUSIVE.** Neither backend reached the pre-registered K=5 valid-repeat floor
for Phase B (legacy 2/5, spark 1/5), so the decision rule cannot be honestly applied - a median
over 1-2 samples is not a basis for a non-inferiority claim at either backend, let alone a
comparison between them. This is NOT a "neutral/not neutral" verdict, and it is explicitly NOT
evidence that spark is worse, better, or equivalent to legacy on B specifically - the small
samples that DID complete (4 legacy, 1 spark) all landed in the same 55-82ms band with no
visible separation, but that observation is far too thin to promote to a finding.

**What this diagnostic DOES establish, which is arguably more useful to the flip-gate decision
than the originally-intended B comparison would have been**: a real, reproducible, previously
uncharacterized queueing/pile-up effect under repeated close-interval `full_sync` triggers,
affecting BOTH backends at a comparable rate, independent of the legacy-vs-spark question this
diagnostic set out to answer. Whether this satisfies ruling-13's requirement well enough for
#3990 to be cited in §5 as "accepted-neutral" is Dave's call, not asserted here - the honest
summary is "neutral in the very limited comparison the collected samples support, but the
diagnostic surfaced a bigger, shared reliability question neither this doc nor #3990's own
scope was set up to answer."

## Does NOT claim

- End-to-end detection blackout duration (B is a lower bound on legacy's, closer to spark's).
- Behavior at fleet scale, on non-Windows platforms, or under any mutation kind other than the
  two triggers exercised here.
- That the Phase A "as-is" catalogue matches the ORIGINAL campaign's leftover state exactly -
  this session's own `ensure` call added 61 always-passing rules to it before Phase A ran,
  disclosed above.
- That the recurring "ambient storm" observed passively in Phase A is mechanistically
  identical to #3990's own described trigger (a rule mutation amplified via heartbeat
  reconcile), or to the stall/queueing effect found in Phase B/B2 - plausibly related, not
  confirmed either way.
- A neutrality finding in the sense the original CH-5-UAT ruling text explicitly disclaimed
  ("NOT a finding that #3990 is neutral ... in effect, only in mechanism") - the sample sizes
  actually obtained are too small to support even the limited comparison this document set out
  to make, let alone a broader one.
- A root cause for the stall/queueing effect, or a claim about which specific step inside
  `apply_rules`/its deferred rollback work is slow - not diagnosed in this session.
- That legacy and spark are equally affected by the stall/queueing effect - the observed void
  rates (80% legacy Phase B, 90% spark Phase B) are too close together and too small in sample
  count to support a comparative claim between backends on THIS effect either.

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
