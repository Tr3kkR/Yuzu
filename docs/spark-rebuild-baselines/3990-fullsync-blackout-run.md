# #3990 - full_sync blackout diagnostic, recorded run

Captured 2026-09-06/07, rig DGRHP (`C:\yuzu-devrig2`, server + agent, data dir `C:\rigA`).
Authority: Dave's 2026-09-06 ruling on #3850 (the third comment on that issue) - CH-5-UAT
excludes rule-mutation churn from its own sampling windows, paired with a required,
non-gating diagnostic: "one baseline deploy on each backend, blackout duration recorded"
before #3990 can be cited in `docs/spark-flip-gate.md` §5 as accepted-neutral. The ruling
specifies nothing beyond that sentence - no measurand, sample size, or neutrality criterion.
Everything below that isn't a direct quote of the ruling is this run's own definition, stated
as such rather than attributed to source.

**Headline result, read this first, CORRECTED TWICE since this doc's own first draft** (see
"Retraction" below the fold in "The driver's T1-detection gap" for the first correction, and
"Decision rule and outcome" for the second - both kept in-doc rather than silently edited
away, since each wrong version was briefly the working conclusion): the 2026-09-06/07 attempt
could not complete the intended legacy-vs-spark comparison at the pre-registered sample size.
The reason was a **flush-lag gap in the agent's own `--log-file` output** (confirmed against
the vendored spdlog source - see "T1 detection: the real root cause" below), not a stall in
the system under test: correlating EVERY `full_sync` trigger in that session's complete agent
log against its own completion line showed all 84 real triggers that ran to completion did so
in **8.3 seconds or less**, most under 100ms at the clean 62-rule cohort - but the log's own
bytes could sit unflushed on disk for up to ~108s before any external reader, including the
diagnostic's own polling, could see them, causing most clean-cohort attempts to time out
waiting for a completion that had, in truth, already happened. A 2026-09-07 re-run with a
widened polling timeout collected enough samples to compute the intended B comparison (both
backends land within the predeclared margin) - **but a SEPARATE, unrelated gap (a
never-wired-up functional-validity check in the driver, plus 2 of 5 targeted Windows services
having an unstable running state on this rig) means the samples do not satisfy the diagnostic's
own pre-registered decision rule.** The FORMAL outcome is therefore still **inconclusive /
invalid by cohort design**, not a pass - see "Decision rule and outcome" for the full,
three-part breakdown of what is and isn't established.

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
or polling logic was never identified in THIS session - **root-caused the following day, see
"T1 detection: the real root cause" below.**

**The valid (non-void) B values, on both backends and both trigger kinds, are all in the same
tight 55-82ms band** - legacy 55, 56, 57, 63ms (4 samples); spark 82ms (1 sample). This is
consistent with, not evidence against, the "no real delay" conclusion above: a healthy trigger
was always fast, on both backends, every time one was correctly detected.

## T1 detection: the real root cause, and the 2026-09-07 re-run reaching K=5

Picked up the next day per Dave's instruction ("fix the driver bug and re-run to reach K=5").
Root-caused by deliberate live reproduction against the running rig, not by further log
archaeology: triggered one Phase B repeat, watched the driver's own `_fetch_window` poll loop
return the IDENTICAL 93 matched events (the cumulative window contents, not new lines) for 16
consecutive polls across 61 seconds, then checked the raw agent log directly (independent of
the driver, two fresh SSH calls 5s apart) and found the file's `Length` and `LastWriteTime`
genuinely frozen for the same window - not a client-side caching artifact, the file had not
grown. **Correction**: an earlier version of this paragraph also called the eventual burst "~15
lines," conflating it with the 93-event window total above without saying what either number
actually counted - the 93 is the poll loop's cumulative matched-event count across the whole
search window; the smaller figure was this one attempt's own new arm/apply lines within that
burst, not independently re-verified against the raw log before this correction, and is left
out rather than restated as a precise number it wasn't checked to be. What IS directly
confirmed: ~2 minutes after the freeze, a burst of new lines appeared at once, ending in
`apply_rules ok`, every line in the burst timestamped within
the SAME real-world second (`06:46:29.6xx`) despite arriving on disk roughly two minutes late.

**Root cause for the flush lag ITSELF, confirmed against the vendored spdlog source, not
assumed**: `agents/core/src/main.cpp`'s `--log-file` sink setup (`:651-669`) never calls
`logger->flush_on(...)`. spdlog's own default `flush_level_` is `level::off`
(`spdlog/logger.h:311`), and `should_flush_()` (`spdlog/logger-inl.h:166-168`) only forces a
sink flush when a message's level meets that (never-raised) threshold - so nothing in this
process ever asks the sink to flush explicitly. A log line's embedded timestamp is recorded at
message-construction time (accurate), but the underlying bytes can sit in the sink's buffered
`ofstream` for an unpredictable period - observed live anywhere from ~2 seconds to ~108
seconds under this rig's ambient log volume - before becoming visible to ANY external reader,
this diagnostic's own polling included.

**Correction (Sol/`gpt-5.6-sol` opine, 2026-09-07)**: "this was never a bug in the driver's
window/timestamp-matching logic" and "only its timeout was too short" overstate what was
actually established. The flush-lag mechanism is real and is a strong explanation for MANY of
the residual `t1_not_found` voids - but the committed evidence does not prove it explains
EVERY historical one: the original run's `t0_not_found` batch on Phase B2/spark had its own,
separately-confirmed cause (the rule-id collision, correction #4, which meant there was
genuinely no trigger to find, nothing to do with flushing); and even after widening the
timeout to 240s, 3 of 8 legacy Phase B attempts in the re-run still voided `t1_not_found` -
consistent with flush lag occasionally exceeding 240s, but not independently confirmed to be
that specific cause each time (the underlying complete-log correlation that grounded the
retraction above was itself a one-time analysis of the FIRST attempt's log, not repeated for
every void in the re-run). Read "flush lag" as the established, dominant, and most likely
explanation for the residual gap - not as a proven, exhaustively-attributed one.

**Fix - more precisely, a bounded workaround for THIS one-time measurement, not a general
fix**: widened `ROOT_CAUSED_T0_TIMEOUT`/`ROOT_CAUSED_T1_TIMEOUT` to 240s each. No change to
the search/matching logic itself. Verified with a small 3-repeat controlled test before
trusting it for the full re-run - **2 of those 3 STILL voided `t1_not_found` even at 240s**,
a roughly 33% hit rate on that pilot, versus 5/8 (63%) on the actual legacy Phase B re-run;
neither rate is "comfortably" anything, and 240s does not reliably outlast the phenomenon it's
compensating for - it only outlasted it often enough, within a generous 10-attempt cap, to
reach the sample counts this run needed. Deliberately NOT changing the agent daemon's own
flush policy for this diagnostic - that would alter the executable being measured and risk
perturbing a sub-100ms measurand; unlike the functional-validity precondition below (a gap in
THIS diagnostic's own driver, fair game to fix and re-run), the flush policy lives in the
agent binary under test, and touching it here would invalidate the very B numbers this run
exists to produce. The underlying observability gap (no flush policy makes `--log-file`
unreliable for any near-real-time external tailing, not just this driver) is real and worth
its own product fix, but is explicitly OUT OF SCOPE for this diagnostic to carry - flagged in
"Open, needs Dave" below rather than left as an implied someone-else's-problem.

**Re-run results, 2026-09-07, same rig/build/cohort as the retracted run (agent untouched
since - `0.13.1+7899 (65f2938156a19)`, spark flip one-liner unchanged), fresh `ensure` after
the previous run's teardown**:

| Phase | Backend | Attempts | Valid | B min (ms) | B median (ms) | B max (ms) |
|---|---|---|---|---|---|---|
| B  | spark  | 5 | 5/5 | 73.0 | 77.0 | 91.0 |
| B  | legacy | 8 | 5/5 | 50.0 | 53.0 | 56.0 |
| B2 | spark  | 3 | 3/3 | 69.0 | 74.0 | 83.0 |
| B2 | legacy | 3 | 3/3 | 65.0 | 66.0 | 72.0 |

Both backends reached the driver's own SAMPLE-COUNT floor (K=5 for Phase B, K=3 for Phase B2)
on the first attempt at the fix - `failed=0`, `applied=total=62`, `n_arm_lines=62` on every
single counted repeat, both backends, every phase. **Correction, found on a second review of
this doc (Sol/`gpt-5.6-sol` opine, 2026-09-07) and confirmed by reading the driver's own
code**: "reached the pre-registered floor" overclaims what the code actually enforces.
`fullsync_blackout_diag.py`'s `run_repeat()` computes `functional_valid` and returns it in
every result row, but `cmd_run()`'s counting loop only checks `void_reason` - `functional_valid`
is written to the output and never read by anything that decides whether a repeat counts. So
the "5/5"/"3/3" tallies below only enforce `failed=0`/`applied=total`/arm-count/push-counter
matching - NOT the functional-validity precondition the pre-registered rule (below) also
requires. See "Decision rule and outcome" for what this means for the actual outcome; treat
every "N/N valid" claim in this section as "N/N by the driver's partial check," not by the
full pre-registered rule.

Raw per-repeat data for this re-run is appended to `fullsync-blackout-results.jsonl` (the
retracted run's 73 rows, then this re-run's 19 rows - rows carry no `run_id`/date field, and
the field SCHEMA does not reliably distinguish them either, since the retracted run's own later
Phase B/B2 rows already used the same fields; the correct, verified distinguisher is the `t0`
timestamp - the retracted run's valid rows all fall in `2026-09-06T21:47` to `2026-09-07T00:16`;
this re-run's valid rows all fall in `2026-09-07T07:12` to `08:22`, with no overlap; the
retracted run's rows, appended first, are clearly the earlier, smaller-sample block by position
in the file). **Also confirmed by the same review**: `cmd_report`'s grouping key is
`(label, backend, phase)` only - both runs used `label="clean"` for Phase B/B2, so re-running
`report` against the combined committed file would silently pool the retracted run's few rows
together with this re-run's, and would NOT reproduce the medians in this doc. Do not run
`report` against the combined file and trust its output; use the by-hand `t0`-range split above,
or filter the file first.

**A second, separate gap found while checking functional-validity (D), not a backend defect
either, but the claim below was itself corrected on review**: `functional_valid` came back
`False` on all 16 valid (by the partial check above) repeats. The ORIGINAL version of this
paragraph claimed all five of `blackout-svc-01/02/04/05/15` were "genuinely Stopped ... in
every repeat." **That is only true for THREE of the five** - checked directly against the raw
per-repeat `compliant_restored_ms_by_rule` data, not re-asserted: `svc-01` and `svc-02` and
`svc-15` show `not_observed` in all 16/16 repeats (consistent with a target that is simply
never in the asserted state); `svc-04` shows `not_observed` in 14/16 (observed compliant in
repeats `B/spark#3`, `B/spark#5`); `svc-05` shows `not_observed` in 11/16 (observed compliant
in 5 of 16, spread across both backends). These two rules' target services (per
`generate_resgate_load.py`'s `SERVICE_NAMES` list, watching Windows services **BITS** and
**wuauserv** for `service-running`) were evidently started and stopped by something else
during the run - Windows' own background servicing/update activity is the obvious candidate,
not confirmed - not held in one fixed state throughout. The blanket claim that these rules
"can never reach `guard.compliant` on ANY backend, at ANY full_sync speed" is true for
`svc-01/02/15` and NOT established for `svc-04/05`, which sometimes did. This does not change
which backend was affected (both, comparably, per repeat-count) but it does mean the
functional-validity gap is smaller and less structurally fixed than first claimed - a cohort
using a service list confirmed running AND held stable for the run's duration would likely
still leave `svc-01/02/15` failing, but might not leave `svc-04/05` failing every time. B
itself is unaffected either way - it measures the `apply_rules` lock window, not rule
compliance state, and every repeat's `applied=total=62`/`n_arm_lines=62` confirms the re-arm
itself was normal for all 20 service rules regardless of their eventual compliance state.
**The pre-registered decision rule's functional-validity precondition is not met by any of the
16 repeats** - for `svc-01/02/15`, for a reason unrelated to what B measures; for `svc-04/05`,
for a reason that is not yet fully characterized. Reported in "Decision rule and outcome" below
as what it actually is: an unmet precondition, not a relaxable technicality.

## Phase B - clean cohort, baseline re-deploy trigger

**2026-09-06/07 attempt (retracted-void-rate run)**: legacy 2/5 valid (56, 57ms; median
56.5ms), spark 1/5 valid (82ms; no median - a single sample) - inconclusive against the K=5
floor, for the driver flush-lag reason documented above.

**2026-09-07 re-run (fixed flush-timeout, see "T1 detection: the real root cause" above)**:
**legacy 5/5 valid in 8 attempts** (50, 50, 53, 54, 56ms; median 53ms), **spark 5/5 valid in 5
attempts, first try** (73, 76, 77, 80, 91ms; median 77ms) - by the driver's partial check
(`failed=0`/`applied=total`/arm-count/push-counter). `n_arm_lines=62` on every one of the 10
counted repeats too. **None of these 10 also satisfy functional-validity** - see "Decision
rule and outcome": the pre-registered K=5 floor, taken in full, was NOT reached.

## Phase B2 - clean cohort, bare rule-create trigger (#3990's literal shape)

**2026-09-06/07 attempt**: legacy 2/3 valid (55, 63ms; median 59ms), spark 0/3 valid on the
corrected (unique-id) runs - inconclusive against the K=3 floor, same driver flush-lag cause.

**2026-09-07 re-run**: **legacy 3/3 valid in 3 attempts, first try** (65, 66, 72ms; median
66ms), **spark 3/3 valid in 3 attempts, first try** (69, 74, 83ms; median 74ms) - by the
driver's partial check, same caveat as Phase B above; `n_arm_lines=62` on every one of the 6
counted repeats too, and none of the 6 also satisfy functional-validity. Create-to-T0 lag
(informational, cross-host, non-verdict-bearing per the plan) was not specifically re-examined
in the re-run - not load-bearing for the decision rule either way.

## Decision rule and outcome

Pre-registered before the clean-cohort runs (this session's own choice, not derived from any
SLO): spark median B <= legacy median B + max(1000 ms, legacy median B); every counted repeat
independently satisfies `failed=0` and functional-validity (D observed for all 60 cohort
rules).

**2026-09-06/07: Outcome INCONCLUSIVE** - neither backend reached the K=5 floor (driver flush
lag, since root-caused and fixed; see above). Superseded by the 2026-09-07 re-run below.

**2026-09-07 re-run: both backends reached the driver's own sample-count floor** (Phase B:
legacy 5/5, spark 5/5; Phase B2: legacy 3/3, spark 3/3, all by the partial check described
above - `failed=0`/`applied=total`/arm-count/push-counter only, NOT functional-validity, which
the code never actually gates on). The numeric B comparison, computed from those samples:

| | legacy median | spark median | margin (max(1000, legacy median)) | threshold | numeric result |
|---|---|---|---|---|---|
| B  | 53.0 ms | 77.0 ms | 1000 ms | 1053.0 ms | 77.0 <= 1053.0 -> within margin |
| B2 | 66.0 ms | 74.0 ms | 1000 ms | 1066.0 ms | 74.0 <= 1066.0 -> within margin |

**Second correction to this section (Sol/`gpt-5.6-sol` opine, 2026-09-07, confirmed against
the code and data before accepting it)**: an earlier version of this section treated "within
margin" as the outcome, framing the unmet functional-validity precondition as a relaxable
judgment call. That is procedurally unsound, for two reasons found on review, not just one:

1. **Pre-registration exists specifically to prevent exactly this** - deciding, after seeing
   data that looks fine, that a precondition set in advance doesn't really need to apply this
   time. A well-argued relaxation is still a relaxation decided post hoc; writing it down
   transparently doesn't restore its status as a pre-registered pass.
2. **The "5/5"/"3/3" counts themselves never enforced functional-validity in the first place**
   - not because it was judged unmeetable and consciously waived at decision time, but because
   `cmd_run()`'s own counting loop only checks `void_reason`, and `void_reason` is never set
   from `functional_valid`. So even setting aside point 1, the correct count of repeats
   satisfying the FULL pre-registered rule (as written: `failed=0` AND functional-validity) is
   **0 of 16**, not 5/5 or 3/3 under any reading.

**Correct statement of the outcome, in three separately-labeled parts, per that review**:
- **Numeric observation** (informational, not a decision): the B values that were collected
  land within the predeclared margin on both phases, table above.
- **Formal pre-registered decision**: **INCONCLUSIVE / INVALID BY COHORT DESIGN.** Zero repeats
  satisfy the rule as written. This is not the same failure mode as the 2026-09-06/07 attempt
  (which failed to collect enough samples at all) - samples exist and are usable as
  observations, but none of them satisfy the full pre-registered criteria for a decision.
- **Accepted-neutral status for §5**: **not established by this document.** Citing #3990 as
  accepted-neutral on the strength of the numeric observation alone would require Dave to
  explicitly waive the functional-validity precondition as a recorded protocol deviation -
  that is his call to make, not a conclusion this document reaches on its own.

**Path to an actual pre-registered pass, not just a relaxation**: re-run Phase B/B2 with a
cohort whose service-watch rules target services confirmed running and held stable for the
whole run (closes the gap for `svc-01/02/15` definitively; `svc-04/05`'s intermittent-service
behavior, per the correction above, may resolve on its own with a better-chosen or
externally-pinned service, or may need one more iteration to confirm). The measurand, cohort
size, purge/ensure mechanics, and driver timeout are otherwise proven to work as of this
re-run - only the functional-validity wiring (a `cmd_run()` fix, not attempted here) and the
service selection need to change for a clean pass.

**Open, needs Dave**: two separate decisions this document deliberately does not make for
itself. (1) Whether to accept the pre-registered rule's failure as final, or fix `cmd_run()`'s
functional-validity wiring and re-run with better-behaved service targets for a genuine pass
(previous paragraph). (2) Whether the agent `--log-file` flush-policy gap (no `flush_on` call,
`spdlog` default `flush_level_=off`, `main.cpp`) should be filed as its own product issue -
it's real, reproducible, and affects any external near-real-time log tailing, not just this
diagnostic's driver, but fixing it here was deliberately out of scope (it would alter the
executable under measurement). Not filed yet; this document is not the place to decide that on
its own.

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
  ("NOT a finding that #3990 is neutral ... in effect, only in mechanism") - even after the
  2026-09-07 re-run collected the intended sample counts, the pre-registered decision rule's
  own functional-validity precondition is not met by any repeat (see "Decision rule and
  outcome"), so the FORMAL outcome remains inconclusive/invalid by cohort design, not a pass.
- That the agent's `--log-file` flush-lag finding (up to ~108s observed) has been measured
  systematically, characterized as a distribution, fully attributed as the SOLE cause of every
  historical void, or reproduced on a differently-loaded rig - one deliberate live reproduction
  plus the 2026-09-07 re-run's attempt/void pattern are the only evidence; no minimum/maximum/
  typical lag is established beyond what was observed, and 3 of 8 legacy Phase B attempts still
  voided even after the timeout was widened to 240s.
- That the "5/5"/"3/3" sample counts in this document represent a pass against the
  pre-registered decision rule - they do not; they represent the driver's own PARTIAL check
  (`failed=0`/`applied=total`/arm-count/push-counter only), because `cmd_run()` never wires
  `functional_valid` into its counting logic (confirmed by reading the code, not assumed).
- That `blackout-svc-01/02/04/05/15` are all equally and consistently non-compliant - only
  `svc-01/02/15` are (16/16 repeats); `svc-04/05` are intermittent (14/16 and 11/16), meaning
  something external to this diagnostic started and stopped their target services during the
  run - not characterized further here.
- That `cmd_report`'s output can be trusted if re-run against the combined
  `fullsync-blackout-results.jsonl` as committed - its grouping key does not distinguish the
  retracted run's rows from this re-run's, and would silently pool both under `label="clean"`.
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

**2026-09-07 re-run teardown**: same `teardown-cohort` call (baselines + cohort/trigger rules,
no `blackout-hbr-*` collision this time - each backend's B2 `hbr-01..03` ids were explicitly
deleted before switching backends, confirmed via a fresh `inventory` beforehand that no stray
ids survived the previous run's teardown). Post-teardown `inventory`: `total_rules=1`,
`riga_rules=0`, `riga_baselines=0`, both protected artifacts present - re-verified directly,
not assumed. Agent stopped and relaunched on **spark** (no `--spark-disable`, unmodified
`run_agent2.ps1`, `--log-file`) via WMI Create; confirmed alive, responding, and the
`detection backend = spark` boot line present (PID 21788). `run_agent_legacy.ps1` (new this
round, adds `--spark-disable` to the existing script) left on-box, not committed. Server and
Postgres tunnel untouched throughout this session.
