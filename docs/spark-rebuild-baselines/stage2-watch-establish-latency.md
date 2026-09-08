# Stage 2 - watch-establishment latency (PR-A harness, DGRHP run PENDING)

Authority: `~/.claude/plans/let-s-deliver-this-claude-plans-spark-20-shiny-jellyfish.md`
("#2012 + #3840 - bound File/Registry/Service watch establishment off the per-type
lock"), "Latency characterization harness (PR-A; produces PR-B's constants)" section.
Companion doc structure: `f11-flood-measurement-run.md` (same baselines directory).

## Status: PENDING - no DGRHP run has been performed yet

This branch (PR-A, `feat/2012-3840-detached-call-f3`) adds the harness itself -
`tests/unit/test_spark_mechanism.cpp`, cases tagged
`[spark][mechanism][windows][latency][establish]`, env-gated on
`YUZU_SPARK_ESTABLISH_BENCH=1` - but was authored in a session with **no Windows
toolchain or host available**. No case in this harness has been compiled or run on a
real Windows box. Every table below is a placeholder awaiting the first DGRHP pass;
do not treat any number that might later appear here as final until this note is
removed and replaced with a real run's output (same discipline as
`f11-flood-measurement-run.md`'s "Captured <date>" header).

**Do not derive PR-B's D constants from anything but a real run of this harness.**
Nothing in this document today is a measurement.

## What the harness measures, and why raw calls (not the mechanism)

The harness measures the RAW Win32 call sequences directly - CreateEventW /
CreateThreadpoolWait / RegOpenKeyExW / RegNotifyChangeKeyValue / SetThreadpoolWait
for Registry; OpenSCManagerW / OpenServiceW / NotifyServiceStatusChangeW for
Service; `std::filesystem::is_directory` / CreateFileW for File - NOT through
`spark_file.cpp` / `spark_registry.cpp` / `spark_service.cpp`, which do not yet have
the off-lock restructuring PR-B will add. This is deliberate, not a shortcut: D must
be chosen from TODAY's raw call cost, before a mechanism hides it behind a bounded
worker. Measuring through the mechanism is only possible once PR-B lands, by which
point D would already be baked into the code the measurement was supposed to inform.

Every Win32 call shape in the harness is modeled directly on the already-shipped
usage in the three mechanism files (cited per case in the test file itself), not
invented - but "modeled on real usage" is not the same as "verified to compile and
run on Windows." That verification is exactly what the pending DGRHP pass is for.

## Cases (see the test file for the authoritative list; summarized here)

| Case | What | Samples |
|---|---|---|
| R1 | Registry, target present, default pool | n=200, per-call split |
| R2 | Registry, target absent, ancestor walk depth 6, default pool | n=200, per-call + per-level |
| R3 | R1 sequence under hive load (200 churn watches, private pool) | n=200 |
| R4 | R2 sequence under hive load | n=200 |
| R5 | `WaitForThreadpoolWaitCallbacks(TRUE)` drain, idle vs. a 50ms in-flight callback (started-handshake before timing; a not-started-within-1s count is reported separately) | n=200 idle / n=200 in-flight |
| R6 | `REG_NOTIFY_THREAD_AGNOSTIC` correctness control - positive (asserted) + negative (before-write/after-write, distinguishing a thread-exit artifact from a real write) | 1 each, characterization not a stats sample |
| S1 | `OpenSCManagerW(SC_MANAGER_CONNECT)` + close | n=200 |
| S2 | `OpenServiceW` + `NotifyServiceStatusChangeW` across the real service list (`EnumServicesStatusExW`-cycled, `resume` reset before the real call) | n=200, `GetLastError()` captured same-thread |
| S3 | S2's full open+notify sequence under SCM load (two background OpenSCManagerW-churn threads); `resume` reset matches S2 | n=200 |
| F1 | `is_directory` + `CreateFileW(BACKUP\|OVERLAPPED)` sanity, local temp dir | n=200 |
| post-fix-cost | Bulk `SparkEngine::arm()`, TODAY's (pre-PR-B) baseline, one series per mechanism: Registry initial arm (N=200 distinct keys), Registry RE-arm (value-write on all 200, wall-clock to observe all 200 fires), File (N=200 distinct real local dirs), Service (up to N=200, cycling the host's real service list - reports explicitly if the list is shorter than 200, since a wrap makes later arms coalescing re-arms of an already-held key, not fresh arms; arm failures skipped and excluded from the timing series) | N=200 per series, wall-clock total + per-op split |

## D derivation formula (to apply once real numbers exist)

Per the plan: `D = max(round_up_50ms(4 x p99_worst), floor)`, ceiling 500ms (File
250ms / Registry / Service - per-type queue-depth x D must stay inside Guardian's
5000ms `backend_op_deadline`, `agents/core/src/guardian_spark_runtime.hpp:198`).
**If 4 x p99 exceeds the ceiling for any mechanism, STOP and re-think - never clamp
silently.** `p99_worst` means the worst of the idle and under-load runs (R1 vs R3,
R2 vs R4, S1/S2 vs S3), not just the idle baseline.

A later commit on this same branch (PR-A's `spark_detached_call.hpp`) ships a
`kGuardianBackendOpDeadlineMirror` constant + a `spark_deadline_below_guardian_
backend_op()` predicate for PR-B to `static_assert` each derived D constant
against, once these are real numbers.

## Run protocol (once DGRHP is available)

Per the plan's Verification section: 3 runs idle + 3 runs under load. Report only -
never assert these numbers as a gate on the shared Wee Tam CI pool (this harness is
env-gated specifically so it never runs there by default). Record each run's raw
`WARN` output here, then the derived D values, then a summary table matching
`f11-flood-measurement-run.md`'s "Claims" section shape (mechanism-measured facts
vs. arithmetic-derived figures, kept visibly separate).

**Treat a 200-sample p99 as deadline-calibration input, not evidence about cold
boot, a dead network share, or true worst-case latency** (round-3 finding in the
plan above) - any PR-B body or changelog fragment citing a number from this
document must repeat that caveat, not just this document.

## Forward action items

1. Run the harness on DGRHP (idle x3, under load x3); replace this document's
   PENDING status with the real output and derived D values.
2. Re-run the `post-fix-cost` case verbatim once PR-B lands, to get the "after"
   figure the plan's "post-fix fast-path cost" note asks for (today's run here is
   the "before" baseline only).
3. Compile-verify the harness itself on a real Windows toolchain before relying on
   any number it produces - this session could not do so.
