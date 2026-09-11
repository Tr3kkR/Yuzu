# Stage 2 - watch-establishment latency (PR-A harness, DGRHP run CAPTURED 2026-09-09)

Authority: issues #2012 + #3840 ("bound File/Registry/Service watch establishment
off the per-type lock"). Companion doc structure: `f11-flood-measurement-run.md`
(same baselines directory). (Gate 6 compliance finding, PR-A round 5: this line
previously cited a session-local, uncommitted plan file
(`~/.claude/plans/let-s-deliver-this-claude-plans-spark-20-shiny-jellyfish.md`,
"Latency characterization harness (PR-A; produces PR-B's constants)" section) as
sole authority - unresolvable for any reader who isn't the authoring operator,
unlike this sibling doc's own ADR/ruling citation. The plan file still holds the
full design rationale if it's needed and still exists on the authoring machine,
but the tracked issues are the durable reference.)

## Status: CAPTURED 2026-09-09 - DGRHP, first real run

This branch (PR-A, `feat/2012-3840-detached-call-f3`) adds the harness itself -
`tests/unit/test_spark_mechanism.cpp`, cases tagged
`[spark][mechanism][windows][latency][establish]`, env-gated on
`YUZU_SPARK_ESTABLISH_BENCH=1`. It was authored in a session with no Windows
toolchain or host available, and stayed uncompiled through 6 governance passes; that
gap is now closed. **DGRHP** (the standing Windows dev rig, Win11 Pro, MSVC 19.44.35227.0 /
BuildTools 2022): worktree at commit `acd9fd3df` + a T6-comment-only follow-up patch
(#4181 citation), `meson setup -Dcmake_prefix_path=<abs path>/vcpkg_installed/x64-windows
-Dbuild_tests=true`, `meson compile -C build-windows yuzu_agent_tests` - clean, zero
warnings on this file, zero errors anywhere. `meson test` on the full `[spark][mechanism]`
tag: **83 test cases, 3843 assertions, 0 failures**. The `[establish]` subset alone, run
3 times with `YUZU_SPARK_ESTABLISH_BENCH=1` via Catch2's own `--out` file write (piping
through the nested ssh/bash session truncated Catch2's wrapped WARN lines mid-message -
`--out` bypasses that): **11 test cases, 6625 assertions, 0 failures, all 3 runs.**

This closes forward action item 3 from the original PENDING version of this doc
(compile-verify on real Windows hardware) and forward item 1 (the actual DGRHP run).
Item 2 (re-run `post-fix-cost` once PR-B lands, for the "after" figure) remains open.

**Still true, and still binding for anyone citing a number below:** treat every p99
here as deadline-calibration input for the *establishment path's own* healthy-case
cost, not as evidence about cold boot, a dead network share, or a hung call's
worst-case duration - see the caveat restated after the results below.

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
run on Windows." That verification is exactly what the 2026-09-09 DGRHP pass
(Status section above) confirmed.

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

## D derivation formula (applied below against the 2026-09-09 numbers)

Per the plan: `D = max(round_up_50ms(4 x p99_worst), floor)`, ceiling 500ms (File
250ms / Registry / Service - per-type queue-depth x D must stay inside Guardian's
5000ms `backend_op_deadline`, `agents/core/src/guardian_spark_runtime.hpp:198`).
**If 4 x p99 exceeds the ceiling for any mechanism, STOP and re-think - never clamp
silently.** `p99_worst` means the worst of the idle and under-load runs (R1 vs R3,
R2 vs R4, S1/S2 vs S3), not just the idle baseline.

**Aggregation convention (Gate 4 happy-path finding, PR-A round 5; CORRECTED at
the DGRHP pass, 2026-09-09):** this paragraph previously claimed "only R2/R4 emit
a per-sample sequence total." That is only half true. Reading the harness source
(`test_spark_mechanism.cpp:4267-4269`) shows the `t_walk_total` emission
(`warn_establish("R2 registry target-absent depth6", "TOTAL ...", t_walk_total)`)
is a **single call site inside R2's own `TEST_CASE`** - R4 (R2's under-hive-load
counterpart) has no equivalent bracket and never emits a TOTAL. This is a real,
previously-undocumented gap in the harness, not a documentation typo alone - see
the Results section below for what it costs us.

R1/R3/S2/S3 emit only PER-CALL series (t_event, t_wait_create, t_open, t_notify,
t_wait_set for R1/R3; t_open, t_notify for S2/S3) - there is no per-sample
sequence total to take a clean p99 of. Until the harness is extended with one (a
before/after bracket per sample, mirroring R2's own shape - and, separately, R4
needs the SAME bracket added, which it currently lacks entirely), apply this
substitute two-step process wherever the D-derivation formula above calls
for one of these four cases' sequence p99 (docs-writer finding, pass 5 -
tightened to avoid reading as a one-step shortcut that skips the idle-vs-
load max entirely): first, compute EACH of R1/R3/S2/S3's own sequence p99
as the SUM of its per-call p99s; `p99_worst` is then the max of that summed
figure across the idle/under-load pair (R1 vs R3, S1/S2 vs S3), per the
rule above - not the sum used in place of that max. The sum-as-substitute-
for-a-real-sequence-total is statistically conservative (an upper bound,
not an exact one) **only when each summed metric is called once per sample**,
which holds for R1/R3/S2/S3 (a direct open, no walk) but does NOT hold for
R2/R4's `RegOpenKeyExW (per level)` metric (called once per ancestor-walk
level - up to 7 times per sample at depth 6, `n=1400` for `n=200` samples).
Applying the same per-call-sum substitute to R4 would UNDERSTATE its real
per-sample cost, not overstate it - the opposite of this substitute's usual
conservative direction. **Do not apply the substitute to R2 or R4.** R2's
real `t_walk_total` is used directly below; R4's is unmeasured and flagged,
not estimated.

A later commit on this same branch (PR-A's `spark_detached_call.hpp`) ships a
`kGuardianBackendOpDeadlineMirror` constant + a `spark_deadline_below_guardian_
backend_op()` predicate for PR-B to `static_assert` each derived D constant
against, using the real numbers derived below.

## Results (3 runs, DGRHP, 2026-09-09)

All times microseconds unless stated. `p99` below is the WORST of the 3 runs per
metric (conservative - the "never clamp silently" posture applies to which run we
trust, not only to the formula). The per-run raw `WARN` output is committed
alongside this doc at `raw/establish-run{1,2,3}.txt` (unhappy-path Gate 4 finding
- an earlier draft of this doc discarded the raw artifact and relied on the
tables below as the sole record, which meant nothing could re-validate a
transcription against source). Each `raw/` file is every `ESTABLISH ...` line
extracted verbatim from that run's Catch2 `--out` file, with only the console-
wrap line breaks Catch2's own writer inserted mid-message rejoined - no values
altered; the full `--out` file also has ~33k lines of ordinary passing-assertion
output not worth committing.

**Registry, direct-target path (R1 idle / R3 under hive load) - per-call p99, worst of 3 runs:**

| metric | R1 (idle) p99 | R3 (hive load) p99 |
|---|---|---|
| CreateEventW | 4 | 5 |
| CreateThreadpoolWait | 5 | 4 |
| RegOpenKeyExW | 53 | 43 |
| RegNotifyChangeKeyValue | 18 | 17 |
| SetThreadpoolWait | 2 | 3 |
| **sum (substitute sequence-p99)** | **82** | **72** |

`p99_worst` (R1 vs R3) = **82us**. Hive load did **not** inflate direct-target
establishment - R3's sum is slightly lower than R1's, within measurement noise at
this scale. Real, not assumed: stated here because it is the opposite of what
"under load" cases are usually expected to show, and is worth a reader's notice.

**Registry, ancestor-walk path (R2 idle, real `t_walk_total`; R4 under hive load, UNMEASURED):**

| run | R2 TOTAL p99 (INCL. teardown/drain) | R2 TOTAL max |
|---|---|---|
| 1 | 1200 | 1221 |
| 2 | 447 | 504 |
| 3 | 1264 | 1284 |

R2's worst-of-3 p99 = **1264us**, with real run-to-run spread worth noting on its
own (1200 / 447 / 1264 - a 2.8x swing between run 2 and run 3, unremarked until
this pass; not explained here, flagged for whoever next touches this harness).

R2's own per-call series (unhappy-path Gate 4 finding - previously measured but
never surfaced in this doc) puts this spread in context. Worst-of-3 p99 per call:
CreateEventW 4us, CreateThreadpoolWait 6us, RegNotifyChangeKeyValue 25us,
RegOpenKeyExW (per level, up to 7 calls/sample) 13us, SetThreadpoolWait 2us -
summing to **50us**, roughly **4% of the 1264us TOTAL**. The other ~96% is
whatever the TOTAL bracket captures that no per-call metric does - per its own
in-code comment, this bracket is establishment PLUS the unmeasured
teardown/drain step, so that step is the leading suspect, not the walk itself.
This matters for R4: R1-vs-R3's "hive load didn't worsen it" finding was measured
on the direct-target path's per-call components only, never on a teardown/drain
bracket - so it's weaker evidence for R4's TOTAL (which needs the SAME
teardown-dominated bracket R2 has) than it looks at first read. R4 would still
need roughly a 10x jump over R2's 1264us before it could move Registry's D off
the 50ms floor computed in the D derivation section below (see "Why Registry's D
above doesn't wait on R4") - genuinely an open question, not a settled one.
**Forward action item, added here:** give R4 the same `t_walk_total` bracket R2
already has.

**File (F1 - no under-load counterpart in this harness):**

| metric | p99 (worst of 3) |
|---|---|
| is_directory | 67 |
| CreateFileW(BACKUP\|OVERLAPPED) | 47 |
| **sum** | **114** |

**Service, per-key path (S2 idle-ish / S3 under SCM load) - per-call p99, worst of 3:**

| metric | S2 p99 | S3 p99 |
|---|---|---|
| OpenServiceW | 47 | 91 |
| NotifyServiceStatusChangeW | 36 | 99 |
| **sum** | **83** | **190** |

`p99_worst` (S2 vs S3) = **190us**. Unlike Registry, SCM load roughly **doubled**
Service's cost (83 -> 190) - a real asymmetry between the two mechanisms, not
noise at this scale.

**Service, `start()`-path cost (S1 - OpenSCManagerW connect, separate from per-key
establishment, not folded into Service's D below):**

| metric | p99 (worst of 3) |
|---|---|
| OpenSCManagerW | 79 |
| CloseServiceHandle | 45 |

**R5 (drain characterization, not a D input):** idle drain p99=0us (no in-flight
callback to wait on). In-flight drain (a deliberately-parked 50ms callback) p99
across the 3 runs: 48826 / 48872 / 48837us - i.e. **the drain waits essentially the
full callback duration**, as designed. This is the direct, measured cost of the
#2819 (shutdown lock-wedge) / #4181 (same-type reentrant deadlock) mechanism's
*stall* case (an unwatch draining a slow-but-not-cyclic callback) - useful
context for both issues, not a D input itself.

**post-fix-cost (today's pre-PR-B baseline - bulk `SparkEngine::arm()`, N=200/mechanism, worst-of-3 p99):**

| mechanism | p99 | max | n |
|---|---|---|---|
| File | 559 | 825 | 200 |
| Registry | 618 | 623 | 200 |
| Service | 155 | 204 | **199** (one arm excluded/skipped this run - real service list, not a harness defect) |

Re-run verbatim once PR-B lands, per forward item 2.

## D derivation, applied to the results above

`D = max(round_up_50ms(4 x p99_worst), floor)` (floor's numeric value is not
stated in the source plan - PR-B's decision, not asserted here):

- File: `4 x 114us = 456us` -> `round_up_50ms = 50ms`.
- Registry (direct-target path only): `4 x 82us = 328us` -> `round_up_50ms = 50ms`.
  Registry's ancestor-walk path is not included in this number - see below.
- Service: `4 x 190us = 760us` -> `round_up_50ms = 50ms`.

All three land on the 50ms quantum, nowhere near their ceilings (500ms general /
250ms File). **This is a meaningful result, not a null one:** it says healthy-case
establishment is microsecond-scale on this hardware, so 4x p99 buys over 50x
headroom before a HEALTHY call would ever be mistaken for a stalled one - which is
what D is actually for (`wait_take(now+D)` deciding "commit now" vs "go Pending and
let the sweeper retry"), not a bound on how long a genuinely hung call can run.
A hung call trivially exceeds any D chosen this way; that is the intended
behavior, not a gap in this measurement.

**Why Registry's D above doesn't wait on R4:** D only leaves the 50ms floor if
`4 x p99 > 50ms`, i.e. `p99 > 12.5ms`. R4 would need to be roughly 10x R2's
measured 1264us worst-case to move the number - and R3-vs-R1 showed hive load did
not measurably worsen the direct-target path on this hardware. That is a reason to
expect R4 stays under the threshold, not proof of it. **A stronger, direct check
(happy-path Gate 4 finding):** even using R2's own measured 1264us worst-case
DIRECTLY as if it were Registry's `p99_worst` (skipping the R4-inference
argument entirely), `4 x 1264us = 5056us` still rounds up to only `50ms` - the
same floor. R4 would have to land far outside anything R1-vs-R3's no-load-effect
finding makes plausible before it could change the derived D. R4 is still
genuinely unmeasured, stated as such, and the forward action item above (give it
its own `t_walk_total`)
should be done before this is treated as settled.

## Run protocol (as executed 2026-09-09)

Per the plan's Verification section: 3 runs idle + 3 runs under load - executed
exactly this way (Status section above). Report only - never assert these numbers
as a gate on the shared Wee Tam CI pool (this harness is env-gated specifically so
it never runs there by default). The Results and D-derivation sections above are
this run's raw output plus derived figures, split into separate sections to match
`f11-flood-measurement-run.md`'s "Claims" shape (mechanism-measured facts vs.
arithmetic-derived figures, kept visibly separate) - within "Results" itself, the
per-metric cells (CreateEventW, RegOpenKeyExW, etc.) are the measured facts; the
bolded `sum`/`p99_worst` rows are already arithmetic, carried into that section
only because they're the direct input to the D derivation that follows.

**Treat a 200-sample p99 as deadline-calibration input, not evidence about cold
boot, a dead network share, or true worst-case latency** (a round-3 governance
finding, recorded in the authoring plan file noted under Authority above) - any
PR-B body or changelog fragment citing a number from this document must repeat
that caveat, not just this document.

## Forward action items

1. ~~Run the harness on DGRHP (idle x3, under load x3)~~ - DONE 2026-09-09, see
   Results above.
2. Re-run the `post-fix-cost` case verbatim once PR-B lands, to get the "after"
   figure the plan's "post-fix fast-path cost" note asks for (today's run here is
   the "before" baseline only). Still open.
3. ~~Compile-verify the harness itself on a real Windows toolchain~~ - DONE
   2026-09-09, see Status section above.
4. **NEW:** give R4 (Registry ancestor-walk under hive load) its own
   `t_walk_total` bracket, mirroring R2's (`test_spark_mechanism.cpp:4267-4269`).
   Without it, Registry's ancestor-walk D contribution rests on an inference from
   R2's idle number plus R1-vs-R3's no-load-effect finding, not a direct
   measurement - see the D-derivation section above for exactly what this gap
   costs and why it likely (not certainly) doesn't change the derived number.
