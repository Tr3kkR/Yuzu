# Audit-retention alert coverage — measurement method

Reproduce with `python3 tests/prometheus/blind_band_sweep.py --emit` (needs Docker or a
native `promtool` 3.x; the script pins the same image the CI gate uses). `--check`
(the default) compares a fresh measurement against the committed
`tests/prometheus/blind_band_manifest.json` and is what `.github/workflows/docs-lint.yml`'s
`prometheus-rules` job runs on every PR as of #2854 rung B — this file is the METHOD, the
manifest is the RESULT and the gate. A change to `docs/prometheus/yuzu-alerts.yml` that
widens or narrows coverage shows up as `--check` reddening; the fix is
`python3 tests/prometheus/blind_band_sweep.py --emit > tests/prometheus/blind_band_manifest.json`
(`--emit` only ever prints to stdout — it never writes the file itself) and commit the new
manifest alongside the rule change, explaining in the PR description which cadences moved
and why, tied to the rule change — so the diff review sees exactly what moved and why,
rather than a reflexive regenerate-to-green.

**Read "uncovered" as: a genuinely dead reaper does not produce a continuous alert at this
restart cadence.** The property inverted from the pre-#2854 version of this script, which
asserted the alert never fires and called a passing case "silent". Under the redesign the
alert firing INTERMITTENTLY — some eval points yes, some no — is just as bad as never
firing at all: Alertmanager still emits RESOLVED mid-fault and an auditor still reads
"transient, self-recovered". So the assertion is now "the alert is firing at EVERY eval
point past settle", and a cadence is UNCOVERED the moment that fails anywhere, which
measures the historical blind band and the auto-resolve duty-cycle hole with one
instrument instead of two.

**Two synthetic scenarios**, because one dead-reaper simulation cannot answer both
restart-liveness questions the alert family needs to:

- `anchored` — `yuzu_server_audit_retention_last_pass_unixtime` held at a constant
  non-zero value: a database that has run before, whose reaper then died. Gates
  `YuzuAuditRetentionNotRunning`.
- `fresh` — the same series held flat at `0`: a database that has never had a pass.
  Gates `YuzuAuditRetentionNeverRan`, which does not exist until #2854 rung D lands. A
  scenario whose alert is absent from the rules file measures as fully uncovered at
  every cadence, by definition — not an instrument error, and not something `--check`
  should be able to paper over by skipping the scenario. See `alert_present` in the
  manifest.

## What the manifest records

`tests/prometheus/blind_band_manifest.json`: the pinned `promtool_image`, the swept
`grid` (settle minutes, cadence low/high/step), the evaluated `intervals_s`, and
`uncovered.<scenario>.by_interval.<interval>` — the list of cadences (minutes) at which
that scenario's alert failed to stay continuously firing. Recording the grid and the image
alongside the result means the manifest reproduces from one invocation instead of, as the
pre-#2854 table here did, merging two runs swept at different resolutions with no way to
tell which cadence came from which pass.

**The current manifest is long, and that is expected, not an instrument bug.** The
inverted assertion sees the auto-resolve hole for the first time: the young-server grace
(`unless (uptime < 10800 and resets(uptime[3h]) <= 1)`) never actually expires for any
cadence at or below 180 minutes (`uptime` never reaches the 10800s threshold when the
process restarts that often), so the alert's coverage there depends entirely on
`resets(uptime[3h])` staying above 1 continuously — which holds comfortably for very
frequent restarts and starts to intermittently dip back to the grace once a 3-hour window
no longer reliably holds two resets. Measured on the committed manifest: cadences up to
~85 minutes stay fully covered (restarts frequent enough that `resets()` never drops to
1), and coverage degrades from there through the historical 164–195 band and beyond, up to
the swept ceiling. The `fresh` scenario is fully uncovered at every cadence today, simply
because `YuzuAuditRetentionNeverRan` does not exist yet.

## Why the assertion is `count(ALERTS{...})`, not a labelled match

`ALERTS{alertname=X, alertstate="firing"}`'s label set is whatever the rule's own
`labels:` block plus its expression's inherited series labels produce, and differs between
the current rule, rung C's new rule, and rung D's redesign. Wrapping in `count(...)`
collapses that to a single anonymous sample when firing (`exp_samples: [{"labels": "{}",
"value": 1}]`) and to no sample at all when not — confirmed against the pinned promtool
image with both a firing and a non-firing probe rule — so the generator never has to name
a label set that a future rule change is free to alter without affecting coverage.

## Runtime: one promtool container per (scenario, evaluation interval)

Every cadence in the swept range is a separately named case (`cadence-<minutes>`) inside
one generated test file per (scenario, interval) pair, so the sweep launches a handful of
containers rather than one per (cadence, interval) combination. Recovering *which* named
cases failed uses `promtool test rules --junit=<path>`, not the plain `FAILED:` text —
**measured against the pinned 3.13.1 image: the plain-text failure output carries no case
name on either stream**, so a regex over it cannot attribute a failure back to a cadence
at all. `--junit` produces one `<testcase name="cadence-N">` per submitted case, with a
`<failure>` child only when it failed (confirmed with a mixed pass/fail probe), so the
sweep can check the recovered case-name set for *exact* equality against the submitted
one — catching promtool silently dropping or renaming a case, not just detecting an
unrecognized name.

The junit file is written through a second, writable bind mount into an otherwise
`--read-only` container. Get that directory's permissions wrong and promtool cannot create
the file at all — the write-side of the same 0700-mkdtemp trap this script has hit before
on the read side (see the third caution below).

## Three cautions for anyone re-measuring, still true

1. **Evaluate densely within a cadence, and in the eval interval's own resolution.** The
   grid used to be rounded to whole minutes regardless of the requested interval, so a
   30-second sweep and a 60-second sweep were checked at the same points and their
   agreement was not independent confirmation. The grid is now expressed in seconds
   throughout (`eval_time` accepts bare-seconds strings like `"330s"`, confirmed against
   the pinned image), so a duty-cycle gap shorter than a minute cannot hide between two
   samples.
2. **A non-zero promtool exit is not evidence of anything by itself.** The original
   version of this script created its scratch directory `0700` while the container runs as
   uid 65534, so promtool exited 1 on every cadence with "permission denied" and the script
   reported the opposite of the truth. The current version treats any run it cannot fully
   attribute to cadences — a missing or unparseable junit file, a case-name mismatch, an
   `errors` count in the junit header, an exit code inconsistent with the junit content —
   as "could not measure" (exit 2), never a verdict either way.
3. **Check the assertion list is not empty.** A fixed cycle count once produced a series
   ending before the eval grid started, giving a case zero assertions that promtool passed
   vacuously. Cycle count is derived from the cadence (`cycles_for`), covered by
   `--selftest`.
