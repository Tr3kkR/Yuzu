# `YuzuAuditRetentionNotRunning` — measured blind band

Reproduce with `python3 tests/prometheus/blind_band_sweep.py` (needs Docker; the
script pins the same promtool image the CI gate uses). This file records the
result so it is reviewable without re-running it, and so a future change to the
expression has something to be compared against.

**Read "silent" as: a genuinely dead reaper produces no alert, ever, at this
restart cadence.** The synthetic server has `yuzu_server_audit_retention_passes_total`
flat forever — no pass has been attempted — and a `yuzu_server_uptime_seconds`
sawtooth restarting every *cadence* minutes. The assertion is "the alert never
fires", evaluated at every point across several full cycles, so `SUCCESS` is the
bad outcome.

## Result — promtool 3.13.1, 2026-08-07

| eval interval | current expression | previous expression (`origin/dev`) |
|---|---|---|
| 30s | silent 164–195 min | silent at every sampled cadence 30–190 |
| 60s | silent 164–195 min | silent at every sampled cadence 30–190 |
| 300s | silent 163–196 min | silent at every sampled cadence 30–200 |

Current expression swept at 1-minute resolution across 155–200 and at 5-minute
resolution across 30–240; outside the band above, no sampled cadence was silent.
The previous expression was swept at 10-minute resolution across 30–240 — every
sample from 30 to 190 was silent, so its band is reported as a floor rather than
as bounds.

**The band is real but narrow, and it moves by about a minute with the
evaluation interval — not more.** An earlier review reported it as "160–195 at a
5-minute interval"; the measurement is 163–196. Another reported "165–179"; that
understated the upper end by 16 minutes. Both came from sparse sampling.

## Why it exists

`unless (uptime < 10800 and resets(uptime[3h]) <= 1)`. For the exclusion to
lapse, either uptime must exceed 10800s — impossible when the process restarts
more often than that — or the 3-hour window must hold two resets, which it does
for only `10800 - cadence` seconds per cycle. Once the cadence passes 9900s
(165 min) that overlap is under the rule's `for: 15m` and the alert can never
latch. The upper bound is where uptime finally clears 10800 for long enough.

## Why it is not closed here

The natural fix is a freshness rule on
`yuzu_server_audit_retention_last_pass_unixtime`, and it does not work as
shipped: that gauge is seeded 0 and never reloaded from the persisted
`audit_retention_meta` anchor, so it zeroes on every process restart, and a
freshness rule built on it goes silent on the 30-minute crash loop the current
rule already catches — a regression, not a fix. Closing the band needs the
server to seed that value at construction, which is a C++ change to `AuditStore`
and out of scope for a rules-and-CI branch.

A second trap for whoever picks this up: any `time() - <server stamp>` shape is
denominated in the server's own wall clock, which is the one input this
subsystem exists to distrust, and `cleanup_once` deliberately stamps a negative
value for the dead-CMOS case. A negative stamp satisfies neither `> 0` nor
`== 0`, so a freshness rule is silent on exactly the machine the clock guard was
built for. Keep a counter-based, clock-independent rule in the design whatever
else changes.

## Three cautions for anyone re-measuring

1. **Evaluate densely within a cadence.** The alert has a duty cycle — as little
   as 2 minutes firing per 162-minute restart cycle — so a single eval point can
   land between firings and report a firing rule as silent. One review sampled
   `eval_time: 300m` alone and concluded cadences 120 and 170 were both silent;
   120 is not.
2. **A non-zero promtool exit is not evidence of firing.** The first version of
   the sweep script created its scratch directory 0700 while the container runs
   as uid 65534, so promtool exited 1 on every cadence with "permission denied"
   and the script reported "no silent cadence anywhere" — the exact opposite of
   the truth. It now distinguishes a test failure from an infrastructure error
   and refuses to return a value for the latter.
3. **Check the assertion list is not empty.** With a fixed four cycles, a
   30-minute cadence produced a series ending at 120 minutes while the eval grid
   started at 200, so the case carried zero assertions and promtool passed it
   vacuously — reported as "silent" when nothing had been measured. The number
   of cycles is now derived from the cadence.
