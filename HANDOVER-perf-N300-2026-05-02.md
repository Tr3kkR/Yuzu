# Perf N=300 calibration — overnight handover (2026-05-02)

This document tracks an overnight perf-baseline calibration that was kicked
off via `setsid nohup` from the previous Claude Code session. When the next
session opens, read this first to determine state.

## What was scheduled

Two stages, both running on Shulgi (canonical 5950X, hardware fingerprint
`AMD Ryzen 9 5950X 16-Core Processor | 47GB`):

### Stage 1 — N=20 cron-mechanism trial (DONE — see "Stage 1 — TRIAL VALIDATED" below)

## Stage 1 — TRIAL VALIDATED ✅ (updated 2026-05-02T19:38Z)

The N=20 trial completed cleanly:

```
exit=0
duration_seconds=1266 (21 min)
started_at=2026-05-02T19:11:49Z
finished_at=2026-05-02T19:32:55Z
host=Shulgi
n_samples_actual=20 / requested=20
```

Trial stats summary (from `perf-stats.py /tmp/perf-cron-trial-N20.jsonl`):

| metric | n | mean | stdev | CV | skew(SE) | kurt-3(SE) | distinct |
|---|---|---|---|---|---|---|---|
| burst_registration_ops_sec | 20 | 16,401 | 1,928 | 11.76% | -0.23 (0.51) | -1.84 (0.99) | 18 |
| heartbeat_queue_ops_sec | 20 | 2,672,056 | 177,049 | 6.63% | -0.05 (0.51) | -0.78 (0.99) | 20 |
| registration_ops_sec | 20 | 18,485 | 1,018 | 5.51% | -1.53 (0.51) | +1.69 (0.99) | 15 |
| session_cleanup_ms_per_agent | 20 | 0.049 | 0.011 | 23.06% | **-4.14 (0.51)** | **+17.68 (0.99)** | 16 |

**⚠️ `session_cleanup_ms_per_agent` skew/kurt is a single-glitch
artifact, not an intrinsic distribution.** The N=20 trial diagnosis:

- 19 of 20 samples: 0.05072 – 0.05201 (CV ~0.7%, essentially constant)
- 1 outlier at iteration 7: 0.00100 (z=-4.25, 50× below the rest)

The "skew = -4.1, kurt-3 = +17.7" drama is generated entirely by that
single point. It is **almost certainly a measurement race in
`wait_for_registry_count(0, ...)`** — the benchmark kills 1000 Erlang
processes and waits for the registry's monitor map to drain to zero;
if the polling fast-path observes 0 before the kill loop has actually
been registered (or before the previous churn group's residual
cleanup has settled), the wait returns instantly and the timer reads
~1 µs. Physically impossible for a 1000-agent cleanup.

**Next-session action item (alongside the PR — DO NOT skip):** make
the measurement deterministic. The iter-7 outlier is the system telling
us the instrument is wrong, not that the data is bad. Filtering it out
defeats the purpose of running statistics.

The race surface is:
1. `wait_for_registry_count(0, _)` polls the global aggregate
   `yuzu_gw_registry:agent_count() = ets:info(?TABLE, size)`.
2. `ets:info(Table, size)` has an `undefined → 0` fallback in
   `agent_count/0`. If the table is briefly inaccessible (CT
   init/teardown crossing the test boundary), the first poll
   silently reads 0 and the loop returns instantly — measured time ~1 µs.
3. Even without the `undefined`-mapping bug, the test would also be
   wrong if the registry just happened to process all DOWNs in a single
   scheduler slice before our first 50 ms poll: the 50 ms polling
   granularity already coarsens the measurement, but the global counter
   doesn't tell us *our* N agents specifically were cleaned up — only
   that the size happens to read 0.

Replacement design (deterministic):

```erlang
session_cleanup_latency(_Config) ->
    N = min(1000, yuzu_gw_perf_helpers:get_env("YUZU_PERF_CHURN_AGENTS", 5000)),
    {Pids, Ids} = yuzu_gw_perf_helpers:spawn_and_register(N, ...),
    ?assertEqual(N, yuzu_gw_registry:agent_count()),

    %% 1. Set up our own monitors so we have a private signal
    %%    independent of the registry's monitor_refs map.
    Refs = [{erlang:monitor(process, Pid), Pid} || Pid <- Pids],

    {CleanupUs, _} = yuzu_gw_perf_helpers:measure_wall_clock_us(fun() ->
        %% 2. Fire the kills (async signals).
        lists:foreach(fun(Pid) -> exit(Pid, kill) end, Pids),

        %% 3. Wait for OUR N DOWNs — proves every agent process has
        %%    terminated from the BEAM's perspective.
        wait_for_n_downs(length(Refs)),

        %% 4. Sync barrier with the registry. gen_server:call queues
        %%    behind every prior info/cast, so once this returns the
        %%    registry has processed every DOWN that arrived before
        %%    our call. (Requires a one-line `handle_call(sync, ...)`
        %%    on yuzu_gw_registry.)
        ok = gen_server:call(yuzu_gw_registry, sync, infinity),

        %% 5. Confirm every Id we registered is gone from ETS — via a
        %%    direct read that bypasses lookup/1's is_process_alive
        %%    filter (which can fool us when the entry exists but the
        %%    pid is dead).
        ?assert(lists:all(fun(Id) ->
            ets:lookup(yuzu_gw_registry_table, Id) =:= []
        end, Ids))
    end),

    MsPerAgent = (CleanupUs / 1000.0) / N,
    ct:pal("Cleanup ~B agents: ~B us (~.5f ms/agent)",
           [N, CleanupUs, MsPerAgent]).

wait_for_n_downs(0) -> ok;
wait_for_n_downs(N) ->
    receive
        {'DOWN', _Ref, process, _Pid, _Reason} ->
            wait_for_n_downs(N - 1)
    after 30000 ->
        erlang:error({timeout, awaiting_downs, N})
    end.
```

Required complementary changes:
- `yuzu_gw_registry:handle_call(sync, _, S) -> {reply, ok, S}` — one
  line, no functional change. This is the canonical Erlang flush-mailbox
  idiom; consider exporting a `sync/0` helper for clarity.
- Optional: split the timing into two metrics — "BEAM termination" (kill
  to our DOWN) vs "registry mailbox latency" (our DOWN to sync reply).
  Tells us where time actually goes; useful for diagnosing future
  regressions.
- Optional but desirable: fix `agent_count/0` to remove the
  `undefined → 0` silent fallback. If the table genuinely doesn't
  exist, that's a programming error and should crash, not return 0.
  The current behaviour can mask race conditions like this one.

With the deterministic measurement in place, σ-bounding
`session_cleanup_ms_per_agent` is correct because the metric will then
have a tight, near-Gaussian distribution. The N=300 calibration should
re-run AFTER this fix lands (or accept that the captured σ reflects
the racy measurement, not the underlying gateway behaviour). For
session_cleanup specifically the sequence is:

  1. Land the deterministic-measurement fix.
  2. Re-run the N=300 calibration for session_cleanup only (or run
     N=300 for all 4 again — cheap, ~5h overnight).
  3. Then convert session_cleanup to σ-bound in `tests/perf-baselines.json`.

The PR opening on Stage 3 should cover the other 3 metrics now and
defer session_cleanup pending the deterministic-measurement fix.

The other 3 metrics looked fine for σ-bounding even on N=20:
- heartbeat_queue: 20/20 distinct, CV 6.6%, skew/kurt within SE bands.
  The bucket-fix `c9e6b0f` is doing exactly what it was supposed to.
- registration_ops_sec: CV 5.5%, skew -1.5 (borderline).
- burst_registration: CV 11.8%, skew/kurt within SE bands.

Also notable: `heartbeat_queue` has 20/20 distinct values (vs the old
3-bucket quantum) and a clean near-normal shape — the bucket-fix
`c9e6b0f` is doing exactly what it was supposed to.

## Stage 2 — N=300 SCHEDULED ✅ (kicked off 2026-05-02T19:39Z)

```
N300_PID=693313 (parent setsid wrapper exited; sleep is in the runner)
N300_START_UTC=2026-05-02T23:00:00Z (= 00:00 BST 2026-05-03)
N300_OUTPUT=/mnt/c/Users/natha/Yuzu/tests/perf-baseline-provenance-N300.jsonl
N300_LOG=~/.local/share/yuzu/perf-cron-N300.log
N300_EXPECTED_FINISH_UTC=2026-05-03T04:15:00Z (= 05:15 BST)
```

Sleeping 12,020 s (3h 20min) until 23:00 UTC, then ~5h 15min of capture.

**NOTE on timezone**: the user originally said "11pm" then "2300 UTC" —
those are different times by 1 hour (BST = UTC+1). Stage 2 above is
scheduled for 23:00 UTC = midnight BST per the most-recent instruction.
If the user later says they meant 23:00 BST (= 22:00 UTC), reschedule.

### Stage 3 — Post-capture: PR (NOT YET DONE)

After Stage 2 finishes (next session, probably mid-morning 2026-05-03):

1. Verify completion:
   ```bash
   cat tests/perf-baseline-provenance-N300.jsonl.done
   wc -l tests/perf-baseline-provenance-N300.jsonl   # should be 300
   ```

2. Run analysis:
   ```bash
   python3 scripts/test/perf-stats.py \
       tests/perf-baseline-provenance-N300.jsonl \
       --output-json tests/perf-baseline-provenance-N300.json
   ```

3. Sanity checks (mandatory before opening PR):
   - All 4 metrics have N=300 distinct samples.
   - `heartbeat_queue_ops_sec` has ≥200 distinct values (proves
     bucket-fix `c9e6b0f` is doing its job; pre-fix would show only the
     3-bucket quantum {2.22M, 2.5M, 2.86M}).
   - `session_cleanup_ms_per_agent` has stdev > 0 (proves precision-fix
     `c9e6b0f` is doing its job; pre-fix would be a constant 0.05).
   - For each metric, |skew| < 3·SE_skew and |kurt-3| < 3·SE_kurt
     (rough normality check; SE_skew ≈ 0.14 and SE_kurt ≈ 0.28 at N=300).
     If any metric fails this, **don't σ-bound it** — leave on percentage
     and add a note pointing at the empirical 1st percentile.

4. Convert `tests/perf-baselines.json` to use the σ schema for all 4
   metrics (the schema introduced in commit `199bb4b`):

   ```json
   "<metric>": {
     "method": "sigma",
     "central": <mean>,
     "central_kind": "mean",
     "stdev": <stdev>,
     "k_sigma": 2.0,
     "n_samples": 300,
     "captured_at": <ts>,
     "captured_commit": "<HEAD-sha>",
     "source": "scripts/test/perf-sample.sh N=300 (label=v0.12.0-baseline-calibration)",
     "note": "..."
   }
   ```

   Update top-level `captured_at` and `captured_commit` to today's
   calibration. Schema version stays `perf-baseline/v2`.

5. Open PR on a fresh branch `perf/baseline-calibration-N300`:
   - Title: "test(perf): N=300 σ-calibrated baselines for all gateway perf metrics"
   - Body: summary stats table (n / mean / median / stdev / CV /
     skew(SE) / kurt-3(SE)) for all 4 metrics; before-and-after replay
     showing how many of the in-session 124 samples failed under 10% rule
     vs how many under N=300 σ-bound.
   - Reference: "Closes #738." Also link to #530.
   - Calibration host: 5950X "Shulgi", capture timestamp.

6. Post a summary comment on issue #530 linking to the PR. Do NOT close
   #530 directly — let Nathan review the PR first.

7. Commit raw data alongside: `tests/perf-baseline-provenance-N300.jsonl`,
   `tests/perf-baseline-provenance-N300.json`,
   `tests/perf-baselines.json`.

## Why a wrapper script instead of `at` or a remote routine

- `at`/`atd` not installed on Shulgi WSL2 (verified 2026-05-02).
- A remote `/schedule` routine would run in Anthropic cloud — wrong
  hardware. Perf is hardware-fingerprinted to the 5950X; cloud-captured
  σ values would auto-downgrade to WARN on every subsequent local run
  and wouldn't actually close #738.
- `setsid nohup` + `sleep $seconds_until_target && cmd` works without
  root, survives shell exit, and runs on the right hardware.

## Files involved

- `scripts/test/perf-cron-runner.sh` — the wait-then-execute wrapper
- `scripts/test/perf-sample.sh` — the actual N-sample sampler
- `scripts/test/perf-stats.py` — distributional stats from JSONL
- `tests/perf-baselines.json` — the file we're going to update
- `tests/perf-baseline-provenance-N300.jsonl` — raw 300 rows (one per sample)
- `tests/perf-baseline-provenance-N300.json` — derived stats (perf-stats.py output)
- `~/.local/share/yuzu/perf-cron-trial.log` — Stage 1 wrapper log
- `~/.local/share/yuzu/perf-cron-N300.log` — Stage 2 wrapper log (created if scheduled)

## How to abort

If anything looks wrong and the run needs to stop:

```bash
# Find the runner process
pgrep -af "perf-cron-runner|perf-sample.sh"
# Kill it (and its sleep child)
pkill -f "perf-cron-runner"
pkill -f "perf-sample.sh"
# Stop UAT if it came up
bash scripts/linux-start-UAT.sh stop
```

## Issues this work closes

- #530 — single-sample baseline + 10% tolerance produces spurious FAILs
- #738 — establish academically credible distribution for gateway perf
