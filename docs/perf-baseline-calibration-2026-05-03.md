# Gateway perf baseline calibration — N=300 (2026-05-03)

**Status:** evidence captured; gate redesign deferred. The data shows
that algorithmic σ-bounding is the wrong tool for 3 of the 4 gateway
perf metrics. Until the gate is rebuilt around the right primitives
(percentile floors for ceiling-bounded metrics, deterministic
measurement for the cleanup race), perf-gate stays as it is and human
judgement is the loop. Future operators investigating a perf-gate
flake should run `python3 scripts/test/perf-histograms.py` against a
fresh capture and eyeball the shape — the modal value, the left tail,
and any pile-up at the right edge tell more than `mean ± 2σ` ever
will.

## Method

- 300 sequential runs of `scripts/test/perf-sample.sh`, label
  `v0.12.0-baseline-calibration`, on Shulgi (5950X, 47 GB).
- Wall clock: 2026-05-02T23:00:00Z → 2026-05-03T04:16:51Z (5h 17min).
- Box held quiet — CI cancelled, UAT down, no overlapping load.
- Stage gate: `tests/perf-baseline-provenance-N300.jsonl.done`
  records exit=0, n=300/300.
- Raw data: `tests/perf-baseline-provenance-N300.jsonl`
  (one JSON object per run).
- Derived stats: `tests/perf-baseline-provenance-N300.json`
  (perf-stats.py output).

## Distributions

```
┌─ burst_registration_ops_sec  n=300  μ=16,777  σ=1,659  CV=9.89%  skew=-0.77  kurt-3=-0.26  range=[10,661, 18,868]
│   35 │                                                      █▃    │
│   32 │                                                      ██    │
│   29 │                                                      ██    │
│   25 │                                                      ██    │
│   22 │                                                      ██▂   │
│   19 │                                                     ▃███   │
│   16 │                                                    ▁████   │
│   13 │                                                    █████▄  │
│   10 │                        ▄   ▇   ▄▄ ▄ ▇▂       ▂     ██████▂ │
│    6 │                     ▅ ▂█▇ ▂█▇  ██▂█ ██▅ ▅▅▇▅▂█▂▇   ███████ │
│    3 │▃    ▃ ▃          ▃  █▅███▃█████████████████████████████████│
│      └────────────────────────────────────────────────────────────┘
│       10,661                        14,764                  18,868
└─────────────────────────────────────────────────────────────────────

┌─ heartbeat_queue_ops_sec  n=300  μ=2,725,650  σ=175,783  CV=6.45%  skew=+0.11  kurt-3=-0.33  range=[2,255,300, 3,231,018]
│   17 │                            █                               │
│   15 │                            █                               │
│   14 │                          ▃ █                               │
│   12 │                  ▁  ▆  ▁ █▁█▆ ▆  ▆                         │
│   11 │                 ▄█  █  █ ████ █▄ █                         │
│    9 │             ▁   ██▇▁█▁ █ ████▁██ █ ▇▁    ▇  ▇              │
│    8 │             █   ██████ █ ███████ █ ██   ▄█  █              │
│    6 │          ▂  █▂  ██████▂█ ███████▇█▂██▇▇ ██  █              │
│    5 │        ▅ █ ▅██  ████████▅██████████████ ██▅ █  ▅           │
│    3 │      ▂ █ █ ██████████████████████████████████  ██  █       │
│    2 │▅ ▅ ▅ █ █ █ ██████████████████████████████████ ▅██▅▅█    ▅ ▅│
│      └────────────────────────────────────────────────────────────┘
│       2,255,300                     2,743,159            3,231,018
└─────────────────────────────────────────────────────────────────────

┌─ registration_ops_sec  n=300  μ=18,546  σ=980.356  CV=5.29%  skew=-1.74  kurt-3=+2.18  range=[14,925, 19,608]
│   26 │                                                   █  █     │
│   24 │                                                  ▆█ ▂█     │
│   21 │                                                  ██▁██▇    │
│   19 │                                                ▂ ██████    │
│   17 │                                                █ ██████    │
│   14 │                                                █ ██████▁   │
│   12 │                                              ▅ █▅███████▅  │
│    9 │                                              █▃██████████▆ │
│    7 │                                        ▁    ▁█████████████▄│
│    5 │         ▂  ▆         ▆          ▂   ▂ ▂█ ▂▂▂███████████████│
│    2 │▃    ▃▃▃▃█ ▃█▃▃▃▃▇ ▃▇▇█▃▇▃▇▇▇▇▃ ▃█▃▇▇█▇██▃██████████████████│
│      └────────────────────────────────────────────────────────────┘
│       14,925                        17,266                  19,608
└─────────────────────────────────────────────────────────────────────

┌─ session_cleanup_ms_per_agent  n=300  μ=0.05066  σ=0.00580  CV=11.45%  skew=-8.44  kurt-3=+69.47  range=[0.00084, 0.05224]
│  170 │                                                          █ │
│  155 │                                                          █ │
│  139 │                                                          █▁│
│  124 │                                                          ██│
│  108 │                                                          ██│
│   93 │                                                          ██│
│   77 │                                                          ██│
│   62 │                                                          ██│
│   46 │                                                          ██│
│   31 │                                                          ██│
│   15 │▂                                                        ▁██│
│      └────────────────────────────────────────────────────────────┘
│       0.00084                       0.02654                0.05224
└─────────────────────────────────────────────────────────────────────
```

## Per-metric reading

| metric | within 5% of max | shape | character |
|---|---:|---|---|
| `burst_registration_ops_sec` | 40% | loose ceiling, mild left tail | mostly ceiling-bounded |
| `heartbeat_queue_ops_sec` | 2.3% | symmetric, smooth shoulders | **genuinely Gaussian** |
| `registration_ops_sec` | 70% | sharp peak right of mean, long sparse left tail | **hard ceiling at ~19,200** |
| `session_cleanup_ms_per_agent` | 98.7% | floor-bounded (smaller=better) plus a single race outlier | **measurement bug** |

### `heartbeat_queue_ops_sec` — Gaussian

280 distinct values out of 300, near-symmetric, well within the
normality bands (|skew| < 3·SE_skew = 0.42, |kurt-3| < 3·SE_kurt =
0.84). The bucket-fix `c9e6b0f` is doing what it was supposed to —
the metric used to quantize into 3 buckets ({2.22M, 2.5M, 2.86M}) and
now spans the full range smoothly. This metric is the only one where
σ-bounding is statistically defensible.

### `registration_ops_sec` — ceiling-bounded, NOT Gaussian

70% of samples within 5% of max, modal cluster at 18,940-19,230
operations/sec. The system has a structural ceiling around 19,200 ops/sec
under this benchmark configuration; the long left tail isn't a feature
of the underlying performance distribution, it's a record of how often
something interrupted (GC, scheduler tick, OS noise). σ-bounding here
would conflate "system capability" with "frequency of contention" and
produce an upper band that is unreachable. The right way to gate this
is on a percentile floor: `p5 ≥ baseline_p5 × (1 - tolerance)` catches
ceiling drops without false-positive flapping from noise.

### `burst_registration_ops_sec` — loose ceiling

Less concentrated than `registration` (40% within 5% of max vs 70%)
but the same shape: right-side peak, asymmetric left tail. Skew -0.77
is ~5× SE, outside the normality band but mild. CV is 9.9% — broad
enough that σ-bounds wouldn't be tight anyway. Same percentile-floor
treatment as `registration`.

### `session_cleanup_ms_per_agent` — measurement race

98.7% of samples within 5% of the maximum (which is the modal
"normal" value of ~0.05 ms/agent). The single outlier at 0.00084 ms
(50× lower than every other sample) drives skew=-8.44, kurt=+70.2.
This is not the distribution of cleanup time — it is the distribution
of one race condition firing once in 300 trials. Diagnosed in the
N=20 trial: `wait_for_registry_count(0, _)` polls the global ETS
table size, which has an `undefined → 0` fallback path that returns
instantly if the table is briefly inaccessible at test boundaries.
Fix design (per-pid `monitor`s + `wait_for_n_downs/1` + a
`gen_server:call(yuzu_gw_registry, sync, infinity)` barrier) is
documented in the previous-session handover. This metric should not
be gated until that fix lands.

## Why σ-bounding is wrong for ceiling-bounded metrics

A ceiling-bounded distribution is the joint of two things: a
deterministic upper bound (system capability under no contention)
and a stochastic process (how often something contends). The
standard `mean ± k·σ` interval models neither well:

1. **Mean is biased downward** by the noise tail and is not the
   number anyone cares about — ideal-conditions throughput is the
   modal value, not the average.
2. **σ encodes noise frequency, not system performance.** A
   regression that lowers the ceiling 5% can leave the mean almost
   unchanged if the long tail still dominates the variance —
   exactly the regression the gate is supposed to catch.
3. **The upper k·σ bound is unreachable.** The system cannot
   exceed the ceiling, so the upper half of the band is dead weight.

The right primitive for ceiling-bounded throughput is a **percentile
floor**: `assert pNN >= baseline_pNN * (1 - tolerance)`. p5 catches
"the system got slower under contention"; p99 catches "the ceiling
itself moved." Both are robust to single-sample outliers.

For floor-bounded latency (smaller=better, like
`session_cleanup_ms_per_agent`), the symmetric primitive is a
**percentile ceiling**: `assert pNN <= baseline_pNN * (1 + tolerance)`.

## Deferred: deterministic-measurement design for `session_cleanup`

The current `session_cleanup_latency` test polls
`yuzu_gw_registry:agent_count() = ets:info(?TABLE, size)` and waits for
the global aggregate to drop to zero. Two known failure modes:

1. `agent_count/0` has an `undefined → 0` silent fallback. If the ETS
   table is briefly inaccessible at a CT init/teardown boundary, the
   first poll reads 0 and the wait returns instantly — measured time
   ~1 µs, physically impossible for 1000 processes.
2. The 50 ms polling granularity coarsens the measurement, and the
   global counter doesn't tell us *our* N agents specifically were
   cleaned up — only that the size happens to read 0.

Replacement design — set up our own monitors so the signal is private
to this test, drain N DOWN messages directly, then sync with the
registry's mailbox via `gen_server:call`:

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

- `yuzu_gw_registry:handle_call(sync, _, S) -> {reply, ok, S}` —
  one line, no functional change. Canonical Erlang flush-mailbox
  idiom; consider exporting a `sync/0` helper for clarity.
- Optional: split the timing into two metrics — "BEAM termination"
  (kill to our DOWN) vs "registry mailbox latency" (our DOWN to
  sync reply). Useful for diagnosing future regressions.
- Optional but desirable: fix `agent_count/0` to remove the
  `undefined → 0` silent fallback. If the table genuinely doesn't
  exist, that's a programming error and should crash, not return 0.

## Deferred work

When perf gates are revisited:

1. **Land the deterministic-measurement fix above first**, then
   re-capture N=300 for `session_cleanup_ms_per_agent`. The other
   3 metrics don't need re-capture — their distributions are
   characterised.
2. **Add a percentile method to `tests/perf-baselines.json`.** The
   schema currently supports `sigma` and percentage; add `percentile`
   with `pct`, `direction` (`>=`/`<=`), and `tolerance_pct`. Migrate
   `registration_ops_sec` and `burst_registration_ops_sec` to it.
3. **Keep `heartbeat_queue_ops_sec` on σ-bound** — it's the only one
   that fits the Gaussian assumption.
4. **Keep the histogram tool gitignored unless we wire it into the
   perf gate output.** If the gate ever runs N≥30 samples per
   invocation, `scripts/test/perf-histograms.py` should print the
   shape so the operator can eyeball regressions; until then it's a
   manual diagnostic.

## References

- Issue #530 — single-sample baseline + 10% tolerance produces spurious FAILs
- Issue #738 — establish academically credible distribution for gateway perf
- Commit `c9e6b0f` — heartbeat_queue / session_cleanup metric resolution fix
- Commit `199bb4b` — initial σ-tolerance for `burst_registration` (revisit
  per the deferred-work item above; σ is not the right primitive for it)
- `scripts/test/perf-sample.sh` — sampler
- `scripts/test/perf-stats.py` — distributional stats from JSONL
- `scripts/test/perf-histograms.py` — ASCII histograms (gitignored,
  reproduce locally as needed)
