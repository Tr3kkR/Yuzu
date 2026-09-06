# Integration: TAR `usage` derived fold (P21)

Wiring the engineer package does NOT do (boundaries: `tar_schema_registry.cpp`,
`tests/meson.build` are integrator-owned) — verbatim material for
IT-TAR-SOURCE, plus the tar_config key list P22/P24 read.

## 1. `agents/plugins/tar/src/tar_schema_registry.cpp` — the `usage` CaptureSourceDef row

Add alongside the other sources in `build_sources()`. Column set matches
what `tar_usage.cpp`'s `run_usage_fold()` reads/writes exactly — see that
file's banner for the full contract (gap detection, gating, transaction
semantics). Only `usage_live` and `usage_daily` come from this row;
`usage_daily_user` and the two UNIQUE indexes are `tar_db.cpp`'s v6 schema
migration (already landed with this package — no registry action needed for
those three).

`default_enabled = false` — `usage` is a usage-class per-machine aggregate
built from `process` event content, so it ships opt-in like
module/procperf/netqual, not always-on like `process`/`tcp`/`service`/`user`.

```cpp
        // ── Usage (derived fold over process_live, P21/wave 2) ────────────
        {
            .name = "usage",
            .dollar_name = "Usage",
            .default_enabled = false,
            .os_support = {
                {"windows", OsSupportStatus::kSupported, "derived",
                 "Derived fold over process_live -- inherits process's OS "
                 "support, not a separate OS-level collector."},
                {"linux",   OsSupportStatus::kSupported, "derived",
                 "Derived fold over process_live."},
                {"macos",   OsSupportStatus::kSupported, "derived",
                 "Derived fold over process_live."},
            },
            .granularities = {
                {
                    .suffix = "live",
                    .retention_type = RetentionType::kRowCount,
                    // Open-run count is bounded by the FOLD itself
                    // (tar_usage.hpp::kMaxOpenRuns = 20000), not by this
                    // retention row -- set generously above that so the
                    // generic row-count prune never fires ahead of the
                    // fold's own cap. tar_usage.cpp's DELETE-then-INSERT
                    // open-run lifecycle is the only writer.
                    .retention_default = 25000,
                    .columns = {
                        {"ts",          "INTEGER"},
                        {"snapshot_id", "INTEGER"},
                        {"action",      "TEXT"},   // always "open"
                        {"pid",         "INTEGER"},
                        {"exe_key",     "TEXT"},
                        {"user",        "TEXT"},
                        {"start_ts",    "INTEGER"},
                    },
                },
                {
                    .suffix = "daily",
                    .retention_type = RetentionType::kTimeBased,
                    .retention_default = 2678400, // 31 days -- matches process_daily;
                                                  // usage_daily_user's own retention in
                                                  // tar_usage.cpp reads THIS value via
                                                  // capture_sources(), so keep them in sync
                                                  // if this default is ever tuned.
                    .columns = {
                        {"day_ts",           "INTEGER"},
                        {"exe_key",          "TEXT"},
                        {"run_count",        "INTEGER"},
                        {"total_seconds",    "INTEGER"},
                        {"first_seen",       "INTEGER"},
                        {"last_seen",        "INTEGER"},
                        {"distinct_users",   "INTEGER"},
                        {"superseded_runs",  "INTEGER"},
                        {"expired_runs",     "INTEGER"},
                    },
                },
            },
        },
```

CORRECTION found while coding: the spec's original column list did not
state an explicit column order; the order above is the one
`run_usage_fold()`'s hand-built INSERT statements use (`tar_usage.cpp`) —
match it exactly if `generate_warehouse_ddl()` or any rollup helper ever
needs the position rather than the name.

## 2. `tests/meson.build`

**Sources** (tar test binary's source list, alongside the other
`test_tar_*.cpp` entries):

```meson
    'unit/test_tar_usage.cpp',   # P21: usage derived-fold pairing + DB tests
```

**Fixture-dir define** — add `-DYUZU_TEST_FIXTURE_DIR` to `tar_test_exe`'s
`cpp_args` (mirrors the `yuzu_agent_tests` define already in this file):

```meson
             '-DYUZU_TEST_FIXTURE_DIR="' +
             (meson.project_source_root() / 'tests' / 'unit' / 'fixtures').replace('\\', '/') +
             '"'
```

The fixtures this test reads already exist at
`tests/unit/fixtures/wave7/app_usage/process_events_{linux,macos}.txt` (A2,
shared with P22's `test_app_usage_parsers.cpp`) — no new fixture files
needed from the integrator.

## 3. `agents/plugins/tar/meson.build`

Already added by this package: `'src/tar_usage.cpp'` in `tar_sources`. No
integrator action.

## 4. tar_config keys (for P22 / P24's `tar status` surface)

All owned/written by `tar_usage.cpp`; P22/P24 read-only:

| key | meaning |
|---|---|
| `usage_hwm_id` | high-water mark over `process_live.id` |
| `usage_unmatched_stops` | cumulative count of "stopped" events with no matching open run |
| `usage_clock_anomalies` | cumulative count of runs whose duration was clamped to 0 by a backward clock step |
| `usage_lag_events` | `max_id - hwm` as of the last fold attempt (0 once caught up) |
| `usage_last_fold_ts` | epoch seconds of the last fold attempt (success or failure) |
| `usage_gap_count` | cumulative count of detected capture gaps (process_live rows pruned before the fold read them) |
| `usage_gap_lost_events` | cumulative count of events lost to gaps |
| `usage_gap_last_ts` | epoch seconds of the most recent gap |
| `usage_feeder_enabled` | `"true"`/`"false"` — both `usage` and `process` sources enabled this tick |
| `usage_coverage_since` | epoch seconds the fold has counted from (set by `usage_rebaseline`) |
| `usage_enabled` | the standard `<source>_enabled` toggle (`source_enabled(db, "usage")`) |

## Notes for the integrator

- `usage_live` / `usage_daily` table DDL comes from this registry row via
  the normal `create_warehouse_tables()` path; `usage_daily_user` and both
  UNIQUE indexes come from `tar_db.cpp`'s v6 migration (this package) and
  need no registry entry.
- This package's own tests (`ensure_usage_schema()` in
  `test_tar_usage.cpp`) create the same three tables + indexes directly
  with `IF NOT EXISTS`, so `test_tar_usage.cpp` passes whether this
  registry row has landed yet or not in a given build — no ordering
  dependency between P21 and this row for that test file specifically.
- `docs/wave7/integration-app-usage.md` (P22) already notes the reverse
  direction: `app_usage_parsers.hpp` duplicates `tar_usage.hpp`'s
  `normalise_exe_key()` rather than depending on this package.
