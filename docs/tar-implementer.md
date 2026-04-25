# Timeline Activity Record — Implementer's Guide

Companion to `docs/user-manual/tar.md` (operator-facing). This doc is for
engineers maintaining the TAR plugin or building features on top of TAR.
It captures the design intent, the on-disk format, and the operational
behavior you cannot derive from the code alone.

For the historical product vision and rollout plan, see
[`docs/tar-warehouse-plan.md`](tar-warehouse-plan.md). For the OS support
matrix, see [`docs/user-manual/tar.md`](user-manual/tar.md#os-compatibility-matrix).

---

## 1. What TAR is for

TAR is a **forensics + inventory** capability, not a SIEM and not an EDR.
The design point is "what was happening on this machine at time T, with
no pre-configuration", which has two distinct uses:

1. **Forensic timeline reconstruction.** When an incident is reported,
   an operator can run a query like "show me every process named
   `chrome.exe` that started on this host between 2026-03-01 and
   2026-03-08" and get an answer regardless of whether logging was
   enabled at the time. The collector defaults are tuned so 90+ days of
   activity fits in single-digit MB on a typical workstation.

2. **Cheap inventory snapshots.** The same data — the most recent
   process list, the open TCP connection map, the running services —
   doubles as an always-fresh inventory source for dashboards and
   compliance evidence. Because the live tier is row-count-bounded, a
   `SELECT * FROM $Process_Live` always returns "now-ish".

What TAR is **not**:

- Not a kernel-mode probe. All collection is poll-based via documented
  user-mode APIs (`CreateToolhelp32Snapshot`, `/proc/*`, `sysctl`,
  `GetExtendedTcpTable`, `systemctl`, `launchctl`, `WTSEnumerateSessionsEx`,
  `getutxent`). Anything that lives shorter than the fast collector
  interval (default 60s) is invisible.
- Not a transport for events. TAR persists everything locally; the
  server queries on demand via the `query` and `sql` actions. There is
  no push-to-server stream and no aggregation across hosts at write
  time.
- Not encryption-at-rest, not compression. See
  §3 for the current on-disk format and the planned posture.

---

## 2. Architecture

```
                ┌────────── tar plugin ──────────┐
collect_fast    │ enumerate_processes()           │       writes
  (60s) ──────► │ enumerate_connections()         │ ───►  process_live
                │   diff vs tar_state             │       tcp_live
collect_slow    │ enumerate_services()            │       service_live
  (300s) ─────► │ enumerate_users()               │       user_live
                │   diff vs tar_state             │
                │ insert_*_events()               │
rollup          │   tar_aggregator runs SQL       │
  (15min) ────► │   INSERT INTO ..._hourly        │ ───►  *_hourly / *_daily / *_monthly
                │   from each lower tier          │
                │ retention_sql() per table       │ ───►  prunes oldest rows
                └─────────────────────────────────┘
```

Flow:

1. The trigger engine fires `collect_fast` / `collect_slow` / `rollup` on
   their respective intervals (configurable via the `configure` action).
2. Each collector enumerates its source, reads the previous snapshot
   from `tar_state` (a key-value table inside `tar.db`), diffs them with
   `compute_*_events()` to produce typed event rows, and inserts via
   `TarDatabase::insert_*_events()`.
3. Periodically (`rollup` action, 15 min default) `tar_aggregator` runs
   the rollup SQL from the schema registry to build hourly summaries
   from live, daily from hourly, monthly from daily. Each tier has
   independent retention.

The schema registry (`tar_schema_registry.cpp`) is the single source of
truth for table shape, retention behavior, rollup SQL, and per-OS
support metadata. Adding a new capture source means: append to
`build_sources()`, populate `os_support`, write the collector, write
the diff, wire the typed insert, write tests. No DDL, no rollup
plumbing edits.

---

## 3. Local persistence

**Path.** `<agent_data_dir>/tar.db`. On Windows defaults to
`C:\ProgramData\yuzu\agent\tar.db`; on Linux/macOS to
`/var/lib/yuzu/agent/tar.db`.

**Format.** Plain SQLite 3, WAL journal mode (`tar_db.cpp` sets
`PRAGMA journal_mode=WAL` at open time). Pages are SQLite-default
(4 KB) and the file uses SQLite's standard schema — readable by any
external tool that can speak SQLite. **The on-disk database is NOT
encrypted and NOT compressed.** This is by design today (zero
runtime dependency, zero key-management surface) but is the target of
two planned changes:

- **Encryption-at-rest** via SQLCipher (deferred — would require
  vcpkg port + key derivation from the agent's TPM-bound identity
  certificate, similar to how the agent's gRPC client cert is bound).
- **Page-level compression** via SQLite's `zlib`-backed VFS shim
  (deferred — typical TAR rows compress 4-6× because of repeated
  process names and remote addresses, but the wins are dwarfed by
  retention-default tuning).

If you ship a feature that places sensitive data in TAR (private keys,
session tokens, customer PII), be aware that the cmdline redaction
patterns are the **only** content-protection layer today. Add new
patterns to `kDefaultRedactionPatterns` in `tar_collectors.hpp` rather
than scrubbing per-callsite.

**Schema versioning.** `tar_db.cpp` runs an idempotent migration at open
time. Current schema version is 3 (legacy `tar_events` retired in PR
M14; see the migration in `apply_migrations`). Bumps go in the same
function, never in `applies_*` collectors.

---

## 4. Persistence across upgrade / uninstall / reinstall

| Operation | tar.db behavior |
|-----------|-----------------|
| **In-place agent upgrade** | tar.db is preserved (lives in the agent data dir, not the install dir). Schema migration runs at first open of the new binary. Live-tier rows captured by the old binary remain queryable; rollups continue. |
| **Uninstall** (`yuzu-agent --remove-service`, MSI uninstall) | tar.db is **left in place** by design. The data dir is operator-managed; uninstall removes the binary and service registration only. To wipe TAR data, delete `<data_dir>/tar.db` explicitly. |
| **Reinstall over an existing data dir** | The new binary opens the existing tar.db, runs migration if the schema version differs, and resumes collection. State in `tar_state` may be stale (see §5). |
| **`data_dir` change** (config update) | The new directory has no tar.db — the next collect_fast creates it from scratch. The old tar.db at the previous path is orphaned but not deleted. Operator concern, not TAR's. |

The "leave data on uninstall" rule is identical to other Yuzu agent
state stores. If a customer asks for "delete tar data on uninstall",
that is a deployment-tooling change (MSI custom action), not a TAR
plugin change.

---

## 5. Startup detection / restart caveat

When the agent restarts, the saved `network` / `process` state in
`tar_state` is **stale** — it captures the world as the previous
process saw it, which may be hours or days ago. The next collect_fast
cycle compares the stale `previous` to a fresh `current` and emits
events for every difference.

For the **TCP collector specifically** this means: every connection
that was open both before the shutdown and after the restart appears
as a `connected` event in the timeline, because the state read from
`tar_state` does not include it (or includes a different connection
table). This is a known double-capture caveat.

The tradeoff was deliberate: the alternative — suppressing post-restart
"new" connections by some heuristic — risks dropping legitimate
re-establishment events (an attacker re-opening a C2 channel after a
reboot looks identical to a legitimate connection re-establishment).
Forensic completeness wins; analysts learn to read the post-restart
spike as a snapshot reset rather than 200 net-new connections.

The behavior is pinned by
`tests/unit/test_tar_warehouse.cpp::"TAR diff: TCP post-restart with
empty previous yields all-connected"`.

For **process and service collectors** the same principle applies but
the operational impact is smaller — long-running processes and
services appear as `started` events, which matches what an analyst
asking "what was running after the reboot?" expects to see anyway.

For **user sessions** there is no double-capture: the tty/session_id
is identical pre- and post-restart for the same logged-in user, so
the diff shows no change.

---

## 6. Device impact expectations

Steady-state CPU cost on a typical 8-core workstation, measured against
`v0.10.0` on a 5950X dev box:

| Phase | CPU | Wall time |
|-------|-----|-----------|
| `enumerate_processes()` (200 procs) | ~3 ms | ~5 ms |
| `enumerate_connections()` (300 sockets) | ~8 ms | ~10 ms |
| `enumerate_services()` (140 services) | ~50 ms | ~80 ms (dominated by `systemctl` fork on Linux) |
| `enumerate_users()` (5 sessions) | <1 ms | <1 ms |
| `compute_*_events()` (full diff) | <2 ms total | <3 ms |
| `insert_*_events()` (~50 rows, batched) | ~1 ms | ~2 ms |
| Rollup pass (15 min) | ~5–15 ms | ~20 ms |

Worst observed full collect_fast: ~25 ms. Worst observed collect_slow:
~150 ms (Linux `systemctl list-units` on a host with 400 units; macOS
`lsof -nP -i` on a host with 5000 sockets — see the lsof note in the
compatibility matrix and consider raising `fast_interval`).

Disk usage at default retention:

- live tiers: 4 × 5000 rows ≈ 20K rows total. ~3–5 MB depending on
  cmdline length.
- hourly: 24h × ~50 distinct process names ≈ ~1200 rows/day. ~30 MB
  over a year.
- daily: 31d × ~50 names ≈ ~1500 rows/month. ~5 MB/year.
- monthly: 12 × ~50 ≈ 600 rows. trivial.

A workstation kept at default retention sits comfortably under 50 MB
of TAR data over a year of normal use. A noisy CI host with hundreds
of helper processes per minute can exceed 500 MB; the
`process_stabilization_exclusions` knob (issue #59) is the intended
mitigation.

The redaction pass is regex-free (substring match, case-insensitive)
and runs once per process per collect cycle. At typical pattern
counts (5 default + 0–10 operator-added) it is dominated by the
`tolower` cost on cmdline; expect <1 µs per process.

---

## 7. Supportability without the upstream page

This file plus `docs/user-manual/tar.md` plus
`docs/tar-warehouse-plan.md` are the canonical TAR references. The
schema registry is queryable at runtime via the `compatibility` action
(per-source/OS matrix) and the `status` action (effective config). If
you find yourself reaching for an external doc or a "what does this
field mean" answer that isn't in this doc tree, file an issue — that's
the gap to close.

Routine debugging entry points:

| Symptom | Where to look |
|---------|---------------|
| "TAR isn't recording anything for source X" | `tar.status` output → `<source>_enabled` row. Then `compatibility` action to confirm OS support. Then check the agent log for "TAR plugin initialized". |
| "Query returns 0 rows but I know the event happened" | Check the collect interval (`fast_interval` / `slow_interval`) vs the event lifetime — anything shorter than the interval is sub-resolution. |
| "TCP collector shows a flood of `connected` events" | Almost always a restart artifact. Confirm against the agent's start time. |
| "tar.db is huge" | `status` returns `db_size_bytes`. If it's growing without bound the rollup trigger may not be firing — check trigger registration in `init()`. |
| "Schema migration failed at startup" | `agent.log` will show `TarDatabase: migrated to schema version N` on success or the SQLite error on failure. Migrations are idempotent — fixing the underlying issue and restarting will retry. |

For new-source bring-up, the smallest viable change is: add a
`CaptureSourceDef` to `build_sources()`, write the platform collectors
+ enumeration function, write the diff, write tests. No DDL, no
rollup, no plumbing changes — the registry is the contract.
