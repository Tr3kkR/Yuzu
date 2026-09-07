# App Usage

App Usage is a **machine-scope, read-only** inventory of which executables ran on a
device and for how long, derived entirely from TAR's own process-event history. It
never carries a pid, a command line, or a user name in its output — the closest it
gets to identity is a `COUNT(DISTINCT user)` per executable and a plain count of
open runs.

Two things ship this release:

- **The TAR `usage` source** (agent-local, `tar.db`) — a derived fold over
  `process_live`, machine-scope, **on by default**.
- **The `app_usage` plugin** (`summary` / `last_used` / `foreground`) — a read-only
  view over that fold, gated behind the `Forensics` securable.
- **The `app_usage` daily-sync source** — centralises a trailing-30-day per-executable
  window to the server so it survives beyond the agent's local retention and is
  queryable fleet-wide via REST/MCP (see [Server-side projection](#server-side-projection-app_usage) below).

## The TAR `usage` source

`usage` is a **DERIVED fold**, not a capture source: it does not snapshot-and-diff
its own OS state the way `process`/`tcp`/`service` do. Instead, on every fast tick,
`run_usage_fold()` pairs `process_live`'s started/stopped rows by `(pid, exe_key)`
into runs, closes them into `usage_daily` (one row per executable per UTC day), and
tracks still-open runs in `usage_live`. See
[`docs/tar-implementer.md`](../tar-implementer.md#8-adding-a-capture-source) §8: if
you are adding a new capture source, `usage` is explicitly **not** the pattern to
copy — it has no `enumerate_*`/`compute_*_events()` collector of its own; it derives
from `process`'s.

**On by default — a works-council-class TAR source that ships enabled, alongside
`power` and `removable`.** `process`, `tcp`, `service`, `user` and `perf` have
always been on as machine-scope operational telemetry; every source added since 1.5
under the opt-in posture defaults off, and `power`/`removable`/`usage` are the
sources that diverge from that opt-in default. What a device runs and when is a
presence/working-hours proxy even though `usage` carries no user column of its own
(the fold does record a `user` field on each open run, folded into a
`distinct_users` count on write) — so the same works-council posture that applies to
`netconn`/`power` applies here: this is a co-determination consideration to raise
at upgrade, not at an operator's opt-in.

- **Collection window: forward-only from enablement.** Unlike `power`/`removable`,
  `usage` has no retrospective-backfill control — it only ever folds `process_live`
  rows written after it starts running, so enabling it (or upgrading into a build
  that ships it) begins coverage from the first tick after that moment. This is
  tracked by `usage_coverage_since` (the tar_config key the fold sets on its first
  successful run) and reported back as `coverage_since` in every `summary` meta row.
- **Config key:** `usage_enabled` (`true`/`false`, default `true`). Setting it to
  `false` stops the fold from advancing; existing `usage_daily`/`usage_live` rows
  stay queryable until they age out under the retention below.
- **Retention:** `usage_daily` (and its per-day `usage_daily_user` sidecar, which
  carries no per-row identity of its own beyond the join) ages out after **31 days**
  — the same window as `process_daily`. `usage_live` (the open-run table) is bounded
  by the fold's own **open-run cap of 20000** (`run_usage_fold`'s operative bound,
  `cap_open_runs`); the table's generic row-count retention is set far above that
  (200000) purely as a backstop and must never be the bound that actually fires. When
  the fold closes a run past the cap it marks it `capped` and folds it into
  `expired_runs` on the corresponding `usage_daily` row — that run is accounted for,
  not silently dropped.

### Identity rule: `exe_key`

Every row is keyed by `exe_key`, computed by `normalise_exe_key()`
(`agents/plugins/tar/src/tar_usage.hpp`, the source of truth — duplicated
byte-for-byte in `agents/plugins/app_usage/src/app_usage_parsers.hpp` since the
plugin cannot depend on TAR's internal headers, with its own parity test pinning
the two copies together):

- Lowercase.
- Basename only — everything up to and including the last `/` or `\` is stripped.
- Trimmed of surrounding whitespace; an empty result becomes `(unknown)`.
- **Windows** keeps the `.exe` suffix — it is never stripped.
- **Linux** `comm` (the process name TAR's process source reports) arrives already
  15-character truncated by the kernel before this function ever sees it; two
  binaries whose names collide in the first 15 bytes will alias to the same
  `exe_key` on Linux. That is a kernel-imposed limit, not a defect in the fold.

`exe_key` today has no join to a software-inventory identity. A future join to the
detected-licence inventory's `exe_hints` field (ADR-0024, `software_licensing`) —
described as "the product→executable bridge used later for usage matching" in
[`software-licensing.md`](software-licensing.md) — is anticipated but not built by
this release.

## The `app_usage` plugin

Three read-only actions, all gated behind the `Forensics` securable (below).

### `summary`

One `meta|` row (the fold's health counters) followed by zero or more `usage|` rows,
one per executable, ranked by `run_time` (total seconds) or `run_count` over a
`days`-day trailing window (default 30, clamped 1-365; `top` clamps 1-500, default
25).

**Real emitted output — this Mac, 2026-09-07.** This build host has no live
`tar.db` under the platform default data directory (`/var/lib/yuzu/agent` — no
build host in this wave's run has one), so the *actual* first line
`app_usage.dylib`'s `summary` action emits here, captured via
`yuzu::agent::LocalDispatcher` against the real compiled plugin, is the honest
"nothing to read yet" answer, never a silent empty success:

```
constrained|tar_db_unavailable|/var/lib/yuzu/agent/tar.db|unable to open database file
```

(exit code 1; the path is real — `resolve_db_path()`'s platform-default fallback,
confirmed against this exact sqlite open call on this host.)

The success shape — computed by the plugin's own `format_meta_line` /
`format_usage_row` (`app_usage_parsers.hpp`) against
`test_app_usage_parsers.cpp`'s fixture inputs, since no host in this wave has a live
`tar.db` yet to demonstrate it directly — is:

```
meta|window_days|7|coverage_since|1000|days_present|3|open_runs|2|unmatched_stops|0|clock_anomalies|0|gap_count|0|gap_lost_events|0|gap_last_ts|-|lag_events|0|feeder_enabled|0|last_fold_ts|-
usage|app.exe|3|0|0|0|0|0|0
```

`usage|` columns, in order: `exe_key`, `run_count`, `total_seconds`, `first_seen`,
`last_seen`, `distinct_users`, `superseded_runs`, `expired_runs`.

**Capture-gap honesty fields** — every field in the `meta|` row, as emitted by
`read_meta()`:

| Field | Meaning when non-zero |
|---|---|
| `open_runs` | This many `(pid, exe_key)` runs are currently open (started, not yet stopped) — normal under steady load; only a persistently large number suggests stop events are being missed. |
| `unmatched_stops` | A "process stopped" event arrived with no matching open run — the start was missed (e.g. it predates `usage_coverage_since`, or fell in a capture gap). |
| `clock_anomalies` | The fold saw a stop timestamp earlier than its paired start — a clock skew or reorder, not treated as a valid run duration. |
| `gap_count` | The fold's high-water mark against `process_live` pointed at a row that no longer exists — `process_live`'s row-cap prune deleted it before the fold reached it. This is a genuine capture gap. |
| `gap_lost_events` | The number of `process_live` rows lost to the gap(s) counted above — the honesty backstop's actual loss count, not just that a gap occurred. |
| `lag_events` | The fold is processing rows behind the current tick by more than one tick's worth — sustained non-zero values mean the fold is falling behind the write rate (see `tar_usage.hpp`'s drain-arithmetic note: ~333 events/s sustained before it starts trailing). |
| `feeder_enabled` | `0` means the `usage_feeder_enabled` tar_config key is off — the fold does not run row-count checks that assume the feeder found rows to close (advisory only; not itself a gap). |

### `last_used`

Per-`exe_key` last/first-seen (all-time) plus a trailing-30-day `run_count`/
`total_seconds` window; an optional `exe=<key>` param narrows to one executable,
normalised the same way. Row shape (`format_last_used_row`):

```
last_used|<exe_key>|<last_seen>|<first_seen>|<run_count_30d>|<total_seconds_30d>
```

### `foreground`

Always reports `UNAVAILABLE`/constrained — this source does not capture
per-session focus-time attribution on any platform today. Real emitted output
(`app_usage.dylib`, this Mac):

```
constrained|foreground_not_captured|user-context-bridge roadmap (session-scope attribution)
```

(exit code 1.) Reserved for the `user-context-bridge` roadmap, which is expected
to fill this in without a schema change once session-scope attribution lands.

## Gating: the `Forensics` securable

All three actions are `Forensics:Read`, `RiskTier::Medium`,
`ExecuteGate::AdminOrApproval` — **Administrator by default**; `Forensics` is
deliberately absent from the Viewer read-list (a forensic read, even with names
redacted, is never a Viewer-tier operation). `Forensics` rows are also
**single-target**: exactly one explicit, in-scope `agent_id` — no `scope` key,
including `"__all__"` — is accepted; a fan-out request is refused with a distinct
message from the ordinary Destructive-class refusal. A targeted request that
passes is still confined to the caller's management-group scope, so a
per-executable usage read can never reach an agent outside the operator's visible
set.

## Server-side projection: `app_usage`

A daily-sync source (agent → server) centralises the trailing-30-day window per
executable so it outlives the agent's local retention and is queryable without
reaching the endpoint. The agent reports a hash of the raw sync blob (SHA-256 over
the received bytes, never re-derived from parsed rows) so an unchanged window is
skipped rather than resent every cycle — the same hash-skip discipline
`software_licensing` uses.

The server store (`app_usage_store`: `usage_state` + `agent_last_used`) is read via:

- REST: `GET /api/v1/forensics/agents/{agent_id}/app-usage`
- MCP tool: `get_agent_app_usage`

Both are gated on the same scoped `Forensics:Read` gate and audited per access
(`app_usage.agent.view`). Sample response (identical shape on both surfaces):

```json
{
  "agent_id": "agent-9",
  "apps": [
    {
      "exe_key": "chrome.exe",
      "first_seen": 1699000000,
      "last_seen": 1700000500,
      "run_count_30d": 12,
      "total_seconds_30d": 43200
    }
  ],
  "collected_at": 1700000600
}
```

An empty result (agent has no rows) is a genuine `200` with `apps: []` —
never conflated with a store/pool degrade, which answers `503` instead.

## Decommission and erasure

`AppUsageStore::delete_agent` clears both `usage_state` and `agent_last_used`
for an agent in one transaction — dropping only one of the two would leave the
hash-skip state pointed at a hash the deleted rows no longer match, so the
projection would never repopulate on the still-enrolled agent's next sync.

`app_usage_store` **is erased** by `DELETE /api/v1/sle/agents/{id}` — the
whole-device agent-decommission cascade. `app_usage` is the cascade's sixth
store, alongside `inventory`, `software_inventory`, `device_inventory`,
`app_perf_daily`, and `software_licensing`. The route is gated on the
per-device-scoped **`Decommission:Delete`** securable (Administrator and
ITServiceOwner by default), which replaces the cascade's earlier per-store
securable conjunction (ADR-0024 Decision 9, as amended Wave 7 PR7.2).
`Forensics` governs this store's READ route only — it plays no part in the
erasure gate. The delete runs inside the same two-table single-transaction
contract described above, and the cascade reports each store's committed
status: a rolled-back delete is reported failed, never a false erasure.

**Still open (accepted risk, Alex 2026-09-06):** the cascade only erases a
*whole device* — there is no row-level / per-subject erasure path for
`app_usage` data (agent-side `usage_daily`/`usage_live`, or the server-side
`agent_last_used` projection) short of that. This is the same pre-existing
gap tracked for every other usage-class store in the fleet (#1666) — not a
new one introduced by this source. A dedicated PII-classification ADR
covering per-subject DSAR and retention policy for usage-class TAR data (and
this projection) is proposed as a follow-up (see
`docs/wave7/followup-issue-app-usage-pii-adr.md`), not built in this release.
