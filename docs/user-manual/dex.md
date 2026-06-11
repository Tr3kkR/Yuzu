# DEX — Digital Employee Experience

The **DEX dashboard** (`/dex`) is a read-only fleet-reliability lens over the
Guardian event store. It reinterprets ruleless [signal observations](guaranteed-state.md#dex-signal-observations)
— app crashes and hangs, service failures, device stability, boot/resume
performance, network, sign-in, security, update, and printing problems — as a
picture of what the workforce actually experiences on their machines. It does
**not** author or enforce anything (that is [Guardian](guaranteed-state.md)); it
only reads and aggregates.

It is reached from the **DEX** link in the dashboard nav, or directly at
`/dex`. Access requires the **`GuaranteedState:Read`** permission.

## What you see

**Headline reliability (measured, not a score).** The top tiles are
industry-standard *measured rates*, not a synthetic 0–100 number:

- **Crash-free devices %** — the share of reporting Windows devices with no app
  crash in the window.
- **Crashes / 1,000 device-days** — crash frequency normalised by fleet size and
  window length.

Both are computed over **currently-reporting Windows agents only** (the only OS
with a collector today). Offline agents are *excluded* from the denominator, not
counted as healthy — so the number can't be inflated by broken telemetry. When
no agents are reporting, the tile honestly shows **—** rather than a fabricated
rate.

**All signals (grouped).** Every one of the monitored signal types is listed,
organised into groups (App reliability, Boot/start-up & shutdown, Service
health, System stability, Hardware & storage, File system, Network, Identity &
logon, Security & protection, Updates & installs, Policy & management, Printing).
A type that fired shows its event and device counts; a type that has been quiet
shows a dashed zero — **monitored, nothing happened** is real information, not a
gap. (Signal sources that don't exist on a given Windows SKU simply stay at zero
on those endpoints.)

**Panels.** App reliability (crashes + hangs per application, with blast
radius), boot/resume performance (average and slowest durations), a crash trend,
per-OS split, top faulting modules, and most-affected devices.

**Window selector.** `24h / 7d / 30d / All` rescopes every panel. Drill-downs
opened from a panel inherit the window you were viewing, so the numbers match.

## Drill-downs

- **Per-application** — click an app to see its crash/hang blast radius across
  the fleet: faulting modules, exception codes, and which devices are affected.
- **Per-device** — click a device to see its unified signal history (every
  signal type on one timeline, with friendly labels).

> **Per-device history is behavioral data.** A device's signal history reveals
> which applications a person runs. Access is gated on `GuaranteedState:Read`
> and **every open is audit-logged** (`dex.device.view`). The same audit applies
> to the agent-scoped REST query `GET /api/v1/guaranteed-state/events?agent_id=…`.
> See the works-council / co-determination posture in
> `docs/enterprise-readiness-soc2-first-customer.md`.

## Platform coverage

DEX collectors are **Windows-only** today. macOS and Linux endpoints report no
DEX signals — the dashboard says so inline, and their devices simply do not
contribute to the rates. macOS/Linux collectors are a planned follow-up.

## Turning it off

DEX collection is a **deploy-time agent setting**. Start the agent with
**`--dex-disable`** (or `YUZU_AGENT_DEX_DISABLE=1`) and that endpoint arms no
observer and sends no DEX telemetry of any kind. There is no server-side runtime
toggle today; per-category collection toggles and an individual-view kill switch
are named roadmap items (see the enterprise-readiness plan).

## No mock data

Every panel renders real aggregations or an explicit "no data" placeholder —
never sample or fabricated values. A zero is a measured zero.

## Recovery — empty or stale DEX projection

`guardian_observations` (the table behind `/dex`) is a **derived, forward-only
read model** projected from the Guardian event store; it holds no source data of
its own. If the server logs a stale-schema warning (a dev/UAT database that ran
a pre-release build) or the projection is otherwise corrupt, the projection
degrades safely — the underlying events are preserved and
`yuzu_server_guardian_proj_failures_total` rises — and recovery is:

1. Stop the server.
2. `sqlite3 <data-dir>/guaranteed-state.db "DROP TABLE guardian_observations;"`
3. Restart — the table is recreated empty and projection resumes **forward only**.

There is no automatic back-fill today: projected history before the drop is not
reconstructed (a back-fill script from the retained source events is a tracked
follow-up). The Guardian event store and rules are unaffected by this operation.

## Related documentation

- [Guaranteed State (Guardian)](guaranteed-state.md) — the underlying event
  store, the observer, and `--dex-disable`.
- [`docs/dex-signal-catalog.md`](../dex-signal-catalog.md) — the full
  signal catalogue (channels, event IDs, extracted fields, privacy
  minimisations, macOS source mapping).
- `docs/enterprise-readiness-soc2-first-customer.md` — behavioral-telemetry
  data inventory and works-council / DPA posture.
