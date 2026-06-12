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

## The four views

DEX is organised as a **hub** (the Overview at `/dex`) that *summarises and
links* into three deep pages. A shared sub-nav switches between **Overview ·
Catalogue · Health score · Trends**; the window selector (below) applies to all
four.

### Overview (the hub)

An at-a-glance executive summary that routes into the deep pages — it summarises
and links, it does not duplicate their detail.

- **Headline reliability (measured, not a score).** Four tiles of
  industry-standard *measured rates*, never a synthetic 0–100 number:
  - **Crash-free devices %** — the share of reporting Windows devices with no app
    crash in the window.
  - **Crashes / 1,000 device-days** — crash frequency normalised by fleet size
    and window length.
  - **Devices impacted** — distinct devices with a crash in the window.
  - **Agents reporting** — the count of currently-reporting agents. This is the
    honest stand-in for "telemetry coverage": a device we can't hear from is
    *unknown*, not healthy, so DEX shows the reporting count rather than
    fabricate a coverage percentage from a fleet size it doesn't know.

  The rates are computed over **currently-reporting Windows agents only** (the
  OS with the most complete collector). Offline agents are *excluded* from the
  denominator, not counted as healthy — so the number can't be inflated by
  broken telemetry. When no agents are reporting, the tile honestly shows **—**
  rather than a fabricated rate.
- **Explore cards** open the three deep pages, each with a live teaser figure.
- **Crashes per day**, then **top crashing apps** (with blast radius)
  side-by-side with **most-affected devices**, and a **by-operating-system**
  summary whose *signal scope* ("N of the monitored types") is derived live so a
  narrower-coverage OS is never mistaken for a healthier one.

### Catalogue

Every monitored signal type, organised into 12 families (App reliability,
Boot/start-up & shutdown, Service health, System stability, Hardware & storage,
File system, Network, Identity & logon, Security & protection, Updates &
installs, Policy & management, Printing). A family card shows how many of its
types are active; opening a family lists **every** type — one that fired shows
its event and device counts, a quiet one shows a dashed zero, because
**monitored, nothing happened** is real information, not a gap. (Signal sources
that don't exist on a given OS or SKU simply stay at zero on those endpoints.)
Each type drills into a per-type view: top subjects, the live OS split, the
most-affected devices, and an activity trend. Any signal a newer agent emits
that isn't catalogued yet appears under **Other**, so nothing the fleet reports
is hidden.

### Health score

A **transparent, secondary** composite (0–100) derived from the measured rates —
explicitly *not* the headline (the measured crash-free % stays primary). The
score is `100 − Σ weighted deductions`, and the page shows the full
decomposition: the per-family deductions and the weighting preset in force
(default / stability / productivity / security). With no reporting agents the
score is **suppressed**, never a fabricated 100.

### Trends

Cross-OS comparison cards — each carrying its **live signal scope**, so an OS
with a narrower collector reads as *less observed*, not healthier — plus
per-family small-multiple sparklines and a family×day activity heatmap.

**Window selector.** `24h / 7d / 30d / All` rescopes every view. Drill-downs
opened from a panel inherit the window you were viewing, so the numbers match.

## Drill-downs

- **Per-application** — click an app to see its crash/hang blast radius across
  the fleet: faulting modules, exception codes, and which devices are affected.
- **Per-device** — click a device to see its unified signal history (every
  signal type on one timeline, with friendly labels).
- **Per-signal-type** — from the Catalogue, open any type for its top subjects,
  live OS split, most-affected devices, and trend.

> **Per-device history is behavioral data.** A device's signal history reveals
> which applications a person runs. Access is gated on `GuaranteedState:Read`
> and **every open is audit-logged** (`dex.device.view`). The same audit applies
> to the agent-scoped REST query `GET /api/v1/guaranteed-state/events?agent_id=…`.
> See the works-council / co-determination posture in
> `docs/enterprise-readiness-soc2-first-customer.md`.

## Agentic access (REST)

Every aggregation on this page has a machine-readable equivalent under
`/api/v1/dex/*` so an agentic worker sees the same DEX read-model the dashboard
does (agentic-first parity):

- **`GET /api/v1/dex/signals`** — the Catalogue rollup (every signal in the
  window: count, blast radius, last seen).
- **`GET /api/v1/dex/scope`** — the per-OS signal coverage that drives the
  cross-OS captions.
- **`GET /api/v1/dex/signals/{obs_type}`** — one signal's drill-down (subjects,
  OS split, most-affected devices, per-day trend).

All three take a `window` of `24h`/`7d`/`30d`/`all` and are gated on
`GuaranteedState:Read`. The per-signal drill-down returns a most-affected
**devices** list (behavioral) and is **audit-logged** (`dex.signal.view`) on
every call, exactly like the dashboard view; the rollup and scope are fleet
aggregates and are not audited. Full request/response shapes are in
[`rest-api.md`](rest-api.md#dex-digital-employee-experience).

## Platform coverage

The **Windows** collector is the most complete — it covers the full Windows
signal catalogue. Alongside the event-log observer, Windows also runs a
**state poll** that emits `storage.low` (a fixed volume ≥90% full or under
5 GiB free) and battery health (`hw.error`, when full-charge capacity drops
below 80% of design) — the same two signals, and the same thresholds, the
macOS collector emits, so they render identically across both platforms. A
**macOS** collector ships too, but is deliberately *limited*: an unprivileged
collector that reuses the same OS-neutral signal types and covers roughly ten
of the eleven experience headings (crashes and hangs, resource pressure,
service failures, boot/resume reports, storage pressure, battery health, and
more). **Linux** endpoints report no DEX signals yet — a collector is a
planned follow-up. Because the by-OS and cross-OS views
label each OS with its live *signal scope*, a fleet running a narrower collector
reads as **less observed**, never as healthier; the rates are read *within* an
OS, never across. The exact macOS source mapping — and what additional fidelity
the Endpoint Security Framework or other entitlements would unlock — is in
[`docs/dex-signal-catalog.md`](../dex-signal-catalog.md).

## Fleet incident alerts (blast radius)

Beyond the per-signal drill-downs, the server watches for a single failure
*spreading across the fleet*. When **≥5 distinct devices** report the same DEX
signal — the same `obs_type` **and** the same subject (e.g. `process.crashed` /
`chrome.exe`) — within a **15-minute** sliding window, it raises a fleet
incident. Detection runs at the shared observation ingest point, so both
directly-connected and gateway-routed agents contribute, and the window uses
server receipt time (an agent with a skewed clock cannot smear it).

Each incident fires two things:

- an **operator notification** (dashboard bell, severity `warn`), and
- a **`dex.blast_radius`** webhook / offload event you can subscribe to so an
  ITSM auto-opens the incident.

`dex.blast_radius` payload:

| Field | Meaning |
|---|---|
| `obs_type` | the signal type (e.g. `process.crashed`) |
| `subject` | the failing entity (e.g. `chrome.exe`; empty for subject-less signals) |
| `device_count` | distinct devices that reported the pair within the window |
| `window_seconds` | the detection window (900 for the 15-minute default) |

A standing incident re-alerts at most once per hour (per-pair cooldown), and a
global per-minute fan-out cap keeps a correlated multi-subject incident (e.g. a
bad update crashing many apps at once) from flooding your ITSM. The thresholds
(5 devices / 15 min / 1 h) are fixed in this release; operator-configurable
thresholds are a planned follow-up. Detector activity is observable via the
`yuzu_server_dex_blast_radius_*` Prometheus metrics. Subscribe to the event in
[Webhooks](rest-api.md#event-subscriptions-webhooks).

## Turning it off

DEX collection is a **deploy-time agent setting**. Start the agent with
**`--dex-disable`** (or `YUZU_AGENT_DEX_DISABLE=1`) and that endpoint arms no
observer and sends no DEX telemetry of any kind. **Note:** `--dex-disable` turns
off the DEX event observer and the Windows state poll, but the TAR performance
sampler is a separate subsystem — disable it with `perf_enabled=false` (see
[TAR configuration](tar.md#configuration)). There is no server-side runtime
toggle today; per-category collection toggles and an individual-view kill switch
are named roadmap items (see the enterprise-readiness plan).

## No mock data

Every view renders real aggregations or an explicit "no data" placeholder —
never sample or fabricated values. A zero is a measured zero, and a rate with no
denominator shows **—**, not a guess.

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
