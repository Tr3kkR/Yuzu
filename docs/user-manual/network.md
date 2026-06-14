# Network Quality Dashboard

The `/network` dashboard is a continuous, fleet-wide view of TCP network
**quality**, measured on each agent endpoint from kernel counters. No packet
capture, no flow export, and no central network appliance is required — the
measurement happens at the edge and only thin, device-aggregate facts leave the
device.

It is deliberately *not* a network-appliance clone: because network quality is
measured on the same box as device performance and process/service activity, the
dashboard can show whether a network-degraded device *co-occurs* with a device
or app problem — something a network-only tool cannot do.

## Access

Navigate to **Network** in the top navigation bar, or go to `/network` directly.
Permission required: **`GuaranteedState:Read`** (the same permission that gates
the Guardian and DEX read surfaces).

## Overview tab

Four fleet-now cards, updated each heartbeat cycle:

| Card | Metric |
|---|---|
| Round-trip time | Median smoothed RTT across active TCP connections (p50 / p90 / max) |
| TCP retransmission | Median retransmit ratio across active TCP connections |
| Throughput (device) | Median device rx+tx bytes/s, non-loopback interfaces |
| Reporting | Devices whose latest heartbeat carried at least one network fact |

Every aggregate carries its reporting population. **RTT carries its own
(smaller) denominator** — devices that do not report smoothed RTT (Windows today)
are excluded from the RTT numbers, never counted as 0 ms.

### Co-occurrence panel

The co-occurrence panel counts how many **network-degraded** devices also have
another problem happening **at the same time on the same device**:

- **also under device perf pressure** — CPU, memory, or disk also elevated
- **no device-perf pressure** — degraded network with no device-perf signal
- **also showing app instability** — *pending* (arrives with the per-connection
  collector slice; shown as `pending`, never a fabricated count)

This is a **measured count, not a causal verdict.** "Also under device pressure"
means those two facts co-occurred; it does *not* assert that device pressure
caused the network slowness. Clicking a band opens the Devices drill filtered to
it.

## Devices tab

Lists devices worst-by-metric (RTT, retransmit, or throughput), or filtered to a
co-occurrence band or to not-reporting devices, with the co-occurring
device/app facts flagged inline. Each row links to the device drill-down.

## Platform coverage (v1)

| Platform | RTT | Retransmit | Throughput |
|---|---|---|---|
| Linux | Full — netlink `INET_DIAG` per-connection `TCP_INFO` | Yes | Yes (`/proc/net/dev`) |
| Windows | Pending (ESTATS/ETW) — absent, not zero | Partial | Pending |
| macOS | Deferred | Deferred | Deferred |

Absent metrics are always omitted from rollups; a device that does not report a
metric is excluded from that metric's denominator, never counted as zero.

## Collection & privacy

Only **device-aggregate** facts leave the endpoint — median RTT, retransmit
ratio, device throughput, and a `degraded` boolean. **No per-connection or
per-destination data** (remote addresses, ports, hostnames) is collected or
transmitted in this version; per-destination collection, with its own opt-in,
is a later slice. Network sampling shares the agent's `--dex-disable` flag —
disabling DEX disables the network heartbeat facts.

## Metrics

The fleet gauges (`yuzu_fleet_net_*`) are documented in
[Metrics — Fleet network gauges](metrics.md#fleet-network-gauges). They are fed
from the same heartbeat facts as this page, via shared validators, so the gauges
and the dashboard cannot disagree.
