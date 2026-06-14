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
| TCP retransmission | Median device **interval** retransmit rate — ΔΣretransmits / ΔΣsegments smoothed over the last few heartbeats (loss in the recent window, **not** a lifetime average) |
| Throughput (device) | Median device rx+tx bytes/s, non-loopback interfaces |
| Reporting | Devices whose latest heartbeat carried at least one network fact |

Every aggregate carries its reporting population. **RTT carries its own
(smaller) denominator** — devices that do not report smoothed RTT are excluded
from the RTT numbers, never counted as 0 ms.

> **RTT is a coarse signal.** It is a device-aggregate median across whatever TCP
> connections are open (loopback / LAN / internet blended together), so read it
> as a rough indicator, not per-flow truth. Actionable per-destination /
> per-app latency is a later (warehouse-tier) slice.

### Why this is device / local-link health, not localization

The interval retransmit rate is a **device-aggregate** signal: a bad *local*
link (Wi-Fi, congested uplink) drives loss across every connection, so the
device-wide rate flags it cleanly. It deliberately **cannot** say *which*
destination or app is affected — that localization ("is it the network, the
device, or the app?") is the deferred per-destination warehouse drill.

### Degraded classification & co-occurrence — a later slice

v1 is **measurement-first**: it surfaces the interval retransmit rate as
evidence but does **not** yet classify a device as *network-degraded*. A
trustworthy threshold needs a real-fleet baseline — healthy internet links
retransmit a little, so the cutoff cannot be guessed (a value tuned on a
loss-free link would cry wolf on every normal device). The earlier
absolute-lifetime-ratio degraded signal was empirically disproven (it is diluted
to noise) and has been retired.

The **co-occurrence headline** — "of the network-degraded devices, how many also
show device-perf pressure or app instability" — is gated on that classification,
so it lands in the same later slice. Until then the page is honest evidence, not
a verdict. The co-occurrence model (`NetCooccurrence`) and the
`yuzu_fleet_net_degraded` gauge stay wired but unfed (the gauge reads 0 =
"not classified", never "0 degraded = healthy").

## Devices tab

Lists devices worst-by-metric (RTT, retransmit, or throughput), or filtered to a
co-occurrence band or to not-reporting devices, with the co-occurring
device/app facts flagged inline. Each row links to the device drill-down.

## Platform coverage (v1)

| Platform | RTT | Retransmit | Throughput |
|---|---|---|---|
| Linux | Full — netlink `INET_DIAG` per-connection `TCP_INFO` | Yes | Yes (`/proc/net/dev`) |
| Windows | Not yet | Not yet | Not yet |
| macOS | Not yet | Not yet | Not yet |

**Today only Linux agents emit network facts.** Windows and macOS agents emit
*nothing* yet — their collectors are later slices (the Windows ESTATS-vs-ETW
mechanism is a spike) — so the dashboard currently reflects the Linux fleet.
Absent metrics are always omitted from rollups; a device that does not report a
metric is excluded from that metric's denominator, never counted as zero.

## Collection & privacy

Only **device-aggregate** facts leave the endpoint on the heartbeat — median
RTT, the interval retransmit rate, and device throughput. **No per-connection or
per-destination data leaves the device on the heartbeat.** Network sampling
shares the agent's `--dex-disable` flag — disabling DEX disables the network
heartbeat facts.

### Per-connection tier (opt-in, off by default)

A separate **`netqual`** TAR capture source can record per-connection TCP
quality — smoothed RTT, jitter, and current-loss counters per ESTABLISHED
connection, joined to the owning process — into the agent's **local edge
warehouse** as `$NetQual_Live`. It is governed independently of the heartbeat:

- **Off by default.** Set the agent TAR config key **`netqual_enabled = true`**
  to enable it (mirrors `procperf_enabled`; per-connection telemetry is
  usage-class data under the works-council posture, so it is never on by
  default).
- **Bucket-only.** Only a coarse destination *class* — `loopback` / `private` /
  `public` — is stored. The raw remote address, port, and hostname are dropped
  at the collector edge and **never persisted**. The owning process is recorded
  as its image name only.
- **On-device.** These rows stay in the local warehouse (queryable via the
  Execute-gated TAR SQL surface as `$NetQual_Live`); they are not shipped to the
  server. A per-tick top-N cap and a row-count retention ceiling bound storage.
- **Linux only** in this version.

This tier has no dashboard consumer yet — it is the foundation for the deferred
per-destination drill. See the [TAR dashboard](tar.md) for the query surface.

## Metrics

The fleet gauges (`yuzu_fleet_net_*`) are documented in
[Metrics — Fleet network gauges](metrics.md#fleet-network-gauges). They are fed
from the same heartbeat facts as this page, via shared validators, so the gauges
and the dashboard cannot disagree.
