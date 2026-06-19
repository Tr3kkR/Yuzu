# ADR-0010: Add ARP and DNS Capture Sources to the TAR Plugin

**Date:** 2026-06-19  
**Status:** Proposed  
**Component:** TAR (Telemetry, Acquisition, Response) — Capture Source Layer  
**Authors:** Alex (Security Architecture)

---

## Context

TAR currently captures four categories of host activity: processes, network connections (TCP), services, and user sessions. Forensic analysts investigating lateral movement, C2 communication, and host-based IOCs have identified two systemic gaps.

**ARP tables** are not captured. Without ARP state at the time of interest, analysts cannot reconstruct Layer 2 adjacency, confirm whether an IP was resolved to an expected MAC address, or detect ARP spoofing and poisoning. ARP poisoning is a well-documented precursor to MitM attacks in enterprise flat networks and is entirely invisible in current TAR artefacts.

**DNS resolution state** is not captured. Analysts regularly need to correlate process-initiated connections with the domain names that resolved to the contacted IPs. Without DNS cache data, attribution of a connection to a domain — and therefore to a threat actor or campaign — requires costly out-of-band reconstruction from SIEM or NDR logs, which may be incomplete or stale by the time a TAR investigation is underway.

Both gaps are standard collection targets in commercial EDR platforms. Adding them to TAR closes visibility that analysts currently expect to be present.

TAR's collection model is snapshot-and-diff at configurable intervals, with events written to a local SQLite database. Both ARP table enumeration and DNS cache reads are finite, read-only, low-frequency operations with well-understood upper bounds, making them compatible with this model and with the agent's memory constraints.

---

## Decision

We will add two new capture sources to the TAR plugin: `arp` and `dns`. Both follow the existing source pattern: a toggle flag, a collection interval assignment, warehouse table tiers, an OS compatibility matrix entry, and a `status` output block.

### Source: `arp`

Collects the host ARP table on each collection cycle by reading from the platform-appropriate interface:

- **Linux**: parses `/proc/net/arp`
- **Windows**: calls `GetIpNetTable2` (IP Helper API)
- **macOS**: uses `sysctl` with `NET_RT_FLAGS` / `RTF_LLINFO`

Because ARP tables represent current L2 state rather than event transitions, the snapshot-and-diff model records an `arp_entry_appeared` event when a new MAC-IP binding is observed and an `arp_entry_removed` event when one disappears. Static entries that are unchanged between snapshots generate no events, keeping the database compact.

**Warehouse tables:**

| Tier | Table | Retention |
|---|---|---|
| Live | `$ARP_Live` | 5,000 rows (ring buffer) |
| Hourly | `$ARP_Hourly` | 24 hours |

A daily tier is not warranted — ARP state is volatile and hourly aggregation is sufficient for retrospective investigation.

**Key columns (`$ARP_Live`):** `ts`, `interface`, `ip_address`, `mac_address`, `entry_type` (`dynamic`, `static`, `incomplete`, `other`), `action` (`appeared`, `removed`).

**Configuration:**

| Setting | Default | Description |
|---|---|---|
| `arp_enabled` | `true` | Toggle the ARP collector |
| `arp_interval` | assigned to `fast_interval` (60s) | ARP changes are time-sensitive; fast cadence is appropriate |

Memory bound: enterprise ARP tables rarely exceed 1,024 entries. The collector will enforce a hard cap of 2,048 entries per cycle and emit a truncation audit event (`{event_type: "arp.truncated", ...}`) if reached.

**OS compatibility:**

| Platform | Status | Notes |
|---|---|---|
| Linux | supported | `/proc/net/arp` — full interface/IP/MAC/type |
| Windows | supported | `GetIpNetTable2` — full interface/IP/MAC/type |
| macOS | constrained | `sysctl NET_RT_FLAGS` — MAC available; `entry_type` reported as `unknown` |

### Source: `dns`

Collects current DNS resolution state visible to the host on each collection cycle:

- **Linux**: queries `systemd-resolved` via the `resolve` D-Bus interface where available; falls back to parsing `/etc/hosts` and marking source accordingly. Hosts without `systemd-resolved` (Alpine, musl-libc environments) yield `hosts_file` entries only.
- **Windows**: calls `DnsGetCacheDataTable` to enumerate the DNS client resolver cache.
- **macOS**: invokes `dscacheutil -cachedump -entries Host` via subprocess.

The snapshot-and-diff model records `dns_entry_appeared` when a new resolution is observed and `dns_entry_removed` when one disappears from cache.

**Warehouse tables:**

| Tier | Table | Retention |
|---|---|---|
| Live | `$DNS_Live` | 5,000 rows (ring buffer) |
| Hourly | `$DNS_Hourly` | 24 hours |

**Key columns (`$DNS_Live`):** `ts`, `name`, `record_type` (`A`, `AAAA`, `CNAME`, `PTR`, etc.), `data`, `ttl_remaining_s`, `source` (`cache`, `hosts_file`, `unknown`), `action` (`appeared`, `removed`).

**Configuration:**

| Setting | Default | Description |
|---|---|---|
| `dns_enabled` | `true` | Toggle the DNS collector |
| `dns_interval` | assigned to `fast_interval` (60s) | DNS cache entries are short-lived; fast cadence reduces missed resolutions |

Memory bound: DNS resolver caches are bounded by the resolver's own limits. The collector will enforce a hard cap of 4,096 entries per cycle with a truncation audit event if reached.

**OS compatibility:**

| Platform | Status | Notes |
|---|---|---|
| Linux | constrained | `systemd-resolved` only; hosts without it yield `/etc/hosts` entries only |
| Windows | supported | `DnsGetCacheDataTable` — full name/type/data/TTL |
| macOS | constrained | `dscacheutil` subprocess — TTL not available; `ttl_remaining_s` reported as `-1` |

### Integration points

**`query` and `sql` actions:** both sources are queryable via `type: "arp"` / `type: "dns"` in the existing `query` action, and via `$ARP_Live`, `$ARP_Hourly`, `$DNS_Live`, `$DNS_Hourly` in `tar.sql`.

**`status` action:** adds `arp_enabled`, `arp_paused_at`, `arp_live_rows`, `arp_oldest_ts` and equivalent `dns_*` blocks to the status output, consistent with existing per-source blocks.

**`snapshot` action:** the immediate snapshot triggered by `tar.snapshot` will include ARP and DNS collection alongside the existing four sources.

**`compatibility` action:** ARP and DNS rows are added to the compatibility matrix returned at runtime.

**Metrics:** both sources emit `yuzu_agent_*` Prometheus metrics with `plugin=tar`, `source=arp` / `source=dns`, and `status` labels consistent with existing sources.

**Audit events:** truncation events use the standard envelope `{event_type, timestamp, source, payload}` with `event_type` of `tar.arp.truncated` and `tar.dns.truncated` respectively.