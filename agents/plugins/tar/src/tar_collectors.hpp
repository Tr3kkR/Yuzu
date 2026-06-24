#pragma once

/**
 * tar_collectors.hpp -- Data types and diff engine for TAR collectors
 *
 * Defines the data structures for each collector type (process, network,
 * service, user session) and the diff functions that compare snapshots
 * to produce TarEvent records for births, deaths, and state changes.
 *
 * Diff algorithm: uses std::unordered_map with composite keys.
 *   - "Birth" = present in current but not in previous
 *   - "Death" = present in previous but not in current
 *   - "State change" = same key, different status field (services only)
 *
 * Command-line redaction: Before storing process events, cmdline is checked
 * against configurable glob patterns (default: *password*, *secret*, *token*,
 * *api_key*, *credential*). Matching cmdlines are replaced with
 * "[REDACTED by TAR]".
 */

#include "tar_db.hpp"
#include "tar_netqual.hpp" // TcpQualitySample (returned by collect_tcp_quality)

#include <yuzu/agent/process_enum.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace yuzu::tar {

// ── Collector data types ─────────────────────────────────────────────────────

struct NetConnection {
    std::string proto; // tcp, tcp6, udp, udp6
    std::string local_addr;
    std::string remote_addr;
    std::string remote_host; // reverse-DNS of remote_addr (resolved at collection time)
    int local_port{0};
    int remote_port{0};
    std::string state; // ESTABLISHED, LISTEN, etc.
    uint32_t pid{0};
    std::string process_name;
    // 0 = currently observed in /proc (live). >0 = observed in the TAR
    // warehouse N seconds ago; renderer can fade tubes older than live.
    // Wire-schema-gated emission: omitted when zero so old consumers and
    // pre-PR-9-pre snapshots stay byte-compatible (schema_minor 1 -> 2).
    int64_t last_seen_seconds_ago{0};
};

struct ServiceInfo {
    std::string name;
    std::string display_name;
    std::string status;       // running, stopped, etc.
    std::string startup_type; // automatic, manual, disabled
};

struct UserSession {
    std::string user;
    std::string domain;
    std::string logon_type; // interactive, remote, service
    std::string session_id;
};

// One host ARP / neighbour-table entry (ADR-0015). Snapshot type for the `arp`
// capture source; diffed into ArpEvent rows. Diff key = (interface, ip_address,
// mac_address); entry_type is a value field. All fields agent-controlled.
struct ArpEntry {
    std::string iface; // NB: 'interface' is a Win32 COM macro under full <windows.h>
    std::string ip_address;
    std::string mac_address;
    std::string entry_type; // dynamic, static, incomplete, other, unknown
};

// One host DNS resolver-cache entry (ADR-0015). Snapshot type for the `dns`
// capture source; diffed into DnsEvent rows. Diff key = (name, record_type,
// data); ttl_remaining_s is a value field (changes every tick, never keyed).
// The cache is system-wide and carries NO pid — there is no process attribution.
struct DnsEntry {
    std::string name;
    std::string record_type; // A, AAAA, CNAME, PTR, ...
    std::string data;
    int64_t ttl_remaining_s{0};
    std::string source; // cache, hosts_file, unknown
};

// ── Platform enumeration functions ────────────────────────────────────────────
//
// Adding a NEW capture source? Follow the core pattern these functions use
// (process/tcp/service/user, NOT the perf/procperf/netqual derived-metric tiers
// which are self-contained tar_<name>.{hpp,cpp}): collected type + enumerate_*()
// + compute_*_events() declared HERE, one tar_<source>_collector.cpp for the
// platform shell (no per-source header), diffs in tar_diff.cpp, row struct +
// insert_*_events in tar_db.{hpp,cpp}, one CaptureSourceDef in
// tar_schema_registry.cpp. Full recipe: docs/tar-implementer.md "Adding a
// capture source".

/** Enumerate active network connections on the current host. */
std::vector<NetConnection> enumerate_connections();

/**
 * Sample per-connection TCP quality (RTT + jitter + current loss + lifetime
 * retrans/segs context) for the netqual warehouse tier. Linux: netlink
 * SOCK_DIAG / INET_DIAG TCP_INFO over ESTABLISHED connections, owning process
 * resolved via the socket inode. Empty off Linux (Windows / macOS are kPlanned
 * — see the `netqual` source in the schema registry).
 *
 * Returns RAW remote addresses; the caller MUST pass the result through
 * select_netqual_rows (which buckets the address away) before persisting —
 * raw destinations never reach the warehouse.
 */
std::vector<TcpQualitySample> collect_tcp_quality();

/** Enumerate installed system services on the current host. */
std::vector<ServiceInfo> enumerate_services();

/** Enumerate active user sessions on the current host. */
std::vector<UserSession> enumerate_users();

/**
 * Enumerate the host ARP / neighbour table (ADR-0015). Windows: GetIpNetTable2
 * (AF_UNSPEC). Hard-capped at kArpEntryCap entries (a `spdlog::warn` is logged on
 * truncation). Returns `{}` off Windows until the Linux/macOS follow-ups land.
 */
std::vector<ArpEntry> enumerate_arp();

/**
 * Enumerate the host DNS resolver cache (ADR-0015). Windows: DnsGetCacheDataTable.
 * Hard-capped at kDnsEntryCap entries (warn on truncation). The cache is
 * system-wide (no process attribution). Returns `{}` off Windows for now.
 */
std::vector<DnsEntry> enumerate_dns();

/// Per-cycle collection caps (ADR-0015 §"Memory bound"). The collector resizes to
/// the cap and logs a truncation warning rather than growing unbounded.
inline constexpr std::size_t kArpEntryCap = 2048;
inline constexpr std::size_t kDnsEntryCap = 4096;

// ── Redaction ────────────────────────────────────────────────────────────────

/**
 * Check if a command line matches any redaction pattern.
 * Patterns use case-insensitive substring matching with the '*' prefix/suffix
 * stripped (e.g. "*password*" matches any cmdline containing "password").
 *
 * @param cmdline   The command line to check.
 * @param patterns  List of glob-like patterns (e.g. {"*password*", "*secret*"}).
 * @return true if the cmdline should be redacted.
 */
bool should_redact(const std::string& cmdline, const std::vector<std::string>& patterns);

/**
 * Apply redaction to a command line string.
 * If the cmdline matches any pattern, returns "[REDACTED by TAR]".
 * Otherwise returns the original cmdline.
 */
std::string redact_cmdline(const std::string& cmdline, const std::vector<std::string>& patterns);

/**
 * Default redaction patterns.
 */
inline const std::vector<std::string> kDefaultRedactionPatterns = {
    "*password*", "*secret*", "*token*", "*api_key*", "*credential*"};

// ── Diff functions ───────────────────────────────────────────────────────────

/**
 * Compute process diff between two snapshots.
 * Detects process births (started) and deaths (stopped).
 * Key: PID (since PIDs are reused, name mismatch on same PID counts as
 * death + birth).
 * Command lines are redacted before storing in detail_json.
 *
 * @param previous    Previous process snapshot.
 * @param current     Current process snapshot.
 * @param timestamp   Epoch seconds for the events.
 * @param snapshot_id Correlating snapshot identifier.
 * @param redaction_patterns  Patterns for cmdline redaction.
 */
std::vector<TarEvent> compute_process_diff(
    const std::vector<yuzu::agent::ProcessInfo>& previous,
    const std::vector<yuzu::agent::ProcessInfo>& current, int64_t timestamp, int64_t snapshot_id,
    const std::vector<std::string>& redaction_patterns = kDefaultRedactionPatterns);

/**
 * Compute network connection diff.
 * Key: proto + local_addr + local_port + remote_addr + remote_port.
 * Detects new connections (connected) and closed connections (disconnected).
 */
std::vector<TarEvent> compute_network_diff(const std::vector<NetConnection>& previous,
                                           const std::vector<NetConnection>& current,
                                           int64_t timestamp, int64_t snapshot_id);

/**
 * Compute service diff.
 * Key: service name.
 * Detects service births (started), deaths (stopped), and state changes
 * (status or startup_type changed).
 */
std::vector<TarEvent> compute_service_diff(const std::vector<ServiceInfo>& previous,
                                           const std::vector<ServiceInfo>& current,
                                           int64_t timestamp, int64_t snapshot_id);

/**
 * Compute user session diff.
 * Key: user + session_id.
 * Detects logins (login) and logouts (logout).
 */
std::vector<TarEvent> compute_user_diff(const std::vector<UserSession>& previous,
                                        const std::vector<UserSession>& current, int64_t timestamp,
                                        int64_t snapshot_id);

// ── Typed event diff functions (for warehouse live tables) ──────────────────

std::vector<ProcessEvent> compute_process_events(
    const std::vector<yuzu::agent::ProcessInfo>& previous,
    const std::vector<yuzu::agent::ProcessInfo>& current, int64_t timestamp, int64_t snapshot_id,
    const std::vector<std::string>& redaction_patterns = kDefaultRedactionPatterns);

std::vector<NetworkEvent> compute_network_events(const std::vector<NetConnection>& previous,
                                                 const std::vector<NetConnection>& current,
                                                 int64_t timestamp, int64_t snapshot_id);

std::vector<ServiceEvent> compute_service_events(const std::vector<ServiceInfo>& previous,
                                                 const std::vector<ServiceInfo>& current,
                                                 int64_t timestamp, int64_t snapshot_id);

std::vector<UserEvent> compute_user_events(const std::vector<UserSession>& previous,
                                           const std::vector<UserSession>& current,
                                           int64_t timestamp, int64_t snapshot_id);

/**
 * Compute ARP diff. Key: interface + ip_address + mac_address.
 * Detects bindings that appeared (`appeared`) and disappeared (`removed`). A
 * changed entry_type on an otherwise-identical binding is NOT an event (value
 * update only), so a flapping dynamic/static flag does not churn the warehouse.
 */
std::vector<ArpEvent> compute_arp_events(const std::vector<ArpEntry>& previous,
                                         const std::vector<ArpEntry>& current,
                                         int64_t timestamp, int64_t snapshot_id);

/**
 * Compute DNS-cache diff. Key: name + record_type + data.
 * Detects resolutions that appeared (`appeared`) and aged out (`removed`). The
 * ttl_remaining_s value is carried on the row but excluded from the key, so the
 * per-tick TTL decrement does not produce spurious appeared/removed churn.
 */
std::vector<DnsEvent> compute_dns_events(const std::vector<DnsEntry>& previous,
                                         const std::vector<DnsEntry>& current,
                                         int64_t timestamp, int64_t snapshot_id);

} // namespace yuzu::tar
