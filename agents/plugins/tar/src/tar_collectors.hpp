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

/// One installed-software entry, as enumerated for the `software` source diff.
/// `scope` is "machine" or "user"; `user` is the profile name for per-user
/// entries and empty for machine scope. The diff key is (scope, user, name);
/// a change in `version` for the same key is an 'upgraded' event.
struct SoftwareInfo {
    std::string name;
    std::string version;
    std::string publisher;
    std::string scope; // machine, user
    std::string user;  // profile name for per-user entries; '' for machine scope
    std::string install_date;
};

/// Result of a steady-state per-user scan (loaded hives only — no NTUSER.DAT
/// mounting). `entries` are the apps found; `scanned_users` is EVERY logged-on
/// profile that was read, even those with zero per-user apps — the caller needs
/// the full scanned set (not just users that happen to have entries) to decide
/// which logged-off users to carry forward, so an uninstall of a logged-on
/// user's last app is not masked by carry-forward.
struct LoadedUserScan {
    std::vector<SoftwareInfo> entries;
    std::vector<std::string> scanned_users;
};

// ── Platform enumeration functions ────────────────────────────────────────────

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
 * Full installed-software enumeration for the `software` source COLD-START
 * baseline only: machine-wide (HKLM Uninstall 64-bit + WOW6432Node 32-bit) plus
 * EVERY user profile (HKU\<SID> for loaded hives; mounting NTUSER.DAT for
 * logged-off profiles, capped at `max_hive_mounts` to bound the one-time I/O on
 * many-profile hosts — profiles beyond the cap are baselined lazily when their
 * user next logs on). Returns empty on Linux/macOS (kPlanned).
 *
 * Steady-state ticks must NOT call this — they use enumerate_machine_software +
 * enumerate_loaded_user_software and carry forward logged-off users, so no hive
 * is mounted after the baseline (a logged-off user cannot install software).
 */
std::vector<SoftwareInfo> enumerate_software(int max_hive_mounts);

/** Machine-scope installed software only (HKLM 64-bit + WOW6432Node). Cheap,
 *  no hive mounts. Empty off Windows. */
void enumerate_machine_software(std::vector<SoftwareInfo>& out);

/** Per-user installed software for CURRENTLY-LOADED hives only (HKU\<SID>) — no
 *  NTUSER.DAT mounting. Returns the entries plus the full set of logged-on
 *  profiles scanned. Empty off Windows. */
LoadedUserScan enumerate_loaded_user_software();

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
 * Compute software install/uninstall diff.
 * Key: scope + user + name.
 * Detects installs (present in current, not previous), removals (present in
 * previous, not current), and upgrades (same key, different version — carries
 * prev_version). The diff is name-keyed, so a version bump is one 'upgraded'
 * event rather than a remove+install pair.
 */
std::vector<SoftwareEvent> compute_software_events(const std::vector<SoftwareInfo>& previous,
                                                   const std::vector<SoftwareInfo>& current,
                                                   int64_t timestamp, int64_t snapshot_id);

/**
 * Assemble the current installed-software snapshot for a STEADY-STATE tick.
 *
 * `machine_and_loaded` is machine-scope software plus the apps found in
 * currently-loaded user hives (from enumerate_machine_software +
 * enumerate_loaded_user_software, no NTUSER.DAT mounting). `scanned_users` is
 * EVERY logged-on profile that was read this tick (even those with zero apps).
 * `previous` is the last persisted snapshot.
 *
 * Logged-off users (scope=="user" and NOT in `scanned_users`) are carried
 * forward unchanged from `previous` — a logged-off user cannot install software,
 * so re-mounting their hive every tick is pure I/O. Because their entries are
 * then identical in `previous` and the returned snapshot, they yield no diff
 * events. Crucially, an uninstall by a *logged-on* user is NOT masked: their SID
 * is in `scanned_users`, so their (now-removed) entry is not carried forward.
 *
 * Pure (no registry I/O) so the carry-forward contract is unit-testable
 * off-Windows. Returns by value (the assembled `current` snapshot).
 */
std::vector<SoftwareInfo> assemble_steady_state_snapshot(
    const std::vector<SoftwareInfo>& previous,
    std::vector<SoftwareInfo> machine_and_loaded,
    const std::vector<std::string>& scanned_users);

} // namespace yuzu::tar
