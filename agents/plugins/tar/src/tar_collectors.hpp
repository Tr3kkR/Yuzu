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

#include <yuzu/agent/process_enum.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace yuzu::tar {

// ── Collector data types ─────────────────────────────────────────────────────

struct NetConnection {
    std::string proto;        // tcp, tcp6, udp, udp6
    std::string local_addr;
    std::string remote_addr;
    int local_port{0};
    int remote_port{0};
    std::string state;        // ESTABLISHED, LISTEN, etc.
    uint32_t pid{0};
    std::string process_name;
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
    std::string logon_type;   // interactive, remote, service
    std::string session_id;
};

// ── Platform enumeration functions ────────────────────────────────────────────

/** Enumerate active network connections on the current host. */
std::vector<NetConnection> enumerate_connections();

/** Enumerate installed system services on the current host. */
std::vector<ServiceInfo> enumerate_services();

/** Enumerate active user sessions on the current host. */
std::vector<UserSession> enumerate_users();

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
    const std::vector<yuzu::agent::ProcessInfo>& current,
    int64_t timestamp, int64_t snapshot_id,
    const std::vector<std::string>& redaction_patterns = kDefaultRedactionPatterns);

/**
 * Compute network connection diff.
 * Key: proto + local_addr + local_port + remote_addr + remote_port.
 * Detects new connections (connected) and closed connections (disconnected).
 */
std::vector<TarEvent> compute_network_diff(
    const std::vector<NetConnection>& previous,
    const std::vector<NetConnection>& current,
    int64_t timestamp, int64_t snapshot_id);

/**
 * Compute service diff.
 * Key: service name.
 * Detects service births (started), deaths (stopped), and state changes
 * (status or startup_type changed).
 */
std::vector<TarEvent> compute_service_diff(
    const std::vector<ServiceInfo>& previous,
    const std::vector<ServiceInfo>& current,
    int64_t timestamp, int64_t snapshot_id);

/**
 * Compute user session diff.
 * Key: user + session_id.
 * Detects logins (login) and logouts (logout).
 */
std::vector<TarEvent> compute_user_diff(
    const std::vector<UserSession>& previous,
    const std::vector<UserSession>& current,
    int64_t timestamp, int64_t snapshot_id);

} // namespace yuzu::tar
