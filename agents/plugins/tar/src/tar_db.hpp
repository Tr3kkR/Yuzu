#pragma once

/**
 * tar_db.hpp -- SQLite-backed Timeline Activity Record database
 *
 * Stores timestamped events (process births/deaths, network connections,
 * service state changes, user sessions) with snapshot IDs for correlation.
 *
 * Schema:
 *   tar_events — core event log (timestamp, type, action, detail_json, snapshot_id)
 *   tar_state  — last-known state per collector for diff computation
 *   tar_config — key/value config (retention_days, redaction patterns, etc.)
 *
 * Thread-safe: a std::mutex guards all sqlite3* operations.
 * Uses WAL mode, busy_timeout=5000, secure_delete=ON.
 */

#include <cstdint>
#include <expected>
#include <filesystem>
#include <mutex>
#include <string>
#include <vector>

struct sqlite3; // Forward declaration

namespace yuzu::tar {

struct TarEvent {
    int64_t id{0};            // row id (0 for new events)
    int64_t timestamp{0};     // epoch seconds
    std::string event_type;   // process, network, service, user
    std::string event_action; // started, stopped, connected, disconnected, state_changed,
                              // login, logout
    std::string detail_json;  // JSON object with type-specific details
    int64_t snapshot_id{0};   // groups events from same collection cycle
};

// ── Typed event structs for warehouse tables ────────────────────────────────

struct ProcessEvent {
    int64_t ts{0};
    int64_t snapshot_id{0};
    std::string action; // started, stopped
    uint32_t pid{0};
    uint32_t ppid{0};
    std::string name;
    std::string cmdline;
    std::string user;
};

struct NetworkEvent {
    int64_t ts{0};
    int64_t snapshot_id{0};
    std::string action; // connected, disconnected
    std::string proto;
    std::string local_addr;
    int local_port{0};
    std::string remote_addr;
    std::string remote_host;
    int remote_port{0};
    std::string state;
    uint32_t pid{0};
    std::string process_name;
};

struct ServiceEvent {
    int64_t ts{0};
    int64_t snapshot_id{0};
    std::string action; // started, stopped, state_changed
    std::string name;
    std::string display_name;
    std::string status;
    std::string prev_status;
    std::string startup_type;
    std::string prev_startup_type;
};

struct UserEvent {
    int64_t ts{0};
    int64_t snapshot_id{0};
    std::string action; // login, logout
    std::string user;
    std::string domain;
    std::string logon_type;
    std::string session_id;
};

/// One arp_live row (ADR-0011 — host ARP / neighbour table). One row per
/// appeared/removed transition of an (interface, ip_address, mac_address)
/// binding; `entry_type` is a value field, not part of the diff key.
struct ArpEvent {
    int64_t ts{0};
    int64_t snapshot_id{0};
    std::string action; // appeared, removed
    std::string iface;  // NB: 'interface' is a Win32 COM macro under full <windows.h>
    std::string ip_address;
    std::string mac_address;
    std::string entry_type; // dynamic, static, incomplete, other, unknown
};

/// One dns_live row (ADR-0011 — host DNS resolver-cache state, NOT per-process
/// queries). One row per appeared/removed transition of a (name, record_type,
/// data) resolution; `ttl_remaining_s` is a value field, not part of the diff
/// key (it decrements every tick). `source` ∈ {cache, hosts_file, unknown}.
struct DnsEvent {
    int64_t ts{0};
    int64_t snapshot_id{0};
    std::string action; // appeared, removed
    std::string name;
    std::string record_type; // A, AAAA, CNAME, PTR, ...
    std::string data;
    int64_t ttl_remaining_s{0};
    std::string source;
};

/// One perf_live row (BRD A1 — continuous device performance sampling).
struct PerfRow {
    int64_t ts{0};
    int64_t snapshot_id{0};
    double cpu_pct{0.0};
    double mem_used_pct{0.0};
    double commit_pct{0.0};
    int64_t disk_read_bps{0};
    int64_t disk_write_bps{0};
    int64_t disk_read_lat_us{0};
    int64_t disk_write_lat_us{0};
    int64_t net_rx_bps{0};
    int64_t net_tx_bps{0};
};

/// One procperf_live row (BRD A2 — top-N per-application samples). One row
/// per (tick, app); `name` is the image name only (never a command line).
struct ProcPerfRow {
    int64_t ts{0};
    int64_t snapshot_id{0};
    std::string name;
    int instances{0};
    double cpu_pct{0.0};
    int64_t ws_bytes{0};
};

/// One module_live row (M2 — image/DLL/driver load capture). `action` and
/// `signed_state` hold the warehouse tokens (module_action_token /
/// module_signed_token from tar_module_stream.hpp); `module_dir` is already
/// redacted of any user-profile prefix by the collector (redact_module_dir).
/// `module_name` is the loaded image basename only (names-only posture; the
/// directory is the deliberate, narrow exception — the search-order-hijack
/// signal). `signer` is the code-signing publisher / team id, "" if unknown.
struct ModuleRow {
    int64_t ts{0};
    int64_t snapshot_id{0};
    std::string action;       // loaded / unloaded / seed / blocked
    uint32_t pid{0};
    std::string process_name;
    std::string module_name;
    std::string module_dir;
    std::string signed_state; // signed / unsigned / invalid / revoked / unknown
    std::string signer;
    bool is_kernel{false};
};

/// One netqual_live row — per-connection TCP quality sample for the /network
/// warehouse tier (BRD Workstream E). Linux-first via netlink INET_DIAG
/// TCP_INFO, joined to the connection's owning process. One row per
/// (tick, connection); co-sampled with the `tcp` source so it shares the
/// snapshot_id and joins to process/perf on `ts`.
///
/// SIGNAL DISCIPLINE — `lost` is the CURRENT-loss gauge (tcpi_lost: segments
/// lost and not yet recovered AT SAMPLE TIME) and is the only field that moves
/// with current network conditions, so it is the degraded driver. `retrans`
/// and `segs_out` are LIFETIME-CUMULATIVE context only: a fresh loss burst
/// barely moves their ratio (diluted by all the historical clean segments),
/// which is exactly why the earlier device-aggregate retransmit signal was
/// empirically disproven — do NOT rebuild a "current loss" signal from their
/// ratio. Per-tick degraded = fraction of a device's rows with current loss,
/// computed server-side as a query (a later slice), never a heartbeat boolean.
///
/// PRIVACY — only `remote_bucket` (a coarse destination CLASS: loopback /
/// private / public / unknown — see remote_bucket() in tar_netqual.hpp) leaves
/// the connection's destination on the row; the raw remote address / hostname is
/// NOT stored in this tier. Collection is gated by its own opt-in toggle and a
/// per-tick top-N cap (collector slice).
struct NetQualRow {
    int64_t ts{0};
    int64_t snapshot_id{0};
    std::string proto;         // tcp, tcp6
    std::string remote_bucket; // destination class: loopback/private/public/unknown (never a raw IP)
    std::string process_name;  // owning process image name only
    int64_t rtt_us{0};         // smoothed RTT (tcpi_rtt), microseconds
    int64_t rtt_var_us{0};     // RTT variance / jitter (tcpi_rttvar), microseconds
    int64_t lost{0};           // CURRENT lost segments (tcpi_lost) — instantaneous degraded driver
    int64_t retrans{0};        // lifetime retransmits (tcpi_total_retrans) — context only
    int64_t segs_out{0};       // lifetime segments out (tcpi_segs_out) — context / denominator
    int64_t ca_state{0};       // tcpi_ca_state: 0=Open 1=Disorder 2=CWR 3=Recovery 4=Loss — a
                               // "struggling right now" gauge that HOLDS across a whole recovery
                               // episode (unlike tcpi_lost, which is gone within an RTT), so it
                               // survives a coarse poll cadence better. Captured to compare
                               // degraded-signal candidates before committing 4b.3's query.
};

/// Row from an arbitrary SQL query (used by tar.sql action).
using QueryRow = std::vector<std::string>;

struct QueryResult {
    std::vector<std::string> columns; // column names
    std::vector<QueryRow> rows;
};

struct TarStats {
    int64_t record_count{0};
    int64_t oldest_timestamp{0};
    int64_t newest_timestamp{0};
    int64_t db_size_bytes{0};
    int retention_days{7};
};

class TarDatabase {
public:
    /**
     * Open (or create) the TAR database at the given path.
     * Creates tables if they don't exist. Sets WAL mode, busy_timeout,
     * and secure_delete pragmas.
     */
    static std::expected<TarDatabase, std::string> open(const std::filesystem::path& path);

    ~TarDatabase();

    TarDatabase(TarDatabase&& other) noexcept;
    TarDatabase& operator=(TarDatabase&& other) noexcept;

    TarDatabase(const TarDatabase&) = delete;
    TarDatabase& operator=(const TarDatabase&) = delete;

    /**
     * Get database statistics.
     * Queries typed warehouse tables (process_live, tcp_live, etc.)
     */
    TarStats stats();

    // ── Snapshot state management ────────────────────────────────────────────

    /**
     * Get the last-known state JSON for a collector (e.g. "process", "network").
     * Returns empty string if no state is stored.
     */
    std::string get_state(const std::string& collector);

    /**
     * Store the last-known state JSON for a collector.
     * @return true on success; false if the write failed (e.g. SQLITE_BUSY /
     *         disk full / prepare error). Callers that must not proceed on a
     *         failed write (the #538 disable baseline-clear) check this;
     *         best-effort collector writes may ignore it.
     */
    bool set_state(const std::string& collector, const std::string& json);

    // ── Config management ────────────────────────────────────────────────────

    /**
     * Get a config value by key, with an optional default.
     */
    std::string get_config(const std::string& key, const std::string& default_val = "");

    /**
     * Set a config value.
     */
    void set_config(const std::string& key, const std::string& value);

    // ── Warehouse schema management ─────────────────────────────────────────

    /** Get the current schema version (0 = legacy-only, 2 = typed tables). */
    int schema_version();

    /** Create all typed warehouse tables from the schema registry. */
    bool create_warehouse_tables();

    // ── Typed inserts ───────────────────────────────────────────────────────

    bool insert_process_events(const std::vector<ProcessEvent>& events);
    bool insert_network_events(const std::vector<NetworkEvent>& events);
    bool insert_service_events(const std::vector<ServiceEvent>& events);
    bool insert_user_events(const std::vector<UserEvent>& events);
    bool insert_arp_events(const std::vector<ArpEvent>& events);
    bool insert_dns_events(const std::vector<DnsEvent>& events);
    bool insert_perf_sample(const PerfRow& row);
    bool insert_proc_perf_samples(const std::vector<ProcPerfRow>& rows);
    bool insert_netqual_samples(const std::vector<NetQualRow>& rows);
    bool insert_module_events(const std::vector<ModuleRow>& rows);

    /**
     * Return one row per unique (proto, local_addr, local_port, remote_addr,
     * remote_port, pid) ESTABLISHED connection observed at or after
     * `since_ts`. Each row's `ts` is set to MAX(ts) across observations of
     * that 5-tuple — i.e. the most recent time TAR saw the connection. Used
     * by `tar.fleet_snapshot` to widen the per-host viz from "currently
     * established at sample time" to "established within the rolling
     * window", so the viz draws blue tubes for connections that have
     * existed recently even if they're closed at the moment of the call.
     *
     * LISTEN / TIME_WAIT / CLOSE_WAIT / etc. are filtered out — they aren't
     * "this box talks to that box" edges.
     */
    std::expected<std::vector<NetworkEvent>, std::string>
    query_recent_tcp_connections(int64_t since_ts);

    // ── Generic SQL execution (for warehouse queries and aggregation) ────────

    /**
     * Execute TRUSTED, internally-constructed read-only SQL on the read-write
     * connection (NO authorizer). For internal callers ONLY — rollup / stats /
     * diff queries built from constants and integer-parsed values, never operator
     * or network input. For any UNTRUSTED operator SQL use execute_user_query
     * instead (#760). Enforces a maximum row limit to prevent agent DoS.
     */
    std::expected<QueryResult, std::string> execute_query(const std::string& sql,
                                                          int max_rows = 10000);

    /**
     * Execute UNTRUSTED operator SQL (the tar.sql action) in a sandbox: a
     * dedicated read-only SQLite connection with an authorizer that permits
     * only SELECT / READ of registry-known warehouse tables. Writes are
     * structurally impossible (read-only handle); non-SELECT statements,
     * ATTACH/PRAGMA, unknown tables, and trailing statements are rejected at
     * prepare time. Fails closed (returns an error) if the sandbox connection
     * is unavailable. Callers must still pre-validate via
     * validate_and_translate_sql — this is defence in depth, not a substitute.
     * Recovery: if the read-only connection cannot be opened at startup it stays
     * unavailable for the process lifetime (fail closed); restart the agent to
     * retry.
     */
    std::expected<QueryResult, std::string> execute_user_query(const std::string& sql,
                                                               int max_rows = 10000);

    /**
     * Execute arbitrary DDL/DML SQL (for rollup inserts, retention deletes).
     * Returns true on success.
     */
    bool execute_sql(const std::string& sql);

    /**
     * Execute parameterized SQL with two int64 bind values.
     * Used by rollup engine for time-range-bounded aggregation.
     */
    bool execute_sql_range(const std::string& sql, int64_t from, int64_t to);

private:
    explicit TarDatabase(sqlite3* db);

    /// Internal set_config that assumes caller already holds mu_.
    void set_config_locked(const std::string& key, const std::string& value);

    sqlite3* db_{nullptr};
    // Read-only, authorizer-sandboxed connection used only by execute_user_query
    // for untrusted operator SQL (#760). Null if it could not be opened, in
    // which case user queries fail closed.
    sqlite3* query_db_{nullptr};
    std::mutex mu_;
    std::mutex query_mu_;
};

} // namespace yuzu::tar
