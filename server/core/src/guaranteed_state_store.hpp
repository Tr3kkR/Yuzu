#pragma once

#include <sqlite3.h>

#include <atomic>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <shared_mutex>
#include <string>
#include <thread>
#include <vector>

namespace yuzu::server {

// Server-side storage for Yuzu Guardian — the "Guaranteed State" system.
// See docs/yuzu-guardian-design-v1.1.md §9.1 for the schema design.
//
// Responsibilities:
//   - Persist GuaranteedStateRule definitions (yaml_source is authoritative;
//     the denormalised columns are for indexing / listing / RBAC filtering).
//     Caller (REST handler in PR 2+) is responsible for deriving the
//     denormalised fields (severity / os_target / scope_expr) from
//     yaml_source atomically on create/update — the store does NOT re-parse.
//   - Persist GuaranteedStateEvent rows reported by agents (drift detected,
//     drift remediated, guard unhealthy, resilience escalated, etc.).
//   - Reap expired events via a background cleanup thread (mirrors
//     AuditStore) so multi-GB/day ingest during a fleet-wide incident does
//     not fill the data directory.
//
// Events are an **immutable audit-style log** — intentionally no foreign key
// from `guaranteed_state_events.rule_id` to `guaranteed_state_rules(rule_id)`.
// When a rule is deleted, its historical events remain for forensic review
// (matches `audit_store`'s retention discipline). Time-based expiry is the
// single retention mechanism — operators control lifetime with the
// `retention_days` constructor argument, not rule deletion cascades.
//
// This store is intentionally write-heavy on events and read-heavy on rules.
// SQLite full-mutex + WAL is the same pattern the other stores use.

struct GuaranteedStateRuleRow {
    std::string rule_id;           // UUID
    std::string name;              // unique, human-authored
    std::string yaml_source;       // verbatim YAML, authoritative
    int64_t version{1};
    bool enabled{true};
    std::string enforcement_mode;  // "enforce" | "audit" | "disabled"
    std::string severity;          // "critical" | "high" | "medium" | "low"
    std::string os_target;         // "windows" | "linux" | "macos" | ""=all
    std::string scope_expr;        // server-side scope expression
    std::vector<uint8_t> signature;// HMAC-SHA256 over yaml_source
    std::string created_at;        // ISO-8601
    std::string updated_at;        // ISO-8601
    // Principal who authored the rule (created_by) and who last modified it
    // (updated_by). Required for SOC 2 audit-chain reconstruction alongside
    // audit_events — the REST handler in PR 2 populates both from the
    // session principal; the store is a plain passthrough.
    std::string created_by;
    std::string updated_by;
};

struct GuaranteedStateEventRow {
    std::string event_id;          // UUID
    std::string rule_id;
    std::string agent_id;
    std::string event_type;        // "drift.detected" | "drift.remediated" | ...
    std::string severity;
    std::string guard_type;        // "registry" | "etw" | ...
    std::string guard_category;    // "event" | "condition"
    std::string detected_value;
    std::string expected_value;
    std::string remediation_action;
    bool remediation_success{false};
    int64_t detection_latency_us{0};
    int64_t remediation_latency_us{0};
    std::string timestamp;         // ISO-8601
};

struct GuaranteedStateEventQuery {
    std::string rule_id;           // filter by rule, optional
    std::string agent_id;          // filter by agent, optional
    std::string severity;          // "critical" ... optional
    int limit{100};                // clamped to [1, kMaxEventsLimit] by the store
    int offset{0};
};

// Hard upper bound on `GuaranteedStateEventQuery::limit`. Defence-in-depth
// against a misconfigured or malicious caller: materialising millions of
// event rows into a std::vector would produce a GB-scale RSS spike. The
// REST layer (PR 2) may apply a tighter clamp on top.
inline constexpr int kMaxEventsLimit = 10'000;

// Default retention for `guaranteed_state_events`. Per the design's stated
// 10k events/s during a fleet-wide incident (~864M rows/day), unbounded
// retention fills the data directory within a day. 30 days matches the
// default for `audit_store` and is documented in the data inventory under
// workstream E. Override via the GuaranteedStateStore constructor.
inline constexpr int kDefaultEventRetentionDays = 30;

class GuaranteedStateStore {
public:
    explicit GuaranteedStateStore(const std::filesystem::path& db_path,
                                   int retention_days = kDefaultEventRetentionDays,
                                   int cleanup_interval_min = 60);
    ~GuaranteedStateStore();

    GuaranteedStateStore(const GuaranteedStateStore&) = delete;
    GuaranteedStateStore& operator=(const GuaranteedStateStore&) = delete;

    bool is_open() const;

    // Rule CRUD. Mutating methods return `std::expected<void, std::string>`.
    // Duplicate-UNIQUE collisions (name or rule_id) are reported as an error
    // prefixed with `kConflictPrefix` so REST handlers map them to HTTP 409
    // via `is_conflict_error()` — see `server/core/src/store_errors.hpp`.
    std::expected<void, std::string> create_rule(const GuaranteedStateRuleRow& row);
    std::expected<void, std::string> update_rule(const GuaranteedStateRuleRow& row);
    std::expected<void, std::string> delete_rule(const std::string& rule_id);
    std::optional<GuaranteedStateRuleRow> get_rule(const std::string& rule_id) const;
    std::vector<GuaranteedStateRuleRow> list_rules() const;

    // Event ingest + query.
    std::expected<void, std::string> insert_event(const GuaranteedStateEventRow& row);

    // Batch ingest: wraps all rows in a single transaction. At 10–50x the
    // per-row throughput (one fsync per batch instead of one per row), this
    // is the preferred path for the gRPC `GuaranteedStatePush` handler in
    // PR 2. On failure, the whole batch is rolled back — there is no
    // partial-success state. Returns the number of rows written on success.
    std::expected<std::size_t, std::string>
    insert_events(const std::vector<GuaranteedStateEventRow>& rows);

    std::vector<GuaranteedStateEventRow> query_events(const GuaranteedStateEventQuery& q = {}) const;

    std::size_t rule_count() const;
    std::size_t event_count() const;

    // Observability — lock-free cumulative counters for Prometheus scraping.
    // Cover the counts that a Prometheus alert on ingest health wants (bytes
    // or rows written, reaper activity) without forcing the collector to
    // issue a SQL `COUNT(*)` every scrape.
    uint64_t events_written_total() const noexcept { return events_written_.load(); }
    uint64_t events_reaped_total() const noexcept { return events_reaped_.load(); }

    void start_cleanup();
    void stop_cleanup();

private:
    sqlite3* db_{nullptr};
    int retention_days_;
    int cleanup_interval_min_;
    mutable std::shared_mutex mtx_;

    std::atomic<uint64_t> events_written_{0};
    std::atomic<uint64_t> events_reaped_{0};

#ifdef __cpp_lib_jthread
    std::jthread cleanup_thread_;
#else
    std::thread cleanup_thread_;
    std::atomic<bool> stop_requested_{false};
#endif

    void create_tables();
#ifdef __cpp_lib_jthread
    void run_cleanup(std::stop_token stop);
#else
    void run_cleanup();
#endif

    // Compute ttl_expires_at = now + retention_days*86400 in epoch seconds;
    // retention_days <= 0 means "never expire" (returns 0, the sentinel the
    // reaper's `WHERE ttl_expires_at > 0` clause excludes).
    int64_t compute_ttl_epoch() const;
};

} // namespace yuzu::server
