#pragma once

#include <sqlite3.h>

#include <cstdint>
#include <filesystem>
#include <optional>
#include <shared_mutex>
#include <string>
#include <vector>

namespace yuzu::server {

// Server-side storage for Yuzu Guardian — the "Guaranteed State" system.
// See docs/yuzu-guardian-design-v1.1.md §9.1 for the schema design.
//
// Responsibilities:
//   - Persist GuaranteedStateRule definitions (yaml_source is authoritative;
//     the denormalised columns are for indexing / listing / RBAC filtering).
//   - Persist GuaranteedStateEvent rows reported by agents (drift detected,
//     drift remediated, guard unhealthy, resilience escalated, etc.).
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
    int limit{100};
    int offset{0};
};

class GuaranteedStateStore {
public:
    explicit GuaranteedStateStore(const std::filesystem::path& db_path);
    ~GuaranteedStateStore();

    GuaranteedStateStore(const GuaranteedStateStore&) = delete;
    GuaranteedStateStore& operator=(const GuaranteedStateStore&) = delete;

    bool is_open() const;

    // Rule CRUD.
    bool create_rule(const GuaranteedStateRuleRow& row);
    bool update_rule(const GuaranteedStateRuleRow& row);
    bool delete_rule(const std::string& rule_id);
    std::optional<GuaranteedStateRuleRow> get_rule(const std::string& rule_id) const;
    std::vector<GuaranteedStateRuleRow> list_rules() const;

    // Event ingest + query.
    bool insert_event(const GuaranteedStateEventRow& row);
    std::vector<GuaranteedStateEventRow> query_events(const GuaranteedStateEventQuery& q = {}) const;

    std::size_t rule_count() const;
    std::size_t event_count() const;

private:
    sqlite3* db_{nullptr};
    mutable std::shared_mutex mtx_;

    void create_tables();
};

} // namespace yuzu::server
