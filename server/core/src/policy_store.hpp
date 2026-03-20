#pragma once

#include <sqlite3.h>

#include <cstdint>
#include <expected>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server {

// ── Data types ───────────────────────────────────────────────────────────────

struct PolicyFragment {
    std::string id;
    std::string name;
    std::string description;
    std::string yaml_source;
    std::string check_instruction;
    std::string check_compliance;     // CEL expression (stored, evaluated later)
    std::string check_parameters;     // JSON of parameter bindings
    std::string fix_instruction;
    std::string fix_parameters;       // JSON of parameter bindings
    std::string post_check_instruction;
    std::string post_check_compliance;
    std::string post_check_parameters;
    int64_t created_at{0};
    int64_t updated_at{0};
};

struct PolicyTrigger {
    int64_t id{0};
    std::string policy_id;
    std::string trigger_type;  // "interval", "file_change", "event_log", etc.
    std::string config_json;   // type-specific config (e.g. {"interval_seconds": 300})
};

struct PolicyInput {
    std::string policy_id;
    std::string key;
    std::string value;
};

struct PolicyGroupBinding {
    std::string policy_id;
    std::string group_id;
};

struct Policy {
    std::string id;
    std::string name;
    std::string description;
    std::string yaml_source;
    std::string fragment_id;
    std::string scope_expression;
    bool enabled{true};
    int64_t created_at{0};
    int64_t updated_at{0};

    // Populated by query methods (not stored in policies table directly)
    std::vector<PolicyInput> inputs;
    std::vector<PolicyTrigger> triggers;
    std::vector<std::string> management_groups;
};

struct PolicyAgentStatus {
    std::string policy_id;
    std::string agent_id;
    std::string status;        // "compliant", "non_compliant", "unknown", "fixing", "error"
    int64_t last_check_at{0};
    int64_t last_fix_at{0};
    std::string check_result;  // JSON of last check output
};

struct ComplianceSummary {
    std::string policy_id;
    int64_t compliant{0};
    int64_t non_compliant{0};
    int64_t unknown{0};
    int64_t fixing{0};
    int64_t error{0};
    int64_t total{0};
};

struct FleetCompliance {
    int64_t total_checks{0};     // total (policy, agent) pairs
    int64_t compliant{0};
    int64_t non_compliant{0};
    int64_t unknown{0};
    int64_t fixing{0};
    int64_t error{0};
    double compliance_pct{0.0};  // compliant / total * 100
};

struct PolicyQuery {
    std::string name_filter;
    std::string fragment_filter;
    bool enabled_only{false};
    int limit{100};
};

struct FragmentQuery {
    std::string name_filter;
    int limit{100};
};

// ── PolicyStore ──────────────────────────────────────────────────────────────

class PolicyStore {
public:
    explicit PolicyStore(const std::filesystem::path& db_path);
    ~PolicyStore();

    PolicyStore(const PolicyStore&) = delete;
    PolicyStore& operator=(const PolicyStore&) = delete;

    bool is_open() const;

    // ── Fragments ────────────────────────────────────────────────────────
    std::expected<std::string, std::string> create_fragment(const std::string& yaml_source);
    std::vector<PolicyFragment> query_fragments(const FragmentQuery& q = {}) const;
    std::optional<PolicyFragment> get_fragment(const std::string& id) const;
    bool delete_fragment(const std::string& id);

    // ── Policies ─────────────────────────────────────────────────────────
    std::expected<std::string, std::string> create_policy(const std::string& yaml_source);
    std::vector<Policy> query_policies(const PolicyQuery& q = {}) const;
    std::optional<Policy> get_policy(const std::string& id) const;
    std::expected<void, std::string> enable_policy(const std::string& id);
    std::expected<void, std::string> disable_policy(const std::string& id);
    bool delete_policy(const std::string& id);

    // ── Compliance tracking ──────────────────────────────────────────────
    std::expected<void, std::string> update_agent_status(const std::string& policy_id,
                                                          const std::string& agent_id,
                                                          const std::string& status,
                                                          const std::string& check_result = "");
    std::optional<PolicyAgentStatus> get_agent_status(const std::string& policy_id,
                                                       const std::string& agent_id) const;
    std::vector<PolicyAgentStatus> get_policy_agent_statuses(const std::string& policy_id) const;
    ComplianceSummary get_compliance_summary(const std::string& policy_id) const;
    FleetCompliance get_fleet_compliance() const;

private:
    sqlite3* db_{nullptr};
    mutable std::mutex mtx_;

    void create_tables();
    std::string generate_id() const;

    // Internal helpers (caller must hold mtx_)
    void store_inputs(const std::string& policy_id,
                      const std::vector<PolicyInput>& inputs);
    void store_triggers(const std::string& policy_id,
                        const std::vector<PolicyTrigger>& triggers);
    void store_groups(const std::string& policy_id,
                      const std::vector<std::string>& group_ids);
    void load_policy_details(Policy& p) const;
};

} // namespace yuzu::server
