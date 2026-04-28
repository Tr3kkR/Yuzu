#pragma once

#include <sqlite3.h>

#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <string>
#include <shared_mutex>
#include <vector>

namespace yuzu::server {

struct InstructionDefinition {
    std::string id;
    std::string name;
    std::string version;
    std::string type; // "question" or "action"
    std::string plugin;
    std::string action;
    std::string description;
    bool enabled{true};
    std::string instruction_set_id;
    int gather_ttl_seconds{300};
    int response_ttl_days{90};
    std::string created_by;
    int64_t created_at{0};
    int64_t updated_at{0};
    // Extended fields (Phase 2)
    std::string yaml_source;      // verbatim YAML (source of truth)
    std::string parameter_schema; // JSON Schema for parameters
    std::string result_schema;    // result column definitions JSON
    std::string approval_mode;    // "auto", "role-gated", "always"
    std::string concurrency_mode; // "per-device", "per-definition", etc.
    std::string platforms;        // comma-separated: "windows,linux,darwin"
    std::string min_agent_version;
    std::string required_plugins; // comma-separated
    std::string readable_payload; // e.g. "Inspect service '${serviceName}'"
    // Issue #253: spec.visualization serialized as JSON. Empty (or "{}") means
    // the definition has no visualization configured and the
    // /api/v1/executions/{id}/visualization endpoint returns 404 for it.
    std::string visualization_spec;
};

struct InstructionQuery {
    std::string name_filter;
    std::string plugin_filter;
    std::string type_filter;
    std::string set_id_filter;
    bool enabled_only{false};
    int limit{100};
};

struct InstructionSet {
    std::string id;
    std::string name;
    std::string description;
    std::string created_by;
    int64_t created_at{0};
};

class InstructionStore {
public:
    explicit InstructionStore(const std::filesystem::path& db_path);
    ~InstructionStore();

    InstructionStore(const InstructionStore&) = delete;
    InstructionStore& operator=(const InstructionStore&) = delete;

    bool is_open() const;

    // Definitions
    std::vector<InstructionDefinition> query_definitions(const InstructionQuery& q = {}) const;
    std::optional<InstructionDefinition> get_definition(const std::string& id) const;
    std::expected<std::string, std::string> create_definition(const InstructionDefinition& def);
    std::expected<void, std::string> update_definition(const InstructionDefinition& def);
    bool delete_definition(const std::string& id);

    // Import/Export
    std::string export_definition_json(const std::string& id) const;
    std::expected<std::string, std::string> import_definition_json(const std::string& json);

    // Instruction Sets
    std::vector<InstructionSet> list_sets() const;
    std::expected<std::string, std::string> create_set(const InstructionSet& s);
    bool delete_set(const std::string& id);

private:
    sqlite3* db_{nullptr};
    mutable std::shared_mutex mtx_; // protects db_ access (G3-ARCH-003)

    // Internal variants called under existing lock (no re-lock)
    std::optional<InstructionDefinition> get_definition_impl(const std::string& id) const;
    std::expected<std::string, std::string> create_definition_impl(const InstructionDefinition& def);
};

} // namespace yuzu::server
