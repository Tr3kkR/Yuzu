#pragma once

#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include <sqlite3.h>

namespace yuzu::server {

struct InstructionDefinition {
    std::string id;
    std::string name;
    std::string version;
    std::string type;
    std::string plugin;
    std::string action;
    std::string description;
    bool        enabled{true};
    std::string instruction_set_id;
    int         gather_ttl_seconds{300};
    int         response_ttl_days{90};
    std::string created_by;
    int64_t     created_at{0};
    int64_t     updated_at{0};
};

struct InstructionQuery {
    std::string name_filter;
    std::string plugin_filter;
    std::string type_filter;
    std::string set_id_filter;
    bool        enabled_only{false};
    int         limit{100};
};

struct InstructionSet {
    std::string id;
    std::string name;
    std::string description;
    std::string created_by;
    int64_t     created_at{0};
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
};

}  // namespace yuzu::server
