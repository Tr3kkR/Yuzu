#pragma once

#include <sqlite3.h>

#include <cstdint>
#include <filesystem>
#include <optional>
#include <shared_mutex>
#include <string>
#include <vector>

namespace yuzu::server {

// ── Data types ───────────────────────────────────────────────────────────────

struct InventoryRecord {
    std::string agent_id;
    std::string plugin;
    std::string data_json; // Structured JSON blob from the plugin
    int64_t collected_at{0};
};

struct InventoryTable {
    std::string plugin;
    int64_t agent_count{0};      // How many agents have reported this plugin
    int64_t last_collected{0};   // Most recent collection timestamp
};

struct InventoryQuery {
    std::string agent_id;   // Filter by agent (empty = all)
    std::string plugin;     // Filter by plugin (empty = all)
    int64_t since{0};       // epoch seconds, 0 = no lower bound
    int64_t until{0};       // epoch seconds, 0 = no upper bound
    int limit{100};
    int offset{0};
};

// ── InventoryStore ──────────────────────────────────────────────────────────

class InventoryStore {
public:
    explicit InventoryStore(const std::filesystem::path& db_path);
    ~InventoryStore();

    InventoryStore(const InventoryStore&) = delete;
    InventoryStore& operator=(const InventoryStore&) = delete;

    bool is_open() const;

    /// Upsert inventory data for an agent+plugin pair.
    /// If data already exists for (agent_id, plugin), it is replaced.
    void upsert(const std::string& agent_id, const std::string& plugin,
                const std::string& data_json, int64_t collected_at = 0);

    /// List available inventory "tables" (distinct plugins with agent counts).
    std::vector<InventoryTable> list_tables() const;

    /// Get inventory data for a specific agent+plugin.
    std::optional<InventoryRecord> get(const std::string& agent_id,
                                       const std::string& plugin) const;

    /// Query inventory across agents with filters.
    std::vector<InventoryRecord> query(const InventoryQuery& q) const;

    /// Get all inventory records for a specific agent.
    std::vector<InventoryRecord> get_agent_inventory(const std::string& agent_id) const;

    /// Delete inventory data for an agent (e.g., on agent removal).
    void delete_agent(const std::string& agent_id);

    /// Count total inventory records.
    int64_t count() const;

private:
    sqlite3* db_{nullptr};
    mutable std::shared_mutex mtx_;

    void create_tables();
};

} // namespace yuzu::server
