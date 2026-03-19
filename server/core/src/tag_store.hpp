#pragma once

#include <sqlite3.h>

#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace yuzu::server {

struct DeviceTag {
    std::string agent_id;
    std::string key;
    std::string value;
    std::string source;    // "agent", "server", "api"
    int64_t updated_at{0}; // epoch seconds
};

struct TagCategory {
    std::string_view key;
    std::string_view display_name;
    std::vector<std::string_view> allowed_values; // empty = free-form
};

// Fixed categories — the only structured tag categories that exist
inline constexpr std::string_view kCategoryKeys[] = {"role", "environment", "location", "service"};

const std::vector<TagCategory>& get_tag_categories();

class TagStore {
public:
    explicit TagStore(const std::filesystem::path& db_path);
    ~TagStore();

    TagStore(const TagStore&) = delete;
    TagStore& operator=(const TagStore&) = delete;

    bool is_open() const;

    void set_tag(const std::string& agent_id, const std::string& key, const std::string& value,
                 const std::string& source = "server");
    std::string get_tag(const std::string& agent_id, const std::string& key) const;
    bool delete_tag(const std::string& agent_id, const std::string& key);
    std::vector<DeviceTag> get_all_tags(const std::string& agent_id) const;
    std::unordered_map<std::string, std::string> get_tag_map(const std::string& agent_id) const;

    /// Sync tags from agent heartbeat/registration — sets source="agent"
    void sync_agent_tags(const std::string& agent_id,
                         const std::unordered_map<std::string, std::string>& tags);

    void delete_all_tags(const std::string& agent_id);
    std::vector<std::string> agents_with_tag(const std::string& key,
                                             const std::string& value = {}) const;

    /// Set tag with category validation. If key matches a category with
    /// allowed_values, value must be in the list. Delegates to set_tag().
    std::expected<void, std::string> set_tag_checked(const std::string& agent_id,
                                                     const std::string& key,
                                                     const std::string& value,
                                                     const std::string& source = "server");

    /// Returns (agent_id, [missing category keys]) for agents missing any category tags.
    std::vector<std::pair<std::string, std::vector<std::string>>> get_compliance_gaps() const;

    /// Returns distinct values for a given tag key.
    std::vector<std::string> get_distinct_values(const std::string& key) const;

    /// Validation: key max 64 chars [a-zA-Z0-9_.:-], value max 448 bytes
    static bool validate_key(const std::string& key);
    static bool validate_value(const std::string& value);

private:
    sqlite3* db_{nullptr};
    void create_tables();
};

} // namespace yuzu::server
