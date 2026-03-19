#include "management_group_store.hpp"

#include <spdlog/spdlog.h>

#include <chrono>
#include <random>

namespace yuzu::server {

// ── Helpers ──────────────────────────────────────────────────────────────────

static const char* safe(const char* p) { return p ? p : ""; }

static int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// ── Construction / teardown ──────────────────────────────────────────────────

ManagementGroupStore::ManagementGroupStore(const std::filesystem::path& db_path) {
    int rc = sqlite3_open(db_path.string().c_str(), &db_);
    if (rc != SQLITE_OK) {
        spdlog::error("ManagementGroupStore: failed to open {}: {}",
                       db_path.string(), sqlite3_errmsg(db_));
        if (db_) { sqlite3_close(db_); db_ = nullptr; }
        return;
    }
    sqlite3_exec(db_, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "PRAGMA busy_timeout=5000;", nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "PRAGMA foreign_keys=ON;", nullptr, nullptr, nullptr);
    create_tables();
    spdlog::info("ManagementGroupStore: opened {}", db_path.string());
}

ManagementGroupStore::~ManagementGroupStore() {
    if (db_) sqlite3_close(db_);
}

bool ManagementGroupStore::is_open() const { return db_ != nullptr; }

// ── DDL ──────────────────────────────────────────────────────────────────────

void ManagementGroupStore::create_tables() {
    const char* sql = R"(
        CREATE TABLE IF NOT EXISTS management_groups (
            id               TEXT PRIMARY KEY,
            name             TEXT NOT NULL UNIQUE,
            description      TEXT NOT NULL DEFAULT '',
            parent_id        TEXT REFERENCES management_groups(id) ON DELETE CASCADE,
            membership_type  TEXT NOT NULL DEFAULT 'static',
            scope_expression TEXT,
            created_by       TEXT,
            created_at       INTEGER NOT NULL DEFAULT 0,
            updated_at       INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS management_group_members (
            group_id  TEXT NOT NULL REFERENCES management_groups(id) ON DELETE CASCADE,
            agent_id  TEXT NOT NULL,
            source    TEXT NOT NULL DEFAULT 'static',
            added_at  INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (group_id, agent_id)
        );

        CREATE TABLE IF NOT EXISTS management_group_roles (
            group_id       TEXT NOT NULL REFERENCES management_groups(id) ON DELETE CASCADE,
            principal_type TEXT NOT NULL,
            principal_id   TEXT NOT NULL,
            role_name      TEXT NOT NULL,
            PRIMARY KEY (group_id, principal_type, principal_id, role_name)
        );

        CREATE INDEX IF NOT EXISTS idx_mgmt_members_agent
            ON management_group_members(agent_id);
        CREATE INDEX IF NOT EXISTS idx_mgmt_groups_parent
            ON management_groups(parent_id);
    )";
    char* err = nullptr;
    if (sqlite3_exec(db_, sql, nullptr, nullptr, &err) != SQLITE_OK) {
        spdlog::error("ManagementGroupStore: create_tables failed: {}", err ? err : "unknown");
        sqlite3_free(err);
    }
}

std::string ManagementGroupStore::generate_id() const {
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    static constexpr char chars[] = "0123456789abcdef";
    std::string id;
    id.reserve(12);
    std::uniform_int_distribution<int> dist(0, 15);
    for (int i = 0; i < 12; ++i)
        id += chars[dist(rng)];
    return id;
}

// ── Group CRUD ───────────────────────────────────────────────────────────────

std::expected<std::string, std::string>
ManagementGroupStore::create_group(const ManagementGroup& group) {
    if (!db_) return std::unexpected("database not open");
    if (group.name.empty()) return std::unexpected("group name cannot be empty");

    // Validate no circular parent reference
    if (!group.parent_id.empty()) {
        auto parent = get_group(group.parent_id);
        if (!parent) return std::unexpected("parent group not found");
        // Check depth limit (max 5 levels)
        auto ancestors = get_ancestor_ids(group.parent_id);
        if (ancestors.size() >= 5)
            return std::unexpected("maximum hierarchy depth (5) exceeded");
    }

    auto id = group.id.empty() ? generate_id() : group.id;
    auto now = now_epoch();

    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
            "INSERT INTO management_groups "
            "(id, name, description, parent_id, membership_type, scope_expression, created_by, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);",
            -1, &s, nullptr) != SQLITE_OK)
        return std::unexpected(sqlite3_errmsg(db_));

    sqlite3_bind_text(s, 1, id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 2, group.name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 3, group.description.c_str(), -1, SQLITE_TRANSIENT);
    if (group.parent_id.empty())
        sqlite3_bind_null(s, 4);
    else
        sqlite3_bind_text(s, 4, group.parent_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 5, group.membership_type.c_str(), -1, SQLITE_TRANSIENT);
    if (group.scope_expression.empty())
        sqlite3_bind_null(s, 6);
    else
        sqlite3_bind_text(s, 6, group.scope_expression.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 7, group.created_by.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(s, 8, now);
    sqlite3_bind_int64(s, 9, now);

    int rc = sqlite3_step(s);
    sqlite3_finalize(s);
    if (rc != SQLITE_DONE)
        return std::unexpected(std::string("failed to create group: ") + sqlite3_errmsg(db_));
    return id;
}

std::optional<ManagementGroup> ManagementGroupStore::get_group(const std::string& id) const {
    if (!db_) return std::nullopt;
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
            "SELECT id, name, description, parent_id, membership_type, scope_expression, "
            "created_by, created_at, updated_at FROM management_groups WHERE id = ?;",
            -1, &s, nullptr) != SQLITE_OK)
        return std::nullopt;
    sqlite3_bind_text(s, 1, id.c_str(), -1, SQLITE_TRANSIENT);
    std::optional<ManagementGroup> result;
    if (sqlite3_step(s) == SQLITE_ROW) {
        ManagementGroup g;
        g.id               = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 0)));
        g.name             = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 1)));
        g.description      = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 2)));
        g.parent_id        = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 3)));
        g.membership_type  = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 4)));
        g.scope_expression = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 5)));
        g.created_by       = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 6)));
        g.created_at       = sqlite3_column_int64(s, 7);
        g.updated_at       = sqlite3_column_int64(s, 8);
        result = std::move(g);
    }
    sqlite3_finalize(s);
    return result;
}

std::vector<ManagementGroup> ManagementGroupStore::list_groups() const {
    std::vector<ManagementGroup> result;
    if (!db_) return result;
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
            "SELECT id, name, description, parent_id, membership_type, scope_expression, "
            "created_by, created_at, updated_at FROM management_groups ORDER BY name;",
            -1, &s, nullptr) != SQLITE_OK)
        return result;
    while (sqlite3_step(s) == SQLITE_ROW) {
        ManagementGroup g;
        g.id               = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 0)));
        g.name             = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 1)));
        g.description      = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 2)));
        g.parent_id        = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 3)));
        g.membership_type  = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 4)));
        g.scope_expression = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 5)));
        g.created_by       = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 6)));
        g.created_at       = sqlite3_column_int64(s, 7);
        g.updated_at       = sqlite3_column_int64(s, 8);
        result.push_back(std::move(g));
    }
    sqlite3_finalize(s);
    return result;
}

std::vector<ManagementGroup> ManagementGroupStore::get_children(const std::string& parent_id) const {
    std::vector<ManagementGroup> result;
    if (!db_) return result;
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
            "SELECT id, name, description, parent_id, membership_type, scope_expression, "
            "created_by, created_at, updated_at FROM management_groups WHERE parent_id = ? ORDER BY name;",
            -1, &s, nullptr) != SQLITE_OK)
        return result;
    sqlite3_bind_text(s, 1, parent_id.c_str(), -1, SQLITE_TRANSIENT);
    while (sqlite3_step(s) == SQLITE_ROW) {
        ManagementGroup g;
        g.id               = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 0)));
        g.name             = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 1)));
        g.description      = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 2)));
        g.parent_id        = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 3)));
        g.membership_type  = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 4)));
        g.scope_expression = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 5)));
        g.created_by       = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 6)));
        g.created_at       = sqlite3_column_int64(s, 7);
        g.updated_at       = sqlite3_column_int64(s, 8);
        result.push_back(std::move(g));
    }
    sqlite3_finalize(s);
    return result;
}

std::expected<void, std::string> ManagementGroupStore::update_group(const ManagementGroup& group) {
    if (!db_) return std::unexpected("database not open");
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
            "UPDATE management_groups SET name = ?, description = ?, parent_id = ?, "
            "membership_type = ?, scope_expression = ?, updated_at = ? WHERE id = ?;",
            -1, &s, nullptr) != SQLITE_OK)
        return std::unexpected(sqlite3_errmsg(db_));
    sqlite3_bind_text(s, 1, group.name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 2, group.description.c_str(), -1, SQLITE_TRANSIENT);
    if (group.parent_id.empty())
        sqlite3_bind_null(s, 3);
    else
        sqlite3_bind_text(s, 3, group.parent_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 4, group.membership_type.c_str(), -1, SQLITE_TRANSIENT);
    if (group.scope_expression.empty())
        sqlite3_bind_null(s, 5);
    else
        sqlite3_bind_text(s, 5, group.scope_expression.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(s, 6, now_epoch());
    sqlite3_bind_text(s, 7, group.id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(s);
    sqlite3_finalize(s);
    if (sqlite3_changes(db_) == 0) return std::unexpected("group not found");
    return {};
}

std::expected<void, std::string> ManagementGroupStore::delete_group(const std::string& id) {
    if (!db_) return std::unexpected("database not open");
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_, "DELETE FROM management_groups WHERE id = ?;",
                           -1, &s, nullptr) != SQLITE_OK)
        return std::unexpected(sqlite3_errmsg(db_));
    sqlite3_bind_text(s, 1, id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(s);
    sqlite3_finalize(s);
    if (sqlite3_changes(db_) == 0) return std::unexpected("group not found");
    return {};
}

// ── Membership ───────────────────────────────────────────────────────────────

std::expected<void, std::string>
ManagementGroupStore::add_member(const std::string& group_id, const std::string& agent_id) {
    if (!db_) return std::unexpected("database not open");
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
            "INSERT OR IGNORE INTO management_group_members (group_id, agent_id, source, added_at) "
            "VALUES (?, ?, 'static', ?);",
            -1, &s, nullptr) != SQLITE_OK)
        return std::unexpected(sqlite3_errmsg(db_));
    sqlite3_bind_text(s, 1, group_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 2, agent_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(s, 3, now_epoch());
    sqlite3_step(s);
    sqlite3_finalize(s);
    return {};
}

std::expected<void, std::string>
ManagementGroupStore::remove_member(const std::string& group_id, const std::string& agent_id) {
    if (!db_) return std::unexpected("database not open");
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
            "DELETE FROM management_group_members WHERE group_id = ? AND agent_id = ? AND source = 'static';",
            -1, &s, nullptr) != SQLITE_OK)
        return std::unexpected(sqlite3_errmsg(db_));
    sqlite3_bind_text(s, 1, group_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 2, agent_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(s);
    sqlite3_finalize(s);
    return {};
}

std::vector<ManagementGroupMember>
ManagementGroupStore::get_members(const std::string& group_id) const {
    std::vector<ManagementGroupMember> result;
    if (!db_) return result;
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
            "SELECT group_id, agent_id, source, added_at "
            "FROM management_group_members WHERE group_id = ? ORDER BY agent_id;",
            -1, &s, nullptr) != SQLITE_OK)
        return result;
    sqlite3_bind_text(s, 1, group_id.c_str(), -1, SQLITE_TRANSIENT);
    while (sqlite3_step(s) == SQLITE_ROW) {
        ManagementGroupMember m;
        m.group_id = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 0)));
        m.agent_id = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 1)));
        m.source   = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 2)));
        m.added_at = sqlite3_column_int64(s, 3);
        result.push_back(std::move(m));
    }
    sqlite3_finalize(s);
    return result;
}

std::vector<std::string>
ManagementGroupStore::get_agent_groups(const std::string& agent_id) const {
    std::vector<std::string> result;
    if (!db_) return result;
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
            "SELECT group_id FROM management_group_members WHERE agent_id = ?;",
            -1, &s, nullptr) != SQLITE_OK)
        return result;
    sqlite3_bind_text(s, 1, agent_id.c_str(), -1, SQLITE_TRANSIENT);
    while (sqlite3_step(s) == SQLITE_ROW)
        result.emplace_back(safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 0))));
    sqlite3_finalize(s);
    return result;
}

void ManagementGroupStore::refresh_dynamic_membership(
    const std::string& group_id, const std::vector<std::string>& matching_agent_ids) {
    if (!db_) return;

    // Remove old dynamic members
    sqlite3_stmt* del = nullptr;
    sqlite3_prepare_v2(db_,
        "DELETE FROM management_group_members WHERE group_id = ? AND source = 'dynamic';",
        -1, &del, nullptr);
    sqlite3_bind_text(del, 1, group_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(del);
    sqlite3_finalize(del);

    // Insert new dynamic members
    auto now = now_epoch();
    for (const auto& aid : matching_agent_ids) {
        sqlite3_stmt* ins = nullptr;
        sqlite3_prepare_v2(db_,
            "INSERT OR IGNORE INTO management_group_members (group_id, agent_id, source, added_at) "
            "VALUES (?, ?, 'dynamic', ?);",
            -1, &ins, nullptr);
        sqlite3_bind_text(ins, 1, group_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(ins, 2, aid.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(ins, 3, now);
        sqlite3_step(ins);
        sqlite3_finalize(ins);
    }
}

// ── Hierarchy ────────────────────────────────────────────────────────────────

std::vector<std::string>
ManagementGroupStore::get_ancestor_ids(const std::string& group_id) const {
    std::vector<std::string> ancestors;
    if (!db_) return ancestors;

    auto current = group_id;
    for (int depth = 0; depth < 10; ++depth) {  // safety limit
        sqlite3_stmt* s = nullptr;
        if (sqlite3_prepare_v2(db_,
                "SELECT parent_id FROM management_groups WHERE id = ?;",
                -1, &s, nullptr) != SQLITE_OK)
            break;
        sqlite3_bind_text(s, 1, current.c_str(), -1, SQLITE_TRANSIENT);
        if (sqlite3_step(s) == SQLITE_ROW) {
            auto* pid = reinterpret_cast<const char*>(sqlite3_column_text(s, 0));
            if (pid && pid[0] != '\0') {
                current = pid;
                ancestors.push_back(current);
                sqlite3_finalize(s);
                continue;
            }
        }
        sqlite3_finalize(s);
        break;
    }
    return ancestors;
}

std::vector<std::string>
ManagementGroupStore::get_descendant_ids(const std::string& group_id) const {
    std::vector<std::string> descendants;
    if (!db_) return descendants;

    // BFS traversal
    std::vector<std::string> queue = {group_id};
    while (!queue.empty()) {
        auto current = queue.back();
        queue.pop_back();

        sqlite3_stmt* s = nullptr;
        if (sqlite3_prepare_v2(db_,
                "SELECT id FROM management_groups WHERE parent_id = ?;",
                -1, &s, nullptr) != SQLITE_OK)
            continue;
        sqlite3_bind_text(s, 1, current.c_str(), -1, SQLITE_TRANSIENT);
        while (sqlite3_step(s) == SQLITE_ROW) {
            auto* cid = reinterpret_cast<const char*>(sqlite3_column_text(s, 0));
            if (cid) {
                descendants.emplace_back(cid);
                queue.emplace_back(cid);
            }
        }
        sqlite3_finalize(s);
    }
    return descendants;
}

// ── Group-scoped role assignments ────────────────────────────────────────────

std::expected<void, std::string>
ManagementGroupStore::assign_role(const GroupRoleAssignment& assignment) {
    if (!db_) return std::unexpected("database not open");
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
            "INSERT OR IGNORE INTO management_group_roles "
            "(group_id, principal_type, principal_id, role_name) VALUES (?, ?, ?, ?);",
            -1, &s, nullptr) != SQLITE_OK)
        return std::unexpected(sqlite3_errmsg(db_));
    sqlite3_bind_text(s, 1, assignment.group_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 2, assignment.principal_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 3, assignment.principal_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 4, assignment.role_name.c_str(), -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(s);
    sqlite3_finalize(s);
    if (rc != SQLITE_DONE) return std::unexpected(sqlite3_errmsg(db_));
    return {};
}

std::expected<void, std::string>
ManagementGroupStore::unassign_role(const std::string& group_id,
                                     const std::string& principal_type,
                                     const std::string& principal_id,
                                     const std::string& role_name) {
    if (!db_) return std::unexpected("database not open");
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
            "DELETE FROM management_group_roles "
            "WHERE group_id = ? AND principal_type = ? AND principal_id = ? AND role_name = ?;",
            -1, &s, nullptr) != SQLITE_OK)
        return std::unexpected(sqlite3_errmsg(db_));
    sqlite3_bind_text(s, 1, group_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 2, principal_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 3, principal_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 4, role_name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(s);
    sqlite3_finalize(s);
    return {};
}

std::vector<GroupRoleAssignment>
ManagementGroupStore::get_group_roles(const std::string& group_id) const {
    std::vector<GroupRoleAssignment> result;
    if (!db_) return result;
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
            "SELECT group_id, principal_type, principal_id, role_name "
            "FROM management_group_roles WHERE group_id = ? ORDER BY role_name;",
            -1, &s, nullptr) != SQLITE_OK)
        return result;
    sqlite3_bind_text(s, 1, group_id.c_str(), -1, SQLITE_TRANSIENT);
    while (sqlite3_step(s) == SQLITE_ROW) {
        GroupRoleAssignment a;
        a.group_id       = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 0)));
        a.principal_type = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 1)));
        a.principal_id   = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 2)));
        a.role_name      = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 3)));
        result.push_back(std::move(a));
    }
    sqlite3_finalize(s);
    return result;
}

std::vector<std::string>
ManagementGroupStore::get_visible_agents(const std::string& username) const {
    std::vector<std::string> result;
    if (!db_) return result;
    // Find all groups where the user has any role assignment, then return their members
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
            "SELECT DISTINCT m.agent_id FROM management_group_members m "
            "JOIN management_group_roles r ON m.group_id = r.group_id "
            "WHERE r.principal_type = 'user' AND r.principal_id = ?;",
            -1, &s, nullptr) != SQLITE_OK)
        return result;
    sqlite3_bind_text(s, 1, username.c_str(), -1, SQLITE_TRANSIENT);
    while (sqlite3_step(s) == SQLITE_ROW)
        result.emplace_back(safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 0))));
    sqlite3_finalize(s);
    return result;
}

}  // namespace yuzu::server
