#include "rbac_store.hpp"

#include "management_group_store.hpp"

#include <spdlog/spdlog.h>
#include <sqlite3.h>

#include <chrono>
#include <unordered_set>

namespace yuzu::server {

// ── Construction / teardown ──────────────────────────────────────────────────

RbacStore::RbacStore(const std::filesystem::path& db_path) {
    int rc = sqlite3_open(db_path.string().c_str(), &db_);
    if (rc != SQLITE_OK) {
        spdlog::error("RbacStore: failed to open {}: {}", db_path.string(), sqlite3_errmsg(db_));
        if (db_) {
            sqlite3_close(db_);
            db_ = nullptr;
        }
        return;
    }

    sqlite3_exec(db_, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "PRAGMA busy_timeout=5000;", nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "PRAGMA foreign_keys=ON;", nullptr, nullptr, nullptr);
    create_tables();
    seed_defaults();
    load_enabled_flag();
    spdlog::info("RbacStore: opened {}", db_path.string());
}

RbacStore::~RbacStore() {
    if (db_)
        sqlite3_close(db_);
}

bool RbacStore::is_open() const {
    return db_ != nullptr;
}

// ── DDL ──────────────────────────────────────────────────────────────────────

void RbacStore::create_tables() {
    const char* sql = R"(
        CREATE TABLE IF NOT EXISTS securable_types (
            name        TEXT PRIMARY KEY,
            description TEXT NOT NULL DEFAULT '',
            is_system   INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS operations (
            id          TEXT PRIMARY KEY,
            description TEXT NOT NULL DEFAULT '',
            is_system   INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS roles (
            name        TEXT PRIMARY KEY,
            description TEXT NOT NULL DEFAULT '',
            is_system   INTEGER NOT NULL DEFAULT 0,
            created_at  INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS role_permissions (
            role_name       TEXT NOT NULL REFERENCES roles(name) ON DELETE CASCADE,
            securable_type  TEXT NOT NULL REFERENCES securable_types(name),
            operation       TEXT NOT NULL REFERENCES operations(id),
            effect          TEXT NOT NULL DEFAULT 'allow',
            PRIMARY KEY (role_name, securable_type, operation)
        );

        CREATE TABLE IF NOT EXISTS principal_roles (
            principal_type  TEXT NOT NULL,
            principal_id    TEXT NOT NULL,
            role_name       TEXT NOT NULL REFERENCES roles(name) ON DELETE CASCADE,
            PRIMARY KEY (principal_type, principal_id, role_name)
        );
        CREATE INDEX IF NOT EXISTS idx_principal_roles_lookup
            ON principal_roles(principal_type, principal_id);

        CREATE TABLE IF NOT EXISTS groups (
            name        TEXT PRIMARY KEY,
            description TEXT NOT NULL DEFAULT '',
            source      TEXT NOT NULL DEFAULT 'local',
            external_id TEXT,
            created_at  INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS group_members (
            group_name  TEXT NOT NULL REFERENCES groups(name) ON DELETE CASCADE,
            username    TEXT NOT NULL,
            PRIMARY KEY (group_name, username)
        );

        CREATE TABLE IF NOT EXISTS rbac_config (
            key     TEXT PRIMARY KEY,
            value   TEXT NOT NULL
        );
    )";
    char* err = nullptr;
    if (sqlite3_exec(db_, sql, nullptr, nullptr, &err) != SQLITE_OK) {
        spdlog::error("RbacStore: create_tables failed: {}", err ? err : "unknown");
        sqlite3_free(err);
    }
}

// ── Seed data ────────────────────────────────────────────────────────────────

void RbacStore::seed_defaults() {
    if (!db_)
        return;

    // Config default
    sqlite3_exec(db_, "INSERT OR IGNORE INTO rbac_config VALUES ('enabled', 'false');", nullptr,
                 nullptr, nullptr);

    // Securable types
    const char* types[] = {"Infrastructure",
                           "UserManagement",
                           "InstructionDefinition",
                           "InstructionSet",
                           "Execution",
                           "Schedule",
                           "Approval",
                           "Tag",
                           "AuditLog",
                           "Response",
                           "ManagementGroup",
                           "ApiToken",
                           "Security"};
    for (auto* t : types) {
        sqlite3_stmt* s = nullptr;
        sqlite3_prepare_v2(db_,
                           "INSERT OR IGNORE INTO securable_types (name, is_system) VALUES (?, 1);",
                           -1, &s, nullptr);
        sqlite3_bind_text(s, 1, t, -1, SQLITE_TRANSIENT);
        sqlite3_step(s);
        sqlite3_finalize(s);
    }

    // Operations
    const char* ops[] = {"Read", "Write", "Execute", "Delete", "Approve"};
    for (auto* o : ops) {
        sqlite3_stmt* s = nullptr;
        sqlite3_prepare_v2(db_, "INSERT OR IGNORE INTO operations (id, is_system) VALUES (?, 1);",
                           -1, &s, nullptr);
        sqlite3_bind_text(s, 1, o, -1, SQLITE_TRANSIENT);
        sqlite3_step(s);
        sqlite3_finalize(s);
    }

    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count();

    // Built-in roles
    struct RoleSeed {
        const char* name;
        const char* desc;
    };
    RoleSeed roles[] = {
        {"Administrator", "Full access to all operations"},
        {"PlatformEngineer", "Author and manage YAML instruction definitions, sets, and schemas"},
        {"Operator", "Execute and manage instructions, schedules, and tags"},
        {"ApiTokenManager", "Create, revoke, and manage API tokens for programmatic access"},
        {"ITServiceOwner", "Admin control over devices tagged with the same IT Service"},
        {"Viewer", "Read-only access to operational data"},
    };
    for (auto& [name, desc] : roles) {
        sqlite3_stmt* s = nullptr;
        sqlite3_prepare_v2(db_,
                           "INSERT OR IGNORE INTO roles (name, description, is_system, created_at) "
                           "VALUES (?, ?, 1, ?);",
                           -1, &s, nullptr);
        sqlite3_bind_text(s, 1, name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(s, 2, desc, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(s, 3, now);
        sqlite3_step(s);
        sqlite3_finalize(s);
    }

    // Administrator: allow everything
    for (auto* t : types) {
        for (auto* o : ops) {
            sqlite3_stmt* s = nullptr;
            sqlite3_prepare_v2(
                db_,
                "INSERT OR IGNORE INTO role_permissions VALUES ('Administrator', ?, ?, 'allow');",
                -1, &s, nullptr);
            sqlite3_bind_text(s, 1, t, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(s, 2, o, -1, SQLITE_TRANSIENT);
            sqlite3_step(s);
            sqlite3_finalize(s);
        }
    }

    // PlatformEngineer: full CRUD on definitions, sets, and read on related types
    const char* pe_full_types[] = {"InstructionDefinition", "InstructionSet"};
    const char* pe_full_ops[] = {"Read", "Write", "Execute", "Delete"};
    for (auto* t : pe_full_types) {
        for (auto* o : pe_full_ops) {
            sqlite3_stmt* s = nullptr;
            sqlite3_prepare_v2(db_,
                               "INSERT OR IGNORE INTO role_permissions VALUES ('PlatformEngineer', "
                               "?, ?, 'allow');",
                               -1, &s, nullptr);
            sqlite3_bind_text(s, 1, t, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(s, 2, o, -1, SQLITE_TRANSIENT);
            sqlite3_step(s);
            sqlite3_finalize(s);
        }
    }
    // PlatformEngineer: read on operational types for context
    const char* pe_read_types[] = {"Execution", "Schedule", "Approval",
                                   "Tag",       "AuditLog", "Response"};
    for (auto* t : pe_read_types) {
        sqlite3_stmt* s = nullptr;
        sqlite3_prepare_v2(db_,
                           "INSERT OR IGNORE INTO role_permissions VALUES ('PlatformEngineer', ?, "
                           "'Read', 'allow');",
                           -1, &s, nullptr);
        sqlite3_bind_text(s, 1, t, -1, SQLITE_TRANSIENT);
        sqlite3_step(s);
        sqlite3_finalize(s);
    }

    // Operator: read/write/execute on operational types, read on audit/response
    const char* op_rwe_types[] = {"InstructionDefinition", "InstructionSet", "Execution",
                                  "Schedule", "Tag"};
    const char* op_rwe_ops[] = {"Read", "Write", "Execute"};
    for (auto* t : op_rwe_types) {
        for (auto* o : op_rwe_ops) {
            sqlite3_stmt* s = nullptr;
            sqlite3_prepare_v2(
                db_, "INSERT OR IGNORE INTO role_permissions VALUES ('Operator', ?, ?, 'allow');",
                -1, &s, nullptr);
            sqlite3_bind_text(s, 1, t, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(s, 2, o, -1, SQLITE_TRANSIENT);
            sqlite3_step(s);
            sqlite3_finalize(s);
        }
    }
    // Operator: delete on operational types
    for (auto* t : op_rwe_types) {
        sqlite3_stmt* s = nullptr;
        sqlite3_prepare_v2(
            db_,
            "INSERT OR IGNORE INTO role_permissions VALUES ('Operator', ?, 'Delete', 'allow');", -1,
            &s, nullptr);
        sqlite3_bind_text(s, 1, t, -1, SQLITE_TRANSIENT);
        sqlite3_step(s);
        sqlite3_finalize(s);
    }
    // Operator: approve on Approval
    sqlite3_exec(
        db_,
        "INSERT OR IGNORE INTO role_permissions VALUES ('Operator', 'Approval', 'Read', 'allow');",
        nullptr, nullptr, nullptr);
    sqlite3_exec(db_,
                 "INSERT OR IGNORE INTO role_permissions VALUES ('Operator', 'Approval', "
                 "'Approve', 'allow');",
                 nullptr, nullptr, nullptr);
    // Operator: read on AuditLog, Response
    sqlite3_exec(
        db_,
        "INSERT OR IGNORE INTO role_permissions VALUES ('Operator', 'AuditLog', 'Read', 'allow');",
        nullptr, nullptr, nullptr);
    sqlite3_exec(
        db_,
        "INSERT OR IGNORE INTO role_permissions VALUES ('Operator', 'Response', 'Read', 'allow');",
        nullptr, nullptr, nullptr);

    // ApiTokenManager: read + write + delete on ApiToken
    const char* atm_ops[] = {"Read", "Write", "Delete"};
    for (auto* o : atm_ops) {
        sqlite3_stmt* s = nullptr;
        sqlite3_prepare_v2(
            db_,
            "INSERT OR IGNORE INTO role_permissions VALUES ('ApiTokenManager', 'ApiToken', ?, "
            "'allow');",
            -1, &s, nullptr);
        sqlite3_bind_text(s, 1, o, -1, SQLITE_TRANSIENT);
        sqlite3_step(s);
        sqlite3_finalize(s);
    }

    // ITServiceOwner: broad access on operational types (excludes UserManagement, Security,
    // ApiToken)
    const char* itso_types[] = {"Infrastructure",
                                "InstructionDefinition",
                                "InstructionSet",
                                "Execution",
                                "Schedule",
                                "Approval",
                                "Tag",
                                "AuditLog",
                                "Response",
                                "ManagementGroup"};
    for (auto* t : itso_types) {
        for (auto* o : ops) {
            sqlite3_stmt* s = nullptr;
            sqlite3_prepare_v2(
                db_,
                "INSERT OR IGNORE INTO role_permissions VALUES ('ITServiceOwner', ?, ?, 'allow');",
                -1, &s, nullptr);
            sqlite3_bind_text(s, 1, t, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(s, 2, o, -1, SQLITE_TRANSIENT);
            sqlite3_step(s);
            sqlite3_finalize(s);
        }
    }

    // Viewer: read on all except Infrastructure
    const char* viewer_types[] = {"UserManagement",
                                  "InstructionDefinition",
                                  "InstructionSet",
                                  "Execution",
                                  "Schedule",
                                  "Approval",
                                  "Tag",
                                  "AuditLog",
                                  "Response",
                                  "ManagementGroup",
                                  "ApiToken",
                                  "Security"};
    for (auto* t : viewer_types) {
        sqlite3_stmt* s = nullptr;
        sqlite3_prepare_v2(
            db_, "INSERT OR IGNORE INTO role_permissions VALUES ('Viewer', ?, 'Read', 'allow');",
            -1, &s, nullptr);
        sqlite3_bind_text(s, 1, t, -1, SQLITE_TRANSIENT);
        sqlite3_step(s);
        sqlite3_finalize(s);
    }
}

void RbacStore::load_enabled_flag() {
    if (!db_)
        return;
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_, "SELECT value FROM rbac_config WHERE key='enabled';", -1, &s,
                           nullptr) == SQLITE_OK) {
        if (sqlite3_step(s) == SQLITE_ROW) {
            auto* v = reinterpret_cast<const char*>(sqlite3_column_text(s, 0));
            rbac_enabled_.store(v && std::string(v) == "true");
        }
        sqlite3_finalize(s);
    }
}

// ── Global toggle ────────────────────────────────────────────────────────────

bool RbacStore::is_rbac_enabled() const {
    return rbac_enabled_.load();
}

void RbacStore::set_rbac_enabled(bool enabled) {
    if (!db_)
        return;
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_, "INSERT OR REPLACE INTO rbac_config VALUES ('enabled', ?);", -1, &s,
                           nullptr) == SQLITE_OK) {
        sqlite3_bind_text(s, 1, enabled ? "true" : "false", -1, SQLITE_TRANSIENT);
        sqlite3_step(s);
        sqlite3_finalize(s);
        rbac_enabled_.store(enabled);
    }
}

// ── Roles CRUD ───────────────────────────────────────────────────────────────

std::vector<RbacRole> RbacStore::list_roles() const {
    std::vector<RbacRole> result;
    if (!db_)
        return result;
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "SELECT name, description, is_system, created_at FROM roles ORDER BY "
                           "is_system DESC, name;",
                           -1, &s, nullptr) != SQLITE_OK)
        return result;
    while (sqlite3_step(s) == SQLITE_ROW) {
        RbacRole r;
        r.name = reinterpret_cast<const char*>(sqlite3_column_text(s, 0));
        r.description = reinterpret_cast<const char*>(sqlite3_column_text(s, 1));
        r.is_system = sqlite3_column_int(s, 2) != 0;
        r.created_at = sqlite3_column_int64(s, 3);
        result.push_back(std::move(r));
    }
    sqlite3_finalize(s);
    return result;
}

std::optional<RbacRole> RbacStore::get_role(const std::string& name) const {
    if (!db_)
        return std::nullopt;
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(
            db_, "SELECT name, description, is_system, created_at FROM roles WHERE name = ?;", -1,
            &s, nullptr) != SQLITE_OK)
        return std::nullopt;
    sqlite3_bind_text(s, 1, name.c_str(), -1, SQLITE_TRANSIENT);
    std::optional<RbacRole> result;
    if (sqlite3_step(s) == SQLITE_ROW) {
        RbacRole r;
        r.name = reinterpret_cast<const char*>(sqlite3_column_text(s, 0));
        r.description = reinterpret_cast<const char*>(sqlite3_column_text(s, 1));
        r.is_system = sqlite3_column_int(s, 2) != 0;
        r.created_at = sqlite3_column_int64(s, 3);
        result = std::move(r);
    }
    sqlite3_finalize(s);
    return result;
}

std::expected<void, std::string> RbacStore::create_role(const RbacRole& role) {
    if (!db_)
        return std::unexpected("database not open");
    if (role.name.empty())
        return std::unexpected("role name cannot be empty");

    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count();

    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(
            db_,
            "INSERT INTO roles (name, description, is_system, created_at) VALUES (?, ?, 0, ?);", -1,
            &s, nullptr) != SQLITE_OK)
        return std::unexpected(sqlite3_errmsg(db_));
    sqlite3_bind_text(s, 1, role.name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 2, role.description.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(s, 3, now);
    int rc = sqlite3_step(s);
    sqlite3_finalize(s);
    if (rc != SQLITE_DONE)
        return std::unexpected(std::string("role already exists or DB error: ") +
                               sqlite3_errmsg(db_));
    return {};
}

std::expected<void, std::string> RbacStore::update_role(const std::string& name,
                                                        const std::string& description) {
    if (!db_)
        return std::unexpected("database not open");
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_, "UPDATE roles SET description = ? WHERE name = ?;", -1, &s,
                           nullptr) != SQLITE_OK)
        return std::unexpected(sqlite3_errmsg(db_));
    sqlite3_bind_text(s, 1, description.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 2, name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(s);
    sqlite3_finalize(s);
    if (sqlite3_changes(db_) == 0)
        return std::unexpected("role not found");
    return {};
}

std::expected<void, std::string> RbacStore::delete_role(const std::string& name) {
    if (!db_)
        return std::unexpected("database not open");

    // Check system role protection
    auto role = get_role(name);
    if (!role)
        return std::unexpected("role not found");
    if (role->is_system)
        return std::unexpected("cannot delete system role");

    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_, "DELETE FROM roles WHERE name = ? AND is_system = 0;", -1, &s,
                           nullptr) != SQLITE_OK)
        return std::unexpected(sqlite3_errmsg(db_));
    sqlite3_bind_text(s, 1, name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(s);
    sqlite3_finalize(s);
    return {};
}

// ── Permissions CRUD ─────────────────────────────────────────────────────────

std::vector<Permission> RbacStore::get_role_permissions(const std::string& role_name) const {
    std::vector<Permission> result;
    if (!db_)
        return result;
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(
            db_,
            "SELECT role_name, securable_type, operation, effect "
            "FROM role_permissions WHERE role_name = ? ORDER BY securable_type, operation;",
            -1, &s, nullptr) != SQLITE_OK)
        return result;
    sqlite3_bind_text(s, 1, role_name.c_str(), -1, SQLITE_TRANSIENT);
    while (sqlite3_step(s) == SQLITE_ROW) {
        Permission p;
        p.role_name = reinterpret_cast<const char*>(sqlite3_column_text(s, 0));
        p.securable_type = reinterpret_cast<const char*>(sqlite3_column_text(s, 1));
        p.operation = reinterpret_cast<const char*>(sqlite3_column_text(s, 2));
        p.effect = reinterpret_cast<const char*>(sqlite3_column_text(s, 3));
        result.push_back(std::move(p));
    }
    sqlite3_finalize(s);
    return result;
}

std::expected<void, std::string> RbacStore::set_permission(const Permission& perm) {
    if (!db_)
        return std::unexpected("database not open");
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "INSERT OR REPLACE INTO role_permissions (role_name, securable_type, "
                           "operation, effect) "
                           "VALUES (?, ?, ?, ?);",
                           -1, &s, nullptr) != SQLITE_OK)
        return std::unexpected(sqlite3_errmsg(db_));
    sqlite3_bind_text(s, 1, perm.role_name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 2, perm.securable_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 3, perm.operation.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 4, perm.effect.c_str(), -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(s);
    sqlite3_finalize(s);
    if (rc != SQLITE_DONE)
        return std::unexpected(sqlite3_errmsg(db_));
    return {};
}

std::expected<void, std::string> RbacStore::remove_permission(const std::string& role_name,
                                                              const std::string& securable_type,
                                                              const std::string& operation) {
    if (!db_)
        return std::unexpected("database not open");
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "DELETE FROM role_permissions WHERE role_name = ? AND securable_type = "
                           "? AND operation = ?;",
                           -1, &s, nullptr) != SQLITE_OK)
        return std::unexpected(sqlite3_errmsg(db_));
    sqlite3_bind_text(s, 1, role_name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 2, securable_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 3, operation.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(s);
    sqlite3_finalize(s);
    return {};
}

// ── Principal-role assignments ───────────────────────────────────────────────

std::vector<PrincipalRole> RbacStore::get_principal_roles(const std::string& principal_type,
                                                          const std::string& principal_id) const {
    std::vector<PrincipalRole> result;
    if (!db_)
        return result;
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "SELECT principal_type, principal_id, role_name FROM principal_roles "
                           "WHERE principal_type = ? AND principal_id = ? ORDER BY role_name;",
                           -1, &s, nullptr) != SQLITE_OK)
        return result;
    sqlite3_bind_text(s, 1, principal_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 2, principal_id.c_str(), -1, SQLITE_TRANSIENT);
    while (sqlite3_step(s) == SQLITE_ROW) {
        PrincipalRole pr;
        pr.principal_type = reinterpret_cast<const char*>(sqlite3_column_text(s, 0));
        pr.principal_id = reinterpret_cast<const char*>(sqlite3_column_text(s, 1));
        pr.role_name = reinterpret_cast<const char*>(sqlite3_column_text(s, 2));
        result.push_back(std::move(pr));
    }
    sqlite3_finalize(s);
    return result;
}

std::vector<PrincipalRole> RbacStore::get_role_members(const std::string& role_name) const {
    std::vector<PrincipalRole> result;
    if (!db_)
        return result;
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "SELECT principal_type, principal_id, role_name FROM principal_roles "
                           "WHERE role_name = ? ORDER BY principal_type, principal_id;",
                           -1, &s, nullptr) != SQLITE_OK)
        return result;
    sqlite3_bind_text(s, 1, role_name.c_str(), -1, SQLITE_TRANSIENT);
    while (sqlite3_step(s) == SQLITE_ROW) {
        PrincipalRole pr;
        pr.principal_type = reinterpret_cast<const char*>(sqlite3_column_text(s, 0));
        pr.principal_id = reinterpret_cast<const char*>(sqlite3_column_text(s, 1));
        pr.role_name = reinterpret_cast<const char*>(sqlite3_column_text(s, 2));
        result.push_back(std::move(pr));
    }
    sqlite3_finalize(s);
    return result;
}

std::expected<void, std::string> RbacStore::assign_role(const PrincipalRole& pr) {
    if (!db_)
        return std::unexpected("database not open");
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(
            db_,
            "INSERT OR IGNORE INTO principal_roles (principal_type, principal_id, role_name) "
            "VALUES (?, ?, ?);",
            -1, &s, nullptr) != SQLITE_OK)
        return std::unexpected(sqlite3_errmsg(db_));
    sqlite3_bind_text(s, 1, pr.principal_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 2, pr.principal_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 3, pr.role_name.c_str(), -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(s);
    sqlite3_finalize(s);
    if (rc != SQLITE_DONE)
        return std::unexpected(sqlite3_errmsg(db_));
    return {};
}

std::expected<void, std::string> RbacStore::unassign_role(const std::string& principal_type,
                                                          const std::string& principal_id,
                                                          const std::string& role_name) {
    if (!db_)
        return std::unexpected("database not open");
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "DELETE FROM principal_roles WHERE principal_type = ? AND principal_id "
                           "= ? AND role_name = ?;",
                           -1, &s, nullptr) != SQLITE_OK)
        return std::unexpected(sqlite3_errmsg(db_));
    sqlite3_bind_text(s, 1, principal_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 2, principal_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 3, role_name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(s);
    sqlite3_finalize(s);
    return {};
}

// ── Groups CRUD ──────────────────────────────────────────────────────────────

std::vector<RbacGroup> RbacStore::list_groups() const {
    std::vector<RbacGroup> result;
    if (!db_)
        return result;
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(
            db_,
            "SELECT name, description, source, external_id, created_at FROM groups ORDER BY name;",
            -1, &s, nullptr) != SQLITE_OK)
        return result;
    while (sqlite3_step(s) == SQLITE_ROW) {
        RbacGroup g;
        g.name = reinterpret_cast<const char*>(sqlite3_column_text(s, 0));
        g.description = reinterpret_cast<const char*>(sqlite3_column_text(s, 1));
        g.source = reinterpret_cast<const char*>(sqlite3_column_text(s, 2));
        auto* eid = reinterpret_cast<const char*>(sqlite3_column_text(s, 3));
        g.external_id = eid ? eid : "";
        g.created_at = sqlite3_column_int64(s, 4);
        result.push_back(std::move(g));
    }
    sqlite3_finalize(s);
    return result;
}

std::expected<void, std::string> RbacStore::create_group(const RbacGroup& group) {
    if (!db_)
        return std::unexpected("database not open");
    if (group.name.empty())
        return std::unexpected("group name cannot be empty");
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count();
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "INSERT INTO groups (name, description, source, external_id, "
                           "created_at) VALUES (?, ?, ?, ?, ?);",
                           -1, &s, nullptr) != SQLITE_OK)
        return std::unexpected(sqlite3_errmsg(db_));
    sqlite3_bind_text(s, 1, group.name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 2, group.description.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 3, group.source.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 4, group.external_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(s, 5, now);
    int rc = sqlite3_step(s);
    sqlite3_finalize(s);
    if (rc != SQLITE_DONE)
        return std::unexpected(std::string("group already exists or DB error: ") +
                               sqlite3_errmsg(db_));
    return {};
}

std::expected<void, std::string> RbacStore::delete_group(const std::string& name) {
    if (!db_)
        return std::unexpected("database not open");
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_, "DELETE FROM groups WHERE name = ?;", -1, &s, nullptr) != SQLITE_OK)
        return std::unexpected(sqlite3_errmsg(db_));
    sqlite3_bind_text(s, 1, name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(s);
    sqlite3_finalize(s);
    return {};
}

std::vector<std::string> RbacStore::get_group_members(const std::string& group_name) const {
    std::vector<std::string> result;
    if (!db_)
        return result;
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(
            db_, "SELECT username FROM group_members WHERE group_name = ? ORDER BY username;", -1,
            &s, nullptr) != SQLITE_OK)
        return result;
    sqlite3_bind_text(s, 1, group_name.c_str(), -1, SQLITE_TRANSIENT);
    while (sqlite3_step(s) == SQLITE_ROW)
        result.emplace_back(reinterpret_cast<const char*>(sqlite3_column_text(s, 0)));
    sqlite3_finalize(s);
    return result;
}

std::expected<void, std::string> RbacStore::add_group_member(const std::string& group_name,
                                                             const std::string& username) {
    if (!db_)
        return std::unexpected("database not open");
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(
            db_, "INSERT OR IGNORE INTO group_members (group_name, username) VALUES (?, ?);", -1,
            &s, nullptr) != SQLITE_OK)
        return std::unexpected(sqlite3_errmsg(db_));
    sqlite3_bind_text(s, 1, group_name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 2, username.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(s);
    sqlite3_finalize(s);
    return {};
}

std::expected<void, std::string> RbacStore::remove_group_member(const std::string& group_name,
                                                                const std::string& username) {
    if (!db_)
        return std::unexpected("database not open");
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_, "DELETE FROM group_members WHERE group_name = ? AND username = ?;",
                           -1, &s, nullptr) != SQLITE_OK)
        return std::unexpected(sqlite3_errmsg(db_));
    sqlite3_bind_text(s, 1, group_name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 2, username.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(s);
    sqlite3_finalize(s);
    return {};
}

// ── Authorization check ──────────────────────────────────────────────────────

std::vector<std::string> RbacStore::collect_roles(const std::string& username) const {
    std::vector<std::string> roles;
    if (!db_)
        return roles;

    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "SELECT role_name FROM principal_roles "
                           "WHERE principal_type = 'user' AND principal_id = ? "
                           "UNION "
                           "SELECT pr.role_name FROM principal_roles pr "
                           "JOIN group_members gm ON pr.principal_type = 'group' AND "
                           "pr.principal_id = gm.group_name "
                           "WHERE gm.username = ?;",
                           -1, &s, nullptr) != SQLITE_OK)
        return roles;
    sqlite3_bind_text(s, 1, username.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 2, username.c_str(), -1, SQLITE_TRANSIENT);
    while (sqlite3_step(s) == SQLITE_ROW)
        roles.emplace_back(reinterpret_cast<const char*>(sqlite3_column_text(s, 0)));
    sqlite3_finalize(s);
    return roles;
}

bool RbacStore::check_permission(const std::string& username, const std::string& securable_type,
                                 const std::string& operation) const {
    if (!db_)
        return false;

    auto roles = collect_roles(username);
    if (roles.empty())
        return false;

    // Build a parameterized IN clause for the collected roles
    std::string placeholders;
    for (size_t i = 0; i < roles.size(); ++i) {
        if (i > 0)
            placeholders += ',';
        placeholders += '?';
    }

    std::string sql = "SELECT effect FROM role_permissions "
                      "WHERE securable_type = ? AND operation = ? AND role_name IN (" +
                      placeholders + ");";

    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &s, nullptr) != SQLITE_OK)
        return false;

    sqlite3_bind_text(s, 1, securable_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 2, operation.c_str(), -1, SQLITE_TRANSIENT);
    for (size_t i = 0; i < roles.size(); ++i)
        sqlite3_bind_text(s, static_cast<int>(3 + i), roles[i].c_str(), -1, SQLITE_TRANSIENT);

    bool has_allow = false;
    while (sqlite3_step(s) == SQLITE_ROW) {
        auto* effect = reinterpret_cast<const char*>(sqlite3_column_text(s, 0));
        if (effect && std::string(effect) == "deny") {
            sqlite3_finalize(s);
            return false; // deny overrides everything
        }
        if (effect && std::string(effect) == "allow")
            has_allow = true;
    }
    sqlite3_finalize(s);
    return has_allow;
}

std::vector<Permission> RbacStore::get_effective_permissions(const std::string& username) const {
    std::vector<Permission> result;
    if (!db_)
        return result;

    auto roles = collect_roles(username);
    if (roles.empty())
        return result;

    std::string placeholders;
    for (size_t i = 0; i < roles.size(); ++i) {
        if (i > 0)
            placeholders += ',';
        placeholders += '?';
    }

    std::string sql = "SELECT role_name, securable_type, operation, effect FROM role_permissions "
                      "WHERE role_name IN (" +
                      placeholders + ") ORDER BY securable_type, operation;";

    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &s, nullptr) != SQLITE_OK)
        return result;

    for (size_t i = 0; i < roles.size(); ++i)
        sqlite3_bind_text(s, static_cast<int>(1 + i), roles[i].c_str(), -1, SQLITE_TRANSIENT);

    while (sqlite3_step(s) == SQLITE_ROW) {
        Permission p;
        p.role_name = reinterpret_cast<const char*>(sqlite3_column_text(s, 0));
        p.securable_type = reinterpret_cast<const char*>(sqlite3_column_text(s, 1));
        p.operation = reinterpret_cast<const char*>(sqlite3_column_text(s, 2));
        p.effect = reinterpret_cast<const char*>(sqlite3_column_text(s, 3));
        result.push_back(std::move(p));
    }
    sqlite3_finalize(s);
    return result;
}

// ── Reference data ───────────────────────────────────────────────────────────

std::vector<std::string> RbacStore::list_securable_types() const {
    std::vector<std::string> result;
    if (!db_)
        return result;
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_, "SELECT name FROM securable_types ORDER BY name;", -1, &s,
                           nullptr) != SQLITE_OK)
        return result;
    while (sqlite3_step(s) == SQLITE_ROW)
        result.emplace_back(reinterpret_cast<const char*>(sqlite3_column_text(s, 0)));
    sqlite3_finalize(s);
    return result;
}

std::vector<std::string> RbacStore::list_operations() const {
    std::vector<std::string> result;
    if (!db_)
        return result;
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_, "SELECT id FROM operations ORDER BY id;", -1, &s, nullptr) !=
        SQLITE_OK)
        return result;
    while (sqlite3_step(s) == SQLITE_ROW)
        result.emplace_back(reinterpret_cast<const char*>(sqlite3_column_text(s, 0)));
    sqlite3_finalize(s);
    return result;
}

// ── Scoped permission check ──────────────────────────────────────────────────

bool RbacStore::check_scoped_permission(const std::string& username,
                                        const std::string& securable_type,
                                        const std::string& operation,
                                        const std::string& agent_id,
                                        const ManagementGroupStore* mgmt_store) const {
    // 1. Try global permission first — if passes, return true immediately
    if (check_permission(username, securable_type, operation))
        return true;

    // 2. If no mgmt_store or no agent_id, cannot do scoped check
    if (!mgmt_store || agent_id.empty())
        return false;

    // 3. Get agent's management groups + ancestors
    auto groups = mgmt_store->get_agent_groups(agent_id);
    std::unordered_set<std::string> all_groups;
    for (const auto& gid : groups) {
        all_groups.insert(gid);
        auto ancestors = mgmt_store->get_ancestor_ids(gid);
        for (const auto& aid : ancestors)
            all_groups.insert(aid);
    }

    if (all_groups.empty())
        return false;

    // 4. Collect user's RBAC group memberships
    std::unordered_set<std::string> user_rbac_groups;
    if (db_) {
        sqlite3_stmt* s = nullptr;
        if (sqlite3_prepare_v2(db_, "SELECT group_name FROM group_members WHERE username = ?;", -1,
                               &s, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(s, 1, username.c_str(), -1, SQLITE_TRANSIENT);
            while (sqlite3_step(s) == SQLITE_ROW) {
                auto* g = reinterpret_cast<const char*>(sqlite3_column_text(s, 0));
                if (g)
                    user_rbac_groups.insert(g);
            }
            sqlite3_finalize(s);
        }
    }

    // 5. For each management group, check role assignments
    bool has_allow = false;
    for (const auto& gid : all_groups) {
        auto assignments = mgmt_store->get_group_roles(gid);
        for (const auto& assignment : assignments) {
            // Check if this assignment is for our user
            bool matches = false;
            if (assignment.principal_type == "user" && assignment.principal_id == username)
                matches = true;
            else if (assignment.principal_type == "group" &&
                     user_rbac_groups.contains(assignment.principal_id))
                matches = true;

            if (!matches)
                continue;

            // Check if the assigned role grants the required permission
            auto perms = get_role_permissions(assignment.role_name);
            for (const auto& p : perms) {
                if (p.securable_type == securable_type && p.operation == operation) {
                    if (p.effect == "deny")
                        return false; // deny overrides
                    if (p.effect == "allow")
                        has_allow = true;
                }
            }
        }
    }

    return has_allow;
}

} // namespace yuzu::server
