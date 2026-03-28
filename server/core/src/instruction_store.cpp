#include "instruction_store.hpp"

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <chrono>
#include <mutex>
#include <random>

namespace yuzu::server {

namespace {

std::string generate_id() {
    static thread_local std::mt19937_64 rng(std::random_device{}());
    std::uniform_int_distribution<uint64_t> dist;
    auto hi = dist(rng);
    auto lo = dist(rng);
    char buf[33];
    std::snprintf(buf, sizeof(buf), "%016llx%016llx", static_cast<unsigned long long>(hi),
                  static_cast<unsigned long long>(lo));
    return std::string(buf, 32);
}

int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::string col_text(sqlite3_stmt* stmt, int col) {
    auto p = sqlite3_column_text(stmt, col);
    return p ? std::string(reinterpret_cast<const char*>(p)) : std::string{};
}

InstructionDefinition row_to_def(sqlite3_stmt* stmt) {
    InstructionDefinition d;
    d.id = col_text(stmt, 0);
    d.name = col_text(stmt, 1);
    d.version = col_text(stmt, 2);
    d.type = col_text(stmt, 3);
    d.plugin = col_text(stmt, 4);
    d.action = col_text(stmt, 5);
    d.description = col_text(stmt, 6);
    d.enabled = sqlite3_column_int(stmt, 7) != 0;
    d.instruction_set_id = col_text(stmt, 8);
    d.gather_ttl_seconds = sqlite3_column_int(stmt, 9);
    d.response_ttl_days = sqlite3_column_int(stmt, 10);
    d.created_by = col_text(stmt, 11);
    d.created_at = sqlite3_column_int64(stmt, 12);
    d.updated_at = sqlite3_column_int64(stmt, 13);
    d.yaml_source = col_text(stmt, 14);
    d.parameter_schema = col_text(stmt, 15);
    d.result_schema = col_text(stmt, 16);
    d.approval_mode = col_text(stmt, 17);
    d.concurrency_mode = col_text(stmt, 18);
    d.platforms = col_text(stmt, 19);
    d.min_agent_version = col_text(stmt, 20);
    d.required_plugins = col_text(stmt, 21);
    d.readable_payload = col_text(stmt, 22);
    return d;
}

const char* kSelectAllCols = "id, name, version, type, plugin, action, description, "
                             "enabled, instruction_set_id, gather_ttl_seconds, response_ttl_days, "
                             "created_by, created_at, updated_at, "
                             "yaml_source, parameter_schema, result_schema, approval_mode, "
                             "concurrency_mode, platforms, min_agent_version, required_plugins, "
                             "readable_payload";

} // namespace

InstructionStore::InstructionStore(const std::filesystem::path& db_path) {
    int rc = sqlite3_open(db_path.string().c_str(), &db_);
    if (rc != SQLITE_OK) {
        spdlog::error("InstructionStore: failed to open DB {}: {}", db_path.string(),
                      sqlite3_errmsg(db_));
        if (db_) {
            sqlite3_close(db_);
            db_ = nullptr;
        }
        return;
    }
    sqlite3_exec(db_, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "PRAGMA busy_timeout=5000;", nullptr, nullptr, nullptr);

    const char* ddl = R"(
        CREATE TABLE IF NOT EXISTS instruction_definitions (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            version TEXT NOT NULL DEFAULT '1.0',
            type TEXT NOT NULL,
            plugin TEXT NOT NULL,
            action TEXT NOT NULL DEFAULT '',
            description TEXT NOT NULL DEFAULT '',
            enabled INTEGER NOT NULL DEFAULT 1,
            instruction_set_id TEXT NOT NULL DEFAULT '',
            gather_ttl_seconds INTEGER NOT NULL DEFAULT 300,
            response_ttl_days INTEGER NOT NULL DEFAULT 90,
            created_by TEXT NOT NULL DEFAULT '',
            created_at INTEGER NOT NULL DEFAULT 0,
            updated_at INTEGER NOT NULL DEFAULT 0,
            yaml_source TEXT NOT NULL DEFAULT '',
            parameter_schema TEXT NOT NULL DEFAULT '{}',
            result_schema TEXT NOT NULL DEFAULT '{}',
            approval_mode TEXT NOT NULL DEFAULT 'auto',
            concurrency_mode TEXT NOT NULL DEFAULT 'per-device',
            platforms TEXT NOT NULL DEFAULT '',
            min_agent_version TEXT NOT NULL DEFAULT '',
            required_plugins TEXT NOT NULL DEFAULT '',
            readable_payload TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS instruction_sets (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            created_by TEXT NOT NULL DEFAULT '',
            created_at INTEGER NOT NULL DEFAULT 0
        );
    )";
    char* err = nullptr;
    if (sqlite3_exec(db_, ddl, nullptr, nullptr, &err) != SQLITE_OK) {
        spdlog::error("InstructionStore: DDL failed: {}", err ? err : "unknown");
        sqlite3_free(err);
    }

    // Migrate: add new columns if upgrading from an older schema
    const char* migrations[] = {
        "ALTER TABLE instruction_definitions ADD COLUMN yaml_source TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE instruction_definitions ADD COLUMN parameter_schema TEXT NOT NULL DEFAULT "
        "'{}'",
        "ALTER TABLE instruction_definitions ADD COLUMN result_schema TEXT NOT NULL DEFAULT '{}'",
        "ALTER TABLE instruction_definitions ADD COLUMN approval_mode TEXT NOT NULL DEFAULT 'auto'",
        "ALTER TABLE instruction_definitions ADD COLUMN concurrency_mode TEXT NOT NULL DEFAULT "
        "'per-device'",
        "ALTER TABLE instruction_definitions ADD COLUMN platforms TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE instruction_definitions ADD COLUMN min_agent_version TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE instruction_definitions ADD COLUMN required_plugins TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE instruction_definitions ADD COLUMN readable_payload TEXT NOT NULL DEFAULT ''",
    };
    for (const auto* m : migrations) {
        sqlite3_exec(db_, m, nullptr, nullptr, nullptr); // ignore "duplicate column" errors
    }

    spdlog::info("InstructionStore: opened {}", db_path.string());
}

InstructionStore::~InstructionStore() {
    if (db_)
        sqlite3_close(db_);
}

bool InstructionStore::is_open() const {
    return db_ != nullptr;
}

// ---------------------------------------------------------------------------
// Definitions CRUD
// ---------------------------------------------------------------------------

std::vector<InstructionDefinition>
InstructionStore::query_definitions(const InstructionQuery& q) const {
    std::shared_lock lock(mtx_);
    std::vector<InstructionDefinition> results;
    if (!db_)
        return results;

    std::string sql =
        std::string("SELECT ") + kSelectAllCols + " FROM instruction_definitions WHERE 1=1";
    std::vector<std::string> binds;

    if (!q.name_filter.empty()) {
        sql += " AND name LIKE ?";
        binds.push_back("%" + q.name_filter + "%");
    }
    if (!q.plugin_filter.empty()) {
        sql += " AND plugin = ?";
        binds.push_back(q.plugin_filter);
    }
    if (!q.type_filter.empty()) {
        sql += " AND type = ?";
        binds.push_back(q.type_filter);
    }
    if (!q.set_id_filter.empty()) {
        sql += " AND instruction_set_id = ?";
        binds.push_back(q.set_id_filter);
    }
    if (q.enabled_only) {
        sql += " AND enabled = 1";
    }
    sql += " ORDER BY name ASC LIMIT ?";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
        return results;

    for (int i = 0; i < static_cast<int>(binds.size()); ++i)
        sqlite3_bind_text(stmt, i + 1, binds[i].c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, static_cast<int>(binds.size()) + 1, q.limit);

    while (sqlite3_step(stmt) == SQLITE_ROW)
        results.push_back(row_to_def(stmt));

    sqlite3_finalize(stmt);
    return results;
}

std::optional<InstructionDefinition> InstructionStore::get_definition(const std::string& id) const {
    std::shared_lock lock(mtx_);
    return get_definition_impl(id);
}

std::optional<InstructionDefinition> InstructionStore::get_definition_impl(const std::string& id) const {
    if (!db_)
        return std::nullopt;

    auto sql =
        std::string("SELECT ") + kSelectAllCols + " FROM instruction_definitions WHERE id = ?";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
        return std::nullopt;

    sqlite3_bind_text(stmt, 1, id.c_str(), -1, SQLITE_TRANSIENT);
    std::optional<InstructionDefinition> result;
    if (sqlite3_step(stmt) == SQLITE_ROW)
        result = row_to_def(stmt);

    sqlite3_finalize(stmt);
    return result;
}

std::expected<std::string, std::string>
InstructionStore::create_definition(const InstructionDefinition& def) {
    std::unique_lock lock(mtx_);
    return create_definition_impl(def);
}

std::expected<std::string, std::string>
InstructionStore::create_definition_impl(const InstructionDefinition& def) {
    if (!db_)
        return std::unexpected("database not open");
    if (def.name.empty())
        return std::unexpected("name is required");
    if (def.type != "question" && def.type != "action")
        return std::unexpected("type must be 'question' or 'action'");
    if (def.plugin.empty())
        return std::unexpected("plugin is required");

    auto id = def.id.empty() ? generate_id() : def.id;
    auto now = now_epoch();

    const char* sql = R"(
        INSERT INTO instruction_definitions
        (id, name, version, type, plugin, action, description, enabled,
         instruction_set_id, gather_ttl_seconds, response_ttl_days,
         created_by, created_at, updated_at,
         yaml_source, parameter_schema, result_schema, approval_mode,
         concurrency_mode, platforms, min_agent_version, required_plugins,
         readable_payload)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    )";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return std::unexpected(std::string("prepare failed: ") + sqlite3_errmsg(db_));

    int i = 1;
    sqlite3_bind_text(stmt, i++, id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, i++, def.name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, i++, def.version.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, i++, def.type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, i++, def.plugin.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, i++, def.action.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, i++, def.description.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, i++, def.enabled ? 1 : 0);
    sqlite3_bind_text(stmt, i++, def.instruction_set_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, i++, def.gather_ttl_seconds);
    sqlite3_bind_int(stmt, i++, def.response_ttl_days);
    sqlite3_bind_text(stmt, i++, def.created_by.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, i++, def.created_at > 0 ? def.created_at : now);
    sqlite3_bind_int64(stmt, i++, now);
    sqlite3_bind_text(stmt, i++, def.yaml_source.c_str(), -1, SQLITE_TRANSIENT);
    auto ps = def.parameter_schema.empty() ? "{}" : def.parameter_schema;
    sqlite3_bind_text(stmt, i++, ps.c_str(), -1, SQLITE_TRANSIENT);
    auto rs = def.result_schema.empty() ? "{}" : def.result_schema;
    sqlite3_bind_text(stmt, i++, rs.c_str(), -1, SQLITE_TRANSIENT);
    auto am = def.approval_mode.empty() ? "auto" : def.approval_mode;
    sqlite3_bind_text(stmt, i++, am.c_str(), -1, SQLITE_TRANSIENT);
    auto cm = def.concurrency_mode.empty() ? "per-device" : def.concurrency_mode;
    sqlite3_bind_text(stmt, i++, cm.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, i++, def.platforms.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, i++, def.min_agent_version.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, i++, def.required_plugins.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, i++, def.readable_payload.c_str(), -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        auto err = std::string(sqlite3_errmsg(db_));
        sqlite3_finalize(stmt);
        return std::unexpected("insert failed: " + err);
    }
    sqlite3_finalize(stmt);
    return id;
}

std::expected<void, std::string>
InstructionStore::update_definition(const InstructionDefinition& def) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return std::unexpected("database not open");
    if (def.id.empty())
        return std::unexpected("id is required for update");

    const char* sql = R"(
        UPDATE instruction_definitions SET
            name=?, version=?, type=?, plugin=?, action=?, description=?,
            enabled=?, instruction_set_id=?, gather_ttl_seconds=?, response_ttl_days=?,
            updated_at=?,
            yaml_source=?, parameter_schema=?, result_schema=?, approval_mode=?,
            concurrency_mode=?, platforms=?, min_agent_version=?, required_plugins=?,
            readable_payload=?
        WHERE id=?
    )";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return std::unexpected(std::string("prepare failed: ") + sqlite3_errmsg(db_));

    int i = 1;
    sqlite3_bind_text(stmt, i++, def.name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, i++, def.version.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, i++, def.type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, i++, def.plugin.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, i++, def.action.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, i++, def.description.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, i++, def.enabled ? 1 : 0);
    sqlite3_bind_text(stmt, i++, def.instruction_set_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, i++, def.gather_ttl_seconds);
    sqlite3_bind_int(stmt, i++, def.response_ttl_days);
    sqlite3_bind_int64(stmt, i++, now_epoch());
    sqlite3_bind_text(stmt, i++, def.yaml_source.c_str(), -1, SQLITE_TRANSIENT);
    auto ps = def.parameter_schema.empty() ? "{}" : def.parameter_schema;
    sqlite3_bind_text(stmt, i++, ps.c_str(), -1, SQLITE_TRANSIENT);
    auto rs = def.result_schema.empty() ? "{}" : def.result_schema;
    sqlite3_bind_text(stmt, i++, rs.c_str(), -1, SQLITE_TRANSIENT);
    auto am = def.approval_mode.empty() ? "auto" : def.approval_mode;
    sqlite3_bind_text(stmt, i++, am.c_str(), -1, SQLITE_TRANSIENT);
    auto cm = def.concurrency_mode.empty() ? "per-device" : def.concurrency_mode;
    sqlite3_bind_text(stmt, i++, cm.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, i++, def.platforms.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, i++, def.min_agent_version.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, i++, def.required_plugins.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, i++, def.readable_payload.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, i++, def.id.c_str(), -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        auto err = std::string(sqlite3_errmsg(db_));
        sqlite3_finalize(stmt);
        return std::unexpected("update failed: " + err);
    }
    auto changes = sqlite3_changes(db_);
    sqlite3_finalize(stmt);
    if (changes == 0)
        return std::unexpected("definition not found");
    return {};
}

bool InstructionStore::delete_definition(const std::string& id) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return false;

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, "DELETE FROM instruction_definitions WHERE id=?", -1, &stmt,
                           nullptr) != SQLITE_OK)
        return false;

    sqlite3_bind_text(stmt, 1, id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    auto changes = sqlite3_changes(db_);
    sqlite3_finalize(stmt);
    return changes > 0;
}

// ---------------------------------------------------------------------------
// Import / Export
// ---------------------------------------------------------------------------

std::string InstructionStore::export_definition_json(const std::string& id) const {
    std::shared_lock lock(mtx_);
    auto def = get_definition_impl(id);
    if (!def)
        return "{}";

    nlohmann::json j;
    j["id"] = def->id;
    j["name"] = def->name;
    j["version"] = def->version;
    j["type"] = def->type;
    j["plugin"] = def->plugin;
    j["action"] = def->action;
    j["description"] = def->description;
    j["enabled"] = def->enabled;
    j["instruction_set_id"] = def->instruction_set_id;
    j["gather_ttl_seconds"] = def->gather_ttl_seconds;
    j["response_ttl_days"] = def->response_ttl_days;
    j["created_by"] = def->created_by;
    j["created_at"] = def->created_at;
    j["updated_at"] = def->updated_at;
    j["yaml_source"] = def->yaml_source;
    j["parameter_schema"] = def->parameter_schema;
    j["result_schema"] = def->result_schema;
    j["approval_mode"] = def->approval_mode;
    j["concurrency_mode"] = def->concurrency_mode;
    j["platforms"] = def->platforms;
    j["min_agent_version"] = def->min_agent_version;
    j["required_plugins"] = def->required_plugins;
    j["readable_payload"] = def->readable_payload;
    return j.dump(2);
}

std::expected<std::string, std::string>
InstructionStore::import_definition_json(const std::string& json_str) {
    auto parsed = nlohmann::json::parse(json_str, nullptr, false);
    if (parsed.is_discarded())
        return std::unexpected("invalid JSON");

    std::unique_lock lock(mtx_);

    InstructionDefinition def;
    if (parsed.contains("id"))
        def.id = parsed["id"].get<std::string>();
    if (parsed.contains("name"))
        def.name = parsed["name"].get<std::string>();
    if (parsed.contains("version"))
        def.version = parsed.value("version", "1.0");
    if (parsed.contains("type"))
        def.type = parsed["type"].get<std::string>();
    if (parsed.contains("plugin"))
        def.plugin = parsed["plugin"].get<std::string>();
    if (parsed.contains("action"))
        def.action = parsed.value("action", "");
    if (parsed.contains("description"))
        def.description = parsed.value("description", "");
    if (parsed.contains("enabled"))
        def.enabled = parsed.value("enabled", true);
    if (parsed.contains("instruction_set_id"))
        def.instruction_set_id = parsed.value("instruction_set_id", "");
    if (parsed.contains("gather_ttl_seconds"))
        def.gather_ttl_seconds = parsed.value("gather_ttl_seconds", 300);
    if (parsed.contains("response_ttl_days"))
        def.response_ttl_days = parsed.value("response_ttl_days", 90);
    if (parsed.contains("created_by"))
        def.created_by = parsed.value("created_by", "");
    if (parsed.contains("yaml_source"))
        def.yaml_source = parsed.value("yaml_source", "");
    if (parsed.contains("parameter_schema"))
        def.parameter_schema = parsed.value("parameter_schema", "{}");
    if (parsed.contains("result_schema"))
        def.result_schema = parsed.value("result_schema", "{}");
    if (parsed.contains("approval_mode"))
        def.approval_mode = parsed.value("approval_mode", "auto");
    if (parsed.contains("concurrency_mode"))
        def.concurrency_mode = parsed.value("concurrency_mode", "per-device");
    if (parsed.contains("platforms"))
        def.platforms = parsed.value("platforms", "");
    if (parsed.contains("min_agent_version"))
        def.min_agent_version = parsed.value("min_agent_version", "");
    if (parsed.contains("required_plugins"))
        def.required_plugins = parsed.value("required_plugins", "");
    if (parsed.contains("readable_payload"))
        def.readable_payload = parsed.value("readable_payload", "");

    return create_definition_impl(def);
}

// ---------------------------------------------------------------------------
// Instruction Sets
// ---------------------------------------------------------------------------

std::vector<InstructionSet> InstructionStore::list_sets() const {
    std::shared_lock lock(mtx_);
    std::vector<InstructionSet> results;
    if (!db_)
        return results;

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "SELECT id, name, description, created_by, created_at FROM "
                           "instruction_sets ORDER BY name",
                           -1, &stmt, nullptr) != SQLITE_OK)
        return results;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        InstructionSet s;
        s.id = col_text(stmt, 0);
        s.name = col_text(stmt, 1);
        s.description = col_text(stmt, 2);
        s.created_by = col_text(stmt, 3);
        s.created_at = sqlite3_column_int64(stmt, 4);
        results.push_back(std::move(s));
    }
    sqlite3_finalize(stmt);
    return results;
}

std::expected<std::string, std::string> InstructionStore::create_set(const InstructionSet& s) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return std::unexpected("database not open");
    if (s.name.empty())
        return std::unexpected("name is required");

    auto id = s.id.empty() ? generate_id() : s.id;

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "INSERT INTO instruction_sets (id, name, description, created_by, "
                           "created_at) VALUES (?,?,?,?,?)",
                           -1, &stmt, nullptr) != SQLITE_OK)
        return std::unexpected(std::string("prepare failed: ") + sqlite3_errmsg(db_));

    sqlite3_bind_text(stmt, 1, id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, s.name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, s.description.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, s.created_by.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 5, s.created_at > 0 ? s.created_at : now_epoch());

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        auto err = std::string(sqlite3_errmsg(db_));
        sqlite3_finalize(stmt);
        return std::unexpected("insert failed: " + err);
    }
    sqlite3_finalize(stmt);
    return id;
}

bool InstructionStore::delete_set(const std::string& id) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return false;

    // Unset instruction_set_id on definitions that reference this set
    sqlite3_stmt* upd = nullptr;
    if (sqlite3_prepare_v2(
            db_,
            "UPDATE instruction_definitions SET instruction_set_id='' WHERE instruction_set_id=?",
            -1, &upd, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(upd, 1, id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(upd);
        sqlite3_finalize(upd);
    }

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, "DELETE FROM instruction_sets WHERE id=?", -1, &stmt, nullptr) !=
        SQLITE_OK)
        return false;

    sqlite3_bind_text(stmt, 1, id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    auto changes = sqlite3_changes(db_);
    sqlite3_finalize(stmt);
    return changes > 0;
}

} // namespace yuzu::server
