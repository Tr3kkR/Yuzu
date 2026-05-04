#include "instruction_store.hpp"
#include "migration_runner.hpp"
#include "response_templates_engine.hpp"
#include "store_errors.hpp"

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

/// Issue #587: visualization_spec is stored as a JSON array of chart
/// objects so the engine sees one shape. This helper takes whatever the
/// caller supplied (object, array, or anything else) and emits a JSON
/// array string suitable for the column.
std::string normalize_to_array_helper(const nlohmann::json& v) {
    if (v.is_array()) {
        // Filter to keep only object entries; non-object array entries
        // (null, scalar, nested array) are dropped silently. The engine
        // does strict validation on the chart objects themselves.
        nlohmann::json out = nlohmann::json::array();
        for (const auto& el : v) {
            if (el.is_object()) out.push_back(el);
        }
        return out.dump();
    }
    if (v.is_object()) {
        // Singular spec.visualization YAML form — wrap as a 1-element array.
        nlohmann::json out = nlohmann::json::array();
        out.push_back(v);
        return out.dump();
    }
    // Anything else (null, scalar): treat as "no visualization configured".
    return "[]";
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
    d.visualization_spec = col_text(stmt, 23);
    d.response_templates_spec = col_text(stmt, 24);
    return d;
}

const char* kSelectAllCols = "id, name, version, type, plugin, action, description, "
                             "enabled, instruction_set_id, gather_ttl_seconds, response_ttl_days, "
                             "created_by, created_at, updated_at, "
                             "yaml_source, parameter_schema, result_schema, approval_mode, "
                             "concurrency_mode, platforms, min_agent_version, required_plugins, "
                             "readable_payload, visualization_spec, response_templates_spec";

} // namespace

InstructionStore::InstructionStore(const std::filesystem::path& db_path) {
    int rc = sqlite3_open_v2(db_path.string().c_str(), &db_,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                             nullptr);
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

    // Legacy compat: bring pre-v0.10 databases up to v1's schema before stamping.
    // v1's CREATE TABLE IF NOT EXISTS is a no-op on existing tables, so columns
    // added historically via silent ALTERs must still be applied here.
    const char* legacy_alters[] = {
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
        // visualization_spec was deliberately moved out of this list and into
        // migration v2 below — see governance arch-B1 / F-6. The legacy ALTER
        // pattern stays only for columns that predate MigrationRunner.
    };
    for (const auto* m : legacy_alters) {
        sqlite3_exec(db_, m, nullptr, nullptr, nullptr); // ignore "duplicate column" errors
    }

    // Issue #253: visualization_spec is added in v2 rather than retroactively
    // edited into v1's CREATE TABLE so the migration ledger remains an
    // accurate historical record (governance arch-B1 / F-6). The legacy
    // ALTER above keeps pre-MigrationRunner deployments alive; v2 ensures
    // that DBs initialised post-#253 see the column even if the legacy
    // ALTER ever changes shape.
    static const std::vector<Migration> kMigrations = {
        {1, R"(
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
        )"},
        // Issue #253: chart visualization spec on InstructionDefinition.
        // SQLite's `ALTER TABLE ADD COLUMN` is NOT idempotent — it returns
        // SQLITE_ERROR on a duplicate column, which the migration runner
        // treats as a fatal failure. Any DB that already has the column
        // (e.g. a developer who ran the very first iteration of this PR
        // before the column moved out of `legacy_alters[]`) would wedge
        // the store. The probe-and-stamp dance below pre-records v2 in
        // `schema_meta` for those DBs so the migration runner skips the
        // ALTER entirely (governance arch-B2 / CP-5).
        {2, "ALTER TABLE instruction_definitions ADD COLUMN visualization_spec "
            "TEXT NOT NULL DEFAULT '{}';"},
        // Issue #254 (8.2): named response view configurations
        // (column subset + sort + filters) on InstructionDefinition. Same
        // probe-and-stamp pattern as v2.
        {3, "ALTER TABLE instruction_definitions ADD COLUMN response_templates_spec "
            "TEXT NOT NULL DEFAULT '[]';"},
    };
    // Pre-migration probe: stamp schema_meta past any version whose ALTER
    // would duplicate-column on the live DB (so the runner skips it). Same
    // technique as the original v2 guard (governance arch-B2 / CP-5),
    // generalised so v3 inherits the protection.
    //
    // UP-4 hardening (Gate 4 governance): every SQLite step return is
    // checked. If the stamp insert fails, we close the DB rather than
    // letting the migration runner attempt the duplicate-column ALTER —
    // a silent-stamp + duplicate-column-ALTER chain wedged the store
    // (`is_open()` false) with no diagnostic, leaving the operator
    // staring at /readyz="ok" while every definition call returned 503.
    bool stamp_failed = false;
    auto probe_and_stamp = [&](const char* column_name, int target_version) {
        if (stamp_failed) return; // earlier stamp failed; skip remaining
        sqlite3_stmt* probe = nullptr;
        bool col_exists = false;
        int rc = sqlite3_prepare_v2(db_,
                                    "SELECT 1 FROM pragma_table_info('instruction_definitions') "
                                    "WHERE name=? LIMIT 1",
                                    -1, &probe, nullptr);
        if (rc != SQLITE_OK) {
            spdlog::error(
                "InstructionStore: probe prepare failed for {} (rc={}): {}",
                column_name, rc, sqlite3_errmsg(db_));
            stamp_failed = true;
            return;
        }
        sqlite3_bind_text(probe, 1, column_name, -1, SQLITE_TRANSIENT);
        int probe_rc = sqlite3_step(probe);
        if (probe_rc != SQLITE_ROW && probe_rc != SQLITE_DONE) {
            spdlog::error(
                "InstructionStore: probe step failed for {} (rc={}): {}",
                column_name, probe_rc, sqlite3_errmsg(db_));
            sqlite3_finalize(probe);
            stamp_failed = true;
            return;
        }
        col_exists = (probe_rc == SQLITE_ROW);
        sqlite3_finalize(probe);

        int current_v = MigrationRunner::current_version(db_, "instruction_store");
        if (col_exists && current_v < target_version) {
            sqlite3_stmt* stamp = nullptr;
            int prep_rc = sqlite3_prepare_v2(
                db_,
                "INSERT OR REPLACE INTO schema_meta "
                "(store, version, upgraded_at) VALUES (?, ?, ?)",
                -1, &stamp, nullptr);
            if (prep_rc != SQLITE_OK) {
                spdlog::error(
                    "InstructionStore: stamp prepare failed for v{} ({}): {}",
                    target_version, column_name, sqlite3_errmsg(db_));
                stamp_failed = true;
                return;
            }
            auto now = std::chrono::duration_cast<std::chrono::seconds>(
                           std::chrono::system_clock::now().time_since_epoch())
                           .count();
            sqlite3_bind_text(stamp, 1, "instruction_store", -1, SQLITE_STATIC);
            sqlite3_bind_int(stamp, 2, target_version);
            sqlite3_bind_int64(stamp, 3, now);
            int step_rc = sqlite3_step(stamp);
            sqlite3_finalize(stamp);
            if (step_rc != SQLITE_DONE) {
                spdlog::error(
                    "InstructionStore: stamp step failed for v{} ({}, rc={}): {}; "
                    "refusing to run migration ledger to avoid duplicate-column ALTER",
                    target_version, column_name, step_rc, sqlite3_errmsg(db_));
                stamp_failed = true;
                return;
            }
            spdlog::info(
                "InstructionStore: {} column already present, stamping schema_meta to v{} "
                "(arch-B2)",
                column_name, target_version);
        }
    };
    probe_and_stamp("visualization_spec", 2);
    probe_and_stamp("response_templates_spec", 3);
    if (stamp_failed) {
        spdlog::error("InstructionStore: probe-and-stamp failed; closing database "
                      "(governance UP-4 hardening — fail-closed instead of wedging boot)");
        sqlite3_close(db_);
        db_ = nullptr;
        return;
    }
    if (!MigrationRunner::run(db_, "instruction_store", kMigrations)) {
        spdlog::error("InstructionStore: schema migration failed, closing database");
        sqlite3_close(db_);
        db_ = nullptr;
        return;
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

    // #402: when caller supplies an explicit id, reject duplicates with the
    // shared kConflictPrefix the routes layer maps to HTTP 409. The id column
    // is PRIMARY KEY so SQLite would also reject the INSERT, but the
    // constraint failure surfaces as a generic "insert failed" error string
    // with no way for the route handler to distinguish a 409 from a 400. An
    // explicit pre-check under unique_lock keeps the error code accurate.
    //
    // sec-LOW2 / sre-1: prepare failure is treated as a hard error rather
    // than silently bypassing the duplicate check — under DB stress we want
    // the 409 contract to fail closed, not to silently degrade to "INSERT
    // anyway and hope SQLite's PK rejects it".
    if (!def.id.empty()) {
        sqlite3_stmt* exists_stmt = nullptr;
        if (sqlite3_prepare_v2(db_, "SELECT 1 FROM instruction_definitions WHERE id=? LIMIT 1",
                               -1, &exists_stmt, nullptr) != SQLITE_OK) {
            spdlog::error("InstructionStore: prepare failed in duplicate-id check: {}",
                          sqlite3_errmsg(db_));
            return std::unexpected("internal: duplicate-id check failed");
        }
        sqlite3_bind_text(exists_stmt, 1, id.c_str(), -1, SQLITE_TRANSIENT);
        bool exists = sqlite3_step(exists_stmt) == SQLITE_ROW;
        sqlite3_finalize(exists_stmt);
        if (exists)
            return std::unexpected(std::string(kConflictPrefix) +
                                   " instruction definition '" + id + "' already exists");
    }

    const char* sql = R"(
        INSERT INTO instruction_definitions
        (id, name, version, type, plugin, action, description, enabled,
         instruction_set_id, gather_ttl_seconds, response_ttl_days,
         created_by, created_at, updated_at,
         yaml_source, parameter_schema, result_schema, approval_mode,
         concurrency_mode, platforms, min_agent_version, required_plugins,
         readable_payload, visualization_spec, response_templates_spec)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
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
    auto vs = def.visualization_spec.empty() ? "{}" : def.visualization_spec;
    sqlite3_bind_text(stmt, i++, vs.c_str(), -1, SQLITE_TRANSIENT);
    auto rts = def.response_templates_spec.empty() ? "[]" : def.response_templates_spec;
    sqlite3_bind_text(stmt, i++, rts.c_str(), -1, SQLITE_TRANSIENT);

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
            readable_payload=?, visualization_spec=?, response_templates_spec=?
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
    auto vs = def.visualization_spec.empty() ? "{}" : def.visualization_spec;
    sqlite3_bind_text(stmt, i++, vs.c_str(), -1, SQLITE_TRANSIENT);
    auto rts = def.response_templates_spec.empty() ? "[]" : def.response_templates_spec;
    sqlite3_bind_text(stmt, i++, rts.c_str(), -1, SQLITE_TRANSIENT);
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
    j["visualization_spec"] = def->visualization_spec;
    j["response_templates_spec"] = def->response_templates_spec;
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
    // Issue #587: visualization_spec is stored as a JSON ARRAY of chart
    // objects so the engine and routes only have to handle one shape.
    // Accepted on the wire:
    //   * single chart object         {"type": "...", ...}
    //   * array of chart objects      [{...}, {...}]
    //   * pre-serialized JSON string  "{\"type\":\"pie\",...}" or "[...]"
    //   * legacy spec.visualization key from CLI YAML converters
    //   * canonical spec.visualizations (plural) array key
    // All forms normalise to "[{...}, {...}, ...]" before storage. Invalid
    // / non-object array entries are silently dropped at this point —
    // strict validation lives in the engine where the error is operator-
    // facing.
    auto normalize_to_array = [](const nlohmann::json& v) -> std::string {
        if (v.is_string()) {
            auto inner = nlohmann::json::parse(v.get<std::string>(), nullptr, false);
            if (inner.is_discarded()) return v.get<std::string>(); // pass through
            return normalize_to_array_helper(inner);
        }
        return normalize_to_array_helper(v);
    };
    auto pick_spec_field = [&]() -> std::optional<nlohmann::json> {
        if (parsed.contains("visualization_spec") && !parsed["visualization_spec"].is_null())
            return parsed["visualization_spec"];
        if (parsed.contains("visualizations") && !parsed["visualizations"].is_null())
            return parsed["visualizations"];
        if (parsed.contains("visualization") && !parsed["visualization"].is_null())
            return parsed["visualization"];
        return std::nullopt;
    };
    if (auto v = pick_spec_field(); v) {
        def.visualization_spec = normalize_to_array(*v);
    }

    // Issue #254 (8.2): spec.responseTemplates — accept canonical
    // `responseTemplates` (camelCase YAML), the snake-case storage column
    // name `response_templates_spec`, and the explicit pre-serialised
    // string form. Always normalises to a JSON array string at rest.
    auto pick_templates_field = [&]() -> std::optional<nlohmann::json> {
        if (parsed.contains("response_templates_spec") && !parsed["response_templates_spec"].is_null())
            return parsed["response_templates_spec"];
        if (parsed.contains("responseTemplates") && !parsed["responseTemplates"].is_null())
            return parsed["responseTemplates"];
        if (parsed.contains("response_templates") && !parsed["response_templates"].is_null())
            return parsed["response_templates"];
        return std::nullopt;
    };
    // Hardening (governance S-4 / sec-L3 / dsl-S2 / F-2): build the storage
    // form via a single normalisation pass that (a) accepts string / object /
    // array shapes, (b) bounds the inner string-form parse depth + size to
    // mitigate sec-M4 (operator-tier JSON bomb on import), and (c) silently
    // strips any element with `id == "__default__"` so an imported pack
    // cannot inject a stuck reserved-id row that REST PUT/DELETE refuse to
    // remove. UP-15 / UP-17: a malformed inner string is dropped with a
    // logged warning rather than passed through verbatim, so a bad import
    // surfaces in logs instead of silently wedging the templates view.
    static constexpr size_t kMaxImportTemplateStringBytes = 256 * 1024; // 256 KiB
    auto strip_reserved_id = [](const nlohmann::json& el) -> bool {
        if (!el.is_object()) return true; // drop non-objects entirely
        if (el.contains("id") && el["id"].is_string() &&
            el["id"].get<std::string>() ==
                std::string(::yuzu::server::ResponseTemplatesEngine::kDefaultId)) {
            return true; // drop reserved id
        }
        return false;
    };
    auto normalise_templates_array = [&](const nlohmann::json& src) -> nlohmann::json {
        nlohmann::json out = nlohmann::json::array();
        if (src.is_array()) {
            for (const auto& el : src) {
                if (strip_reserved_id(el)) continue;
                out.push_back(el);
            }
        } else if (src.is_object()) {
            if (!strip_reserved_id(src)) out.push_back(src);
        }
        return out;
    };
    if (auto v = pick_templates_field(); v) {
        if (v->is_string()) {
            const std::string& s = v->get_ref<const std::string&>();
            if (s.size() > kMaxImportTemplateStringBytes) {
                spdlog::warn("InstructionStore::import_definition_json: "
                             "responseTemplates string exceeds {} bytes; dropped "
                             "(governance sec-M4 / UP-15)",
                             kMaxImportTemplateStringBytes);
                def.response_templates_spec = "[]";
            } else {
                auto inner = nlohmann::json::parse(s, nullptr, /*allow_exceptions=*/false);
                if (inner.is_discarded()) {
                    spdlog::warn("InstructionStore::import_definition_json: "
                                 "responseTemplates string is not valid JSON; dropped "
                                 "(governance UP-15)");
                    def.response_templates_spec = "[]";
                } else {
                    def.response_templates_spec = normalise_templates_array(inner).dump();
                }
            }
        } else {
            def.response_templates_spec = normalise_templates_array(*v).dump();
        }
    }

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

    // Pre-INSERT existence check so duplicate IDs return the shared
    // kConflictPrefix-prefixed error instead of "insert failed: UNIQUE
    // constraint failed: ...". Mirrors create_definition_impl above and
    // is the contract the auto-import loop in server.cpp + the REST 409
    // handler at /api/v1/instruction-sets both rely on (Gate 4 C-B1).
    if (!s.id.empty()) {
        sqlite3_stmt* exists_stmt = nullptr;
        if (sqlite3_prepare_v2(db_,
                               "SELECT 1 FROM instruction_sets WHERE id=? LIMIT 1",
                               -1, &exists_stmt, nullptr) != SQLITE_OK)
            return std::unexpected("internal: duplicate-id check failed");
        sqlite3_bind_text(exists_stmt, 1, id.c_str(), -1, SQLITE_TRANSIENT);
        bool exists = sqlite3_step(exists_stmt) == SQLITE_ROW;
        sqlite3_finalize(exists_stmt);
        if (exists)
            return std::unexpected(std::string(kConflictPrefix) +
                                   " instruction set '" + id + "' already exists");
    }

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
