#include "policy_store.hpp"

#include "cel_eval.hpp"
#include "compliance_eval.hpp"
#include "migration_runner.hpp"
#include "scope_yaml.hpp"
#include "store_errors.hpp"
#include "yaml_scan.hpp"

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <chrono>
#include <random>
#include <shared_mutex>

namespace yuzu::server {

// ── Helpers ──────────────────────────────────────────────────────────────────

namespace {

int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::string col_text(sqlite3_stmt* stmt, int col) {
    auto p = sqlite3_column_text(stmt, col);
    return p ? std::string(reinterpret_cast<const char*>(p)) : std::string{};
}

/// Minimal YAML value extractor for the subset of YAML structures used in
/// PolicyFragment and Policy definitions. This avoids adding a YAML library
/// dependency by parsing the simple key-value and nested-block patterns that
/// appear in Yuzu's DSL.
///
/// Supported patterns:
///   key: value                  (scalar)
///   key: "quoted value"         (quoted scalar)
///   key: >                      (folded block — first indented line only)
///   key:                        (start of mapping/sequence — returned empty)
///   - item                      (sequence items, via extract_yaml_list)
///   nested.key via section walking
///
/// NOT a general-purpose YAML parser. Sufficient for yuzu.io/v1alpha1 DSL.

// Definitions moved to yaml_scan.{hpp,cpp} in PR-E (scope-walking YAML DSL) so
// scope_yaml can share them. Re-exported unqualified here so this file's call
// sites keep compiling without per-call qualification.
using yaml_scan::extract_yaml_list;
using yaml_scan::extract_yaml_mapping;
using yaml_scan::extract_yaml_section;
using yaml_scan::extract_yaml_value;

} // namespace

// ── Construction / teardown ──────────────────────────────────────────────────

PolicyStore::PolicyStore(const std::filesystem::path& db_path) {
    int rc = sqlite3_open_v2(db_path.string().c_str(), &db_,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                             nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("PolicyStore: failed to open {}: {}", db_path.string(),
                      sqlite3_errmsg(db_));
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
    if (db_)
        spdlog::info("PolicyStore: opened {}", db_path.string());
}

PolicyStore::~PolicyStore() {
    if (db_)
        sqlite3_close(db_);
}

bool PolicyStore::is_open() const {
    return db_ != nullptr;
}

// ── DDL ──────────────────────────────────────────────────────────────────────

void PolicyStore::create_tables() {
    // Legacy compat: bring pre-v0.10 databases up to v1's schema before stamping.
    // v1's CREATE TABLE IF NOT EXISTS is a no-op on existing tables, so the
    // fix_attempt_count column (G4-UHP-POL-003) must still be applied here.
    sqlite3_exec(db_, "ALTER TABLE policy_status ADD COLUMN fix_attempt_count INTEGER NOT NULL DEFAULT 0;",
                 nullptr, nullptr, nullptr);

    static const std::vector<Migration> kMigrations = {
        {1, R"(
            CREATE TABLE IF NOT EXISTS policy_fragments (
                id                    TEXT PRIMARY KEY,
                name                  TEXT NOT NULL,
                description           TEXT NOT NULL DEFAULT '',
                yaml_source           TEXT NOT NULL,
                check_instruction     TEXT,
                check_compliance      TEXT,
                check_parameters      TEXT NOT NULL DEFAULT '{}',
                fix_instruction       TEXT,
                fix_parameters        TEXT NOT NULL DEFAULT '{}',
                post_check_instruction TEXT,
                post_check_compliance TEXT,
                post_check_parameters TEXT NOT NULL DEFAULT '{}',
                created_at            INTEGER NOT NULL DEFAULT 0,
                updated_at            INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS policies (
                id               TEXT PRIMARY KEY,
                name             TEXT NOT NULL,
                description      TEXT NOT NULL DEFAULT '',
                yaml_source      TEXT NOT NULL,
                fragment_id      TEXT NOT NULL REFERENCES policy_fragments(id),
                scope_expression TEXT,
                enabled          INTEGER NOT NULL DEFAULT 1,
                created_at       INTEGER NOT NULL DEFAULT 0,
                updated_at       INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS policy_inputs (
                policy_id TEXT NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
                key       TEXT NOT NULL,
                value     TEXT NOT NULL,
                PRIMARY KEY(policy_id, key)
            );

            CREATE TABLE IF NOT EXISTS policy_triggers (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                policy_id    TEXT NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
                trigger_type TEXT NOT NULL,
                config_json  TEXT NOT NULL DEFAULT '{}'
            );

            CREATE TABLE IF NOT EXISTS policy_groups (
                policy_id TEXT NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
                group_id  TEXT NOT NULL,
                PRIMARY KEY(policy_id, group_id)
            );

            CREATE TABLE IF NOT EXISTS policy_status (
                policy_id         TEXT NOT NULL,
                agent_id          TEXT NOT NULL,
                status            TEXT NOT NULL DEFAULT 'unknown',
                last_check_at     INTEGER NOT NULL DEFAULT 0,
                last_fix_at       INTEGER NOT NULL DEFAULT 0,
                check_result      TEXT NOT NULL DEFAULT '',
                fix_attempt_count INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(policy_id, agent_id)
            );

            CREATE INDEX IF NOT EXISTS idx_policies_fragment
                ON policies(fragment_id);
            CREATE INDEX IF NOT EXISTS idx_policies_enabled
                ON policies(enabled);
            CREATE INDEX IF NOT EXISTS idx_policy_triggers_policy
                ON policy_triggers(policy_id);
            CREATE INDEX IF NOT EXISTS idx_policy_status_status
                ON policy_status(status);
        )"},
    };
    if (!MigrationRunner::run(db_, "policy_store", kMigrations)) {
        spdlog::error("PolicyStore: schema migration failed, closing database");
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

std::string PolicyStore::peek_fragment_name(const std::string& yaml_source) {
    // Mirrors the resolution order inside create_fragment(): displayName,
    // then name, then id, finally empty. Used by route layers to attribute
    // denial audits without re-implementing YAML parsing.
    auto display = extract_yaml_value(yaml_source, "displayName");
    if (!display.empty()) return display;
    auto name = extract_yaml_value(yaml_source, "name");
    if (!name.empty()) return name;
    return extract_yaml_value(yaml_source, "id");
}

std::string PolicyStore::generate_id() const {
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    std::uniform_int_distribution<uint64_t> dist;
    auto hi = dist(rng);
    auto lo = dist(rng);
    char buf[33];
    std::snprintf(buf, sizeof(buf), "%016llx%016llx", static_cast<unsigned long long>(hi),
                  static_cast<unsigned long long>(lo));
    return std::string(buf, 32);
}

// ── Fragment CRUD ────────────────────────────────────────────────────────────

std::expected<std::string, std::string>
PolicyStore::create_fragment(const std::string& yaml_source) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return std::unexpected("database not open");
    if (yaml_source.empty())
        return std::unexpected("yaml_source is required");

    // M9: Reject oversized YAML input to prevent resource exhaustion
    if (yaml_source.size() > 1048576)
        return std::unexpected("YAML too large (max 1MB)");

    // Validate kind. Issue #621: the cryptic "got ''" error confused
    // operators sending JSON like {"kind":"PolicyFragment", "yaml_source":"..."}
    // — `kind` must be a YAML field inside `yaml_source`, not a top-level
    // request parameter. Keep the "kind must be 'PolicyFragment'" prefix so
    // existing operator scripts that grep on it still work, then append a
    // worked example.
    auto kind = extract_yaml_value(yaml_source, "kind");
    if (kind != "PolicyFragment")
        return std::unexpected(
            "kind must be 'PolicyFragment', got '" + kind +
            "'. yaml_source must be a complete YAML document including "
            "'apiVersion: yuzu.io/v1alpha1' and 'kind: PolicyFragment'. "
            "Example:\n"
            "  apiVersion: yuzu.io/v1alpha1\n"
            "  kind: PolicyFragment\n"
            "  metadata:\n"
            "    name: my-fragment\n"
            "  spec:\n"
            "    check:\n"
            "      plugin: <plugin>\n"
            "      action: <action>\n"
            "      compliance: <CEL expression>\n"
            "See docs/user-manual/policy-engine.md.");

    // Extract metadata
    auto id_val = extract_yaml_value(yaml_source, "id");
    auto id = id_val.empty() ? generate_id() : id_val;
    auto name = extract_yaml_value(yaml_source, "displayName");
    if (name.empty())
        name = extract_yaml_value(yaml_source, "name");
    if (name.empty())
        name = id;
    auto description = extract_yaml_value(yaml_source, "description");

    // Extract check/fix/postCheck from spec
    auto check_section = extract_yaml_section(yaml_source, "spec.check");
    auto check_instruction = extract_yaml_value(check_section, "instruction");
    auto check_compliance = extract_yaml_value(check_section, "compliance");
    auto check_params_map = extract_yaml_mapping(check_section, "parameters");
    nlohmann::json check_params_json = nlohmann::json::object();
    for (const auto& [k, v] : check_params_map)
        check_params_json[k] = v;

    auto fix_section = extract_yaml_section(yaml_source, "spec.fix");
    auto fix_instruction = extract_yaml_value(fix_section, "instruction");
    auto fix_params_map = extract_yaml_mapping(fix_section, "parameters");
    nlohmann::json fix_params_json = nlohmann::json::object();
    for (const auto& [k, v] : fix_params_map)
        fix_params_json[k] = v;

    auto post_section = extract_yaml_section(yaml_source, "spec.postCheck");
    auto post_instruction = extract_yaml_value(post_section, "instruction");
    auto post_compliance = extract_yaml_value(post_section, "compliance");
    auto post_params_map = extract_yaml_mapping(post_section, "parameters");
    nlohmann::json post_params_json = nlohmann::json::object();
    for (const auto& [k, v] : post_params_map)
        post_params_json[k] = v;

    // M11: Validate compliance expressions before storing
    if (!check_compliance.empty()) {
        check_compliance = cel::migrate_expression(check_compliance);
        auto err = validate_compliance_expression(check_compliance);
        if (!err.empty())
            return std::unexpected("invalid check compliance expression: " + err);
    }
    if (!post_compliance.empty()) {
        post_compliance = cel::migrate_expression(post_compliance);
        auto err = validate_compliance_expression(post_compliance);
        if (!err.empty())
            return std::unexpected("invalid postCheck compliance expression: " + err);
    }

    auto now = now_epoch();

    // #396: reject duplicate fragment name with the shared kConflictPrefix
    // the routes layer maps to HTTP 409. The schema does not enforce UNIQUE
    // on name (would require a destructive migration on existing
    // deployments), so the check lives in application code under the
    // unique_lock acquired above. Empty name is impossible — defaults to id
    // at extraction time.
    //
    // sec-LOW2 / sre-1: prepare failure is treated as a hard error rather
    // than silently bypassing the duplicate check.
    {
        sqlite3_stmt* exists_stmt = nullptr;
        if (sqlite3_prepare_v2(db_, "SELECT 1 FROM policy_fragments WHERE name=? LIMIT 1",
                               -1, &exists_stmt, nullptr) != SQLITE_OK) {
            spdlog::error("PolicyStore: prepare failed in duplicate-name check: {}",
                          sqlite3_errmsg(db_));
            return std::unexpected("internal: duplicate-name check failed");
        }
        sqlite3_bind_text(exists_stmt, 1, name.c_str(), -1, SQLITE_TRANSIENT);
        bool exists = sqlite3_step(exists_stmt) == SQLITE_ROW;
        sqlite3_finalize(exists_stmt);
        if (exists)
            return std::unexpected(std::string(kConflictPrefix) +
                                   " policy fragment named '" + name + "' already exists");
    }

    const char* sql = R"(
        INSERT INTO policy_fragments
        (id, name, description, yaml_source,
         check_instruction, check_compliance, check_parameters,
         fix_instruction, fix_parameters,
         post_check_instruction, post_check_compliance, post_check_parameters,
         created_at, updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    )";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        // M10: Do not expose raw SQLite error messages to callers
        spdlog::error("PolicyStore: prepare failed in create_fragment: {}", sqlite3_errmsg(db_));
        return std::unexpected("failed to create fragment");
    }

    int i = 1;
    sqlite3_bind_text(stmt, i++, id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, i++, name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, i++, description.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, i++, yaml_source.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, i++, check_instruction.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, i++, check_compliance.c_str(), -1, SQLITE_TRANSIENT);
    auto cp = check_params_json.dump();
    sqlite3_bind_text(stmt, i++, cp.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, i++, fix_instruction.c_str(), -1, SQLITE_TRANSIENT);
    auto fp = fix_params_json.dump();
    sqlite3_bind_text(stmt, i++, fp.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, i++, post_instruction.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, i++, post_compliance.c_str(), -1, SQLITE_TRANSIENT);
    auto pp = post_params_json.dump();
    sqlite3_bind_text(stmt, i++, pp.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, i++, now);
    sqlite3_bind_int64(stmt, i++, now);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        // M10: Log the real error but return a generic message to the caller
        spdlog::error("PolicyStore: insert failed in create_fragment: {}", sqlite3_errmsg(db_));
        sqlite3_finalize(stmt);
        return std::unexpected("failed to create fragment");
    }
    sqlite3_finalize(stmt);
    spdlog::info("PolicyStore: created fragment '{}' ({})", name, id);
    return id;
}

std::vector<PolicyFragment>
PolicyStore::query_fragments(const FragmentQuery& q) const {
    std::shared_lock lock(mtx_);
    std::vector<PolicyFragment> results;
    if (!db_)
        return results;

    std::string sql = "SELECT id, name, description, yaml_source, "
                      "check_instruction, check_compliance, check_parameters, "
                      "fix_instruction, fix_parameters, "
                      "post_check_instruction, post_check_compliance, post_check_parameters, "
                      "created_at, updated_at "
                      "FROM policy_fragments WHERE 1=1";
    std::vector<std::string> binds;

    if (!q.name_filter.empty()) {
        sql += " AND name LIKE ?";
        binds.push_back("%" + q.name_filter + "%");
    }
    sql += " ORDER BY name ASC LIMIT ?";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
        return results;

    for (int i = 0; i < static_cast<int>(binds.size()); ++i)
        sqlite3_bind_text(stmt, i + 1, binds[i].c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, static_cast<int>(binds.size()) + 1, q.limit);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        PolicyFragment f;
        f.id = col_text(stmt, 0);
        f.name = col_text(stmt, 1);
        f.description = col_text(stmt, 2);
        f.yaml_source = col_text(stmt, 3);
        f.check_instruction = col_text(stmt, 4);
        f.check_compliance = col_text(stmt, 5);
        f.check_parameters = col_text(stmt, 6);
        f.fix_instruction = col_text(stmt, 7);
        f.fix_parameters = col_text(stmt, 8);
        f.post_check_instruction = col_text(stmt, 9);
        f.post_check_compliance = col_text(stmt, 10);
        f.post_check_parameters = col_text(stmt, 11);
        f.created_at = sqlite3_column_int64(stmt, 12);
        f.updated_at = sqlite3_column_int64(stmt, 13);
        results.push_back(std::move(f));
    }
    sqlite3_finalize(stmt);
    return results;
}

std::optional<PolicyFragment> PolicyStore::get_fragment(const std::string& id) const {
    std::shared_lock lock(mtx_);
    if (!db_)
        return std::nullopt;

    const char* sql = "SELECT id, name, description, yaml_source, "
                      "check_instruction, check_compliance, check_parameters, "
                      "fix_instruction, fix_parameters, "
                      "post_check_instruction, post_check_compliance, post_check_parameters, "
                      "created_at, updated_at "
                      "FROM policy_fragments WHERE id = ?";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return std::nullopt;

    sqlite3_bind_text(stmt, 1, id.c_str(), -1, SQLITE_TRANSIENT);
    std::optional<PolicyFragment> result;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        PolicyFragment f;
        f.id = col_text(stmt, 0);
        f.name = col_text(stmt, 1);
        f.description = col_text(stmt, 2);
        f.yaml_source = col_text(stmt, 3);
        f.check_instruction = col_text(stmt, 4);
        f.check_compliance = col_text(stmt, 5);
        f.check_parameters = col_text(stmt, 6);
        f.fix_instruction = col_text(stmt, 7);
        f.fix_parameters = col_text(stmt, 8);
        f.post_check_instruction = col_text(stmt, 9);
        f.post_check_compliance = col_text(stmt, 10);
        f.post_check_parameters = col_text(stmt, 11);
        f.created_at = sqlite3_column_int64(stmt, 12);
        f.updated_at = sqlite3_column_int64(stmt, 13);
        result = std::move(f);
    }
    sqlite3_finalize(stmt);
    return result;
}

bool PolicyStore::delete_fragment(const std::string& id) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return false;

    // Check if any policies reference this fragment
    {
        sqlite3_stmt* check = nullptr;
        if (sqlite3_prepare_v2(db_, "SELECT COUNT(*) FROM policies WHERE fragment_id = ?", -1,
                               &check, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(check, 1, id.c_str(), -1, SQLITE_TRANSIENT);
            if (sqlite3_step(check) == SQLITE_ROW && sqlite3_column_int(check, 0) > 0) {
                sqlite3_finalize(check);
                spdlog::warn("PolicyStore: cannot delete fragment {} — referenced by policies", id);
                return false;
            }
            sqlite3_finalize(check);
        }
    }

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, "DELETE FROM policy_fragments WHERE id = ?", -1, &stmt, nullptr) !=
        SQLITE_OK)
        return false;

    sqlite3_bind_text(stmt, 1, id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    auto changes = sqlite3_changes(db_);
    sqlite3_finalize(stmt);
    return changes > 0;
}

// ── Policy CRUD ──────────────────────────────────────────────────────────────

void PolicyStore::store_inputs(const std::string& policy_id,
                               const std::vector<PolicyInput>& inputs) {
    // Caller must hold mtx_
    sqlite3_stmt* del = nullptr;
    if (sqlite3_prepare_v2(db_, "DELETE FROM policy_inputs WHERE policy_id = ?", -1, &del,
                           nullptr) == SQLITE_OK) {
        sqlite3_bind_text(del, 1, policy_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(del);
        sqlite3_finalize(del);
    }

    const char* sql = "INSERT INTO policy_inputs (policy_id, key, value) VALUES (?,?,?)";
    for (const auto& inp : inputs) {
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
            continue;
        sqlite3_bind_text(stmt, 1, policy_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, inp.key.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, inp.value.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
}

void PolicyStore::store_triggers(const std::string& policy_id,
                                 const std::vector<PolicyTrigger>& triggers) {
    // Caller must hold mtx_
    sqlite3_stmt* del = nullptr;
    if (sqlite3_prepare_v2(db_, "DELETE FROM policy_triggers WHERE policy_id = ?", -1, &del,
                           nullptr) == SQLITE_OK) {
        sqlite3_bind_text(del, 1, policy_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(del);
        sqlite3_finalize(del);
    }

    const char* sql =
        "INSERT INTO policy_triggers (policy_id, trigger_type, config_json) VALUES (?,?,?)";
    for (const auto& t : triggers) {
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
            continue;
        sqlite3_bind_text(stmt, 1, policy_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, t.trigger_type.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, t.config_json.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
}

void PolicyStore::store_groups(const std::string& policy_id,
                               const std::vector<std::string>& group_ids) {
    // Caller must hold mtx_
    sqlite3_stmt* del = nullptr;
    if (sqlite3_prepare_v2(db_, "DELETE FROM policy_groups WHERE policy_id = ?", -1, &del,
                           nullptr) == SQLITE_OK) {
        sqlite3_bind_text(del, 1, policy_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(del);
        sqlite3_finalize(del);
    }

    const char* sql = "INSERT INTO policy_groups (policy_id, group_id) VALUES (?,?)";
    for (const auto& gid : group_ids) {
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
            continue;
        sqlite3_bind_text(stmt, 1, policy_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, gid.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
}

void PolicyStore::load_policy_details(Policy& p) const {
    // Caller must hold mtx_
    // Load inputs
    {
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, "SELECT key, value FROM policy_inputs WHERE policy_id = ?", -1,
                               &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, p.id.c_str(), -1, SQLITE_TRANSIENT);
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                PolicyInput inp;
                inp.policy_id = p.id;
                inp.key = col_text(stmt, 0);
                inp.value = col_text(stmt, 1);
                p.inputs.push_back(std::move(inp));
            }
            sqlite3_finalize(stmt);
        }
    }
    // Load triggers
    {
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(
                db_, "SELECT id, trigger_type, config_json FROM policy_triggers WHERE policy_id = ?",
                -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, p.id.c_str(), -1, SQLITE_TRANSIENT);
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                PolicyTrigger t;
                t.id = sqlite3_column_int64(stmt, 0);
                t.policy_id = p.id;
                t.trigger_type = col_text(stmt, 1);
                t.config_json = col_text(stmt, 2);
                p.triggers.push_back(std::move(t));
            }
            sqlite3_finalize(stmt);
        }
    }
    // Load management groups
    {
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, "SELECT group_id FROM policy_groups WHERE policy_id = ?", -1,
                               &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, p.id.c_str(), -1, SQLITE_TRANSIENT);
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                p.management_groups.push_back(col_text(stmt, 0));
            }
            sqlite3_finalize(stmt);
        }
    }
}

std::expected<std::string, std::string>
PolicyStore::create_policy(const std::string& yaml_source) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return std::unexpected("database not open");
    if (yaml_source.empty())
        return std::unexpected("yaml_source is required");

    // M9: Reject oversized YAML input to prevent resource exhaustion
    if (yaml_source.size() > 1048576)
        return std::unexpected("YAML too large (max 1MB)");

    // Validate kind. See create_fragment() for the rationale on the
    // verbose example — same UX issue (#621), different kind.
    auto kind = extract_yaml_value(yaml_source, "kind");
    if (kind != "Policy")
        return std::unexpected(
            "kind must be 'Policy', got '" + kind +
            "'. yaml_source must be a complete YAML document including "
            "'apiVersion: yuzu.io/v1alpha1' and 'kind: Policy'. "
            "Example:\n"
            "  apiVersion: yuzu.io/v1alpha1\n"
            "  kind: Policy\n"
            "  metadata:\n"
            "    name: my-policy\n"
            "  spec:\n"
            "    fragment: <fragment-name-or-id>\n"
            "    scope: <scope-expression>\n"
            "    triggers:\n"
            "      - type: interval\n"
            "        interval: 3600\n"
            "See docs/user-manual/policy-engine.md.");

    // Extract metadata
    auto id_val = extract_yaml_value(yaml_source, "id");
    auto id = id_val.empty() ? generate_id() : id_val;
    auto name = extract_yaml_value(yaml_source, "displayName");
    if (name.empty())
        name = extract_yaml_value(yaml_source, "name");
    if (name.empty())
        name = id;
    auto description = extract_yaml_value(yaml_source, "description");

    // Extract spec
    auto fragment_id = extract_yaml_value(yaml_source, "fragment");
    if (fragment_id.empty())
        return std::unexpected("spec.fragment is required");

    // Validate fragment exists
    {
        sqlite3_stmt* check = nullptr;
        if (sqlite3_prepare_v2(db_, "SELECT COUNT(*) FROM policy_fragments WHERE id = ?", -1,
                               &check, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(check, 1, fragment_id.c_str(), -1, SQLITE_TRANSIENT);
            if (sqlite3_step(check) == SQLITE_ROW && sqlite3_column_int(check, 0) == 0) {
                sqlite3_finalize(check);
                return std::unexpected("fragment '" + fragment_id + "' not found");
            }
            sqlite3_finalize(check);
        }
    }

    // Scope. A scalar `scope:` is a raw scope-engine expression (the common,
    // backward-compatible form). A `scope:` that opens a mapping carries the
    // scope-walking DSL (PR-E): `selector:` and/or `fromResultSet:`.
    auto scope = extract_yaml_value(yaml_source, "scope");
    if (!scope.empty() && scope.front() == '{')
        return std::unexpected(
            "inline flow-mapping scope is not supported; use the block form "
            "(scope: <newline> indented selector:/fromResultSet:)");
    // PR-E2: result sets are not yet valid in a continuously-evaluated policy (a
    // result set's ~1h TTL does not match a policy that re-evaluates forever), in
    // EITHER form. The mapping form is rejected in the scope.empty() branch below
    // via parse_scope_block; this catches the SCALAR form (`scope: from_result_set:rs_x`)
    // that branch would otherwise skip because extract_yaml_value returns it
    // non-empty — closing the policy fromResultSet bypass (#1221 MEDIUM-1).
    if (scope.find("from_result_set:") != std::string::npos)
        return std::unexpected(
            "spec.scope.fromResultSet is not yet supported for policies (follow-up "
            "PR-E2): a result set's 1h TTL does not match a continuously-evaluated "
            "policy. Use a selector or a scope expression.");
    if (scope.empty()) {
        auto sb = parse_scope_block(yaml_source);
        if (sb.has_from_result_set)
            return std::unexpected(
                "spec.scope.fromResultSet is not yet supported for policies (follow-up "
                "PR-E2): a result set's 1h TTL does not match a continuously-evaluated "
                "policy. Use a selector or a scope expression.");
        // Validate the selector charset (sec-L1/dsl-S1) before lowering.
        auto asn = extract_yaml_section(yaml_source, "spec.assignment");
        if (auto err = validate_scope_block(sb, extract_yaml_value(asn, "mode"),
                                            !extract_yaml_list(asn, "managementGroups").empty()))
            return std::unexpected(*err);
        // Lower a selector-only block. Before PR-E a `scope.selector:` mapping
        // was read by the scalar extractor as empty and silently stored no
        // scope; it now lowers to a real predicate.
        scope = lower_scope_block(sb);
    }

    // Parse inputs
    auto inputs_map = extract_yaml_mapping(yaml_source, "inputs");
    std::vector<PolicyInput> inputs;
    for (const auto& [k, v] : inputs_map) {
        PolicyInput inp;
        inp.policy_id = id;
        inp.key = k;
        inp.value = v;
        inputs.push_back(std::move(inp));
    }

    // Parse triggers
    std::vector<PolicyTrigger> triggers;
    auto triggers_section = extract_yaml_section(yaml_source, "triggers");
    if (!triggers_section.empty()) {
        // Each trigger is a "- type: xxx" block in the triggers list
        // Parse as sequential list items. The extracted section preserves
        // original indentation, so list dashes may have leading whitespace.
        // Find all positions of "- " that represent top-level list items.
        std::vector<size_t> dash_positions;
        {
            // Find the first dash to determine its indentation level
            auto first_dash = triggers_section.find('-');
            if (first_dash == std::string::npos)
                goto done_triggers;
            // Determine indent: count spaces from start of its line
            auto line_start = triggers_section.rfind('\n', first_dash);
            size_t dash_indent = (line_start == std::string::npos) ? first_dash : first_dash - line_start - 1;

            // Scan for all dashes at this indentation level
            size_t scan = 0;
            while (scan < triggers_section.size()) {
                auto nl = triggers_section.find('\n', scan);
                if (nl == std::string::npos) nl = triggers_section.size();
                auto line = triggers_section.substr(scan, nl - scan);
                auto fc = line.find_first_not_of(" \t");
                if (fc != std::string::npos && line[fc] == '-' && fc == dash_indent) {
                    dash_positions.push_back(scan + fc);
                }
                scan = nl + 1;
            }
        }

        for (size_t di = 0; di < dash_positions.size(); ++di) {
            auto dash = dash_positions[di];
            size_t item_end = (di + 1 < dash_positions.size()) ? dash_positions[di + 1] : triggers_section.size();

            auto item_block = triggers_section.substr(dash + 2, item_end - dash - 2);

            PolicyTrigger t;
            t.policy_id = id;

            // Extract type from the item
            auto ttype = extract_yaml_value(item_block, "type");
            t.trigger_type = ttype;

            // Build config JSON from remaining fields
            nlohmann::json config;
            auto interval = extract_yaml_value(item_block, "interval_seconds");
            if (!interval.empty()) {
                try {
                    config["interval_seconds"] = std::stoi(interval);
                } catch (...) {
                    config["interval_seconds"] = interval;
                }
            }
            auto path = extract_yaml_value(item_block, "path");
            if (!path.empty())
                config["path"] = path;
            auto event_source = extract_yaml_value(item_block, "event_source");
            if (!event_source.empty())
                config["event_source"] = event_source;
            auto event_id = extract_yaml_value(item_block, "event_id");
            if (!event_id.empty())
                config["event_id"] = event_id;
            auto expression = extract_yaml_value(item_block, "expression");
            if (!expression.empty())
                config["expression"] = expression;

            t.config_json = config.dump();
            if (!t.trigger_type.empty())
                triggers.push_back(std::move(t));
        }
        done_triggers:;
    }

    // Parse management groups
    auto groups = extract_yaml_list(yaml_source, "managementGroups");

    auto now = now_epoch();

    // Insert policy row
    const char* sql = R"(
        INSERT INTO policies
        (id, name, description, yaml_source, fragment_id, scope_expression, enabled,
         created_at, updated_at)
        VALUES (?,?,?,?,?,?,1,?,?)
    )";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        // M10: Do not expose raw SQLite error messages to callers
        spdlog::error("PolicyStore: prepare failed in create_policy: {}", sqlite3_errmsg(db_));
        return std::unexpected("failed to create policy");
    }

    int i = 1;
    sqlite3_bind_text(stmt, i++, id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, i++, name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, i++, description.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, i++, yaml_source.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, i++, fragment_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, i++, scope.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, i++, now);
    sqlite3_bind_int64(stmt, i++, now);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        // M10: Log the real error but return a generic message to the caller
        spdlog::error("PolicyStore: insert failed in create_policy: {}", sqlite3_errmsg(db_));
        sqlite3_finalize(stmt);
        return std::unexpected("failed to create policy");
    }
    sqlite3_finalize(stmt);

    // Store related data
    store_inputs(id, inputs);
    store_triggers(id, triggers);
    store_groups(id, groups);

    spdlog::info("PolicyStore: created policy '{}' ({}) -> fragment '{}'", name, id, fragment_id);
    return id;
}

std::vector<Policy> PolicyStore::query_policies(const PolicyQuery& q) const {
    std::shared_lock lock(mtx_);
    std::vector<Policy> results;
    if (!db_)
        return results;

    std::string sql = "SELECT id, name, description, yaml_source, fragment_id, "
                      "scope_expression, enabled, created_at, updated_at "
                      "FROM policies WHERE 1=1";
    std::vector<std::string> binds;

    if (!q.name_filter.empty()) {
        sql += " AND name LIKE ?";
        binds.push_back("%" + q.name_filter + "%");
    }
    if (!q.fragment_filter.empty()) {
        sql += " AND fragment_id = ?";
        binds.push_back(q.fragment_filter);
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
    sqlite3_bind_int(stmt, static_cast<int>(binds.size()) + 1, q.limit);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        Policy p;
        p.id = col_text(stmt, 0);
        p.name = col_text(stmt, 1);
        p.description = col_text(stmt, 2);
        p.yaml_source = col_text(stmt, 3);
        p.fragment_id = col_text(stmt, 4);
        p.scope_expression = col_text(stmt, 5);
        p.enabled = sqlite3_column_int(stmt, 6) != 0;
        p.created_at = sqlite3_column_int64(stmt, 7);
        p.updated_at = sqlite3_column_int64(stmt, 8);
        load_policy_details(p);
        results.push_back(std::move(p));
    }
    sqlite3_finalize(stmt);
    return results;
}

std::optional<Policy> PolicyStore::get_policy(const std::string& id) const {
    std::shared_lock lock(mtx_);
    if (!db_)
        return std::nullopt;

    const char* sql = "SELECT id, name, description, yaml_source, fragment_id, "
                      "scope_expression, enabled, created_at, updated_at "
                      "FROM policies WHERE id = ?";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return std::nullopt;

    sqlite3_bind_text(stmt, 1, id.c_str(), -1, SQLITE_TRANSIENT);
    std::optional<Policy> result;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        Policy p;
        p.id = col_text(stmt, 0);
        p.name = col_text(stmt, 1);
        p.description = col_text(stmt, 2);
        p.yaml_source = col_text(stmt, 3);
        p.fragment_id = col_text(stmt, 4);
        p.scope_expression = col_text(stmt, 5);
        p.enabled = sqlite3_column_int(stmt, 6) != 0;
        p.created_at = sqlite3_column_int64(stmt, 7);
        p.updated_at = sqlite3_column_int64(stmt, 8);
        load_policy_details(p);
        result = std::move(p);
    }
    sqlite3_finalize(stmt);
    return result;
}

std::expected<void, std::string> PolicyStore::enable_policy(const std::string& id) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return std::unexpected("database not open");

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, "UPDATE policies SET enabled = 1, updated_at = ? WHERE id = ?", -1,
                           &stmt, nullptr) != SQLITE_OK) {
        spdlog::error("PolicyStore: prepare failed in enable_policy: {}", sqlite3_errmsg(db_));
        return std::unexpected("failed to enable policy");
    }

    sqlite3_bind_int64(stmt, 1, now_epoch());
    sqlite3_bind_text(stmt, 2, id.c_str(), -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        spdlog::error("PolicyStore: update failed in enable_policy: {}", sqlite3_errmsg(db_));
        sqlite3_finalize(stmt);
        return std::unexpected("failed to enable policy");
    }
    auto changes = sqlite3_changes(db_);
    sqlite3_finalize(stmt);
    if (changes == 0)
        return std::unexpected("policy not found");
    spdlog::info("PolicyStore: enabled policy {}", id);
    return {};
}

std::expected<void, std::string> PolicyStore::disable_policy(const std::string& id) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return std::unexpected("database not open");

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, "UPDATE policies SET enabled = 0, updated_at = ? WHERE id = ?", -1,
                           &stmt, nullptr) != SQLITE_OK) {
        spdlog::error("PolicyStore: prepare failed in disable_policy: {}", sqlite3_errmsg(db_));
        return std::unexpected("failed to disable policy");
    }

    sqlite3_bind_int64(stmt, 1, now_epoch());
    sqlite3_bind_text(stmt, 2, id.c_str(), -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        spdlog::error("PolicyStore: update failed in disable_policy: {}", sqlite3_errmsg(db_));
        sqlite3_finalize(stmt);
        return std::unexpected("failed to disable policy");
    }
    auto changes = sqlite3_changes(db_);
    sqlite3_finalize(stmt);
    if (changes == 0)
        return std::unexpected("policy not found");
    spdlog::info("PolicyStore: disabled policy {}", id);
    return {};
}

bool PolicyStore::delete_policy(const std::string& id) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return false;

    // CASCADE will handle policy_inputs, policy_triggers, policy_groups
    // But we also need to clean up policy_status
    {
        sqlite3_stmt* del = nullptr;
        if (sqlite3_prepare_v2(db_, "DELETE FROM policy_status WHERE policy_id = ?", -1, &del,
                               nullptr) == SQLITE_OK) {
            sqlite3_bind_text(del, 1, id.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(del);
            sqlite3_finalize(del);
        }
    }

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, "DELETE FROM policies WHERE id = ?", -1, &stmt, nullptr) !=
        SQLITE_OK)
        return false;

    sqlite3_bind_text(stmt, 1, id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    auto changes = sqlite3_changes(db_);
    sqlite3_finalize(stmt);
    return changes > 0;
}

// ── Compliance tracking ──────────────────────────────────────────────────────

std::expected<void, std::string>
PolicyStore::update_agent_status(const std::string& policy_id, const std::string& agent_id,
                                 const std::string& status, const std::string& check_result) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return std::unexpected("database not open");
    if (policy_id.empty() || agent_id.empty())
        return std::unexpected("policy_id and agent_id are required");

    // Valid statuses
    if (status != "compliant" && status != "non_compliant" && status != "unknown" &&
        status != "fixing" && status != "error")
        return std::unexpected("invalid status: " + status);

    auto now = now_epoch();

    // Fix retry limit (G4-UHP-POL-003): if transitioning to 'fixing' and
    // the agent has already exceeded max fix attempts, force status to 'error'
    constexpr int kMaxFixAttempts = 3;
    std::string effective_status = status;
    if (status == "fixing") {
        sqlite3_stmt* chk = nullptr;
        if (sqlite3_prepare_v2(db_,
                "SELECT fix_attempt_count FROM policy_status WHERE policy_id = ? AND agent_id = ?",
                -1, &chk, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(chk, 1, policy_id.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(chk, 2, agent_id.c_str(), -1, SQLITE_TRANSIENT);
            if (sqlite3_step(chk) == SQLITE_ROW) {
                int attempts = sqlite3_column_int(chk, 0);
                if (attempts >= kMaxFixAttempts) {
                    effective_status = "error";
                    spdlog::warn("PolicyStore: fix retry limit ({}) exceeded for policy={} agent={}, "
                                 "transitioning to error", kMaxFixAttempts, policy_id, agent_id);
                }
            }
            sqlite3_finalize(chk);
        }
    }

    // Upsert with fix_attempt_count tracking
    const char* sql = R"(
        INSERT INTO policy_status (policy_id, agent_id, status, last_check_at, last_fix_at, check_result, fix_attempt_count)
        VALUES (?, ?, ?, ?, 0, ?, 0)
        ON CONFLICT(policy_id, agent_id) DO UPDATE SET
            status = excluded.status,
            last_check_at = excluded.last_check_at,
            check_result = excluded.check_result,
            last_fix_at = CASE WHEN excluded.status = 'fixing'
                          THEN excluded.last_check_at
                          ELSE policy_status.last_fix_at END,
            fix_attempt_count = CASE
                WHEN excluded.status = 'fixing' THEN policy_status.fix_attempt_count + 1
                WHEN excluded.status = 'compliant' THEN 0
                ELSE policy_status.fix_attempt_count END
    )";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        spdlog::error("PolicyStore: prepare failed in update_compliance_status: {}", sqlite3_errmsg(db_));
        return std::unexpected("failed to update compliance status");
    }

    sqlite3_bind_text(stmt, 1, policy_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, agent_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, effective_status.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 4, now);
    sqlite3_bind_text(stmt, 5, check_result.c_str(), -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        spdlog::error("PolicyStore: upsert failed in update_compliance_status: {}", sqlite3_errmsg(db_));
        sqlite3_finalize(stmt);
        return std::unexpected("failed to update compliance status");
    }
    sqlite3_finalize(stmt);
    // Invalidate the fleet-compliance cache (gov happy-path-F2): a freshly
    // written verdict must surface promptly. Without this, the 60s cache would
    // keep serving the pre-evaluation value (e.g. 0%) right after a check lands —
    // the exact window an operator (or a demo) hits after POST /evaluate. Held
    // under the same unique_lock as the cache reader, so the reset is safe.
    fleet_compliance_last_computed_ = {};
    return {};
}

std::optional<PolicyAgentStatus>
PolicyStore::get_agent_status(const std::string& policy_id, const std::string& agent_id) const {
    std::shared_lock lock(mtx_);
    if (!db_)
        return std::nullopt;

    const char* sql = "SELECT policy_id, agent_id, status, last_check_at, last_fix_at, "
                      "check_result FROM policy_status WHERE policy_id = ? AND agent_id = ?";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return std::nullopt;

    sqlite3_bind_text(stmt, 1, policy_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, agent_id.c_str(), -1, SQLITE_TRANSIENT);

    std::optional<PolicyAgentStatus> result;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        PolicyAgentStatus s;
        s.policy_id = col_text(stmt, 0);
        s.agent_id = col_text(stmt, 1);
        s.status = col_text(stmt, 2);
        s.last_check_at = sqlite3_column_int64(stmt, 3);
        s.last_fix_at = sqlite3_column_int64(stmt, 4);
        s.check_result = col_text(stmt, 5);
        result = std::move(s);
    }
    sqlite3_finalize(stmt);
    return result;
}

std::vector<PolicyAgentStatus>
PolicyStore::get_policy_agent_statuses(const std::string& policy_id) const {
    std::shared_lock lock(mtx_);
    std::vector<PolicyAgentStatus> results;
    if (!db_)
        return results;

    const char* sql = "SELECT policy_id, agent_id, status, last_check_at, last_fix_at, "
                      "check_result FROM policy_status WHERE policy_id = ? ORDER BY agent_id";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return results;

    sqlite3_bind_text(stmt, 1, policy_id.c_str(), -1, SQLITE_TRANSIENT);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        PolicyAgentStatus s;
        s.policy_id = col_text(stmt, 0);
        s.agent_id = col_text(stmt, 1);
        s.status = col_text(stmt, 2);
        s.last_check_at = sqlite3_column_int64(stmt, 3);
        s.last_fix_at = sqlite3_column_int64(stmt, 4);
        s.check_result = col_text(stmt, 5);
        results.push_back(std::move(s));
    }
    sqlite3_finalize(stmt);
    return results;
}

ComplianceSummary PolicyStore::get_compliance_summary(const std::string& policy_id) const {
    std::shared_lock lock(mtx_);
    ComplianceSummary cs;
    cs.policy_id = policy_id;
    if (!db_)
        return cs;

    const char* sql = "SELECT status, COUNT(*) FROM policy_status "
                      "WHERE policy_id = ? GROUP BY status";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return cs;

    sqlite3_bind_text(stmt, 1, policy_id.c_str(), -1, SQLITE_TRANSIENT);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        auto status = col_text(stmt, 0);
        auto count = sqlite3_column_int64(stmt, 1);
        if (status == "compliant")
            cs.compliant = count;
        else if (status == "non_compliant")
            cs.non_compliant = count;
        else if (status == "unknown")
            cs.unknown = count;
        else if (status == "fixing")
            cs.fixing = count;
        else if (status == "error")
            cs.error = count;
        cs.total += count;
    }
    sqlite3_finalize(stmt);
    return cs;
}

FleetCompliance PolicyStore::compute_fleet_compliance_locked() const {
    // Caller must hold at least a shared lock on mtx_
    FleetCompliance fc;
    if (!db_)
        return fc;

    // Count fresh statuses (checked within staleness TTL) and stale ones separately (G4-UHP-POL-007)
    constexpr int64_t kStalenessTtl = 24 * 3600; // 24 hours
    auto cutoff = now_epoch() - kStalenessTtl;

    const char* sql =
        "SELECT CASE WHEN last_check_at >= ? THEN status ELSE 'unknown' END AS effective_status, "
        "COUNT(*) FROM policy_status GROUP BY effective_status";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return fc;

    sqlite3_bind_int64(stmt, 1, cutoff);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        auto status = col_text(stmt, 0);
        auto count = sqlite3_column_int64(stmt, 1);
        if (status == "compliant")
            fc.compliant = count;
        else if (status == "non_compliant")
            fc.non_compliant = count;
        else if (status == "unknown")
            fc.unknown = count;
        else if (status == "fixing")
            fc.fixing = count;
        else if (status == "error")
            fc.error = count;
        fc.total_checks += count;
    }
    sqlite3_finalize(stmt);

    if (fc.total_checks > 0)
        fc.compliance_pct =
            static_cast<double>(fc.compliant) / static_cast<double>(fc.total_checks) * 100.0;

    return fc;
}

FleetCompliance PolicyStore::get_fleet_compliance() const {
    auto now = std::chrono::steady_clock::now();

    // Fast path: return cached value if still fresh (under shared lock)
    {
        std::shared_lock lock(mtx_);
        if (fleet_compliance_last_computed_.time_since_epoch().count() > 0 &&
            (now - fleet_compliance_last_computed_) < kFleetComplianceCacheTtl) {
            return cached_fleet_compliance_;
        }
    }

    // Slow path: recompute under unique lock to prevent data race (CHAOS-T1-006)
    std::unique_lock lock(mtx_);
    // Double-check: another thread may have refreshed while we waited
    if (fleet_compliance_last_computed_.time_since_epoch().count() > 0 &&
        (now - fleet_compliance_last_computed_) < kFleetComplianceCacheTtl) {
        return cached_fleet_compliance_;
    }

    auto fc = compute_fleet_compliance_locked();
    cached_fleet_compliance_ = fc;
    fleet_compliance_last_computed_ = now;
    return fc;
}

// ── Cache invalidation ───────────────────────────────────────────────────────

std::expected<int64_t, std::string>
PolicyStore::invalidate_policy(const std::string& policy_id) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return std::unexpected("database not open");
    if (policy_id.empty())
        return std::unexpected("policy_id is required");

    const char* sql = "UPDATE policy_status SET status = 'unknown' WHERE policy_id = ?";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        spdlog::error("PolicyStore: prepare failed in invalidate_policy: {}", sqlite3_errmsg(db_));
        return std::unexpected("failed to invalidate policy");
    }

    sqlite3_bind_text(stmt, 1, policy_id.c_str(), -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        spdlog::error("PolicyStore: update failed in invalidate_policy: {}", sqlite3_errmsg(db_));
        sqlite3_finalize(stmt);
        return std::unexpected("failed to invalidate policy");
    }

    auto changes = static_cast<int64_t>(sqlite3_changes(db_));
    sqlite3_finalize(stmt);

    spdlog::info("PolicyStore: invalidated {} agent statuses for policy '{}'", changes, policy_id);
    return changes;
}

std::expected<int64_t, std::string>
PolicyStore::invalidate_all_policies() {
    std::unique_lock lock(mtx_);
    if (!db_)
        return std::unexpected("database not open");

    const char* sql = "UPDATE policy_status SET status = 'unknown'";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        spdlog::error("PolicyStore: prepare failed in invalidate_all_policies: {}", sqlite3_errmsg(db_));
        return std::unexpected("failed to invalidate policies");
    }

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        spdlog::error("PolicyStore: update failed in invalidate_all_policies: {}", sqlite3_errmsg(db_));
        sqlite3_finalize(stmt);
        return std::unexpected("failed to invalidate policies");
    }

    auto changes = static_cast<int64_t>(sqlite3_changes(db_));
    sqlite3_finalize(stmt);

    spdlog::info("PolicyStore: invalidated ALL agent statuses ({} rows)", changes);
    return changes;
}

} // namespace yuzu::server
