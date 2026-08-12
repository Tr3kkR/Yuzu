#include "custom_properties_store.hpp"

#include "pg/pg_array.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "sqlite_raii.hpp"
#include "utf8_sanitize.hpp"

#include <yuzu/metrics.hpp>

#include <libpq-fe.h>
#include <openssl/evp.h>
#include <re2/re2.h>
#include <spdlog/spdlog.h>
#include <sqlite3.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <system_error>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "custom_properties_store";

// Bounded acquires (ADR-0012 §2(a)). Nothing here runs the gRPC heartbeat hot
// path — writes come from operator/REST calls, reads back both REST and the
// props.<key> scope resolver's bulk preload (agent_registry.cpp). All can
// wait a little; none may block unboundedly on a saturated pool.
constexpr std::chrono::milliseconds kAcquireTimeout{2000};
constexpr std::chrono::milliseconds kBackfillTxnTimeout{60000};

std::int64_t now_secs() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::string text_col(PGresult* res, int row, int col) {
    if (PQgetisnull(res, row, col))
        return {};
    return std::string(PQgetvalue(res, row, col),
                       static_cast<std::size_t>(PQgetlength(res, row, col)));
}

std::int64_t to_i64(const char* s) {
    if (s == nullptr || s[0] == '\0')
        return 0;
    return static_cast<std::int64_t>(std::strtoll(s, nullptr, 10));
}

// Same treatment as RbacStore/ManagementGroupStore (ADR-0041/0042): scrub
// invalid UTF-8 to U+FFFD, then replace any embedded NUL the scrub leaves
// behind (a valid ASCII byte the scrub doesn't touch) — PostgreSQL TEXT can't
// store NUL and libpq's text-format bind C-string-truncates at the first one.
// Applied to every free-text column INCLUDING the backfill path (a bad byte
// at-rest in a legacy custom-properties.db must not brick the MANDATORY
// backfill).
std::string sanitize_pg_text(std::string_view s) {
    std::string out = sanitize_utf8_strict(s);
    std::size_t pos = 0;
    while ((pos = out.find('\0', pos)) != std::string::npos) {
        out.replace(pos, 1, "\xEF\xBF\xBD");
        pos += 3;
    }
    return out;
}

// ── Read-degrade observability (#1675 convention, mirrors ProductRegistryStore) ──
constexpr const char* kReasonStoreNotOpen = "store_not_open";
constexpr const char* kReasonPoolTimeout = "pool_acquire_timeout";
constexpr const char* kReasonQueryError = "query_error";
constexpr std::uint64_t kReadDegradeLogSample = 100;
constexpr std::int64_t kDegradeEpisodeGapSecs = 60;

struct DegradeSampler {
    std::atomic<std::uint64_t> count{0};
    std::atomic<std::int64_t> last_ts{0};
};

bool note_read_degrade(yuzu::MetricsRegistry* metrics, const char* reason, DegradeSampler& s) {
    if (metrics)
        metrics->counter("yuzu_server_custom_properties_read_degrade_total", {{"reason", reason}})
            .increment();
    const std::int64_t now = now_secs();
    const std::int64_t prev = s.last_ts.exchange(now, std::memory_order_relaxed);
    const std::uint64_t n = s.count.fetch_add(1, std::memory_order_relaxed) + 1;
    const bool new_episode = prev == 0 || (now - prev) > kDegradeEpisodeGapSecs;
    return new_episode || (n % kReadDegradeLogSample) == 0;
}

// One sampler per distinct read call site (a shared sampler would let a
// hot get_value degrade mask a cold get_properties one from ever logging).
DegradeSampler g_props_sampler;
DegradeSampler g_prop_sampler;
DegradeSampler g_value_sampler;
DegradeSampler g_map_sampler;

// Unqualified DDL: the runner sets search_path to `custom_properties_store`
// for the migration transaction; runtime statements below schema-qualify
// explicitly. Two independent tables, no FK between them (header comment —
// cross-table validation stays application-layer, matching the SQLite
// original's behavior).
const std::vector<pg::PgMigration>& migrations() {
    static const std::vector<pg::PgMigration> kMigrations = {
        {1, R"(
            CREATE TABLE custom_properties (
                agent_id    TEXT NOT NULL,
                key         TEXT NOT NULL,
                value       TEXT NOT NULL,
                type        TEXT NOT NULL DEFAULT 'string',
                updated_at  BIGINT NOT NULL,
                PRIMARY KEY (agent_id, key)
            );
            CREATE INDEX custom_props_agent_idx ON custom_properties (agent_id);

            CREATE TABLE custom_property_schemas (
                key               TEXT PRIMARY KEY,
                display_name      TEXT NOT NULL DEFAULT '',
                type              TEXT NOT NULL DEFAULT 'string',
                description       TEXT NOT NULL DEFAULT '',
                validation_regex  TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE custom_properties_meta (
                key    TEXT PRIMARY KEY,
                value  TEXT NOT NULL
            );
        )"},
    };
    return kMigrations;
}

} // namespace

// ── Constructor ───────────────────────────────────────────────────────────

CustomPropertiesStore::CustomPropertiesStore(pg::PgPool& pool) : pool_(pool) {
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("CustomPropertiesStore: no database connection at construction ({}) — "
                      "custom-properties persistence disabled",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("CustomPropertiesStore: schema migration failed — custom-properties "
                      "persistence disabled");
        return;
    }
    open_ = true;
}

// ── Validation ───────────────────────────────────────────────────────────────
// Pure C++ — unchanged by the substrate migration.

bool CustomPropertiesStore::validate_key(const std::string& key) {
    if (key.empty() || key.size() > 64)
        return false;
    for (char c : key) {
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
              c == '_' || c == '-' || c == '.' || c == ':')) {
            return false;
        }
    }
    return true;
}

bool CustomPropertiesStore::validate_value(const std::string& value) {
    return value.size() <= 1024;
}

std::expected<void, std::string>
CustomPropertiesStore::validate_against_schema(PGconn* conn, const std::string& key,
                                               const std::string& value) const {
    pg::PgResult res = pg::exec_params(
        conn,
        "SELECT type, validation_regex FROM custom_properties_store.custom_property_schemas "
        "WHERE key = $1",
        std::vector<std::string>{key});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) == 0)
        return {}; // no schema (or a query error — same "no validation" fallback as SQLite original)

    const std::string schema_type = text_col(res.get(), 0, 0);
    const std::string validation_regex = text_col(res.get(), 0, 1);

    if (schema_type.empty())
        return {};

    if (schema_type == "int") {
        try {
            (void)std::stoll(value);
        } catch (...) {
            return std::unexpected("value must be a valid integer for property '" + key + "'");
        }
    } else if (schema_type == "bool") {
        if (value != "true" && value != "false")
            return std::unexpected("value must be 'true' or 'false' for property '" + key + "'");
    }
    // "string" and "datetime" accept any text.

    if (!validation_regex.empty()) {
        RE2 re(validation_regex, RE2::Quiet);
        if (!re.ok()) {
            spdlog::warn("CustomPropertiesStore: invalid regex for schema key '{}': {}", key,
                        validation_regex);
        } else if (!RE2::FullMatch(value, re)) {
            return std::unexpected("value does not match validation pattern for '" + key + "'");
        }
    }

    return {};
}

// ── Property CRUD ────────────────────────────────────────────────────────────

std::expected<std::vector<CustomProperty>, CustomPropertiesReadError>
CustomPropertiesStore::get_properties(const std::string& agent_id) const {
    if (!open_) {
        if (note_read_degrade(metrics_, kReasonStoreNotOpen, g_props_sampler))
            spdlog::warn("CustomPropertiesStore::get_properties: store not open");
        return std::unexpected(CustomPropertiesReadError::kDegraded);
    }
    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease) {
        if (note_read_degrade(metrics_, kReasonPoolTimeout, g_props_sampler))
            spdlog::warn("CustomPropertiesStore::get_properties: no connection in time ({})",
                        pool_.last_error());
        return std::unexpected(CustomPropertiesReadError::kDegraded);
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT key, value, type, updated_at FROM custom_properties_store.custom_properties "
        "WHERE agent_id = $1 ORDER BY key",
        std::vector<std::string>{agent_id});
    if (res.status() != PGRES_TUPLES_OK) {
        if (note_read_degrade(metrics_, kReasonQueryError, g_props_sampler))
            spdlog::warn("CustomPropertiesStore::get_properties: query failed: {}",
                        PQerrorMessage(lease.get()));
        return std::unexpected(CustomPropertiesReadError::kDegraded);
    }
    std::vector<CustomProperty> results;
    const int rows = PQntuples(res.get());
    results.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i) {
        CustomProperty p;
        p.agent_id = agent_id;
        p.key = text_col(res.get(), i, 0);
        p.value = text_col(res.get(), i, 1);
        p.type = text_col(res.get(), i, 2);
        p.updated_at = to_i64(PQgetvalue(res.get(), i, 3));
        results.push_back(std::move(p));
    }
    return results;
}

std::expected<std::optional<CustomProperty>, CustomPropertiesReadError>
CustomPropertiesStore::get_property(const std::string& agent_id, const std::string& key) const {
    if (!open_) {
        if (note_read_degrade(metrics_, kReasonStoreNotOpen, g_prop_sampler))
            spdlog::warn("CustomPropertiesStore::get_property: store not open");
        return std::unexpected(CustomPropertiesReadError::kDegraded);
    }
    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease) {
        if (note_read_degrade(metrics_, kReasonPoolTimeout, g_prop_sampler))
            spdlog::warn("CustomPropertiesStore::get_property: no connection in time ({})",
                        pool_.last_error());
        return std::unexpected(CustomPropertiesReadError::kDegraded);
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT value, type, updated_at FROM custom_properties_store.custom_properties "
        "WHERE agent_id = $1 AND key = $2",
        std::vector<std::string>{agent_id, key});
    if (res.status() != PGRES_TUPLES_OK) {
        if (note_read_degrade(metrics_, kReasonQueryError, g_prop_sampler))
            spdlog::warn("CustomPropertiesStore::get_property: query failed: {}",
                        PQerrorMessage(lease.get()));
        return std::unexpected(CustomPropertiesReadError::kDegraded);
    }
    if (PQntuples(res.get()) == 0)
        return std::optional<CustomProperty>{std::nullopt};
    CustomProperty p;
    p.agent_id = agent_id;
    p.key = key;
    p.value = text_col(res.get(), 0, 0);
    p.type = text_col(res.get(), 0, 1);
    p.updated_at = to_i64(PQgetvalue(res.get(), 0, 2));
    return std::optional<CustomProperty>{std::move(p)};
}

std::expected<std::optional<std::string>, CustomPropertiesReadError>
CustomPropertiesStore::get_value(const std::string& agent_id, const std::string& key) const {
    auto prop = get_property(agent_id, key);
    if (!prop)
        return std::unexpected(prop.error());
    if (!*prop)
        return std::optional<std::string>{std::nullopt};
    return std::optional<std::string>{(*prop)->value};
}

std::expected<std::unordered_map<std::string, std::string>, CustomPropertiesReadError>
CustomPropertiesStore::get_property_map(const std::string& agent_id) const {
    if (!open_) {
        if (note_read_degrade(metrics_, kReasonStoreNotOpen, g_map_sampler))
            spdlog::warn("CustomPropertiesStore::get_property_map: store not open");
        return std::unexpected(CustomPropertiesReadError::kDegraded);
    }
    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease) {
        if (note_read_degrade(metrics_, kReasonPoolTimeout, g_map_sampler))
            spdlog::warn("CustomPropertiesStore::get_property_map: no connection in time ({})",
                        pool_.last_error());
        return std::unexpected(CustomPropertiesReadError::kDegraded);
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT key, value FROM custom_properties_store.custom_properties WHERE agent_id = $1",
        std::vector<std::string>{agent_id});
    if (res.status() != PGRES_TUPLES_OK) {
        if (note_read_degrade(metrics_, kReasonQueryError, g_map_sampler))
            spdlog::warn("CustomPropertiesStore::get_property_map: query failed: {}",
                        PQerrorMessage(lease.get()));
        return std::unexpected(CustomPropertiesReadError::kDegraded);
    }
    std::unordered_map<std::string, std::string> result;
    const int rows = PQntuples(res.get());
    result.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        result.emplace(text_col(res.get(), i, 0), text_col(res.get(), i, 1));
    return result;
}

std::expected<std::unordered_map<std::string, std::unordered_map<std::string, std::string>>,
              CustomPropertiesReadError>
CustomPropertiesStore::get_values_for_keys(const std::vector<std::string>& keys) const {
    std::unordered_map<std::string, std::unordered_map<std::string, std::string>> result;
    if (keys.empty())
        return result;
    if (!open_) {
        if (note_read_degrade(metrics_, kReasonStoreNotOpen, g_map_sampler))
            spdlog::warn("CustomPropertiesStore::get_values_for_keys: store not open");
        return std::unexpected(CustomPropertiesReadError::kDegraded);
    }
    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease) {
        if (note_read_degrade(metrics_, kReasonPoolTimeout, g_map_sampler))
            spdlog::warn("CustomPropertiesStore::get_values_for_keys: no connection in time ({})",
                        pool_.last_error());
        return std::unexpected(CustomPropertiesReadError::kDegraded);
    }
    std::vector<std::string_view> key_views(keys.begin(), keys.end());
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT agent_id, key, value FROM custom_properties_store.custom_properties "
        "WHERE key = ANY($1::text[])",
        std::vector<std::string>{pg::to_text_array(key_views)});
    if (res.status() != PGRES_TUPLES_OK) {
        if (note_read_degrade(metrics_, kReasonQueryError, g_map_sampler))
            spdlog::warn("CustomPropertiesStore::get_values_for_keys: query failed: {}",
                        PQerrorMessage(lease.get()));
        return std::unexpected(CustomPropertiesReadError::kDegraded);
    }
    const int rows = PQntuples(res.get());
    for (int i = 0; i < rows; ++i) {
        result[text_col(res.get(), i, 0)].emplace(text_col(res.get(), i, 1),
                                                   text_col(res.get(), i, 2));
    }
    return result;
}

std::expected<void, std::string>
CustomPropertiesStore::set_property(const std::string& agent_id, const std::string& key,
                                    const std::string& value, const std::string& type) {
    if (!open_)
        return std::unexpected("store not open");
    if (!validate_key(key))
        return std::unexpected("invalid property key (1-64 chars, alphanumeric/._:-)");
    if (!validate_value(value))
        return std::unexpected("property value exceeds maximum length (1024 bytes)");

    // ADR-0012 §2(c): schema-check + upsert as ONE logical operation on ONE
    // lease (a single with_txn), not two separate acquires — the SQLite
    // original held one mutex across both under the same lock for the same
    // reason (a schema landing between the check and the write must not be
    // able to observe a partially-validated write).
    const std::string sanitized_value = sanitize_pg_text(value);
    std::string effective_type = type;
    std::string schema_error;
    const bool ok = pool_.with_txn_for(kAcquireTimeout, [&](PGconn* c) -> bool {
        auto schema_result = validate_against_schema(c, key, sanitized_value);
        if (!schema_result) {
            schema_error = schema_result.error();
            return false;
        }
        // Use schema type if available, otherwise the caller-provided type
        // (matches SQLite original's effective-type resolution).
        pg::PgResult st = pg::exec_params(
            c, "SELECT type FROM custom_properties_store.custom_property_schemas WHERE key = $1",
            std::vector<std::string>{key});
        if (st.status() == PGRES_TUPLES_OK && PQntuples(st.get()) > 0)
            effective_type = text_col(st.get(), 0, 0);

        pg::PgResult res = pg::exec_params(
            c,
            "INSERT INTO custom_properties_store.custom_properties "
            "(agent_id, key, value, type, updated_at) VALUES ($1, $2, $3, $4, $5::bigint) "
            "ON CONFLICT (agent_id, key) DO UPDATE SET "
            "  value = EXCLUDED.value, type = EXCLUDED.type, updated_at = EXCLUDED.updated_at "
            "RETURNING agent_id",
            std::vector<std::string>{agent_id, key, sanitized_value, effective_type,
                                     std::to_string(now_secs())});
        if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) != 1) {
            schema_error = "database write failed";
            return false;
        }
        return true;
    });
    if (!ok) {
        if (schema_error.empty())
            schema_error = "database error";
        return std::unexpected(schema_error);
    }
    return {};
}

bool CustomPropertiesStore::delete_property(const std::string& agent_id, const std::string& key) {
    if (!open_)
        return false;
    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease) {
        spdlog::debug("CustomPropertiesStore::delete_property: no connection in time ({})",
                      pool_.last_error());
        return false;
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "DELETE FROM custom_properties_store.custom_properties "
        "WHERE agent_id = $1 AND key = $2 RETURNING agent_id",
        std::vector<std::string>{agent_id, key});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::debug("CustomPropertiesStore::delete_property: query failed: {}",
                      PQerrorMessage(lease.get()));
        return false;
    }
    return PQntuples(res.get()) > 0;
}

void CustomPropertiesStore::delete_all_properties(const std::string& agent_id) {
    if (!open_)
        return;
    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease) {
        spdlog::debug("CustomPropertiesStore::delete_all_properties: no connection in time ({})",
                      pool_.last_error());
        return;
    }
    pg::PgResult res = pg::exec_params(
        lease.get(), "DELETE FROM custom_properties_store.custom_properties WHERE agent_id = $1",
        std::vector<std::string>{agent_id});
    if (res.status() != PGRES_COMMAND_OK) {
        spdlog::warn("CustomPropertiesStore::delete_all_properties: delete failed for agent={}: {}",
                    agent_id, PQerrorMessage(lease.get()));
    }
}

// ── Schema CRUD ──────────────────────────────────────────────────────────────

std::vector<CustomPropertySchema> CustomPropertiesStore::list_schemas() const {
    std::vector<CustomPropertySchema> results;
    if (!open_)
        return results;
    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease) {
        spdlog::debug("CustomPropertiesStore::list_schemas: no connection in time ({})",
                      pool_.last_error());
        return results;
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT key, display_name, type, description, validation_regex "
        "FROM custom_properties_store.custom_property_schemas ORDER BY key",
        std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::debug("CustomPropertiesStore::list_schemas: query failed: {}",
                      PQerrorMessage(lease.get()));
        return results;
    }
    const int rows = PQntuples(res.get());
    results.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i) {
        CustomPropertySchema s;
        s.key = text_col(res.get(), i, 0);
        s.display_name = text_col(res.get(), i, 1);
        s.type = text_col(res.get(), i, 2);
        s.description = text_col(res.get(), i, 3);
        s.validation_regex = text_col(res.get(), i, 4);
        results.push_back(std::move(s));
    }
    return results;
}

std::optional<CustomPropertySchema>
CustomPropertiesStore::get_schema(const std::string& key) const {
    if (!open_)
        return std::nullopt;
    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease) {
        spdlog::debug("CustomPropertiesStore::get_schema: no connection in time ({})",
                      pool_.last_error());
        return std::nullopt;
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT key, display_name, type, description, validation_regex "
        "FROM custom_properties_store.custom_property_schemas WHERE key = $1",
        std::vector<std::string>{key});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) == 0) {
        if (res.status() != PGRES_TUPLES_OK)
            spdlog::debug("CustomPropertiesStore::get_schema: query failed: {}",
                          PQerrorMessage(lease.get()));
        return std::nullopt;
    }
    CustomPropertySchema s;
    s.key = text_col(res.get(), 0, 0);
    s.display_name = text_col(res.get(), 0, 1);
    s.type = text_col(res.get(), 0, 2);
    s.description = text_col(res.get(), 0, 3);
    s.validation_regex = text_col(res.get(), 0, 4);
    return s;
}

std::expected<void, std::string>
CustomPropertiesStore::upsert_schema(const CustomPropertySchema& schema) {
    if (!open_)
        return std::unexpected("store not open");
    if (!validate_key(schema.key))
        return std::unexpected("invalid schema key");

    static const std::array<const char*, 4> kValidTypes = {"string", "int", "bool", "datetime"};
    if (std::find(kValidTypes.begin(), kValidTypes.end(), schema.type) == kValidTypes.end())
        return std::unexpected("type must be one of: string, int, bool, datetime");

    if (!schema.validation_regex.empty()) {
        // L10: limit regex length to prevent ReDoS.
        constexpr std::size_t kMaxRegexLength = 256;
        if (schema.validation_regex.size() > kMaxRegexLength)
            return std::unexpected("validation regex exceeds maximum length of 256 characters");
        RE2 re(schema.validation_regex, RE2::Quiet);
        if (!re.ok())
            return std::unexpected(std::string("invalid validation regex: ") + re.error());
    }

    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease)
        return std::unexpected("database error");

    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO custom_properties_store.custom_property_schemas "
        "(key, display_name, type, description, validation_regex) VALUES ($1, $2, $3, $4, $5) "
        "ON CONFLICT (key) DO UPDATE SET "
        "  display_name = EXCLUDED.display_name, type = EXCLUDED.type, "
        "  description = EXCLUDED.description, validation_regex = EXCLUDED.validation_regex "
        "RETURNING key",
        std::vector<std::string>{schema.key, sanitize_pg_text(schema.display_name), schema.type,
                                 sanitize_pg_text(schema.description), schema.validation_regex});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) != 1)
        return std::unexpected("database write failed");
    return {};
}

bool CustomPropertiesStore::delete_schema(const std::string& key) {
    if (!open_)
        return false;
    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease) {
        spdlog::debug("CustomPropertiesStore::delete_schema: no connection in time ({})",
                      pool_.last_error());
        return false;
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "DELETE FROM custom_properties_store.custom_property_schemas WHERE key = $1 RETURNING key",
        std::vector<std::string>{key});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::debug("CustomPropertiesStore::delete_schema: query failed: {}",
                      PQerrorMessage(lease.get()));
        return false;
    }
    return PQntuples(res.get()) > 0;
}

// ── Backfill (ADR-0009) ───────────────────────────────────────────────────────
//
// Mirrors RbacStore::migrate_from_sqlite's post-#2703 reference shape
// (docs/postgres-store-playbook.md "Local source absence never creates
// terminal migration state on its own"), sized down: this store's two
// independent tables carry no revoke-vs-reseed conflict and no promotable
// "sourceless" writer race worth its own state machine — the fingerprint IS
// the sourceless sentinel (an empty-tables legacy DB and a missing legacy
// file fingerprint identically), so a plain first-writer-wins ON CONFLICT DO
// NOTHING on the marker is sufficient (unlike RbacStore, nothing here can
// legitimately "promote" a sourceless stamp — every real fingerprint that
// loses the race left no partial writes behind it worth reconciling, because
// the only writes this backfill makes are its own idempotent upserts on
// tables no other writer touches before first boot completes).

namespace {

constexpr const char* kSourcelessFingerprint = "sourceless";

std::optional<bool> legacy_has_table(sqlite3* db, const char* table) {
    SqliteStmt s;
    if (sqlite3_prepare_v2(db, "SELECT 1 FROM sqlite_master WHERE type='table' AND name = ?", -1,
                           s.addr(), nullptr) != SQLITE_OK)
        return std::nullopt;
    sqlite3_bind_text(s.get(), 1, table, -1, SQLITE_STATIC);
    const int rc = sqlite3_step(s.get());
    if (rc == SQLITE_ROW)
        return true;
    if (rc == SQLITE_DONE)
        return false;
    return std::nullopt;
}

std::optional<std::string> sha256_hex(std::string_view in) {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    if (EVP_Digest(in.data(), in.size(), md, &len, EVP_sha256(), nullptr) != 1)
        return std::nullopt;
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (unsigned int i = 0; i < len; ++i) {
        out.push_back(kHex[md[i] >> 4]);
        out.push_back(kHex[md[i] & 0x0F]);
    }
    return out;
}

std::string legacy_text(sqlite3_stmt* s, int col) {
    const auto* v = sqlite3_column_text(s, col);
    return v ? std::string(reinterpret_cast<const char*>(v),
                           static_cast<std::size_t>(sqlite3_column_bytes(s, col)))
             : std::string{};
}

struct LProperty {
    std::string agent_id, key, value, type;
    std::int64_t updated_at{0};
};
struct LSchema {
    std::string key, display_name, type, description, validation_regex;
};
struct LegacySnapshot {
    std::vector<LProperty> properties;
    std::vector<LSchema> schemas;
};

// Deterministic canonical serialization for the content fingerprint — field
// order and delimiter matter (mirrors RbacStore's canonicalize_legacy_snapshot),
// but this store's rows have no cross-row ordering ambiguity risk beyond a
// straight sort, since PRIMARY KEY already makes every row's key tuple unique.
void append_field(std::string& out, std::string_view v) {
    out += std::to_string(v.size());
    out += ':';
    out += v;
}
void append_field(std::string& out, std::int64_t v) { append_field(out, std::to_string(v)); }

std::string canonicalize_legacy_snapshot(const LegacySnapshot& snap) {
    std::vector<std::string> rows;
    rows.reserve(snap.properties.size() + snap.schemas.size());
    for (const auto& p : snap.properties) {
        std::string r;
        append_field(r, "prop");
        append_field(r, p.agent_id);
        append_field(r, p.key);
        append_field(r, p.value);
        append_field(r, p.type);
        append_field(r, p.updated_at);
        rows.push_back(std::move(r));
    }
    for (const auto& s : snap.schemas) {
        std::string r;
        append_field(r, "schema");
        append_field(r, s.key);
        append_field(r, s.display_name);
        append_field(r, s.type);
        append_field(r, s.description);
        append_field(r, s.validation_regex);
        rows.push_back(std::move(r));
    }
    std::sort(rows.begin(), rows.end());
    std::string canon = "custom-properties-legacy-fingerprint-v1\n";
    for (const auto& r : rows)
        canon += r;
    return canon;
}

std::optional<std::string> fingerprint_legacy_snapshot(const LegacySnapshot& snap) {
    const auto hash = sha256_hex(canonicalize_legacy_snapshot(snap));
    if (!hash)
        return std::nullopt;
    return "v1:" + *hash;
}

// nullopt == a genuine read error (fail-closed); an empty snapshot with no
// error is a legitimate zero-row legacy database.
std::optional<LegacySnapshot> read_legacy_snapshot(sqlite3* db) {
    LegacySnapshot snap;
    {
        SqliteStmt s;
        if (sqlite3_prepare_v2(db, "SELECT agent_id, key, value, type, updated_at FROM custom_properties",
                               -1, s.addr(), nullptr) != SQLITE_OK)
            return std::nullopt;
        int rc;
        while ((rc = sqlite3_step(s.get())) == SQLITE_ROW) {
            LProperty p;
            p.agent_id = legacy_text(s.get(), 0);
            p.key = legacy_text(s.get(), 1);
            p.value = legacy_text(s.get(), 2);
            p.type = legacy_text(s.get(), 3);
            p.updated_at = sqlite3_column_int64(s.get(), 4);
            snap.properties.push_back(std::move(p));
        }
        if (rc != SQLITE_DONE)
            return std::nullopt;
    }
    {
        SqliteStmt s;
        if (sqlite3_prepare_v2(
                db, "SELECT key, display_name, type, description, validation_regex FROM custom_property_schemas",
                -1, s.addr(), nullptr) != SQLITE_OK)
            return std::nullopt;
        int rc;
        while ((rc = sqlite3_step(s.get())) == SQLITE_ROW) {
            LSchema sc;
            sc.key = legacy_text(s.get(), 0);
            sc.display_name = legacy_text(s.get(), 1);
            sc.type = legacy_text(s.get(), 2);
            sc.description = legacy_text(s.get(), 3);
            sc.validation_regex = legacy_text(s.get(), 4);
            snap.schemas.push_back(std::move(sc));
        }
        if (rc != SQLITE_DONE)
            return std::nullopt;
    }
    return snap;
}

// Path-based convenience for the holder-side verification call site: opens
// read-only, probes for corruption, and either returns the sourceless
// sentinel (neither table present — same "nothing to protect" class as no
// local file at all) or fingerprints a full snapshot. Returns nullopt ONLY on
// a corrupt/unreadable file or a snapshot read failure — the caller MUST fail
// closed on that, never treat it as sourceless-equivalent.
std::optional<std::string> legacy_fingerprint(const std::filesystem::path& legacy_db_path) {
    SqliteDb legacy;
    if (sqlite3_open_v2(legacy_db_path.string().c_str(), legacy.addr(), SQLITE_OPEN_READONLY,
                        nullptr) != SQLITE_OK)
        return std::nullopt;
    sqlite3_exec(legacy.get(), "PRAGMA busy_timeout=5000;", nullptr, nullptr, nullptr);
    {
        SqliteStmt probe;
        if (sqlite3_prepare_v2(legacy.get(), "SELECT count(*) FROM sqlite_master", -1, probe.addr(),
                               nullptr) != SQLITE_OK ||
            sqlite3_step(probe.get()) != SQLITE_ROW)
            return std::nullopt;
    }
    const auto has_props = legacy_has_table(legacy.get(), "custom_properties");
    if (!has_props)
        return std::nullopt; // genuine read error, NOT "no table"
    if (!*has_props)
        return std::string(kSourcelessFingerprint);
    const auto snap = read_legacy_snapshot(legacy.get());
    if (!snap)
        return std::nullopt;
    return fingerprint_legacy_snapshot(*snap);
}

} // namespace

bool CustomPropertiesStore::migrate_from_sqlite(const std::filesystem::path& legacy_db_path) {
    if (!open_)
        return false;

    const auto backfill_metric = [this](const char* result) {
        if (metrics_)
            metrics_->counter("yuzu_server_custom_properties_backfill_total", {{"result", result}})
                .increment();
    };

    // The marker and its source fingerprint are ALWAYS stamped together, in
    // the SAME transaction — the anti-pattern the playbook's "Local source
    // absence never creates terminal migration state on its own" note
    // guards against.
    const auto stamp_complete = [&](std::string_view source_fingerprint) -> bool {
        return pool_.with_txn_for(kBackfillTxnTimeout, [source_fingerprint](PGconn* c) -> bool {
            pg::PgResult mk = pg::exec_params(
                c,
                "INSERT INTO custom_properties_store.custom_properties_meta (key, value) VALUES "
                "('backfill_complete', $1) ON CONFLICT (key) DO NOTHING",
                std::vector<std::string>{std::to_string(now_secs())});
            if (mk.status() != PGRES_COMMAND_OK) {
                spdlog::error("CustomPropertiesStore: migrate_from_sqlite: marker stamp failed: {}",
                              PQerrorMessage(c));
                return false;
            }
            pg::PgResult fp = pg::exec_params(
                c,
                "INSERT INTO custom_properties_store.custom_properties_meta (key, value) VALUES "
                "('backfill_source_fingerprint', $1) ON CONFLICT (key) DO NOTHING RETURNING value",
                std::vector<std::string>{std::string(source_fingerprint)});
            if (fp.status() != PGRES_TUPLES_OK) {
                spdlog::error(
                    "CustomPropertiesStore: migrate_from_sqlite: source-fingerprint stamp failed: {}",
                    PQerrorMessage(c));
                return false;
            }
            // A DO NOTHING lost race is fine here (unlike RbacStore): nothing
            // else writes custom_properties/custom_property_schemas before
            // first boot completes, so whichever replica's fingerprint won
            // reflects the same shared legacy file content this replica
            // would have derived — see the header comment above for the
            // full reasoning this simplification relies on.
            return true;
        });
    };

    const auto move_legacy_aside = [](const std::filesystem::path& path) {
        std::filesystem::path aside;
        for (int suffix = 0;; ++suffix) {
            aside = path;
            aside += ".migrated-" + std::to_string(now_secs());
            if (suffix > 0)
                aside += "-" + std::to_string(suffix);
            std::error_code exists_ec;
            if (!std::filesystem::exists(aside, exists_ec))
                break;
        }
        std::error_code mv_ec;
        std::filesystem::rename(path, aside, mv_ec);
        if (mv_ec)
            spdlog::warn("CustomPropertiesStore: migrate_from_sqlite: could not move legacy {} "
                         "aside ({}); it is safe to archive/remove manually",
                         path.string(), mv_ec.message());
        else
            spdlog::info("CustomPropertiesStore: migrate_from_sqlite: moved legacy db to {}",
                        aside.string());
    };

    // 1. Local legacy-file presence (cheap stat), hoisted before the marker
    // lookup so step 2 knows whether this replica has something to verify a
    // pre-existing marker against.
    std::error_code ec;
    const bool legacy_exists = std::filesystem::exists(legacy_db_path, ec);
    if (ec) {
        spdlog::error("CustomPropertiesStore: migrate_from_sqlite: cannot stat legacy path {}: {}",
                      legacy_db_path.string(), ec.message());
        backfill_metric("failed");
        return false;
    }

    // 2. Idempotency marker (short-lived lease, released before any legacy
    // file I/O — ADR-0012 §2(b)).
    bool marker_present = false;
    std::optional<std::string> stored_fingerprint;
    {
        auto lease = pool_.acquire();
        if (!lease) {
            spdlog::error("CustomPropertiesStore: migrate_from_sqlite: no database connection ({})",
                          pool_.last_error());
            backfill_metric("failed");
            return false;
        }
        pg::PgResult mk = pg::exec_params(
            lease.get(),
            "SELECT key, value FROM custom_properties_store.custom_properties_meta WHERE key IN "
            "('backfill_complete', 'backfill_source_fingerprint')",
            std::vector<std::string>{});
        if (mk.status() != PGRES_TUPLES_OK) {
            spdlog::error("CustomPropertiesStore: migrate_from_sqlite: marker lookup failed: {}",
                          PQerrorMessage(lease.get()));
            backfill_metric("failed");
            return false;
        }
        for (int i = 0; i < PQntuples(mk.get()); ++i) {
            const std::string key = text_col(mk.get(), i, 0);
            if (key == "backfill_complete")
                marker_present = true;
            else if (key == "backfill_source_fingerprint")
                stored_fingerprint = text_col(mk.get(), i, 1);
        }
    }

    if (marker_present) {
        if (!legacy_exists) {
            spdlog::debug("CustomPropertiesStore: migrate_from_sqlite already completed, skipping");
            return true;
        }
        // This replica still holds a local legacy file even though the
        // marker is already set — verify it was actually the file that got
        // migrated before trusting the marker.
        const auto verify_fp = legacy_fingerprint(legacy_db_path);
        if (!verify_fp) {
            spdlog::error(
                "CustomPropertiesStore: migrate_from_sqlite: backfill_complete is already set, "
                "and this replica's own legacy db {} exists but is unreadable/corrupt while "
                "being fingerprint-verified — refusing (fail-closed; never silently trust a "
                "marker over an unverifiable local file)",
                legacy_db_path.string());
            backfill_metric("failed");
            return false;
        }
        if (*verify_fp == kSourcelessFingerprint) {
            spdlog::debug("CustomPropertiesStore: migrate_from_sqlite already completed; this "
                         "replica's own legacy db has no custom_properties table (nothing to "
                         "lose), skipping");
            return true;
        }
        if (!stored_fingerprint || *stored_fingerprint != *verify_fp) {
            spdlog::error(
                "CustomPropertiesStore: migrate_from_sqlite: HOLDER-SIDE VERIFICATION FAILED — "
                "backfill_complete is already set with fingerprint '{}' but this replica's own "
                "legacy db {} fingerprints as '{}' — some other replica's legacy data was "
                "migrated, not this one's (docs/postgres-store-playbook.md anti-pattern 'Local "
                "source absence never creates terminal migration state on its own'). Refusing "
                "to silently accept a completion this replica's properties/schemas were never "
                "part of.",
                stored_fingerprint.value_or("<none recorded>"), legacy_db_path.string(),
                *verify_fp);
            backfill_metric("failed");
            return false;
        }
        spdlog::debug("CustomPropertiesStore: migrate_from_sqlite already completed (fingerprint "
                     "verified), skipping");
        move_legacy_aside(legacy_db_path);
        return true;
    }

    if (!legacy_exists) {
        if (!stamp_complete(kSourcelessFingerprint)) {
            backfill_metric("failed");
            return false;
        }
        spdlog::info("CustomPropertiesStore: migrate_from_sqlite: no legacy db at {}; marking "
                     "backfill complete (fresh install)",
                     legacy_db_path.string());
        backfill_metric("fresh");
        return true;
    }

    // 3. Open legacy read-only, probe for corruption.
    SqliteDb legacy;
    if (sqlite3_open_v2(legacy_db_path.string().c_str(), legacy.addr(), SQLITE_OPEN_READONLY,
                        nullptr) != SQLITE_OK) {
        spdlog::error("CustomPropertiesStore: migrate_from_sqlite: failed to open legacy db {}: {}",
                      legacy_db_path.string(),
                      legacy ? sqlite3_errmsg(legacy.get()) : "open failed");
        backfill_metric("failed");
        return false;
    }
    sqlite3_exec(legacy.get(), "PRAGMA busy_timeout=5000;", nullptr, nullptr, nullptr);
    {
        SqliteStmt probe;
        if (sqlite3_prepare_v2(legacy.get(), "SELECT count(*) FROM sqlite_master", -1, probe.addr(),
                               nullptr) != SQLITE_OK ||
            sqlite3_step(probe.get()) != SQLITE_ROW) {
            spdlog::error("CustomPropertiesStore: migrate_from_sqlite: legacy db {} is "
                          "unreadable/corrupt ({}); refusing backfill (fail-closed — never "
                          "silently drop operator custom-properties data)",
                          legacy_db_path.string(), sqlite3_errmsg(legacy.get()));
            backfill_metric("failed");
            return false;
        }
    }
    const auto has_props = legacy_has_table(legacy.get(), "custom_properties");
    if (!has_props) {
        spdlog::error("CustomPropertiesStore: migrate_from_sqlite: legacy db {} could not be "
                      "probed for a custom_properties table ({}); refusing backfill (fail-closed)",
                      legacy_db_path.string(), sqlite3_errmsg(legacy.get()));
        backfill_metric("failed");
        return false;
    }
    if (!*has_props) {
        if (!stamp_complete(kSourcelessFingerprint)) {
            backfill_metric("failed");
            return false;
        }
        spdlog::warn("CustomPropertiesStore: migrate_from_sqlite: legacy db {} has no "
                     "custom_properties table; marking backfill complete",
                     legacy_db_path.string());
        backfill_metric("fresh");
        return true;
    }

    // 4. Read every legacy row ONCE into a shared snapshot — both the real
    // migration below and this run's own stamp_complete fingerprint derive
    // from it, so there is no second file read anywhere in this function
    // (no TOCTOU window between what got migrated and what got fingerprinted).
    const auto snap_opt = read_legacy_snapshot(legacy.get());
    if (!snap_opt) {
        spdlog::error("CustomPropertiesStore: migrate_from_sqlite: legacy read failed: {}",
                      sqlite3_errmsg(legacy.get()));
        backfill_metric("failed");
        return false;
    }
    const LegacySnapshot& snap = *snap_opt;
    const auto fingerprint = fingerprint_legacy_snapshot(snap);
    if (!fingerprint) {
        spdlog::error(
            "CustomPropertiesStore: migrate_from_sqlite: failed to fingerprint legacy content "
            "(SHA-256 digest failure) — refusing backfill (fail-closed)");
        backfill_metric("failed");
        return false;
    }

    // 5. Bulk-insert schemas first (properties don't FK to them in Postgres,
    // but ordering matches the original table-creation order and keeps the
    // migration legible). ON CONFLICT DO NOTHING per row (unnest arrays kept
    // to a bounded batch size for simplicity — this store's config data is
    // small; the ~27-store playbook doesn't mandate batching for reference-
    // sized tables the way it does for high-volume ingest).
    const bool ok = pool_.with_txn_for(kBackfillTxnTimeout, [&](PGconn* c) -> bool {
        for (const auto& s : snap.schemas) {
            pg::PgResult r = pg::exec_params(
                c,
                "INSERT INTO custom_properties_store.custom_property_schemas "
                "(key, display_name, type, description, validation_regex) "
                "VALUES ($1, $2, $3, $4, $5) ON CONFLICT (key) DO NOTHING",
                std::vector<std::string>{s.key, sanitize_pg_text(s.display_name), s.type,
                                         sanitize_pg_text(s.description), s.validation_regex});
            if (r.status() != PGRES_COMMAND_OK) {
                spdlog::error("CustomPropertiesStore: migrate_from_sqlite: schema insert failed "
                              "for key='{}': {}",
                              s.key, PQerrorMessage(c));
                return false;
            }
        }
        for (const auto& p : snap.properties) {
            pg::PgResult r = pg::exec_params(
                c,
                "INSERT INTO custom_properties_store.custom_properties "
                "(agent_id, key, value, type, updated_at) VALUES ($1, $2, $3, $4, $5::bigint) "
                "ON CONFLICT (agent_id, key) DO NOTHING",
                std::vector<std::string>{p.agent_id, p.key, sanitize_pg_text(p.value), p.type,
                                         std::to_string(p.updated_at)});
            if (r.status() != PGRES_COMMAND_OK) {
                spdlog::error("CustomPropertiesStore: migrate_from_sqlite: property insert failed "
                              "for agent_id='{}' key='{}': {}",
                              p.agent_id, p.key, PQerrorMessage(c));
                return false;
            }
        }
        return true;
    });
    if (!ok) {
        backfill_metric("failed");
        return false;
    }

    if (!stamp_complete(*fingerprint)) {
        backfill_metric("failed");
        return false;
    }
    spdlog::info("CustomPropertiesStore: migrate_from_sqlite: backfilled {} properties, {} "
                 "schemas from {}",
                 snap.properties.size(), snap.schemas.size(), legacy_db_path.string());
    move_legacy_aside(legacy_db_path);
    backfill_metric("success");
    return true;
}

} // namespace yuzu::server
