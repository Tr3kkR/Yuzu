#include "rbac_store.hpp"

#include "management_group_store.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "sqlite_raii.hpp"
#include "utf8_sanitize.hpp"

#include <yuzu/metrics.hpp>

#include <libpq-fe.h>
#include <spdlog/spdlog.h>
#include <sqlite3.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstring>
#include <functional>
#include <optional>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "rbac_store";

// Bounded acquires (ADR-0012 §2(a)). Reads back interactive REST/dashboard/MCP
// callers; writes get a slightly wider budget. Backfill runs single-threaded at
// construction before serving, so a wide deadline is fine.
constexpr std::chrono::milliseconds kReadTimeout{2000};
constexpr std::chrono::milliseconds kWriteTimeout{4000};
constexpr std::chrono::milliseconds kBackfillTxnTimeout{60000};

// Cross-replica permission-cache coherence (ADR-0041): re-validate the durable
// generation token at most this often on the read hot path.
constexpr std::int64_t kRbacGenerationRefreshMs = 1000;

// Read-degrade reason labels (ADR-0037 convention). A !open_ store fails boot
// closed (never serves), so only the pool-timeout / query-error hot-path
// degrades are counted here.
constexpr const char* kReasonPoolTimeout = "pool_acquire_timeout";
constexpr const char* kReasonQueryError = "query_error";
constexpr std::uint64_t kReadDegradeLogSample = 100;
constexpr std::int64_t kDegradeEpisodeGapSecs = 60;

// ── IdP / engine namespace guards (ported verbatim from the SQLite store) ────

constexpr std::array<std::string_view, 3> kRecognizedIdpSources = {"entra", "saml", "ad"};
constexpr std::string_view kLocalPrefix = "local:";
constexpr std::string_view kEnginePrefix = "engine:";

bool has_reserved_idp_prefix(std::string_view name) {
    if (name.size() >= kLocalPrefix.size() && name.compare(0, kLocalPrefix.size(), kLocalPrefix) == 0)
        return true;
    if (name.size() >= kEnginePrefix.size() &&
        name.compare(0, kEnginePrefix.size(), kEnginePrefix) == 0)
        return true;
    for (auto source : kRecognizedIdpSources) {
        if (name.size() > source.size() && name[source.size()] == ':' &&
            name.compare(0, source.size(), source) == 0)
            return true;
    }
    return false;
}

bool is_blank(std::string_view s) {
    for (unsigned char c : s) {
        if (!std::isspace(c))
            return false;
    }
    return true;
}

constexpr size_t kMaxExternalIdLength = 512;

/// Built-in role names an engine-principal assignment must never receive —
/// `RbacStore::validate_assignment`'s "no admin, ever" bar (design §4.2).
/// EXTEND this set — never fork a second bar elsewhere.
constexpr std::array<std::string_view, 2> kEngineDisallowedRoles = {"admin", "Administrator"};

std::int64_t now_secs() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}
std::int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

std::int64_t to_i64(const char* s) {
    if (s == nullptr || s[0] == '\0')
        return 0;
    return static_cast<std::int64_t>(std::strtoll(s, nullptr, 10));
}
std::uint64_t to_u64(const char* s) {
    if (s == nullptr || s[0] == '\0')
        return 0;
    return static_cast<std::uint64_t>(std::strtoull(s, nullptr, 10));
}
bool to_bool(const char* s) { return s != nullptr && (s[0] == 't' || s[0] == 'T' || s[0] == '1'); }

std::string text_col(PGresult* res, int row, int col) {
    if (PQgetisnull(res, row, col))
        return {};
    return std::string(PQgetvalue(res, row, col),
                       static_cast<std::size_t>(PQgetlength(res, row, col)));
}

// sanitize_utf8_strict scrubs invalid UTF-8 to U+FFFD but keeps embedded NUL (a
// valid ASCII byte). PostgreSQL TEXT cannot store a NUL and libpq's text-format
// bind C-string-truncates at the first one. So after the UTF-8 scrub, replace
// every NUL with U+FFFD too. Ported verbatim from audit_store.cpp (ADR-0040) —
// applied to every free-text column, INCLUDING the backfill path (a bad byte
// at-rest in a legacy rbac.db must not brick the MANDATORY backfill).
std::string sanitize_pg_text(std::string_view s) {
    std::string out = sanitize_utf8_strict(s);
    std::size_t pos = 0;
    while ((pos = out.find('\0', pos)) != std::string::npos) {
        out.replace(pos, 1, "\xEF\xBF\xBD");
        pos += 3;
    }
    return out;
}

// ── Read-degrade observability (mirrors AuditStore/InventoryStore) ───────────
struct DegradeSampler {
    std::atomic<std::uint64_t> count{0};
    std::atomic<std::int64_t> last_ts{0};
};

bool note_read_degrade(yuzu::MetricsRegistry* metrics, const char* reason, DegradeSampler& s) {
    if (metrics)
        metrics->counter("yuzu_server_rbac_read_degrade_total", {{"reason", reason}}).increment();
    const std::int64_t now = now_secs();
    const std::int64_t prev = s.last_ts.exchange(now, std::memory_order_relaxed);
    const std::uint64_t n = s.count.fetch_add(1, std::memory_order_relaxed) + 1;
    const bool new_episode = prev == 0 || (now - prev) > kDegradeEpisodeGapSecs;
    return new_episode || (n % kReadDegradeLogSample) == 0;
}

// ── PostgreSQL schema (ADR-0041): the final column set of the SQLite store's
// four migrations, collapsed into one v1. Migrations v3/v4 were data cleanups
// against a live rbac.db — a fresh PG database needs neither (nothing to clean),
// and backfill copies an already-cleaned legacy DB, so they are not replayed.
// Unqualified DDL — the runner sets search_path to `rbac_store`; runtime
// statements below schema-qualify explicitly. `is_system` is BOOLEAN in PG.
const std::vector<pg::PgMigration>& migrations() {
    static const std::vector<pg::PgMigration> kMigrations = {
        {1, R"(
            CREATE TABLE securable_types (
                name        TEXT PRIMARY KEY,
                description TEXT NOT NULL DEFAULT '',
                is_system   BOOLEAN NOT NULL DEFAULT FALSE
            );

            CREATE TABLE operations (
                id          TEXT PRIMARY KEY,
                description TEXT NOT NULL DEFAULT '',
                is_system   BOOLEAN NOT NULL DEFAULT FALSE
            );

            CREATE TABLE roles (
                name        TEXT PRIMARY KEY,
                description TEXT NOT NULL DEFAULT '',
                is_system   BOOLEAN NOT NULL DEFAULT FALSE,
                created_at  BIGINT NOT NULL DEFAULT 0
            );

            CREATE TABLE role_permissions (
                role_name       TEXT NOT NULL REFERENCES roles(name) ON DELETE CASCADE,
                securable_type  TEXT NOT NULL REFERENCES securable_types(name),
                operation       TEXT NOT NULL REFERENCES operations(id),
                effect          TEXT NOT NULL DEFAULT 'allow',
                PRIMARY KEY (role_name, securable_type, operation)
            );

            CREATE TABLE principal_roles (
                principal_type  TEXT NOT NULL,
                principal_id    TEXT NOT NULL,
                role_name       TEXT NOT NULL REFERENCES roles(name) ON DELETE CASCADE,
                PRIMARY KEY (principal_type, principal_id, role_name)
            );
            CREATE INDEX idx_principal_roles_lookup
                ON principal_roles(principal_type, principal_id);

            CREATE TABLE groups (
                name        TEXT PRIMARY KEY,
                description TEXT NOT NULL DEFAULT '',
                source      TEXT NOT NULL DEFAULT 'local',
                external_id TEXT,
                created_at  BIGINT NOT NULL DEFAULT 0
            );
            CREATE INDEX idx_groups_source ON groups(source);

            CREATE TABLE group_members (
                group_name  TEXT NOT NULL REFERENCES groups(name) ON DELETE CASCADE,
                username    TEXT NOT NULL,
                PRIMARY KEY (group_name, username)
            );
            CREATE INDEX idx_group_members_username ON group_members(username);

            -- Durable k/v (ADR-0041): the global `rbac_enabled` flag AND the
            -- cross-replica `write_generation` counter (bumped in the same txn
            -- as every mutation), plus the one-time `backfill_complete` marker.
            CREATE TABLE rbac_meta (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
        )"},
    };
    return kMigrations;
}

// ── Legacy (SQLite) introspection for the backfill ───────────────────────────
bool legacy_has_table(sqlite3* db, const char* table) {
    SqliteStmt s;
    if (sqlite3_prepare_v2(db, "SELECT 1 FROM sqlite_master WHERE type='table' AND name = ?", -1,
                           s.addr(), nullptr) != SQLITE_OK)
        return false;
    sqlite3_bind_text(s.get(), 1, table, -1, SQLITE_STATIC);
    return sqlite3_step(s.get()) == SQLITE_ROW;
}

std::string sqlite_text(sqlite3_stmt* s, int col) {
    const auto* v = sqlite3_column_text(s, col);
    return v ? std::string(reinterpret_cast<const char*>(v),
                           static_cast<std::size_t>(sqlite3_column_bytes(s, col)))
             : std::string{};
}

// Bind the SQL boolean literal for a legacy INTEGER is_system value.
const char* bool_lit(std::int64_t v) { return v != 0 ? "true" : "false"; }

} // namespace

std::string namespaced_group_name(const std::string& source, const std::string& external_id) {
    if (source == "local")
        return external_id;
    return source + ":" + external_id;
}

// ── Construction / teardown ──────────────────────────────────────────────────

RbacStore::RbacStore(pg::PgPool& pool) : pool_(pool) {
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("RbacStore: no database connection at construction ({}) — authorization "
                      "substrate disabled (fail-closed: every authz read will DENY)",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("RbacStore: schema migration failed — authorization substrate disabled "
                      "(fail-closed)");
        return;
    }
    lease.reset(); // seed_defaults/load_enabled_flag re-acquire their own leases
    open_ = true;
    seed_defaults();
    load_enabled_flag();
    spdlog::info("RbacStore initialized (schema {})", kStoreName);
}

RbacStore::~RbacStore() = default;

// ── Seed data (idempotent — ON CONFLICT DO NOTHING) ──────────────────────────

void RbacStore::seed_defaults() {
    if (!open_)
        return;
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("RbacStore: seed_defaults: no connection ({})", pool_.last_error());
        return;
    }
    PGconn* c = lease.get();

    const auto exec = [&](const char* sql,
                          const std::vector<std::string>& params = {}) -> bool {
        pg::PgResult r = pg::exec_params(c, sql, params);
        if (!r.ok()) {
            spdlog::error("RbacStore: seed_defaults statement failed: {}", PQerrorMessage(c));
            return false;
        }
        return true;
    };

    // Durable meta defaults — never clobber a migrated value (DO NOTHING).
    exec("INSERT INTO rbac_store.rbac_meta (key, value) VALUES ('rbac_enabled','false') "
         "ON CONFLICT (key) DO NOTHING");
    exec("INSERT INTO rbac_store.rbac_meta (key, value) VALUES ('write_generation','0') "
         "ON CONFLICT (key) DO NOTHING");

    // Securable types.
    const std::array<std::string_view, 22> types = {
        "Infrastructure",  "UserManagement",  "InstructionDefinition",
        "InstructionSet",  "Execution",       "Schedule",
        "Approval",        "Tag",             "AuditLog",
        "Response",        "ManagementGroup", "ApiToken",
        "Security",        "Policy",          "DeviceToken",
        "SoftwareDeployment", "License",      "FileRetrieval",
        "GuaranteedState", "Inventory",       "AccessReview",
        "SoftwareLicensing"};
    for (auto t : types)
        exec("INSERT INTO rbac_store.securable_types (name, is_system) VALUES ($1, TRUE) "
             "ON CONFLICT (name) DO NOTHING",
             {std::string(t)});
    // R18 (ADR-0024 Decision 9): defuse the SoftwareLicensing name (does NOT
    // gate the /inventory catalog). Set only when empty — never clobber an
    // operator-set value.
    exec("UPDATE rbac_store.securable_types SET description = "
         "'gates the /api/v1/sle/* detected-licence reads and the agent-decommission erasure; "
         "the /inventory software catalog remains under Inventory:Read' "
         "WHERE name = 'SoftwareLicensing' AND description = ''");

    // Operations.
    const std::array<std::string_view, 7> ops = {"Read",    "Write", "Execute", "Delete",
                                                 "Approve", "Push",  "Attest"};
    for (auto o : ops)
        exec("INSERT INTO rbac_store.operations (id, is_system) VALUES ($1, TRUE) "
             "ON CONFLICT (id) DO NOTHING",
             {std::string(o)});
    const std::array<std::string_view, 5> crud_ops = {"Read", "Write", "Execute", "Delete",
                                                      "Approve"};

    const std::int64_t now = now_secs();

    struct RoleSeed {
        std::string_view name;
        std::string_view desc;
    };
    const std::array<RoleSeed, 7> roles = {
        RoleSeed{"Administrator", "Full access to all operations"},
        {"PlatformEngineer", "Author and manage YAML instruction definitions, sets, and schemas"},
        {"Operator", "Execute and manage instructions, schedules, and tags"},
        {"ApiTokenManager", "Create, revoke, and manage API tokens for programmatic access"},
        {"ITServiceOwner", "Admin control over devices tagged with the same IT Service"},
        {"Viewer", "Read-only access to operational data"},
        {"Reviewer", "Read audit evidence and attest/flag access-review grants (SOC 2 CC6.2)"}};
    for (const auto& r : roles)
        exec("INSERT INTO rbac_store.roles (name, description, is_system, created_at) "
             "VALUES ($1, $2, TRUE, $3::bigint) ON CONFLICT (name) DO NOTHING",
             {std::string(r.name), std::string(r.desc), std::to_string(now)});

    const auto grant = [&](std::string_view role, std::string_view type, std::string_view op) {
        exec("INSERT INTO rbac_store.role_permissions (role_name, securable_type, operation, "
             "effect) VALUES ($1, $2, $3, 'allow') ON CONFLICT DO NOTHING",
             {std::string(role), std::string(type), std::string(op)});
    };

    // Administrator: CRUD on everything + targeted Push + Attest.
    for (auto t : types)
        for (auto o : crud_ops)
            grant("Administrator", t, o);
    grant("Administrator", "GuaranteedState", "Push");
    grant("Administrator", "AccessReview", "Attest");

    // PlatformEngineer.
    for (std::string_view t : {"InstructionDefinition", "InstructionSet"})
        for (std::string_view o : {"Read", "Write", "Execute", "Delete"})
            grant("PlatformEngineer", t, o);
    for (std::string_view t : {"Execution", "Schedule", "Approval", "Tag", "AuditLog", "Response",
                               "SoftwareLicensing", "Inventory"})
        grant("PlatformEngineer", t, "Read");
    for (std::string_view o : {"Read", "Write", "Delete"})
        grant("PlatformEngineer", "Policy", o);
    for (std::string_view o : {"Read", "Write", "Delete", "Push"})
        grant("PlatformEngineer", "GuaranteedState", o);

    // Operator.
    for (std::string_view t : {"InstructionDefinition", "InstructionSet", "Execution", "Schedule",
                               "Tag"}) {
        for (std::string_view o : {"Read", "Write", "Execute", "Delete"})
            grant("Operator", t, o);
    }
    grant("Operator", "Approval", "Read");
    grant("Operator", "Approval", "Approve");
    grant("Operator", "AuditLog", "Read");
    grant("Operator", "Response", "Read");
    grant("Operator", "Policy", "Read");
    grant("Operator", "Policy", "Execute");
    grant("Operator", "SoftwareDeployment", "Read");
    grant("Operator", "SoftwareDeployment", "Execute");
    grant("Operator", "DeviceToken", "Read");
    grant("Operator", "License", "Read");
    grant("Operator", "Inventory", "Read");
    grant("Operator", "SoftwareLicensing", "Read");
    grant("Operator", "SoftwareLicensing", "Write");
    grant("Operator", "FileRetrieval", "Read");
    grant("Operator", "FileRetrieval", "Write");
    grant("Operator", "GuaranteedState", "Read");
    grant("Operator", "GuaranteedState", "Push");

    // ApiTokenManager.
    for (std::string_view o : {"Read", "Write", "Delete"})
        grant("ApiTokenManager", "ApiToken", o);

    // ITServiceOwner.
    for (std::string_view t : {"Infrastructure", "InstructionDefinition", "InstructionSet",
                               "Execution", "Schedule", "Approval", "Tag", "AuditLog", "Response",
                               "ManagementGroup", "Policy", "DeviceToken", "SoftwareDeployment",
                               "License", "FileRetrieval", "GuaranteedState", "Inventory",
                               "SoftwareLicensing"}) {
        for (auto o : crud_ops)
            grant("ITServiceOwner", t, o);
    }
    grant("ITServiceOwner", "GuaranteedState", "Push");

    // Viewer: read on all except Infrastructure.
    for (std::string_view t : {"UserManagement", "InstructionDefinition", "InstructionSet",
                               "Execution", "Schedule", "Approval", "Tag", "AuditLog", "Response",
                               "ManagementGroup", "ApiToken", "Security", "Policy", "DeviceToken",
                               "SoftwareDeployment", "License", "FileRetrieval", "GuaranteedState",
                               "Inventory", "SoftwareLicensing"})
        grant("Viewer", t, "Read");

    // Reviewer.
    grant("Reviewer", "AccessReview", "Read");
    grant("Reviewer", "AccessReview", "Attest");
}

void RbacStore::load_enabled_flag() {
    if (!open_)
        return;
    auto lease = pool_.acquire();
    if (!lease)
        return;
    pg::PgResult r = pg::exec_params(
        lease.get(), "SELECT value FROM rbac_store.rbac_meta WHERE key='rbac_enabled'",
        std::vector<std::string>{});
    if (r.status() == PGRES_TUPLES_OK && PQntuples(r.get()) == 1)
        rbac_enabled_.store(text_col(r.get(), 0, 0) == "true", std::memory_order_relaxed);
    // Anchor the generation cache from the durable counter so the first read
    // does not immediately re-query.
    pg::PgResult g = pg::exec_params(
        lease.get(), "SELECT value FROM rbac_store.rbac_meta WHERE key='write_generation'",
        std::vector<std::string>{});
    std::lock_guard lock(cache_mtx_);
    if (g.status() == PGRES_TUPLES_OK && PQntuples(g.get()) == 1) {
        cached_generation_ = to_u64(PQgetvalue(g.get(), 0, 0));
        generation_valid_ = true;
    }
    last_generation_refresh_ms_ = now_ms();
}

// ── Durable generation token (ADR-0041 cross-replica coherence) ──────────────

void RbacStore::maybe_refresh_generation() const {
    if (!open_)
        return;
    {
        std::lock_guard lock(cache_mtx_);
        if ((now_ms() - last_generation_refresh_ms_) < kRbacGenerationRefreshMs)
            return;
    }
    // Read the durable generation + enabled flag WITHOUT holding cache_mtx_.
    std::optional<std::uint64_t> durable_gen;
    std::optional<bool> durable_enabled;
    if (auto lease = pool_.try_acquire_for(kReadTimeout)) {
        pg::PgResult r = pg::exec_params(
            lease.get(),
            "SELECT key, value FROM rbac_store.rbac_meta WHERE key IN "
            "('write_generation','rbac_enabled')",
            std::vector<std::string>{});
        if (r.status() == PGRES_TUPLES_OK) {
            for (int i = 0; i < PQntuples(r.get()); ++i) {
                const std::string k = text_col(r.get(), i, 0);
                if (k == "write_generation")
                    durable_gen = to_u64(PQgetvalue(r.get(), i, 1));
                else if (k == "rbac_enabled")
                    durable_enabled = (text_col(r.get(), i, 1) == "true");
            }
        }
    }
    std::lock_guard lock(cache_mtx_);
    last_generation_refresh_ms_ = now_ms();
    if (!durable_gen) {
        // Fail toward "assume changed": drop the cache and stop trusting it. Do
        // NOT touch rbac_enabled_ — flipping it to disabled would be fail-open.
        perm_cache_.clear();
        generation_valid_ = false;
        return;
    }
    if (durable_enabled)
        rbac_enabled_.store(*durable_enabled, std::memory_order_relaxed);
    if (!generation_valid_ || *durable_gen != cached_generation_) {
        perm_cache_.clear();
        cached_generation_ = *durable_gen;
        generation_valid_ = true;
    }
}

void RbacStore::apply_local_generation(std::uint64_t new_gen) const {
    std::lock_guard lock(cache_mtx_);
    perm_cache_.clear();
    cached_generation_ = new_gen;
    generation_valid_ = true;
    last_generation_refresh_ms_ = now_ms();
}

namespace {
// Bump `write_generation` inside an already-open txn on `c`; return the new
// value, or nullopt on any error. The mutation and this bump commit atomically
// (ADR-0041: the durable counter advances in the SAME txn as the write).
std::optional<std::uint64_t> bump_generation_in_txn(PGconn* c) {
    pg::PgResult r = pg::exec_params(
        c,
        "INSERT INTO rbac_store.rbac_meta (key, value) VALUES ('write_generation','1') "
        "ON CONFLICT (key) DO UPDATE SET value = "
        "(rbac_store.rbac_meta.value::bigint + 1)::text RETURNING value::bigint",
        std::vector<std::string>{});
    if (r.status() != PGRES_TUPLES_OK || PQntuples(r.get()) != 1)
        return std::nullopt;
    return to_u64(PQgetvalue(r.get(), 0, 0));
}
} // namespace

// ── Global toggle ────────────────────────────────────────────────────────────

bool RbacStore::is_rbac_enabled() const {
    maybe_refresh_generation();
    return rbac_enabled_.load(std::memory_order_relaxed);
}

void RbacStore::set_rbac_enabled(bool enabled) {
    if (!open_)
        return;
    std::optional<std::uint64_t> new_gen;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        pg::PgResult r = pg::exec_params(
            c,
            "INSERT INTO rbac_store.rbac_meta (key, value) VALUES ('rbac_enabled', $1) "
            "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
            std::vector<std::string>{enabled ? "true" : "false"});
        if (r.status() != PGRES_COMMAND_OK) {
            spdlog::error("RbacStore::set_rbac_enabled: write failed: {}", PQerrorMessage(c));
            return false;
        }
        new_gen = bump_generation_in_txn(c);
        return new_gen.has_value();
    });
    if (!ok) {
        spdlog::error("RbacStore::set_rbac_enabled: transaction failed; flag unchanged");
        return;
    }
    rbac_enabled_.store(enabled, std::memory_order_relaxed);
    apply_local_generation(*new_gen);
}

bool rbac_enforcement_in_effect(const RbacStore* store) noexcept {
    // Permit the full-fleet fallback (return false) ONLY for a store that is
    // loaded AND explicitly disabled. Null / load-failed (!is_open()) fail
    // CLOSED — see the header for the #1498 rationale.
    return !(store && store->is_open() && !store->is_rbac_enabled());
}

// ── Roles CRUD ───────────────────────────────────────────────────────────────

std::vector<RbacRole> RbacStore::list_roles() const {
    std::vector<RbacRole> result;
    if (!open_)
        return result;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return result;
    pg::PgResult r = pg::exec_params(
        lease.get(),
        "SELECT name, description, is_system, created_at FROM rbac_store.roles "
        "ORDER BY is_system DESC, name",
        std::vector<std::string>{});
    if (r.status() != PGRES_TUPLES_OK)
        return result;
    for (int i = 0; i < PQntuples(r.get()); ++i) {
        RbacRole role;
        role.name = text_col(r.get(), i, 0);
        role.description = text_col(r.get(), i, 1);
        role.is_system = to_bool(PQgetvalue(r.get(), i, 2));
        role.created_at = to_i64(PQgetvalue(r.get(), i, 3));
        result.push_back(std::move(role));
    }
    return result;
}

std::optional<RbacRole> RbacStore::get_role(const std::string& name) const {
    if (!open_)
        return std::nullopt;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::nullopt;
    pg::PgResult r = pg::exec_params(
        lease.get(),
        "SELECT name, description, is_system, created_at FROM rbac_store.roles WHERE name = $1",
        std::vector<std::string>{name});
    if (r.status() != PGRES_TUPLES_OK || PQntuples(r.get()) != 1)
        return std::nullopt;
    RbacRole role;
    role.name = text_col(r.get(), 0, 0);
    role.description = text_col(r.get(), 0, 1);
    role.is_system = to_bool(PQgetvalue(r.get(), 0, 2));
    role.created_at = to_i64(PQgetvalue(r.get(), 0, 3));
    return role;
}

std::expected<void, std::string> RbacStore::create_role(const RbacRole& role) {
    if (!open_)
        return std::unexpected("database not open");
    if (role.name.empty())
        return std::unexpected("role name cannot be empty");
    const std::int64_t now = now_secs();
    std::optional<std::uint64_t> new_gen;
    std::string err;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        pg::PgResult r = pg::exec_params(
            c,
            "INSERT INTO rbac_store.roles (name, description, is_system, created_at) "
            "VALUES ($1, $2, FALSE, $3::bigint)",
            std::vector<std::string>{sanitize_pg_text(role.name),
                                     sanitize_pg_text(role.description), std::to_string(now)});
        if (r.status() != PGRES_COMMAND_OK) {
            err = std::string("role already exists or DB error: ") + PQerrorMessage(c);
            return false;
        }
        new_gen = bump_generation_in_txn(c);
        return new_gen.has_value();
    });
    if (!ok)
        return std::unexpected(err.empty() ? "role create failed" : err);
    apply_local_generation(*new_gen);
    return {};
}

std::expected<void, std::string> RbacStore::update_role(const std::string& name,
                                                        const std::string& description) {
    if (!open_)
        return std::unexpected("database not open");
    std::optional<std::uint64_t> new_gen;
    bool not_found = false;
    std::string err;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        pg::PgResult r = pg::exec_params(
            c, "UPDATE rbac_store.roles SET description = $1 WHERE name = $2 RETURNING name",
            std::vector<std::string>{sanitize_pg_text(description), name});
        if (r.status() != PGRES_TUPLES_OK) {
            err = PQerrorMessage(c);
            return false;
        }
        if (PQntuples(r.get()) == 0) {
            not_found = true;
            return false; // roll back — nothing changed, no generation bump
        }
        new_gen = bump_generation_in_txn(c);
        return new_gen.has_value();
    });
    if (not_found)
        return std::unexpected("role not found");
    if (!ok)
        return std::unexpected(err.empty() ? "role update failed" : err);
    apply_local_generation(*new_gen);
    return {};
}

std::expected<void, std::string> RbacStore::delete_role(const std::string& name) {
    if (!open_)
        return std::unexpected("database not open");
    std::optional<std::uint64_t> new_gen;
    bool not_found = false;
    bool is_system = false;
    std::string err;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        pg::PgResult chk = pg::exec_params(
            c, "SELECT is_system FROM rbac_store.roles WHERE name = $1",
            std::vector<std::string>{name});
        if (chk.status() != PGRES_TUPLES_OK) {
            err = PQerrorMessage(c);
            return false;
        }
        if (PQntuples(chk.get()) == 0) {
            not_found = true;
            return false;
        }
        if (to_bool(PQgetvalue(chk.get(), 0, 0))) {
            is_system = true;
            return false;
        }
        pg::PgResult del = pg::exec_params(
            c, "DELETE FROM rbac_store.roles WHERE name = $1 AND is_system = FALSE",
            std::vector<std::string>{name});
        if (del.status() != PGRES_COMMAND_OK) {
            err = PQerrorMessage(c);
            return false;
        }
        new_gen = bump_generation_in_txn(c);
        return new_gen.has_value();
    });
    if (not_found)
        return std::unexpected("role not found");
    if (is_system)
        return std::unexpected("cannot delete system role");
    if (!ok)
        return std::unexpected(err.empty() ? "role delete failed" : err);
    apply_local_generation(*new_gen);
    return {};
}

// ── Permissions CRUD ─────────────────────────────────────────────────────────

namespace {
Permission read_perm(PGresult* r, int i) {
    Permission p;
    p.role_name = text_col(r, i, 0);
    p.securable_type = text_col(r, i, 1);
    p.operation = text_col(r, i, 2);
    p.effect = text_col(r, i, 3);
    return p;
}
} // namespace

std::vector<Permission> RbacStore::get_role_permissions(const std::string& role_name) const {
    std::vector<Permission> result;
    if (!open_)
        return result;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return result;
    pg::PgResult r = pg::exec_params(
        lease.get(),
        "SELECT role_name, securable_type, operation, effect FROM rbac_store.role_permissions "
        "WHERE role_name = $1 ORDER BY securable_type, operation",
        std::vector<std::string>{role_name});
    if (r.status() != PGRES_TUPLES_OK)
        return result;
    for (int i = 0; i < PQntuples(r.get()); ++i)
        result.push_back(read_perm(r.get(), i));
    return result;
}

std::expected<std::vector<Permission>, std::string>
RbacStore::get_role_permissions_checked(const std::string& role_name) const {
    if (!open_)
        return std::unexpected("rbac store not open");
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected("pool acquire timeout");
    pg::PgResult r = pg::exec_params(
        lease.get(),
        "SELECT role_name, securable_type, operation, effect FROM rbac_store.role_permissions "
        "WHERE role_name = $1 ORDER BY securable_type, operation",
        std::vector<std::string>{role_name});
    if (r.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string("query failed: ") + PQerrorMessage(lease.get()));
    std::vector<Permission> result;
    for (int i = 0; i < PQntuples(r.get()); ++i)
        result.push_back(read_perm(r.get(), i));
    return result;
}

std::expected<std::vector<Permission>, std::string>
RbacStore::list_all_role_permissions_checked() const {
    if (!open_)
        return std::unexpected("rbac store not open");
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected("pool acquire timeout");
    pg::PgResult r = pg::exec_params(
        lease.get(),
        "SELECT role_name, securable_type, operation, effect FROM rbac_store.role_permissions "
        "ORDER BY role_name, securable_type, operation",
        std::vector<std::string>{});
    if (r.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string("query failed: ") + PQerrorMessage(lease.get()));
    std::vector<Permission> result;
    for (int i = 0; i < PQntuples(r.get()); ++i)
        result.push_back(read_perm(r.get(), i));
    return result;
}

std::expected<void, std::string> RbacStore::set_permission(const Permission& perm) {
    if (perm.effect != "allow" && perm.effect != "deny")
        return std::unexpected("effect must be 'allow' or 'deny'");
    if (!open_)
        return std::unexpected("database not open");
    std::optional<std::uint64_t> new_gen;
    std::string err;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        pg::PgResult r = pg::exec_params(
            c,
            "INSERT INTO rbac_store.role_permissions (role_name, securable_type, operation, effect) "
            "VALUES ($1, $2, $3, $4) ON CONFLICT (role_name, securable_type, operation) "
            "DO UPDATE SET effect = EXCLUDED.effect",
            std::vector<std::string>{sanitize_pg_text(perm.role_name),
                                     sanitize_pg_text(perm.securable_type),
                                     sanitize_pg_text(perm.operation), perm.effect});
        if (r.status() != PGRES_COMMAND_OK) {
            err = PQerrorMessage(c);
            return false;
        }
        new_gen = bump_generation_in_txn(c);
        return new_gen.has_value();
    });
    if (!ok)
        return std::unexpected(err.empty() ? "set_permission failed" : err);
    apply_local_generation(*new_gen);
    return {};
}

std::expected<void, std::string> RbacStore::remove_permission(const std::string& role_name,
                                                              const std::string& securable_type,
                                                              const std::string& operation) {
    if (!open_)
        return std::unexpected("database not open");
    std::optional<std::uint64_t> new_gen;
    std::string err;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        pg::PgResult r = pg::exec_params(
            c,
            "DELETE FROM rbac_store.role_permissions WHERE role_name = $1 AND securable_type = $2 "
            "AND operation = $3",
            std::vector<std::string>{role_name, securable_type, operation});
        if (r.status() != PGRES_COMMAND_OK) {
            err = PQerrorMessage(c);
            return false;
        }
        new_gen = bump_generation_in_txn(c);
        return new_gen.has_value();
    });
    if (!ok)
        return std::unexpected(err.empty() ? "remove_permission failed" : err);
    apply_local_generation(*new_gen);
    return {};
}

// ── Principal-role assignments ───────────────────────────────────────────────

namespace {
PrincipalRole read_pr(PGresult* r, int i) {
    PrincipalRole pr;
    pr.principal_type = text_col(r, i, 0);
    pr.principal_id = text_col(r, i, 1);
    pr.role_name = text_col(r, i, 2);
    return pr;
}
} // namespace

std::vector<PrincipalRole> RbacStore::get_principal_roles(const std::string& principal_type,
                                                          const std::string& principal_id) const {
    std::vector<PrincipalRole> result;
    if (!open_)
        return result;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return result;
    pg::PgResult r = pg::exec_params(
        lease.get(),
        "SELECT principal_type, principal_id, role_name FROM rbac_store.principal_roles "
        "WHERE principal_type = $1 AND principal_id = $2 ORDER BY role_name",
        std::vector<std::string>{principal_type, principal_id});
    if (r.status() != PGRES_TUPLES_OK)
        return result;
    for (int i = 0; i < PQntuples(r.get()); ++i)
        result.push_back(read_pr(r.get(), i));
    return result;
}

std::expected<std::vector<PrincipalRole>, std::string>
RbacStore::get_principal_roles_checked(const std::string& principal_type,
                                       const std::string& principal_id) const {
    if (!open_)
        return std::unexpected("rbac store not open");
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected("pool acquire timeout");
    pg::PgResult r = pg::exec_params(
        lease.get(),
        "SELECT principal_type, principal_id, role_name FROM rbac_store.principal_roles "
        "WHERE principal_type = $1 AND principal_id = $2 ORDER BY role_name",
        std::vector<std::string>{principal_type, principal_id});
    if (r.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string("query failed: ") + PQerrorMessage(lease.get()));
    std::vector<PrincipalRole> result;
    for (int i = 0; i < PQntuples(r.get()); ++i)
        result.push_back(read_pr(r.get(), i));
    return result;
}

std::expected<std::vector<PrincipalRole>, std::string>
RbacStore::list_all_principal_roles_checked() const {
    if (!open_)
        return std::unexpected("rbac store not open");
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected("pool acquire timeout");
    pg::PgResult r = pg::exec_params(
        lease.get(),
        "SELECT principal_type, principal_id, role_name FROM rbac_store.principal_roles "
        "ORDER BY principal_type, principal_id, role_name",
        std::vector<std::string>{});
    if (r.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string("query failed: ") + PQerrorMessage(lease.get()));
    std::vector<PrincipalRole> result;
    for (int i = 0; i < PQntuples(r.get()); ++i)
        result.push_back(read_pr(r.get(), i));
    return result;
}

std::vector<PrincipalRole> RbacStore::get_role_members(const std::string& role_name) const {
    std::vector<PrincipalRole> result;
    if (!open_)
        return result;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return result;
    pg::PgResult r = pg::exec_params(
        lease.get(),
        "SELECT principal_type, principal_id, role_name FROM rbac_store.principal_roles "
        "WHERE role_name = $1 ORDER BY principal_type, principal_id",
        std::vector<std::string>{role_name});
    if (r.status() != PGRES_TUPLES_OK)
        return result;
    for (int i = 0; i < PQntuples(r.get()); ++i)
        result.push_back(read_pr(r.get(), i));
    return result;
}

std::expected<void, std::string> RbacStore::validate_assignment(const std::string& principal_type,
                                                                const std::string& principal_id,
                                                                const std::string& role_name) {
    // F2: an `engine:`-prefixed principal_id must ONLY be assigned under
    // principal_type=="engine" (else a shadow ('user','engine:x',role) row
    // would attribute an engine identity's perms to a user lookup).
    if (principal_type != "engine" && principal_id.starts_with(kEnginePrefix))
        return std::unexpected(
            "principal_id in the reserved 'engine:' namespace may only be assigned under "
            "principal_type=\"engine\"");

    if (principal_type != "user" && principal_type != "group" && principal_type != "engine")
        return std::unexpected("unrecognized principal_type '" + principal_type + "'");

    if (principal_type != "engine")
        return {};

    if (!principal_id.starts_with(kEnginePrefix) || principal_id.size() == kEnginePrefix.size())
        return std::unexpected(
            "engine principal_id must be in the reserved 'engine:<slug>' namespace with a "
            "non-empty slug");

    for (auto disallowed : kEngineDisallowedRoles) {
        if (role_name == disallowed)
            return std::unexpected("engine principals cannot be granted the admin/full-access "
                                   "role '" +
                                   role_name + "' — no admin, ever (design §4.2)");
    }
    return {};
}

std::expected<void, std::string> RbacStore::assign_role(const PrincipalRole& pr) {
    if (!open_)
        return std::unexpected("database not open");
    if (auto v = validate_assignment(pr.principal_type, pr.principal_id, pr.role_name); !v)
        return std::unexpected(v.error());

    std::optional<std::uint64_t> new_gen;
    bool builtin_reject = false;
    std::string err;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        // F1: for an engine principal, reject ANY built-in (is_system) role via
        // its own `is_system` flag — generalizes the static "no admin, ever"
        // bar to "no built-in role, ever" for the fleet-wide path.
        if (pr.principal_type == "engine") {
            pg::PgResult chk = pg::exec_params(
                c, "SELECT is_system FROM rbac_store.roles WHERE name = $1",
                std::vector<std::string>{pr.role_name});
            if (chk.status() != PGRES_TUPLES_OK) {
                err = PQerrorMessage(c);
                return false;
            }
            if (PQntuples(chk.get()) == 1 && to_bool(PQgetvalue(chk.get(), 0, 0))) {
                builtin_reject = true;
                return false;
            }
        }
        pg::PgResult r = pg::exec_params(
            c,
            "INSERT INTO rbac_store.principal_roles (principal_type, principal_id, role_name) "
            "VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
            std::vector<std::string>{sanitize_pg_text(pr.principal_type),
                                     sanitize_pg_text(pr.principal_id),
                                     sanitize_pg_text(pr.role_name)});
        if (r.status() != PGRES_COMMAND_OK) {
            err = PQerrorMessage(c);
            return false;
        }
        new_gen = bump_generation_in_txn(c);
        return new_gen.has_value();
    });
    if (builtin_reject)
        return std::unexpected("engine principals cannot be granted a built-in system role '" +
                               pr.role_name + "' — no built-in role, ever (design §4.2)");
    if (!ok)
        return std::unexpected(err.empty() ? "assign_role failed" : err);
    apply_local_generation(*new_gen);
    return {};
}

std::expected<void, std::string> RbacStore::unassign_role(const std::string& principal_type,
                                                          const std::string& principal_id,
                                                          const std::string& role_name) {
    if (!open_)
        return std::unexpected("database not open");
    std::optional<std::uint64_t> new_gen;
    std::string err;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        pg::PgResult r = pg::exec_params(
            c,
            "DELETE FROM rbac_store.principal_roles WHERE principal_type = $1 AND principal_id = $2 "
            "AND role_name = $3",
            std::vector<std::string>{principal_type, principal_id, role_name});
        if (r.status() != PGRES_COMMAND_OK) {
            err = PQerrorMessage(c);
            return false;
        }
        new_gen = bump_generation_in_txn(c);
        return new_gen.has_value();
    });
    if (!ok)
        return std::unexpected(err.empty() ? "unassign_role failed" : err);
    apply_local_generation(*new_gen);
    return {};
}

// ── Groups CRUD ──────────────────────────────────────────────────────────────

std::vector<RbacGroup> RbacStore::list_groups() const {
    std::vector<RbacGroup> result;
    if (!open_)
        return result;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return result;
    pg::PgResult r = pg::exec_params(
        lease.get(),
        "SELECT name, description, source, external_id, created_at FROM rbac_store.groups "
        "ORDER BY name",
        std::vector<std::string>{});
    if (r.status() != PGRES_TUPLES_OK)
        return result;
    for (int i = 0; i < PQntuples(r.get()); ++i) {
        RbacGroup g;
        g.name = text_col(r.get(), i, 0);
        g.description = text_col(r.get(), i, 1);
        g.source = text_col(r.get(), i, 2);
        g.external_id = text_col(r.get(), i, 3); // NULL → ""
        g.created_at = to_i64(PQgetvalue(r.get(), i, 4));
        result.push_back(std::move(g));
    }
    return result;
}

std::expected<std::vector<RbacGroup>, std::string> RbacStore::list_groups_checked() const {
    if (!open_)
        return std::unexpected("rbac store not open");
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected("pool acquire timeout");
    pg::PgResult r = pg::exec_params(
        lease.get(),
        "SELECT name, description, source, external_id, created_at FROM rbac_store.groups "
        "ORDER BY name",
        std::vector<std::string>{});
    if (r.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string("query failed: ") + PQerrorMessage(lease.get()));
    std::vector<RbacGroup> result;
    for (int i = 0; i < PQntuples(r.get()); ++i) {
        RbacGroup g;
        g.name = text_col(r.get(), i, 0);
        g.description = text_col(r.get(), i, 1);
        g.source = text_col(r.get(), i, 2);
        g.external_id = text_col(r.get(), i, 3);
        g.created_at = to_i64(PQgetvalue(r.get(), i, 4));
        result.push_back(std::move(g));
    }
    return result;
}

std::optional<std::vector<std::string>>
RbacStore::find_local_groups_with_prefix(const std::string& prefix) const {
    // A closed/unopened store, a pool timeout, or a query error is a scan
    // FAILURE, not "nothing to match" — signal it distinctly (nullopt) so the T8
    // preflight fails closed instead of trusting an engaged-but-empty result.
    if (!open_)
        return std::nullopt;
    // `prefix` is code-controlled — fail closed (empty result) if it ever
    // carries a LIKE metacharacter.
    if (prefix.empty() || prefix.find_first_of("%_\\") != std::string::npos)
        return std::vector<std::string>{};
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::nullopt;
    pg::PgResult r = pg::exec_params(
        lease.get(),
        "SELECT name FROM rbac_store.groups WHERE source = 'local' AND name LIKE $1",
        std::vector<std::string>{prefix + "%"});
    if (r.status() != PGRES_TUPLES_OK) {
        spdlog::error("find_local_groups_with_prefix: scan of prefix '{}' failed: {}", prefix,
                      PQerrorMessage(lease.get()));
        return std::nullopt;
    }
    std::vector<std::string> result;
    for (int i = 0; i < PQntuples(r.get()); ++i)
        result.push_back(text_col(r.get(), i, 0));
    return result;
}

std::expected<void, std::string> RbacStore::create_group(const RbacGroup& group) {
    if (!open_)
        return std::unexpected("database not open");
    if (group.name.empty())
        return std::unexpected("group name cannot be empty");
    if (group.source == "local" && has_reserved_idp_prefix(group.name))
        return std::unexpected(
            "group name uses a reserved identity-provider or engine-principal namespace prefix "
            "(local:/entra:/saml:/ad:/engine:)");
    const std::int64_t now = now_secs();
    std::optional<std::uint64_t> new_gen;
    std::string err;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        pg::PgResult r = pg::exec_params(
            c,
            "INSERT INTO rbac_store.groups (name, description, source, external_id, created_at) "
            "VALUES ($1, $2, $3, $4, $5::bigint)",
            std::vector<std::string>{sanitize_pg_text(group.name),
                                     sanitize_pg_text(group.description),
                                     sanitize_pg_text(group.source),
                                     sanitize_pg_text(group.external_id), std::to_string(now)});
        if (r.status() != PGRES_COMMAND_OK) {
            err = std::string("group already exists or DB error: ") + PQerrorMessage(c);
            return false;
        }
        new_gen = bump_generation_in_txn(c);
        return new_gen.has_value();
    });
    if (!ok)
        return std::unexpected(err.empty() ? "create_group failed" : err);
    apply_local_generation(*new_gen);
    return {};
}

std::expected<void, std::string> RbacStore::delete_group(const std::string& name) {
    if (!open_)
        return std::unexpected("database not open");
    std::optional<std::uint64_t> new_gen;
    std::string err;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        pg::PgResult r =
            pg::exec_params(c, "DELETE FROM rbac_store.groups WHERE name = $1",
                            std::vector<std::string>{name});
        if (r.status() != PGRES_COMMAND_OK) {
            err = PQerrorMessage(c);
            return false;
        }
        new_gen = bump_generation_in_txn(c);
        return new_gen.has_value();
    });
    if (!ok)
        return std::unexpected(err.empty() ? "delete_group failed" : err);
    apply_local_generation(*new_gen);
    return {};
}

std::vector<std::string> RbacStore::get_group_members(const std::string& group_name) const {
    std::vector<std::string> result;
    if (!open_)
        return result;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return result;
    pg::PgResult r = pg::exec_params(
        lease.get(),
        "SELECT username FROM rbac_store.group_members WHERE group_name = $1 ORDER BY username",
        std::vector<std::string>{group_name});
    if (r.status() != PGRES_TUPLES_OK)
        return result;
    for (int i = 0; i < PQntuples(r.get()); ++i)
        result.push_back(text_col(r.get(), i, 0));
    return result;
}

std::expected<void, std::string> RbacStore::add_group_member(const std::string& group_name,
                                                             const std::string& username) {
    if (!open_)
        return std::unexpected("database not open");
    // G5: reject an `engine:`-prefixed username at this write surface too
    // (the group-resolution arm would otherwise hand it the group's roles).
    if (username.starts_with(kEnginePrefix))
        return std::unexpected(
            "principal_id in the reserved 'engine:' namespace cannot be added as a group member");
    std::optional<std::uint64_t> new_gen;
    std::string err;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        pg::PgResult r = pg::exec_params(
            c,
            "INSERT INTO rbac_store.group_members (group_name, username) VALUES ($1, $2) "
            "ON CONFLICT DO NOTHING",
            std::vector<std::string>{sanitize_pg_text(group_name), sanitize_pg_text(username)});
        if (r.status() != PGRES_COMMAND_OK) {
            err = PQerrorMessage(c);
            return false;
        }
        new_gen = bump_generation_in_txn(c);
        return new_gen.has_value();
    });
    if (!ok)
        return std::unexpected(err.empty() ? "add_group_member failed" : err);
    apply_local_generation(*new_gen);
    return {};
}

std::expected<void, std::string> RbacStore::remove_group_member(const std::string& group_name,
                                                                const std::string& username) {
    if (!open_)
        return std::unexpected("database not open");
    std::optional<std::uint64_t> new_gen;
    std::string err;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        pg::PgResult r = pg::exec_params(
            c, "DELETE FROM rbac_store.group_members WHERE group_name = $1 AND username = $2",
            std::vector<std::string>{group_name, username});
        if (r.status() != PGRES_COMMAND_OK) {
            err = PQerrorMessage(c);
            return false;
        }
        new_gen = bump_generation_in_txn(c);
        return new_gen.has_value();
    });
    if (!ok)
        return std::unexpected(err.empty() ? "remove_group_member failed" : err);
    apply_local_generation(*new_gen);
    return {};
}

std::expected<ReconcileResult, std::string> RbacStore::reconcile_idp_memberships(
    const std::string& username, const std::string& source,
    const std::vector<std::pair<std::string, std::string>>& asserted) {
    if (asserted.size() > kMaxIdpGroupsPerLogin)
        return std::unexpected("group_count_exceeded");

    bool recognized_source = false;
    for (auto s : kRecognizedIdpSources) {
        if (source == s) {
            recognized_source = true;
            break;
        }
    }
    if (!recognized_source)
        return std::unexpected("invalid_source");

    // UP-9: drop asserted entries whose external_id can't produce a sane group
    // name — blank/whitespace-only or implausibly long.
    std::vector<std::pair<std::string, std::string>> valid;
    valid.reserve(asserted.size());
    for (const auto& a : asserted) {
        if (is_blank(a.first)) {
            spdlog::warn("reconcile_idp_memberships: skipping asserted entry with blank "
                         "external_id (user='{}', source='{}')",
                         username, source);
            continue;
        }
        if (a.first.size() > kMaxExternalIdLength) {
            spdlog::warn("reconcile_idp_memberships: skipping asserted external_id exceeding {} "
                         "bytes (user='{}', source='{}')",
                         kMaxExternalIdLength, username, source);
            continue;
        }
        valid.push_back(a);
    }

    if (!open_)
        return std::unexpected("database not open");

    const std::int64_t now = now_secs();

    // Namespaced names computed once: reused for the upsert loop AND the
    // stale-membership DELETE's NOT IN list.
    std::vector<std::string> namespaced;
    namespaced.reserve(valid.size());
    for (const auto& a : valid)
        namespaced.push_back(namespaced_group_name(source, a.first));

    ReconcileResult result;
    std::optional<std::uint64_t> new_gen;
    std::string err;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        for (size_t i = 0; i < valid.size(); ++i) {
            const auto& external_id = valid[i].first;
            const auto& display = valid[i].second;
            const auto& name = namespaced[i];
            const auto description = std::string("IdP-provisioned group (") + source + "): " +
                                     (display.empty() ? external_id : display);

            pg::PgResult ins_group = pg::exec_params(
                c,
                "INSERT INTO rbac_store.groups (name, description, source, external_id, created_at) "
                "VALUES ($1, $2, $3, $4, $5::bigint) ON CONFLICT (name) DO NOTHING",
                std::vector<std::string>{sanitize_pg_text(name), sanitize_pg_text(description),
                                         sanitize_pg_text(source), sanitize_pg_text(external_id),
                                         std::to_string(now)});
            if (ins_group.status() != PGRES_COMMAND_OK) {
                err = std::string("group upsert failed: ") + PQerrorMessage(c);
                return false;
            }

            // sec-L1: verify the (possibly pre-existing) row's source before
            // joining a membership — never leak a different-source group's roles.
            pg::PgResult chk = pg::exec_params(
                c, "SELECT source FROM rbac_store.groups WHERE name = $1",
                std::vector<std::string>{sanitize_pg_text(name)});
            if (chk.status() != PGRES_TUPLES_OK) {
                err = std::string("group source check failed: ") + PQerrorMessage(c);
                return false;
            }
            bool source_mismatch = false;
            if (PQntuples(chk.get()) == 1) {
                const std::string existing = text_col(chk.get(), 0, 0);
                if (source != existing)
                    source_mismatch = true;
            }
            if (source_mismatch) {
                spdlog::warn("reconcile_idp_memberships: NOT joining '{}' to pre-existing group "
                             "'{}' — row source differs from reconcile source '{}' "
                             "(confused-deputy guard)",
                             username, name, source);
                continue;
            }

            pg::PgResult ins_member = pg::exec_params(
                c,
                "INSERT INTO rbac_store.group_members (group_name, username) VALUES ($1, $2) "
                "ON CONFLICT DO NOTHING RETURNING 1",
                std::vector<std::string>{sanitize_pg_text(name), sanitize_pg_text(username)});
            if (ins_member.status() != PGRES_TUPLES_OK) {
                err = std::string("membership upsert failed: ") + PQerrorMessage(c);
                return false;
            }
            if (PQntuples(ins_member.get()) == 1)
                ++result.added;
        }

        // Remove stale IdP memberships: any group_members row for this user
        // whose group is owned by THIS source and was NOT re-asserted.
        std::string sql = "DELETE FROM rbac_store.group_members WHERE username = $1 "
                          "AND group_name IN (SELECT name FROM rbac_store.groups WHERE source = $2)";
        std::vector<std::string> params{username, source};
        if (!namespaced.empty()) {
            sql += " AND group_name NOT IN (";
            for (size_t i = 0; i < namespaced.size(); ++i) {
                sql += (i == 0 ? "$" : ",$") + std::to_string(3 + i);
                params.push_back(sanitize_pg_text(namespaced[i]));
            }
            sql += ")";
        }
        sql += " RETURNING group_name";
        pg::PgResult del = pg::exec_params(c, sql.c_str(), params);
        if (del.status() != PGRES_TUPLES_OK) {
            err = std::string("stale-membership delete failed: ") + PQerrorMessage(c);
            return false;
        }
        result.removed = static_cast<size_t>(PQntuples(del.get()));

        new_gen = bump_generation_in_txn(c);
        return new_gen.has_value();
    });
    if (!ok)
        return std::unexpected(err.empty() ? "reconcile transaction failed" : err);
    apply_local_generation(*new_gen);
    return result;
}

// ── Authorization check ──────────────────────────────────────────────────────

std::vector<std::string> RbacStore::collect_roles(void* conn, const std::string& username) const {
    std::vector<std::string> roles;
    auto* c = static_cast<PGconn*>(conn);
    // Three-way UNION: direct user grant, group-membership grant, and (§4.1)
    // direct engine-principal grant. $1 reused for all three arms.
    pg::PgResult r = pg::exec_params(
        c,
        "SELECT role_name FROM rbac_store.principal_roles "
        "WHERE principal_type = 'user' AND principal_id = $1 "
        "UNION "
        "SELECT pr.role_name FROM rbac_store.principal_roles pr "
        "JOIN rbac_store.group_members gm ON pr.principal_type = 'group' AND "
        "pr.principal_id = gm.group_name WHERE gm.username = $1 "
        "UNION "
        "SELECT role_name FROM rbac_store.principal_roles "
        "WHERE principal_type = 'engine' AND principal_id = $1",
        std::vector<std::string>{username});
    if (r.status() != PGRES_TUPLES_OK)
        return roles; // fail-closed: empty role set → deny
    for (int i = 0; i < PQntuples(r.get()); ++i)
        roles.push_back(text_col(r.get(), i, 0));
    return roles;
}

std::string RbacStore::perm_cache_key(const std::string& user, const std::string& type,
                                      const std::string& op) const {
    return user + ":" + type + ":" + op;
}

bool RbacStore::check_permission(const std::string& username, const std::string& securable_type,
                                 const std::string& operation) const {
    if (!open_)
        return false; // fail-closed

    maybe_refresh_generation();

    const auto key = perm_cache_key(username, securable_type, operation);
    std::uint64_t gen_at_check = 0;
    bool gen_ok = false;
    {
        std::lock_guard lock(cache_mtx_);
        gen_ok = generation_valid_;
        gen_at_check = cached_generation_;
        if (gen_ok) {
            auto it = perm_cache_.find(key);
            if (it != perm_cache_.end())
                return it->second;
        }
    }

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        static DegradeSampler sampler;
        if (note_read_degrade(metrics_, kReasonPoolTimeout, sampler))
            spdlog::warn("RbacStore::check_permission: pool acquire timed out — DENY");
        return false; // fail-closed
    }
    PGconn* conn = lease.get();

    const auto roles = collect_roles(conn, username);
    if (roles.empty())
        return false;

    std::string sql = "SELECT effect FROM rbac_store.role_permissions "
                      "WHERE securable_type = $1 AND operation = $2 AND role_name IN (";
    std::vector<std::string> params{securable_type, operation};
    for (size_t i = 0; i < roles.size(); ++i) {
        sql += (i == 0 ? "$" : ",$") + std::to_string(3 + i);
        params.push_back(roles[i]);
    }
    sql += ")";

    pg::PgResult r = pg::exec_params(conn, sql.c_str(), params);
    if (r.status() != PGRES_TUPLES_OK) {
        static DegradeSampler sampler;
        if (note_read_degrade(metrics_, kReasonQueryError, sampler))
            spdlog::warn("RbacStore::check_permission: query failed: {} — DENY",
                         PQerrorMessage(conn));
        return false; // fail-closed
    }
    bool has_allow = false;
    for (int i = 0; i < PQntuples(r.get()); ++i) {
        const std::string effect = text_col(r.get(), i, 0);
        if (effect == "deny")
            return false; // deny overrides everything
        if (effect == "allow")
            has_allow = true;
    }

    // Store only if the generation we validated against is still current — a
    // mutation racing this read (local or cross-replica) must not persist a
    // stale verdict under the new generation.
    {
        std::lock_guard lock(cache_mtx_);
        if (generation_valid_ && gen_ok && cached_generation_ == gen_at_check)
            perm_cache_[key] = has_allow;
    }
    return has_allow;
}

std::vector<Permission> RbacStore::get_effective_permissions(const std::string& username) const {
    std::vector<Permission> result;
    if (!open_)
        return result;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return result;
    PGconn* conn = lease.get();

    const auto roles = collect_roles(conn, username);
    if (roles.empty())
        return result;

    std::string sql =
        "SELECT role_name, securable_type, operation, effect FROM rbac_store.role_permissions "
        "WHERE role_name IN (";
    std::vector<std::string> params;
    for (size_t i = 0; i < roles.size(); ++i) {
        sql += (i == 0 ? "$" : ",$") + std::to_string(1 + i);
        params.push_back(roles[i]);
    }
    sql += ") ORDER BY securable_type, operation";

    pg::PgResult r = pg::exec_params(conn, sql.c_str(), params);
    if (r.status() != PGRES_TUPLES_OK)
        return result;
    for (int i = 0; i < PQntuples(r.get()); ++i)
        result.push_back(read_perm(r.get(), i));
    return result;
}

// ── Reference data ───────────────────────────────────────────────────────────

std::vector<std::string> RbacStore::list_securable_types() const {
    std::vector<std::string> result;
    if (!open_)
        return result;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return result;
    pg::PgResult r = pg::exec_params(
        lease.get(), "SELECT name FROM rbac_store.securable_types ORDER BY name",
        std::vector<std::string>{});
    if (r.status() != PGRES_TUPLES_OK)
        return result;
    for (int i = 0; i < PQntuples(r.get()); ++i)
        result.push_back(text_col(r.get(), i, 0));
    return result;
}

std::vector<std::string> RbacStore::list_operations() const {
    std::vector<std::string> result;
    if (!open_)
        return result;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return result;
    pg::PgResult r = pg::exec_params(lease.get(), "SELECT id FROM rbac_store.operations ORDER BY id",
                                     std::vector<std::string>{});
    if (r.status() != PGRES_TUPLES_OK)
        return result;
    for (int i = 0; i < PQntuples(r.get()); ++i)
        result.push_back(text_col(r.get(), i, 0));
    return result;
}

// ── Scoped permission check ──────────────────────────────────────────────────

bool RbacStore::check_scoped_permission(const std::string& username,
                                        const std::string& securable_type,
                                        const std::string& operation, const std::string& agent_id,
                                        const ManagementGroupStore* mgmt_store) const {
    // 1. Global permission first (a global ALLOW short-circuits, #1715(b)).
    if (check_permission(username, securable_type, operation))
        return true;

    // 2. No mgmt store or agent → cannot do the scoped check.
    if (!mgmt_store || agent_id.empty())
        return false;

    // 3. Resolve allow/deny groups via the shared INV-7 resolver, intersect
    //    with the agent's reachable groups. Deny wins within the scoped set.
    //    Fail-closed: any store error → false.
    auto pg = resolve_perm_groups(username, securable_type, operation, mgmt_store);
    if (!pg)
        return false;

    auto groups = mgmt_store->get_agent_groups(agent_id);
    std::unordered_set<std::string> reachable;
    for (const auto& gid : groups) {
        reachable.insert(gid);
        for (const auto& aid : mgmt_store->get_ancestor_ids(gid))
            reachable.insert(aid);
    }
    if (reachable.empty())
        return false;

    for (const auto& g : pg->deny_groups)
        if (reachable.contains(g))
            return false;
    for (const auto& g : pg->allow_groups)
        if (reachable.contains(g))
            return true;
    return false;
}

// ── ADR-0017 admit-then-filter list gate ─────────────────────────────────────

std::expected<std::vector<std::string>, std::string>
RbacStore::user_rbac_group_names(const std::string& username) const {
    std::vector<std::string> groups;
    if (!open_)
        return std::unexpected("rbac store not open");
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected("pool acquire timeout");
    pg::PgResult r = pg::exec_params(
        lease.get(), "SELECT group_name FROM rbac_store.group_members WHERE username = $1",
        std::vector<std::string>{username});
    if (r.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string("query failed: ") + PQerrorMessage(lease.get()));
    for (int i = 0; i < PQntuples(r.get()); ++i)
        groups.push_back(text_col(r.get(), i, 0));
    return groups;
}

std::expected<std::unordered_map<std::string, int>, std::string>
RbacStore::role_effects_for(const std::string& securable_type, const std::string& operation) const {
    std::unordered_map<std::string, int> role_effect; // -1 deny (wins), 1 allow, 0 none
    if (!open_)
        return std::unexpected("rbac store not open");
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected("pool acquire timeout");
    pg::PgResult r = pg::exec_params(
        lease.get(),
        "SELECT role_name, effect FROM rbac_store.role_permissions "
        "WHERE securable_type = $1 AND operation = $2",
        std::vector<std::string>{securable_type, operation});
    if (r.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string("query failed: ") + PQerrorMessage(lease.get()));
    for (int i = 0; i < PQntuples(r.get()); ++i) {
        const std::string role = text_col(r.get(), i, 0);
        const std::string effect = text_col(r.get(), i, 1);
        if (role.empty())
            continue;
        int& e = role_effect[role];
        if (effect == "deny")
            e = -1;
        else if (effect == "allow" && e == 0)
            e = 1;
    }
    return role_effect;
}

std::expected<RbacStore::PermGroups, std::string>
RbacStore::resolve_perm_groups(const std::string& username, const std::string& securable_type,
                               const std::string& operation,
                               const ManagementGroupStore* mgmt_store) const {
    if (!mgmt_store)
        return std::unexpected("management group store unavailable");

    auto rbac_groups = user_rbac_group_names(username);
    if (!rbac_groups)
        return std::unexpected(rbac_groups.error());

    auto assignments = mgmt_store->get_assignments_for_principal(username, *rbac_groups);
    if (!assignments)
        return std::unexpected(assignments.error());

    auto role_effect_r = role_effects_for(securable_type, operation);
    if (!role_effect_r)
        return std::unexpected(role_effect_r.error());
    const auto& role_effect = *role_effect_r;

    PermGroups pg;
    std::unordered_set<std::string> allow_seen, deny_seen;
    for (const auto& a : *assignments) {
        auto it = role_effect.find(a.role_name);
        if (it == role_effect.end() || it->second == 0)
            continue;
        if (it->second == -1) {
            if (deny_seen.insert(a.group_id).second)
                pg.deny_groups.push_back(a.group_id);
        } else if (allow_seen.insert(a.group_id).second) {
            pg.allow_groups.push_back(a.group_id);
        }
    }
    return pg;
}

std::expected<std::vector<std::string>, std::string>
RbacStore::expand_visible_set(const PermGroups& pg, const ManagementGroupStore* mgmt_store) const {
    if (!mgmt_store)
        return std::unexpected("management group store unavailable");
    if (pg.allow_groups.empty())
        return std::vector<std::string>{}; // holds nothing via groups → empty (INV-2)

    auto allow_agents = mgmt_store->get_member_agents_in_subtrees(pg.allow_groups);
    if (!allow_agents)
        return std::unexpected(allow_agents.error());

    if (!pg.deny_groups.empty()) {
        auto deny_agents = mgmt_store->get_member_agents_in_subtrees(pg.deny_groups);
        if (!deny_agents)
            return std::unexpected(deny_agents.error());
        std::unordered_set<std::string> denied(deny_agents->begin(), deny_agents->end());
        std::vector<std::string> visible;
        visible.reserve(allow_agents->size());
        for (auto& a : *allow_agents)
            if (!denied.contains(a))
                visible.push_back(std::move(a));
        allow_agents = std::move(visible);
    }
    std::sort(allow_agents->begin(), allow_agents->end());
    allow_agents->erase(std::unique(allow_agents->begin(), allow_agents->end()),
                        allow_agents->end());
    return allow_agents;
}

bool RbacStore::holds_permission_via_any_group(const std::string& username,
                                               const std::string& securable_type,
                                               const std::string& operation,
                                               const ManagementGroupStore* mgmt_store) const {
    auto pg = resolve_perm_groups(username, securable_type, operation, mgmt_store);
    if (!pg)
        return false; // fail-closed on any store error
    return !pg->allow_groups.empty();
}

std::expected<std::vector<std::string>, std::string>
RbacStore::visible_agents_for_permission(const std::string& username,
                                         const std::string& securable_type,
                                         const std::string& operation,
                                         const ManagementGroupStore* mgmt_store) const {
    auto pg = resolve_perm_groups(username, securable_type, operation, mgmt_store);
    if (!pg)
        return std::unexpected(pg.error());
    return expand_visible_set(*pg, mgmt_store);
}

ListReadAuthorization RbacStore::authorize_list_read(const std::string& username,
                                                     const std::string& securable_type,
                                                     const std::string& operation,
                                                     const ManagementGroupStore* mgmt_store) const {
    ListReadAuthorization out; // DenyAll by default — the INV-1 fail-closed default.

    // Legacy-open: RBAC loaded AND explicitly disabled → full-fleet read. A
    // null / load-failed store returns true from rbac_enforcement_in_effect and
    // falls through to the RBAC path, which denies (INV-1).
    if (!rbac_enforcement_in_effect(this)) {
        out.decision = ListReadDecision::AdmitAll;
        return out;
    }

    // #1715(b): a global ALLOW overrides any group deny → unfiltered read.
    if (check_permission(username, securable_type, operation)) {
        out.decision = ListReadDecision::AdmitAll;
        return out;
    }

    // #1715(a): additive — a group allow admits even against a global deny/absent.
    auto pg = resolve_perm_groups(username, securable_type, operation, mgmt_store);
    if (!pg || pg->allow_groups.empty()) {
        out.decision = ListReadDecision::DenyAll; // INV-1/INV-5: error or no grant → deny
        return out;
    }
    auto visible = expand_visible_set(*pg, mgmt_store);
    if (!visible) {
        out.decision = ListReadDecision::DenyAll; // fail-closed on a subtree-read error
        return out;
    }
    out.decision = ListReadDecision::AdmitScoped;
    out.visible_agents = std::move(*visible);
    return out;
}

bool RbacStore::check_role_has_permission(const std::string& role_name,
                                          const std::string& securable_type,
                                          const std::string& operation) const {
    // Uses the fail-closed authoritative read: on a store error the checked
    // variant returns unexpected → DENY (never a false allow).
    auto perms = get_role_permissions_checked(role_name);
    if (!perms)
        return false;
    for (const auto& p : *perms) {
        if (p.securable_type == securable_type && p.operation == operation) {
            if (p.effect == "deny")
                return false;
            if (p.effect == "allow")
                return true;
        }
    }
    return false;
}

// ── Backfill (ADR-0009 MANDATORY class / ADR-0041) ───────────────────────────

bool RbacStore::migrate_from_sqlite(const std::filesystem::path& legacy_db_path) {
    if (!open_)
        return false;

    const auto backfill_metric = [this](const char* result) {
        if (metrics_)
            metrics_->counter("yuzu_server_rbac_backfill_total", {{"result", result}}).increment();
    };

    const auto stamp_complete = [&]() -> bool {
        return pool_.with_txn_for(kBackfillTxnTimeout, [](PGconn* c) -> bool {
            pg::PgResult mk = pg::exec_params(
                c,
                "INSERT INTO rbac_store.rbac_meta (key, value) VALUES ('backfill_complete', $1) "
                "ON CONFLICT (key) DO NOTHING",
                std::vector<std::string>{std::to_string(now_secs())});
            if (mk.status() != PGRES_COMMAND_OK) {
                spdlog::error("RbacStore: migrate_from_sqlite: marker stamp failed: {}",
                              PQerrorMessage(c));
                return false;
            }
            return true;
        });
    };

    // 1. Idempotency marker (short-lived lease released before any legacy I/O).
    {
        auto lease = pool_.acquire();
        if (!lease) {
            spdlog::error("RbacStore: migrate_from_sqlite: no database connection ({})",
                          pool_.last_error());
            backfill_metric("failed");
            return false;
        }
        pg::PgResult mk = pg::exec_params(
            lease.get(), "SELECT 1 FROM rbac_store.rbac_meta WHERE key='backfill_complete'",
            std::vector<std::string>{});
        if (mk.status() != PGRES_TUPLES_OK) {
            spdlog::error("RbacStore: migrate_from_sqlite: marker lookup failed: {}",
                          PQerrorMessage(lease.get()));
            backfill_metric("failed");
            return false;
        }
        if (PQntuples(mk.get()) > 0) {
            spdlog::debug("RbacStore: migrate_from_sqlite already completed, skipping");
            return true;
        }
    }

    // 2. Legacy present?
    std::error_code ec;
    const bool legacy_exists = std::filesystem::exists(legacy_db_path, ec);
    if (ec) {
        spdlog::error("RbacStore: migrate_from_sqlite: cannot stat legacy path {}: {}",
                      legacy_db_path.string(), ec.message());
        backfill_metric("failed");
        return false;
    }
    if (!legacy_exists) {
        // Fresh install — the seeded default rbac_enabled='false' is correct.
        if (!stamp_complete()) {
            backfill_metric("failed");
            return false;
        }
        spdlog::info("RbacStore: migrate_from_sqlite: no legacy rbac.db at {}; marking backfill "
                     "complete (fresh install)",
                     legacy_db_path.string());
        backfill_metric("fresh");
        return true;
    }

    // 3. Open legacy read-only.
    SqliteDb legacy;
    if (sqlite3_open_v2(legacy_db_path.string().c_str(), legacy.addr(), SQLITE_OPEN_READONLY,
                        nullptr) != SQLITE_OK) {
        spdlog::error("RbacStore: migrate_from_sqlite: failed to open legacy db {}: {}",
                      legacy_db_path.string(),
                      legacy ? sqlite3_errmsg(legacy.get()) : "open failed");
        backfill_metric("failed");
        return false;
    }
    sqlite3_exec(legacy.get(), "PRAGMA busy_timeout=5000;", nullptr, nullptr, nullptr);
    // Corruption probe: a non-empty, non-SQLite file opens lazily under
    // READONLY, then the first real query fails with SQLITE_NOTADB. Distinguish
    // that (fail CLOSED — an unreadable legacy DB must NOT be silently skipped,
    // which would drop every operator-authored grant) from a genuine fresh/other
    // DB where the query succeeds and merely finds no `roles` table.
    {
        SqliteStmt probe;
        if (sqlite3_prepare_v2(legacy.get(), "SELECT count(*) FROM sqlite_master", -1, probe.addr(),
                               nullptr) != SQLITE_OK ||
            sqlite3_step(probe.get()) != SQLITE_ROW) {
            spdlog::error("RbacStore: migrate_from_sqlite: legacy db {} is unreadable/corrupt ({}); "
                          "refusing backfill (fail-closed — never silently drop operator RBAC "
                          "config)",
                          legacy_db_path.string(), sqlite3_errmsg(legacy.get()));
            backfill_metric("failed");
            return false;
        }
    }
    if (!legacy_has_table(legacy.get(), "roles")) {
        if (!stamp_complete()) {
            backfill_metric("failed");
            return false;
        }
        spdlog::warn("RbacStore: migrate_from_sqlite: legacy db {} has no roles table; marking "
                     "backfill complete",
                     legacy_db_path.string());
        backfill_metric("fresh");
        return true;
    }

    // 4. CRITICAL — the rbac_enabled flag FIRST, read-back-verified. Losing it
    // silently reverts the fleet to RBAC-off (catastrophic fail-open). The
    // seeded default 'false' is a placeholder legacy intent must OVERRIDE, so
    // this is DO UPDATE (not DO NOTHING).
    std::string legacy_enabled = "false";
    if (legacy_has_table(legacy.get(), "rbac_config")) {
        SqliteStmt s;
        if (sqlite3_prepare_v2(legacy.get(),
                               "SELECT value FROM rbac_config WHERE key='enabled'", -1, s.addr(),
                               nullptr) == SQLITE_OK &&
            sqlite3_step(s.get()) == SQLITE_ROW) {
            legacy_enabled = (sqlite_text(s.get(), 0) == "true") ? "true" : "false";
        }
    }
    {
        const bool ok = pool_.with_txn_for(kBackfillTxnTimeout, [&](PGconn* c) -> bool {
            pg::PgResult up = pg::exec_params(
                c,
                "INSERT INTO rbac_store.rbac_meta (key, value) VALUES ('rbac_enabled', $1) "
                "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
                std::vector<std::string>{legacy_enabled});
            if (up.status() != PGRES_COMMAND_OK) {
                spdlog::error("RbacStore: migrate_from_sqlite: rbac_enabled write failed: {}",
                              PQerrorMessage(c));
                return false;
            }
            // Read-back-after-write verification IN THE SAME TXN.
            pg::PgResult rb = pg::exec_params(
                c, "SELECT value FROM rbac_store.rbac_meta WHERE key='rbac_enabled'",
                std::vector<std::string>{});
            if (rb.status() != PGRES_TUPLES_OK || PQntuples(rb.get()) != 1 ||
                text_col(rb.get(), 0, 0) != legacy_enabled) {
                spdlog::error("RbacStore: migrate_from_sqlite: rbac_enabled read-back verification "
                              "FAILED — refusing backfill (fail-closed; losing this flag is "
                              "catastrophic fail-open)");
                return false;
            }
            return true;
        });
        if (!ok) {
            backfill_metric("failed");
            return false;
        }
        rbac_enabled_.store(legacy_enabled == "true", std::memory_order_relaxed);
        spdlog::info("RbacStore: migrate_from_sqlite: rbac_enabled migrated + verified as '{}'",
                     legacy_enabled);
    }

    // 5. Backfill config tables. Small, authoritative sets — one transaction,
    // whole-table reads, ON CONFLICT DO NOTHING (idempotent + crash-resumable
    // by re-run). securable_types/operations are backfilled too (defensive:
    // keeps role_permissions FKs satisfiable even for a hypothetical custom
    // type). Legacy is already migration-cleaned, so v3/v4 cleanups are not
    // replayed. Reconciliation counts are gathered here for the assert below.
    struct TableCounts {
        std::int64_t roles{0}, perms{0}, principals{0}, groups{0}, members{0};
    };
    TableCounts legacy_counts;
    const auto count_legacy = [&](const char* table) -> std::int64_t {
        if (!legacy_has_table(legacy.get(), table))
            return 0;
        SqliteStmt s;
        const std::string q = std::string("SELECT COUNT(*) FROM ") + table;
        if (sqlite3_prepare_v2(legacy.get(), q.c_str(), -1, s.addr(), nullptr) != SQLITE_OK ||
            sqlite3_step(s.get()) != SQLITE_ROW)
            return -1;
        return sqlite3_column_int64(s.get(), 0);
    };
    legacy_counts.roles = count_legacy("roles");
    legacy_counts.perms = count_legacy("role_permissions");
    legacy_counts.principals = count_legacy("principal_roles");
    legacy_counts.groups = count_legacy("groups");
    legacy_counts.members = count_legacy("group_members");
    if (legacy_counts.roles < 0 || legacy_counts.perms < 0 || legacy_counts.principals < 0 ||
        legacy_counts.groups < 0 || legacy_counts.members < 0) {
        spdlog::error("RbacStore: migrate_from_sqlite: legacy count failed: {}",
                      sqlite3_errmsg(legacy.get()));
        backfill_metric("failed");
        return false;
    }

    // Read every legacy row into memory (config tables are small) BEFORE the PG
    // txn, so no two leases are held at once.
    struct LRole {
        std::string name, description;
        std::int64_t is_system{0}, created_at{0};
    };
    struct LType {
        std::string name, description;
        std::int64_t is_system{0};
    };
    struct LPerm {
        std::string role_name, securable_type, operation, effect;
    };
    struct LPrincipal {
        std::string principal_type, principal_id, role_name;
    };
    struct LGroup {
        std::string name, description, source;
        std::optional<std::string> external_id;
        std::int64_t created_at{0};
    };
    struct LMember {
        std::string group_name, username;
    };
    std::vector<LType> types;
    std::vector<std::pair<std::string, std::string>> ops; // (id, description) is_system implied
    std::vector<LRole> roles;
    std::vector<LPerm> perms;
    std::vector<LPrincipal> principals;
    std::vector<LGroup> groups;
    std::vector<LMember> members;

    const auto read_all = [&](const char* sql, const std::function<void(sqlite3_stmt*)>& row)
        -> bool {
        SqliteStmt s;
        if (sqlite3_prepare_v2(legacy.get(), sql, -1, s.addr(), nullptr) != SQLITE_OK)
            return false;
        int rc;
        while ((rc = sqlite3_step(s.get())) == SQLITE_ROW)
            row(s.get());
        return rc == SQLITE_DONE;
    };

    bool read_ok = true;
    if (legacy_has_table(legacy.get(), "securable_types"))
        read_ok &= read_all("SELECT name, description, is_system FROM securable_types",
                            [&](sqlite3_stmt* s) {
                                types.push_back({sqlite_text(s, 0), sqlite_text(s, 1),
                                                 sqlite3_column_int64(s, 2)});
                            });
    if (legacy_has_table(legacy.get(), "operations"))
        read_ok &= read_all("SELECT id, description FROM operations", [&](sqlite3_stmt* s) {
            ops.emplace_back(sqlite_text(s, 0), sqlite_text(s, 1));
        });
    read_ok &= read_all("SELECT name, description, is_system, created_at FROM roles",
                       [&](sqlite3_stmt* s) {
                           roles.push_back({sqlite_text(s, 0), sqlite_text(s, 1),
                                            sqlite3_column_int64(s, 2), sqlite3_column_int64(s, 3)});
                       });
    read_ok &= read_all("SELECT role_name, securable_type, operation, effect FROM role_permissions",
                       [&](sqlite3_stmt* s) {
                           perms.push_back({sqlite_text(s, 0), sqlite_text(s, 1), sqlite_text(s, 2),
                                            sqlite_text(s, 3)});
                       });
    read_ok &= read_all("SELECT principal_type, principal_id, role_name FROM principal_roles",
                       [&](sqlite3_stmt* s) {
                           principals.push_back(
                               {sqlite_text(s, 0), sqlite_text(s, 1), sqlite_text(s, 2)});
                       });
    if (legacy_has_table(legacy.get(), "groups"))
        read_ok &= read_all("SELECT name, description, source, external_id, created_at FROM groups",
                           [&](sqlite3_stmt* s) {
                               LGroup g{sqlite_text(s, 0), sqlite_text(s, 1), sqlite_text(s, 2),
                                        std::nullopt, sqlite3_column_int64(s, 4)};
                               if (sqlite3_column_type(s, 3) != SQLITE_NULL)
                                   g.external_id = sqlite_text(s, 3);
                               groups.push_back(std::move(g));
                           });
    if (legacy_has_table(legacy.get(), "group_members"))
        read_ok &= read_all("SELECT group_name, username FROM group_members", [&](sqlite3_stmt* s) {
            members.push_back({sqlite_text(s, 0), sqlite_text(s, 1)});
        });
    if (!read_ok) {
        spdlog::error("RbacStore: migrate_from_sqlite: legacy read failed: {}",
                      sqlite3_errmsg(legacy.get()));
        backfill_metric("failed");
        return false;
    }

    const bool insert_ok = pool_.with_txn_for(kBackfillTxnTimeout, [&](PGconn* c) -> bool {
        const auto run = [&](const char* sql, const std::vector<std::string>& p) -> bool {
            pg::PgResult r = pg::exec_params(c, sql, p);
            if (r.status() != PGRES_COMMAND_OK) {
                spdlog::error("RbacStore: migrate_from_sqlite: insert failed: {}", PQerrorMessage(c));
                return false;
            }
            return true;
        };
        for (const auto& t : types)
            if (!run("INSERT INTO rbac_store.securable_types (name, description, is_system) "
                     "VALUES ($1, $2, $3::boolean) ON CONFLICT (name) DO NOTHING",
                     {sanitize_pg_text(t.name), sanitize_pg_text(t.description),
                      bool_lit(t.is_system)}))
                return false;
        for (const auto& o : ops)
            if (!run("INSERT INTO rbac_store.operations (id, description, is_system) "
                     "VALUES ($1, $2, TRUE) ON CONFLICT (id) DO NOTHING",
                     {sanitize_pg_text(o.first), sanitize_pg_text(o.second)}))
                return false;
        for (const auto& r : roles)
            if (!run("INSERT INTO rbac_store.roles (name, description, is_system, created_at) "
                     "VALUES ($1, $2, $3::boolean, $4::bigint) ON CONFLICT (name) DO NOTHING",
                     {sanitize_pg_text(r.name), sanitize_pg_text(r.description),
                      bool_lit(r.is_system), std::to_string(r.created_at)}))
                return false;
        for (const auto& p : perms)
            if (!run("INSERT INTO rbac_store.role_permissions (role_name, securable_type, "
                     "operation, effect) VALUES ($1, $2, $3, $4) "
                     "ON CONFLICT (role_name, securable_type, operation) DO NOTHING",
                     {sanitize_pg_text(p.role_name), sanitize_pg_text(p.securable_type),
                      sanitize_pg_text(p.operation), sanitize_pg_text(p.effect)}))
                return false;
        for (const auto& p : principals)
            if (!run("INSERT INTO rbac_store.principal_roles (principal_type, principal_id, "
                     "role_name) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
                     {sanitize_pg_text(p.principal_type), sanitize_pg_text(p.principal_id),
                      sanitize_pg_text(p.role_name)}))
                return false;
        for (const auto& g : groups) {
            pg::PgResult r = pg::exec_params(
                c,
                "INSERT INTO rbac_store.groups (name, description, source, external_id, created_at) "
                "VALUES ($1, $2, $3, $4, $5::bigint) ON CONFLICT (name) DO NOTHING",
                std::vector<std::optional<std::string>>{
                    sanitize_pg_text(g.name), sanitize_pg_text(g.description),
                    sanitize_pg_text(g.source),
                    g.external_id ? std::optional<std::string>(sanitize_pg_text(*g.external_id))
                                  : std::nullopt,
                    std::to_string(g.created_at)});
            if (r.status() != PGRES_COMMAND_OK) {
                spdlog::error("RbacStore: migrate_from_sqlite: group insert failed: {}",
                              PQerrorMessage(c));
                return false;
            }
        }
        for (const auto& m : members)
            if (!run("INSERT INTO rbac_store.group_members (group_name, username) VALUES ($1, $2) "
                     "ON CONFLICT DO NOTHING",
                     {sanitize_pg_text(m.group_name), sanitize_pg_text(m.username)}))
                return false;
        return true;
    });
    if (!insert_ok) {
        backfill_metric("failed");
        return false;
    }

    // 6. Row-count reconciliation — PG must hold at least the legacy counts
    // (PG also holds seeded system rows; DO NOTHING never drops a legacy row).
    {
        auto lease = pool_.acquire();
        if (!lease) {
            backfill_metric("failed");
            return false;
        }
        const auto pg_count = [&](const char* table) -> std::int64_t {
            pg::PgResult r = pg::exec_params(
                lease.get(), (std::string("SELECT COUNT(*) FROM rbac_store.") + table).c_str(),
                std::vector<std::string>{});
            if (r.status() != PGRES_TUPLES_OK)
                return -1;
            return to_i64(PQgetvalue(r.get(), 0, 0));
        };
        const std::int64_t pr = pg_count("roles"), pp = pg_count("role_permissions"),
                           ppr = pg_count("principal_roles"), pg_ = pg_count("groups"),
                           pm = pg_count("group_members");
        if (pr < 0 || pp < 0 || ppr < 0 || pg_ < 0 || pm < 0) {
            spdlog::error("RbacStore: migrate_from_sqlite: reconciliation count failed");
            backfill_metric("failed");
            return false;
        }
        if (pr < legacy_counts.roles || pp < legacy_counts.perms ||
            ppr < legacy_counts.principals || pg_ < legacy_counts.groups ||
            pm < legacy_counts.members) {
            spdlog::error("RbacStore: migrate_from_sqlite: reconciliation FAILED — legacy "
                          "(roles={},perms={},principals={},groups={},members={}) vs PG "
                          "(roles={},perms={},principals={},groups={},members={}); refusing marker",
                          legacy_counts.roles, legacy_counts.perms, legacy_counts.principals,
                          legacy_counts.groups, legacy_counts.members, pr, pp, ppr, pg_, pm);
            backfill_metric("failed");
            return false;
        }
        spdlog::info("RbacStore: migrate_from_sqlite: reconciled — legacy "
                     "(roles={},perms={},principals={},groups={},members={}), PG "
                     "(roles={},perms={},principals={},groups={},members={})",
                     legacy_counts.roles, legacy_counts.perms, legacy_counts.principals,
                     legacy_counts.groups, legacy_counts.members, pr, pp, ppr, pg_, pm);
    }

    // 7. Stamp the one-time marker.
    if (!stamp_complete()) {
        backfill_metric("failed");
        return false;
    }

    // 8. Move the verified legacy file aside (non-fatal on failure).
    std::error_code mv_ec;
    auto aside = legacy_db_path;
    aside += ".migrated-" + std::to_string(now_secs());
    std::filesystem::rename(legacy_db_path, aside, mv_ec);
    if (mv_ec)
        spdlog::warn("RbacStore: migrate_from_sqlite: backfill complete but could not move legacy "
                     "{} aside ({}); it is safe to archive/remove manually",
                     legacy_db_path.string(), mv_ec.message());
    else
        spdlog::info("RbacStore: migrate_from_sqlite: moved legacy rbac db to {}", aside.string());

    backfill_metric("completed");
    return true;
}

} // namespace yuzu::server
