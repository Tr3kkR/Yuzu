#include "engine_principal_store.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <string_view>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "engine_principal_store";

// Bounded acquires (ADR-0012 §2). Auth lookups sit on a hot(ish) path — every
// engine-credential session synthesis / delegation redemption falls through
// here — so a short read budget; mutations (create/revoke/transfer) are rarer
// admin operations and get a little more room. Neither is unbounded.
constexpr std::chrono::milliseconds kReadTimeout{1500};
constexpr std::chrono::milliseconds kWriteTimeout{2000};

const std::vector<pg::PgMigration>& migrations() {
    // Unqualified DDL: the runner sets search_path to the store schema for
    // the migration txn. Runtime statements below schema-qualify explicitly.
    static const std::vector<pg::PgMigration> kMigrations = {
        {1,
         "CREATE TABLE engine_principals ("
         // F7 (Hermes pass-2 LOW 4a): '_' requires >=1 char after 'engine:' so
         // the DB CHECK matches the C++-side empty-slug rejection exactly
         // (this migration is unreleased on this branch — amend v1 directly,
         // no v2 needed).
         "  principal_id     TEXT PRIMARY KEY CHECK (principal_id LIKE 'engine:_%'),"
         "  display_name     TEXT NOT NULL DEFAULT '',"
         "  owner_username   TEXT NOT NULL,"
         "  justification    TEXT NOT NULL DEFAULT '',"
         "  classification   TEXT NOT NULL CHECK (classification IN ('internal','external')),"
         "  lifecycle_state  TEXT NOT NULL DEFAULT 'active' "
         "    CHECK (lifecycle_state IN ('active','revoked')),"
         "  superseded_by    TEXT NOT NULL DEFAULT '',"
         "  created_at       BIGINT NOT NULL DEFAULT 0,"
         "  revoked_at       BIGINT NOT NULL DEFAULT 0,"
         "  created_by       TEXT NOT NULL DEFAULT '');"
         "CREATE INDEX engine_principals_owner_idx ON engine_principals (owner_username);"},
    };
    return kMigrations;
}

// Epoch SECONDS (matches api_token_store's now_epoch idiom).
std::int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::int64_t to_i64(const char* s) {
    if (s == nullptr || s[0] == '\0')
        return 0;
    return static_cast<std::int64_t>(std::strtoll(s, nullptr, 10));
}

// G8 (governance hardening, cpp-expert N2): null-safe column read, mirroring
// api_token_store.cpp's `col()` helper. Every column in the v1 projection is
// NOT NULL, so PQgetvalue never returns a NULL cell today (libpq returns ""
// for a NULL cell's value, never nullptr — but a future migration relaxing a
// NOT NULL constraint, or a projection drift from `kCols`, must degrade to
// "" here rather than the caller silently trusting an un-vetted cell).
const char* col(PGresult* res, int row, int c) {
    return PQgetisnull(res, row, c) ? "" : PQgetvalue(res, row, c);
}

EnginePrincipalRow read_row(PGresult* res, int i) {
    EnginePrincipalRow r;
    int c = 0;
    r.principal_id = col(res, i, c++);
    r.display_name = col(res, i, c++);
    r.owner_username = col(res, i, c++);
    r.justification = col(res, i, c++);
    r.classification = col(res, i, c++);
    r.lifecycle_state = col(res, i, c++);
    r.superseded_by = col(res, i, c++);
    r.created_at = to_i64(col(res, i, c++));
    r.revoked_at = to_i64(col(res, i, c++));
    r.created_by = col(res, i, c++);
    return r;
}

constexpr const char* kCols =
    "principal_id, display_name, owner_username, justification, classification, "
    "lifecycle_state, superseded_by, created_at, revoked_at, created_by";

} // namespace

EnginePrincipalStore::EnginePrincipalStore(pg::PgPool& pool) : pool_(pool) {
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("EnginePrincipalStore: no database connection at construction ({}) — "
                      "engine-principal identity store disabled",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error(
            "EnginePrincipalStore: schema migration failed — engine-principal identity "
            "store disabled");
        return;
    }
    open_ = true;
}

namespace {
// G6 (governance hardening, sre SHOULD / UP-6): a throttled diagnostic warn
// for the StoreUnreachable arm — first hit, then every kLogEvery-th, mirroring
// on_behalf_guard.hpp's note_rejection idiom — so a PG-availability blip is
// visible in logs (distinct from a routine revoked/missing credential, which
// stays quiet) without turning a sustained outage into a per-request log
// flood on this hot auth-lookup path.
constexpr std::uint64_t kLogEvery = 100;
bool should_log_unreachable() {
    static std::atomic<std::uint64_t> hits{0};
    return hits.fetch_add(1, std::memory_order_relaxed) % kLogEvery == 0;
}
} // namespace

EngineLookup EnginePrincipalStore::get_for_auth(const std::string& principal_id) const {
    // ADR-0012 §1 authoritative posture (design doc §3.1 / §12 decision 1):
    // BOTH non-Active outcomes below DENY the request — the split changes
    // retry behavior only (StoreUnreachable = retryable/503-class,
    // MissingOrRevoked = terminal/401-class), never the authorization
    // outcome. There is no downgrade path from "unreachable" to "admitted".
    if (!open_) {
        if (should_log_unreachable())
            spdlog::warn("{}: get_for_auth denied (store not open) — retryable PG-availability "
                        "condition, not a revoked credential",
                        kStoreName);
        return {EngineLookupStatus::StoreUnreachable, std::nullopt};
    }

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        if (should_log_unreachable())
            spdlog::warn("{}: get_for_auth denied (lease acquire failed/timed out) — retryable "
                        "PG-availability condition, not a revoked credential",
                        kStoreName);
        return {EngineLookupStatus::StoreUnreachable, std::nullopt};
    }

    std::string sql =
        std::string("SELECT ") + kCols + " FROM engine_principal_store.engine_principals "
                                         "WHERE principal_id = $1";
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(),
                                       std::vector<std::string>{principal_id});
    if (res.status() != PGRES_TUPLES_OK) {
        if (should_log_unreachable())
            spdlog::warn("{}: get_for_auth denied (query failed, status={}) — retryable "
                        "PG-availability condition, not a revoked credential",
                        kStoreName, static_cast<int>(res.status()));
        return {EngineLookupStatus::StoreUnreachable, std::nullopt}; // transient/retryable
    }

    if (PQntuples(res.get()) == 0)
        return {EngineLookupStatus::MissingOrRevoked, std::nullopt}; // terminal — no such row

    EnginePrincipalRow row = read_row(res.get(), 0);
    if (row.lifecycle_state != "active")
        return {EngineLookupStatus::MissingOrRevoked, std::nullopt}; // terminal — revoked

    return {EngineLookupStatus::Active, std::move(row)};
}

std::expected<EnginePrincipalRow, std::string>
EnginePrincipalStore::create(const std::string& display_name, const std::string& owner_username,
                             const std::string& justification, const std::string& classification,
                             const std::string& created_by, const std::string& principal_id) {
    if (!open_)
        return std::unexpected("database not open");
    if (classification != "internal" && classification != "external")
        return std::unexpected("classification must be 'internal' or 'external'");
    constexpr std::string_view kPrefix = "engine:";
    if (!principal_id.starts_with(kPrefix) || principal_id.size() == kPrefix.size())
        return std::unexpected("principal_id must be in the reserved 'engine:<slug>' namespace "
                               "with a non-empty slug");
    // G4 (governance hardening, UP-4): beyond non-empty, constrain the slug
    // to a conservative identifier charset. Without this an
    // injection/XSS-shaped principal_id (e.g. `engine:<script>alert(1)</script>`)
    // could be stored and later flow unescaped into audit rows / the PR-4.3
    // dashboard. Allowed set: lowercase ASCII letters, digits, '.', '_', '-'.
    {
        std::string_view slug = std::string_view(principal_id).substr(kPrefix.size());
        auto is_allowed = [](unsigned char c) {
            return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_' ||
                  c == '-';
        };
        for (unsigned char c : slug) {
            if (!is_allowed(c))
                return std::unexpected(
                    "principal_id slug may only contain lowercase letters, digits, '.', '_', "
                    "'-'");
        }
    }
    if (owner_username.empty())
        return std::unexpected("owner_username cannot be empty");
    // G7 (governance hardening, compliance MEDIUM): mirror the classification
    // requirement — an empty justification would leave the access-review
    // evidence field uncaptured at creation time.
    if (justification.empty())
        return std::unexpected("justification cannot be empty");

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected("database unavailable — try again");

    const auto now = now_epoch();
    std::string sql = std::string("INSERT INTO engine_principal_store.engine_principals "
                                  "(principal_id, display_name, owner_username, justification, "
                                  " classification, created_at, created_by) "
                                  "VALUES ($1,$2,$3,$4,$5,$6::bigint,$7) RETURNING ") +
                      kCols;
    pg::PgResult res = pg::exec_params(
        lease.get(), sql.c_str(),
        std::vector<std::string>{principal_id, display_name, owner_username, justification,
                                 classification, std::to_string(now), created_by});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) == 0)
        return std::unexpected(std::string("failed to create engine principal: ") +
                               PQerrorMessage(lease.get()));
    return read_row(res.get(), 0);
}

std::expected<std::optional<EnginePrincipalRow>, std::string>
EnginePrincipalStore::get(const std::string& principal_id) const {
    // Authoritative store (ADR-0012 §1): distinguish a runtime read error
    // (surfaced → caller 503s/retries) from a genuine no-such-row (value ==
    // nullopt → caller 404s), mirroring ApiTokenStore::get_token. A bare
    // `optional<...>` return here previously conflated the two.
    if (!open_)
        return std::unexpected("database not open");
    if (principal_id.empty())
        return std::optional<EnginePrincipalRow>{std::nullopt}; // argument guard, not a DB error

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected("database unavailable — try again");

    std::string sql =
        std::string("SELECT ") + kCols + " FROM engine_principal_store.engine_principals "
                                         "WHERE principal_id = $1";
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(),
                                       std::vector<std::string>{principal_id});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string("get read failed: ") + PQerrorMessage(lease.get()));
    if (PQntuples(res.get()) == 0)
        return std::optional<EnginePrincipalRow>{std::nullopt}; // genuine not-found

    return std::optional<EnginePrincipalRow>{read_row(res.get(), 0)};
}

std::expected<bool, std::string>
EnginePrincipalStore::revoke(const std::string& principal_id,
                             const std::string& superseded_by) {
    // Authoritative store (ADR-0012 §1): distinguish a write that did NOT
    // persist (unexpected — caller must 503/retry, never audit success) from
    // a write that ran fine but matched no active row (false — genuine
    // no-op), mirroring ApiTokenStore::revoke_token. A bare `bool` return
    // here previously conflated the two.
    if (!open_)
        return std::unexpected("database not open");
    if (principal_id.empty())
        return false; // argument guard, not a DB error — nothing to revoke

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected("database unavailable — try again");
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE engine_principal_store.engine_principals "
        "SET lifecycle_state='revoked', revoked_at=$3::bigint, superseded_by=$2 "
        "WHERE principal_id=$1 AND lifecycle_state='active' RETURNING principal_id",
        std::vector<std::string>{principal_id, superseded_by, std::to_string(now_epoch())});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string("revoke did not persist: ") +
                               PQerrorMessage(lease.get()));
    // RETURNING 0 rows ⇒ no such principal or already revoked — a genuine
    // no-op (ADR-0012 §1), distinct from the query-error arm above.
    return PQntuples(res.get()) > 0;
}

std::expected<bool, std::string>
EnginePrincipalStore::transfer_owner(const std::string& principal_id,
                                     const std::string& new_owner) {
    if (!open_)
        return std::unexpected("database not open");
    if (principal_id.empty() || new_owner.empty())
        return false; // argument guard, not a DB error — nothing to transfer

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected("database unavailable — try again");
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE engine_principal_store.engine_principals SET owner_username=$2 "
        "WHERE principal_id=$1 AND lifecycle_state='active' RETURNING principal_id",
        std::vector<std::string>{principal_id, new_owner});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string("transfer_owner did not persist: ") +
                               PQerrorMessage(lease.get()));
    return PQntuples(res.get()) > 0;
}

std::vector<EnginePrincipalRow> EnginePrincipalStore::list_all(bool include_revoked) const {
    std::vector<EnginePrincipalRow> rows;
    if (!open_)
        return rows;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        spdlog::warn("{}: list_all denied (lease acquire failed/timed out) — returning empty",
                    kStoreName);
        return rows;
    }
    std::string sql = std::string("SELECT ") + kCols +
                      " FROM engine_principal_store.engine_principals ";
    if (!include_revoked)
        sql += "WHERE lifecycle_state='active' ";
    sql += "ORDER BY created_at";
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::warn("{}: list_all denied (query failed, status={}) — returning empty",
                    kStoreName, static_cast<int>(res.status()));
        return rows;
    }
    int n = PQntuples(res.get());
    rows.reserve(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i)
        rows.push_back(read_row(res.get(), i));
    return rows;
}

std::optional<std::size_t>
EnginePrincipalStore::count_active_owned_by(const std::string& owner_username) const {
    if (!open_)
        return std::nullopt; // cannot verify → caller fails closed
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::nullopt;
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT COUNT(*) FROM engine_principal_store.engine_principals "
        "WHERE owner_username=$1 AND lifecycle_state='active'",
        std::vector<std::string>{owner_username});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) == 0)
        return std::nullopt;
    return static_cast<std::size_t>(to_i64(col(res.get(), 0, 0)));
}

} // namespace yuzu::server
