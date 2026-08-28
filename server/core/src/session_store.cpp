/**
 * session_store.cpp -- see session_store.hpp
 *
 * Idioms mirror access_review_store.cpp (authoritative std::expected + with_txn_for)
 * and rbac_store.cpp (durable write-generation bumped in the same txn as every
 * authz-affecting mutation). Runtime SQL is schema-qualified; migration DDL is
 * unqualified (the runner sets search_path).
 */

#include "session_store.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

#include <algorithm> // std::max (reap anchor) — not transitively guaranteed on libc++
#include <chrono>
#include <cstdlib>

namespace yuzu::server {

using pg::exec_params;
using pg::PgResult;

namespace {

constexpr const char* kStoreName = "session_store"; // schema = snake_case(SessionStore)
constexpr std::chrono::milliseconds kWriteTimeout{2000};
constexpr std::chrono::milliseconds kReadTimeout{2000};

// Retention: substrate-tuned; copy the SHAPE from a sibling, never the numbers.
constexpr int kReapCap = 5000;                 // hard per-pass cap (always applies)
constexpr std::int64_t kMaxPlausibleSkewMs = 366LL * 24 * 3600 * 1000; // ~1y ahead of anchor = anomaly

std::int64_t to_i64(const char* s) {
    if (!s || !*s)
        return 0;
    return std::strtoll(s, nullptr, 10);
}

std::uint64_t to_u64(const char* s) {
    if (!s || !*s)
        return 0;
    return std::strtoull(s, nullptr, 10);
}

// Bump the durable write-generation IN THE CALLER'S TXN. Every authz-affecting
// mutation calls this so a replica's validate-cache sees the change on its next
// generation refresh. Mirrors RbacStore::bump_generation_in_txn.
bool bump_generation_in_txn(PGconn* c) {
    PgResult r = exec_params(
        c,
        "INSERT INTO session_store.session_meta (key, value) VALUES ('write_generation', '1') "
        "ON CONFLICT (key) DO UPDATE SET value = "
        "(session_store.session_meta.value::bigint + 1)::text",
        std::vector<std::string>{});
    return r.status() == PGRES_COMMAND_OK || r.status() == PGRES_TUPLES_OK;
}

SessionRow row_from(PGresult* res, int i) {
    SessionRow row;
    row.token_hash = PQgetvalue(res, i, 0);
    row.username = PQgetvalue(res, i, 1);
    row.display_name = PQgetvalue(res, i, 2);
    row.role = PQgetvalue(res, i, 3);
    row.auth_source = PQgetvalue(res, i, 4);
    row.oidc_sub = PQgetvalue(res, i, 5);
    row.token_scope_service = PQgetvalue(res, i, 6);
    row.mcp_tier = PQgetvalue(res, i, 7);
    row.principal_kind = PQgetvalue(res, i, 8);
    row.created_at_ms = to_i64(PQgetvalue(res, i, 9));
    row.expires_at_ms = to_i64(PQgetvalue(res, i, 10));
    row.last_activity_ms = to_i64(PQgetvalue(res, i, 11));
    row.mfa_verified_ms = to_i64(PQgetvalue(res, i, 12));
    row.elevated_until_ms = to_i64(PQgetvalue(res, i, 13));
    row.elevation_issued_ms = to_i64(PQgetvalue(res, i, 14));
    return row;
}

constexpr const char* kSelectCols =
    "token_hash, username, display_name, role, auth_source, oidc_sub, token_scope_service, "
    "mcp_tier, principal_kind, created_at_ms, expires_at_ms, last_activity_ms, mfa_verified_ms, "
    "elevated_until_ms, elevation_issued_ms";

const std::vector<pg::PgMigration>& migrations() {
    static const std::vector<pg::PgMigration> kMigrations = {
        {1,
         "CREATE TABLE sessions ("
         "  token_hash          TEXT PRIMARY KEY,"
         "  username            TEXT NOT NULL,"
         "  display_name        TEXT NOT NULL DEFAULT '',"
         "  role                TEXT NOT NULL,"
         "  auth_source         TEXT NOT NULL DEFAULT 'local',"
         "  oidc_sub            TEXT NOT NULL DEFAULT '',"
         "  token_scope_service TEXT NOT NULL DEFAULT '',"
         "  mcp_tier            TEXT NOT NULL DEFAULT '',"
         "  principal_kind      TEXT NOT NULL DEFAULT 'human',"
         "  created_at_ms       BIGINT NOT NULL,"
         "  expires_at_ms       BIGINT NOT NULL,"
         "  last_activity_ms    BIGINT NOT NULL,"
         "  mfa_verified_ms     BIGINT NOT NULL DEFAULT 0,"
         "  elevated_until_ms   BIGINT NOT NULL DEFAULT 0,"
         "  elevation_issued_ms BIGINT NOT NULL DEFAULT 0);"
         "CREATE INDEX sessions_username_idx ON sessions (username);"
         "CREATE INDEX sessions_expires_idx ON sessions (expires_at_ms);"
         "CREATE TABLE session_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);"},
    };
    return kMigrations;
}

} // namespace

SessionStore::SessionStore(pg::PgPool& pool) : pool_(pool) {
    auto lease = pool_.acquire(); // unbounded — construction ONLY
    if (!lease) {
        spdlog::error("SessionStore: no database connection at construction ({})",
                      pool_.last_error());
        return; // open_ stays false → fail closed
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("SessionStore: schema migration failed");
        return;
    }
    open_ = true;
}

std::expected<void, SessionStore::Error> SessionStore::create(const SessionRow& row) {
    if (!open_)
        return std::unexpected(Error{"session store not open"});
    if (row.token_hash.empty() || row.username.empty())
        return std::unexpected(Error{"token_hash and username are required"});

    std::string err;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        PgResult r = exec_params(
            c,
            "INSERT INTO session_store.sessions ("
            "token_hash, username, display_name, role, auth_source, oidc_sub, token_scope_service, "
            "mcp_tier, principal_kind, created_at_ms, expires_at_ms, last_activity_ms, "
            "mfa_verified_ms, elevated_until_ms, elevation_issued_ms) VALUES ("
            "$1,$2,$3,$4,$5,$6,$7,$8,$9,$10::bigint,$11::bigint,$12::bigint,$13::bigint,"
            "$14::bigint,$15::bigint) "
            "ON CONFLICT (token_hash) DO UPDATE SET "
            "username=EXCLUDED.username, display_name=EXCLUDED.display_name, role=EXCLUDED.role, "
            "auth_source=EXCLUDED.auth_source, oidc_sub=EXCLUDED.oidc_sub, "
            "token_scope_service=EXCLUDED.token_scope_service, mcp_tier=EXCLUDED.mcp_tier, "
            "principal_kind=EXCLUDED.principal_kind, created_at_ms=EXCLUDED.created_at_ms, "
            "expires_at_ms=EXCLUDED.expires_at_ms, last_activity_ms=EXCLUDED.last_activity_ms, "
            "mfa_verified_ms=EXCLUDED.mfa_verified_ms, elevated_until_ms=EXCLUDED.elevated_until_ms, "
            "elevation_issued_ms=EXCLUDED.elevation_issued_ms",
            std::vector<std::string>{row.token_hash, row.username, row.display_name, row.role,
                                     row.auth_source, row.oidc_sub, row.token_scope_service,
                                     row.mcp_tier, row.principal_kind,
                                     std::to_string(row.created_at_ms),
                                     std::to_string(row.expires_at_ms),
                                     std::to_string(row.last_activity_ms),
                                     std::to_string(row.mfa_verified_ms),
                                     std::to_string(row.elevated_until_ms),
                                     std::to_string(row.elevation_issued_ms)});
        if (r.status() != PGRES_COMMAND_OK) {
            err = std::string("session insert failed: ") + PQerrorMessage(c);
            return false;
        }
        return bump_generation_in_txn(c);
    });
    if (!ok)
        return std::unexpected(Error{err.empty() ? "create failed" : err});
    return {};
}

std::expected<bool, SessionStore::Error> SessionStore::invalidate(const std::string& token_hash) {
    if (!open_)
        return std::unexpected(Error{"session store not open"});
    bool removed = false;
    std::string err;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        PgResult r =
            exec_params(c,
                        "DELETE FROM session_store.sessions WHERE token_hash=$1 RETURNING token_hash",
                        std::vector<std::string>{token_hash});
        if (r.status() != PGRES_TUPLES_OK) {
            err = std::string("session delete failed: ") + PQerrorMessage(c);
            return false;
        }
        removed = PQntuples(r.get()) > 0;
        return bump_generation_in_txn(c);
    });
    if (!ok)
        return std::unexpected(Error{err.empty() ? "invalidate failed" : err});
    return removed;
}

std::expected<int, SessionStore::Error>
SessionStore::invalidate_user(const std::string& username) {
    if (!open_)
        return std::unexpected(Error{"session store not open"});
    int count = 0;
    std::string err;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        PgResult r = exec_params(
            c, "DELETE FROM session_store.sessions WHERE username=$1 RETURNING token_hash",
            std::vector<std::string>{username});
        if (r.status() != PGRES_TUPLES_OK) {
            err = std::string("session delete-by-user failed: ") + PQerrorMessage(c);
            return false;
        }
        count = PQntuples(r.get());
        return bump_generation_in_txn(c);
    });
    if (!ok)
        return std::unexpected(Error{err.empty() ? "invalidate_user failed" : err});
    return count;
}

std::expected<bool, SessionStore::Error>
SessionStore::set_elevation(const std::string& token_hash, std::int64_t elevated_until_ms,
                            std::int64_t elevation_issued_ms) {
    if (!open_)
        return std::unexpected(Error{"session store not open"});
    bool existed = false;
    std::string err;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        PgResult r = exec_params(
            c,
            "UPDATE session_store.sessions SET elevated_until_ms=$2::bigint, "
            "elevation_issued_ms=$3::bigint WHERE token_hash=$1 RETURNING token_hash",
            std::vector<std::string>{token_hash, std::to_string(elevated_until_ms),
                                     std::to_string(elevation_issued_ms)});
        if (r.status() != PGRES_TUPLES_OK) {
            err = std::string("set_elevation failed: ") + PQerrorMessage(c);
            return false;
        }
        existed = PQntuples(r.get()) > 0;
        return bump_generation_in_txn(c);
    });
    if (!ok)
        return std::unexpected(Error{err.empty() ? "set_elevation failed" : err});
    return existed;
}

std::expected<bool, SessionStore::Error>
SessionStore::clear_elevation(const std::string& token_hash) {
    if (!open_)
        return std::unexpected(Error{"session store not open"});
    bool existed = false;
    std::string err;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        PgResult r = exec_params(c,
                                 "UPDATE session_store.sessions SET elevated_until_ms=0, "
                                 "elevation_issued_ms=0 WHERE token_hash=$1 RETURNING token_hash",
                                 std::vector<std::string>{token_hash});
        if (r.status() != PGRES_TUPLES_OK) {
            err = std::string("clear_elevation failed: ") + PQerrorMessage(c);
            return false;
        }
        existed = PQntuples(r.get()) > 0;
        return bump_generation_in_txn(c);
    });
    if (!ok)
        return std::unexpected(Error{err.empty() ? "clear_elevation failed" : err});
    return existed;
}

std::expected<int, SessionStore::Error>
SessionStore::clear_user_elevations(const std::string& username) {
    if (!open_)
        return std::unexpected(Error{"session store not open"});
    int count = 0;
    std::string err;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        PgResult r = exec_params(
            c,
            "UPDATE session_store.sessions SET elevated_until_ms=0, elevation_issued_ms=0 "
            "WHERE username=$1 AND elevated_until_ms<>0 RETURNING token_hash",
            std::vector<std::string>{username});
        if (r.status() != PGRES_TUPLES_OK) {
            err = std::string("clear_user_elevations failed: ") + PQerrorMessage(c);
            return false;
        }
        count = PQntuples(r.get());
        return bump_generation_in_txn(c);
    });
    if (!ok)
        return std::unexpected(Error{err.empty() ? "clear_user_elevations failed" : err});
    return count;
}

std::expected<bool, SessionStore::Error> SessionStore::mark_mfa(const std::string& token_hash,
                                                                std::int64_t mfa_verified_ms) {
    if (!open_)
        return std::unexpected(Error{"session store not open"});
    bool existed = false;
    std::string err;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        PgResult r = exec_params(
            c,
            "UPDATE session_store.sessions SET mfa_verified_ms=$2::bigint WHERE token_hash=$1 "
            "RETURNING token_hash",
            std::vector<std::string>{token_hash, std::to_string(mfa_verified_ms)});
        if (r.status() != PGRES_TUPLES_OK) {
            err = std::string("mark_mfa failed: ") + PQerrorMessage(c);
            return false;
        }
        existed = PQntuples(r.get()) > 0;
        return bump_generation_in_txn(c);
    });
    if (!ok)
        return std::unexpected(Error{err.empty() ? "mark_mfa failed" : err});
    return existed;
}

std::expected<bool, SessionStore::Error>
SessionStore::touch_activity(const std::string& token_hash, std::int64_t last_activity_ms) {
    if (!open_)
        return std::unexpected(Error{"session store not open"});
    // NO generation bump — a sliding idle update is not an authz change, and
    // bumping here would invalidate every replica's cache on every request.
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(Error{"database unavailable"});
    PgResult r = exec_params(
        lease.get(),
        "UPDATE session_store.sessions SET last_activity_ms=$2::bigint WHERE token_hash=$1 "
        "RETURNING token_hash",
        std::vector<std::string>{token_hash, std::to_string(last_activity_ms)});
    if (r.status() != PGRES_TUPLES_OK)
        return std::unexpected(Error{std::string("touch_activity failed: ") +
                                     PQerrorMessage(lease.get())});
    return PQntuples(r.get()) > 0;
}

std::expected<std::optional<SessionRow>, SessionStore::Error>
SessionStore::find(const std::string& token_hash) const {
    if (!open_)
        return std::unexpected(Error{"session store not open"});
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(Error{"database unavailable"});
    PgResult r = exec_params(lease.get(),
                             (std::string("SELECT ") + kSelectCols +
                              " FROM session_store.sessions WHERE token_hash=$1")
                                 .c_str(),
                             std::vector<std::string>{token_hash});
    if (r.status() != PGRES_TUPLES_OK)
        return std::unexpected(Error{std::string("find failed: ") + PQerrorMessage(lease.get())});
    if (PQntuples(r.get()) == 0)
        return std::optional<SessionRow>{}; // definitively absent
    return std::optional<SessionRow>{row_from(r.get(), 0)};
}

std::expected<std::uint64_t, SessionStore::Error> SessionStore::read_generation() const {
    if (!open_)
        return std::unexpected(Error{"session store not open"});
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(Error{"database unavailable"});
    PgResult r = exec_params(
        lease.get(),
        "SELECT value FROM session_store.session_meta WHERE key='write_generation'",
        std::vector<std::string>{});
    if (r.status() != PGRES_TUPLES_OK)
        return std::unexpected(Error{std::string("read_generation failed: ") +
                                     PQerrorMessage(lease.get())});
    if (PQntuples(r.get()) == 0)
        return std::uint64_t{0}; // no mutation has happened yet
    return to_u64(PQgetvalue(r.get(), 0, 0));
}

std::expected<int, SessionStore::Error> SessionStore::reap_expired(std::int64_t now_ms) {
    if (!open_)
        return std::unexpected(Error{"session store not open"});

    // Clock-guarded, single-writer across replicas. The advisory lock is taken as
    // its OWN statement before the check-and-delete (a CTE-embedded lock does not
    // work — fixed-snapshot hazard). now_ms is the caller's wall clock; it is
    // sanitised against a durable anchor in session_meta so a forward-skewed
    // reading (an already-wrong clock on the pass that matters) is DECLINED, not
    // acted on. Every accepted pass is unconditionally capped.
    //
    // Part-6 (missing-anchor) DECISION, recorded per the clock-guarded-retention
    // rule: on the FIRST pass (no `reap_anchor_ms` yet) this store PROCEEDS to
    // delete rather than declining — ResultSetStore's answer, not audit_store's.
    // Rationale: a session is REGENERABLE via re-login, so the worst case of a
    // from-boot forward-skewed clock on that first pass is a mass early logout
    // (annoying, self-healing), never the loss of non-reproducible compliance
    // evidence that makes audit_store/Guardian decline. Part-1 (would-wipe) is
    // deliberately NOT probed for the same reason api_token_store omits it:
    // sessions reach 100% expiry as routine drain, so a would-wipe verdict cannot
    // separate a true from a false positive here. The magnitude guard
    // (kMaxPlausibleSkewMs) still declines a later implausibly-forward reading.
    int deleted = 0;
    std::string err;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        if (exec_params(c, "SELECT pg_advisory_xact_lock(hashtext('session_store:reap'))",
                        std::vector<std::string>{})
                .status() != PGRES_TUPLES_OK) {
            err = "reap advisory lock failed";
            return false;
        }
        // Persisted anchor = the max now_ms any prior pass accepted. A reading
        // implausibly far ahead of it is an anomaly: decline this pass, do not
        // advance the anchor (part 2/3 — compare against a PERSISTED reading,
        // sanitise it).
        PgResult ar = exec_params(
            c, "SELECT value FROM session_store.session_meta WHERE key='reap_anchor_ms'",
            std::vector<std::string>{});
        if (ar.status() != PGRES_TUPLES_OK) {
            err = "reap anchor read failed";
            return false;
        }
        const bool has_anchor = PQntuples(ar.get()) > 0;
        const std::int64_t anchor = has_anchor ? to_i64(PQgetvalue(ar.get(), 0, 0)) : 0;
        if (has_anchor && now_ms > anchor + kMaxPlausibleSkewMs) {
            spdlog::warn("SessionStore::reap declined: now_ms {} implausibly ahead of anchor {}",
                         now_ms, anchor);
            return true; // decline (commit the no-op lock release), anchor unchanged
        }
        // Accepted pass: capped delete of absolutely-expired sessions.
        PgResult dr = exec_params(
            c,
            "DELETE FROM session_store.sessions WHERE token_hash IN "
            "(SELECT token_hash FROM session_store.sessions WHERE expires_at_ms < $1::bigint "
            "LIMIT $2::bigint) RETURNING token_hash",
            std::vector<std::string>{std::to_string(now_ms), std::to_string(kReapCap)});
        if (dr.status() != PGRES_TUPLES_OK) {
            err = std::string("reap delete failed: ") + PQerrorMessage(c);
            return false;
        }
        deleted = PQntuples(dr.get());
        const std::int64_t new_anchor = has_anchor ? std::max(anchor, now_ms) : now_ms;
        PgResult ur = exec_params(
            c,
            "INSERT INTO session_store.session_meta (key, value) VALUES ('reap_anchor_ms', $1) "
            "ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value",
            std::vector<std::string>{std::to_string(new_anchor)});
        if (ur.status() != PGRES_COMMAND_OK) {
            err = "reap anchor update failed";
            return false;
        }
        return true;
    });
    if (!ok)
        return std::unexpected(Error{err.empty() ? "reap failed" : err});
    return deleted;
}

} // namespace yuzu::server
