#include "leader_elector.hpp"

#include "pg/pg_exec.hpp"

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

#include <charconv>
#include <cctype>

namespace yuzu::server {

namespace {

/// A leadership lock name must be a strict lowercase identifier so it can be
/// embedded in the advisory-key SQL expression without an injection risk (the
/// key SQL is a literal handed to Postgres' `hashtext`, not a bound parameter).
bool is_valid_lock_name(const std::string& name) {
    if (name.empty() || name.size() > 48)
        return false;
    if (!(name[0] >= 'a' && name[0] <= 'z'))
        return false;
    for (char c : name) {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
        if (!ok)
            return false;
    }
    return true;
}

/// Derive the session advisory-lock key for a leadership name. `classid` is a
/// fixed constant naming the leader-elector key namespace (distinct from the
/// KEK-op lock's `2037545589`); `objid` is `hashtext('leader:<name>')`. An
/// invalid name falls back to the default key so the embedded SQL literal is
/// always a validated identifier — the elector refuses to open on an invalid
/// name anyway, so the fallback key is never actually used to lead.
pg::PgAdvisoryLockKey make_lock_key(const std::string& name) {
    const std::string safe = is_valid_lock_name(name) ? name : kServerBackgroundLeaderLock;
    return pg::PgAdvisoryLockKey::pair("1735291205", "hashtext('leader:" + safe + "')");
}

/// Parse a Postgres bigint text value. Returns nullopt on any parse failure.
std::optional<std::int64_t> parse_i64(const char* s) {
    if (s == nullptr)
        return std::nullopt;
    std::int64_t v = 0;
    const char* end = s + std::strlen(s);
    auto [p, ec] = std::from_chars(s, end, v);
    if (ec != std::errc{} || p != end)
        return std::nullopt;
    return v;
}

} // namespace

const std::vector<pg::PgMigration>& LeaderElector::migrations() {
    // Slice 3.1: the fenced-leadership registry only. The transactional command
    // outbox (slice 3.3) is deliberately NOT created here — its column set must
    // be designed against ADR-1007's `ConfinedDispatchOutcome`/`not_sent`, so
    // freezing its schema now would risk a needless re-migration.
    static const std::vector<pg::PgMigration> kMigrations = {
        {1,
         "CREATE SEQUENCE IF NOT EXISTS leader_epoch_seq AS bigint;"
         "CREATE TABLE leader_state ("
         "  lock_key             TEXT PRIMARY KEY,"
         "  current_leader_epoch BIGINT NOT NULL,"
         "  holder_id            TEXT NOT NULL,"
         "  acquired_at          TIMESTAMPTZ NOT NULL DEFAULT now()"
         ");"},
    };
    return kMigrations;
}

LeaderElector::LeaderElector(Config cfg)
    : cfg_(std::move(cfg)),
      name_valid_(is_valid_lock_name(cfg_.lock_name)),
      lock_key_(make_lock_key(cfg_.lock_name)) {
    if (!name_valid_) {
        spdlog::error("leader_elector: invalid lock_name; elector stays non-open (fail-closed)");
        return;
    }
    std::lock_guard<std::mutex> lk(mu_);
    connect_locked();
}

LeaderElector::~LeaderElector() {
    std::lock_guard<std::mutex> lk(mu_);
    // Release the advisory lock (via the guard) BEFORE the dedicated connection
    // is finished. lock_guard_ is declared after conn_, so member destruction
    // would already run in this order; reset explicitly for clarity.
    drop_leadership_locked();
}

bool LeaderElector::connect_locked() {
    // Never reassign the connection while a lock guard still references it.
    drop_leadership_locked();
    open_ = false;
    if (!name_valid_)
        return false;

    conn_ = pg::PgConn{PQconnectdb(cfg_.dsn.c_str())};
    if (conn_.get() == nullptr || PQstatus(conn_.get()) != CONNECTION_OK) {
        spdlog::warn("leader_elector: dedicated connection failed: {}",
                     conn_.get() != nullptr ? PQerrorMessage(conn_.get()) : "null conn");
        return false;
    }
    if (!pg::PgMigrationRunner::run(conn_.get(), kLeaderElectorStore, migrations())) {
        spdlog::error("leader_elector: schema migration failed; elector non-open");
        return false;
    }
    open_ = true;
    return true;
}

void LeaderElector::drop_leadership_locked() {
    lock_guard_.reset(); // runs pg_advisory_unlock on conn_ if it was held
    epoch_.reset();
}

bool LeaderElector::is_open() const {
    std::lock_guard<std::mutex> lk(mu_);
    return open_;
}

bool LeaderElector::try_acquire() {
    std::lock_guard<std::mutex> lk(mu_);
    if (!open_ && !connect_locked())
        return false;

    // Already leader: confirm the connection is live and keep the epoch.
    if (epoch_.has_value()) {
        pg::PgResult live = pg::exec_params(conn_.get(), "SELECT 1", std::vector<std::string>{});
        if (live.status() == PGRES_TUPLES_OK)
            return true;
        drop_leadership_locked();
        if (!connect_locked())
            return false;
    }

    // Attempt the session advisory lock on the owned connection.
    pg::PgResult lock_res =
        pg::exec_params(conn_.get(), lock_key_.try_lock_sql().c_str(), std::vector<std::string>{});
    if (lock_res.status() != PGRES_TUPLES_OK || PQntuples(lock_res.get()) != 1 ||
        PQgetisnull(lock_res.get(), 0, 0)) {
        spdlog::warn("leader_elector: try-lock query failed");
        return false;
    }
    if (PQgetvalue(lock_res.get(), 0, 0)[0] != 't')
        return false; // another replica holds leadership

    // Lock granted: emplace the release guard IMMEDIATELY so the lock cannot
    // leak on any subsequent failure path, then mint + record the new epoch.
    lock_guard_.emplace(conn_.get(), lock_key_, "server background leader");

    pg::PgResult ep = pg::exec_params(
        conn_.get(),
        "WITH e AS (SELECT nextval('leader_elector.leader_epoch_seq') AS ep) "
        "INSERT INTO leader_elector.leader_state "
        "  (lock_key, current_leader_epoch, holder_id, acquired_at) "
        "SELECT $1, e.ep, $2, now() FROM e "
        "ON CONFLICT (lock_key) DO UPDATE "
        "  SET current_leader_epoch = EXCLUDED.current_leader_epoch, "
        "      holder_id = EXCLUDED.holder_id, acquired_at = now() "
        "RETURNING current_leader_epoch",
        std::vector<std::string>{cfg_.lock_name, cfg_.holder_id});
    if (ep.status() != PGRES_TUPLES_OK || PQntuples(ep.get()) != 1 || PQgetisnull(ep.get(), 0, 0)) {
        spdlog::error("leader_elector: acquired lock but failed to record epoch; releasing");
        drop_leadership_locked();
        return false;
    }
    auto parsed = parse_i64(PQgetvalue(ep.get(), 0, 0));
    if (!parsed) {
        spdlog::error("leader_elector: unparseable epoch; releasing");
        drop_leadership_locked();
        return false;
    }
    epoch_ = *parsed;
    spdlog::info("leader_elector: acquired leadership '{}' at epoch {}", cfg_.lock_name, *epoch_);
    return true;
}

bool LeaderElector::is_leader() const {
    std::lock_guard<std::mutex> lk(mu_);
    return epoch_.has_value();
}

std::optional<std::int64_t> LeaderElector::epoch() const {
    std::lock_guard<std::mutex> lk(mu_);
    return epoch_;
}

bool LeaderElector::heartbeat() {
    std::lock_guard<std::mutex> lk(mu_);
    if (!epoch_.has_value())
        return false;
    pg::PgResult live = pg::exec_params(conn_.get(), "SELECT 1", std::vector<std::string>{});
    if (live.status() == PGRES_TUPLES_OK)
        return true;
    spdlog::warn("leader_elector: heartbeat failed; dropping leadership");
    drop_leadership_locked();
    connect_locked(); // best-effort reconnect so a later try_acquire can re-lead
    return false;
}

void LeaderElector::resign() {
    std::lock_guard<std::mutex> lk(mu_);
    if (epoch_.has_value())
        spdlog::info("leader_elector: resigning leadership '{}'", cfg_.lock_name);
    drop_leadership_locked();
}

bool LeaderElector::epoch_is_current(PGconn* claim_conn, const std::string& lock_name,
                                     std::int64_t expected_epoch) {
    if (claim_conn == nullptr)
        return false;
    pg::PgResult res = pg::exec_params(
        claim_conn,
        "SELECT current_leader_epoch FROM leader_elector.leader_state WHERE lock_key = $1",
        std::vector<std::string>{lock_name});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) != 1 ||
        PQgetisnull(res.get(), 0, 0))
        return false; // fail closed: no leader row, or a degraded read
    auto cur = parse_i64(PQgetvalue(res.get(), 0, 0));
    return cur.has_value() && *cur == expected_epoch;
}

} // namespace yuzu::server
