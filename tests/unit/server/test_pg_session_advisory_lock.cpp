// test_pg_session_advisory_lock.cpp — pg/pg_session_advisory_lock.hpp:
// `PgAdvisoryLockKey`'s SQL generation, and `PgSessionAdvisoryLockGuard`'s
// aborted-transaction recovery path (#2964 round 3 review finding 3).
//
// The finding this file exists to pin: a PRIOR revision of this guard's
// destructor, on a live-connection unlock-QUERY failure, went straight to
// `SELECT pg_terminate_backend(pg_backend_pid())` and claimed that was
// "correct by construction". Measured against live Postgres:
// `pg_terminate_backend(pg_backend_pid())` is ALSO an ordinary SQL
// statement, so it fails IDENTICALLY to the `pg_advisory_unlock` it was
// meant to backstop when the connection is in an ABORTED transaction — the
// lock stayed granted, the connection reported `CONNECTION_OK`, and
// `PgPool::release()` would have recycled it. The fix rolls back the aborted
// transaction (the one statement Postgres accepts in that state) and
// retries the SAME targeted unlock once before falling back to termination.
// The [pg] test below reproduces the aborted-transaction case directly and
// asserts BOTH that the lock is actually released (a second connection can
// re-acquire it) AND that the guard's own connection was NOT terminated
// (recovery succeeded without needing the last-resort kill).

#include <catch2/catch_test_macros.hpp>

#include "pg/pg_raii.hpp"
#include "pg/pg_session_advisory_lock.hpp"

#include "../test_helpers.hpp"

#include <libpq-fe.h>

#include <string>

using yuzu::server::pg::PgAdvisoryLockKey;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgResult;
using yuzu::server::pg::PgSessionAdvisoryLockGuard;

namespace {

PgConn connect(const std::string& dsn) {
    PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    return conn;
}

} // namespace

TEST_CASE("PgAdvisoryLockKey::single generates matching try-lock/unlock SQL from ONE key "
          "expression",
          "[server][pg-session-advisory-lock]") {
    const auto key = PgAdvisoryLockKey::single("hashtextextended('some:key', 0)");
    CHECK(key.try_lock_sql() ==
          "SELECT pg_try_advisory_lock(hashtextextended('some:key', 0))");
    CHECK(key.unlock_sql() == "SELECT pg_advisory_unlock(hashtextextended('some:key', 0))");
}

TEST_CASE("PgAdvisoryLockKey::pair generates matching two-argument try-lock/unlock SQL from ONE "
          "key expression pair",
          "[server][pg-session-advisory-lock]") {
    const auto key = PgAdvisoryLockKey::pair("2037545589", "hashtext('secrets_kek_op')");
    CHECK(key.try_lock_sql() ==
          "SELECT pg_try_advisory_lock(2037545589, hashtext('secrets_kek_op'))");
    CHECK(key.unlock_sql() ==
          "SELECT pg_advisory_unlock(2037545589, hashtext('secrets_kek_op'))");
}

TEST_CASE("PgSessionAdvisoryLockGuard: an unlock attempted on an ABORTED transaction rolls "
          "back and retries — the lock is actually released and the connection is NOT "
          "terminated (#2964 round 3 review finding 3)",
          "[pg][server][pg-session-advisory-lock]") {
    YUZU_REQUIRE_PG_DB(db);

    const auto key = PgAdvisoryLockKey::single(
        "hashtextextended('test:pg_session_advisory_lock:aborted-txn', 0)");

    auto holder = connect(db.dsn());

    // Take the lock, then poison the connection's transaction state exactly
    // the way the guard's destructor must recover from: BEGIN, then a
    // statement that errors, leaving the transaction ABORTED (every ordinary
    // statement other than ROLLBACK now fails at the query level).
    {
        const std::string try_lock_sql = key.try_lock_sql();
        PgResult lock_res{PQexec(holder.get(), try_lock_sql.c_str())};
        REQUIRE(lock_res.status() == PGRES_TUPLES_OK);
        REQUIRE(PQntuples(lock_res.get()) == 1);
        REQUIRE(std::string(PQgetvalue(lock_res.get(), 0, 0)) == "t");
    }
    {
        PgResult begin{PQexec(holder.get(), "BEGIN")};
        REQUIRE(begin.status() == PGRES_COMMAND_OK);
    }
    {
        // Division by zero is a query-level ERROR that aborts the
        // transaction without killing the connection.
        PgResult poison{PQexec(holder.get(), "SELECT 1/0")};
        REQUIRE(poison.status() != PGRES_TUPLES_OK);
        REQUIRE(poison.status() != PGRES_COMMAND_OK);
    }
    REQUIRE(PQtransactionStatus(holder.get()) == PQTRANS_INERROR);

    // Destroy the guard NOW, while the connection is still in the aborted
    // state — this is the exact moment the release protocol must recover
    // from.
    {
        PgSessionAdvisoryLockGuard guard{holder.get(), key, "test aborted-txn lock"};
        (void)guard;
    }

    // THE ASSERTION THIS TEST EXISTS FOR, part 1: recovery worked without
    // needing to terminate the backend — reverting the rollback+retry fix
    // (falling straight to `pg_terminate_backend`) makes this fail, because
    // that statement ALSO fails on an aborted transaction and the
    // connection would report CONNECTION_BAD or the terminate signal would
    // land on a connection libpq itself then marks bad.
    CHECK(PQstatus(holder.get()) == CONNECTION_OK);
    // The rollback leaves the connection able to run ordinary statements
    // again — proves this is a genuinely recovered, reusable connection, not
    // merely one whose PQstatus() hasn't caught up yet.
    {
        PgResult probe{PQexec(holder.get(), "SELECT 1")};
        CHECK(probe.status() == PGRES_TUPLES_OK);
    }

    // THE ASSERTION THIS TEST EXISTS FOR, part 2: the lock was ACTUALLY
    // released — a second, independent connection can acquire it
    // immediately. Reverting the fix (leaving the lock silently held because
    // the unlock query failed and was never retried) makes this fail: the
    // try-lock below would return `false`.
    auto observer = connect(db.dsn());
    const std::string observer_try_lock_sql = key.try_lock_sql();
    PgResult observer_res{PQexec(observer.get(), observer_try_lock_sql.c_str())};
    REQUIRE(observer_res.status() == PGRES_TUPLES_OK);
    REQUIRE(PQntuples(observer_res.get()) == 1);
    CHECK(std::string(PQgetvalue(observer_res.get(), 0, 0)) == "t");

    // Clean up the observer's own hold so this test leaves nothing behind.
    const std::string unlock_sql = key.unlock_sql();
    PgResult cleanup{PQexec(observer.get(), unlock_sql.c_str())};
    (void)cleanup;
}
