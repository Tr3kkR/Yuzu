// test_leader_elector.cpp — WS-3 slice 3.1 (ADR-2002 §3/§6/§10): the fenced
// LeaderElector primitive. These [pg] tests take real Postgres backends and
// prove the four properties the fencing model rests on:
//   1. schema migrates on a fresh DB;
//   2. a single acquirer becomes leader and mints an epoch;
//   3. a second elector is REFUSED while the first holds (mutual exclusion via
//      the session advisory lock);
//   4. the epoch is strictly monotonic across a handover, and
//      `epoch_is_current()` fences a stale ex-leader's epoch (fail-closed).
// The primitive is not wired into any loop yet (slice 3.2), so nothing here
// exercises runtime dispatch — this binds the coordination primitive alone.

#include "leader_elector.hpp"

#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>

#include <string>

using yuzu::server::LeaderElector;
using yuzu::server::kServerBackgroundLeaderLock;
using yuzu::server::pg::PgConn;

namespace {

PgConn connect(const std::string& dsn) {
    PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    return conn;
}

LeaderElector::Config cfg(const std::string& dsn, std::string holder) {
    return LeaderElector::Config{.dsn = dsn, .holder_id = std::move(holder)};
}

} // namespace

TEST_CASE("LeaderElector migrates schema and starts non-leader", "[pg][store][leader-elector]") {
    YUZU_REQUIRE_PG_DB(db);
    LeaderElector e(cfg(db.dsn(), "holder-a"));
    CHECK(e.is_open());
    CHECK_FALSE(e.is_leader());
    CHECK_FALSE(e.epoch().has_value());
}

TEST_CASE("LeaderElector acquires leadership and mints an epoch", "[pg][store][leader-elector]") {
    YUZU_REQUIRE_PG_DB(db);
    LeaderElector e(cfg(db.dsn(), "holder-a"));
    REQUIRE(e.is_open());
    REQUIRE(e.try_acquire());
    CHECK(e.is_leader());
    REQUIRE(e.epoch().has_value());
    CHECK(*e.epoch() >= 1);
    // Re-acquire while already leader keeps the same epoch (liveness re-check).
    const auto first = *e.epoch();
    REQUIRE(e.try_acquire());
    CHECK(*e.epoch() == first);
}

TEST_CASE("LeaderElector refuses a second elector while the first holds",
          "[pg][store][leader-elector]") {
    YUZU_REQUIRE_PG_DB(db);
    LeaderElector a(cfg(db.dsn(), "holder-a"));
    LeaderElector b(cfg(db.dsn(), "holder-b"));
    REQUIRE(a.is_open());
    REQUIRE(b.is_open());

    REQUIRE(a.try_acquire());
    CHECK(a.is_leader());

    // b cannot lead while a holds the session advisory lock.
    CHECK_FALSE(b.try_acquire());
    CHECK_FALSE(b.is_leader());
    CHECK_FALSE(b.epoch().has_value());
}

TEST_CASE("LeaderElector epoch is strictly monotonic across handover",
          "[pg][store][leader-elector]") {
    YUZU_REQUIRE_PG_DB(db);
    LeaderElector a(cfg(db.dsn(), "holder-a"));
    LeaderElector b(cfg(db.dsn(), "holder-b"));
    REQUIRE(a.try_acquire());
    const auto e1 = *a.epoch();

    a.resign();
    CHECK_FALSE(a.is_leader());
    CHECK_FALSE(a.epoch().has_value());

    REQUIRE(b.try_acquire());
    const auto e2 = *b.epoch();
    CHECK(e2 > e1); // a strictly higher epoch than the resigned leader

    // a re-acquiring after b resigns mints a still-higher epoch.
    b.resign();
    REQUIRE(a.try_acquire());
    CHECK(*a.epoch() > e2);
}

TEST_CASE("epoch_is_current fences a stale ex-leader epoch (fail-closed)",
          "[pg][store][leader-elector]") {
    YUZU_REQUIRE_PG_DB(db);
    const std::string lock_name = kServerBackgroundLeaderLock;
    auto observer = connect(db.dsn()); // an ordinary (non-owning) connection, like a claim conn

    LeaderElector a(cfg(db.dsn(), "holder-a"));
    LeaderElector b(cfg(db.dsn(), "holder-b"));
    REQUIRE(a.try_acquire());
    const auto e_a = *a.epoch();

    // The current leader's epoch passes; a lower (stale) epoch fails.
    CHECK(LeaderElector::epoch_is_current(observer.get(), lock_name, e_a));
    CHECK_FALSE(LeaderElector::epoch_is_current(observer.get(), lock_name, e_a - 1));

    // Handover: a resigns, b takes over with a higher epoch. a's old epoch is
    // now stale and must be rejected — the paused-ex-leader guarantee.
    a.resign();
    REQUIRE(b.try_acquire());
    const auto e_b = *b.epoch();
    REQUIRE(e_b > e_a);
    CHECK_FALSE(LeaderElector::epoch_is_current(observer.get(), lock_name, e_a));
    CHECK(LeaderElector::epoch_is_current(observer.get(), lock_name, e_b));
}

TEST_CASE("epoch_is_current fails closed when no leader row exists",
          "[pg][store][leader-elector]") {
    YUZU_REQUIRE_PG_DB(db);
    // Construct an elector only to run the migration (creates leader_state), but
    // never acquire — so the table exists with no row.
    LeaderElector e(cfg(db.dsn(), "holder-a"));
    REQUIRE(e.is_open());
    auto observer = connect(db.dsn());
    CHECK_FALSE(
        LeaderElector::epoch_is_current(observer.get(), kServerBackgroundLeaderLock, 1));
}
