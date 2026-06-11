// PgPool tests (#1320 PR 1, F1 conditions ledger #2): acquire/release,
// exhaustion, failed construction, concurrent acquire + teardown, with_txn.

#include <catch2/catch_test_macros.hpp>

#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"

#include <libpq-fe.h>

#include <atomic>
#include <chrono>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace std::chrono_literals;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;

namespace {

bool select_1_works(PGconn* conn) {
    PgResult res{PQexec(conn, "SELECT 1")};
    return res.status() == PGRES_TUPLES_OK && PQntuples(res.get()) == 1;
}

} // namespace

TEST_CASE("PgPool acquire and release", "[pg][pool]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());

    SECTION("acquire yields a working connection") {
        auto lease = pool.acquire();
        REQUIRE(static_cast<bool>(lease));
        CHECK(select_1_works(lease.get()));
        CHECK(pool.in_use() == 1);
        CHECK(pool.open() == 1);
    }

    SECTION("released connections are reused, not reopened") {
        PGconn* first = nullptr;
        {
            auto lease = pool.acquire();
            REQUIRE(static_cast<bool>(lease));
            first = lease.get();
        }
        CHECK(pool.in_use() == 0);
        auto lease = pool.acquire();
        REQUIRE(static_cast<bool>(lease));
        CHECK(lease.get() == first);
        CHECK(pool.open() == 1);
    }

    SECTION("lease move transfers the return obligation") {
        auto a = pool.acquire();
        REQUIRE(static_cast<bool>(a));
        auto b = std::move(a);
        CHECK_FALSE(static_cast<bool>(a));
        CHECK(pool.in_use() == 1);
        b.reset();
        CHECK(pool.in_use() == 0);
        b.reset(); // idempotent
    }

    SECTION("a connection returned mid-transaction is rolled back") {
        {
            auto lease = pool.acquire();
            REQUIRE(static_cast<bool>(lease));
            PgResult begin{PQexec(lease.get(), "BEGIN")};
            REQUIRE(begin.ok());
        } // released without COMMIT/ROLLBACK
        auto lease = pool.acquire();
        REQUIRE(static_cast<bool>(lease));
        CHECK(PQtransactionStatus(lease.get()) == PQTRANS_IDLE);
    }
}

TEST_CASE("PgPool exhaustion", "[pg][pool]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 1}};

    auto held = pool.acquire();
    REQUIRE(static_cast<bool>(held));

    auto denied = pool.try_acquire_for(100ms);
    CHECK_FALSE(static_cast<bool>(denied));
    CHECK(pool.last_error() == "acquire timed out before a connection was available");

    // Zero timeout: the deadline-is-already-past path returns immediately.
    auto denied_now = pool.try_acquire_for(0ms);
    CHECK_FALSE(static_cast<bool>(denied_now));

    held.reset();
    auto granted = pool.try_acquire_for(1000ms);
    CHECK(static_cast<bool>(granted));
}

TEST_CASE("PgPool size 0 clamps to 1", "[pg][pool]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 0}};
    CHECK(pool.size() == 1);
    auto lease = pool.acquire();
    REQUIRE(static_cast<bool>(lease));
    CHECK(select_1_works(lease.get()));
}

TEST_CASE("PgPool failed construction", "[pg][pool]") {
    SECTION("malformed conninfo: invalid, sanitized error, empty leases") {
        // The embedded credential must never appear in the error surface
        // (F1 conditions ledger #3 — malformed-conninfo errors quote tokens).
        PgPool pool{{.conninfo = "=quohth4eeQu5 garbage =", .size = 2}};
        CHECK_FALSE(pool.valid());
        auto lease = pool.acquire();
        CHECK_FALSE(static_cast<bool>(lease));
        CHECK(pool.last_error().find("quohth4eeQu5") == std::string::npos);
        CHECK_FALSE(pool.last_error().empty());
    }

    SECTION("unreachable host: valid conninfo, acquire fails with error") {
        // Port 9 (discard) on loopback — nothing listens there in CI or dev.
        PgPool pool{{.conninfo = "host=127.0.0.1 port=9 dbname=nope "
                                 "user=nobody connect_timeout=2",
                     .size = 2}};
        CHECK(pool.valid());
        auto lease = pool.acquire();
        CHECK_FALSE(static_cast<bool>(lease));
        CHECK_FALSE(pool.last_error().empty());
        CHECK(pool.open() == 0);
        CHECK(pool.in_use() == 0);
    }
}

TEST_CASE("PgPool discards a connection lost mid-use", "[pg][pool]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};

    // Sever the leased connection server-side (the F1 ledger's
    // "connection loss mid-txn" error path), then verify the pool discards
    // it on release instead of recycling a dead handle.
    auto victim = pool.acquire();
    REQUIRE(static_cast<bool>(victim));
    const int victim_pid = PQbackendPID(victim.get());
    REQUIRE(victim_pid > 0);

    {
        auto axe = pool.acquire();
        REQUIRE(static_cast<bool>(axe));
        const std::string kill = "SELECT pg_terminate_backend(" + std::to_string(victim_pid) + ")";
        PgResult res{PQexec(axe.get(), kill.c_str())};
        REQUIRE(res.status() == PGRES_TUPLES_OK);
    }

    // pg_terminate_backend returns when the signal is SENT, not when the
    // backend has exited — poll until the client side observes the loss
    // (cross-platform hardening; the window is tiny but nonzero on a
    // native Windows service).
    bool severed = false;
    for (int i = 0; i < 100 && !severed; ++i) {
        PgResult ping{PQexec(victim.get(), "SELECT 1")};
        severed = ping.status() != PGRES_TUPLES_OK && PQstatus(victim.get()) != CONNECTION_OK;
        if (!severed)
            std::this_thread::sleep_for(50ms);
    }
    CHECK(severed);
    const std::size_t open_before = pool.open();
    victim.reset(); // ...and release must close it, not pool it
    CHECK(pool.open() == open_before - 1);

    // The freed capacity yields a fresh, working connection.
    auto replacement = pool.acquire();
    REQUIRE(static_cast<bool>(replacement));
    CHECK(select_1_works(replacement.get()));
}

TEST_CASE("PgPool concurrent acquire and teardown", "[pg][pool]") {
    YUZU_REQUIRE_PG_DB(db);

    // Each worker holds a lease — which provably keeps the destructor
    // blocked (it waits for every lease to come home) — and then issues a
    // second acquire that exhausts the pool and blocks. Tearing the pool
    // down must wake those blocked acquires with empty leases, then wait
    // for the held leases before completing. The held lease is what makes
    // this race-free: a worker's blocked acquire happens strictly before
    // its own release, and the destructor cannot return before that
    // release.
    constexpr int kWorkers = 2;
    auto pool = std::make_optional<PgPool>(PgPool::Options{.conninfo = db.dsn(), .size = kWorkers});
    REQUIRE(pool->valid());

    // Catch2 assertion macros are not thread-safe — workers only count via
    // atomics; all CHECKs happen on the main thread after join.
    std::atomic<int> holding{0};
    std::atomic<int> got_lease{0};
    std::atomic<int> woken_empty{0};
    std::atomic<bool> destroyed{false};
    std::vector<std::thread> workers;
    workers.reserve(kWorkers);
    for (int i = 0; i < kWorkers; ++i) {
        workers.emplace_back([&] {
            auto held = pool->acquire();
            if (!held) {
                ++holding; // keep the main thread's wait loop live
                return;
            }
            ++got_lease;
            ++holding;
            auto denied = pool->acquire(); // pool exhausted -> blocks here
            if (!denied)
                ++woken_empty; // woken by shutdown, not by capacity
            held.reset();      // now the destructor may finish
        });
    }

    while (holding.load() < kWorkers)
        std::this_thread::sleep_for(1ms);
    std::this_thread::sleep_for(50ms); // let the second acquires block

    std::thread destroyer{[&] {
        pool.reset();
        destroyed = true;
    }};
    for (auto& w : workers)
        w.join();
    destroyer.join();

    CHECK(destroyed.load());
    CHECK(got_lease.load() == kWorkers);
    CHECK(woken_empty.load() == kWorkers);
}

TEST_CASE("PgPool with_txn", "[pg][pool]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    {
        auto lease = pool.acquire();
        REQUIRE(static_cast<bool>(lease));
        PgResult res{PQexec(lease.get(), "CREATE TABLE t (id INT PRIMARY KEY)")};
        REQUIRE(res.ok());
    }

    auto count_rows = [&] {
        auto lease = pool.acquire();
        REQUIRE(static_cast<bool>(lease));
        PgResult res{PQexec(lease.get(), "SELECT count(*) FROM t")};
        REQUIRE(res.status() == PGRES_TUPLES_OK);
        return std::atoi(PQgetvalue(res.get(), 0, 0));
    };

    SECTION("fn true -> committed") {
        const bool ok = pool.with_txn([](PGconn* c) {
            PgResult res{PQexec(c, "INSERT INTO t (id) VALUES (1)")};
            return res.ok();
        });
        CHECK(ok);
        CHECK(count_rows() == 1);
    }

    SECTION("fn false -> rolled back") {
        const bool ok = pool.with_txn([](PGconn* c) {
            PgResult res{PQexec(c, "INSERT INTO t (id) VALUES (2)")};
            (void)res;
            return false;
        });
        CHECK_FALSE(ok);
        CHECK(count_rows() == 0);
    }

    SECTION("fn swallowing a failed statement cannot fake a commit") {
        // COMMIT on an aborted txn completes as ROLLBACK but reports
        // PGRES_COMMAND_OK — with_txn must detect PQTRANS_INERROR and
        // return false rather than trusting the callback (UP-3).
        const bool ok = pool.with_txn([](PGconn* c) {
            PgResult bad{PQexec(c, "INSERT INTO t (id) VALUES ('not an int')")};
            (void)bad; // callback "forgets" to check
            return true;
        });
        CHECK_FALSE(ok);
        CHECK(count_rows() == 0);
    }

    SECTION("fn throws -> rolled back, exception propagates, conn healthy") {
        CHECK_THROWS_AS(pool.with_txn([](PGconn* c) -> bool {
            PgResult res{PQexec(c, "INSERT INTO t (id) VALUES (3)")};
            throw std::runtime_error("boom");
        }),
                        std::runtime_error);
        CHECK(count_rows() == 0);
        // The pooled connection must come back idle and reusable.
        auto lease = pool.acquire();
        REQUIRE(static_cast<bool>(lease));
        CHECK(PQtransactionStatus(lease.get()) == PQTRANS_IDLE);
    }
}
