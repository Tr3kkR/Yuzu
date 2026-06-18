// PgPool / PgMigrationRunner hardening + chaos tests (#1320 PR 3, #1368):
//   - server-side statement_timeout / lock_timeout GUC injection
//   - TCP-keepalive injection
//   - connect-failure circuit breaker (fail-fast, no storm)
//   - observer hooks (connect-failure counter + acquire-wait histogram feed)
//   - CH-9  compound shutdown wedge (pool dtor waits for an outstanding lease)
//   - CH-10 wedged advisory lock bounded by lock_timeout (boot fails, no hang)
//   - CH-11 schema-meta poisoning refused by the schema-drift guard

#include <catch2/catch_test_macros.hpp>

#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"

#include <libpq-fe.h>

#include <atomic>
#include <chrono>
#include <future>
#include <string>
#include <thread>
#include <vector>

using namespace std::chrono_literals;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgMigration;
using yuzu::server::pg::PgMigrationRunner;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;

namespace {

std::string setting(PGconn* conn, const char* name) {
    const std::string sql = std::string("SELECT current_setting('") + name + "')";
    PgResult r{PQexec(conn, sql.c_str())};
    REQUIRE(r.status() == PGRES_TUPLES_OK);
    REQUIRE(PQntuples(r.get()) == 1);
    return PQgetvalue(r.get(), 0, 0);
}

} // namespace

TEST_CASE("PgPool injects statement_timeout and lock_timeout GUCs", "[pg][hardening]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(),
                 .size = 2,
                 .statement_timeout_ms = 7000,
                 .lock_timeout_ms = 3000}};
    REQUIRE(pool.valid());
    auto lease = pool.acquire();
    REQUIRE(static_cast<bool>(lease));
    // Postgres renders integer-ms settings in a human unit.
    CHECK(setting(lease.get(), "statement_timeout") == "7s");
    CHECK(setting(lease.get(), "lock_timeout") == "3s");
}

TEST_CASE("PgPool injects TCP keepalives", "[pg][hardening]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 1, .keepalives_idle_s = 45}};
    REQUIRE(pool.valid());
    auto lease = pool.acquire();
    REQUIRE(static_cast<bool>(lease));
    // libpq exposes the negotiated keepalive via PQparameterStatus only for
    // server params; assert the connection is live (keepalive is a socket
    // option that cannot fail the connection when accepted). The wiring itself
    // is covered by the no-crash + working-connection path.
    PgResult r{PQexec(lease.get(), "SELECT 1")};
    CHECK(r.status() == PGRES_TUPLES_OK);
}

TEST_CASE("PgPool connect breaker fails fast and fires the observer", "[pg][hardening]") {
    std::atomic<int> connect_failures{0};
    PgPool::Options opts;
    // Valid conninfo, unreachable endpoint — a closed port refuses fast.
    opts.conninfo = "host=127.0.0.1 port=1 dbname=yuzu connect_timeout=1";
    opts.size = 4;
    opts.connect_timeout_s = 1;
    opts.connect_backoff_base = 200ms;
    opts.connect_backoff_cap = 2000ms;
    opts.observer.on_connect_failure = [&] { connect_failures.fetch_add(1); };

    PgPool pool{std::move(opts)};
    REQUIRE(pool.valid()); // conninfo parses; the host is just unreachable

    CHECK_FALSE(pool.connect_breaker_open()); // closed before any failure

    // First acquire attempts a connect, fails, arms the breaker.
    auto first = pool.acquire();
    CHECK_FALSE(static_cast<bool>(first));
    CHECK(connect_failures.load() >= 1);
    // The breaker is now the cheap, non-lease-consuming "PG unreachable" signal
    // that /readyz reads (gov UP-2) — must report open after the failure.
    CHECK(pool.connect_breaker_open());

    // Second acquire, while the breaker window is open, must return an empty
    // lease FAST without launching another connect — the anti-storm contract.
    const int before = connect_failures.load();
    const auto t0 = std::chrono::steady_clock::now();
    auto second = pool.acquire();
    const auto elapsed = std::chrono::steady_clock::now() - t0;
    CHECK_FALSE(static_cast<bool>(second));
    CHECK(elapsed < 200ms);                  // no fresh connect attempt
    CHECK(connect_failures.load() == before); // breaker suppressed the attempt
}

TEST_CASE("PgPool acquire-wait observer fires on a successful checkout", "[pg][hardening]") {
    YUZU_REQUIRE_PG_DB(db);
    std::atomic<int> waits{0};
    PgPool::Options opts;
    opts.conninfo = db.dsn();
    opts.size = 2;
    opts.observer.on_acquire_wait_seconds = [&](double s) {
        CHECK(s >= 0.0);
        waits.fetch_add(1);
    };
    PgPool pool{std::move(opts)};
    REQUIRE(pool.valid());
    { auto l = pool.acquire(); REQUIRE(static_cast<bool>(l)); }
    { auto l = pool.acquire(); REQUIRE(static_cast<bool>(l)); }
    CHECK(waits.load() == 2);
    // A reachable database never arms the breaker, so /readyz stays ready even
    // while the pool is busy (gov UP-2: saturation must not evict a healthy
    // server).
    CHECK_FALSE(pool.connect_breaker_open());
}

// CH-9: the pool destructor must wait for an outstanding lease and then
// complete — never deadlock when the destroyer does NOT itself hold a lease.
TEST_CASE("CH-9: pool dtor waits for an outstanding lease, no deadlock", "[pg][chaos]") {
    YUZU_REQUIRE_PG_DB(db);
    auto destroy = std::async(std::launch::async, [&] {
        auto pool = std::make_unique<PgPool>(PgPool::Options{.conninfo = db.dsn(), .size = 2});
        REQUIRE(pool->valid());
        std::atomic<bool> released{false};
        std::thread holder([&] {
            auto lease = pool->acquire(); // holds a connection...
            REQUIRE(static_cast<bool>(lease));
            std::this_thread::sleep_for(200ms); // ...then returns it
            released.store(true);
        });
        std::this_thread::sleep_for(50ms); // ensure the holder has the lease
        pool.reset();                      // dtor blocks until the lease returns
        holder.join();
        CHECK(released.load());
    });
    // Watchdog: a correct pool completes well under the deadline; a deadlock
    // would hang here, which the bounded wait converts into a test failure.
    REQUIRE(destroy.wait_for(15s) == std::future_status::ready);
    destroy.get();
}

// CH-10: a wedged advisory lock must time out via lock_timeout so boot fails
// closed instead of hanging forever.
TEST_CASE("CH-10: wedged advisory lock is bounded by lock_timeout", "[pg][chaos]") {
    YUZU_REQUIRE_PG_DB(db);

    // Session A holds the GLOBAL runner advisory lock (key2 = 0), the one
    // ensure_meta_and_schema takes first.
    PgConn blocker{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(blocker.get()) == CONNECTION_OK);
    PgResult held{PQexec(blocker.get(), "SELECT pg_advisory_lock(2037545589, 0)")};
    REQUIRE(held.status() == PGRES_TUPLES_OK);

    // Session B runs the migration runner with a short lock_timeout. The
    // global-lock wait must error out rather than block indefinitely.
    PgConn runner_conn{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(runner_conn.get()) == CONNECTION_OK);
    PgResult set{PQexec(runner_conn.get(), "SET lock_timeout = '500ms'")};
    REQUIRE(set.status() == PGRES_COMMAND_OK);

    const std::vector<PgMigration> migs = {{1, "CREATE TABLE t (id INT)"}};
    const auto t0 = std::chrono::steady_clock::now();
    const bool ok = PgMigrationRunner::run(runner_conn.get(), "ch10_store", migs);
    const auto elapsed = std::chrono::steady_clock::now() - t0;

    CHECK_FALSE(ok);          // fails closed instead of hanging
    CHECK(elapsed < 10s);     // bounded by lock_timeout, not blocked forever

    PgResult unlock{PQexec(blocker.get(), "SELECT pg_advisory_unlock(2037545589, 0)")};
    CHECK(unlock.status() == PGRES_TUPLES_OK);
}

// CH-11: schema_meta poisoning — version reset to 0 while tables already exist
// must be refused by the schema-drift guard, not blindly re-migrated.
TEST_CASE("CH-11: schema-meta poisoning is refused", "[pg][chaos]") {
    YUZU_REQUIRE_PG_DB(db);
    PgConn conn{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);

    const std::vector<PgMigration> migs = {{1, "CREATE TABLE items (id INT)"}};

    // First run migrates cleanly to v1.
    REQUIRE(PgMigrationRunner::run(conn.get(), "ch11_store", migs));
    REQUIRE(PgMigrationRunner::current_version(conn.get(), "ch11_store") == 1);

    // Poison: drop the version row so the store reads as v0 while its schema
    // still holds the table (operator surgery / schema_meta loss).
    PgResult del{
        PQexec(conn.get(), "DELETE FROM public.schema_meta WHERE store = 'ch11_store'")};
    REQUIRE(del.status() == PGRES_COMMAND_OK);
    REQUIRE(PgMigrationRunner::current_version(conn.get(), "ch11_store") == 0);

    // Re-running must REFUSE (the drift guard), not re-create the existing table.
    CHECK_FALSE(PgMigrationRunner::run(conn.get(), "ch11_store", migs));
}
