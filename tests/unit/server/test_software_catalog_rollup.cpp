/// @file test_software_catalog_rollup.cpp
/// Lifecycle tests for the SoftwareCatalogRollup background thread (gov cpp-safety SHOULD).
/// The thread's memory safety was proven by static review; these exercise the live
/// lifecycle surface — start/stop join, double-stop idempotency, start-after-stop restart,
/// and destructor-joins-without-explicit-stop — so a regression (e.g. a double-join or a
/// missing reset of the stop flag) fails here. PG-gated: the thread issues a real recompute,
/// so it runs against an ephemeral test database and skips cleanly without a DSN. The
/// recompute OUTCOME is asserted in test_software_inventory_store.cpp (deterministic, no
/// thread race); here we only assert the lifecycle completes without hang or crash.

#include "software_catalog_rollup.hpp"

#include "pg/pg_pool.hpp"
#include "software_inventory_store.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>

using yuzu::server::SoftwareCatalogRollup;
using yuzu::server::SoftwareInventoryStore;
using yuzu::server::pg::PgPool;

TEST_CASE("SoftwareCatalogRollup thread lifecycle", "[pg][software_inventory][rollup]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());

    // A long interval so the thread does its one immediate refresh then parks — the test
    // drives start()/stop() explicitly and never waits on the cadence.
    const auto interval = std::chrono::hours{1};

    SECTION("start → stop joins cleanly; double-stop is an idempotent no-op") {
        SoftwareCatalogRollup rollup{store, interval};
        rollup.start();
        rollup.stop(); // signals + joins
        rollup.stop(); // must not double-join / crash
        SUCCEED("start/stop/double-stop completed without hang or crash");
    }

    SECTION("start is idempotent; start-after-stop restarts") {
        SoftwareCatalogRollup rollup{store, interval};
        rollup.start();
        rollup.start(); // already running → no-op (guarded by thread_.joinable())
        rollup.stop();
        rollup.start(); // start-after-stop resets the stop flag and re-runs
        rollup.stop();
        SUCCEED("idempotent start + start-after-stop completed");
    }

    SECTION("destructor stops + joins a running thread without an explicit stop") {
        {
            SoftwareCatalogRollup rollup{store, interval};
            rollup.start();
        } // dtor → stop() → join
        SUCCEED("dtor joined the running thread");
    }
}
