// PreflightRunStore tests (#governance Gate-7 quality-B1): the OWNER-SCOPE
// security boundary (list/get/delete), the create→persist→complete→prune
// lifecycle + FK cascade, and the complete_run no-op contract. Born-on-Postgres
// store, schema `preflight_run_store`. PG-gated: skips when YUZU_TEST_POSTGRES_DSN
// is unset, fails when it is set but broken.

#include <catch2/catch_test_macros.hpp>

#include "pg/pg_pool.hpp"
#include "preflight_run_store.hpp"

#include "../test_helpers.hpp"

#include <chrono>
#include <string>

using yuzu::server::PreflightRunDeviceRow;
using yuzu::server::PreflightRunRow;
using yuzu::server::PreflightRunStore;
using yuzu::server::pg::PgPool;
using yuzu::server::preflight::PreflightTarget;

namespace {

std::int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

PreflightRunRow make_run(const std::string& id, const std::string& owner, std::int64_t created) {
    PreflightRunRow r;
    r.run_id = id;
    r.execution_id = "preflight-" + id;
    r.created_by = owner;
    r.name = "test " + id;
    r.scope_label = "all visible devices";
    r.config_json = R"({"app_name":"","min_gib":20})";
    r.window_seconds = 300;
    r.created_at_ms = created;
    r.deadline_at_ms = created + 300000;
    r.status = "running";
    return r;
}

PreflightTarget tgt(const std::string& aid) { return {aid, "host-" + aid, "windows"}; }

} // namespace

TEST_CASE("PreflightRunStore owner-scope boundary", "[pg][preflight][store]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    PreflightRunStore store{pool};
    REQUIRE(store.is_open());

    const auto t = now_ms();
    REQUIRE(store.create_run(make_run("rA", "alice", t), {tgt("a1"), tgt("a2")}));
    REQUIRE(store.create_run(make_run("rB", "bob", t), {tgt("b1")}));

    SECTION("list_runs is owner-scoped; admin sees all") {
        auto alice = store.list_runs("alice", /*is_admin=*/false, 50);
        REQUIRE(alice.size() == 1);
        CHECK(alice[0].run_id == "rA");
        auto bob = store.list_runs("bob", false, 50);
        REQUIRE(bob.size() == 1);
        CHECK(bob[0].run_id == "rB");
        auto admin = store.list_runs("anyone", /*is_admin=*/true, 50);
        CHECK(admin.size() >= 2); // sees both
    }

    SECTION("get_run owner-scope = no existence oracle") {
        CHECK(store.get_run("rA", "alice").has_value());     // owner sees it
        CHECK_FALSE(store.get_run("rA", "bob").has_value()); // not-yours → nullopt (== not-found)
        CHECK_FALSE(store.get_run("nope", "alice").has_value());
        CHECK(store.get_run("rA").has_value()); // unscoped (internal) still works
    }

    SECTION("delete_run is owner-scoped at the seam; cascades run_device") {
        // Wrong owner: no-op, row + its devices survive.
        CHECK_FALSE(store.delete_run("rA", "bob"));
        CHECK(store.get_run("rA").has_value());
        CHECK(store.get_targets("rA").size() == 2);
        // Correct owner: deletes, run_device cascades.
        CHECK(store.delete_run("rA", "alice"));
        CHECK_FALSE(store.get_run("rA").has_value());
        CHECK(store.get_devices("rA").empty()); // FK ON DELETE CASCADE
        CHECK(store.get_targets("rA").empty());
    }
}

TEST_CASE("PreflightRunStore lifecycle: create→persist→complete→prune", "[pg][preflight][store]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    PreflightRunStore store{pool};
    REQUIRE(store.is_open());

    const auto t = now_ms();
    REQUIRE(store.create_run(make_run("rL", "carol", t), {tgt("c1"), tgt("c2")}));

    SECTION("seeded targets read back; grid persists; complete is gated + no-op-safe") {
        // Seeded run_device rows are 'inc' with no checks yet.
        auto seeded = store.get_devices("rL");
        REQUIRE(seeded.size() == 2);
        CHECK(seeded[0].bucket == "inc");

        // persist a computed grid + summary in one txn.
        std::vector<PreflightRunDeviceRow> grid = {
            {"c1", "host-c1", "windows", "go", R"([{"key":"disk","v":0,"val":"x"}])", t},
            {"c2", "host-c2", "windows", "nogo", R"([{"key":"disk","v":1,"val":"y"}])", t},
        };
        REQUIRE(store.persist_grid("rL", grid, 2, 1, 0, 1, 0));
        auto after = store.get_devices("rL");
        REQUIRE(after.size() == 2);
        // verify the computed bucket round-tripped
        bool saw_go = false, saw_nogo = false;
        for (const auto& d : after) {
            saw_go |= (d.bucket == "go");
            saw_nogo |= (d.bucket == "nogo");
        }
        CHECK(saw_go);
        CHECK(saw_nogo);
        auto row = store.get_run("rL");
        REQUIRE(row);
        CHECK(row->go == 1);
        CHECK(row->nogo == 1);

        // complete_run: real transition true; repeat / unknown = false (no-op contract).
        CHECK(store.complete_run("rL", t));
        CHECK_FALSE(store.complete_run("rL", t));     // already complete
        CHECK_FALSE(store.complete_run("ghost", t));  // unknown run
        auto done = store.get_run("rL");
        REQUIRE(done);
        CHECK(done->status == "complete");
    }

    SECTION("prune removes old runs + cascades") {
        const auto old_t = t - 100000;
        REQUIRE(store.create_run(make_run("rOld", "carol", old_t), {tgt("o1")}));
        int n = store.prune_older_than(t - 50000); // cutoff between old and new
        CHECK(n >= 1);
        CHECK_FALSE(store.get_run("rOld").has_value());
        CHECK(store.get_devices("rOld").empty()); // cascaded
        CHECK(store.get_run("rL").has_value());    // newer run survives
    }
}
