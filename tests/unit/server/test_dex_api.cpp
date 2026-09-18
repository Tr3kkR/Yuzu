/**
 * test_dex_api.cpp — the FIFTH per-family in-process API seam for the
 * presentation/core/engine split (ADR-0031, WS-A4), copying the
 * `verify_api`/`test_verify_api.cpp` template. `LocalDexApi` (dex_api.cpp) is
 * the DEX signals/experience-score assembly moved behind the `DexApi` seam:
 * the 9 builder-backed resources forward to the shared `build_dex_*_model`
 * helpers (deriving `since`/`fleet` internally), and the 3 builder-less ones
 * (signals/scope/signal_detail) make the same raw store reads the handler
 * assembled inline. Each case asserts the seam is behaviour-preserving —
 * PARITY with the direct builder/store read it wraps — plus the null-store
 * degrade. Reached only through the public `DexApi` interface + the
 * `make_local_dex_api` factory, exactly as a real presentation/MCP caller
 * will use it (`LocalDexApi` is private to dex_api.cpp).
 */

#include "dex_api_local.hpp"

#include "dex_read_model.hpp"          // build_dex_*_model parity oracles
#include "dex_routes.hpp"              // dex_iso_since / dex_window_to_days
#include "guaranteed_state_store.hpp"  // seed + direct-read parity oracles
#include "pg/pg_pool.hpp"

#include "../test_helpers.hpp"

#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>

using yuzu::server::build_dex_device_score_model;
using yuzu::server::DexFleet;
using yuzu::server::GuaranteedStateEventRow;
using yuzu::server::GuaranteedStateStore;
using yuzu::server::make_local_dex_api;
using yuzu::server::pg::PgPool;

namespace {

yuzu::test::PgTestTemplate dex_api_tpl{"dexapi", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    GuaranteedStateStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("dexapi template: store failed to migrate");
}};

void seed_crash(GuaranteedStateStore& store, const std::string& id, const std::string& agent,
                const std::string& proc, const std::string& plat, const std::string& ts) {
    GuaranteedStateEventRow e;
    e.event_id = id;
    e.rule_id = "__observation__";
    e.agent_id = agent;
    e.event_type = "process.crashed";
    e.severity = "info";
    e.detail_json = "{\"subject\":\"" + proc + "\",\"reason\":\"0xC0000005\",\"symbolic\":"
                    "\"ACCESS_VIOLATION\",\"component\":\"ntdll.dll\",\"platform\":\"" + plat +
                    "\"}";
    e.timestamp = ts;
    REQUIRE(store.insert_event(e));
}

// Seed dates anchored a few days back from *now* so they stay inside the
// default 7d window (same rationale as test_dex_routes.cpp's kDayA/kDayB).
const std::string kTs = yuzu::server::dex_iso_since(2).substr(0, 10) + "T12:00:00Z";

} // namespace

TEST_CASE("DexApi: null store is the honest degrade, never a throw", "[pg][dex_api]") {
    // The macro gates on PG availability (skip locally when unset), but this
    // case exercises the null-store path — no seeding needed.
    YUZU_REQUIRE_PG_DB_TPL(db, dex_api_tpl);
    auto api = make_local_dex_api(/*store=*/nullptr, /*fleet_fn=*/{});

    CHECK(api->signals("7d", "").empty());
    CHECK(api->scope("7d").empty());
    const auto detail = api->signal_detail("process.crashed", "7d", "", 50);
    CHECK(detail.subjects.empty());
    CHECK(detail.by_os.empty());
    CHECK(detail.devices.empty());
    CHECK(detail.by_day.empty());
    // Builder-backed degrade: score unavailable, empty model — never a crash.
    CHECK(api->device_score("a1", "7d").score == -1);
    CHECK(api->apps("7d").apps.empty());
}

TEST_CASE("DexApi: signals/scope/signal_detail match the direct store reads", "[pg][dex_api]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dex_api_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    seed_crash(store, "e1", "a1", "notepad.exe", "windows", kTs);
    seed_crash(store, "e2", "a2", "notepad.exe", "windows", kTs);

    auto api = make_local_dex_api(&store, {});
    const std::string since = yuzu::server::dex_iso_since(yuzu::server::dex_window_to_days("7d"));

    // signals == store.dex_signal_summary(since, "")
    const auto via_api = api->signals("7d", "");
    const auto via_store = store.dex_signal_summary(since, "");
    REQUIRE(via_api.size() == via_store.size());
    REQUIRE_FALSE(via_api.empty());
    CHECK(via_api.front().obs_type == via_store.front().obs_type);
    CHECK(via_api.front().count == via_store.front().count);
    CHECK(via_api.front().distinct_devices == via_store.front().distinct_devices);

    // scope == store.dex_os_signal_scope(since)
    CHECK(api->scope("7d").size() == store.dex_os_signal_scope(since).size());

    // signal_detail bundles the four raw reads unchanged
    const auto detail = api->signal_detail("process.crashed", "7d", "", 50);
    CHECK(detail.subjects.size() == store.dex_signal_subjects("process.crashed", since, 50, "").size());
    CHECK(detail.devices.size() == store.dex_signal_devices("process.crashed", since, 50, "").size());
    CHECK(detail.by_day.size() == store.dex_signal_by_day("process.crashed", since, "").size());
    // notepad.exe crashed on two devices -> the most-affected list names both
    CHECK(detail.devices.size() == 2);
}

TEST_CASE("DexApi: device_score matches the shared builder (seam is a pure forward)",
          "[pg][dex_api]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dex_api_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    seed_crash(store, "e1", "a1", "notepad.exe", "windows", kTs);

    auto api = make_local_dex_api(&store, {});
    const std::string since = yuzu::server::dex_iso_since(yuzu::server::dex_window_to_days("7d"));

    const auto via_api = api->device_score("a1", "7d");
    const auto via_builder = build_dex_device_score_model(&store, "a1", "7d", since);
    CHECK(via_api.agent_id == via_builder.agent_id);
    CHECK(via_api.window == via_builder.window);
    CHECK(via_api.score == via_builder.score);
    CHECK(via_api.signals.size() == via_builder.signals.size());
}

TEST_CASE("DexApi: fleet-dependent reads use the injected FleetFn", "[pg][dex_api]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dex_api_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());

    // A non-empty fleet denominator flows through health()/trends()/overview();
    // an empty FleetFn degrades to DexFleet{} (the honest no-data denominator).
    bool fleet_called = false;
    auto api = make_local_dex_api(&store, [&]() -> DexFleet {
        fleet_called = true;
        return DexFleet{1, 1, {"windows"}};
    });
    (void)api->overview("7d", /*visible=*/nullptr);
    CHECK(fleet_called); // the seam obtains the fleet from the injected FleetFn
}
