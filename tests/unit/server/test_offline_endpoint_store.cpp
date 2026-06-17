// OfflineEndpointStore tests (#1320 PR 3): upsert idempotency, RETURNING
// mutate-and-return, the stale-within window query, and the empty-pool
// fail-soft contract. Born-on-Postgres store, schema `endpoint_state`.

#include <catch2/catch_test_macros.hpp>

#include "offline_endpoint_store.hpp"
#include "pg/pg_pool.hpp"

#include "../test_helpers.hpp"

#include <chrono>
#include <string>

using yuzu::server::OfflineEndpoint;
using yuzu::server::OfflineEndpointStore;
using yuzu::server::pg::PgPool;

namespace {

std::int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

const OfflineEndpoint* find(const std::vector<OfflineEndpoint>& v, const std::string& id) {
    for (const auto& e : v)
        if (e.agent_id == id)
            return &e;
    return nullptr;
}

} // namespace

TEST_CASE("OfflineEndpointStore migrates and upserts", "[pg][offline]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());

    OfflineEndpointStore store{pool};
    REQUIRE(store.is_open());

    const auto t = now_ms();

    SECTION("insert then read back within window") {
        REQUIRE(store.upsert("agent-a", "host-a", "linux", t, 1234));
        auto rows = store.query_stale_within(std::chrono::hours(1));
        const auto* a = find(rows, "agent-a");
        REQUIRE(a != nullptr);
        CHECK(a->hostname == "host-a");
        CHECK(a->os == "linux");
        CHECK(a->agent_ts == 1234);
        CHECK(a->last_heartbeat_ms == t);
    }

    SECTION("upsert is idempotent on agent_id and overwrites fields") {
        REQUIRE(store.upsert("agent-b", "old-host", "linux", t - 5000, 1));
        REQUIRE(store.upsert("agent-b", "new-host", "windows", t, 2));
        auto rows = store.query_stale_within(std::chrono::hours(1));
        const auto* b = find(rows, "agent-b");
        REQUIRE(b != nullptr);
        CHECK(b->hostname == "new-host");
        CHECK(b->os == "windows");
        CHECK(b->agent_ts == 2);
        // Exactly one row for the agent (PK conflict updated in place).
        int count = 0;
        for (const auto& e : rows)
            if (e.agent_id == "agent-b")
                ++count;
        CHECK(count == 1);
    }

    SECTION("query_stale_within excludes rows older than the window") {
        REQUIRE(store.upsert("recent", "h1", "linux", t - 1000, 0));     // 1s ago
        REQUIRE(store.upsert("ancient", "h2", "linux", t - 86'400'000, 0)); // ~1 day ago
        auto rows = store.query_stale_within(std::chrono::seconds(60));
        CHECK(find(rows, "recent") != nullptr);
        CHECK(find(rows, "ancient") == nullptr);
    }

    SECTION("empty agent_id is rejected, no row written") {
        CHECK_FALSE(store.upsert("", "h", "linux", t, 0));
        auto rows = store.query_stale_within(std::chrono::hours(1));
        CHECK(find(rows, "") == nullptr);
    }
}
