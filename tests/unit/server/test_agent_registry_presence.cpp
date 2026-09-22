// HA WS-5 (ADR-2002 §7a) — cross-replica presence merge into
// AgentRegistry::all_ids()/evaluate_scope(). A live OfflineEndpointStore is
// the presence source; register_agent alone simulates the LOCAL registry, a
// direct OfflineEndpointStore::upsert() (with no matching register_agent)
// simulates an agent connected to a DIFFERENT replica.

#include <catch2/catch_test_macros.hpp>

#include "agent_registry.hpp"
#include "event_bus.hpp"
#include "offline_endpoint_store.hpp"
#include "pg/pg_pool.hpp"
#include "scope_engine.hpp"

#include "../test_helpers.hpp"

#include <yuzu/metrics.hpp>

#include <algorithm>
#include <chrono>
#include <stdexcept>
#include <string>

using yuzu::server::detail::AgentRegistry;
using yuzu::server::detail::EventBus;
using yuzu::server::OfflineEndpointStore;
using yuzu::server::pg::PgPool;

namespace agent_pb = ::yuzu::agent::v1;

namespace {

agent_pb::AgentInfo make_agent_info(const std::string& id, const std::string& os,
                                    const std::string& hostname) {
    agent_pb::AgentInfo a;
    a.set_agent_id(id);
    a.set_hostname(hostname);
    a.mutable_platform()->set_os(os);
    a.mutable_platform()->set_arch("x86_64");
    a.set_agent_version("0.13.0");
    return a;
}

yuzu::test::PgTestTemplate presence_tpl{"agent_presence", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    OfflineEndpointStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("agent_presence template: store failed to migrate");
}};

bool contains(const std::vector<std::string>& v, const std::string& id) {
    return std::find(v.begin(), v.end(), id) != v.end();
}

} // namespace

TEST_CASE("HA WS-5: all_ids() merges live presence for a remote-only agent", "[pg][ha][presence]") {
    YUZU_REQUIRE_PG_DB_TPL(db, presence_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    OfflineEndpointStore store{pool};
    REQUIRE(store.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    (void)registry.register_agent(make_agent_info("local-agent", "linux", "local-host"));

    SECTION("unconfigured presence: byte-identical to pre-WS-5 local-only behavior") {
        REQUIRE(store.upsert("remote-agent", "remote-host", "windows",
                             /*last_heartbeat_ms=*/0, /*agent_ts=*/0, "1.0.0", "x86_64",
                             "sess-remote"));
        auto ids = registry.all_ids();
        CHECK(contains(ids, "local-agent"));
        CHECK_FALSE(contains(ids, "remote-agent")); // presence never consulted
        CHECK(registry.local_agent_count() == ids.size());
    }

    SECTION("configured presence: a remote-only live row is merged in") {
        registry.configure_presence(&store, std::chrono::hours(1));
        REQUIRE(store.upsert("remote-agent", "remote-host", "windows", 0, 0, "1.0.0", "x86_64",
                             "sess-remote"));
        auto ids = registry.all_ids();
        CHECK(contains(ids, "local-agent"));
        CHECK(contains(ids, "remote-agent"));
        // local_agent_count() never includes presence, by construction.
        CHECK(registry.local_agent_count() == 1);
        CHECK(ids.size() == 2);
    }

    SECTION("local always wins: an id in BOTH is never duplicated") {
        registry.configure_presence(&store, std::chrono::hours(1));
        REQUIRE(store.upsert("local-agent", "stale-host-from-presence", "windows", 0, 0, "9.9.9",
                             "arm64", "sess-x"));
        auto ids = registry.all_ids();
        CHECK(std::count(ids.begin(), ids.end(), "local-agent") == 1);
        CHECK(ids.size() == 1);
    }

    SECTION("presence outside the TTL window is not merged") {
        registry.configure_presence(&store, std::chrono::seconds(0));
        REQUIRE(store.upsert("remote-agent", "remote-host", "windows", 0, 0, "", "", ""));
        auto ids = registry.all_ids();
        CHECK_FALSE(contains(ids, "remote-agent"));
    }
}

TEST_CASE("HA WS-5: evaluate_scope resolves a remote-only agent's identity attributes",
          "[pg][ha][presence]") {
    YUZU_REQUIRE_PG_DB_TPL(db, presence_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    OfflineEndpointStore store{pool};
    REQUIRE(store.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    registry.configure_presence(&store, std::chrono::hours(1));
    (void)registry.register_agent(make_agent_info("local-agent", "linux", "local-host"));
    REQUIRE(store.upsert("remote-agent", "remote-host", "windows", 0, 0, "2.0.0", "arm64",
                         "sess-remote"));

    SECTION("ostype matches the presence-sourced value") {
        auto parsed = yuzu::scope::parse(R"(ostype == "windows")");
        REQUIRE(parsed.has_value());
        auto matched = registry.evaluate_scope(*parsed, nullptr);
        REQUIRE(matched.has_value());
        CHECK(contains(*matched, "remote-agent"));
        CHECK_FALSE(contains(*matched, "local-agent"));
    }

    SECTION("hostname/arch/agent_version all resolve for a presence-only id") {
        auto parsed = yuzu::scope::parse(
            R"((hostname == "remote-host") AND (arch == "arm64") AND (agent_version == "2.0.0"))");
        REQUIRE(parsed.has_value());
        auto matched = registry.evaluate_scope(*parsed, nullptr);
        REQUIRE(matched.has_value());
        CHECK(contains(*matched, "remote-agent"));
    }

    SECTION("a predicate matching neither agent returns an empty (non-null) result") {
        auto parsed = yuzu::scope::parse(R"(hostname == "nobody-here")");
        REQUIRE(parsed.has_value());
        auto matched = registry.evaluate_scope(*parsed, nullptr);
        REQUIRE(matched.has_value());
        CHECK(matched->empty());
    }
}

TEST_CASE("HA WS-5: a graceful disconnect's remove_if_session prevents zero-monolith-outcome drift",
          "[pg][ha][presence]") {
    // Simulates the decoy-row shape the WS-4 slices held themselves to: once
    // an agent is gone from BOTH the local registry (simulated here by never
    // registering it) AND presence (remove_if_session already ran), it must
    // not be resolvable via evaluate_scope — exactly the pre-WS-5 behavior
    // for a disconnected agent.
    YUZU_REQUIRE_PG_DB_TPL(db, presence_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    OfflineEndpointStore store{pool};
    REQUIRE(store.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    registry.configure_presence(&store, std::chrono::hours(1));

    REQUIRE(store.upsert("departed-agent", "h", "linux", 0, 0, "", "", "sess-departed"));
    REQUIRE(store.remove_if_session("departed-agent", "sess-departed")); // the disconnect handler's call

    auto parsed = yuzu::scope::parse(R"(ostype == "linux")");
    REQUIRE(parsed.has_value());
    auto matched = registry.evaluate_scope(*parsed, nullptr);
    REQUIRE(matched.has_value());
    CHECK_FALSE(contains(*matched, "departed-agent"));
}
