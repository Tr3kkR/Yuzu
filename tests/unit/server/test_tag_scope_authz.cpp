/**
 * test_tag_scope_authz.cpp — the ADR-0050 fail-closed contract for
 * `tag:<key>` scope-DSL resolution (AgentRegistry::evaluate_scope).
 *
 * Mirrors test_props_scope_authz.cpp's `props.<key>` degrade coverage: the
 * TagStore migration to Postgres introduced a real runtime failure mode (a
 * pool-acquire timeout, a dropped connection) where SQLite's synchronous
 * read had none, and the pre-migration resolver collapsed "no such tag" and
 * "the read failed" to the same empty string — under `NOT tag:<key>` (or
 * `!=`) a silently-empty resolution is a match, so a transient Postgres blip
 * would invert to "every agent matches" (#2500 family).
 *
 * One deliberate asymmetry vs the props contract (the resolver comment in
 * agent_registry.cpp records it): a NULL tag_store with a tag: atom does NOT
 * abort, because session->scopable_tags is a first-class in-memory source
 * that legitimately answers tag: atoms without any store. A DEGRADED
 * (non-null, failing) store still aborts.
 */

#include "agent_registry.hpp"
#include "event_bus.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "scope_engine.hpp"
#include "tag_store.hpp"

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>

#include "../test_helpers.hpp"
#include "test_tag_store_pg_helper.hpp"

#include "agent.pb.h"

#include <libpq-fe.h>

#include <algorithm>
#include <string>
#include <vector>

using namespace yuzu::server;
using yuzu::server::detail::AgentRegistry;
using yuzu::server::detail::EventBus;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;
namespace agent_pb = ::yuzu::agent::v1;

namespace {

agent_pb::AgentInfo info(const std::string& id) {
    agent_pb::AgentInfo a;
    a.set_agent_id(id);
    a.set_hostname(id + ".local");
    return a;
}

bool has(const std::vector<std::string>& v, const std::string& id) {
    return std::find(v.begin(), v.end(), id) != v.end();
}

} // namespace

TEST_CASE("evaluate_scope: tag:<key> resolves preloaded store values",
          "[pg][scope][tag_store][authz]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::tag_store_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    TagStore store(pool);
    REQUIRE(store.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    registry.register_agent(info("agent-win"));
    registry.register_agent(info("agent-lin"));

    REQUIRE(store.set_tag("agent-win", "env", "prod").has_value());
    REQUIRE(store.set_tag("agent-lin", "env", "staging").has_value());

    SECTION("matches only the agent with the tag value") {
        auto expr = yuzu::scope::parse(R"(tag:env == "prod")");
        REQUIRE(expr.has_value());
        auto matched = registry.evaluate_scope(*expr, &store, /*props_store=*/nullptr);
        REQUIRE(matched.has_value());
        REQUIRE(matched->size() == 1);
        CHECK(has(*matched, "agent-win"));
        CHECK_FALSE(has(*matched, "agent-lin"));
    }

    SECTION("in-memory scopable_tags shadow the store row (pre-existing precedence, preserved)") {
        auto shadowed = info("agent-shadow");
        (*shadowed.mutable_scopable_tags())["env"] = "prod";
        registry.register_agent(shadowed);
        REQUIRE(store.set_tag("agent-shadow", "env", "staging").has_value());

        auto expr = yuzu::scope::parse(R"(tag:env == "prod")");
        REQUIRE(expr.has_value());
        auto matched = registry.evaluate_scope(*expr, &store, nullptr);
        REQUIRE(matched.has_value());
        CHECK(has(*matched, "agent-shadow")); // in-memory "prod" wins over store "staging"
    }

    SECTION("a scope with no tag: atom triggers no preload") {
        auto expr = yuzu::scope::parse(R"(ostype == "")");
        REQUIRE(expr.has_value());
        auto matched = registry.evaluate_scope(*expr, &store, nullptr);
        REQUIRE(matched.has_value());
    }
}

// The concrete vulnerability this guards: a `NOT tag:<key>` scope resolves
// the atom to "" (no match) for every agent whose tag couldn't be read
// because of a transient Postgres error, and NOT inverts "no match" to
// "match" — so a degraded preload would make every connected agent match.
// evaluate_scope must instead return std::nullopt the instant the preload
// can't be trusted (mirrors the props.<key>/from_result_set: contract).
TEST_CASE("evaluate_scope: a degraded TagStore ABORTS — never expands a NOT-inverted tag: "
          "scope to the whole fleet",
          "[pg][scope][tag_store][authz][failclosed]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::tag_store_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    TagStore store(pool);
    REQUIRE(store.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    registry.register_agent(info("agent-win"));
    registry.register_agent(info("agent-lin"));

    REQUIRE(store.set_tag("agent-win", "env", "prod").has_value());

    // Simulate a Postgres-side degrade: drop the table the preload queries
    // out from under the live store (same mechanism as
    // test_props_scope_authz.cpp — a QUERY failure once the store believes
    // it is open).
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult r{PQexec(conn.get(), "DROP TABLE tag_store.tags CASCADE")};
        REQUIRE(r.ok());
    }

    SECTION("NOT tag:<key> aborts rather than matching every agent") {
        auto expr = yuzu::scope::parse(R"(NOT tag:env == "prod")");
        REQUIRE(expr.has_value());
        auto matched = registry.evaluate_scope(*expr, &store, nullptr);
        // Pre-fix (per-agent get_tag collapsing degrade to ""), `matched`
        // would come back holding EVERY registered agent under NOT.
        REQUIRE_FALSE(matched.has_value());
    }

    SECTION("the plain (non-NOT) form also aborts, never a false empty match") {
        auto expr = yuzu::scope::parse(R"(tag:env == "prod")");
        REQUIRE(expr.has_value());
        auto matched = registry.evaluate_scope(*expr, &store, nullptr);
        REQUIRE_FALSE(matched.has_value());
    }
}

// The deliberate asymmetry vs props.<key>: no store at all is NOT a degrade —
// tags have a first-class in-memory source (scopable_tags) that answers tag:
// atoms without one. In production the store cannot be null post-migration
// (fatal at boot); this is the test/embedded configuration.
TEST_CASE("evaluate_scope: tag:<key> with a NULL TagStore resolves from in-memory "
          "scopable_tags alone (no abort — deliberate asymmetry vs props.<key>)",
          "[scope][tag_store][authz]") {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);

    auto tagged = info("agent-mem");
    (*tagged.mutable_scopable_tags())["env"] = "prod";
    registry.register_agent(tagged);
    registry.register_agent(info("agent-bare"));

    auto expr = yuzu::scope::parse(R"(tag:env == "prod")");
    REQUIRE(expr.has_value());
    auto matched = registry.evaluate_scope(*expr, /*tag_store=*/nullptr, nullptr);
    REQUIRE(matched.has_value());
    REQUIRE(matched->size() == 1);
    CHECK(has(*matched, "agent-mem"));

    // NOT form still evaluates (in-memory answers are trustworthy — there is
    // no store whose failure could be hiding).
    auto not_expr = yuzu::scope::parse(R"(NOT tag:env == "prod")");
    REQUIRE(not_expr.has_value());
    auto not_matched = registry.evaluate_scope(*not_expr, nullptr, nullptr);
    REQUIRE(not_matched.has_value());
    CHECK(has(*not_matched, "agent-bare"));
    CHECK_FALSE(has(*not_matched, "agent-mem"));
}
