/**
 * test_scope_walking_authz.cpp — cross-operator authorization for the
 * `from_result_set:` scope kind (scope-walking review finding B1).
 *
 * AgentRegistry::evaluate_scope must resolve `from_result_set:<id>` ONLY for a
 * dispatching principal that owns the set. An operator who learns another
 * operator's rs_ id and embeds it in a scope expression must target ZERO of
 * that set's devices (the IDOR the review blocked merge on). The owner check
 * lives in the preload step (ResultSetStore::member_set_owned), scoped to the
 * principal threaded into evaluate_scope; an empty principal (the untracked
 * raw-dispatch path with no operator) resolves nothing.
 */

#include "agent_registry.hpp"
#include "event_bus.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "result_set_store.hpp"
#include "scope_engine.hpp"
#include "scope_yaml.hpp"

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>

#include "../test_helpers.hpp"

#include "agent.pb.h"

#include <libpq-fe.h>

#include <algorithm>
#include <stdexcept>
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

// ResultSetStore is now a migrated Postgres store (ADR-0036) — shares the
// "resultset" template key with test_result_set_store.cpp (identical setup).
yuzu::test::PgTestTemplate result_set_tpl{"resultset", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    ResultSetStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("resultset template: store failed to migrate");
}};

} // namespace

TEST_CASE("evaluate_scope: from_result_set is owner-scoped (no cross-operator targeting)",
          "[pg][scope][result_set][authz]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);
    REQUIRE(store.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    registry.register_agent(info("agent-win"));
    registry.register_agent(info("agent-lin"));

    // Alice curates a set containing only one of the two connected agents.
    CreateRequest cr;
    cr.owner_principal = "alice";
    cr.name = "alice-suspects";
    cr.source_kind = std::string(source_kind::kManualCurate);
    cr.source_payload = "{}";
    auto set = store.create_materialized(cr, {"agent-win"});
    REQUIRE(set.has_value());

    auto expr = yuzu::scope::parse("from_result_set:" + set->id);
    REQUIRE(expr.has_value());

    SECTION("owner resolves exactly the set's members") {
        auto matched = registry.evaluate_scope(*expr, /*tag_store=*/nullptr,
                                               /*props_store=*/nullptr, &store, "alice");
        REQUIRE(matched.has_value()); // no preload degrade (ADR-0036)
        REQUIRE(matched->size() == 1);
        CHECK(has(*matched, "agent-win"));
        CHECK_FALSE(has(*matched, "agent-lin")); // not a broadcast
    }

    SECTION("a non-owner targets nothing — IDOR blocked (review B1)") {
        auto matched = registry.evaluate_scope(*expr, nullptr, nullptr, &store, "bob");
        REQUIRE(matched.has_value());
        CHECK(matched->empty());
    }

    SECTION("empty principal (untracked raw-dispatch path) resolves nothing") {
        auto matched = registry.evaluate_scope(*expr, nullptr, nullptr, &store, "");
        REQUIRE(matched.has_value());
        CHECK(matched->empty());
    }

    SECTION("an unknown result-set id resolves to nothing — fail-closed, not match-all (UP-14)") {
        auto e2 = yuzu::scope::parse("from_result_set:rs_does_not_exist");
        REQUIRE(e2.has_value());
        auto matched = registry.evaluate_scope(*e2, nullptr, nullptr, &store, "alice");
        REQUIRE(matched.has_value());
        CHECK(matched->empty());
    }
}

// ── Dispatch-time alias resolution (PR-E) ────────────────────────────────────

TEST_CASE("resolve_scope_aliases: rewrites owner aliases, leaves ids/non-owners",
          "[pg][scope][result_set][authz]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);
    REQUIRE(store.is_open());

    CreateRequest cr;
    cr.owner_principal = "alice";
    cr.name = "alice-suspects"; // per-operator alias
    cr.source_kind = std::string(source_kind::kManualCurate);
    cr.source_payload = "{}";
    auto set = store.create_materialized(cr, {"agent-win"});
    REQUIRE(set.has_value());
    const std::string canonical = "from_result_set:" + set->id;

    SECTION("owner alias is rewritten to the canonical id") {
        CHECK(resolve_scope_aliases("from_result_set:alice-suspects", "alice", &store) == canonical);
    }
    SECTION("composition: only the ref atom is rewritten") {
        CHECK(resolve_scope_aliases("from_result_set:alice-suspects AND ostype == \"windows\"",
                                    "alice", &store) == canonical + " AND ostype == \"windows\"");
    }
    SECTION("two refs: the alias resolves, a canonical rs_ id passes through") {
        CHECK(resolve_scope_aliases(
                  "from_result_set:alice-suspects AND from_result_set:" + set->id, "alice",
                  &store) == canonical + " AND " + canonical);
    }
    SECTION("a canonical rs_ id passes through untouched") {
        CHECK(resolve_scope_aliases(canonical, "alice", &store) == canonical);
    }
    SECTION("a non-owner's alias does not resolve (left as-is, no-matches downstream)") {
        CHECK(resolve_scope_aliases("from_result_set:alice-suspects", "bob", &store) ==
              "from_result_set:alice-suspects");
    }
    SECTION("empty owner is a no-op") {
        CHECK(resolve_scope_aliases("from_result_set:alice-suspects", "", &store) ==
              "from_result_set:alice-suspects");
    }
    SECTION("an alias inside a quoted literal is never rewritten") {
        const std::string e = "hostname == \"from_result_set:alice-suspects\"";
        CHECK(resolve_scope_aliases(e, "alice", &store) == e);
    }
}

TEST_CASE("scope_refs_failing_owner_check: flags absent/unowned, not empty-but-owned",
          "[pg][scope][result_set][authz]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);
    REQUIRE(store.is_open());

    CreateRequest cr;
    cr.owner_principal = "alice";
    cr.source_kind = std::string(source_kind::kManualCurate);
    cr.source_payload = "{}";
    auto owned = store.create_materialized(cr, {"agent-win"});
    REQUIRE(owned.has_value());
    auto empty_owned = store.create_materialized(cr, {}); // owned, zero members
    REQUIRE(empty_owned.has_value());

    SECTION("an owned, non-empty set is not flagged") {
        auto f = scope_refs_failing_owner_check("from_result_set:" + owned->id, "alice", &store);
        REQUIRE(f.has_value());
        CHECK(f->empty());
    }
    SECTION("an owned but legitimately empty set is not flagged") {
        auto f =
            scope_refs_failing_owner_check("from_result_set:" + empty_owned->id, "alice", &store);
        REQUIRE(f.has_value());
        CHECK(f->empty());
    }
    SECTION("an absent id is flagged") {
        auto f = scope_refs_failing_owner_check("from_result_set:rs_does_not_exist", "alice", &store);
        REQUIRE(f.has_value());
        REQUIRE(f->size() == 1);
        CHECK((*f)[0] == "rs_does_not_exist");
    }
    SECTION("another operator's id is flagged (not owned)") {
        auto f = scope_refs_failing_owner_check("from_result_set:" + owned->id, "bob", &store);
        REQUIRE(f.has_value());
        REQUIRE(f->size() == 1);
        CHECK((*f)[0] == owned->id);
    }
    SECTION("mixed owned + absent: only the absent ref is flagged") {
        auto f = scope_refs_failing_owner_check(
            "from_result_set:" + owned->id + " AND from_result_set:rs_ghost", "alice", &store);
        REQUIRE(f.has_value());
        REQUIRE(f->size() == 1);
        CHECK((*f)[0] == "rs_ghost");
    }
    SECTION("empty owner yields no findings (no owner context)") {
        auto f = scope_refs_failing_owner_check("from_result_set:" + owned->id, "", &store);
        REQUIRE(f.has_value());
        CHECK(f->empty());
    }
}

// ── ADR-0036 fail-closed regression: a degraded store must ABORT, never ─────
// ── silently expand a NOT-inverted scope to the whole fleet.             ────
//
// The concrete vulnerability this guards: a `NOT from_result_set:<id>` scope
// resolves the atom to "" (no match) for every agent NOT in the (possibly
// empty/degraded) preloaded membership set, and NOT inverts "no match" to
// "match" — so a membership preload that silently came back empty because of
// a transient Postgres error (not because the set is genuinely empty) used to
// make every connected agent match. `evaluate_scope` must instead return
// `std::nullopt` the instant the preload can't be trusted, so the dispatch
// layer aborts (503) rather than sending to "everyone".
TEST_CASE("evaluate_scope: a degraded result-set store ABORTS — never expands a "
          "NOT-inverted scope to the whole fleet",
          "[pg][scope][result_set][authz][failclosed]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);
    REQUIRE(store.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    registry.register_agent(info("agent-win"));
    registry.register_agent(info("agent-lin"));

    CreateRequest cr;
    cr.owner_principal = "alice";
    cr.source_kind = std::string(source_kind::kManualCurate);
    cr.source_payload = "{}";
    auto set = store.create_materialized(cr, {"agent-win"});
    REQUIRE(set.has_value());

    // Simulate a Postgres-side degrade: drop the table `member_set_owned`
    // queries out from under the live store — a reproducible stand-in for a
    // transient connection loss / botched migration, without needing to kill
    // the whole pool (which would also fail is_open()-style checks upstream
    // and hide the specific regression this test targets: a QUERY failure
    // once the store believes it is open).
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult r{PQexec(conn.get(), "DROP TABLE result_set_store.result_set_members CASCADE")};
        REQUIRE(r.ok());
    }

    SECTION("NOT from_result_set:<id> aborts rather than matching every agent") {
        auto expr = yuzu::scope::parse("NOT from_result_set:" + set->id);
        REQUIRE(expr.has_value());
        auto matched = registry.evaluate_scope(*expr, nullptr, nullptr, &store, "alice");
        // The regression this test exists to catch: pre-fix, a degraded
        // preload silently produced an EMPTY (but present) membership map,
        // so `matched` would come back holding EVERY registered agent under
        // the NOT combinator. Post-fix, degrade is type-distinguishable —
        // std::nullopt — so a caller can never mistake this for "0 matches"
        // or, worse, silently dispatch to `*matched` at all.
        REQUIRE_FALSE(matched.has_value());
    }

    SECTION("the plain (non-NOT) form also aborts, never a false empty match") {
        auto expr = yuzu::scope::parse("from_result_set:" + set->id);
        REQUIRE(expr.has_value());
        auto matched = registry.evaluate_scope(*expr, nullptr, nullptr, &store, "alice");
        REQUIRE_FALSE(matched.has_value());
    }
}
