/**
 * test_session_store.cpp -- SessionStore (HA WS-1/1a) behaviour tests.
 *
 * Behaviour cases use the pre-migrated template (YUZU_REQUIRE_PG_DB_TPL); the
 * fresh-migrate / fail-closed cases use YUZU_REQUIRE_PG_MIGRATION_DB. All behind
 * YUZU_TEST_ENABLE_PG (server suite only) — skipped when the DSN is unset.
 */

#include "session_store.hpp"

#include "pg/pg_pool.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <string>

using namespace yuzu::server;
using yuzu::server::pg::PgPool;

namespace {

std::int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

SessionRow make_row(std::string hash, std::string user, std::int64_t now) {
    SessionRow r;
    r.token_hash = std::move(hash);
    r.username = std::move(user);
    r.display_name = "Test User";
    r.role = "admin";
    r.auth_source = "local";
    r.principal_kind = "human";
    r.created_at_ms = now;
    r.expires_at_ms = now + 8 * 3600 * 1000; // +8h
    r.last_activity_ms = now;
    return r;
}

// Setup constructs the store (runs the migration), then closes all conns.
yuzu::test::PgTestTemplate session_store_tpl{"sessstore", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    SessionStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("session_store template: store failed to migrate");
}};

} // namespace

TEST_CASE("SessionStore: create → find round-trips every field", "[session_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, session_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SessionStore store{pool};
    REQUIRE(store.is_open());

    const auto now = now_ms();
    auto row = make_row("hash-abc", "alice", now);
    row.oidc_sub = "sub-123";
    row.mcp_tier = "operator";
    row.mfa_verified_ms = now;

    REQUIRE(store.create(row).has_value());

    auto got = store.find("hash-abc");
    REQUIRE(got.has_value());          // no DB error
    REQUIRE(got->has_value());         // present
    CHECK((*got)->username == "alice");
    CHECK((*got)->role == "admin");
    CHECK((*got)->oidc_sub == "sub-123");
    CHECK((*got)->mcp_tier == "operator");
    CHECK((*got)->expires_at_ms == row.expires_at_ms);
    CHECK((*got)->mfa_verified_ms == now);

    // A definitively-absent read is nullopt, NOT an error (type-distinguishable).
    auto missing = store.find("nope");
    REQUIRE(missing.has_value());
    CHECK_FALSE(missing->has_value());
}

TEST_CASE("SessionStore: mutations bump the durable generation; touch does not",
          "[session_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, session_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SessionStore store{pool};
    REQUIRE(store.is_open());
    const auto now = now_ms();

    auto g0 = store.read_generation();
    REQUIRE(g0.has_value());

    REQUIRE(store.create(make_row("h1", "bob", now)).has_value());
    auto g1 = store.read_generation();
    REQUIRE(g1.has_value());
    CHECK(*g1 > *g0); // create bumped

    REQUIRE(store.mark_mfa("h1", now).has_value());
    auto g2 = store.read_generation();
    REQUIRE(*g2 > *g1); // mfa bumped

    // touch_activity is a sliding update — must NOT bump the generation.
    REQUIRE(store.touch_activity("h1", now + 1000).has_value());
    auto g3 = store.read_generation();
    REQUIRE(g3.has_value());
    CHECK(*g3 == *g2);
}

TEST_CASE("SessionStore: elevation set/clear and per-user clear", "[session_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, session_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SessionStore store{pool};
    REQUIRE(store.is_open());
    const auto now = now_ms();

    REQUIRE(store.create(make_row("h1", "carol", now)).has_value());
    REQUIRE(store.create(make_row("h2", "carol", now)).has_value());

    auto set = store.set_elevation("h1", now + 600'000, now);
    REQUIRE(set.has_value());
    CHECK(*set); // existed
    auto row = store.find("h1");
    CHECK((*row)->elevated_until_ms == now + 600'000);
    CHECK((*row)->elevation_issued_ms == now);

    // set on a missing session returns existed=false, not an error.
    auto missing = store.set_elevation("nope", now + 1, now);
    REQUIRE(missing.has_value());
    CHECK_FALSE(*missing);

    // clear per-user clears every elevated session for that user.
    REQUIRE(store.set_elevation("h2", now + 600'000, now).has_value());
    auto cleared = store.clear_user_elevations("carol");
    REQUIRE(cleared.has_value());
    CHECK(*cleared == 2);
    CHECK((*store.find("h1"))->elevated_until_ms == 0);
}

TEST_CASE("SessionStore: invalidate one and per-user", "[session_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, session_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SessionStore store{pool};
    REQUIRE(store.is_open());
    const auto now = now_ms();

    REQUIRE(store.create(make_row("h1", "dave", now)).has_value());
    REQUIRE(store.create(make_row("h2", "dave", now)).has_value());
    REQUIRE(store.create(make_row("h3", "erin", now)).has_value());

    auto one = store.invalidate("h1");
    REQUIRE(one.has_value());
    CHECK(*one);
    CHECK_FALSE(store.find("h1")->has_value()); // gone

    auto n = store.invalidate_user("dave");
    REQUIRE(n.has_value());
    CHECK(*n == 1); // only h2 remained for dave
    CHECK(store.find("h3")->has_value()); // erin untouched
}

TEST_CASE("SessionStore: reap deletes only absolutely-expired sessions",
          "[session_store][pg][retention]") {
    YUZU_REQUIRE_PG_DB_TPL(db, session_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SessionStore store{pool};
    REQUIRE(store.is_open());
    const auto now = now_ms();

    auto live = make_row("live", "frank", now); // expires_at = now + 8h
    auto dead = make_row("dead", "frank", now);
    dead.expires_at_ms = now - 1000; // already expired
    REQUIRE(store.create(live).has_value());
    REQUIRE(store.create(dead).has_value());

    auto reaped = store.reap_expired(now);
    REQUIRE(reaped.has_value());
    CHECK(*reaped == 1);
    CHECK(store.find("live")->has_value());
    CHECK_FALSE(store.find("dead")->has_value());
}

TEST_CASE("SessionStore: reap declines an implausibly-forward clock reading",
          "[session_store][pg][retention]") {
    YUZU_REQUIRE_PG_DB_TPL(db, session_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SessionStore store{pool};
    REQUIRE(store.is_open());
    const auto now = now_ms();

    auto dead = make_row("dead", "gina", now);
    dead.expires_at_ms = now - 1000;
    REQUIRE(store.create(dead).has_value());

    // First pass at a sane clock anchors it.
    REQUIRE(store.reap_expired(now).has_value());

    auto dead2 = make_row("dead2", "gina", now);
    dead2.expires_at_ms = now - 1000;
    REQUIRE(store.create(dead2).has_value());

    // A wildly-forward reading (well beyond the plausible-skew bound) is declined:
    // the pass must NOT delete under an anomalous clock.
    auto reaped = store.reap_expired(now + 2LL * 366 * 24 * 3600 * 1000);
    REQUIRE(reaped.has_value());
    CHECK(*reaped == 0);
    CHECK(store.find("dead2")->has_value()); // survived the declined pass
}
