/**
 * test_rbac_admin_predicate.cpp — Unit tests for
 * `rbac_admin_predicate.hpp`'s `is_rbac_administrator` / `is_self_target`
 * (A2, `.claude/plans/rbac-industry-leading-DELIVERY-PLAN.md` §2).
 *
 * Covers: the RBAC-off durable-AuthDB-reread branch, the RBAC-on
 * principal_roles branch, the four deliberate scope decisions documented at
 * the header (no JIT elevation, no group-held Administrator, structural
 * service-scope/engine-session denial), and every `kUnavailable` fail-closed
 * path (null store, degraded read).
 *
 * PG-gated: RbacStore AND AuthDB are both born-on-Postgres (ADR-0006).
 * Independent databases (mirrors test_rest_access_review.cpp's
 * AuthDbPgShared-alongside-RbacStore composition) — the predicate takes two
 * independent store pointers with no cross-store transaction requirement.
 * Skips when YUZU_TEST_POSTGRES_DSN is unset, fails when set but broken.
 */

#include "rbac_admin_predicate.hpp"

#include "test_auth_db_pg_helper.hpp"
#include "test_rbac_store_pg_helper.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace yuzu::server;

namespace {

/// One fresh RbacStore + one fresh AuthDB, independent databases. Both
/// fixtures SKIP the TEST_CASE when YUZU_TEST_POSTGRES_DSN is unset.
struct PredicateHarness {
    yuzu::test::RbacStorePg rbac;
    yuzu::test::AuthDbPg auth_db;
};

auth::Session make_session(const std::string& username) {
    auth::Session s;
    s.username = username;
    return s;
}

} // namespace

// ── RBAC-off branch: durable AuthDB re-read ─────────────────────────────────

TEST_CASE("is_rbac_administrator: RBAC off, durable role=admin -> kAdmin",
          "[pg][rbac_admin_predicate]") {
    PredicateHarness h;
    REQUIRE_FALSE(h.rbac->is_rbac_enabled());
    REQUIRE(h.auth_db->upsert_user("adminuser", "hash", "salt", auth::Role::admin).has_value());

    auto gate = is_rbac_administrator(make_session("adminuser"), h.auth_db.get(), h.rbac.get());
    CHECK(gate == RbacAdminGate::kAdmin);
}

TEST_CASE("is_rbac_administrator: RBAC off, durable role=user -> kDenied",
          "[pg][rbac_admin_predicate]") {
    PredicateHarness h;
    REQUIRE(h.auth_db->upsert_user("plainuser", "hash", "salt", auth::Role::user).has_value());

    auto gate = is_rbac_administrator(make_session("plainuser"), h.auth_db.get(), h.rbac.get());
    CHECK(gate == RbacAdminGate::kDenied);
}

TEST_CASE("is_rbac_administrator: RBAC off, session role='admin' but NO durable "
          "auth.users row (JIT-elevation-shaped session) -> kDenied, not kAdmin",
          "[pg][rbac_admin_predicate]") {
    // Simulates the plan's decision 1: a session carrying a JIT-elevated
    // effective role must NOT satisfy this predicate — only a durable
    // auth.users row does. A session for a username with no row at all is
    // the simplest way to prove the predicate never trusts the Session
    // object's own .role field.
    PredicateHarness h;
    auth::Session s = make_session("nobody-durable");
    s.role = auth::Role::admin; // the session's own cached role — ignored

    auto gate = is_rbac_administrator(s, h.auth_db.get(), h.rbac.get());
    CHECK(gate == RbacAdminGate::kDenied);
}

TEST_CASE("is_rbac_administrator: RBAC off, null AuthDB -> kUnavailable",
          "[pg][rbac_admin_predicate]") {
    PredicateHarness h;
    auto gate = is_rbac_administrator(make_session("whoever"), nullptr, h.rbac.get());
    CHECK(gate == RbacAdminGate::kUnavailable);
}

// ── RBAC-on branch: principal_roles re-read ─────────────────────────────────

TEST_CASE("is_rbac_administrator: RBAC on, principal_roles(user,*,Administrator) "
          "row -> kAdmin",
          "[pg][rbac_admin_predicate]") {
    PredicateHarness h;
    h.rbac->set_rbac_enabled(true);
    REQUIRE(h.rbac->assign_role({"user", "rbacadmin", "Administrator"}).has_value());

    auto gate = is_rbac_administrator(make_session("rbacadmin"), h.auth_db.get(), h.rbac.get());
    CHECK(gate == RbacAdminGate::kAdmin);
}

TEST_CASE("is_rbac_administrator: RBAC on, no principal_roles row -> kDenied "
          "(even with a durable auth.users role=admin row — RBAC-on ignores AuthDB)",
          "[pg][rbac_admin_predicate]") {
    PredicateHarness h;
    h.rbac->set_rbac_enabled(true);
    // A durable AuthDB admin row exists, but once RBAC is truly on, only the
    // principal_roles grant table is authoritative — the two branches are
    // mutually exclusive, never "OR"'d together.
    REQUIRE(h.auth_db->upsert_user("legacyadmin", "hash", "salt", auth::Role::admin).has_value());

    auto gate = is_rbac_administrator(make_session("legacyadmin"), h.auth_db.get(), h.rbac.get());
    CHECK(gate == RbacAdminGate::kDenied);
}

TEST_CASE("is_rbac_administrator: RBAC on, principal_roles row for a DIFFERENT "
          "role -> kDenied",
          "[pg][rbac_admin_predicate]") {
    PredicateHarness h;
    h.rbac->set_rbac_enabled(true);
    REQUIRE(h.rbac->assign_role({"user", "vieweronly", "Viewer"}).has_value());

    auto gate = is_rbac_administrator(make_session("vieweronly"), h.auth_db.get(), h.rbac.get());
    CHECK(gate == RbacAdminGate::kDenied);
}

TEST_CASE("is_rbac_administrator: RBAC on, ONLY a group-held Administrator grant "
          "-> kDenied (deliberate A2 scope limit)",
          "[pg][rbac_admin_predicate]") {
    PredicateHarness h;
    h.rbac->set_rbac_enabled(true);
    REQUIRE(h.rbac->assign_role({"group", "admins-group", "Administrator"}).has_value());

    // "groupmember" holds no DIRECT principal_roles(user,...) row — only
    // group membership would grant it, which this predicate deliberately
    // does not resolve (decision 2 in the header comment).
    auto gate = is_rbac_administrator(make_session("groupmember"), h.auth_db.get(), h.rbac.get());
    CHECK(gate == RbacAdminGate::kDenied);
}

TEST_CASE("is_rbac_administrator: null RbacStore -> kUnavailable regardless of "
          "RBAC on/off",
          "[pg][rbac_admin_predicate]") {
    PredicateHarness h;
    auto gate = is_rbac_administrator(make_session("whoever"), h.auth_db.get(), nullptr);
    CHECK(gate == RbacAdminGate::kUnavailable);
}

// ── Structural exclusions (checked before any I/O) ──────────────────────────

TEST_CASE("is_rbac_administrator: an engine-classed session is denied even if "
          "the username coincidentally has a durable admin row",
          "[pg][rbac_admin_predicate]") {
    PredicateHarness h;
    REQUIRE(
        h.auth_db->upsert_user("coincidence", "hash", "salt", auth::Role::admin).has_value());
    REQUIRE(
        h.auth_db->upsert_user("coincidence2", "hash", "salt", auth::Role::admin).has_value());

    auto s = make_session("coincidence");
    s.principal_kind = "engine";
    CHECK(is_rbac_administrator(s, h.auth_db.get(), h.rbac.get()) == RbacAdminGate::kDenied);

    auto s2 = make_session("coincidence2");
    s2.auth_source = "engine_token";
    CHECK(is_rbac_administrator(s2, h.auth_db.get(), h.rbac.get()) == RbacAdminGate::kDenied);
}

TEST_CASE("is_rbac_administrator: a service-scoped session is denied even for a "
          "durable admin user",
          "[pg][rbac_admin_predicate]") {
    PredicateHarness h;
    REQUIRE(h.auth_db->upsert_user("scopedadmin", "hash", "salt", auth::Role::admin).has_value());

    auto s = make_session("scopedadmin");
    s.token_scope_service = "some-service";
    CHECK(is_rbac_administrator(s, h.auth_db.get(), h.rbac.get()) == RbacAdminGate::kDenied);
}

// ── is_self_target ───────────────────────────────────────────────────────────

TEST_CASE("is_self_target: same username -> true", "[rbac_admin_predicate]") {
    CHECK(is_self_target(make_session("dave"), "dave"));
}

TEST_CASE("is_self_target: different username -> false", "[rbac_admin_predicate]") {
    CHECK_FALSE(is_self_target(make_session("dave"), "someone-else"));
}

TEST_CASE("is_self_target: empty session.username fails closed to true",
          "[rbac_admin_predicate]") {
    auth::Session s;
    CHECK(is_self_target(s, "anyone"));
    CHECK(is_self_target(s, ""));
}
