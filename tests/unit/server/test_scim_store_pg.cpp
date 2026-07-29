// ScimStore born-on-Postgres tests (auth.db -> PG migration, ADR-0006):
// resource provision/deprovision/reactivate + etag bump, token create ->
// verify -> revoke, group CRUD + membership, active-flag transitions, the
// displayName-keyed group lookup semantics, and the fresh-start /
// migration-failure construction contracts. Schema `scim_store`.

#include <catch2/catch_test_macros.hpp>

#include "yuzu/server/scim_store.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"

#include <libpq-fe.h>

#include <algorithm>
#include <stdexcept>
#include <string>
#include <vector>

using yuzu::server::ScimGroup;
using yuzu::server::ScimResource;
using yuzu::server::ScimStore;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;

namespace {

// Pre-migrated template (see PgTestTemplate in test_helpers.hpp). The
// migration-failure / fresh-start-construction tests stay on plain
// YUZU_REQUIRE_PG_DB — they need an empty database, not an already-migrated
// one.
yuzu::test::PgTestTemplate scim_tpl{"scimstore", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    ScimStore store{pool}; // ctor runs the schema migration
    if (!store.is_open())
        throw std::runtime_error("scim template: store failed to migrate");
}};

} // namespace

TEST_CASE("ScimStore fresh-start construction succeeds on an empty database", "[pg][scim]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    CHECK(store.is_open());
}

// gov fjarvis B1 pattern (mirrors OfflineEndpointStore): a reachable database
// whose schema migration FAILS must leave the store !is_open() — the server
// wires that to startup_failed_ (fail closed, never serve-degraded).
TEST_CASE("ScimStore reports !is_open on a migration failure", "[pg][scim]") {
    YUZU_REQUIRE_PG_DB(db);

    // Pre-seed: create the scim_store schema + a conflicting table, but no
    // public.schema_meta row for the store — the runner's schema-drift guard
    // refuses (version 0 but tables exist).
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult s{PQexec(conn.get(), "CREATE SCHEMA scim_store")};
        REQUIRE(s.ok());
        PgResult t{PQexec(conn.get(), "CREATE TABLE scim_store.scim_resources (bogus int)")};
        REQUIRE(t.ok());
    }

    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    CHECK_FALSE(store.is_open());
}

TEST_CASE("ScimStore resource provision / deprovision / reactivate + etag bump", "[pg][scim]") {
    YUZU_REQUIRE_PG_DB_TPL(db, scim_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    SECTION("create_resource assigns a scim_id, defaults active=true, etag=1") {
        auto r = store.create_resource("alice", "ext-1");
        REQUIRE(r.has_value());
        CHECK_FALSE(r->scim_id.empty());
        CHECK(r->external_id == "ext-1");
        CHECK(r->username == "alice");
        CHECK(r->active);
        CHECK(r->etag_version == 1);
        CHECK_FALSE(r->created_at.empty());
        CHECK_FALSE(r->updated_at.empty());
    }

    SECTION("create_resource with empty external_id round-trips as empty (stored NULL)") {
        auto r = store.create_resource("noext");
        REQUIRE(r.has_value());
        CHECK(r->external_id.empty());
    }

    SECTION("create_resource rejects a duplicate username (UNIQUE)") {
        REQUIRE(store.create_resource("dupe").has_value());
        CHECK_FALSE(store.create_resource("dupe").has_value());
    }

    SECTION("get_by_scim_id / get_by_username / find_by_external_id round-trip") {
        auto r = store.create_resource("bob", "ext-bob");
        REQUIRE(r.has_value());

        auto by_id = store.get_by_scim_id(r->scim_id);
        REQUIRE(by_id.has_value());
        CHECK(by_id->username == "bob");

        auto by_username = store.get_by_username("bob");
        REQUIRE(by_username.has_value());
        CHECK(by_username->scim_id == r->scim_id);

        auto by_ext = store.find_by_external_id("ext-bob");
        REQUIRE(by_ext.has_value());
        CHECK(by_ext->scim_id == r->scim_id);

        CHECK_FALSE(store.find_by_external_id("").has_value());
        CHECK_FALSE(store.get_by_scim_id("does-not-exist").has_value());
    }

    SECTION("set_active toggles + bumps etag_version and updated_at") {
        auto r = store.create_resource("carol");
        REQUIRE(r.has_value());
        REQUIRE(store.set_active(r->scim_id, false)); // deprovision
        auto after_deactivate = store.get_by_scim_id(r->scim_id);
        REQUIRE(after_deactivate.has_value());
        CHECK_FALSE(after_deactivate->active);
        CHECK(after_deactivate->etag_version == 2);

        REQUIRE(store.set_active(r->scim_id, true)); // reactivate
        auto after_reactivate = store.get_by_scim_id(r->scim_id);
        REQUIRE(after_reactivate.has_value());
        CHECK(after_reactivate->active);
        CHECK(after_reactivate->etag_version == 3);

        CHECK_FALSE(store.set_active("no-such-id", true));
    }

    SECTION("update_resource bumps etag_version") {
        auto r = store.create_resource("dave", "old-ext");
        REQUIRE(r.has_value());
        REQUIRE(store.update_resource(r->scim_id, "dave2", "new-ext"));
        auto updated = store.get_by_scim_id(r->scim_id);
        REQUIRE(updated.has_value());
        CHECK(updated->username == "dave2");
        CHECK(updated->external_id == "new-ext");
        CHECK(updated->etag_version == 2);
    }

    SECTION("delete_by_scim_id: true on first delete, false (idempotent) on the second") {
        auto r = store.create_resource("erin");
        REQUIRE(r.has_value());
        auto first = store.delete_by_scim_id(r->scim_id);
        REQUIRE(first.has_value());
        CHECK(*first == true);

        auto second = store.delete_by_scim_id(r->scim_id);
        REQUIRE(second.has_value());
        CHECK(*second == false);

        CHECK_FALSE(store.get_by_scim_id(r->scim_id).has_value());
    }

    // Gate-8 round-2 MEDIUM (CC6.8), ported from the pre-migration SQLite
    // test (dropped in the PG migration): a genuine query-time failure must
    // surface as `nullopt`, NEVER collapse to `false` ("already gone") — the
    // routes layer relies on that distinction to 500 a failed teardown
    // instead of 204ing it. Force a deterministic PG-side failure by
    // dropping the backing table out from under the already-open store
    // (each YUZU_REQUIRE_PG_DB_TPL test gets its own clone, so this cannot
    // bleed into another case).
    SECTION("delete_by_scim_id surfaces a genuine query-time error as nullopt, never false") {
        auto r = store.create_resource("frank");
        REQUIRE(r.has_value());

        {
            auto lease = pool.acquire();
            REQUIRE(lease);
            auto drop = yuzu::server::pg::exec_params(
                lease.get(), "DROP TABLE scim_store.scim_resources", std::vector<std::string>{});
            REQUIRE(drop.ok());
        }

        auto result = store.delete_by_scim_id(r->scim_id);
        CHECK_FALSE(result.has_value()); // DB error → nullopt, NOT value(false)
    }

    SECTION("list paginates in stable creation order and reports total_out") {
        REQUIRE(store.create_resource("p1").has_value());
        REQUIRE(store.create_resource("p2").has_value());
        REQUIRE(store.create_resource("p3").has_value());

        int total = 0;
        auto page1 = store.list(1, 2, total);
        CHECK(total >= 3);
        REQUIRE(page1.size() == 2);
        CHECK(page1[0].username == "p1");
        CHECK(page1[1].username == "p2");

        int total2 = 0;
        auto page2 = store.list(3, 2, total2);
        REQUIRE(page2.size() >= 1);
        CHECK(page2[0].username == "p3");
    }
}

TEST_CASE("ScimStore bearer token create / verify / revoke", "[pg][scim]") {
    YUZU_REQUIRE_PG_DB_TPL(db, scim_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    SECTION("no token initially") {
        CHECK_FALSE(store.has_token());
        CHECK_FALSE(store.validate_token("anything"));
    }

    SECTION("set_token then validate with the correct raw value succeeds") {
        REQUIRE(store.set_token("s3cr3t-raw-token", "idp-1"));
        CHECK(store.has_token());
        CHECK(store.validate_token("s3cr3t-raw-token"));
        CHECK_FALSE(store.validate_token("wrong-token"));
        CHECK_FALSE(store.validate_token(""));
    }

    SECTION("re-setting the same label revokes the prior token (upsert by label)") {
        REQUIRE(store.set_token("first-token", "idp-1"));
        REQUIRE(store.set_token("second-token", "idp-1"));
        CHECK_FALSE(store.validate_token("first-token"));
        CHECK(store.validate_token("second-token"));
    }

    SECTION("set_token rejects an empty raw value") {
        CHECK_FALSE(store.set_token("", "idp-1"));
        CHECK_FALSE(store.has_token());
    }

    // Ported from the pre-migration SQLite test (dropped in the PG
    // migration): set_token upserts BY LABEL, so two distinct labels are
    // two independent active rows, not one overwritten row — both must
    // still validate.
    SECTION("distinct labels coexist as separate active tokens") {
        REQUIRE(store.set_token("token-a", "label-a"));
        REQUIRE(store.set_token("token-b", "label-b"));

        CHECK(store.validate_token("token-a"));
        CHECK(store.validate_token("token-b"));
    }
}

TEST_CASE("ScimStore group CRUD, membership, and displayName-keyed lookup", "[pg][scim]") {
    YUZU_REQUIRE_PG_DB_TPL(db, scim_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    SECTION("create_group + get_group_by_id / get_group_by_display_name round-trip") {
        auto g = store.create_group("Engineering", "ext-grp-1");
        REQUIRE(g.has_value());
        CHECK_FALSE(g->scim_id.empty());
        CHECK(g->display_name == "Engineering");
        CHECK(g->active);
        CHECK(g->etag_version == 1);

        auto by_id = store.get_group_by_id(g->scim_id);
        REQUIRE(by_id.has_value());
        CHECK(by_id->display_name == "Engineering");

        // displayName-keyed match: exact-match lookup, no DB-level UNIQUE —
        // used by the routes layer for idempotent-create / 409 checks.
        auto by_name = store.get_group_by_display_name("Engineering");
        REQUIRE(by_name.has_value());
        CHECK(by_name->scim_id == g->scim_id);
        CHECK_FALSE(store.get_group_by_display_name("Nonexistent").has_value());
    }

    SECTION("displayName has no uniqueness constraint at the storage layer") {
        auto g1 = store.create_group("Sales");
        auto g2 = store.create_group("Sales");
        REQUIRE(g1.has_value());
        REQUIRE(g2.has_value());
        CHECK(g1->scim_id != g2->scim_id);
    }

    SECTION("update_group bumps etag_version") {
        auto g = store.create_group("Support", "old-ext");
        REQUIRE(g.has_value());
        REQUIRE(store.update_group(g->scim_id, "Support2", "new-ext"));
        auto updated = store.get_group_by_id(g->scim_id);
        REQUIRE(updated.has_value());
        CHECK(updated->display_name == "Support2");
        CHECK(updated->external_id == "new-ext");
        CHECK(updated->etag_version == 2);
        CHECK_FALSE(store.update_group("no-such-group", "x", ""));
    }

    SECTION("count_groups / list_groups pagination") {
        REQUIRE(store.create_group("G1").has_value());
        REQUIRE(store.create_group("G2").has_value());
        int before = store.count_groups();
        REQUIRE(store.create_group("G3").has_value());
        CHECK(store.count_groups() == before + 1);

        int total = 0;
        auto page = store.list_groups(1, 2, total);
        CHECK(total >= 3);
        CHECK(page.size() == 2);
    }

    SECTION("add_group_member / remove_group_member are idempotent") {
        auto g = store.create_group("Membership1");
        REQUIRE(g.has_value());
        CHECK(store.add_group_member(g->scim_id, "user-a"));
        CHECK(store.add_group_member(g->scim_id, "user-a")); // idempotent no-op
        auto members = store.list_group_member_user_scim_ids(g->scim_id).value();
        REQUIRE(members.size() == 1);
        CHECK(members[0] == "user-a");

        CHECK(store.remove_group_member(g->scim_id, "user-a"));
        CHECK(store.remove_group_member(g->scim_id, "user-a")); // idempotent no-op
        CHECK(store.list_group_member_user_scim_ids(g->scim_id).value().empty());
    }

    SECTION("set_group_members replaces the entire membership set") {
        auto g = store.create_group("Membership2");
        REQUIRE(g.has_value());
        REQUIRE(store.set_group_members(g->scim_id, {"u1", "u2", "u3"}));
        auto members = store.list_group_member_user_scim_ids(g->scim_id).value();
        CHECK(members.size() == 3);

        REQUIRE(store.set_group_members(g->scim_id, {"u4"}));
        members = store.list_group_member_user_scim_ids(g->scim_id).value();
        REQUIRE(members.size() == 1);
        CHECK(members[0] == "u4");

        REQUIRE(store.set_group_members(g->scim_id, {})); // empty set is a real value
        CHECK(store.list_group_member_user_scim_ids(g->scim_id).value().empty());
    }

    SECTION("list_group_display_names_for_user reverse lookup") {
        auto g1 = store.create_group("Alpha");
        auto g2 = store.create_group("Beta");
        REQUIRE(g1.has_value());
        REQUIRE(g2.has_value());
        REQUIRE(store.add_group_member(g1->scim_id, "shared-user"));
        REQUIRE(store.add_group_member(g2->scim_id, "shared-user"));

        auto names = store.list_group_display_names_for_user("shared-user").value();
        REQUIRE(names.size() == 2);
        CHECK(names[0] == "Alpha"); // ordered by display_name ASC
        CHECK(names[1] == "Beta");

        CHECK(store.list_group_display_names_for_user("no-such-user").value().empty());
    }

    SECTION("replace_group_and_members atomically renames + replaces membership") {
        auto g = store.create_group("Original", "orig-ext");
        REQUIRE(g.has_value());
        REQUIRE(store.set_group_members(g->scim_id, {"old-member"}));

        auto result =
            store.replace_group_and_members(g->scim_id, "Renamed", "new-ext", {"new-member"});
        REQUIRE(result.has_value());
        CHECK(*result == true);

        auto updated = store.get_group_by_id(g->scim_id);
        REQUIRE(updated.has_value());
        CHECK(updated->display_name == "Renamed");
        CHECK(updated->external_id == "new-ext");
        CHECK(updated->etag_version == 2);

        auto members = store.list_group_member_user_scim_ids(g->scim_id).value();
        REQUIRE(members.size() == 1);
        CHECK(members[0] == "new-member");
    }

    SECTION("replace_group_and_members on an unknown scim_id reports false, no side effects") {
        auto result = store.replace_group_and_members("no-such-group", "X", "", {"m1"});
        REQUIRE(result.has_value());
        CHECK(*result == false);
    }

    SECTION("delete_group cascades membership and is idempotent (tri-state)") {
        auto g = store.create_group("ToDelete");
        REQUIRE(g.has_value());
        REQUIRE(store.add_group_member(g->scim_id, "member-x"));

        auto first = store.delete_group(g->scim_id);
        REQUIRE(first.has_value());
        CHECK(*first == true);
        CHECK_FALSE(store.get_group_by_id(g->scim_id).has_value());
        // The reverse lookup must not dangle after the cascade.
        CHECK(store.list_group_member_user_scim_ids(g->scim_id).value().empty());

        auto second = store.delete_group(g->scim_id);
        REQUIRE(second.has_value());
        CHECK(*second == false); // idempotent: already gone
    }
}

// ── Transaction-rollback coverage (re-ported from the deleted SQLite
//    test_scim_group_store.cpp; 2026-07-25 review MEDIUM) ──────────────────
//
// The SQLite suite proved all three `with_txn_for` writers roll back FULLY —
// not just the failed statement — by poisoning a member id with a trigger so
// the INSERT loop aborts after the transaction's earlier DELETE/UPDATE have
// already run. Those three cases were dropped in the PG migration and had no
// replacement, leaving every rollback path untested. This is the same
// technique in Postgres (plpgsql RAISE EXCEPTION instead of RAISE(ABORT)).
//
// This matters more on PG than it did on SQLite: `replace_group_and_members`
// is what the SCIM PUT/PATCH routes commit, so a partial apply here is a
// torn group membership and, through the role recompute, a wrong admin set.

namespace {

// Abort any INSERT of the sentinel member id, mid-transaction.
void install_member_insert_poison(PGconn* conn) {
    PgResult fn{PQexec(conn, R"(
        CREATE OR REPLACE FUNCTION scim_store.poison_member_insert() RETURNS trigger AS $$
        BEGIN
            IF NEW.user_scim_id = 'POISON' THEN
                RAISE EXCEPTION 'induced failure';
            END IF;
            RETURN NEW;
        END; $$ LANGUAGE plpgsql;
    )")};
    REQUIRE(fn.ok());
    PgResult trg{PQexec(conn, "CREATE TRIGGER poison_member_insert BEFORE INSERT ON "
                              "scim_store.scim_group_members FOR EACH ROW "
                              "EXECUTE FUNCTION scim_store.poison_member_insert()")};
    REQUIRE(trg.ok());
}

// Abort the group DELETE itself, after the membership rows have been removed
// earlier in the same transaction.
void install_group_delete_poison(PGconn* conn) {
    PgResult fn{PQexec(conn, R"(
        CREATE OR REPLACE FUNCTION scim_store.poison_group_delete() RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'induced failure';
        END; $$ LANGUAGE plpgsql;
    )")};
    REQUIRE(fn.ok());
    PgResult trg{PQexec(conn, "CREATE TRIGGER poison_group_delete BEFORE DELETE ON "
                              "scim_store.scim_groups FOR EACH ROW "
                              "EXECUTE FUNCTION scim_store.poison_group_delete()")};
    REQUIRE(trg.ok());
}

std::vector<std::string> sorted_members(ScimStore& store, const std::string& scim_id) {
    auto members = store.list_group_member_user_scim_ids(scim_id);
    REQUIRE(members.has_value());
    auto out = *members;
    std::sort(out.begin(), out.end());
    return out;
}

} // namespace

TEST_CASE("ScimStore: replace_group_and_members rolls back fully on a mid-transaction failure",
          "[pg][scim][group][transaction]") {
    YUZU_REQUIRE_PG_DB_TPL(db, scim_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    ScimStore store{pool};
    REQUIRE(store.is_open());

    auto grp = store.create_group("Sales", "ext-1");
    REQUIRE(grp.has_value());
    REQUIRE(store.set_group_members(grp->scim_id, {"old-a", "old-b"}));

    PgConn conn{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    install_member_insert_poison(conn.get());

    auto result = store.replace_group_and_members(grp->scim_id, "Sales EMEA", "ext-2",
                                                  {"new-1", "POISON", "new-2"});
    REQUIRE_FALSE(result.has_value());

    // Neither half of the write leaked: the rename did NOT persist...
    auto after = store.get_group_by_id(grp->scim_id);
    REQUIRE(after.has_value());
    CHECK(after->display_name == "Sales");
    CHECK(after->external_id == "ext-1");

    // ...and the membership-clearing DELETE that ran earlier in the SAME
    // transaction rolled back too. A half-applied outcome (just "new-1", or
    // an empty set) is the bug this guards.
    auto members = sorted_members(store, grp->scim_id);
    REQUIRE(members.size() == 2);
    CHECK(members[0] == "old-a");
    CHECK(members[1] == "old-b");
}

TEST_CASE("ScimStore: set_group_members rolls back fully on a mid-transaction failure",
          "[pg][scim][group][transaction]") {
    YUZU_REQUIRE_PG_DB_TPL(db, scim_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    ScimStore store{pool};
    REQUIRE(store.is_open());

    auto grp = store.create_group("Team");
    REQUIRE(grp.has_value());
    REQUIRE(store.set_group_members(grp->scim_id, {"old-a", "old-b"}));

    PgConn conn{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    install_member_insert_poison(conn.get());

    CHECK_FALSE(store.set_group_members(grp->scim_id, {"new-1", "POISON", "new-2"}));

    auto members = sorted_members(store, grp->scim_id);
    REQUIRE(members.size() == 2);
    CHECK(members[0] == "old-a");
    CHECK(members[1] == "old-b");
}

TEST_CASE("ScimStore: delete_group rolls back fully on a mid-transaction failure",
          "[pg][scim][group][transaction]") {
    YUZU_REQUIRE_PG_DB_TPL(db, scim_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    ScimStore store{pool};
    REQUIRE(store.is_open());

    auto grp = store.create_group("Doomed");
    REQUIRE(grp.has_value());
    REQUIRE(store.set_group_members(grp->scim_id, {"m1", "m2"}));

    PgConn conn{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    install_group_delete_poison(conn.get());

    // nullopt = "could not determine" (fail closed / retry), never a silent
    // "already gone" — the tri-state delete_by_scim_id contract.
    auto result = store.delete_group(grp->scim_id);
    CHECK_FALSE(result.has_value());

    // The group AND its membership both survive — the cascade DELETE that ran
    // first in the transaction was rolled back with it.
    CHECK(store.get_group_by_id(grp->scim_id).has_value());
    auto members = sorted_members(store, grp->scim_id);
    REQUIRE(members.size() == 2);
    CHECK(members[0] == "m1");
    CHECK(members[1] == "m2");
}

// ── 2026-07-25 review HIGH #3: authoritative membership reads fail CLOSED ──
//
// The reviewer's scenario: a transient read failure was indistinguishable
// from "this group has no members", and because the SCIM PATCH route folds
// its ops onto that read and then persists the whole set, one blip durably
// deleted a group's entire membership. The store-level contract that makes
// the route fix possible is that a failed read is `nullopt`, never an
// engaged-but-empty vector.
TEST_CASE("ScimStore: a FAILED membership read is nullopt, never an empty member set",
          "[pg][scim][group][failclosed]") {
    YUZU_REQUIRE_PG_DB_TPL(db, scim_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    ScimStore store{pool};
    REQUIRE(store.is_open());

    auto grp = store.create_group("RealMembers");
    REQUIRE(grp.has_value());
    REQUIRE(store.set_group_members(grp->scim_id, {"u1", "u2"}));

    // Sanity: a genuinely empty group is an ENGAGED empty vector, which must
    // stay distinguishable from the failure below.
    auto empty_grp = store.create_group("NoMembers");
    REQUIRE(empty_grp.has_value());
    auto empty_read = store.list_group_member_user_scim_ids(empty_grp->scim_id);
    REQUIRE(empty_read.has_value());
    CHECK(empty_read->empty());

    // Break the reads' statements only (the join table for the forward read,
    // which the reverse read also traverses).
    PgConn conn{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PgResult drop{PQexec(conn.get(), "DROP TABLE scim_store.scim_group_members")};
    REQUIRE(drop.ok());

    CHECK_FALSE(store.list_group_member_user_scim_ids(grp->scim_id).has_value());
    CHECK_FALSE(store.list_group_display_names_for_user("u1").has_value());
}
