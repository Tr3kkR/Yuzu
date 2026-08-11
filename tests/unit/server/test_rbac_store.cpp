/**
 * test_rbac_store.cpp — Unit tests for RbacStore
 *
 * Covers: lifecycle, seed data, role CRUD, permission CRUD, principal-role
 * assignments, group membership, check_permission, deny-overrides-allow,
 * RBAC toggle, check_scoped_permission.
 */

#include "management_group_store.hpp"
#include "mcp_server_testonly.hpp" // rbac_ops/securables_for_test (#2383 mirror binding)
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "rbac_generation_rules.hpp"
#include "rbac_store.hpp"
#include "sqlite_raii.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <libpq-fe.h>
#include <sqlite3.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

using namespace yuzu::server;
namespace pg = yuzu::server::pg;
using yuzu::server::pg::PgPool;

namespace {
// Pre-migrated + seeded template (RbacStore construction runs the migration AND
// seed_defaults). Every store-behaviour case clones this instead of
// re-migrating/re-seeding per test (docs/postgres-store-playbook.md step 7).
yuzu::test::PgTestTemplate rbac_tpl{"rbacstore", [](const std::string& dsn) {
                                        PgPool pool{{.conninfo = dsn, .size = 1}};
                                        RbacStore store{pool};
                                        if (!store.is_open())
                                            throw std::runtime_error(
                                                "rbac template: store failed to migrate/seed");
                                    }};

// Seed a group row DIRECTLY (bypassing create_group's reserved-prefix guard) to
// reproduce a legacy artifact that predates the guard. `source` is written
// verbatim, so a local group literally named `entra:x` can be planted.
void seed_group_raw(PgPool& pool, const std::string& name, const std::string& description,
                    const std::string& source, const std::string& external_id) {
    auto lease = pool.acquire();
    REQUIRE(lease);
    pg::PgResult r = pg::exec_params(
        lease.get(),
        "INSERT INTO rbac_store.groups (name, description, source, external_id, created_at) "
        "VALUES ($1, $2, $3, $4, 0)",
        std::vector<std::string>{name, description, source, external_id});
    REQUIRE(r.status() == PGRES_COMMAND_OK);
}
} // namespace

// Fixture: a fresh cloned PG database, a pool, and an open RbacStore. Expands to
// statements (includes the SKIP-if-no-DSN guard), so it must lead a block. The
// db/pool must outlive `store_var`; declaring all three here keeps that order.
#define RBAC_STORE(store_var)                                                                      \
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_fx_, rbac_tpl);                                                  \
    PgPool rbac_pool_fx_{{.conninfo = rbac_db_fx_.dsn(), .size = 4}};                               \
    REQUIRE(rbac_pool_fx_.valid());                                                                 \
    RbacStore store_var{rbac_pool_fx_};                                                             \
    REQUIRE(store_var.is_open())

// ── Lifecycle ────────────────────────────────────────────────────────────────

TEST_CASE("RbacStore: open in-memory", "[rbac_store][db][pg]") {
    RBAC_STORE(store);
    REQUIRE(store.is_open());
}

TEST_CASE("RbacStore: seed data — system roles exist", "[rbac_store][pg]") {
    RBAC_STORE(store);
    auto roles = store.list_roles();

    auto find = [&](const std::string& name) {
        return std::find_if(roles.begin(), roles.end(),
                            [&](const RbacRole& r) { return r.name == name; });
    };

    REQUIRE(find("Administrator") != roles.end());
    REQUIRE(find("Operator") != roles.end());
    REQUIRE(find("ITServiceOwner") != roles.end());
    REQUIRE(find("Viewer") != roles.end());
    CHECK(find("Administrator")->is_system);
    CHECK(find("Operator")->is_system);
    CHECK(find("ITServiceOwner")->is_system);
    CHECK(find("Viewer")->is_system);
}

TEST_CASE("RbacStore: seed data — securable types", "[rbac_store][pg]") {
    RBAC_STORE(store);
    auto types = store.list_securable_types();
    REQUIRE(types.size() == 23); // +SoftwareLicensing (ADR-0024) +AccessReview (SOC 2 CC6.2)
                                 // +EnginePrincipal (#2376, cut away from Security:Read)

    auto has = [&](const std::string& t) {
        return std::find(types.begin(), types.end(), t) != types.end();
    };
    CHECK(has("Infrastructure"));
    CHECK(has("Execution"));
    CHECK(has("AuditLog"));
    CHECK(has("Response"));
    CHECK(has("ManagementGroup"));
    CHECK(has("ApiToken"));
    CHECK(has("Security"));
    CHECK(has("Policy"));
    CHECK(has("DeviceToken"));
    CHECK(has("SoftwareDeployment"));
    CHECK(has("License")); // Yuzu's OWN product licence (§22.3) — DISTINCT from SLE
    CHECK(has("FileRetrieval"));
    CHECK(has("GuaranteedState"));
    CHECK(has("Inventory"));
    CHECK(has("SoftwareLicensing")); // SLE securable (ADR-0024 Decision 9) — NOT `License`
    CHECK(has("AccessReview")); // Periodic Access Reviews (SOC 2 CC6.2), dedicated + narrow
    CHECK(has("EnginePrincipal")); // Engine-principal inventory + grant-graph reads (#2376),
                                   // cut away from the over-broad Security:Read
}

TEST_CASE("RbacStore: seed data — operations", "[rbac_store][pg]") {
    RBAC_STORE(store);
    auto ops = store.list_operations();
    // Read, Write, Execute, Delete, Approve, Push (Push added for Guardian
    // distribute-rules-to-fleet operation; design v1.1 §9.2), Attest (added
    // for Periodic Access Reviews, SOC 2 CC6.2 — AccessReview:Attest sign-off).
    REQUIRE(ops.size() == 7);
}

// #2383 (governance C-3/UP-6): the MCP C8 boot validator carries closed-catalogue
// MIRRORS of this store's seeded `ops[]` and `types[]` (kRbacOps /
// kRbacSecurables in mcp_server.cpp). This test binds mirror to seed by NAME,
// both directions, so adding/removing an operation or securable in one place
// without the other fails here instead of drifting silently.
TEST_CASE("RbacStore: seeded catalogues match the MCP C8 validator mirrors",
          "[rbac_store][mcp][2g][pg]") {
    RBAC_STORE(store);

    auto sorted = [](std::vector<std::string> v) {
        std::sort(v.begin(), v.end());
        return v;
    };
    CHECK(sorted(store.list_operations()) == sorted(yuzu::server::mcp::rbac_ops_for_test()));
    CHECK(sorted(store.list_securable_types()) ==
          sorted(yuzu::server::mcp::rbac_securables_for_test()));
}

TEST_CASE("RbacStore: seed data — Administrator has all permissions", "[rbac_store][pg]") {
    RBAC_STORE(store);
    auto perms = store.get_role_permissions("Administrator");
    // 23 types * 5 CRUD ops = 115 permissions, plus a single targeted Push
    // grant on GuaranteedState (= 116), plus a single AccessReview:Attest grant
    // (Periodic Access Reviews, CC6.2) = 117 permissions total. Push and Attest
    // are deliberately NOT cross-seeded on other securables — see the rationale
    // in rbac_store.cpp seed_defaults(). (23rd type: EnginePrincipal, #2376;
    // 22nd: AccessReview, SOC 2 CC6.2; 21st: SoftwareLicensing, ADR-0024.)
    CHECK(perms.size() == 117);
    for (auto& p : perms)
        CHECK(p.effect == "allow");

    // Confirm the Push grant exists exactly once, and only on GuaranteedState.
    size_t push_count = 0;
    for (const auto& p : perms) {
        if (p.operation == "Push") {
            ++push_count;
            CHECK(p.securable_type == "GuaranteedState");
        }
    }
    CHECK(push_count == 1);
}

TEST_CASE("RbacStore: seed data — Viewer has read-only", "[rbac_store][pg]") {
    RBAC_STORE(store);
    auto perms = store.get_role_permissions("Viewer");
    // 21 types * Read only (everything except Infrastructure; incl. Inventory +
    // SoftwareLicensing, ADR-0024, + EnginePrincipal, #2376)
    CHECK(perms.size() == 21);
    for (auto& p : perms) {
        CHECK(p.operation == "Read");
        CHECK(p.effect == "allow");
        CHECK(p.securable_type != "Infrastructure");
    }
}

// ── RBAC toggle ──────────────────────────────────────────────────────────────

TEST_CASE("RbacStore: RBAC disabled by default", "[rbac_store][pg]") {
    RBAC_STORE(store);
    CHECK_FALSE(store.is_rbac_enabled());
}

TEST_CASE("RbacStore: enable and disable RBAC", "[rbac_store][pg]") {
    RBAC_STORE(store);
    store.set_rbac_enabled(true);
    CHECK(store.is_rbac_enabled());
    store.set_rbac_enabled(false);
    CHECK_FALSE(store.is_rbac_enabled());
}

// #1498 — the device-visibility fallback must distinguish a store that is
// loaded-and-explicitly-disabled (full-fleet fallback OK) from one that is
// missing or failed to load (fail CLOSED). The probe wired into
// ManagementGroupStore is exactly rbac_enforcement_in_effect(rbac_store_.get()),
// so this exercises the real predicate, not a stand-in lambda.
TEST_CASE("rbac_enforcement_in_effect fails closed on null / load-failed store",
          "[rbac_store][visibility][pg]") {
    SECTION("null store → enforcement in effect (fail closed)") {
        CHECK(rbac_enforcement_in_effect(nullptr));
    }

    SECTION("load-failed store (is_open()==false) → fail closed, not full-fleet") {
        // The PG analogue of the SQLite load-failed store (ADR-0041 fail-closed
        // construction test): a pool whose DSN never connects leaves the store's
        // construction lease empty, so migration never runs and is_open()==false
        // — the same state a corrupt/unreachable rbac substrate produces, and
        // indistinguishable by the enabled flag alone.
        PgPool bad{{.conninfo = "host=127.0.0.1 port=1 dbname=nope user=nope connect_timeout=1",
                    .size = 1}};
        RbacStore broken{bad};
        REQUIRE_FALSE(broken.is_open());
        CHECK(rbac_enforcement_in_effect(&broken)); // must fail closed
    }

    SECTION("unreachable-substrate store (open/migration failed) → fail closed") {
        // The constructor's failure path when the substrate is unreachable — a
        // second unroutable DSN (distinct host) exercising the same fail-closed
        // is_open()==false outcome that #1717's corrupt-but-openable rbac.db
        // produced on SQLite.
        PgPool bad{{.conninfo = "host=192.0.2.1 port=5432 dbname=x user=x connect_timeout=1",
                    .size = 1}};
        RbacStore broken{bad};
        REQUIRE_FALSE(broken.is_open());
        CHECK(rbac_enforcement_in_effect(&broken)); // must fail closed
    }

    SECTION("loaded + explicitly disabled → full-fleet fallback permitted") {
        RBAC_STORE(store);
        REQUIRE(store.is_open());
        REQUIRE_FALSE(store.is_rbac_enabled()); // disabled by default
        CHECK_FALSE(rbac_enforcement_in_effect(&store));
    }

    SECTION("loaded + enabled → enforcement in effect (role-scoped path)") {
        RBAC_STORE(store);
        store.set_rbac_enabled(true);
        REQUIRE(store.is_rbac_enabled());
        CHECK(rbac_enforcement_in_effect(&store));
    }
}

// ── Role CRUD ────────────────────────────────────────────────────────────────

TEST_CASE("RbacStore: create custom role", "[rbac_store][pg]") {
    RBAC_STORE(store);
    auto result = store.create_role({"SOC Analyst", "Security operations read access", false, 0});
    REQUIRE(result.has_value());

    auto role = store.get_role("SOC Analyst");
    REQUIRE(role.has_value());
    CHECK(role->name == "SOC Analyst");
    CHECK(role->description == "Security operations read access");
    CHECK_FALSE(role->is_system);
    CHECK(role->created_at > 0);
}

TEST_CASE("RbacStore: create duplicate role fails", "[rbac_store][pg]") {
    RBAC_STORE(store);
    store.create_role({"MyRole", "", false, 0});
    auto result = store.create_role({"MyRole", "", false, 0});
    CHECK_FALSE(result.has_value());
}

TEST_CASE("RbacStore: create role with empty name fails", "[rbac_store][pg]") {
    RBAC_STORE(store);
    auto result = store.create_role({"", "desc", false, 0});
    CHECK_FALSE(result.has_value());
}

TEST_CASE("RbacStore: delete custom role succeeds", "[rbac_store][pg]") {
    RBAC_STORE(store);
    store.create_role({"Temp", "temporary", false, 0});
    auto result = store.delete_role("Temp");
    REQUIRE(result.has_value());
    CHECK_FALSE(store.get_role("Temp").has_value());
}

TEST_CASE("RbacStore: delete system role fails", "[rbac_store][pg]") {
    RBAC_STORE(store);
    auto result = store.delete_role("Administrator");
    CHECK_FALSE(result.has_value());
    CHECK(store.get_role("Administrator").has_value());
}

TEST_CASE("RbacStore: update role description", "[rbac_store][pg]") {
    RBAC_STORE(store);
    store.create_role({"MyRole", "old desc", false, 0});
    auto result = store.update_role("MyRole", "new desc");
    REQUIRE(result.has_value());
    CHECK(store.get_role("MyRole")->description == "new desc");
}

// ── Permission CRUD ──────────────────────────────────────────────────────────

TEST_CASE("RbacStore: set and get permission", "[rbac_store][pg]") {
    RBAC_STORE(store);
    store.create_role({"TestRole", "", false, 0});

    auto result = store.set_permission({"TestRole", "Execution", "Execute", "allow"});
    REQUIRE(result.has_value());

    auto perms = store.get_role_permissions("TestRole");
    REQUIRE(perms.size() == 1);
    CHECK(perms[0].securable_type == "Execution");
    CHECK(perms[0].operation == "Execute");
    CHECK(perms[0].effect == "allow");
}

// fable (Gate 4, #2703, HIGH — REVISED from an earlier deny-tombstone fix):
// remove_permission() DELETEs the role_permissions row (restoring the exact
// legacy contract — absence, not a 'deny' row) and separately records the
// revocation in revoked_seed_defaults, bookkeeping consulted ONLY by
// seed_defaults()'s grant(). An earlier fix upserted an explicit 'deny' row
// instead, on the theory the authorization OUTCOME was identical either
// way — false: check_permission()/check_scoped_permission() apply "deny
// overrides everything, across ALL of a principal's held roles", so a deny
// row from THIS role would veto an allow the SAME principal holds via a
// DIFFERENT role (see the dual-role divergence test below). The marker
// table fixes the resurrection bug without creating that authorization
// fact.
TEST_CASE("RbacStore: remove permission deletes the row and survives a reseed",
          "[rbac_store][pg]") {
    RBAC_STORE(store);
    // Operator's AuditLog:Read is a real seed_defaults() default.
    REQUIRE(store.check_role_has_permission("Operator", "AuditLog", "Read"));

    REQUIRE(store.remove_permission("Operator", "AuditLog", "Read").has_value());
    // THE FIX: the row is genuinely gone — absent, not tombstoned.
    for (const auto& p : store.get_role_permissions("Operator"))
        CHECK_FALSE((p.securable_type == "AuditLog" && p.operation == "Read"));
    CHECK_FALSE(store.check_role_has_permission("Operator", "AuditLog", "Read"));

    // THE REGRESSION THIS CLOSES: a second construction against the SAME
    // pool runs the REAL seed_defaults() (unconditional on every boot,
    // ON CONFLICT DO NOTHING) — its grant() now consults
    // revoked_seed_defaults and skips re-inserting the revoked row.
    RbacStore reopened{rbac_pool_fx_};
    CHECK_FALSE(reopened.check_role_has_permission("Operator", "AuditLog", "Read"));
}

// chaos-injector (Gate 5, #2703, HIGH — CHAOS-1, verified against live PG):
// grant()'s `INSERT ... SELECT ... WHERE NOT EXISTS (marker) ... ON CONFLICT
// DO NOTHING` takes its READ COMMITTED snapshot once, at statement start. If
// that snapshot is taken BEFORE a concurrent revoke's marker-insert commits,
// but grant() then blocks on the ON CONFLICT arbiter waiting for that same
// revoke's uncommitted DELETE, Postgres — once the revoke commits — only
// re-checks the CONFLICT TARGET (now gone), never re-evaluates the WHERE NOT
// EXISTS subquery. So grant()'s already-computed INSERT lands anyway: the
// marker AND the resurrected row both end up present, permanently (nothing
// ever re-syncs role_permissions against revoked_seed_defaults). Fixed by a
// pg_advisory_xact_lock, acquired in its OWN statement strictly before the
// check-and-mutate statement, in every writer (grant(), remove_permission(),
// the backfill's F1 block) — see kRevokeCoordLockSql in rbac_store.cpp.
TEST_CASE("RbacStore: seed_defaults()'s grant() cannot resurrect a permission mid-revoke "
          "(CHAOS-1)",
          "[rbac_store][pg]") {
    RBAC_STORE(store);
    REQUIRE(store.check_role_has_permission("Operator", "AuditLog", "Read"));

    // Connection A: open a revoke transaction (lock + marker insert + DELETE)
    // and hold it UNCOMMITTED — simulating remove_permission()'s in-flight
    // write racing a concurrent seed_defaults() boot on another connection.
    auto lease_a = rbac_pool_fx_.acquire();
    REQUIRE(lease_a);
    REQUIRE(pg::exec_params(lease_a.get(), "BEGIN", std::vector<std::string>{}).ok());
    REQUIRE(pg::exec_params(lease_a.get(),
                            "SELECT pg_advisory_xact_lock(2037545589, "
                            "hashtext('rbac_store:revoke_coordination'))",
                            std::vector<std::string>{})
                .ok());
    REQUIRE(pg::exec_params(lease_a.get(),
                            "INSERT INTO rbac_store.revoked_seed_defaults (role_name, "
                            "securable_type, operation) VALUES ('Operator','AuditLog','Read') "
                            "ON CONFLICT DO NOTHING",
                            std::vector<std::string>{})
                .ok());
    REQUIRE(pg::exec_params(lease_a.get(),
                            "DELETE FROM rbac_store.role_permissions WHERE role_name='Operator' "
                            "AND securable_type='AuditLog' AND operation='Read'",
                            std::vector<std::string>{})
                .ok());

    // Connection B, on a separate thread: a SECOND RbacStore construction
    // against the SAME pool — a genuine replica boot, exercising the REAL
    // (production) seed_defaults()/grant() code, not a hand-copy of its SQL.
    // Its grant() call for Operator/AuditLog/Read must BLOCK on connection
    // A's held lock, and once unblocked, must see the marker and insert
    // NOTHING. No REQUIRE/CHECK runs on this background thread — a Catch2
    // assertion macro throwing off the main thread has no handler and calls
    // std::terminate() immediately; the outcome is captured in a plain
    // atomic and asserted on the main thread after join() instead.
    std::atomic<bool> b_started{false};
    std::atomic<bool> b_done{false};
    std::atomic<bool> b_open{false};
    std::thread grant_thread([&] {
        b_started = true;
        RbacStore reopened{rbac_pool_fx_};
        b_open = reopened.is_open();
        b_done = true;
    });
    // cpp-safety (Gate 8, #2703, BLOCKING): join-on-unwind guard. A REQUIRE
    // between thread construction and the explicit .join() below throws on
    // failure, and a joinable std::thread destroyed mid-unwind calls
    // std::terminate() (test_approval_manager.cpp:888-954 hit this same
    // hazard class). Detaching instead of joining would NOT be safe here
    // (unlike that file's case): this lambda captures rbac_pool_fx_/
    // b_started/b_done/b_open BY REFERENCE — stack locals of this
    // TEST_CASE — so a detached thread outliving them would be a
    // use-after-free, not a fix. The background thread's only blocking
    // wait is the advisory lock, server-side bounded by the pool's
    // lock_timeout, so join() here cannot hang indefinitely.
    struct ThreadJoiner {
        std::thread& t;
        ~ThreadJoiner() {
            if (t.joinable())
                t.join();
        }
    } joiner{grant_thread};

    // Give the grant thread time to start and genuinely block on connection
    // A's held lock — proves this is a real blocked-then-unblocked
    // interleaving, not a lucky race.
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    CHECK(b_started.load());
    CHECK_FALSE(b_done.load());

    const bool commit_ok =
        pg::exec_params(lease_a.get(), "COMMIT", std::vector<std::string>{}).ok();
    lease_a.reset();
    grant_thread.join();
    CHECK(commit_ok);
    CHECK(b_done.load());
    CHECK(b_open.load());

    // THE FIX: the permission must stay revoked.
    CHECK_FALSE(store.check_role_has_permission("Operator", "AuditLog", "Read"));
}

// fable (Gate 4, #2703, HIGH): a principal holding BOTH a role whose default
// was revoked AND a different role that independently grants the same
// (securable_type, operation) must still be granted — matching legacy,
// where the revoked role's row was simply absent and never vetoed the other
// role's independent allow. This is the scenario the deny-tombstone fix
// silently broke (verified empirically before the marker-table fix landed:
// the same setup denied dualuser under the tombstone).
TEST_CASE("RbacStore: revoking one role's default does not veto a different role's "
          "independent grant (dual-role)",
          "[rbac_store][pg]") {
    RBAC_STORE(store);
    // PlatformEngineer and Operator both seed AuditLog:Read by default.
    REQUIRE(store.check_role_has_permission("PlatformEngineer", "AuditLog", "Read"));
    REQUIRE(store.check_role_has_permission("Operator", "AuditLog", "Read"));
    store.assign_role({"user", "dualuser", "PlatformEngineer"});
    store.assign_role({"user", "dualuser", "Operator"});
    REQUIRE(store.check_permission("dualuser", "AuditLog", "Read"));

    REQUIRE(store.remove_permission("PlatformEngineer", "AuditLog", "Read").has_value());
    CHECK_FALSE(store.check_role_has_permission("PlatformEngineer", "AuditLog", "Read"));
    // Operator's independent grant is untouched...
    CHECK(store.check_role_has_permission("Operator", "AuditLog", "Read"));
    // ...and dualuser, holding both roles, is STILL granted — Operator's
    // allow controls, matching legacy (an absent row from PlatformEngineer
    // is neutral, not a veto).
    CHECK(store.check_permission("dualuser", "AuditLog", "Read"));
}

// quality-engineer (#2703): remove_permission() still validates all three
// columns (role_permissions AND revoked_seed_defaults both REFERENCE the
// same catalogue tables) — an unrecognized triple must fail, not silently
// "succeed".
TEST_CASE("RbacStore: remove permission on an unrecognized triple fails", "[rbac_store][pg]") {
    RBAC_STORE(store);
    CHECK_FALSE(store.remove_permission("NoSuchRole", "Tag", "Read").has_value());

    store.create_role({"TestRole", "", false, 0});
    CHECK_FALSE(store.remove_permission("TestRole", "NoSuchType", "Read").has_value());
    CHECK_FALSE(store.remove_permission("TestRole", "Tag", "NoSuchOp").has_value());
}

TEST_CASE("RbacStore: deleting role cascades permissions", "[rbac_store][pg]") {
    RBAC_STORE(store);
    store.create_role({"Cascade", "", false, 0});
    store.set_permission({"Cascade", "Tag", "Read", "allow"});
    store.delete_role("Cascade");

    auto perms = store.get_role_permissions("Cascade");
    CHECK(perms.empty());
}

// ── Principal-role assignments ───────────────────────────────────────────────

TEST_CASE("RbacStore: assign and list principal roles", "[rbac_store][pg]") {
    RBAC_STORE(store);
    store.assign_role({"user", "alice", "Administrator"});
    store.assign_role({"user", "alice", "Viewer"});

    auto roles = store.get_principal_roles("user", "alice");
    REQUIRE(roles.size() == 2);
}

TEST_CASE("RbacStore: duplicate assignment is idempotent", "[rbac_store][pg]") {
    RBAC_STORE(store);
    store.assign_role({"user", "bob", "Viewer"});
    store.assign_role({"user", "bob", "Viewer"});

    auto roles = store.get_principal_roles("user", "bob");
    CHECK(roles.size() == 1);
}

TEST_CASE("RbacStore: unassign role", "[rbac_store][pg]") {
    RBAC_STORE(store);
    store.assign_role({"user", "carol", "Operator"});
    store.unassign_role("user", "carol", "Operator");

    auto roles = store.get_principal_roles("user", "carol");
    CHECK(roles.empty());
}

TEST_CASE("RbacStore: get role members", "[rbac_store][pg]") {
    RBAC_STORE(store);
    store.assign_role({"user", "alice", "Operator"});
    store.assign_role({"user", "bob", "Operator"});

    auto members = store.get_role_members("Operator");
    REQUIRE(members.size() == 2);
}

TEST_CASE("RbacStore: deleting role cascades assignments", "[rbac_store][pg]") {
    RBAC_STORE(store);
    store.create_role({"Temp", "", false, 0});
    store.assign_role({"user", "alice", "Temp"});
    store.delete_role("Temp");

    auto roles = store.get_principal_roles("user", "alice");
    CHECK(roles.empty());
}

// ── check_permission ─────────────────────────────────────────────────────────

TEST_CASE("RbacStore: check_permission with direct role", "[rbac_store][pg]") {
    RBAC_STORE(store);
    store.assign_role({"user", "alice", "Administrator"});

    CHECK(store.check_permission("alice", "Infrastructure", "Write"));
    CHECK(store.check_permission("alice", "Execution", "Execute"));
    CHECK(store.check_permission("alice", "AuditLog", "Read"));
}

TEST_CASE("RbacStore: check_permission denied when no role", "[rbac_store][pg]") {
    RBAC_STORE(store);
    CHECK_FALSE(store.check_permission("nobody", "Execution", "Execute"));
}

TEST_CASE("RbacStore: Viewer cannot write", "[rbac_store][pg]") {
    RBAC_STORE(store);
    store.assign_role({"user", "bob", "Viewer"});

    CHECK(store.check_permission("bob", "Execution", "Read"));
    CHECK_FALSE(store.check_permission("bob", "Execution", "Execute"));
    CHECK_FALSE(store.check_permission("bob", "Tag", "Write"));
    CHECK_FALSE(store.check_permission("bob", "Infrastructure", "Read"));
}

TEST_CASE("RbacStore: check_permission via group membership", "[rbac_store][pg]") {
    RBAC_STORE(store);
    store.create_group({"soc-team", "Security Operations", "local", "", 0});
    store.add_group_member("soc-team", "carol");
    store.assign_role({"group", "soc-team", "Operator"});

    CHECK(store.check_permission("carol", "Execution", "Execute"));
    CHECK(store.check_permission("carol", "Tag", "Write"));
    CHECK_FALSE(store.check_permission("carol", "Infrastructure", "Write"));
}

TEST_CASE("RbacStore: deny overrides allow", "[rbac_store][pg]") {
    RBAC_STORE(store);
    store.create_role({"NoPatch", "No patching allowed", false, 0});
    store.set_permission({"NoPatch", "Execution", "Execute", "deny"});

    // alice has Operator (allow Execute) AND NoPatch (deny Execute)
    store.assign_role({"user", "alice", "Operator"});
    store.assign_role({"user", "alice", "NoPatch"});

    CHECK_FALSE(store.check_permission("alice", "Execution", "Execute"));
    // But read still works
    CHECK(store.check_permission("alice", "Execution", "Read"));
}

TEST_CASE("RbacStore: multiple roles combine permissions", "[rbac_store][pg]") {
    RBAC_STORE(store);
    store.create_role({"AuditReader", "Read audit logs", false, 0});
    store.set_permission({"AuditReader", "AuditLog", "Read", "allow"});

    store.assign_role({"user", "dave", "Viewer"});
    store.assign_role({"user", "dave", "AuditReader"});

    // Viewer gives Read on most types; AuditReader adds AuditLog Read
    CHECK(store.check_permission("dave", "AuditLog", "Read"));
    CHECK(store.check_permission("dave", "Execution", "Read"));
    CHECK_FALSE(store.check_permission("dave", "Execution", "Execute"));
}

// ── Effective permissions ────────────────────────────────────────────────────

TEST_CASE("RbacStore: get_effective_permissions", "[rbac_store][pg]") {
    RBAC_STORE(store);
    store.assign_role({"user", "alice", "Viewer"});

    auto perms = store.get_effective_permissions("alice");
    CHECK_FALSE(perms.empty());
    for (auto& p : perms)
        CHECK(p.effect == "allow");
}

TEST_CASE("RbacStore: effective permissions empty for unassigned user", "[rbac_store][pg]") {
    RBAC_STORE(store);
    auto perms = store.get_effective_permissions("nobody");
    CHECK(perms.empty());
}

// ── Group CRUD ───────────────────────────────────────────────────────────────

TEST_CASE("RbacStore: create and list groups", "[rbac_store][pg]") {
    RBAC_STORE(store);
    store.create_group({"dev-team", "Development", "local", "", 0});
    store.create_group({"ops-team", "Operations", "local", "", 0});

    auto groups = store.list_groups();
    REQUIRE(groups.size() == 2);
}

TEST_CASE("RbacStore: group membership", "[rbac_store][pg]") {
    RBAC_STORE(store);
    store.create_group({"team", "Test team", "local", "", 0});
    store.add_group_member("team", "alice");
    store.add_group_member("team", "bob");

    auto members = store.get_group_members("team");
    REQUIRE(members.size() == 2);

    store.remove_group_member("team", "bob");
    members = store.get_group_members("team");
    CHECK(members.size() == 1);
    CHECK(members[0] == "alice");
}

TEST_CASE("RbacStore: deleting group cascades members", "[rbac_store][pg]") {
    RBAC_STORE(store);
    store.create_group({"temp", "", "local", "", 0});
    store.add_group_member("temp", "alice");
    store.delete_group("temp");

    auto members = store.get_group_members("temp");
    CHECK(members.empty());
}

// ── find_local_groups_with_prefix (T8 namespace-collision preflight) ───────

TEST_CASE("RbacStore: find_local_groups_with_prefix matches local-source groups by prefix",
          "[rbac_store][pg]") {
    // create_group() rejects a new local group named inside the reserved
    // 'engine:' prefix, so a colliding row can only exist as one that predates
    // that guard — seed it directly (bypassing the app layer), the same way a
    // real pre-upgrade deployment's data would appear.
    RBAC_STORE(store);
    seed_group_raw(rbac_pool_fx_, "engine:foo", "", "local", "");
    seed_group_raw(rbac_pool_fx_, "engine:bar", "", "local", "");
    seed_group_raw(rbac_pool_fx_, "other", "", "local", "");
    // An IdP-sourced group asserting the same prefixed name is disambiguated
    // by principal_type at the resolution site, not this scan (§3.3) — must
    // not appear in the result.
    REQUIRE(store.create_group({"engine:idp-sourced", "IdP group", "entra", "ext-1", 0})
               .has_value());

    auto result = store.find_local_groups_with_prefix("engine:");
    REQUIRE(result.has_value());
    CHECK(result->size() == 2);
}

TEST_CASE("RbacStore: find_local_groups_with_prefix returns empty engaged optional "
          "when nothing matches",
          "[rbac_store][pg]") {
    RBAC_STORE(store);
    store.create_group({"other", "", "local", "", 0});

    auto result = store.find_local_groups_with_prefix("engine:");
    REQUIRE(result.has_value());
    CHECK(result->empty());
}

TEST_CASE("RbacStore: find_local_groups_with_prefix returns nullopt (not an engaged "
          "empty optional) on a closed/load-failed store",
          "[rbac_store][visibility][pg]") {
    // Mirrors the load-failed construction used by the
    // rbac_enforcement_in_effect fail-closed tests above: an unroutable DSN
    // leaves the store unopened. The bug this guards (Blocker 2 / PR #2202
    // review): the T8 preflight in server.cpp treats nullopt as "scan failed,
    // fail closed" and an engaged empty vector as "scan completed, nothing
    // colliding" — an unopened store must return the former, not silently
    // report a clean scan.
    PgPool bad{{.conninfo = "host=127.0.0.1 port=1 dbname=nope user=nope connect_timeout=1",
                .size = 1}};
    RbacStore broken{bad};
    REQUIRE_FALSE(broken.is_open());

    auto result = broken.find_local_groups_with_prefix("engine:");
    CHECK_FALSE(result.has_value());
}

// ── IdP membership reconciliation (#1832) ───────────────────────────────────

TEST_CASE("RbacStore: namespaced_group_name", "[rbac_store][pg]") {
    CHECK(namespaced_group_name("entra", "abc-123") == "entra:abc-123");
    CHECK(namespaced_group_name("saml", "g1") == "saml:g1");
    // 'local' is NOT namespaced.
    CHECK(namespaced_group_name("local", "raw-name") == "raw-name");
}

TEST_CASE("RbacStore: reconcile_idp_memberships namespacing prevents confused deputy",
         "[rbac_store][pg]") {
    RBAC_STORE(store);

    // A LOCAL group named "admins" already carries a role.
    store.create_group({"admins", "Local admins", "local", "", 0});
    REQUIRE(store.assign_role({"group", "admins", "Operator"}).has_value());

    // The IdP asserts a group with the SAME raw id "admins" for carol.
    auto reconciled = store.reconcile_idp_memberships("carol", "entra", {{"admins", "Admins"}});
    REQUIRE(reconciled.has_value());

    // carol must NOT inherit the local group's role via the same-named IdP
    // group — she landed in "entra:admins", a distinct row with no role
    // assignment of its own yet.
    CHECK_FALSE(store.check_permission("carol", "Execution", "Execute"));

    // The local group's membership is never touched by reconcile.
    auto local_members = store.get_group_members("admins");
    CHECK(local_members.empty());

    // Assigning the role to the NAMESPACED group (the correct, explicit
    // grant an operator would make) is what it takes for carol to get it —
    // proving namespacing, not raw-name collision, decides the outcome.
    REQUIRE(store.assign_role({"group", "entra:admins", "Operator"}).has_value());
    CHECK(store.check_permission("carol", "Execution", "Execute"));
}

TEST_CASE("RbacStore: reconcile_idp_memberships add/remove diff", "[rbac_store][pg]") {
    RBAC_STORE(store);

    REQUIRE(store.reconcile_idp_memberships("dave", "entra", {{"A", "A"}, {"B", "B"}})
                .has_value());
    CHECK(store.get_group_members("entra:A") == std::vector<std::string>{"dave"});
    CHECK(store.get_group_members("entra:B") == std::vector<std::string>{"dave"});

    // A separately-added LOCAL membership must survive every reconcile.
    store.create_group({"crew", "", "local", "", 0});
    store.add_group_member("crew", "dave");

    // Re-login only asserts A now — B must be dropped.
    REQUIRE(store.reconcile_idp_memberships("dave", "entra", {{"A", "A"}}).has_value());
    CHECK(store.get_group_members("entra:A") == std::vector<std::string>{"dave"});
    CHECK(store.get_group_members("entra:B").empty());
    CHECK(store.get_group_members("crew") == std::vector<std::string>{"dave"});
}

TEST_CASE("RbacStore: reconcile_idp_memberships empty asserted removes only that source",
         "[rbac_store][pg]") {
    RBAC_STORE(store);

    REQUIRE(store.reconcile_idp_memberships("erin", "entra", {{"A", "A"}}).has_value());
    REQUIRE(store.reconcile_idp_memberships("erin", "saml", {{"S1", "S1"}}).has_value());
    store.create_group({"local-crew", "", "local", "", 0});
    store.add_group_member("local-crew", "erin");

    // Next SSO login asserts NO groups at all — full deprovisioning.
    REQUIRE(store.reconcile_idp_memberships("erin", "entra", {}).has_value());

    CHECK(store.get_group_members("entra:A").empty());
    // Untouched: a different source, and a local group.
    CHECK(store.get_group_members("saml:S1") == std::vector<std::string>{"erin"});
    CHECK(store.get_group_members("local-crew") == std::vector<std::string>{"erin"});
}

// qa-S1: the row-presence assertions above prove the DELETE didn't touch the
// local group's *membership table row*, but the invariant that actually
// matters is the permission it grants. Attach a role to the LOCAL group and
// prove check_permission is bit-for-bit unchanged before and after an
// empty-asserted (full-deprovisioning) reconcile — this is what would catch
// a future regression that widens the stale-membership DELETE's scoping
// (e.g. a refactor that drops the `group_name IN (SELECT name FROM groups
// WHERE source = ?)` clause) even if row-presence checks were accidentally
// preserved.
TEST_CASE("RbacStore: empty-asserted reconcile cannot strip a local role grant",
         "[rbac_store][pg]") {
    RBAC_STORE(store);

    store.create_group({"local-crew", "", "local", "", 0});
    store.add_group_member("local-crew", "erin");
    REQUIRE(store.assign_role({"group", "local-crew", "Operator"}).has_value());

    REQUIRE(store.reconcile_idp_memberships("erin", "entra", {{"A", "A"}}).has_value());

    // Baseline: erin holds Operator permissions via the local group.
    REQUIRE(store.check_permission("erin", "Execution", "Execute"));
    REQUIRE(store.check_permission("erin", "Tag", "Write"));
    REQUIRE_FALSE(store.check_permission("erin", "Infrastructure", "Write"));

    // Full deprovisioning of the 'entra' source — asserts NO groups at all.
    REQUIRE(store.reconcile_idp_memberships("erin", "entra", {}).has_value());

    // The local role grant must be bit-for-bit unchanged.
    CHECK(store.check_permission("erin", "Execution", "Execute"));
    CHECK(store.check_permission("erin", "Tag", "Write"));
    CHECK_FALSE(store.check_permission("erin", "Infrastructure", "Write"));
}

TEST_CASE("RbacStore: reconcile_idp_memberships enforces the group-count cap", "[rbac_store][pg]") {
    RBAC_STORE(store);

    std::vector<std::pair<std::string, std::string>> asserted;
    asserted.reserve(RbacStore::kMaxIdpGroupsPerLogin + 1);
    for (size_t i = 0; i <= RbacStore::kMaxIdpGroupsPerLogin; ++i)
        asserted.emplace_back("g" + std::to_string(i), "g" + std::to_string(i));

    auto result = store.reconcile_idp_memberships("frank", "entra", asserted);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error() == "group_count_exceeded");

    // No mutation on rejection.
    CHECK(store.list_groups().empty());
    CHECK(store.get_group_members("entra:g0").empty());
}

// qa-S3: exactly the cap boundary succeeds — only `> kMaxIdpGroupsPerLogin`
// is rejected, not `==`.
TEST_CASE("RbacStore: reconcile_idp_memberships accepts exactly the group-count cap",
         "[rbac_store][pg]") {
    RBAC_STORE(store);

    std::vector<std::pair<std::string, std::string>> asserted;
    asserted.reserve(RbacStore::kMaxIdpGroupsPerLogin);
    for (size_t i = 0; i < RbacStore::kMaxIdpGroupsPerLogin; ++i)
        asserted.emplace_back("g" + std::to_string(i), "g" + std::to_string(i));

    auto result = store.reconcile_idp_memberships("frank2", "entra", asserted);
    REQUIRE(result.has_value());
    CHECK(result->added == RbacStore::kMaxIdpGroupsPerLogin);
    CHECK(store.get_group_members("entra:g0") == std::vector<std::string>{"frank2"});
}

TEST_CASE("RbacStore: reconcile_idp_memberships is idempotent", "[rbac_store][pg]") {
    RBAC_STORE(store);

    std::vector<std::pair<std::string, std::string>> asserted = {{"A", "A"}, {"B", "B"}};
    REQUIRE(store.reconcile_idp_memberships("gina", "entra", asserted).has_value());
    REQUIRE(store.reconcile_idp_memberships("gina", "entra", asserted).has_value());

    CHECK(store.get_group_members("entra:A") == std::vector<std::string>{"gina"});
    CHECK(store.get_group_members("entra:B") == std::vector<std::string>{"gina"});
    CHECK(store.list_groups().size() == 2);
}

// comp-S2/cons-S3: the {added, removed} counts a caller uses to decide
// whether to write a provisioning audit row.
TEST_CASE("RbacStore: reconcile_idp_memberships reports added/removed counts",
         "[rbac_store][pg]") {
    RBAC_STORE(store);

    auto first = store.reconcile_idp_memberships("hank", "entra", {{"A", "A"}, {"B", "B"}});
    REQUIRE(first.has_value());
    CHECK(first->added == 2);
    CHECK(first->removed == 0);

    // No-op re-login: same asserted set, nothing added or removed.
    auto noop = store.reconcile_idp_memberships("hank", "entra", {{"A", "A"}, {"B", "B"}});
    REQUIRE(noop.has_value());
    CHECK(noop->added == 0);
    CHECK(noop->removed == 0);

    // Drop B, add C: one added, one removed.
    auto diff = store.reconcile_idp_memberships("hank", "entra", {{"A", "A"}, {"C", "C"}});
    REQUIRE(diff.has_value());
    CHECK(diff->added == 1);
    CHECK(diff->removed == 1);
}

// UP-6: reconcile_idp_memberships must never accept "local" (or an empty
// string) as `source` — the stale-membership DELETE it runs is scoped to
// `groups.source = ?` and is only safe for an IdP source. A miswired call
// with "local" would mass-delete local group memberships fleet-wide.
TEST_CASE("RbacStore: reconcile_idp_memberships rejects source=='local'", "[rbac_store][pg]") {
    RBAC_STORE(store);

    store.create_group({"crew", "", "local", "", 0});
    store.add_group_member("crew", "ivan");
    REQUIRE(store.assign_role({"group", "crew", "Operator"}).has_value());

    auto result = store.reconcile_idp_memberships("ivan", "local", {{"crew", "crew"}});
    REQUIRE_FALSE(result.has_value());
    CHECK_FALSE(result.error().empty());

    // No mutation: the local membership and its role grant survive.
    CHECK(store.get_group_members("crew") == std::vector<std::string>{"ivan"});
    CHECK(store.check_permission("ivan", "Execution", "Execute"));
}

TEST_CASE("RbacStore: reconcile_idp_memberships rejects an empty source", "[rbac_store][pg]") {
    RBAC_STORE(store);
    auto result = store.reconcile_idp_memberships("ivan", "", {{"g", "g"}});
    REQUIRE_FALSE(result.has_value());
}

// F3 (Hermes pass-2 HIGH H2): reject any `source` outside the recognized IdP
// allowlist, not just "local"/empty. Without this, a caller passing
// source="engine" (or any other unrecognized string) could mint
// `engine:`-prefixed "IdP" groups via this path — it never checks
// has_reserved_idp_prefix or the create_group collision scan, since it's a
// raw upsert into `groups`, not a call through create_group.
TEST_CASE("RbacStore: reconcile_idp_memberships rejects an unrecognized source (e.g. 'engine')",
          "[rbac_store][pg]") {
    RBAC_STORE(store);
    auto result =
        store.reconcile_idp_memberships("ivan", "engine", {{"vuln", "engine:vuln"}});
    REQUIRE_FALSE(result.has_value());
    // No mutation on rejection — the rejected 'source' never gets a chance to
    // mint any group row (reserved 'engine:' namespace or otherwise).
    CHECK(store.list_groups().empty());

    // Also reject an arbitrary unrecognized string, not just the specific
    // "engine" probe above.
    auto result2 = store.reconcile_idp_memberships("ivan", "totally-made-up", {{"g", "g"}});
    REQUIRE_FALSE(result2.has_value());
}

// sec-L1: a group row that pre-exists with a DIFFERENT source than this
// reconcile call (e.g. a local group literally named `entra:x`, created
// before the create_group reserved-prefix guard existed, or by direct DB
// manipulation) must never be joined — that would leak whatever roles are
// granted to the pre-existing group to the IdP-authenticated user.
TEST_CASE("RbacStore: reconcile_idp_memberships does not join a pre-existing "
         "differently-sourced group",
         "[rbac_store][pg]") {
    // The `create_group` reserved-prefix guard means a source='local' create
    // named "entra:x" can no longer be made through the public API — which
    // is exactly the point of this scenario: a row like this can only exist
    // as a LEGACY artifact from before the guard shipped (or direct DB
    // manipulation). Seed it by bypassing the app layer, the same way a real
    // pre-upgrade deployment's data would.
    RBAC_STORE(store);
    seed_group_raw(rbac_pool_fx_, "entra:x", "Local admins", "local", "");

    REQUIRE(store.assign_role({"group", "entra:x", "Administrator"}).has_value());

    auto reconciled = store.reconcile_idp_memberships("judy", "entra", {{"x", "x"}});
    REQUIRE(reconciled.has_value());
    CHECK(reconciled->added == 0); // the join was skipped, not counted as added

    // judy must NOT be a member of the pre-existing local group, and must
    // NOT inherit its Administrator role.
    CHECK(store.get_group_members("entra:x").empty());
    CHECK_FALSE(store.check_permission("judy", "Infrastructure", "Write"));
}

// UP-9: an asserted entry with a blank/whitespace-only external_id must be
// skipped, never turned into a garbage `entra:` / `entra:   ` group.
TEST_CASE("RbacStore: reconcile_idp_memberships skips blank external_id", "[rbac_store][pg]") {
    RBAC_STORE(store);

    auto reconciled =
        store.reconcile_idp_memberships("karen", "entra", {{"", "Empty"}, {"   ", "Blank"},
                                                            {"real-id", "Real"}});
    REQUIRE(reconciled.has_value());
    CHECK(reconciled->added == 1);

    CHECK(store.get_group_members("entra:real-id") == std::vector<std::string>{"karen"});
    CHECK(store.get_group_members("entra:").empty());
    // No group was created for the blank/whitespace entries.
    auto groups = store.list_groups();
    CHECK(groups.size() == 1);
    CHECK(groups[0].name == "entra:real-id");
}

TEST_CASE("RbacStore: create_group rejects a local group with a reserved IdP prefix",
         "[rbac_store][pg]") {
    RBAC_STORE(store);

    auto local_collision = store.create_group({"entra:x", "", "local", "", 0});
    REQUIRE_FALSE(local_collision.has_value());

    // Every reserved prefix is covered.
    CHECK_FALSE(store.create_group({"saml:x", "", "local", "", 0}).has_value());
    CHECK_FALSE(store.create_group({"ad:x", "", "local", "", 0}).has_value());
    CHECK_FALSE(store.create_group({"local:x", "", "local", "", 0}).has_value());

    // An IdP-sourced create of the SAME name is exempt from the guard.
    auto idp_create = store.create_group({"entra:x", "", "entra", "x", 0});
    CHECK(idp_create.has_value());

    // A local group whose name merely CONTAINS (not starts with) a reserved
    // token is fine — only the leading `prefix:` is reserved.
    CHECK(store.create_group({"my-entra:team", "", "local", "", 0}).has_value());
}

// ── ITServiceOwner role ──────────────────────────────────────────────────────

TEST_CASE("RbacStore: ITServiceOwner role seeded with correct permissions", "[rbac_store][pg]") {
    RBAC_STORE(store);
    auto role = store.get_role("ITServiceOwner");
    REQUIRE(role.has_value());
    CHECK(role->is_system);
    CHECK(role->description.find("IT Service") != std::string::npos);

    auto perms = store.get_role_permissions("ITServiceOwner");
    // 18 types * 5 CRUD ops = 90 permissions, plus the targeted Push grant on
    // GuaranteedState = 91 permissions total. Push is deliberately NOT
    // cross-seeded on non-Guardian securables — see the rationale in
    // rbac_store.cpp seed_defaults(). (18th type: SoftwareLicensing, ADR-0024 —
    // ITServiceOwner full CRUD per the D-9 matrix.)
    CHECK(perms.size() == 91);
    size_t push_count = 0;
    for (auto& p : perms) {
        CHECK(p.effect == "allow");
        // Should not include UserManagement, Security, ApiToken
        CHECK(p.securable_type != "UserManagement");
        CHECK(p.securable_type != "Security");
        CHECK(p.securable_type != "ApiToken");
        if (p.operation == "Push") {
            ++push_count;
            CHECK(p.securable_type == "GuaranteedState");
        }
    }
    CHECK(push_count == 1);
}

// ── check_scoped_permission ──────────────────────────────────────────────────

namespace {
// The ManagementGroupStore is now a Postgres store (ADR-0042); the scoped-
// permission tests below wire the SQLite RbacStore to a PG-backed mgmt store.
// Pre-migrated template cloned per test (see PgTestTemplate in test_helpers.hpp).
yuzu::test::PgTestTemplate scoped_mgmt_tpl{"rbacscopedmgmt", [](const std::string& dsn) {
    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    ManagementGroupStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("rbacscopedmgmt template: mgmt store failed to migrate");
}};
} // namespace

TEST_CASE("RbacStore: check_scoped_permission global allow bypasses scoping", "[rbac_store][pg]") {
    RBAC_STORE(rbac);
    YUZU_REQUIRE_PG_DB_TPL(db, scoped_mgmt_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ManagementGroupStore mgmt{pool};

    rbac.assign_role({"user", "admin_user", "Administrator"});
    CHECK(rbac.check_scoped_permission("admin_user", "Tag", "Write", "agent-1", &mgmt));
}

TEST_CASE("RbacStore: check_scoped_permission group-scoped allow", "[rbac_store][pg]") {
    RBAC_STORE(rbac);
    YUZU_REQUIRE_PG_DB_TPL(db, scoped_mgmt_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ManagementGroupStore mgmt{pool};

    // Create a management group and add agent to it
    ManagementGroup g;
    g.name = "Service: CRM";
    g.membership_type = "static";
    auto group_id = mgmt.create_group(g);
    REQUIRE(group_id.has_value());
    mgmt.add_member(*group_id, "agent-crm-1");

    // Assign ITServiceOwner to alice on this group
    GroupRoleAssignment a;
    a.group_id = *group_id;
    a.principal_type = "user";
    a.principal_id = "alice";
    a.role_name = "ITServiceOwner";
    mgmt.assign_role(a);

    // alice has NO global role, but should have scoped access
    CHECK(rbac.check_scoped_permission("alice", "Tag", "Write", "agent-crm-1", &mgmt));
    CHECK(rbac.check_scoped_permission("alice", "Execution", "Execute", "agent-crm-1", &mgmt));
}

TEST_CASE("RbacStore: check_scoped_permission denied without scope", "[rbac_store][pg]") {
    RBAC_STORE(rbac);
    YUZU_REQUIRE_PG_DB_TPL(db, scoped_mgmt_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ManagementGroupStore mgmt{pool};

    // alice has ITServiceOwner on CRM group, but agent-other is not in it
    ManagementGroup g;
    g.name = "Service: CRM";
    g.membership_type = "static";
    auto group_id = mgmt.create_group(g);
    REQUIRE(group_id.has_value());
    mgmt.add_member(*group_id, "agent-crm-1");

    GroupRoleAssignment a;
    a.group_id = *group_id;
    a.principal_type = "user";
    a.principal_id = "alice";
    a.role_name = "ITServiceOwner";
    mgmt.assign_role(a);

    // agent-other is NOT in the CRM group
    CHECK_FALSE(rbac.check_scoped_permission("alice", "Tag", "Write", "agent-other", &mgmt));
}

// fable (Gate 4, #2703, HIGH): the scoped/confinement path has the SAME
// dual-role hazard as the global one above — role_effects_for() maps a
// role's effect for (type,op) into resolve_perm_groups()'s deny_groups,
// which check_scoped_permission()/authorize_list_read() then treat as a
// hard veto (and expand_visible_set() subtracts whole agent subtrees for).
// A revoked-default role must stay NEUTRAL in that resolution — never a
// deny_group — so a principal's independent grant via a DIFFERENT role
// scoped to the SAME management group still controls.
TEST_CASE("RbacStore: revoking one role's default does not create a scoped deny_group "
          "vetoing a different role's independent grant",
          "[rbac_store][pg]") {
    RBAC_STORE(rbac);
    YUZU_REQUIRE_PG_DB_TPL(db, scoped_mgmt_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ManagementGroupStore mgmt{pool};

    // Both ITServiceOwner and Operator seed Tag:Write by default.
    REQUIRE(rbac.check_role_has_permission("ITServiceOwner", "Tag", "Write"));
    REQUIRE(rbac.check_role_has_permission("Operator", "Tag", "Write"));
    REQUIRE(rbac.remove_permission("ITServiceOwner", "Tag", "Write").has_value());
    CHECK_FALSE(rbac.check_role_has_permission("ITServiceOwner", "Tag", "Write"));

    ManagementGroup g;
    g.name = "Service: CRM";
    g.membership_type = "static";
    auto group_id = mgmt.create_group(g);
    REQUIRE(group_id.has_value());
    mgmt.add_member(*group_id, "agent-crm-1");

    // alice holds BOTH roles scoped to the SAME group: ITServiceOwner
    // (revoked default) and Operator (independent, unrevoked grant).
    GroupRoleAssignment a_ito;
    a_ito.group_id = *group_id;
    a_ito.principal_type = "user";
    a_ito.principal_id = "alice";
    a_ito.role_name = "ITServiceOwner";
    mgmt.assign_role(a_ito);
    GroupRoleAssignment a_op;
    a_op.group_id = *group_id;
    a_op.principal_type = "user";
    a_op.principal_id = "alice";
    a_op.role_name = "Operator";
    mgmt.assign_role(a_op);

    // If the revoked role's absence were (wrongly) treated as a deny_group,
    // this would come back false. It must not — the revoked role is
    // neutral, exactly as if alice never held it for this (type,op).
    CHECK(rbac.check_scoped_permission("alice", "Tag", "Write", "agent-crm-1", &mgmt));
}

// ── Backfill (ADR-0009/0041 MANDATORY class) ─────────────────────────────────

namespace {
// Build a legacy (SQLite) rbac.db with the pre-migration schema + a known custom
// fixture: one custom role with a grant, a direct user assignment, a local group
// with a member, and the rbac_config('enabled') row set to `enabled`.
void make_legacy_rbac_db(const std::filesystem::path& path, bool enabled) {
    // adversarial-review (PR #2703, BLOCKER): raw sqlite3* with manual cleanup
    // leaked the handle on a REQUIRE failure between open and the final
    // sqlite3_close below — the same pattern already fixed elsewhere in this
    // file (e.g. the R2/F1 tests above) via SqliteDb RAII, missed here.
    SqliteDb db;
    REQUIRE(sqlite3_open_v2(path.string().c_str(), db.addr(),
                            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) == SQLITE_OK);
    const char* ddl =
        "CREATE TABLE securable_types (name TEXT PRIMARY KEY, description TEXT, is_system INTEGER);"
        "CREATE TABLE operations (id TEXT PRIMARY KEY, description TEXT, is_system INTEGER);"
        "CREATE TABLE roles (name TEXT PRIMARY KEY, description TEXT, is_system INTEGER, created_at "
        "INTEGER);"
        "CREATE TABLE role_permissions (role_name TEXT, securable_type TEXT, operation TEXT, effect "
        "TEXT);"
        "CREATE TABLE principal_roles (principal_type TEXT, principal_id TEXT, role_name TEXT);"
        "CREATE TABLE groups (name TEXT PRIMARY KEY, description TEXT, source TEXT, external_id "
        "TEXT, created_at INTEGER);"
        "CREATE TABLE group_members (group_name TEXT, username TEXT);"
        "CREATE TABLE rbac_config (key TEXT PRIMARY KEY, value TEXT);"
        // Custom operator-authored config that CANNOT be re-derived from seeds.
        "INSERT INTO roles VALUES ('CustomRole', 'operator authored', 0, 42);"
        "INSERT INTO role_permissions VALUES ('CustomRole', 'Tag', 'Read', 'allow');"
        "INSERT INTO principal_roles VALUES ('user', 'alice', 'CustomRole');"
        "INSERT INTO groups VALUES ('team-a', 'a local team', 'local', '', 7);"
        "INSERT INTO group_members VALUES ('team-a', 'bob');";
    SqliteErrMsg err;
    REQUIRE(sqlite3_exec(db.get(), ddl, nullptr, nullptr, err.addr()) == SQLITE_OK);
    std::string cfg = std::string("INSERT INTO rbac_config VALUES ('enabled', '") +
                      (enabled ? "true" : "false") + "');";
    REQUIRE(sqlite3_exec(db.get(), cfg.c_str(), nullptr, nullptr, nullptr) == SQLITE_OK);
}

// governance re-review (PR #2703, BLOCKING — canonicalization collision):
// minimal legacy DB with exactly ONE role, whose name/description are the
// caller's choice — lets a test craft two field splits that would collide
// under an unescaped delimiter join (e.g. name="a|b",desc="c" vs
// name="a",desc="b|c") but must NOT collide under the length-prefixed
// encoding this fix ships.
void make_legacy_rbac_db_one_role(const std::filesystem::path& path, const std::string& role_name,
                                  const std::string& role_desc) {
    SqliteDb db;
    REQUIRE(sqlite3_open_v2(path.string().c_str(), db.addr(),
                            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) == SQLITE_OK);
    const char* ddl =
        "CREATE TABLE roles (name TEXT PRIMARY KEY, description TEXT, is_system INTEGER, created_at "
        "INTEGER);"
        "CREATE TABLE role_permissions (role_name TEXT, securable_type TEXT, operation TEXT, effect "
        "TEXT);"
        "CREATE TABLE principal_roles (principal_type TEXT, principal_id TEXT, role_name TEXT);";
    SqliteErrMsg err;
    REQUIRE(sqlite3_exec(db.get(), ddl, nullptr, nullptr, err.addr()) == SQLITE_OK);
    SqliteStmt s;
    REQUIRE(sqlite3_prepare_v2(db.get(),
                               "INSERT INTO roles (name, description, is_system, created_at) "
                               "VALUES (?, ?, 0, 5)",
                               -1, s.addr(), nullptr) == SQLITE_OK);
    sqlite3_bind_text(s.get(), 1, role_name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s.get(), 2, role_desc.c_str(), -1, SQLITE_TRANSIENT);
    REQUIRE(sqlite3_step(s.get()) == SQLITE_DONE);
}
} // namespace

TEST_CASE("RbacStore: migrate_from_sqlite's fingerprint does not collide on a delimiter-crafted "
          "field split (governance re-review, PR #2703)",
          "[rbac_store][pg]") {
    RBAC_STORE(store);
    yuzu::test::TempDbFile legacy_a{"yuzu_test_rbac_collide_a-"};
    std::filesystem::remove(legacy_a.path);
    make_legacy_rbac_db_one_role(legacy_a.path, "a|b", "c");
    REQUIRE(store.migrate_from_sqlite(legacy_a.path));

    // Same shared marker (stamped for A's content above); replica B holds a
    // DIFFERENT legacy file whose fields split the same raw bytes across the
    // name/description boundary differently ("a" / "b|c" vs "a|b" / "c"). An
    // unescaped '|' join would canonicalize both to the identical preimage —
    // this must now be correctly detected as a MISMATCH, not silently waved
    // through as "already migrated, matches".
    RbacStore replica_b{rbac_pool_fx_};
    REQUIRE(replica_b.is_open());
    yuzu::test::TempDbFile legacy_b{"yuzu_test_rbac_collide_b-"};
    std::filesystem::remove(legacy_b.path);
    make_legacy_rbac_db_one_role(legacy_b.path, "a", "b|c");

    CHECK_FALSE(replica_b.migrate_from_sqlite(legacy_b.path));
    CHECK(std::filesystem::exists(legacy_b.path)); // refused, never moved aside
}

// governance re-review (PR #2703, HIGH — chaos-injector/unhappy-path,
// independently): the race stamp_complete's fingerprint upsert resolves is
// only reachable through genuine concurrency between two migrate_from_sqlite
// callers (a fileless replica's marker-absent check racing a real replica's
// slower migration) — the public API's own step-2 idempotency check makes a
// SEQUENTIAL two-call repro of the full end-to-end race impossible (whichever
// call completes first makes the second see "marker already present" and
// take the verify branch, never reaching stamp_complete at all). A fixed
// timing-dependent thread race, forcing the exact interleaving, would need a
// test-only pause hook inside migrate_from_sqlite — exactly the
// disproportionate-for-this-round complexity advisor input flagged when this
// fix was scoped.
//
// DISCLOSED LIMITATION: this test therefore verifies the upsert's SQL
// semantics directly against Postgres (the same three cases checked by hand
// before this was shipped) using a COPY of stamp_complete's fingerprint
// query, not a call into stamp_complete itself (a private lambda with no
// external call site). The copy is NOT auto-synced — if stamp_complete's
// fingerprint UPSERT in rbac_store.cpp ever changes, this copy must be
// updated to match or this test silently stops covering the real code.
TEST_CASE("RbacStore: backfill_source_fingerprint upsert promotes sourceless, protects a real "
          "value, and accepts a matching value (governance re-review, PR #2703)",
          "[rbac_store][pg]") {
    RBAC_STORE(store);
    REQUIRE(store.migrate_from_sqlite("/nonexistent/path/rbac.db")); // seeds 'sourceless'

    const auto stamp = [&](const std::string& value) -> int {
        auto lease = rbac_pool_fx_.acquire();
        REQUIRE(lease);
        pg::PgResult r = pg::exec_params(
            lease.get(),
            "INSERT INTO rbac_store.rbac_meta (key, value) VALUES "
            "('backfill_source_fingerprint', $1) ON CONFLICT (key) DO UPDATE SET "
            "value = EXCLUDED.value WHERE rbac_store.rbac_meta.value = 'sourceless' OR "
            "rbac_store.rbac_meta.value = EXCLUDED.value RETURNING value",
            std::vector<std::string>{value});
        REQUIRE(r.status() == PGRES_TUPLES_OK);
        return PQntuples(r.get());
    };
    const auto stored_value = [&]() -> std::string {
        auto lease = rbac_pool_fx_.acquire();
        REQUIRE(lease);
        pg::PgResult r = pg::exec_params(
            lease.get(),
            "SELECT value FROM rbac_store.rbac_meta WHERE key = 'backfill_source_fingerprint'",
            std::vector<std::string>{});
        REQUIRE(r.status() == PGRES_TUPLES_OK);
        REQUIRE(PQntuples(r.get()) == 1);
        return PQgetvalue(r.get(), 0, 0);
    };
    REQUIRE(stored_value() == "sourceless");

    // A real fingerprint promotes a stored sourceless placeholder — 1 row.
    CHECK(stamp("v2:real_A") == 1);
    CHECK(stored_value() == "v2:real_A");

    // A DIFFERENT real fingerprint may not overwrite the now-real value — 0
    // rows, and the stored value is untouched.
    CHECK(stamp("v2:real_B") == 0);
    CHECK(stored_value() == "v2:real_A");

    // The SAME real fingerprint writing again (two replicas sharing storage,
    // both migrating identical content, one loses only the INSERT race, not
    // the content race) counts as success, not a lost race — 1 row.
    CHECK(stamp("v2:real_A") == 1);
    CHECK(stored_value() == "v2:real_A");

    // A sourceless writer never overwrites an established real value — 0
    // rows (non-error for the sourceless caller per stamp_complete's own
    // exemption, exercised at the migrate_from_sqlite level elsewhere).
    CHECK(stamp("sourceless") == 0);
    CHECK(stored_value() == "v2:real_A");
}

TEST_CASE("RbacStore: migrate_from_sqlite returns false on an unopened store", "[rbac_store][pg]") {
    PgPool bad{{.conninfo = "host=127.0.0.1 port=1 dbname=nope user=nope connect_timeout=1",
                .size = 1}};
    RbacStore broken{bad};
    REQUIRE_FALSE(broken.is_open());
    CHECK_FALSE(broken.migrate_from_sqlite("/nonexistent/path/rbac.db"));
}

TEST_CASE("RbacStore: migrate_from_sqlite with no legacy file is a clean idempotent no-op",
          "[rbac_store][pg]") {
    RBAC_STORE(store);
    CHECK(store.migrate_from_sqlite("/nonexistent/path/rbac.db")); // fresh install
    CHECK(store.migrate_from_sqlite("/nonexistent/path/rbac.db")); // marker present → no-op
    // A fresh install stays RBAC-disabled by default (the seeded value).
    CHECK_FALSE(store.is_rbac_enabled());
}

TEST_CASE("RbacStore: migrate_from_sqlite backfills operator config, idempotently",
          "[rbac_store][pg]") {
    RBAC_STORE(store);
    yuzu::test::TempDbFile legacy{"yuzu_test_rbac_legacy-"};
    std::filesystem::remove(legacy.path); // make_legacy_rbac_db creates it fresh
    make_legacy_rbac_db(legacy.path, /*enabled=*/false);

    REQUIRE(store.migrate_from_sqlite(legacy.path));

    // Custom role + grant carried across.
    CHECK(store.get_role("CustomRole").has_value());
    CHECK(store.check_role_has_permission("CustomRole", "Tag", "Read"));
    // Direct assignment carried across → alice resolves the custom grant.
    CHECK(store.check_permission("alice", "Tag", "Read"));
    // Group + membership carried across.
    CHECK(store.get_group_members("team-a") == std::vector<std::string>{"bob"});

    // Legacy file moved aside after a verified backfill.
    CHECK_FALSE(std::filesystem::exists(legacy.path));

    // Idempotent: a second call (marker present) is a no-op success.
    CHECK(store.migrate_from_sqlite(legacy.path));
    // No duplicate assignment rows.
    auto pr = store.get_principal_roles("user", "alice");
    CHECK(pr.size() == 1);
}

// adversarial-review (PR #2703, BLOCKER, both Kimi and Codex independently):
// docs/postgres-store-playbook.md "Local source absence never creates
// terminal migration state on its own" (#2697). A replica with no local
// legacy file stamping the SHARED backfill_complete marker must not let a
// SIBLING replica that genuinely holds the legacy file silently skip its
// own migration — the fix is holder-side fingerprint verification, and this
// is the regression test for the exact scenario both reviewers described.
TEST_CASE("RbacStore: migrate_from_sqlite refuses a sourceless sibling's marker on a later boot "
          "even though this replica genuinely holds the legacy file (adversarial-review #2703, "
          "REVERTED by governance re-review round 2 back to refusal — see the code comment at "
          "the sourceless branch)",
          "[rbac_store][pg]") {
    // governance re-review round 2 (unhappy-path, HIGH): this test previously
    // asserted a fall-through-and-promote here, which this replica's own
    // round-2 re-review found unsafe — a fileless sibling's sourceless stamp
    // makes rbac_store operational (seeded defaults only), and a live IdP
    // login in the interim can run reconcile_idp_memberships, which this
    // replica's later fall-through migration could silently clobber (delete-
    // then-resurrect a group_members row). Promotion stays safe ONLY at
    // STAMP TIME, inside a replica's OWN migration (see the separate
    // "backfill_source_fingerprint upsert promotes sourceless" test above,
    // which exercises exactly that path and is unaffected by this revert). A
    // LATER boot that merely FINDS the marker already sourceless must refuse.
    RBAC_STORE(store);
    // "Replica A" — no local legacy file, stamps the shared marker with the
    // sourceless sentinel fingerprint.
    CHECK(store.migrate_from_sqlite("/nonexistent/path/rbac.db"));

    // "Replica B" — same shared Postgres (rbac_pool_fx_), but this one
    // genuinely holds a legacy file with real, non-empty operator content,
    // and boots AFTER the marker was already stamped sourceless.
    RbacStore replica_b{rbac_pool_fx_};
    REQUIRE(replica_b.is_open());
    yuzu::test::TempDbFile legacy{"yuzu_test_rbac_sourceless_race-"};
    std::filesystem::remove(legacy.path);
    make_legacy_rbac_db(legacy.path, /*enabled=*/true);

    // Refused, not silently accepted OR silently re-migrated — the file must
    // survive untouched, and no operator config it holds must land in PG.
    CHECK_FALSE(replica_b.migrate_from_sqlite(legacy.path));
    CHECK(std::filesystem::exists(legacy.path));
    CHECK_FALSE(replica_b.is_rbac_enabled());
    auto pr = replica_b.get_principal_roles("user", "alice");
    CHECK(pr.empty());
}

// The positive counterpart: a replica whose OWN legacy file is still present
// after ITS OWN completed migration (e.g. the move-aside rename failed) must
// verify as a MATCH and skip re-migrating, not refuse.
TEST_CASE("RbacStore: migrate_from_sqlite verifies a matching fingerprint when this replica's "
          "own already-migrated legacy file is still present (adversarial-review #2703)",
          "[rbac_store][pg]") {
    RBAC_STORE(store);
    yuzu::test::TempDbFile legacy{"yuzu_test_rbac_fp_match-"};
    std::filesystem::remove(legacy.path);
    make_legacy_rbac_db(legacy.path, /*enabled=*/false);
    REQUIRE(store.migrate_from_sqlite(legacy.path));
    CHECK_FALSE(std::filesystem::exists(legacy.path)); // moved aside as usual

    // Recreate a file with IDENTICAL logical content at the same path —
    // simulating a failed move-aside on a real restart, where the original
    // file is still sitting there holding the SAME content already migrated.
    make_legacy_rbac_db(legacy.path, /*enabled=*/false);
    RbacStore reopened{rbac_pool_fx_};
    REQUIRE(reopened.is_open());
    CHECK(reopened.migrate_from_sqlite(legacy.path));
    // Verified, not re-migrated: no duplicate assignment rows.
    auto pr = reopened.get_principal_roles("user", "alice");
    CHECK(pr.size() == 1);
    // cpp-safety (governance re-review round 2): the matched-fingerprint
    // branch retries move_legacy_aside — machine-check that it actually
    // ran, not just that migrate_from_sqlite returned true.
    CHECK_FALSE(std::filesystem::exists(legacy.path));
}

// governance re-review (PR #2703, HIGH — unhappy-path, EMPIRICALLY reproduced
// against a live Postgres before this fix): a marker stamped by the
// pre-fingerprint-mechanism code (backfill_complete present, NO
// backfill_source_fingerprint row at all) must NOT be silently trusted or
// silently re-migrated — unlike the sourceless case, a real migration DID
// happen under the old scheme, so this replica may hold live post-cutover
// operator changes a fresh re-migration would clobber. Making this permanent
// per the original scratch repro (built, run red, reverted).
TEST_CASE("RbacStore: migrate_from_sqlite refuses (not silently trusts, not silently "
          "re-migrates) a pre-fingerprint-mechanism marker when this replica holds real legacy "
          "content (governance re-review, PR #2703)",
          "[rbac_store][pg]") {
    RBAC_STORE(store);
    // Simulate a marker stamped by the pre-31273f288 code: `backfill_complete`
    // present, no `backfill_source_fingerprint` row.
    {
        auto lease = rbac_pool_fx_.acquire();
        REQUIRE(lease);
        pg::PgResult r = pg::exec_params(
            lease.get(),
            "INSERT INTO rbac_store.rbac_meta (key, value) VALUES ('backfill_complete', '1') "
            "ON CONFLICT (key) DO NOTHING",
            std::vector<std::string>{});
        REQUIRE(r.status() == PGRES_COMMAND_OK);
    }
    yuzu::test::TempDbFile legacy{"yuzu_test_rbac_prefingerprint_upgrade-"};
    std::filesystem::remove(legacy.path);
    make_legacy_rbac_db(legacy.path, /*enabled=*/true);

    CHECK_FALSE(store.migrate_from_sqlite(legacy.path));
    // Refused, not silently accepted OR silently re-migrated — the file must
    // survive untouched either way.
    CHECK(std::filesystem::exists(legacy.path));
    CHECK_FALSE(store.is_rbac_enabled());
}

// THE CRITICAL CLAUSE (ADR-0041): losing the rbac_enabled flag silently reverts
// the fleet to RBAC-off = catastrophic fail-open. An ENABLED legacy DB must come
// up ENABLED even though the fresh PG store seeds the default 'false' first.
TEST_CASE("RbacStore: migrate_from_sqlite preserves an ENABLED rbac_enabled flag",
          "[rbac_store][pg]") {
    RBAC_STORE(store);
    REQUIRE_FALSE(store.is_rbac_enabled()); // seeded default before backfill
    yuzu::test::TempDbFile legacy{"yuzu_test_rbac_legacy_on-"};
    std::filesystem::remove(legacy.path);
    make_legacy_rbac_db(legacy.path, /*enabled=*/true);

    REQUIRE(store.migrate_from_sqlite(legacy.path));

    // The flag was migrated first + read-back-verified — the store is now ENABLED
    // and enforcement is in effect (never silently reverted to RBAC-off).
    CHECK(store.is_rbac_enabled());
    CHECK(rbac_enforcement_in_effect(&store));
}

TEST_CASE("RbacStore: migrate_from_sqlite fails closed on an unreadable legacy file",
          "[rbac_store][pg]") {
    RBAC_STORE(store);
    yuzu::test::TempDbFile corrupt{"yuzu_test_rbac_corrupt-"};
    {
        std::ofstream f(corrupt.path, std::ios::binary | std::ios::trunc);
        REQUIRE(f.is_open());
        f << "not a valid sqlite database at all";
    }
    // A non-empty non-SQLite file cannot be opened read-only → fail closed
    // (boot refuses), never a silent skip that would drop operator config.
    CHECK_FALSE(store.migrate_from_sqlite(corrupt.path));
    // No marker stamped → a later boot with a repaired/absent file retries and
    // can still complete (proves the failure did not stamp the completion marker).
    CHECK(store.migrate_from_sqlite("/nonexistent/rbac.db"));
}

// governance re-review (PR #2703 round 2, cpp-expert HIGH): read_legacy_snapshot's
// rbac_config.enabled read previously had NO failure accounting at all, unlike
// every other row-category read — a genuine SQLite read error there (not
// "table/row absent") silently kept the "false" default, which nothing
// downstream (read-back verify, reconciliation, the fingerprint) could catch
// because they all derive from the same already-poisoned snapshot. This
// forces exactly that error (rbac_config exists with the WRONG schema, so
// the SELECT fails to PREPARE) and proves the backfill now refuses instead
// of silently proceeding with rbac_enabled=false.
TEST_CASE("RbacStore: migrate_from_sqlite fails closed when legacy rbac_config.enabled cannot "
          "be read due to a genuine schema error, not silently defaulted to false",
          "[rbac_store][pg]") {
    RBAC_STORE(store);
    yuzu::test::TempDbFile legacy{"yuzu_test_rbac_config_read_error-"};
    std::filesystem::remove(legacy.path);
    {
        SqliteDb db;
        REQUIRE(sqlite3_open_v2(legacy.path.string().c_str(), db.addr(),
                                SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) == SQLITE_OK);
        const char* ddl =
            "CREATE TABLE roles (name TEXT PRIMARY KEY, description TEXT, is_system INTEGER, "
            "created_at INTEGER);"
            "CREATE TABLE role_permissions (role_name TEXT, securable_type TEXT, operation TEXT, "
            "effect TEXT);"
            "CREATE TABLE principal_roles (principal_type TEXT, principal_id TEXT, role_name "
            "TEXT);"
            // rbac_config EXISTS but WITHOUT a `value` column, so the SELECT
            // that reads rbac_enabled fails to PREPARE — a genuine read
            // error, not "table/row absent".
            "CREATE TABLE rbac_config (key TEXT PRIMARY KEY);"
            "INSERT INTO roles VALUES ('CustomRole', 'operator authored', 0, 42);";
        SqliteErrMsg err;
        REQUIRE(sqlite3_exec(db.get(), ddl, nullptr, nullptr, err.addr()) == SQLITE_OK);
    }

    CHECK_FALSE(store.migrate_from_sqlite(legacy.path));
    // Refused, not silently accepted with rbac_enabled defaulted to false —
    // the file must survive untouched.
    CHECK(std::filesystem::exists(legacy.path));
}

// The load-bearing ADR-0041 invariant (Gate 3 QE BLOCKING): every authz read
// on a degraded/unopened store must DENY, never fail open. This is the whole
// reason the migration preserves deny-on-error on the bool paths.
TEST_CASE("RbacStore: every authz read fails closed (DENY) on a broken store",
          "[rbac_store][pg]") {
    PgPool bad{{.conninfo = "host=192.0.2.1 port=1 dbname=x user=x connect_timeout=1", .size = 1}};
    RbacStore broken{bad};
    REQUIRE_FALSE(broken.is_open());
    CHECK_FALSE(broken.check_permission("alice", "Execution", "Execute"));
    CHECK_FALSE(broken.check_scoped_permission("alice", "Execution", "Execute", "agent-1", nullptr));
    CHECK_FALSE(broken.holds_permission_via_any_group("alice", "Execution", "Execute", nullptr));
    CHECK_FALSE(broken.check_role_has_permission("Administrator", "Execution", "Execute"));
    // Tri-state read degrades distinguishably (unexpected), never an engaged allow.
    CHECK_FALSE(broken.get_principal_roles_checked("user", "alice").has_value());
    // The list-read chokepoint denies-all on a degraded store (never AdmitAll).
    CHECK(broken.authorize_list_read("alice", "Agent", "Read", nullptr).decision ==
          ListReadDecision::DenyAll);
}

// The generation-token cache must not serve a stale ALLOW after a revoke on the
// same instance (Gate 3 QE BLOCKING): a mutation bumps the durable generation
// in-txn and clears the local cache, so the next check re-reads and denies.
TEST_CASE("RbacStore: a revoke invalidates a cached allow (generation token)",
          "[rbac_store][pg]") {
    RBAC_STORE(store);
    store.assign_role({"user", "cacheuser", "Administrator"}); // Administrator = allow-all
    // Warm perm_cache_ with an ALLOW verdict.
    CHECK(store.check_permission("cacheuser", "Execution", "Execute"));
    // Revoke — bumps write_generation in the same txn + clears the local cache.
    REQUIRE(store.unassign_role("user", "cacheuser", "Administrator").has_value());
    // The previously-cached allow must NOT be served; the check re-reads → DENY.
    CHECK_FALSE(store.check_permission("cacheuser", "Execution", "Execute"));
}

// adversarial-review round (PR #2703): both external reviewers (Kimi, Codex)
// independently found that maybe_refresh_generation()'s "never touch
// rbac_enabled_ on a read error" contract only reasons about the true->false
// fail-open direction -- a replica that has never itself observed a remote
// enable stays cached false (enforcement NOT in effect, i.e. AdmitAll)
// indefinitely through an outage, even after the durable flag has genuinely
// flipped true elsewhere. Reproduces the real production code path: replica
// A durably enables RBAC (bumping write_generation); replica B (a SEPARATE
// store+pool against the SAME database) never observes that write because
// its own size-1 pool is starved for its next refresh attempt, which
// genuinely times out and lands in the !durable_gen branch.
TEST_CASE("RbacStore: rbac_enforcement_in_effect fails closed when a generation refresh fails "
          "while another replica has durably enabled RBAC (adversarial-review round, #2703)",
          "[rbac_store][pg]") {
    RBAC_STORE(replica_a);
    REQUIRE_FALSE(replica_a.is_rbac_enabled()); // fresh install default

    // "Replica B": a separate store + size-1 pool against the SAME database,
    // so it can be starved independently of replica_a's own pool.
    PgPool pool_b{{.conninfo = rbac_db_fx_.dsn(), .size = 1}};
    REQUIRE(pool_b.valid());
    RbacStore replica_b{pool_b};
    REQUIRE(replica_b.is_open());
    REQUIRE_FALSE(replica_b.is_rbac_enabled());
    // Baseline this test's failure branch must diverge from: genuinely
    // fresh + disabled correctly reports enforcement NOT in effect.
    REQUIRE_FALSE(rbac_enforcement_in_effect(&replica_b));

    // Replica A durably enables RBAC -- bumps write_generation in the same
    // txn (ADR-0041 contract).
    replica_a.set_rbac_enabled(true);
    REQUIRE(replica_a.is_rbac_enabled());

    // Clear replica_b's refresh gate so its next read genuinely attempts a
    // durable re-read rather than serving its just-constructed cache.
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));

    // Starve replica_b's own pool: its next maybe_refresh_generation() call
    // cannot acquire a connection and must time out.
    auto held = pool_b.acquire();
    REQUIRE(held);

    // Pre-fix: is_rbac_enabled() correctly stays false (the existing
    // contract), but rbac_enforcement_in_effect() ALSO returned false,
    // wrongly admitting the full fleet. Post-fix: enforcement stays in
    // effect because the view is degraded, not confirmed-disabled.
    CHECK_FALSE(replica_b.is_rbac_enabled());
    CHECK(rbac_enforcement_in_effect(&replica_b));
}

// quality-engineer (#2703): the F3 staleness predicate, pinned with synthetic
// timestamps — no DB, no real clock. rbac_generation_rules.hpp.
TEST_CASE("rbac_generation::is_stale_beyond_bound", "[rbac_store]") {
    using yuzu::server::rbac_generation::is_stale_beyond_bound;

    // Fresh: last success just now, bound not yet reached.
    CHECK_FALSE(is_stale_beyond_bound(/*now_ms=*/1000, /*last_successful_refresh_ms=*/1000,
                                       /*bound_ms=*/1000));
    CHECK_FALSE(is_stale_beyond_bound(1500, 1000, 1000));
    // Exactly at the bound counts as stale (>=, not >).
    CHECK(is_stale_beyond_bound(2000, 1000, 1000));
    // Past the bound.
    CHECK(is_stale_beyond_bound(5000, 1000, 1000));
    // A refresh that has never succeeded (last_successful_refresh_ms_ still at
    // its zero-init) is stale from the first ms once the bound has elapsed.
    CHECK(is_stale_beyond_bound(1000, 0, 1000));
    CHECK_FALSE(is_stale_beyond_bound(999, 0, 1000));
}

// R2 (Gate 4 unhappy, CONFIRMED fail-open): the backfill must preserve an
// operator's edit to a SEEDED system-role permission (e.g. flipping a default
// 'allow' to 'deny'), which collides on the (role,type,op) key with the seed.
// DO NOTHING would drop the operator's deny (resurrecting a revoked permission);
// DO UPDATE preserves it.
TEST_CASE("RbacStore: backfill preserves an operator's deny-override on a seeded role",
          "[rbac_store][pg]") {
    RBAC_STORE(store);
    // Seeded Viewer has AuditLog/Read = allow.
    yuzu::test::TempDbFile legacy{"yuzu_test_rbac_r2-"};
    std::filesystem::remove(legacy.path);
    make_legacy_rbac_db(legacy.path, /*enabled=*/false);
    // The operator had revoked Viewer's AuditLog/Read in the legacy DB (deny).
    {
        // cpp-safety (Gate 3, #2703): RAII throughout — see the F1 test below
        // for the same fix and rationale.
        SqliteDb db;
        REQUIRE(sqlite3_open(legacy.path.string().c_str(), db.addr()) == SQLITE_OK);
        REQUIRE(sqlite3_exec(db.get(),
                             "INSERT INTO role_permissions VALUES "
                             "('Viewer','AuditLog','Read','deny');",
                             nullptr, nullptr, nullptr) == SQLITE_OK);
    }
    REQUIRE(store.migrate_from_sqlite(legacy.path));
    // The legacy 'deny' must win over the seeded 'allow' (DO UPDATE, not DO NOTHING).
    const auto perms = store.get_role_permissions("Viewer");
    std::string effect;
    for (const auto& p : perms)
        if (p.securable_type == "AuditLog" && p.operation == "Read")
            effect = p.effect;
    CHECK(effect == "deny");
}

// fjarvis F1 (#2703, HIGH) — the mirror image of R2 above. R2 is "legacy has
// an explicit deny that collides with the seed" (DO UPDATE preserves it). F1
// is "legacy has NOTHING for a seeded default" (no row to collide with): the
// backfill's perms loop only iterates rows PRESENT in legacy, so a default
// permission the operator explicitly removed via remove_permission() before
// upgrading has no positive row to upsert against. seed_defaults() (which
// runs in the constructor, before this backfill) already re-added it, and
// nothing touched it. The row-count reconciliation can't catch this either
// (PG always holds >= legacy counts by design — a missing-in-legacy row is
// invisible to a count check). The fix scopes a DELETE + revoked_seed_defaults
// marker to (role,type) pairs legacy's OWN catalogue actually knew about, so
// it never touches a securable a LATER seed_defaults() adds — e.g.
// EnginePrincipal, #2376 — asserted explicitly below alongside the surgical
// role/type scoping. (Two earlier versions of this fix each reintroduced a
// hazard: a plain DELETE resurrects on the next restart — the same disease
// remove_permission() was fixed to avoid, asserted below; an UPDATE-to-deny
// tombstone avoids that but silently changes the authorization OUTCOME for a
// dual-role principal — see the dedicated dual-role test above.)
TEST_CASE("RbacStore: backfill removes a seeded default permission the operator explicitly "
          "removed in legacy, and it survives a reseed",
          "[rbac_store][pg]") {
    RBAC_STORE(store);
    yuzu::test::TempDbFile legacy{"yuzu_test_rbac_f1-"};
    std::filesystem::remove(legacy.path);
    make_legacy_rbac_db(legacy.path, /*enabled=*/false);
    {
        // cpp-safety (Gate 3, #2703): RAII throughout, matching production
        // migrate_from_sqlite's own SqliteDb usage — a REQUIRE failure
        // between open and close must not leak the handle.
        SqliteDb db;
        REQUIRE(sqlite3_open(legacy.path.string().c_str(), db.addr()) == SQLITE_OK);
        // Legacy KNOWS about role "Viewer" and securable_type "AuditLog"
        // (both existed pre-upgrade) — this is exactly what scopes the
        // delete. Deliberately NO ('Viewer','AuditLog','Read') row: the
        // operator called remove_permission() to revoke it before upgrading.
        REQUIRE(sqlite3_exec(db.get(),
                             "INSERT INTO roles VALUES ('Viewer', 'seeded', 1, 0);"
                             "INSERT INTO securable_types VALUES ('AuditLog', '', 1);",
                             nullptr, nullptr, nullptr) == SQLITE_OK);
    }
    REQUIRE(store.migrate_from_sqlite(legacy.path));

    // THE FIX: the revoked default does not come back.
    CHECK_FALSE(store.check_role_has_permission("Viewer", "AuditLog", "Read"));
    // Surgical, not wholesale: an UNRELATED seeded default for the SAME role
    // survives — its securable_type ("Response") is not in legacy's
    // securable_types, so the type-filter excludes it from the deny.
    CHECK(store.check_role_has_permission("Viewer", "Response", "Read"));
    // A DIFFERENT role's grant on the SAME securable_type ("AuditLog")
    // survives — "Administrator" is not in legacy's roles table, so the
    // role-filter excludes it regardless of the type match.
    CHECK(store.check_role_has_permission("Administrator", "AuditLog", "Read"));
    // A securable that never existed in legacy at all — EnginePrincipal,
    // #2376 — is never touched by this deny for either role: its type is
    // absent from legacy's securable_types, so the type-filter excludes it
    // outright. This is the assertion that would fail if the fix's scoping
    // were loosened to "deny anything absent from legacy's perms".
    CHECK(store.check_role_has_permission("Administrator", "EnginePrincipal", "Read"));
    CHECK(store.check_role_has_permission("Viewer", "EnginePrincipal", "Read"));

    // happy-path (Gate 4, #2703, HIGH) — THE REGRESSION THIS CLOSES: a hard
    // DELETE with no accompanying marker has nothing for seed_defaults()'s
    // ON CONFLICT DO NOTHING to conflict with, so the very next ordinary
    // restart after this one-time backfill silently reinserts the seeded
    // 'allow' and undoes the operator's pre-cutover revocation — reproduced
    // empirically by constructing a second RbacStore against the same pool
    // (simulating a restart) and observing the revoked permission come
    // back. Fixed by recording the revocation in revoked_seed_defaults
    // alongside the DELETE, mirroring remove_permission()'s own fix for the
    // identical hazard post-cutover — grant()'s WHERE NOT EXISTS against
    // that table is what makes this assertion hold.
    RbacStore reopened{rbac_pool_fx_};
    CHECK_FALSE(reopened.check_role_has_permission("Viewer", "AuditLog", "Read"));
}

// fjarvis F2 (#2703, HIGH), schema-level layer: `rbac_meta.value` for
// key='rbac_enabled' is now constrained to exactly "true"/"false" (migration
// v2). A write attempting anything else — a hand-edit, a future bug writing
// a different boolean convention — must be rejected outright at write time,
// not land silently and wait to be discovered on the next boot/refresh.
TEST_CASE("RbacStore: rbac_meta rejects a non-canonical rbac_enabled value at write time",
          "[rbac_store][pg]") {
    RBAC_STORE(store);
    auto lease = rbac_pool_fx_.acquire();
    REQUIRE(lease);
    pg::PgResult r = pg::exec_params(
        lease.get(), "UPDATE rbac_store.rbac_meta SET value = 'TRUE' WHERE key = 'rbac_enabled'",
        std::vector<std::string>{});
    CHECK(r.status() == PGRES_FATAL_ERROR);
    // 23514 = check_violation (SQLSTATE) — confirms it's the new constraint
    // firing, not some unrelated failure.
    const char* sqlstate = PQresultErrorField(r.get(), PG_DIAG_SQLSTATE);
    REQUIRE(sqlstate != nullptr);
    CHECK(std::string(sqlstate) == "23514");
}

// fjarvis F2 (#2703, HIGH), application-level layer (defense in depth): even
// with the schema-level guard bypassed — as an older un-migrated deployment
// would be, or a maintenance script run with elevated privilege — a
// non-canonical value already sitting in the row must not silently coerce to
// "false" (RBAC-off) on the next boot. `load_enabled_flag()` must refuse.
TEST_CASE("RbacStore: refuses to start on a non-canonical rbac_enabled value already in the row",
          "[rbac_store][pg]") {
    RBAC_STORE(store);
    {
        auto lease = rbac_pool_fx_.acquire();
        REQUIRE(lease);
        REQUIRE(pg::exec_params(lease.get(),
                                "ALTER TABLE rbac_store.rbac_meta DROP CONSTRAINT "
                                "rbac_meta_enabled_canonical",
                                std::vector<std::string>{})
                    .ok());
        REQUIRE(pg::exec_params(lease.get(),
                                "UPDATE rbac_store.rbac_meta SET value = 'TRUE' WHERE key = "
                                "'rbac_enabled'",
                                std::vector<std::string>{})
                    .ok());
    }
    // A fresh construction against the SAME (now-corrupted) database must
    // refuse to open, not silently boot RBAC-off. seed_defaults()'s
    // rbac_enabled INSERT is ON CONFLICT DO NOTHING, so it does not clobber
    // the hand-set value before load_enabled_flag() reads it.
    RbacStore reopened{rbac_pool_fx_};
    CHECK_FALSE(reopened.is_open());
}
