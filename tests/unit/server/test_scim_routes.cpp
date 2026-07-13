/**
 * test_scim_routes.cpp — HTTP-level coverage for the SCIM v2 provisioning
 * surface (/scim/v2/*, slice 3 of 3). Registers ScimRoutes against an
 * in-process TestRouteSink (no socket, no acceptor thread — TSan-safe,
 * #438) over a REAL AuthDB + ScimStore pair sharing one auth.db file, so
 * the AuthManager provisioning path (upsert_user/remove_user/
 * get_provisioning_source) is exercised for real rather than faked.
 *
 * Coverage: bearer gate (401 missing/wrong token), discovery documents,
 * POST provision (201 + Location/ETag, 409 duplicate userName), GET by id
 * (200/404), GET ?filter=, the full PATCH active=false -> active=true
 * deprovision/reactivate round-trip (asserts the underlying auth account
 * is ACTUALLY deactivated then reactivated — not just the SCIM resource
 * flag — and that lockout state is cleared on reactivation per AuthDB::
 * reactivate_user's contract), DELETE (204 + soft-deleted), and the
 * LOAD-BEARING provenance guard: SCIM must never mutate a LOCALLY-created
 * account, even when a scim_resource row happens to reference it
 * (defense-in-depth — see scim_routes.cpp `provenance_ok`), including on
 * the reactivate path.
 */

#include "scim_routes.hpp"

#include "audit_store.hpp"
#include "on_behalf_guard.hpp"
#include "rate_limiter.hpp"
#include "test_route_sink.hpp"
#include "web_utils.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>
#include <yuzu/server/auth_db.hpp>
#include <yuzu/server/scim_json.hpp>
#include <yuzu/server/scim_store.hpp>
#include <yuzu/server/server.hpp>

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

using namespace yuzu::server;
using json = nlohmann::json;

namespace {

/// Wires ScimRoutes against a real AuthDB + ScimStore sharing one auth.db
/// file (mirrors production: ScimStore opens a second connection to the
/// SAME file AuthDB manages) plus a real AuditStore, all over an
/// in-process TestRouteSink.
struct Fixture {
    std::filesystem::path data_dir{yuzu::test::unique_temp_path("yuzu-scim-routes-")};
    std::unique_ptr<AuthDB> auth_db;
    auth::AuthManager auth_mgr;
    std::unique_ptr<ScimStore> scim_store;
    yuzu::test::TempDbFile audit_db_file{std::string_view{"yuzu-scim-routes-audit-"}};
    std::unique_ptr<AuditStore> audit_store;
    test::TestRouteSink sink;
    std::unique_ptr<ScimRoutes> routes;
    const std::string token{"unit-test-scim-bearer-token-0123456789"};

    /// `broken_audit=true` points AuditStore at a path whose parent
    /// directory does not exist, so `sqlite3_open_v2` fails and every
    /// `AuditStore::log()` call returns false thereafter — used to exercise
    /// the set-and-proceed vs. fail-closed audit contract
    /// (M-AUDIT-FAILCLOSED) without needing mid-test fault injection.
    /// `scim_admin_group` mirrors `Config::scim_admin_group` (#2021
    /// Groups->role) — empty (the default) means no SCIM group ever
    /// promotes to admin.
    explicit Fixture(bool broken_audit = false, std::string scim_admin_group = {}) {
        std::filesystem::create_directories(data_dir);
        auth_db = std::make_unique<AuthDB>(data_dir, /*cleanup_interval_secs=*/0);
        REQUIRE(auth_db->initialize().has_value());
        auth_mgr.set_auth_db(auth_db.get());

        scim_store = std::make_unique<ScimStore>(data_dir / "auth.db");
        REQUIRE(scim_store->is_open());
        REQUIRE(scim_store->set_token(token, "test"));

        if (broken_audit) {
            audit_store = std::make_unique<AuditStore>(
                std::filesystem::path("/nonexistent-yuzu-scim-test-dir-0123") / "audit.db");
            REQUIRE_FALSE(audit_store->is_open());
        } else {
            audit_store = std::make_unique<AuditStore>(audit_db_file.path);
            REQUIRE(audit_store->is_open());
        }

        routes = std::make_unique<ScimRoutes>();
        routes->register_routes(sink, scim_store.get(), &auth_mgr, audit_store.get(),
                                std::move(scim_admin_group));
    }

    ~Fixture() {
        std::error_code ec;
        routes.reset();
        audit_store.reset();
        scim_store.reset();
        auth_db.reset();
        std::filesystem::remove_all(data_dir, ec);
    }

    std::unordered_map<std::string, std::string> auth_header() const {
        return {{"Authorization", "Bearer " + token}};
    }

    auto get(const std::string& path) {
        return sink.dispatch("GET", path, {}, "application/json", auth_header());
    }
    auto post(const std::string& path, const json& body) {
        return sink.dispatch("POST", path, body.dump(), "application/scim+json", auth_header());
    }
    auto patch(const std::string& path, const json& body) {
        return sink.dispatch("PATCH", path, body.dump(), "application/scim+json", auth_header());
    }
    auto put(const std::string& path, const json& body) {
        return sink.dispatch("PUT", path, body.dump(), "application/scim+json", auth_header());
    }
    auto del(const std::string& path) {
        return sink.dispatch("DELETE", path, {}, "application/scim+json", auth_header());
    }
};

} // namespace

// ── Bearer gate ──────────────────────────────────────────────────────────

TEST_CASE("ScimRoutes: 401 without a bearer token", "[scim][routes][auth]") {
    Fixture f;
    auto res = f.sink.dispatch("GET", "/scim/v2/Users");
    REQUIRE(res);
    CHECK(res->status == 401);
    CHECK(res->get_header_value("WWW-Authenticate") == "Bearer");
    CHECK(json::parse(res->body)["status"] == "401");
}

TEST_CASE("ScimRoutes: 401 with the wrong bearer token", "[scim][routes][auth]") {
    Fixture f;
    auto res = f.sink.dispatch("GET", "/scim/v2/Users", "", "application/json",
                               {{"Authorization", "Bearer wrong-token"}});
    REQUIRE(res);
    CHECK(res->status == 401);
}

// ── Discovery ─────────────────────────────────────────────────────────────

TEST_CASE("ScimRoutes: discovery endpoints return the right schemas", "[scim][routes][discovery]") {
    Fixture f;

    auto spc = f.get("/scim/v2/ServiceProviderConfig");
    REQUIRE(spc);
    CHECK(spc->status == 200);
    CHECK(json::parse(spc->body)["schemas"][0] ==
         "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig");

    auto rt = f.get("/scim/v2/ResourceTypes");
    REQUIRE(rt);
    CHECK(rt->status == 200);
    auto rt_body = json::parse(rt->body);
    CHECK(rt_body["schemas"][0] == "urn:ietf:params:scim:api:messages:2.0:ListResponse");
    CHECK(rt_body["Resources"][0]["schema"] == "urn:ietf:params:scim:schemas:core:2.0:User");

    auto sch = f.get("/scim/v2/Schemas");
    REQUIRE(sch);
    CHECK(sch->status == 200);
    CHECK(json::parse(sch->body)["Resources"][0]["id"] ==
         "urn:ietf:params:scim:schemas:core:2.0:User");
}

// ── POST /Users (provision) ────────────────────────────────────────────────

TEST_CASE("ScimRoutes: POST provisions a user — 201 + Location + ETag", "[scim][routes][post]") {
    Fixture f;
    auto res = f.post("/scim/v2/Users", {{"userName", "alice"}, {"externalId", "ext-1"}});
    REQUIRE(res);
    CHECK(res->status == 201);
    CHECK_FALSE(res->get_header_value("Location").empty());
    CHECK(res->get_header_value("Location").ends_with(
        json::parse(res->body)["id"].get<std::string>()));
    CHECK(res->get_header_value("ETag") == R"(W/"1")");

    auto body = json::parse(res->body);
    CHECK(body["userName"] == "alice");
    CHECK(body["active"] == true);
    CHECK(body["externalId"] == "ext-1");

    // The account is provisioned at the read-only 'user' role, and its
    // provenance is recorded so the guard can verify it later.
    auto role = f.auth_mgr.get_user_role("alice");
    REQUIRE(role.has_value());
    CHECK(*role == auth::Role::user);
    auto src = f.auth_db->get_provisioning_source("alice");
    REQUIRE(src.has_value());
    CHECK(*src == "scim");
}

TEST_CASE("ScimRoutes: POST duplicate userName — 409, existing account untouched",
         "[scim][routes][post]") {
    Fixture f;
    auto first = f.post("/scim/v2/Users", {{"userName", "bob"}});
    REQUIRE(first);
    REQUIRE(first->status == 201);

    auto dup = f.post("/scim/v2/Users", {{"userName", "bob"}});
    REQUIRE(dup);
    CHECK(dup->status == 409);
    CHECK(json::parse(dup->body)["scimType"] == "uniqueness");

    // Only one scim_resource / auth account exists for "bob".
    int total = -1;
    auto page = f.scim_store->list(1, 100, total);
    CHECK(total == 1);
}

// ── GET /Users/{id}, GET /Users?filter= ────────────────────────────────────

TEST_CASE("ScimRoutes: GET /Users/{id} — 200 known, 404 unknown", "[scim][routes][get]") {
    Fixture f;
    auto created = json::parse(f.post("/scim/v2/Users", {{"userName", "carol"}})->body);
    auto id = created["id"].get<std::string>();

    auto ok = f.get("/scim/v2/Users/" + id);
    REQUIRE(ok);
    CHECK(ok->status == 200);
    CHECK(json::parse(ok->body)["userName"] == "carol");

    auto missing = f.get("/scim/v2/Users/deadbeefdeadbeefdeadbeefdeadbeef");
    REQUIRE(missing);
    CHECK(missing->status == 404);
}

TEST_CASE("ScimRoutes: GET ?filter=userName eq \"x\" returns the one match",
         "[scim][routes][get][filter]") {
    Fixture f;
    REQUIRE(f.post("/scim/v2/Users", {{"userName", "dave"}})->status == 201);
    REQUIRE(f.post("/scim/v2/Users", {{"userName", "erin"}})->status == 201);

    auto res = f.get(R"(/scim/v2/Users?filter=userName%20eq%20%22dave%22)");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = json::parse(res->body);
    CHECK(body["totalResults"] == 1);
    CHECK(body["Resources"][0]["userName"] == "dave");
}

// ── PATCH — the critical deprovision path ──────────────────────────────────

TEST_CASE("ScimRoutes: PATCH active=false deactivates the auth account",
         "[scim][routes][patch][deprovision]") {
    Fixture f;
    auto created = json::parse(f.post("/scim/v2/Users", {{"userName", "frank"}})->body);
    auto id = created["id"].get<std::string>();
    REQUIRE(f.auth_mgr.get_user_role("frank").has_value());

    json patch_body{{"Operations", json::array({{{"op", "replace"},
                                                 {"value", {{"active", false}}}}})}};
    auto res = f.patch("/scim/v2/Users/" + id, patch_body);
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(json::parse(res->body)["active"] == false);

    // The underlying auth account is ACTUALLY deactivated, not just the
    // SCIM resource flag.
    CHECK_FALSE(f.auth_mgr.get_user_role("frank").has_value());
    auto stored = f.scim_store->get_by_scim_id(id);
    REQUIRE(stored.has_value());
    CHECK_FALSE(stored->active);
}

TEST_CASE("ScimRoutes: PATCH active=false -> active=true round-trips (deprovision then "
         "reactivate), clearing stale lockout state",
         "[scim][routes][patch][reactivate]") {
    Fixture f;
    auto created = json::parse(f.post("/scim/v2/Users", {{"userName", "grace"}})->body);
    auto id = created["id"].get<std::string>();

    // Seed a REAL lockout (threshold=1 so the first recorded failure both
    // increments the counter and crosses the lock threshold) so the
    // post-reactivation assertions below prove reactivate_user actually
    // cleared it, rather than coincidentally observing an all-zero row.
    auto lockout = f.auth_db->record_failed_login("grace", /*threshold=*/1,
                                                  /*window_secs=*/3600);
    REQUIRE(lockout.has_value());
    REQUIRE(lockout->locked);
    auto pre_status = f.auth_db->lockout_status("grace");
    REQUIRE(pre_status.has_value());
    CHECK(pre_status->locked);
    CHECK(pre_status->failed_count > 0);

    json deactivate_body{{"Operations", json::array({{{"op", "replace"},
                                                      {"value", {{"active", false}}}}})}};
    auto deactivate_res = f.patch("/scim/v2/Users/" + id, deactivate_body);
    REQUIRE(deactivate_res);
    CHECK(deactivate_res->status == 200);
    CHECK_FALSE(f.auth_mgr.get_user_role("grace").has_value());

    json reactivate_body{{"Operations", json::array({{{"op", "replace"},
                                                      {"value", {{"active", true}}}}})}};
    auto res = f.patch("/scim/v2/Users/" + id, reactivate_body);
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(json::parse(res->body)["active"] == true);

    // The underlying auth account actually resolves again (is_active=1)...
    auto role = f.auth_mgr.get_user_role("grace");
    REQUIRE(role.has_value());
    CHECK(*role == auth::Role::user);
    // ...the SCIM resource flag flipped back too...
    auto stored = f.scim_store->get_by_scim_id(id);
    REQUIRE(stored.has_value());
    CHECK(stored->active);
    // ...provenance is untouched (still scim, not silently reset to local)...
    CHECK(f.auth_db->get_provisioning_source("grace").value() == "scim");
    // ...and the stale lockout from before deprovisioning is CLEARED, not
    // inherited by the returning user.
    auto post_status = f.auth_db->lockout_status("grace");
    REQUIRE(post_status.has_value());
    CHECK_FALSE(post_status->locked);
    CHECK(post_status->failed_count == 0);
}

TEST_CASE("ScimRoutes: PATCH active=true is a no-op when the resource is already active",
         "[scim][routes][patch][reactivate]") {
    Fixture f;
    auto created = json::parse(f.post("/scim/v2/Users", {{"userName", "heidi2"}})->body);
    auto id = created["id"].get<std::string>();

    json reactivate_body{{"Operations", json::array({{{"op", "replace"},
                                                      {"value", {{"active", true}}}}})}};
    auto res = f.patch("/scim/v2/Users/" + id, reactivate_body);
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(f.auth_mgr.get_user_role("heidi2").has_value());
}

// FIX-2 (MEDIUM-1, CC6.8 deprovision desync): a PATCH active=false against a
// resource whose MIRROR already reads inactive must not blindly no-op — it
// must verify the real auth account state first. Desync is induced directly
// at the store layer (`set_active`, bypassing `deactivate()`) so the auth
// account stays genuinely live while the mirror flips to inactive — the
// exact "IdP believes terminated, account is not" gap the fix closes.
TEST_CASE("ScimRoutes: PATCH active=false re-runs deactivation when the mirror is desynced "
         "from a still-live auth account",
         "[scim][routes][patch][deprovision]") {
    Fixture f;
    auto created = json::parse(f.post("/scim/v2/Users", {{"userName", "ivan"}})->body);
    auto id = created["id"].get<std::string>();
    REQUIRE(f.auth_mgr.get_user_role("ivan").has_value());

    // Desync: flip the mirror to inactive WITHOUT touching the auth account.
    REQUIRE(f.scim_store->set_active(id, false));
    REQUIRE(f.auth_mgr.get_user_role("ivan").has_value()); // still live

    json patch_body{{"Operations", json::array({{{"op", "replace"},
                                                 {"value", {{"active", false}}}}})}};
    auto res = f.patch("/scim/v2/Users/" + id, patch_body);
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(json::parse(res->body)["active"] == false);

    // The desync is repaired: the auth account is now ACTUALLY deactivated,
    // and the real deactivation path fired — asserted via the dedicated
    // "scim.user.deactivated" audit action (NOT total_count(), which every
    // PATCH bumps via the routine "scim.user.updated" row regardless of
    // whether active actually transitioned).
    CHECK_FALSE(f.auth_mgr.get_user_role("ivan").has_value());
    AuditQuery q;
    q.action = "scim.user.deactivated";
    q.target_id = id;
    CHECK(f.audit_store->query(q).size() == 1);
}

TEST_CASE("ScimRoutes: PATCH active=false stays a clean no-op when the account is genuinely "
         "already inactive",
         "[scim][routes][patch][deprovision]") {
    Fixture f;
    auto created = json::parse(f.post("/scim/v2/Users", {{"userName", "ivan2"}})->body);
    auto id = created["id"].get<std::string>();

    json patch_body{{"Operations", json::array({{{"op", "replace"},
                                                 {"value", {{"active", false}}}}})}};
    REQUIRE(f.patch("/scim/v2/Users/" + id, patch_body)->status == 200);
    CHECK_FALSE(f.auth_mgr.get_user_role("ivan2").has_value());

    // Second active=false against an account that is ALSO genuinely
    // inactive at the auth layer — must stay a true no-op: 200, and no
    // SECOND "scim.user.deactivated" row (deactivate() is not re-run;
    // preserves the happy-path idempotency other reviewers verified). The
    // routine "scim.user.updated" audit still fires per-PATCH regardless —
    // that is pre-existing, orthogonal behavior, not what this fix guards.
    auto res = f.patch("/scim/v2/Users/" + id, patch_body);
    REQUIRE(res);
    CHECK(res->status == 200);
    AuditQuery q;
    q.action = "scim.user.deactivated";
    q.target_id = id;
    CHECK(f.audit_store->query(q).size() == 1);
}

// ── DELETE ──────────────────────────────────────────────────────────────────

TEST_CASE("ScimRoutes: DELETE — 204 + account soft-deleted", "[scim][routes][delete]") {
    Fixture f;
    auto created = json::parse(f.post("/scim/v2/Users", {{"userName", "heidi"}})->body);
    auto id = created["id"].get<std::string>();

    auto res = f.del("/scim/v2/Users/" + id);
    REQUIRE(res);
    CHECK(res->status == 204);
    CHECK(res->body.empty());

    CHECK_FALSE(f.auth_mgr.get_user_role("heidi").has_value());
    CHECK_FALSE(f.scim_store->get_by_scim_id(id).has_value());
}

TEST_CASE("ScimRoutes: concurrent DELETE on the same id never 500s on an already-gone mapping "
         "row (UP-N4)",
         "[scim][routes][delete][race]") {
    Fixture f;
    auto created = json::parse(f.post("/scim/v2/Users", {{"userName", "wren"}})->body);
    auto id = created["id"].get<std::string>();

    // Deactivate first so both racing DELETEs land in the already-inactive
    // branch (no remove_user() call there) — isolates the delete_by_scim_id
    // idempotency this test targets from the separate, pre-existing
    // remove_user()-return-value residual on the active branch (see
    // deactivate()'s M-ATOMICITY comment; out of scope here).
    json deactivate_body{{"Operations", json::array({{{"op", "replace"},
                                                      {"value", {{"active", false}}}}})}};
    REQUIRE(f.patch("/scim/v2/Users/" + id, deactivate_body)->status == 200);

    std::atomic<int> status_204{0};
    std::atomic<int> status_404{0};
    std::atomic<int> unexpected{0};
    std::vector<std::thread> threads;
    for (int i = 0; i < 2; ++i) {
        threads.emplace_back([&f, &id, &status_204, &status_404, &unexpected] {
            auto res = f.del("/scim/v2/Users/" + id);
            if (!res) {
                unexpected.fetch_add(1, std::memory_order_relaxed);
                return;
            }
            if (res->status == 204)
                status_204.fetch_add(1, std::memory_order_relaxed);
            else if (res->status == 404)
                status_404.fetch_add(1, std::memory_order_relaxed);
            else
                unexpected.fetch_add(1, std::memory_order_relaxed);
        });
    }
    for (auto& t : threads)
        t.join();

    // The regression this guards: a race where one thread's own
    // delete_by_scim_id() call finds the mapping row already removed by
    // the other thread used to 500 (treated as a DB error). It must now be
    // idempotent success (204) — or, if a thread's OWN initial
    // get_by_scim_id already observed the row gone (a legitimately later,
    // fully-sequential DELETE), a plain 404 — but NEVER a spurious 500.
    CHECK(unexpected.load() == 0);
    CHECK(status_204.load() >= 1);
    CHECK(status_204.load() + status_404.load() == 2);
}

// ── Provenance guard (LOAD-BEARING) ────────────────────────────────────────

TEST_CASE("ScimRoutes: provenance guard — SCIM cannot touch a locally-created account",
         "[scim][routes][provenance]") {
    Fixture f;
    // A local admin, created OUTSIDE the SCIM path (upsert_user directly —
    // mirrors first-run-setup / an operator-run `yuzu-server --add-user`).
    REQUIRE(f.auth_mgr.upsert_user("admin", "correct-horse-battery-staple", auth::Role::admin));
    REQUIRE(f.auth_db->get_provisioning_source("admin").value() == "local");

    // 1) POST /Users with a colliding userName — must 409, not silently
    //    take over the existing admin account.
    auto dup = f.post("/scim/v2/Users", {{"userName", "admin"}});
    REQUIRE(dup);
    CHECK(dup->status == 409);
    CHECK(f.auth_db->get_provisioning_source("admin").value() == "local");
    CHECK(f.auth_mgr.get_user_role("admin").value() == auth::Role::admin);

    // 2) Defense-in-depth: even if a scim_resource row somehow existed for
    //    this username (a bug, or an operator hand-editing scim_resources —
    //    ScimStore has no FK to the auth.db users table), the provenance
    //    re-check must refuse the mutation with 404 (never 403 — a 403
    //    would confirm the local account's existence to the IdP).
    auto mapped = f.scim_store->create_resource("admin");
    REQUIRE(mapped.has_value());

    json deactivate_body{{"Operations", json::array({{{"op", "replace"},
                                                      {"value", {{"active", false}}}}})}};
    auto patch_res = f.patch("/scim/v2/Users/" + mapped->scim_id, deactivate_body);
    REQUIRE(patch_res);
    CHECK(patch_res->status == 404);

    auto del_res = f.del("/scim/v2/Users/" + mapped->scim_id);
    REQUIRE(del_res);
    CHECK(del_res->status == 404);

    // The local admin account is COMPLETELY untouched throughout.
    CHECK(f.auth_db->get_provisioning_source("admin").value() == "local");
    CHECK(f.auth_mgr.get_user_role("admin").value() == auth::Role::admin);
    // The bogus scim_resource mapping itself is untouched too (refused, not
    // silently no-op'd/deleted).
    auto still_mapped = f.scim_store->get_by_scim_id(mapped->scim_id);
    REQUIRE(still_mapped.has_value());
    CHECK(still_mapped->active);
}

TEST_CASE("ScimRoutes: POST refuses to adopt a SOFT-DELETED local account (S-UNIQUE-DBREAD)",
         "[scim][routes][provenance]") {
    Fixture f;
    // A local admin, soft-deleted via the ordinary human /api/settings/users
    // DELETE path (remove_user) — no longer visible via get_user_role, the
    // in-memory cache the OLD uniqueness check relied on.
    REQUIRE(f.auth_mgr.upsert_user("paul", "correct-horse-battery-staple", auth::Role::admin));
    REQUIRE(f.auth_mgr.remove_user("paul"));
    CHECK_FALSE(f.auth_mgr.get_user_role("paul").has_value());

    auto res = f.post("/scim/v2/Users", {{"userName", "paul"}});
    REQUIRE(res);
    CHECK(res->status == 409);
    CHECK(json::parse(res->body)["scimType"] == "uniqueness");
    // Still local and still inactive — SCIM never adopted it.
    CHECK(f.auth_db->get_provisioning_source("paul").value() == "local");
    CHECK_FALSE(f.auth_mgr.get_user_role("paul").has_value());
}

// ── M-LIFECYCLE — revive-on-reprovision ─────────────────────────────────

TEST_CASE("ScimRoutes: DELETE then re-POST the same userName revives the account",
         "[scim][routes][revive]") {
    Fixture f;
    auto created = json::parse(f.post("/scim/v2/Users", {{"userName", "olga"}})->body);
    auto old_id = created["id"].get<std::string>();

    auto del_res = f.del("/scim/v2/Users/" + old_id);
    REQUIRE(del_res);
    CHECK(del_res->status == 204);
    CHECK_FALSE(f.auth_mgr.get_user_role("olga").has_value());
    // The scim_resource mapping is hard-deleted...
    CHECK_FALSE(f.scim_store->get_by_scim_id(old_id).has_value());
    // ...but the underlying auth row survives as a soft-deleted SCIM
    // tombstone — the exact state a returning employee's account is in.
    auto tombstoned_source = f.auth_db->get_provisioning_source("olga");
    REQUIRE(tombstoned_source.has_value());
    CHECK(*tombstoned_source == "scim");

    // Revive: re-POST the same userName. Previously this deadlocked (UP-1/
    // 2/3): upsert_user's ON CONFLICT DO NOTHING made the write silently
    // no-op forever, and no path ever called reactivate_user for a POST.
    auto revived_res = f.post("/scim/v2/Users", {{"userName", "olga"}});
    REQUIRE(revived_res);
    CHECK(revived_res->status == 201);
    auto revived_body = json::parse(revived_res->body);
    CHECK(revived_body["userName"] == "olga");
    CHECK(revived_body["active"] == true);
    // Fresh scim_id — the old scim_resource row is gone for good.
    auto new_id = revived_body["id"].get<std::string>();
    CHECK(new_id != old_id);

    auto role = f.auth_mgr.get_user_role("olga");
    REQUIRE(role.has_value());
    CHECK(*role == auth::Role::user);
    CHECK(f.auth_db->get_provisioning_source("olga").value() == "scim");

    // The revived account is fully usable again through the ordinary
    // PATCH deprovision path.
    json deactivate_body{{"Operations", json::array({{{"op", "replace"},
                                                      {"value", {{"active", false}}}}})}};
    auto patch_res = f.patch("/scim/v2/Users/" + new_id, deactivate_body);
    REQUIRE(patch_res);
    CHECK(patch_res->status == 200);
    CHECK_FALSE(f.auth_mgr.get_user_role("olga").has_value());
}

TEST_CASE("ScimRoutes: concurrent revive race — the create_resource-conflict rollback must not "
         "deactivate the winner (UP-N1)",
         "[scim][routes][revive][race]") {
    Fixture f;
    // Leave "vic" as a tombstoned SCIM account: auth row soft-deleted,
    // provisioning_source == "scim", no scim_resource row — exactly the
    // state two concurrent re-POSTs for a returning employee would race
    // over (both pass Step 1's "no live mapping" check and enter the
    // REVIVE branch; they can only serialize on create_resource's
    // UNIQUE(username) constraint).
    auto created = json::parse(f.post("/scim/v2/Users", {{"userName", "vic"}})->body);
    auto del_res = f.del("/scim/v2/Users/" + created["id"].get<std::string>());
    REQUIRE(del_res);
    REQUIRE(del_res->status == 204);
    REQUIRE_FALSE(f.auth_mgr.get_user_role("vic").has_value());

    std::atomic<int> created_count{0};
    std::atomic<int> conflicted_count{0};
    std::atomic<int> other{0};

    std::vector<std::thread> threads;
    for (int i = 0; i < 2; ++i) {
        threads.emplace_back([&f, &created_count, &conflicted_count, &other] {
            auto res = f.post("/scim/v2/Users", {{"userName", "vic"}});
            if (!res) {
                other.fetch_add(1, std::memory_order_relaxed);
                return;
            }
            if (res->status == 201)
                created_count.fetch_add(1, std::memory_order_relaxed);
            else if (res->status == 409)
                conflicted_count.fetch_add(1, std::memory_order_relaxed);
            else
                other.fetch_add(1, std::memory_order_relaxed);
        });
    }
    for (auto& t : threads)
        t.join();

    // Exactly one winner (201), one loser (409 uniqueness) — same shape as
    // the fresh-create race below, but this one exercises the REVIVE
    // branch's create_resource-failure handler.
    CHECK(created_count.load() == 1);
    CHECK(conflicted_count.load() == 1);
    CHECK(other.load() == 0);

    // UP-N1 (the actual regression): the loser's rollback must NEVER have
    // called remove_user() against the winner's freshly-revived account —
    // it must still resolve and still be active, not silently deactivated
    // behind a 201 no one retries.
    auto role = f.auth_mgr.get_user_role("vic");
    REQUIRE(role.has_value());
    CHECK(*role == auth::Role::user);

    int total = -1;
    auto page = f.scim_store->list(1, 100, total);
    CHECK(total == 1);
    REQUIRE_FALSE(page.empty());
    CHECK(page.front().active);
}

TEST_CASE("ScimRoutes: concurrent duplicate POST for a brand-new userName — exactly one 201, "
         "one 409 (UP-9, store layer race)",
         "[scim][routes][post][race]") {
    Fixture f;
    std::atomic<int> created{0};
    std::atomic<int> conflicted{0};
    std::atomic<int> other{0};

    std::vector<std::thread> threads;
    for (int i = 0; i < 2; ++i) {
        threads.emplace_back([&f, &created, &conflicted, &other] {
            auto res = f.post("/scim/v2/Users", {{"userName", "race-user"}});
            if (!res) {
                other.fetch_add(1, std::memory_order_relaxed);
                return;
            }
            if (res->status == 201)
                created.fetch_add(1, std::memory_order_relaxed);
            else if (res->status == 409)
                conflicted.fetch_add(1, std::memory_order_relaxed);
            else
                other.fetch_add(1, std::memory_order_relaxed);
        });
    }
    for (auto& t : threads)
        t.join();

    CHECK(created.load() == 1);
    CHECK(conflicted.load() == 1);
    CHECK(other.load() == 0);

    // Exactly one scim_resource / auth account for "race-user" survives.
    int total = -1;
    auto page = f.scim_store->list(1, 100, total);
    CHECK(total == 1);
    CHECK(f.auth_mgr.get_user_role("race-user").has_value());
}

// ── Groups: concurrency (safety-S2) ─────────────────────────────────────

TEST_CASE("ScimRoutes: concurrent Group PATCH-promote + User DELETE on the same SCIM user — no "
         "crash, no torn state",
         "[scim][routes][groups][race]") {
    // Not a provenance-guard test (that's covered elsewhere — a group can
    // only ever elevate a SCIM-provenanced account in the first place) —
    // this purely proves the two mutations racing on the same user_scim_id
    // never crash and never leave a torn/inconsistent final state,
    // regardless of which one "wins" the race.
    Fixture f{/*broken_audit=*/false, /*scim_admin_group=*/"Yuzu-Admins"};
    auto user = json::parse(f.post("/scim/v2/Users", {{"userName", "victor"}})->body);
    auto user_id = user["id"].get<std::string>();

    auto group = json::parse(f.post("/scim/v2/Groups", {{"displayName", "Yuzu-Admins"}})->body);
    auto group_id = group["id"].get<std::string>();

    json add_body{{"Operations",
                   json::array({{{"op", "add"},
                                 {"path", "members"},
                                 {"value", json::array({{{"value", user_id}}})}}})}};

    std::atomic<bool> saw_unexpected{false};
    std::vector<std::thread> threads;
    threads.emplace_back([&] {
        auto res = f.patch("/scim/v2/Groups/" + group_id, add_body);
        if (!res || (res->status != 200 && res->status != 404))
            saw_unexpected.store(true);
    });
    threads.emplace_back([&] {
        auto res = f.del("/scim/v2/Users/" + user_id);
        if (!res || (res->status != 204 && res->status != 404))
            saw_unexpected.store(true);
    });
    for (auto& t : threads)
        t.join();

    // Both requests completed with an expected status (the mere fact we
    // got here at all rules out a crash/deadlock/hang).
    CHECK_FALSE(saw_unexpected.load());

    // Consistent final state, whichever order the race resolved in: if the
    // user still exists (DELETE lost the race, or PATCH ran first and left
    // the account admin-elevated so DELETE 404'd via M-DEPROV-ROLE), its
    // AuthDB role must match what its CURRENT group membership resolves to
    // — never a stale/mismatched role.
    //
    // NOTE: if the user is gone instead, `scim_group_members` can still
    // carry a row referencing the now-deleted user_scim_id — DELETE /Users
    // (ScimStore::delete_by_scim_id) never cleans up group membership rows.
    // That's pre-existing behavior unrelated to this race (recompute_scim_
    // user_role's get_by_scim_id provenance check makes a ghost member
    // inert — it can never again drive a role change), so this test does
    // not assert on it; the orphaned row itself is a separate hygiene gap,
    // not a race-specific correctness bug.
    auto still_there = f.scim_store->get_by_scim_id(user_id);
    if (still_there.has_value()) {
        auto groups = f.scim_store->list_group_display_names_for_user(user_id);
        auto expected = auth::resolve_role_from_groups(groups, "Yuzu-Admins");
        auto actual = f.auth_mgr.get_user_role("victor");
        REQUIRE(actual.has_value());
        CHECK(*actual == expected);
    }
}

// ── M-DEPROV-ROLE ────────────────────────────────────────────────────────

TEST_CASE("ScimRoutes: deprovision refused once an operator elevates the SCIM account to admin",
         "[scim][routes][deprov_role]") {
    Fixture f;
    auto created = json::parse(f.post("/scim/v2/Users", {{"userName", "noah"}})->body);
    auto id = created["id"].get<std::string>();

    REQUIRE(f.auth_mgr.update_role("noah", auth::Role::admin));

    json deactivate_body{{"Operations", json::array({{{"op", "replace"},
                                                      {"value", {{"active", false}}}}})}};
    auto patch_res = f.patch("/scim/v2/Users/" + id, deactivate_body);
    REQUIRE(patch_res);
    CHECK(patch_res->status == 404);
    CHECK(f.auth_mgr.get_user_role("noah").value() == auth::Role::admin);

    auto del_res = f.del("/scim/v2/Users/" + id);
    REQUIRE(del_res);
    CHECK(del_res->status == 404);
    // Untouched — still admin, still active, still SCIM-provenanced (the
    // account itself was never SCIM's to begin with adopting; only its
    // lifecycle ownership is revoked by the role elevation).
    CHECK(f.auth_mgr.get_user_role("noah").value() == auth::Role::admin);
    CHECK(f.scim_store->get_by_scim_id(id).has_value());
}

TEST_CASE("ScimRoutes: deprovision refused for a DB-elevated admin even with a COLD "
         "AuthManager cache (H2, 2026-07-08 review — fail-closed, not fail-open)",
         "[scim][routes][deprov_role][cold_cache]") {
    // H2: AuthManager::get_user_role only ever reads the in-memory `users_`
    // cache, which nothing preloads at construction. A freshly-started
    // process (modeled here by a SECOND AuthManager wired to the SAME
    // AuthDB, whose cache has never seen this username) previously read
    // back nullopt for a DB-elevated admin and treated that as "no
    // elevation on file" — deactivating an admin an operator had promoted
    // out of SCIM's ownership. The fix reads the role authoritatively from
    // AuthDB (db_authoritative_role) instead.
    Fixture f;
    auto created = json::parse(f.post("/scim/v2/Users", {{"userName", "cora"}})->body);
    auto id = created["id"].get<std::string>();
    REQUIRE(f.auth_mgr.update_role("cora", auth::Role::admin));

    // A user-role sibling, provisioned the same way, to prove the
    // cold-cache manager still deprovisions a genuinely SCIM-owned 'user'
    // account normally (not an across-the-board fail-closed regression).
    auto created_user = json::parse(f.post("/scim/v2/Users", {{"userName", "dana"}})->body);
    auto user_id = created_user["id"].get<std::string>();

    // A second AuthManager over the SAME AuthDB file/object, standing in
    // for a fresh process: its users_ cache has never been populated for
    // either username.
    auth::AuthManager cold_auth_mgr;
    cold_auth_mgr.set_auth_db(f.auth_db.get());
    REQUIRE_FALSE(cold_auth_mgr.get_user_role("cora").has_value());
    REQUIRE_FALSE(cold_auth_mgr.get_user_role("dana").has_value());

    // Prime the cache for "dana" only, via `reactivate_user` — a legitimate,
    // idempotent AuthDB write (harmless on an already-active row; clears
    // lockout state, nothing else) that happens to be the ONLY mechanism
    // AuthManager exposes for loading an entry into a cold `users_` map.
    // This is NOT priming the thing H2 actually fixes (the role read below
    // still goes through `db_authoritative_role`'s DB-authoritative path
    // regardless of cache state) — it works around a SEPARATE, pre-existing
    // quirk this test surfaced: `AuthManager::remove_user()`'s bool return
    // is `users_.erase(username) > 0`, so on a truly virgin cache it
    // returns false — and `deactivate()` treats that as a failed removal —
    // even though the underlying AuthDB write already succeeded. That is a
    // latent bug in the shared `remove_user()` primitive, well outside this
    // PR's scope (H2 only asked for a DB-authoritative ROLE read; the
    // review explicitly says not to touch `AuthManager::get_user_role`,
    // let alone `remove_user`), so it is deferred rather than fixed here —
    // flagged instead as a follow-up in the review response.
    REQUIRE(cold_auth_mgr.reactivate_user("dana"));

    test::TestRouteSink cold_sink;
    ScimRoutes cold_routes;
    cold_routes.register_routes(cold_sink, f.scim_store.get(), &cold_auth_mgr, f.audit_store.get());

    auto del_admin =
        cold_sink.dispatch("DELETE", "/scim/v2/Users/" + id, {}, "application/scim+json",
                           f.auth_header());
    REQUIRE(del_admin);
    CHECK(del_admin->status == 404);
    CHECK(json::parse(del_admin->body)["detail"] == "resource not found");
    // Untouched — the admin is still active, despite the cold cache.
    CHECK(f.auth_mgr.get_user_role("cora").value() == auth::Role::admin);
    CHECK(f.scim_store->get_by_scim_id(id)->active);

    auto del_user =
        cold_sink.dispatch("DELETE", "/scim/v2/Users/" + user_id, {}, "application/scim+json",
                           f.auth_header());
    REQUIRE(del_user);
    CHECK(del_user->status == 204);
    // Checked via `cold_auth_mgr` (the manager that actually performed the
    // removal), not `f.auth_mgr` — the two AuthManager instances have
    // entirely independent in-memory caches over the SAME AuthDB, so
    // `f.auth_mgr`'s cache legitimately still holds dana's pre-removal
    // entry (it was never touched by cold_auth_mgr's write). The
    // DB-authoritative source of truth agrees with cold_auth_mgr here.
    CHECK_FALSE(cold_auth_mgr.get_user_role("dana").has_value());
    CHECK_FALSE(f.auth_db->get_user("dana").has_value());
}

TEST_CASE("ScimRoutes: revive-on-reprovision refuses an operator-elevated account — 404, and "
         "the remove_user() undo leaves the account INACTIVE, not reactivated-at-elevated-role "
         "(UP-N5/FIX-5, Gate-8 round-2)",
         "[scim][routes][revive][role_refusal]") {
    // Gate-8 round-2 MEDIUM (privilege fail-open): the revive path
    // (POST re-provisioning a tombstoned SCIM account) reactivates the
    // underlying auth row FIRST, then refuses if the role isn't 'user',
    // undoing the reactivation via remove_user(). Previously that undo's
    // bool return was discarded — a failure there would leave the account
    // ACTIVE at its elevated role behind a 404 the IdP never retries. This
    // exercises the happy-path undo (remove_user() succeeds) end-to-end:
    // the account must land INACTIVE, never reactivated.
    Fixture f;
    auto created = json::parse(f.post("/scim/v2/Users", {{"userName", "frank"}})->body);
    auto old_id = created["id"].get<std::string>();

    // An operator elevates the account while it is still active...
    REQUIRE(f.auth_mgr.update_role("frank", auth::Role::admin));
    // ...then it is torn down through a path OTHER than SCIM's own DELETE
    // (which would itself have refused via deprovision_role_ok — see the
    // M-DEPROV-ROLE test above, e.g. an admin-console deactivation).
    // remove_user() never touches the role column, so this reproduces
    // exactly the state the revive-refusal guard defends against: a
    // tombstoned SCIM account whose role is still 'admin'.
    REQUIRE(f.auth_mgr.remove_user("frank"));
    auto mapping_deleted = f.scim_store->delete_by_scim_id(old_id);
    REQUIRE(mapping_deleted.has_value());
    CHECK(*mapping_deleted);
    REQUIRE(f.auth_db->get_provisioning_source("frank").value() == "scim");

    // Re-POST: hits the REVIVE branch, reactivate_user() succeeds (role
    // column untouched by it), the role check sees 'admin' != 'user' and
    // refuses — remove_user()'s undo is exercised here.
    auto revive_res = f.post("/scim/v2/Users", {{"userName", "frank"}});
    REQUIRE(revive_res);
    CHECK(revive_res->status == 404);

    // The account must be left INACTIVE — not reactivated-at-elevated-role
    // behind the 404. get_user_role() misses an inactive account's
    // in-memory cache entry the same way the other deactivation assertions
    // in this file do (see e.g. the revive/deprovision tests above).
    CHECK_FALSE(f.auth_mgr.get_user_role("frank").has_value());

    // NOTE (injection gap): this test exercises the SUCCESS path of the
    // remove_user() undo (matches the deactivate() sibling's checked-return
    // pattern). Forcing remove_user()'s own DB write to fail at exactly
    // that point — without also failing the earlier reactivate_user() call
    // on the same connection (which would hit a different, already-tested
    // 500 branch) — needs either a multi-second SQLITE_BUSY wait on
    // AuthDB's fixed 5s busy_timeout or corrupting the shared auth.db file
    // mid-request, neither of which is a clean/fast unit-test injection.
    // The code path itself (`if (!auth_mgr->remove_user(...)) { ... 500
    // ... }`) is exercised by inspection and mirrors deactivate()'s
    // identical, already-tested contract.
}

// ── M-OPTDEREF ───────────────────────────────────────────────────────────

TEST_CASE("ScimRoutes: PATCH after DELETE on the same id — 404, no crash",
         "[scim][routes][optderef]") {
    Fixture f;
    auto created = json::parse(f.post("/scim/v2/Users", {{"userName", "rex"}})->body);
    auto id = created["id"].get<std::string>();

    auto del_res = f.del("/scim/v2/Users/" + id);
    REQUIRE(del_res);
    CHECK(del_res->status == 204);

    json patch_body{{"Operations", json::array({{{"op", "replace"},
                                                 {"value", {{"active", false}}}}})}};
    auto patch_res = f.patch("/scim/v2/Users/" + id, patch_body);
    REQUIRE(patch_res);
    CHECK(patch_res->status == 404);

    auto put_res = f.put("/scim/v2/Users/" + id, {{"userName", "rex"}});
    REQUIRE(put_res);
    CHECK(put_res->status == 404);
}

// ── Set-and-proceed audit posture (UP-N2) ───────────────────────────────
//
// A lost audit write NEVER fails the request on this surface — including
// the termination actions (deactivate/delete/reactivate). Fail-closed here
// used to 500 the IdP's request, but the mutation had already committed and
// the IdP's retry would observe post-state and never re-attempt the lost
// audit write anyway — the evidence gap was permanent either way, at the
// cost of a spurious 500. CC6.8 evidence integrity is instead enforced by
// alerting on yuzu_scim_audit_write_failures_total (bumped inside audit()
// on every failure, independent of the caller's response).

TEST_CASE("ScimRoutes: audit write failure on a non-termination action — set-and-proceed (201)",
         "[scim][routes][audit]") {
    Fixture f{/*broken_audit=*/true};
    auto res = f.post("/scim/v2/Users", {{"userName", "sam"}});
    REQUIRE(res);
    CHECK(res->status == 201);
    CHECK(f.auth_mgr.get_user_role("sam").has_value());
}

TEST_CASE("ScimRoutes: audit write failure on a termination action — set-and-proceed (200)",
         "[scim][routes][audit]") {
    Fixture f{/*broken_audit=*/true};
    auto created = json::parse(f.post("/scim/v2/Users", {{"userName", "tara"}})->body);
    auto id = created["id"].get<std::string>();

    json deactivate_body{{"Operations", json::array({{{"op", "replace"},
                                                      {"value", {{"active", false}}}}})}};
    auto res = f.patch("/scim/v2/Users/" + id, deactivate_body);
    REQUIRE(res);
    // The mutation committed AND is reported — a lost audit row no longer
    // costs the caller a spurious 500 (see the file comment above).
    CHECK(res->status == 200);
    CHECK_FALSE(f.auth_mgr.get_user_role("tara").has_value());
    auto stored = f.scim_store->get_by_scim_id(id);
    REQUIRE(stored.has_value());
    CHECK_FALSE(stored->active);
}

TEST_CASE("ScimRoutes: audit write failure on DELETE — set-and-proceed (204)",
         "[scim][routes][audit]") {
    Fixture f{/*broken_audit=*/true};
    auto created = json::parse(f.post("/scim/v2/Users", {{"userName", "uri"}})->body);
    auto id = created["id"].get<std::string>();

    auto res = f.del("/scim/v2/Users/" + id);
    REQUIRE(res);
    CHECK(res->status == 204);
    CHECK_FALSE(f.auth_mgr.get_user_role("uri").has_value());
}

// ── PUT /scim/v2/Users/{id} — full replace ──────────────────────────────

TEST_CASE("ScimRoutes: PUT identity replace — 200, externalId updated", "[scim][routes][put]") {
    Fixture f;
    auto created =
        json::parse(f.post("/scim/v2/Users", {{"userName", "ivy"}, {"externalId", "ext-old"}})
                        ->body);
    auto id = created["id"].get<std::string>();

    auto res = f.put("/scim/v2/Users/" + id, {{"userName", "ivy"}, {"externalId", "ext-new"}});
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = json::parse(res->body);
    CHECK(body["userName"] == "ivy");
    CHECK(body["externalId"] == "ext-new");
    CHECK(body["active"] == true);
}

TEST_CASE("ScimRoutes: PUT userName change — 400 mutability, account untouched",
         "[scim][routes][put]") {
    Fixture f;
    auto created = json::parse(f.post("/scim/v2/Users", {{"userName", "jack"}})->body);
    auto id = created["id"].get<std::string>();

    auto res = f.put("/scim/v2/Users/" + id, {{"userName", "jack2"}});
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(json::parse(res->body)["scimType"] == "mutability");
    CHECK(f.auth_mgr.get_user_role("jack").has_value());
}

TEST_CASE("ScimRoutes: PUT unknown id — 404", "[scim][routes][put]") {
    Fixture f;
    auto res = f.put("/scim/v2/Users/deadbeefdeadbeefdeadbeefdeadbeef", {{"userName", "nobody"}});
    REQUIRE(res);
    CHECK(res->status == 404);
}

TEST_CASE("ScimRoutes: PUT active=false then active=true round-trips the auth account",
         "[scim][routes][put]") {
    Fixture f;
    auto created = json::parse(f.post("/scim/v2/Users", {{"userName", "kate"}})->body);
    auto id = created["id"].get<std::string>();

    auto deactivate_res =
        f.put("/scim/v2/Users/" + id, {{"userName", "kate"}, {"active", false}});
    REQUIRE(deactivate_res);
    CHECK(deactivate_res->status == 200);
    CHECK(json::parse(deactivate_res->body)["active"] == false);
    CHECK_FALSE(f.auth_mgr.get_user_role("kate").has_value());

    auto reactivate_res = f.put("/scim/v2/Users/" + id, {{"userName", "kate"}, {"active", true}});
    REQUIRE(reactivate_res);
    CHECK(reactivate_res->status == 200);
    CHECK(json::parse(reactivate_res->body)["active"] == true);
    CHECK(f.auth_mgr.get_user_role("kate").has_value());
}

// FIX-2 (MEDIUM-1, CC6.8 deprovision desync) — PUT counterpart of the PATCH
// test above.
TEST_CASE("ScimRoutes: PUT active=false re-runs deactivation when the mirror is desynced "
         "from a still-live auth account",
         "[scim][routes][put]") {
    Fixture f;
    auto created = json::parse(f.post("/scim/v2/Users", {{"userName", "laura"}})->body);
    auto id = created["id"].get<std::string>();
    REQUIRE(f.auth_mgr.get_user_role("laura").has_value());

    REQUIRE(f.scim_store->set_active(id, false));
    REQUIRE(f.auth_mgr.get_user_role("laura").has_value()); // still live

    auto res = f.put("/scim/v2/Users/" + id, {{"userName", "laura"}, {"active", false}});
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(json::parse(res->body)["active"] == false);
    CHECK_FALSE(f.auth_mgr.get_user_role("laura").has_value());
}

// ── Malformed body handling ──────────────────────────────────────────────

TEST_CASE("ScimRoutes: malformed JSON body — 400 on POST/PATCH", "[scim][routes][malformed]") {
    Fixture f;
    auto post_res = f.sink.dispatch("POST", "/scim/v2/Users", "{not json",
                                    "application/scim+json", f.auth_header());
    REQUIRE(post_res);
    CHECK(post_res->status == 400);

    auto created = json::parse(f.post("/scim/v2/Users", {{"userName", "leo"}})->body);
    auto id = created["id"].get<std::string>();
    auto patch_res = f.sink.dispatch("PATCH", "/scim/v2/Users/" + id, "{not json",
                                     "application/scim+json", f.auth_header());
    REQUIRE(patch_res);
    CHECK(patch_res->status == 400);
}

TEST_CASE("ScimRoutes: POST with a non-string userName/externalId — 400, not 500 (FIX-3)",
         "[scim][routes][malformed]") {
    // Confirms the route path that calls scim::parse_user() propagates its
    // std::expected 400 cleanly rather than an nlohmann::json::type_error
    // unwinding to an unhandled 500.
    Fixture f;
    auto res1 = f.post("/scim/v2/Users", {{"userName", 123}});
    REQUIRE(res1);
    CHECK(res1->status == 400);
    auto body1 = json::parse(res1->body);
    CHECK(body1["scimType"] == "invalidValue");

    auto res2 = f.post("/scim/v2/Users", {{"userName", "vic"}, {"externalId", json::array()}});
    REQUIRE(res2);
    CHECK(res2->status == 400);
    auto body2 = json::parse(res2->body);
    CHECK(body2["scimType"] == "invalidValue");
}

TEST_CASE("ScimRoutes: oversized body — 413 on POST/PATCH", "[scim][routes][malformed]") {
    Fixture f;
    std::string huge_body = R"({"userName":")" + std::string(70 * 1024, 'x') + R"("})";
    auto post_res = f.sink.dispatch("POST", "/scim/v2/Users", huge_body, "application/scim+json",
                                    f.auth_header());
    REQUIRE(post_res);
    CHECK(post_res->status == 413);

    auto created = json::parse(f.post("/scim/v2/Users", {{"userName", "mia"}})->body);
    auto id = created["id"].get<std::string>();
    auto patch_res = f.sink.dispatch("PATCH", "/scim/v2/Users/" + id, huge_body,
                                     "application/scim+json", f.auth_header());
    REQUIRE(patch_res);
    CHECK(patch_res->status == 413);
}

// ── S-POST-REFETCH ───────────────────────────────────────────────────────

TEST_CASE("ScimRoutes: POST active:false — 201 body's ETag matches a following GET",
         "[scim][routes][post]") {
    Fixture f;
    auto res = f.post("/scim/v2/Users", {{"userName", "uma"}, {"active", false}});
    REQUIRE(res);
    CHECK(res->status == 201);
    auto body = json::parse(res->body);
    CHECK(body["active"] == false);
    auto id = body["id"].get<std::string>();
    auto post_etag = res->get_header_value("ETag");
    CHECK_FALSE(post_etag.empty());
    CHECK(body["meta"]["version"] == post_etag);

    auto get_res = f.get("/scim/v2/Users/" + id);
    REQUIRE(get_res);
    auto get_body = json::parse(get_res->body);
    CHECK(get_body["meta"]["version"] == post_etag);
    CHECK(get_body["active"] == false);
}

TEST_CASE("ScimRoutes: POST active:false — the underlying account is ACTUALLY deactivated "
         "(FIX-1)",
         "[scim][routes][post]") {
    // Hermes MEDIUM (fail-open): honouring active:false on create previously
    // only LOGGED a remove_user() failure and fell through to set_active(),
    // so a failed deactivation could ship a 201 with active:false while the
    // auth account stayed LIVE. This asserts the success path end-to-end —
    // not just the SCIM resource flag (covered by the ETag test above) but
    // that the auth account itself is actually deactivated, the way
    // deactivate()'s own tests assert for PATCH/DELETE.
    Fixture f;
    auto res = f.post("/scim/v2/Users", {{"userName", "uma2"}, {"active", false}});
    REQUIRE(res);
    CHECK(res->status == 201);
    CHECK_FALSE(f.auth_mgr.get_user_role("uma2").has_value());

    // NOTE (injection gap): forcing remove_user()'s own DB write to fail at
    // exactly this point — without also failing the preceding
    // upsert_user()/reactivate_user() call on the same connection — needs
    // either a multi-second SQLITE_BUSY wait on AuthDB's fixed 5s
    // busy_timeout or corrupting the shared auth.db file mid-request,
    // neither of which is a clean/fast unit-test injection (same gap
    // documented on the revive-refusal undo test above). The fail-closed
    // branch itself (remove_user() failure -> 500 + audit "failure" +
    // return, never falling through to set_active()) is exercised by
    // inspection and mirrors deactivate()'s identical, already-tested
    // contract.
}

// ── S-CLAMP-COUNT ────────────────────────────────────────────────────────

TEST_CASE("ScimRoutes: GET list clamps count to maxResults", "[scim][routes][list]") {
    Fixture f;
    // Seed scim_resource rows directly at the store layer (cheap — no
    // PBKDF2/AuthDB write per row) so this test can exceed maxResults
    // without the cost of 200+ real HTTP provisions.
    for (int i = 0; i < scim::kMaxScimListResults + 5; ++i) {
        REQUIRE(f.scim_store->create_resource("clampuser" + std::to_string(i)).has_value());
    }

    auto res = f.get("/scim/v2/Users?count=99999");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = json::parse(res->body);
    CHECK(body["itemsPerPage"] == scim::kMaxScimListResults);
    CHECK(body["Resources"].size() == static_cast<std::size_t>(scim::kMaxScimListResults));
}

// FIX-1 (MEDIUM-2, S-BOUND-INTPARAM): a malformed startIndex/count must
// fail cleanly with a SCIM 400 `invalidValue`, never an unhandled
// std::stoi exception escaping to a 500.
TEST_CASE("ScimRoutes: GET list — non-numeric startIndex is a 400, not a 500",
         "[scim][routes][list]") {
    Fixture f;
    auto res = f.get("/scim/v2/Users?startIndex=abc");
    REQUIRE(res);
    CHECK(res->status == 400);
    auto body = json::parse(res->body);
    CHECK(body["scimType"] == "invalidValue");
}

TEST_CASE("ScimRoutes: GET list — an absurdly long startIndex is a 400, not a 500",
         "[scim][routes][list]") {
    Fixture f;
    auto res = f.get("/scim/v2/Users?startIndex=" + std::string(40, '9'));
    REQUIRE(res);
    CHECK(res->status == 400);
    auto body = json::parse(res->body);
    CHECK(body["scimType"] == "invalidValue");
}

TEST_CASE("ScimRoutes: GET list — a malformed count is a 400, not a 500",
         "[scim][routes][list]") {
    Fixture f;
    auto res = f.get("/scim/v2/Users?count=" + std::string(40, '9'));
    REQUIRE(res);
    CHECK(res->status == 400);
    auto body = json::parse(res->body);
    CHECK(body["scimType"] == "invalidValue");
}

TEST_CASE("ScimRoutes: GET list — a negative startIndex is clamped to 1, not a 400",
         "[scim][routes][list]") {
    Fixture f;
    REQUIRE(f.scim_store->create_resource("negidxuser").has_value());

    auto res = f.get("/scim/v2/Users?startIndex=-5");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = json::parse(res->body);
    CHECK(body["startIndex"] == 1);
}

TEST_CASE("ScimRoutes: GET list — a valid startIndex/count still works", "[scim][routes][list]") {
    Fixture f;
    for (int i = 0; i < 10; ++i)
        REQUIRE(f.scim_store->create_resource("pageuser" + std::to_string(i)).has_value());

    auto res = f.get("/scim/v2/Users?startIndex=2&count=5");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = json::parse(res->body);
    CHECK(body["startIndex"] == 2);
    CHECK(body["itemsPerPage"] == 5);
    CHECK(body["Resources"].size() == 5);
}

// ── scim_boot_guard_ok (S-BOOTGUARD-TEST) ───────────────────────────────

TEST_CASE("scim_boot_guard_ok: disabled — always ok", "[scim][bootguard]") {
    Config cfg;
    cfg.scim_enable = false;
    std::string err;
    CHECK(scim_boot_guard_ok(cfg, err));
    CHECK(err.empty());
}

TEST_CASE("scim_boot_guard_ok: enabled without a token — fails", "[scim][bootguard]") {
    Config cfg;
    cfg.scim_enable = true;
    cfg.https_enabled = true;
    cfg.scim_token.clear();
    std::string err;
    CHECK_FALSE(scim_boot_guard_ok(cfg, err));
    CHECK_FALSE(err.empty());
}

TEST_CASE("scim_boot_guard_ok: enabled without HTTPS — fails", "[scim][bootguard]") {
    Config cfg;
    cfg.scim_enable = true;
    cfg.https_enabled = false;
    // Long enough to clear the M1 length floor, so this test exercises the
    // HTTPS branch specifically, not the length one.
    cfg.scim_token = "a-plenty-long-enough-token-0123456789";
    std::string err;
    CHECK_FALSE(scim_boot_guard_ok(cfg, err));
    CHECK_FALSE(err.empty());
}

TEST_CASE("scim_boot_guard_ok: enabled with token AND https — ok", "[scim][bootguard]") {
    Config cfg;
    cfg.scim_enable = true;
    cfg.https_enabled = true;
    cfg.scim_token = "a-plenty-long-enough-token-0123456789";
    std::string err;
    CHECK(scim_boot_guard_ok(cfg, err));
    CHECK(err.empty());
}

// ── M1 — token length/entropy floor ─────────────────────────────────────

TEST_CASE("scim_boot_guard_ok: enabled with a short token — fails (M1)",
         "[scim][bootguard][m1]") {
    Config cfg;
    cfg.scim_enable = true;
    cfg.https_enabled = true;
    cfg.scim_token = "short-token"; // < 24 chars
    std::string err;
    CHECK_FALSE(scim_boot_guard_ok(cfg, err));
    CHECK_FALSE(err.empty());
}

TEST_CASE("scim_boot_guard_ok: a 32-hex-char token passes the length floor (M1)",
         "[scim][bootguard][m1]") {
    Config cfg;
    cfg.scim_enable = true;
    cfg.https_enabled = true;
    cfg.scim_token = "0123456789abcdef0123456789abcdef"; // 32 hex chars
    std::string err;
    CHECK(scim_boot_guard_ok(cfg, err));
    CHECK(err.empty());
}

TEST_CASE("scim_boot_guard_ok: exactly 24 chars is the accepted floor (M1)",
         "[scim][bootguard][m1]") {
    Config cfg;
    cfg.scim_enable = true;
    cfg.https_enabled = true;
    cfg.scim_token = std::string(24, 'a');
    std::string err;
    CHECK(scim_boot_guard_ok(cfg, err));
}

TEST_CASE("scim_boot_guard_ok: 23 chars fails the floor by one (M1)",
         "[scim][bootguard][m1]") {
    Config cfg;
    cfg.scim_enable = true;
    cfg.https_enabled = true;
    cfg.scim_token = std::string(23, 'a');
    std::string err;
    CHECK_FALSE(scim_boot_guard_ok(cfg, err));
}

// ── H1 integration: real httplib::Server + Client (2026-07-08 review) ──────
//
// The TestRouteSink-based tests above dispatch directly into ScimRoutes'
// registered handlers — they can never reproduce H1 (every /scim/v2/* call
// 302-redirected to /login before ScimRoutes ever ran) because the sink has
// no pre-routing middleware at all (#438's whole reason for existing). This
// section spins up a REAL httplib::Server with a pre-routing handler that
// mirrors server.cpp's production wiring (the ADR-1005 on-behalf-of guard
// FIRST, then the rate limiter, THEN `is_login_exempt_path`, THEN a
// no-session-cookie 401/redirect fallback for everything else), registers
// ScimRoutes against it, and drives it over the wire with httplib::Client —
// the only way to prove the exemption + ordering holds on a real request.
//
// UPDATE (post PR #2018 review, dev merge landed the ADR-1005 guard on this
// branch): the on-behalf-of guard shipped in server.cpp (~line 4781, guarded
// by `on_behalf_guard.hpp`'s `onbehalf::find_reserved_key`) since the note
// below was written. This harness now wires the SAME production helper —
// not a re-implementation — into the mock pre-routing handler, positioned
// exactly where server.cpp runs it: before the rate limiter and before
// `is_login_exempt_path`. That proves the SCIM login-exemption (H1's whole
// point) does NOT also exempt /scim/v2/* from ADR-1005 — a reserved
// on-behalf-of header still 403s even with an otherwise-valid SCIM bearer
// token, and even though the request never reaches the login-redirect
// fallback this exemption softened.
//
// SKIPPED UNDER ThreadSanitizer (#438) — same rationale as
// test_security_headers.cpp's integration block: httplib::Server's threaded
// acceptor crashes under TSan's interceptors with no usable report. The
// TestRouteSink coverage above still exercises ScimRoutes' own logic under
// TSan; only the on-the-wire pre-routing-handler wiring is gated here.
#if defined(__has_feature)
#  if __has_feature(thread_sanitizer)
#    define YUZU_SCIM_TSAN_BUILD 1
#  endif
#endif
#if defined(__SANITIZE_THREAD__)
#  define YUZU_SCIM_TSAN_BUILD 1
#endif

#ifndef YUZU_SCIM_TSAN_BUILD

namespace {

/// Wires ScimRoutes against a REAL httplib::Server whose pre-routing
/// handler mirrors server.cpp's `set_pre_routing_handler` lambda closely
/// enough to reproduce H1: the ADR-1005 on-behalf-of guard runs FIRST
/// (production helper, `onbehalf::find_reserved_key` — not a
/// re-implementation), then a configurable RateLimiter, then
/// `is_login_exempt_path` gates the login-redirect fallback (same ordering
/// as production) — see the "Do NOT" warning in the review against wiring
/// the SCIM exemption into an earlier early-return that skips the limiter
/// (and, now, against wiring it before the on-behalf-of guard either).
struct ScimIntegrationServer {
    httplib::Server svr;
    std::thread server_thread;
    int port{0};
    std::filesystem::path data_dir{yuzu::test::unique_temp_path("yuzu-scim-integration-")};
    std::unique_ptr<AuthDB> auth_db;
    auth::AuthManager auth_mgr;
    std::unique_ptr<ScimStore> scim_store;
    yuzu::test::TempDbFile audit_db_file{std::string_view{"yuzu-scim-integration-audit-"}};
    std::unique_ptr<AuditStore> audit_store;
    std::unique_ptr<ScimRoutes> routes;
    RateLimiter rate_limiter;
    yuzu::MetricsRegistry metrics;
    const std::string token{"integration-test-scim-bearer-0123456789"};
    std::string scim_admin_group;

    explicit ScimIntegrationServer(int rate_per_second = 100, std::string admin_group = {})
        : rate_limiter(rate_per_second), scim_admin_group(std::move(admin_group)) {}

    void start() {
        std::filesystem::create_directories(data_dir);
        auth_db = std::make_unique<AuthDB>(data_dir, /*cleanup_interval_secs=*/0);
        REQUIRE(auth_db->initialize().has_value());
        auth_mgr.set_auth_db(auth_db.get());

        scim_store = std::make_unique<ScimStore>(data_dir / "auth.db");
        REQUIRE(scim_store->is_open());
        REQUIRE(scim_store->set_token(token, "test"));

        audit_store = std::make_unique<AuditStore>(audit_db_file.path);
        REQUIRE(audit_store->is_open());

        // Mirrors server.cpp's pre-routing lambda ordering (server.cpp
        // ~4743-4830): the ADR-1005 on-behalf-of guard FIRST (using the
        // real production helper, not a reimplementation — the whole point
        // is exercising the shipped reserved-key detection), then the rate
        // limiter, then the login-exempt-path decision, then a 401
        // (API-shaped path) or a redirect (page-shaped path) for anything
        // unauthenticated that falls through. There is no session cookie
        // anywhere in this harness — every non-exempt path is always
        // "unauthenticated".
        svr.set_pre_routing_handler(
            [this](const httplib::Request& req, httplib::Response& res)
                -> httplib::Server::HandlerResponse {
                if (auto reserved = onbehalf::find_reserved_key(req.headers)) {
                    (void)onbehalf::note_rejection(metrics, "http");
                    res.status = 403;
                    res.set_content(
                        R"({"error":{"code":403,"message":"on-behalf-of assertion rejected per ADR-1005"}})",
                        "application/json");
                    (void)reserved;
                    return httplib::Server::HandlerResponse::Handled;
                }
                if (!rate_limiter.allow(req.remote_addr)) {
                    res.status = 429;
                    return httplib::Server::HandlerResponse::Handled;
                }
                if (is_login_exempt_path(req.path))
                    return httplib::Server::HandlerResponse::Unhandled;
                if (req.path.starts_with("/api/") || req.path.starts_with("/scim/v2/")) {
                    res.status = 401;
                    res.set_content(R"({"error":{"code":401,"message":"unauthorized"}})",
                                    "application/json");
                } else {
                    res.set_redirect("/login");
                }
                return httplib::Server::HandlerResponse::Handled;
            });

        routes = std::make_unique<ScimRoutes>();
        routes->register_routes(svr, scim_store.get(), &auth_mgr, audit_store.get(),
                                scim_admin_group);

        port = svr.bind_to_any_port("127.0.0.1");
        REQUIRE(port > 0);
        server_thread = std::thread([this]() { svr.listen_after_bind(); });
        for (int i = 0; i < 100; ++i) {
            if (svr.is_running())
                break;
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        REQUIRE(svr.is_running());
    }

    ~ScimIntegrationServer() {
        svr.stop();
        if (server_thread.joinable())
            server_thread.join();
        std::error_code ec;
        routes.reset();
        audit_store.reset();
        scim_store.reset();
        auth_db.reset();
        std::filesystem::remove_all(data_dir, ec);
    }
};

/// Provision a SCIM user over real HTTP and return its `id`. Fails the test
/// (via REQUIRE) rather than returning an error — every caller needs a
/// live scim_id to proceed.
std::string create_scim_user_over_wire(httplib::Client& cli, const std::string& token,
                                       const std::string& username) {
    httplib::Headers hdr{{"Authorization", "Bearer " + token}};
    auto r = cli.Post("/scim/v2/Users", hdr, json{{"userName", username}}.dump(),
                      "application/scim+json");
    REQUIRE(r);
    REQUIRE(r->status == 201);
    return json::parse(r->body)["id"].get<std::string>();
}

} // namespace

TEST_CASE("H1 integration: /scim/v2/Users with a valid bearer provisions over real HTTP — "
         "201, not a login redirect",
         "[scim][routes][integration][h1]") {
    ScimIntegrationServer ts;
    ts.start();

    httplib::Client cli("127.0.0.1", ts.port);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);

    httplib::Headers auth_hdr{{"Authorization", "Bearer " + ts.token}};
    auto r = cli.Post("/scim/v2/Users", auth_hdr, R"({"userName":"wire-user"})",
                      "application/scim+json");
    REQUIRE(r);
    CHECK(r->status == 201);
    CHECK(r->has_header("Location"));
}

TEST_CASE("H1 integration: a bogus bearer against /scim/v2/Users is 401, NEVER a 302 to /login",
         "[scim][routes][integration][h1]") {
    ScimIntegrationServer ts;
    ts.start();

    httplib::Client cli("127.0.0.1", ts.port);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);

    httplib::Headers bogus{{"Authorization", "Bearer totally-wrong-token"}};
    auto r = cli.Post("/scim/v2/Users", bogus, R"({"userName":"nope"})", "application/scim+json");
    REQUIRE(r);
    // Pre-fix, this exact request 302-redirected to /login (H1): the
    // pre-routing handler's unauthenticated fallback only 401'd paths
    // starting with "/api/"; /scim/v2/* does not, so it fell into the
    // page-shaped redirect branch instead. Assert the negative explicitly
    // so a regression back to that behavior is caught even if some future
    // refactor produces a different non-401 status.
    CHECK(r->status != 302);
    CHECK(r->status == 401);
    CHECK(r->get_header_value("WWW-Authenticate") == "Bearer");
}

TEST_CASE("H1 integration: a missing bearer against /scim/v2/Users is 401, not a redirect",
         "[scim][routes][integration][h1]") {
    ScimIntegrationServer ts;
    ts.start();

    httplib::Client cli("127.0.0.1", ts.port);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);

    auto r = cli.Post("/scim/v2/Users", R"({"userName":"nope"})", "application/scim+json");
    REQUIRE(r);
    CHECK(r->status != 302);
    CHECK(r->status == 401);
}

TEST_CASE("H1 integration: a non-exempt API path with no session still gets the ordinary "
         "unauthenticated-API 401 (control — the SCIM exemption did not broaden beyond "
         "/scim/v2/*)",
         "[scim][routes][integration][h1]") {
    ScimIntegrationServer ts;
    ts.start();

    httplib::Client cli("127.0.0.1", ts.port);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);

    auto r = cli.Get("/api/v1/foo");
    REQUIRE(r);
    CHECK(r->status == 401);
}

TEST_CASE("H1 integration: rate limiting is RETAINED for /scim/v2/* despite the login "
         "exemption (ordering: the limiter runs before the exempt-path check)",
         "[scim][routes][integration][h1][ratelimit]") {
    ScimIntegrationServer ts(/*rate_per_second=*/1);
    ts.start();

    httplib::Client cli("127.0.0.1", ts.port);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);

    httplib::Headers auth_hdr{{"Authorization", "Bearer " + ts.token}};
    auto r1 = cli.Get("/scim/v2/ServiceProviderConfig", auth_hdr);
    REQUIRE(r1);
    CHECK(r1->status == 200);

    // Same client IP, immediately after — rate=1 leaves the bucket at 0
    // tokens, so this MUST be rejected before it ever reaches ScimRoutes,
    // proving the login exemption is not ALSO a rate-limit bypass.
    auto r2 = cli.Get("/scim/v2/ServiceProviderConfig", auth_hdr);
    REQUIRE(r2);
    CHECK(r2->status == 429);
}

TEST_CASE("H1 integration: a reserved on-behalf-of header against /scim/v2/* is 403 per "
         "ADR-1005, even with an otherwise-valid SCIM bearer token (the SCIM login-exemption "
         "does not strip the on-behalf-of guard)",
         "[scim][routes][integration][h1][adr1005][onbehalf]") {
    ScimIntegrationServer ts;
    ts.start();

    httplib::Client cli("127.0.0.1", ts.port);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);

    // A real reserved key from on_behalf_guard.hpp's kReservedKeys, alongside
    // an otherwise-valid bearer token — proving the 403 fires on the
    // presence of the reserved header, not on the absence of auth.
    httplib::Headers hdr{{"Authorization", "Bearer " + ts.token},
                         {"X-Yuzu-On-Behalf-Of", "alice@example.com"}};
    auto r = cli.Post("/scim/v2/Users", hdr, R"({"userName":"onbehalf-user"})",
                      "application/scim+json");
    REQUIRE(r);
    CHECK(r->status == 403);

    // Control: the same request MINUS the reserved header provisions
    // normally (201) — isolates the 403 to the on-behalf-of guard, not some
    // other rejection of this payload/token pair.
    httplib::Headers clean{{"Authorization", "Bearer " + ts.token}};
    auto r2 = cli.Post("/scim/v2/Users", clean, R"({"userName":"onbehalf-user-clean"})",
                       "application/scim+json");
    REQUIRE(r2);
    CHECK(r2->status == 201);
}

// ── SCIM v2 Groups (#2021, slice 2) — real httplib::Server + Client ─────────
//
// Same rationale as the H1 section above (PR #2018's HIGH bugs slipped
// because tests bypassed the `pre_routing_handler`) — every Group-route
// test in this section drives the surface over the wire, never through
// TestRouteSink.

TEST_CASE("Groups integration: POST creates a group — 201, GET finds it, unknown id is 404 not "
         "403",
         "[scim][routes][integration][groups]") {
    ScimIntegrationServer ts;
    ts.start();
    httplib::Client cli("127.0.0.1", ts.port);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);
    httplib::Headers hdr{{"Authorization", "Bearer " + ts.token}};

    auto post_res = cli.Post("/scim/v2/Groups", hdr, R"({"displayName":"Engineering"})",
                             "application/scim+json");
    REQUIRE(post_res);
    CHECK(post_res->status == 201);
    CHECK(post_res->has_header("Location"));
    auto body = json::parse(post_res->body);
    CHECK(body["displayName"] == "Engineering");
    auto id = body["id"].get<std::string>();

    auto get_res = cli.Get(("/scim/v2/Groups/" + id).c_str(), hdr);
    REQUIRE(get_res);
    CHECK(get_res->status == 200);
    CHECK(json::parse(get_res->body)["displayName"] == "Engineering");

    // Unknown id: 404, never 403 (no existence oracle — mirrors the Users
    // surface's posture).
    auto missing_get = cli.Get("/scim/v2/Groups/deadbeefdeadbeefdeadbeefdeadbeef", hdr);
    REQUIRE(missing_get);
    CHECK(missing_get->status == 404);

    auto missing_del = cli.Delete("/scim/v2/Groups/deadbeefdeadbeefdeadbeefdeadbeef", hdr);
    REQUIRE(missing_del);
    CHECK(missing_del->status == 404);
}

TEST_CASE("Groups integration: bogus bearer against /scim/v2/Groups is 401, missing bearer is "
         "401",
         "[scim][routes][integration][groups][auth]") {
    ScimIntegrationServer ts;
    ts.start();
    httplib::Client cli("127.0.0.1", ts.port);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);

    httplib::Headers bogus{{"Authorization", "Bearer totally-wrong-token"}};
    auto r1 = cli.Post("/scim/v2/Groups", bogus, R"({"displayName":"X"})",
                       "application/scim+json");
    REQUIRE(r1);
    CHECK(r1->status == 401);

    auto r2 = cli.Get("/scim/v2/Groups");
    REQUIRE(r2);
    CHECK(r2->status == 401);
}

TEST_CASE("Groups integration: promotion — PATCH-adding a SCIM user to the admin group promotes "
         "them, removing demotes them back",
         "[scim][routes][integration][groups][promotion]") {
    ScimIntegrationServer ts(/*rate_per_second=*/100, /*admin_group=*/"Yuzu-Admins");
    ts.start();
    httplib::Client cli("127.0.0.1", ts.port);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);
    httplib::Headers hdr{{"Authorization", "Bearer " + ts.token}};

    auto user_id = create_scim_user_over_wire(cli, ts.token, "grace");
    REQUIRE(ts.auth_mgr.get_user_role("grace").value() == auth::Role::user);

    auto group_post = cli.Post("/scim/v2/Groups", hdr, R"({"displayName":"Yuzu-Admins"})",
                               "application/scim+json");
    REQUIRE(group_post);
    REQUIRE(group_post->status == 201);
    auto group_id = json::parse(group_post->body)["id"].get<std::string>();

    json add_body{{"Operations",
                   json::array({{{"op", "add"},
                                 {"path", "members"},
                                 {"value", json::array({{{"value", user_id}}})}}})}};
    auto patch_res = cli.Patch(("/scim/v2/Groups/" + group_id).c_str(), hdr, add_body.dump(),
                               "application/scim+json");
    REQUIRE(patch_res);
    CHECK(patch_res->status == 200);
    // The group role-application core ran synchronously inside the PATCH
    // handler (see recompute_scim_user_role) — no polling/eventual
    // consistency needed.
    CHECK(ts.auth_mgr.get_user_role("grace").value() == auth::Role::admin);

    json remove_body{
        {"Operations",
         json::array({{{"op", "remove"}, {"path", "members[value eq \"" + user_id + "\"]"}}})}};
    auto patch_res2 = cli.Patch(("/scim/v2/Groups/" + group_id).c_str(), hdr, remove_body.dump(),
                                "application/scim+json");
    REQUIRE(patch_res2);
    CHECK(patch_res2->status == 200);
    CHECK(ts.auth_mgr.get_user_role("grace").value() == auth::Role::user);
}

TEST_CASE("Groups integration: PROVENANCE — a group member value mapping to a local (non-SCIM) "
         "admin never changes that account's role, and never audits scim.user.role_changed for "
         "it",
         "[scim][routes][integration][groups][provenance]") {
    ScimIntegrationServer ts(/*rate_per_second=*/100, /*admin_group=*/"Yuzu-Admins");
    ts.start();
    httplib::Client cli("127.0.0.1", ts.port);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);
    httplib::Headers hdr{{"Authorization", "Bearer " + ts.token}};

    // A local admin, created OUTSIDE the SCIM path — mirrors first-run-setup
    // / an operator-run `yuzu-server --add-user`.
    REQUIRE(ts.auth_mgr.upsert_user("root-admin", "correct-horse-battery-staple",
                                    auth::Role::admin));
    REQUIRE(ts.auth_db->get_provisioning_source("root-admin").value() == "local");
    // Craft a scim_resource mapping pointing at the local account (the
    // defense-in-depth scenario the Users provenance guard already covers —
    // e.g. an operator hand-editing scim_resources, or a future bug) so a
    // Group member `value` CAN reference it by scim_id.
    auto local_admin_mapping = ts.scim_store->create_resource("root-admin");
    REQUIRE(local_admin_mapping.has_value());

    auto group_post = cli.Post("/scim/v2/Groups", hdr, R"({"displayName":"Yuzu-Admins"})",
                               "application/scim+json");
    REQUIRE(group_post);
    REQUIRE(group_post->status == 201);
    auto group_id = json::parse(group_post->body)["id"].get<std::string>();

    json add_body{
        {"Operations",
         json::array({{{"op", "add"},
                       {"path", "members"},
                       {"value", json::array({{{"value", local_admin_mapping->scim_id}}})}}})}};
    auto patch_res = cli.Patch(("/scim/v2/Groups/" + group_id).c_str(), hdr, add_body.dump(),
                               "application/scim+json");
    REQUIRE(patch_res);
    CHECK(patch_res->status == 200);

    // The local admin's role/provenance are COMPLETELY untouched.
    CHECK(ts.auth_mgr.get_user_role("root-admin").value() == auth::Role::admin);
    CHECK(ts.auth_db->get_provisioning_source("root-admin").value() == "local");

    // No scim.user.role_changed audit row was ever written for this target.
    AuditQuery q;
    q.action = "scim.user.role_changed";
    q.target_id = local_admin_mapping->scim_id;
    auto rows = ts.audit_store->query(q);
    CHECK(rows.empty());

    // The membership ITSELF is a valid store operation (the local admin's
    // scim_id IS a live scim_resource row — the routes layer's
    // validate-and-skip only rejects a value that resolves to NO scim
    // resource at all; it does not, and must not, need to know about
    // provenance to decide what a Group's membership list contains). The
    // security boundary is entirely at ROLE APPLICATION — proven above by
    // the untouched role/provenance and the missing audit row.
    auto get_res = cli.Get(("/scim/v2/Groups/" + group_id).c_str(), hdr);
    REQUIRE(get_res);
    auto members = json::parse(get_res->body)["members"];
    bool found = false;
    for (const auto& m : members)
        if (m["value"] == local_admin_mapping->scim_id)
            found = true;
    CHECK(found);

    // Control: a BOGUS member value (never resolves to any SCIM User
    // resource at all) IS validate-and-skip'd — the PATCH still succeeds
    // and simply never persists that membership.
    json bogus_body{{"Operations",
                     json::array({{{"op", "add"},
                                   {"path", "members"},
                                   {"value", json::array({{{"value", "deadbeefdeadbeef"}}})}}})}};
    auto patch_res2 = cli.Patch(("/scim/v2/Groups/" + group_id).c_str(), hdr, bogus_body.dump(),
                                "application/scim+json");
    REQUIRE(patch_res2);
    CHECK(patch_res2->status == 200);
    auto get_res2 = cli.Get(("/scim/v2/Groups/" + group_id).c_str(), hdr);
    REQUIRE(get_res2);
    auto members2 = json::parse(get_res2->body)["members"];
    for (const auto& m : members2)
        CHECK(m["value"] != "deadbeefdeadbeef");
}

TEST_CASE("Groups integration: deprovision ordering — a group-elevated admin cannot be SCIM-"
         "deprovisioned until the IdP removes them from the admin group",
         "[scim][routes][integration][groups][deprovision-ordering]") {
    ScimIntegrationServer ts(/*rate_per_second=*/100, /*admin_group=*/"Yuzu-Admins");
    ts.start();
    httplib::Client cli("127.0.0.1", ts.port);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);
    httplib::Headers hdr{{"Authorization", "Bearer " + ts.token}};

    auto user_id = create_scim_user_over_wire(cli, ts.token, "hank");

    auto group_post = cli.Post("/scim/v2/Groups", hdr, R"({"displayName":"Yuzu-Admins"})",
                               "application/scim+json");
    REQUIRE(group_post);
    REQUIRE(group_post->status == 201);
    auto group_id = json::parse(group_post->body)["id"].get<std::string>();

    json add_body{{"Operations",
                   json::array({{{"op", "add"},
                                 {"path", "members"},
                                 {"value", json::array({{{"value", user_id}}})}}})}};
    auto promote_res = cli.Patch(("/scim/v2/Groups/" + group_id).c_str(), hdr, add_body.dump(),
                                 "application/scim+json");
    REQUIRE(promote_res);
    REQUIRE(promote_res->status == 200);
    REQUIRE(ts.auth_mgr.get_user_role("hank").value() == auth::Role::admin);

    // Group-elevated — deprovision_role_ok refuses exactly like an
    // operator-elevated account. 404, never 403.
    auto del1 = cli.Delete(("/scim/v2/Users/" + user_id).c_str(), hdr);
    REQUIRE(del1);
    CHECK(del1->status == 404);
    CHECK(ts.auth_mgr.get_user_role("hank").value() == auth::Role::admin);

    // The IdP removes them from the admin group — demotes back to 'user'.
    json remove_body{
        {"Operations",
         json::array({{{"op", "remove"}, {"path", "members[value eq \"" + user_id + "\"]"}}})}};
    auto demote_res = cli.Patch(("/scim/v2/Groups/" + group_id).c_str(), hdr, remove_body.dump(),
                                "application/scim+json");
    REQUIRE(demote_res);
    REQUIRE(demote_res->status == 200);
    REQUIRE(ts.auth_mgr.get_user_role("hank").value() == auth::Role::user);

    // NOW the deprovision succeeds.
    auto del2 = cli.Delete(("/scim/v2/Users/" + user_id).c_str(), hdr);
    REQUIRE(del2);
    CHECK(del2->status == 204);
}

TEST_CASE("Groups integration: --scim-admin-group unset (empty) — group membership never "
         "promotes anyone",
         "[scim][routes][integration][groups][admin-group-unset]") {
    ScimIntegrationServer ts; // no admin_group argument — empty by default
    ts.start();
    httplib::Client cli("127.0.0.1", ts.port);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);
    httplib::Headers hdr{{"Authorization", "Bearer " + ts.token}};

    auto user_id = create_scim_user_over_wire(cli, ts.token, "ivy");

    // Even a group literally named "Yuzu-Admins" (or anything else) cannot
    // promote when scim_admin_group is unconfigured — resolve_role_from_groups
    // never matches against an empty admin_group.
    auto group_post = cli.Post("/scim/v2/Groups", hdr, R"({"displayName":"Yuzu-Admins"})",
                               "application/scim+json");
    REQUIRE(group_post);
    REQUIRE(group_post->status == 201);
    auto group_id = json::parse(group_post->body)["id"].get<std::string>();

    json add_body{{"Operations",
                   json::array({{{"op", "add"},
                                 {"path", "members"},
                                 {"value", json::array({{{"value", user_id}}})}}})}};
    auto patch_res = cli.Patch(("/scim/v2/Groups/" + group_id).c_str(), hdr, add_body.dump(),
                               "application/scim+json");
    REQUIRE(patch_res);
    CHECK(patch_res->status == 200);
    CHECK(ts.auth_mgr.get_user_role("ivy").value() == auth::Role::user);
}

TEST_CASE("Groups integration: DELETE demotes every member and audits the demotion (qa-4)",
          "[scim][routes][integration][groups][delete]") {
    ScimIntegrationServer ts(/*rate_per_second=*/100, /*admin_group=*/"Yuzu-Admins");
    ts.start();
    httplib::Client cli("127.0.0.1", ts.port);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);
    httplib::Headers hdr{{"Authorization", "Bearer " + ts.token}};

    auto user_id = create_scim_user_over_wire(cli, ts.token, "quinn");

    auto group_post = cli.Post("/scim/v2/Groups", hdr, R"({"displayName":"Yuzu-Admins"})",
                               "application/scim+json");
    REQUIRE(group_post);
    REQUIRE(group_post->status == 201);
    auto group_id = json::parse(group_post->body)["id"].get<std::string>();

    json add_body{{"Operations",
                   json::array({{{"op", "add"},
                                 {"path", "members"},
                                 {"value", json::array({{{"value", user_id}}})}}})}};
    auto promote_res = cli.Patch(("/scim/v2/Groups/" + group_id).c_str(), hdr, add_body.dump(),
                                 "application/scim+json");
    REQUIRE(promote_res);
    REQUIRE(promote_res->status == 200);
    REQUIRE(ts.auth_mgr.get_user_role("quinn").value() == auth::Role::admin);

    auto del = cli.Delete(("/scim/v2/Groups/" + group_id).c_str(), hdr);
    REQUIRE(del);
    CHECK(del->status == 204);

    // The member is demoted back to 'user' as soon as its only admin-
    // granting group disappears (recompute_scim_user_role runs over the
    // pre-delete membership snapshot).
    CHECK(ts.auth_mgr.get_user_role("quinn").value() == auth::Role::user);

    // A durable scim.user.role_changed=success audit row exists for the
    // demotion, keyed on the user's scim_id (not the group's).
    AuditQuery q;
    q.action = "scim.user.role_changed";
    q.target_id = user_id;
    auto rows = ts.audit_store->query(q);
    REQUIRE_FALSE(rows.empty());
    bool found_demotion = false;
    for (const auto& row : rows) {
        if (row.result == "success" && row.detail.find("new_role=user") != std::string::npos)
            found_demotion = true;
    }
    CHECK(found_demotion);

    // The group itself is gone.
    auto get_res = cli.Get(("/scim/v2/Groups/" + group_id).c_str(), hdr);
    REQUIRE(get_res);
    CHECK(get_res->status == 404);
}

TEST_CASE("Groups integration: PUT full-replace — dropped member demoted, added member promoted "
          "(qa-5)",
          "[scim][routes][integration][groups][put]") {
    ScimIntegrationServer ts(/*rate_per_second=*/100, /*admin_group=*/"Yuzu-Admins");
    ts.start();
    httplib::Client cli("127.0.0.1", ts.port);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);
    httplib::Headers hdr{{"Authorization", "Bearer " + ts.token}};

    auto old_member = create_scim_user_over_wire(cli, ts.token, "rex");
    auto new_member = create_scim_user_over_wire(cli, ts.token, "sara");

    auto group_post =
        cli.Post("/scim/v2/Groups", hdr,
                 json{{"displayName", "Yuzu-Admins"},
                      {"members", json::array({{{"value", old_member}}})}}
                     .dump(),
                 "application/scim+json");
    REQUIRE(group_post);
    REQUIRE(group_post->status == 201);
    auto group_id = json::parse(group_post->body)["id"].get<std::string>();
    REQUIRE(ts.auth_mgr.get_user_role("rex").value() == auth::Role::admin);
    REQUIRE(ts.auth_mgr.get_user_role("sara").value() == auth::Role::user);

    // Full replace: drop rex, add sara.
    json put_body{{"displayName", "Yuzu-Admins"},
                  {"members", json::array({{{"value", new_member}}})}};
    auto put_res = cli.Put(("/scim/v2/Groups/" + group_id).c_str(), hdr, put_body.dump(),
                           "application/scim+json");
    REQUIRE(put_res);
    CHECK(put_res->status == 200);

    CHECK(ts.auth_mgr.get_user_role("rex").value() == auth::Role::user);
    CHECK(ts.auth_mgr.get_user_role("sara").value() == auth::Role::admin);

    auto get_res = cli.Get(("/scim/v2/Groups/" + group_id).c_str(), hdr);
    REQUIRE(get_res);
    auto members = json::parse(get_res->body)["members"];
    REQUIRE(members.size() == 1);
    CHECK(members[0]["value"] == new_member);
}

TEST_CASE("Groups integration: PATCH with both replace and add/remove ops — replace wins "
          "(qa-6)",
          "[scim][routes][integration][groups][patch-precedence]") {
    ScimIntegrationServer ts(/*rate_per_second=*/100, /*admin_group=*/"Yuzu-Admins");
    ts.start();
    httplib::Client cli("127.0.0.1", ts.port);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);
    httplib::Headers hdr{{"Authorization", "Bearer " + ts.token}};

    auto replace_member = create_scim_user_over_wire(cli, ts.token, "tina");
    auto add_member = create_scim_user_over_wire(cli, ts.token, "uma");

    auto group_post = cli.Post("/scim/v2/Groups", hdr, R"({"displayName":"Yuzu-Admins"})",
                               "application/scim+json");
    REQUIRE(group_post);
    REQUIRE(group_post->status == 201);
    auto group_id = json::parse(group_post->body)["id"].get<std::string>();

    // A single PATCH body mixing an `add` op with a `replace` op on members
    // — parse_group_patch documents "last replace in the body wins" and the
    // routes layer applies `replace_members` exclusively when present
    // (ignoring the accumulated add/remove lists). Only replace_member
    // should end up a member.
    json mixed_body{
        {"Operations",
         json::array(
             {{{"op", "add"},
              {"path", "members"},
              {"value", json::array({{{"value", add_member}}})}},
             {{"op", "replace"},
              {"path", "members"},
              {"value", json::array({{{"value", replace_member}}})}}})}};
    auto patch_res = cli.Patch(("/scim/v2/Groups/" + group_id).c_str(), hdr, mixed_body.dump(),
                               "application/scim+json");
    REQUIRE(patch_res);
    CHECK(patch_res->status == 200);

    auto get_res = cli.Get(("/scim/v2/Groups/" + group_id).c_str(), hdr);
    REQUIRE(get_res);
    auto members = json::parse(get_res->body)["members"];
    REQUIRE(members.size() == 1);
    CHECK(members[0]["value"] == replace_member);
    CHECK(ts.auth_mgr.get_user_role("tina").value() == auth::Role::admin);
    CHECK(ts.auth_mgr.get_user_role("uma").value() == auth::Role::user);
}

TEST_CASE("Groups integration: PUT rename onto an existing group's displayName 409s, B unchanged "
          "(arch-S4/UP-2)",
          "[scim][routes][integration][groups][rename-409]") {
    ScimIntegrationServer ts;
    ts.start();
    httplib::Client cli("127.0.0.1", ts.port);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);
    httplib::Headers hdr{{"Authorization", "Bearer " + ts.token}};

    auto a_post = cli.Post("/scim/v2/Groups", hdr, R"({"displayName":"Group-A"})",
                           "application/scim+json");
    REQUIRE(a_post);
    REQUIRE(a_post->status == 201);

    auto b_post = cli.Post("/scim/v2/Groups", hdr, R"({"displayName":"Group-B"})",
                           "application/scim+json");
    REQUIRE(b_post);
    REQUIRE(b_post->status == 201);
    auto b_id = json::parse(b_post->body)["id"].get<std::string>();
    auto b_etag = json::parse(b_post->body)["meta"]["version"].get<std::string>();

    auto put_res = cli.Put(("/scim/v2/Groups/" + b_id).c_str(), hdr,
                           R"({"displayName":"Group-A"})", "application/scim+json");
    REQUIRE(put_res);
    CHECK(put_res->status == 409);

    AuditQuery q;
    q.action = "scim.group.updated";
    q.target_id = b_id;
    auto rows = ts.audit_store->query(q);
    bool found_denied = false;
    for (const auto& row : rows)
        if (row.result == "denied")
            found_denied = true;
    CHECK(found_denied);

    auto get_res = cli.Get(("/scim/v2/Groups/" + b_id).c_str(), hdr);
    REQUIRE(get_res);
    auto body = json::parse(get_res->body);
    CHECK(body["displayName"] == "Group-B");
    CHECK(body["meta"]["version"] == b_etag);
}

TEST_CASE("Groups integration: PATCH rename onto an existing group's displayName 409s, B "
          "unchanged (arch-S4/UP-2)",
          "[scim][routes][integration][groups][rename-409]") {
    ScimIntegrationServer ts;
    ts.start();
    httplib::Client cli("127.0.0.1", ts.port);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);
    httplib::Headers hdr{{"Authorization", "Bearer " + ts.token}};

    auto a_post = cli.Post("/scim/v2/Groups", hdr, R"({"displayName":"Group-C"})",
                           "application/scim+json");
    REQUIRE(a_post);
    REQUIRE(a_post->status == 201);

    auto b_post = cli.Post("/scim/v2/Groups", hdr, R"({"displayName":"Group-D"})",
                           "application/scim+json");
    REQUIRE(b_post);
    REQUIRE(b_post->status == 201);
    auto b_id = json::parse(b_post->body)["id"].get<std::string>();

    json patch_body{
        {"Operations",
         json::array({{{"op", "replace"}, {"path", "displayName"}, {"value", "Group-C"}}})}};
    auto patch_res = cli.Patch(("/scim/v2/Groups/" + b_id).c_str(), hdr, patch_body.dump(),
                               "application/scim+json");
    REQUIRE(patch_res);
    CHECK(patch_res->status == 409);

    AuditQuery q;
    q.action = "scim.group.updated";
    q.target_id = b_id;
    auto rows = ts.audit_store->query(q);
    bool found_denied = false;
    for (const auto& row : rows)
        if (row.result == "denied")
            found_denied = true;
    CHECK(found_denied);

    auto get_res = cli.Get(("/scim/v2/Groups/" + b_id).c_str(), hdr);
    REQUIRE(get_res);
    CHECK(json::parse(get_res->body)["displayName"] == "Group-D");
}

TEST_CASE("Groups integration: an embedded-NUL displayName is never truncated to the configured "
         "admin group — no spurious promotion (UP-3)",
         "[scim][routes][integration][groups][embedded-nul]") {
    // "Admins\0decoy" — read-side truncation (the bug this guards) would
    // silently turn this into the literal string "Admins", exactly
    // matching --scim-admin-group and promoting the member to admin. The
    // fixed read path returns the full 12 bytes, which != "Admins", so
    // resolve_role_from_groups must not match.
    ScimIntegrationServer ts(/*rate_per_second=*/100, /*admin_group=*/"Admins");
    ts.start();
    httplib::Client cli("127.0.0.1", ts.port);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);
    httplib::Headers hdr{{"Authorization", "Bearer " + ts.token}};

    auto user_id = create_scim_user_over_wire(cli, ts.token, "walt");

    std::string nul_name = std::string("Admins") + std::string(1, '\0') + std::string("decoy");
    REQUIRE(nul_name.size() == 12);

    json group_body{{"displayName", nul_name},
                    {"members", json::array({{{"value", user_id}}})}};
    auto group_post = cli.Post("/scim/v2/Groups", hdr, group_body.dump(), "application/scim+json");
    REQUIRE(group_post);
    REQUIRE(group_post->status == 201);
    auto group_id = json::parse(group_post->body)["id"].get<std::string>();

    // No spurious promotion — the group's real name is NOT "Admins".
    CHECK(ts.auth_mgr.get_user_role("walt").value() == auth::Role::user);

    // The stored/returned displayName is the full 12 bytes, not truncated.
    auto get_res = cli.Get(("/scim/v2/Groups/" + group_id).c_str(), hdr);
    REQUIRE(get_res);
    auto returned_name = json::parse(get_res->body)["displayName"].get<std::string>();
    CHECK(returned_name.size() == 12);
    CHECK(returned_name == nul_name);

    // Control: a group actually named exactly "Admins" (no embedded NUL)
    // DOES promote — confirms the guard above is about truncation, not
    // about the admin-group feature being broken outright.
    auto plain_group_post = cli.Post("/scim/v2/Groups", hdr, R"({"displayName":"Admins"})",
                                     "application/scim+json");
    REQUIRE(plain_group_post);
    REQUIRE(plain_group_post->status == 201);
    auto plain_group_id = json::parse(plain_group_post->body)["id"].get<std::string>();
    json add_body{{"Operations",
                   json::array({{{"op", "add"},
                                 {"path", "members"},
                                 {"value", json::array({{{"value", user_id}}})}}})}};
    auto patch_res = cli.Patch(("/scim/v2/Groups/" + plain_group_id).c_str(), hdr,
                               add_body.dump(), "application/scim+json");
    REQUIRE(patch_res);
    CHECK(patch_res->status == 200);
    CHECK(ts.auth_mgr.get_user_role("walt").value() == auth::Role::admin);
}

TEST_CASE("Groups integration: sec-L3 caps over HTTP — oversized displayName on POST and PATCH "
          "400s",
          "[scim][routes][integration][groups][caps]") {
    ScimIntegrationServer ts;
    ts.start();
    httplib::Client cli("127.0.0.1", ts.port);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);
    httplib::Headers hdr{{"Authorization", "Bearer " + ts.token}};

    std::string oversized(scim::kMaxDisplayNameLen + 1, 'x');

    auto post_res = cli.Post("/scim/v2/Groups", hdr,
                             json{{"displayName", oversized}}.dump(), "application/scim+json");
    REQUIRE(post_res);
    CHECK(post_res->status == 400);

    auto group_post = cli.Post("/scim/v2/Groups", hdr, R"({"displayName":"CapsGroup"})",
                               "application/scim+json");
    REQUIRE(group_post);
    REQUIRE(group_post->status == 201);
    auto group_id = json::parse(group_post->body)["id"].get<std::string>();

    json patch_body{
        {"Operations",
         json::array({{{"op", "replace"}, {"path", "displayName"}, {"value", oversized}}})}};
    auto patch_res = cli.Patch(("/scim/v2/Groups/" + group_id).c_str(), hdr, patch_body.dump(),
                               "application/scim+json");
    REQUIRE(patch_res);
    CHECK(patch_res->status == 400);

    // Unchanged.
    auto get_res = cli.Get(("/scim/v2/Groups/" + group_id).c_str(), hdr);
    REQUIRE(get_res);
    CHECK(json::parse(get_res->body)["displayName"] == "CapsGroup");
}

TEST_CASE("Groups integration: sec-L3/#7 member cap over HTTP — >5000 members 400s + denied",
          "[scim][routes][integration][groups][caps][members]") {
    ScimIntegrationServer ts;
    ts.start();
    httplib::Client cli("127.0.0.1", ts.port);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);
    httplib::Headers hdr{{"Authorization", "Bearer " + ts.token}};

    // The cap check runs BEFORE any per-member resolution, so a synthetic
    // list of ids that never resolve to real SCIM Users is sufficient —
    // this proves the guard, not membership resolution semantics. Bare
    // single-char string entries (parse_group tolerates the plain-string
    // members shape) keep the body well under kMaxBodyBytes (64 KiB) even
    // at 5001 entries — a `{"value":...}` object shape per entry would blow
    // that budget first and mask the member-count guard behind a 413.
    json members = json::array();
    for (std::size_t i = 0; i < 5001; ++i)
        members.push_back("x");

    auto post_res =
        cli.Post("/scim/v2/Groups", hdr,
                 json{{"displayName", "HugeGroup"}, {"members", members}}.dump(),
                 "application/scim+json");
    REQUIRE(post_res);
    CHECK(post_res->status == 400);

    AuditQuery q;
    q.action = "scim.group.created";
    auto rows = ts.audit_store->query(q);
    bool found_denied = false;
    for (const auto& row : rows)
        if (row.result == "denied" && row.detail.find("member count exceeds cap") != std::string::npos)
            found_denied = true;
    CHECK(found_denied);

    // The group was never created.
    auto by_name =
        cli.Get(R"(/scim/v2/Groups?filter=displayName%20eq%20%22HugeGroup%22)", hdr);
    REQUIRE(by_name);
    CHECK(json::parse(by_name->body)["totalResults"] == 0);
}

#endif // YUZU_SCIM_TSAN_BUILD
