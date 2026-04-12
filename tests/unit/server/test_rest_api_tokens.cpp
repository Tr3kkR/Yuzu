/**
 * test_rest_api_tokens.cpp — HTTP-level tests for `DELETE /api/v1/tokens/:id`.
 *
 * Governance Gate 3 (quality-engineer) flagged that the #222 IDOR fix landed
 * with only store-level coverage. The vulnerability was in the handler, not
 * the store, so we need end-to-end coverage of:
 *   - owner self-revoke (200)
 *   - admin cross-user revoke (200)
 *   - non-admin non-owner attempt (404, denied audit)
 *   - unknown token id (404, no audit)
 *
 * Pattern mirrors `test_mcp_server.cpp`: spin up an httplib::Server on a
 * random port, register the RestApiV1 routes with mock callbacks, and hit
 * the real HTTP surface with httplib::Client.
 */

#include "api_token_store.hpp"
#include "rest_api_v1.hpp"

#include <catch2/catch_test_macros.hpp>

#include <httplib.h>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <string>
#include <thread>
#include <vector>

namespace fs = std::filesystem;
using namespace yuzu::server;

namespace {

static fs::path unique_temp_path(const std::string& prefix) {
    return fs::temp_directory_path() /
           (prefix + "-" +
            std::to_string(std::hash<std::thread::id>{}(std::this_thread::get_id()) ^
                           static_cast<size_t>(std::chrono::steady_clock::now()
                                                   .time_since_epoch()
                                                   .count())));
}

struct AuditRecord {
    std::string action;
    std::string result;
    std::string target_id;
    std::string detail;
};

struct RestTokensHarness {
    httplib::Server svr;
    std::thread server_thread;
    int port{0};

    fs::path db_path;
    std::unique_ptr<ApiTokenStore> token_store;

    // Mock session state — the caller sets these before calling any
    // endpoint; the auth_fn closure captures by reference and returns a
    // session reflecting the current values.
    std::string session_user;
    auth::Role session_role{auth::Role::user};

    std::vector<AuditRecord> audit_log;

    RestApiV1 api;

    RestTokensHarness() : db_path(unique_temp_path("rest-api-tokens")) {
        fs::remove(db_path);
        token_store = std::make_unique<ApiTokenStore>(db_path);
        REQUIRE(token_store->is_open());

        auto auth_fn =
            [this](const httplib::Request&, httplib::Response&)
            -> std::optional<auth::Session> {
            if (session_user.empty())
                return std::nullopt;
            auth::Session s;
            s.username = session_user;
            s.role = session_role;
            return s;
        };

        // Permission check always passes — the point of these tests is
        // the owner check, which runs AFTER the RBAC gate.
        auto perm_fn = [](const httplib::Request&, httplib::Response&,
                          const std::string&, const std::string&) -> bool {
            return true;
        };

        auto audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string&,
                               const std::string& target_id, const std::string& detail) {
            audit_log.push_back({action, result, target_id, detail});
        };

        // Pass nullptr for every store except the one under test — every
        // REST handler checks for null and returns 503, so unrelated routes
        // just fail cleanly if accidentally hit.
        api.register_routes(svr, auth_fn, perm_fn, audit_fn,
                            /*rbac_store=*/nullptr,
                            /*mgmt_store=*/nullptr,
                            token_store.get(),
                            /*quarantine_store=*/nullptr,
                            /*response_store=*/nullptr,
                            /*instruction_store=*/nullptr,
                            /*execution_tracker=*/nullptr,
                            /*schedule_engine=*/nullptr,
                            /*approval_manager=*/nullptr,
                            /*tag_store=*/nullptr,
                            /*audit_store=*/nullptr);

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

    ~RestTokensHarness() {
        svr.stop();
        if (server_thread.joinable())
            server_thread.join();
        token_store.reset();
        fs::remove(db_path);
    }

    std::string create_token_for(const std::string& owner, const std::string& name) {
        auto raw = token_store->create_token(name, owner);
        REQUIRE(raw.has_value());
        auto listing = token_store->list_tokens(owner);
        REQUIRE(!listing.empty());
        return listing.back().token_id;
    }

    httplib::Result delete_token(const std::string& token_id) {
        httplib::Client cli("127.0.0.1", port);
        cli.set_connection_timeout(5);
        cli.set_read_timeout(5);
        return cli.Delete(("/api/v1/tokens/" + token_id).c_str());
    }
};

} // namespace

TEST_CASE("REST DELETE /api/v1/tokens: owner can revoke own token",
          "[rest][token][owner]") {
    RestTokensHarness h;
    auto token_id = h.create_token_for("alice", "alice-key");

    h.session_user = "alice";
    h.session_role = auth::Role::user;

    auto res = h.delete_token(token_id);
    REQUIRE(res);
    CHECK(res->status == 200);

    // Store state: token is now revoked.
    auto looked_up = h.token_store->get_token(token_id);
    REQUIRE(looked_up.has_value());
    CHECK(looked_up->revoked);

    // Audit: exactly one success event with owner=alice.
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "api_token.revoke");
    CHECK(h.audit_log[0].result == "success");
    CHECK(h.audit_log[0].detail.find("owner=alice") != std::string::npos);
}

TEST_CASE("REST DELETE /api/v1/tokens: non-owner non-admin gets 404 (no oracle)",
          "[rest][token][owner][idor]") {
    RestTokensHarness h;
    auto token_id = h.create_token_for("alice", "alice-key");

    // Bob is a non-admin non-owner with ApiToken:Delete (perm_fn mock always
    // grants). The handler must now reject with 404, matching the response
    // for a completely unknown token id so bob cannot enumerate alice's
    // token ids by probing.
    h.session_user = "bob";
    h.session_role = auth::Role::user;

    auto res = h.delete_token(token_id);
    REQUIRE(res);
    CHECK(res->status == 404);

    // Store state: token is NOT revoked.
    auto looked_up = h.token_store->get_token(token_id);
    REQUIRE(looked_up.has_value());
    CHECK_FALSE(looked_up->revoked);

    // Audit: the denied attempt is logged with owner=alice so forensics can
    // distinguish a real unknown-id probe (no audit) from an enumeration
    // attempt (denied audit).
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "api_token.revoke");
    CHECK(h.audit_log[0].result == "denied");
    CHECK(h.audit_log[0].target_id == token_id);
    CHECK(h.audit_log[0].detail == "owner=alice");
}

TEST_CASE("REST DELETE /api/v1/tokens: response body is identical for "
          "unknown id and not-owner (enumeration oracle closed)",
          "[rest][token][owner][idor]") {
    RestTokensHarness h;
    auto token_id = h.create_token_for("alice", "alice-key");

    h.session_user = "bob";
    h.session_role = auth::Role::user;

    auto not_owner = h.delete_token(token_id);
    auto unknown = h.delete_token("deadbeef1234567890");
    REQUIRE(not_owner);
    REQUIRE(unknown);
    CHECK(not_owner->status == unknown->status);
    // Bodies differ only in the `meta` block at most; the `error.message`
    // text must be identical so client-side enumeration is defeated.
    CHECK(not_owner->body.find("token not found") != std::string::npos);
    CHECK(unknown->body.find("token not found") != std::string::npos);
}

TEST_CASE("REST DELETE /api/v1/tokens: admin bypass revokes any token",
          "[rest][token][owner][admin]") {
    RestTokensHarness h;
    auto token_id = h.create_token_for("alice", "alice-key");

    // Admin session can revoke alice's token.
    h.session_user = "root";
    h.session_role = auth::Role::admin;

    auto res = h.delete_token(token_id);
    REQUIRE(res);
    CHECK(res->status == 200);

    auto looked_up = h.token_store->get_token(token_id);
    REQUIRE(looked_up.has_value());
    CHECK(looked_up->revoked);

    // Audit success event names alice as the owner even though root
    // performed the revoke.
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].result == "success");
    CHECK(h.audit_log[0].detail == "owner=alice");
}

TEST_CASE("REST DELETE /api/v1/tokens: unknown token id returns 404 with no audit",
          "[rest][token]") {
    RestTokensHarness h;
    h.session_user = "alice";
    h.session_role = auth::Role::user;

    auto res = h.delete_token("nonexistent1234");
    REQUIRE(res);
    CHECK(res->status == 404);
    // No audit event on clean not-found — only denied attempts are logged.
    CHECK(h.audit_log.empty());
}
