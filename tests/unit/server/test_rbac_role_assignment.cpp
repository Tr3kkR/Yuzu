/**
 * test_rbac_role_assignment.cpp — HTTP-level (and MCP-twin) coverage for the
 * A2 global human role assignment surface (`.claude/plans/rbac-industry-
 * leading-DELIVERY-PLAN.md` §2): `POST/DELETE
 * /api/v1/rbac/roles/{name}/assignments[/{principal_id}]` + MCP twins
 * `assign_rbac_role`/`unassign_rbac_role`.
 *
 * Pattern: register both `RestApiV1::register_routes(HttpRouteSink&, ...)`
 * (TestRouteSink, mirrors test_rest_engine_principal_roles.cpp) AND
 * `McpServer::build_handler(...)` (mirrors test_mcp_engine_principal_roles.cpp)
 * against the SAME underlying RbacStore/AuthDB from one harness. UNLIKE
 * McpEngineRolesHarness's "not an MCP token" convention (empty `mcp_tier`,
 * which makes `tier_allows()`/`requires_approval()` both no-op): both MCP
 * tools here carry the empty-`mcp_tier` deny-outright guard (#4309,
 * adversarial-review PR1/A2 round-2), so the harness's DEFAULT session tier
 * is `"supervised"` (matching what the tool descriptions claim) and a real
 * PG-backed `ApprovalManager` IS wired in. Every MCP call that is meant to
 * reach the tool handler goes through the full ticket-then-recall dance
 * (`RbacRoleHarness::mcp_call_tool_approved`/`mcp_mint_and_approve` — mint,
 * approve as "reviewer-bob", recall with `approval_id`), mirroring
 * `test_mcp_server.cpp`'s `SchemaGateHarness` pattern; the two dedicated
 * empty-tier tests explicitly reset `session_mcp_tier` to `""` to exercise
 * the new guard directly, bypassing C8's ticket flow entirely (an empty
 * tier is still a no-op for `tier_allows()`/`requires_approval()` — that
 * has not changed, only the NEW per-handler guard has been added on top).
 *
 * Covers: the is_rbac_administrator gate on both transports (RBAC-off
 * durable-AuthDB-reread AND RBAC-on principal_roles-reread), the
 * ITServiceOwner/non-"user"/unknown-role rejections (M1 uniform message;
 * on MCP, an out-of-enum `role` is now actually caught by the tool's own
 * input schema before the handler's M1 logic runs at all — see that test's
 * own comment), the self-target and last-Administrator guards, service-scope
 * structural denial, the empty-`mcp_tier` deny-outright guard, and
 * audit-fail-closed on both mutations.
 *
 * PG-gated: RbacStore, AuthDB, AND ApprovalManager are all born-on-Postgres
 * (ADR-0006/ADR-0065). Skips when YUZU_TEST_POSTGRES_DSN is unset, fails
 * when set but broken.
 */

#include "mcp_jsonrpc.hpp" // mcp::kApprovalRequired — the ticket-then-recall dance
#include "mcp_server.hpp"
#include "rbac_store.hpp"
#include "rest_api_v1.hpp"
#include "test_route_sink.hpp"

#include "test_approval_manager_pg_helper.hpp"
#include "test_auth_db_pg_helper.hpp"
#include "test_rbac_store_pg_helper.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <httplib.h>

#include <string>
#include <vector>

#include "../test_helpers.hpp"

using namespace yuzu::server;

namespace {

struct AuditRecord {
    std::string action, result, target_id, detail;
};

/// One harness driving BOTH the REST TestRouteSink and the MCP JSON-RPC
/// handler off the SAME RbacStore/AuthDB/ApprovalManager (independent PG
/// databases — the predicate takes two independent store pointers with no
/// cross-store transaction requirement, mirrors test_rest_access_review.cpp's
/// AuthDbPgShared-alongside-RbacStore composition).
struct RbacRoleHarness {
    yuzu::server::test::TestRouteSink sink;

    yuzu::test::RbacStorePg rbac;
    yuzu::test::AuthDbPg auth_db;
    yuzu::test::ApprovalManagerPg appr;

    std::string session_user{"admin"};
    std::string session_token_scope_service;
    std::string session_principal_kind{"human"};
    std::string session_auth_source{"local"};
    // Both MCP tools deny an empty mcp_tier outright (#4309, adversarial-
    // review PR1/A2 round-2) and are approval-gated at "supervised" once a
    // real tier is presented — default to the tier the tool descriptions
    // themselves claim, so an MCP call reaches the tool handler via the
    // real ticket-then-recall dance (mcp_call_tool_approved below) rather
    // than being intercepted by C8 before ever reaching it. The two
    // dedicated empty-tier tests reset this to "" explicitly.
    std::string session_mcp_tier{"supervised"};
    bool auth_enabled{true};
    bool audit_allow{true};

    std::vector<AuditRecord> audit_log;

    RestApiV1 api;
    yuzu::server::mcp::McpServer mcp;
    yuzu::server::mcp::McpServer::HandlerFn mcp_handler;
    bool read_only_mode_{false};
    bool mcp_disabled_{false};

    RbacRoleHarness() {
        REQUIRE(rbac->is_open());
        REQUIRE(auth_db->is_open());
        REQUIRE(appr->is_open());

        auto session_of = [this]() {
            auth::Session s;
            s.username = session_user;
            s.token_scope_service = session_token_scope_service;
            s.principal_kind = session_principal_kind;
            s.auth_source = session_auth_source;
            // REST never reads session->mcp_tier (its own gate is
            // is_rbac_administrator + step_up_fn) — this field only matters
            // to the MCP transport below, where it drives tier_allows()/
            // requires_approval() and the new empty-tier guard.
            s.mcp_tier = session_mcp_tier;
            return s;
        };

        auto rest_auth_fn = [this, session_of](const httplib::Request&,
                                               httplib::Response&) -> std::optional<auth::Session> {
            if (!auth_enabled)
                return std::nullopt;
            return session_of();
        };
        // Deliberately permissive — neither route under test calls perm_fn at
        // all (gated on is_rbac_administrator instead); kept only because the
        // register_routes signature requires one.
        auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                          const std::string&) -> bool { return true; };
        auto audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string&,
                               const std::string& target_id, const std::string& detail) -> bool {
            audit_log.push_back({action, result, target_id, detail});
            return audit_allow;
        };

        api.register_routes(sink, rest_auth_fn, perm_fn, audit_fn,
                            /*rbac_store=*/rbac.get(),
                            /*mgmt_store=*/nullptr,
                            /*token_store=*/nullptr,
                            /*quarantine_store=*/nullptr,
                            /*response_store=*/nullptr,
                            /*instruction_store=*/nullptr,
                            /*execution_tracker=*/nullptr,
                            /*schedule_engine=*/nullptr,
                            /*approval_manager=*/nullptr,
                            /*tag_store=*/nullptr,
                            /*audit_store=*/nullptr,
                            /*service_group_fn=*/{},
                            /*tag_push_fn=*/{},
                            /*inventory_store=*/nullptr,
                            /*product_pack_store=*/nullptr,
                            /*sw_deploy_store=*/nullptr,
                            /*device_token_store=*/nullptr,
                            /*license_store=*/nullptr,
                            /*guaranteed_state_store=*/nullptr,
                            /*metrics_registry=*/nullptr,
                            /*session_revoke_fn=*/{},
                            /*execution_event_bus=*/nullptr,
                            /*result_set_store=*/nullptr,
                            /*command_dispatch_fn=*/{},
                            /*step_up_fn=*/{}, // no MFA gate in this harness (mirrors token tests)
                            /*guardian_push_fn=*/{},
                            /*dex_perf_fn=*/{},
                            /*network_api=*/{},
                            /*lockout_clear_fn=*/{},
                            /*baseline_store=*/nullptr,
                            /*scoped_perm_fn=*/{},
                            /*software_inventory_store=*/nullptr,
                            /*response_scope_fn=*/{},
                            /*engine_principal_store=*/nullptr,
                            /*access_review_store=*/nullptr,
                            /*auth_db=*/auth_db.get());

        auto mcp_auth_fn = [this, session_of](const httplib::Request&,
                                              httplib::Response&) -> std::optional<auth::Session> {
            if (!auth_enabled)
                return std::nullopt;
            return session_of(); // mcp_tier from session_mcp_tier — see its own doc comment
        };
        auto mcp_perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                              const std::string&) -> bool { return true; };
        auto mcp_audit_fn = [this](const httplib::Request&, const std::string& action,
                                   const std::string& result, const std::string&,
                                   const std::string& target_id, const std::string& detail) -> bool {
            audit_log.push_back({action, result, target_id, detail});
            return audit_allow;
        };
        auto agents_fn = []() -> nlohmann::json { return nlohmann::json::array(); };

        mcp_handler = mcp.build_handler(
            std::move(mcp_auth_fn), std::move(mcp_perm_fn), std::move(mcp_audit_fn),
            std::move(agents_fn),
            /*rbac_store=*/rbac.get(),
            /*instruction_store=*/nullptr,
            /*execution_tracker=*/nullptr,
            /*response_store=*/nullptr,
            /*audit_store=*/nullptr,
            /*tag_store=*/nullptr,
            /*inventory_store=*/nullptr,
            /*policy_store=*/nullptr,
            /*mgmt_store=*/nullptr,
            /*approval_manager=*/appr.get(),
            /*schedule_engine=*/nullptr, read_only_mode_, mcp_disabled_,
            /*dispatch_fn=*/nullptr,
            /*ca_store=*/nullptr,
            /*publish_crl_fn=*/nullptr,
            /*guaranteed_state_store=*/nullptr,
            /*dex_perf_fn=*/{},
            /*network_api=*/{},
            /*response_scope_fn=*/{},
            /*software_inventory_store=*/nullptr,
            /*metrics=*/nullptr,
            /*quarantine_store=*/nullptr,
            /*tag_push_fn=*/{},
            /*agent_registry=*/nullptr,
            /*scoped_perm_fn=*/{},
            /*sessions=*/nullptr,
            /*mcp_streaming_disabled=*/nullptr,
            /*mcp_streamed_post_enabled=*/nullptr,
            /*allowed_origins=*/{},
            /*software_licensing_store=*/nullptr,
            /*engine_principal_store=*/nullptr,
            /*access_review_store=*/nullptr,
            /*auth_db=*/auth_db.get(),
            /*directory_sync=*/nullptr);
    }

    auto assign_rest(const std::string& role, const std::string& body) {
        return sink.Post("/api/v1/rbac/roles/" + role + "/assignments", body);
    }
    auto unassign_rest(const std::string& role, const std::string& principal_id) {
        return sink.Delete("/api/v1/rbac/roles/" + role + "/assignments/" + principal_id);
    }

    std::unique_ptr<httplib::Response> mcp_call(const std::string& json_body) {
        httplib::Request req;
        req.method = "POST";
        req.path = "/mcp/v1/";
        req.body = json_body;
        req.set_header("Content-Type", "application/json");
        auto res = std::make_unique<httplib::Response>();
        res->status = 200;
        REQUIRE(mcp_handler);
        mcp_handler(req, *res);
        return res;
    }
    std::unique_ptr<httplib::Response> mcp_call_tool(const std::string& name,
                                                      const nlohmann::json& args) {
        nlohmann::json req = {{"jsonrpc", "2.0"},
                              {"id", 1},
                              {"method", "tools/call"},
                              {"params", {{"name", name}, {"arguments", args}}}};
        return mcp_call(req.dump());
    }

    /// Ticket-then-recall mint+approve for one approval-gated MCP call
    /// (mirrors test_mcp_server.cpp's SchemaGateHarness pattern): the FIRST
    /// `mcp_call_tool(name, args)` call must mint a pending ticket
    /// (kApprovalRequired), approved here as "reviewer-bob". Returns the
    /// approval_id — the caller embeds it into `args` for the recall.
    /// REQUIREs `audit_allow` to be `true` for this call (the ticket's own
    /// mint/approve-path audit is not what an audit_failclose test exercises
    /// — flip `audit_allow` AFTER calling this, before the recall).
    std::string mcp_mint_and_approve(const std::string& name, const nlohmann::json& args) {
        auto first = mcp_call_tool(name, args);
        REQUIRE(first);
        auto body = nlohmann::json::parse(first->body, nullptr, false);
        REQUIRE_FALSE(body.is_discarded());
        REQUIRE(body.contains("error"));
        REQUIRE(body["error"]["code"] == yuzu::server::mcp::kApprovalRequired);
        REQUIRE(body["error"].contains("data"));
        REQUIRE(body["error"]["data"].contains("approval_id"));
        const std::string approval_id = body["error"]["data"]["approval_id"].get<std::string>();
        REQUIRE(appr->approve(approval_id, "reviewer-bob", "").has_value());
        return approval_id;
    }

    /// Full ticket-then-recall for a call meant to reach the tool handler
    /// (mint+approve via mcp_mint_and_approve, then recall with
    /// `approval_id` embedded in the SAME args). Use this instead of a bare
    /// `mcp_call_tool` for every MCP call to assign_rbac_role/
    /// unassign_rbac_role in this file EXCEPT the dedicated empty-tier
    /// tests (which deliberately bypass C8's ticket flow) and the schema
    /// -enum-rejection test (which fails BEFORE a ticket is ever minted).
    std::unique_ptr<httplib::Response> mcp_call_tool_approved(const std::string& name,
                                                               const nlohmann::json& args) {
        const std::string approval_id = mcp_mint_and_approve(name, args);
        nlohmann::json recall_args = args;
        recall_args["approval_id"] = approval_id;
        return mcp_call_tool(name, recall_args);
    }

    /// Seeds `admin` as a durable RBAC administrator for the default
    /// `session_user` ("admin"), via whichever branch `rbac_on` selects.
    void make_caller_admin(bool rbac_on) {
        if (rbac_on) {
            rbac->set_rbac_enabled(true);
            REQUIRE(rbac->assign_role({"user", session_user, "Administrator"}).has_value());
        } else {
            REQUIRE(auth_db->upsert_user(session_user, "hash", "salt", auth::Role::admin)
                       .has_value());
        }
    }
};

} // namespace

// ── REST: happy path ────────────────────────────────────────────────────────

TEST_CASE("REST POST .../rbac/roles/{name}/assignments: RBAC-off durable admin "
          "grants Operator to a user",
          "[pg][rest][rbac][a2]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);

    auto res = h.assign_rest("Operator",
                             R"({"principal_type":"user","principal_id":"jane"})");
    REQUIRE(res);
    CHECK(res->status == 201);
    CHECK(res->body.find("\"assigned\":true") != std::string::npos);

    auto roles = h.rbac->get_principal_roles("user", "jane");
    REQUIRE(roles.size() == 1);
    CHECK(roles[0].role_name == "Operator");

    bool found = false;
    for (const auto& a : h.audit_log)
        if (a.action == "rbac.role.assigned" && a.result == "success")
            found = true;
    CHECK(found);
}

TEST_CASE("REST POST .../rbac/roles/{name}/assignments: RBAC-on durable admin "
          "grants Viewer to a user",
          "[pg][rest][rbac][a2]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/true);

    auto res = h.assign_rest("Viewer",
                             R"({"principal_type":"user","principal_id":"jane"})");
    REQUIRE(res);
    CHECK(res->status == 201);
    CHECK(h.rbac->get_principal_roles("user", "jane").size() == 1);
}

TEST_CASE("REST DELETE .../rbac/roles/{name}/assignments/{id}: removes a "
          "non-Administrator grant",
          "[pg][rest][rbac][a2]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    REQUIRE(h.assign_rest("Operator", R"({"principal_type":"user","principal_id":"jane"})")
               ->status == 201);

    auto res = h.unassign_rest("Operator", "jane");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(h.rbac->get_principal_roles("user", "jane").empty());
}

// ── REST: rejections ────────────────────────────────────────────────────────

TEST_CASE("REST assign: ITServiceOwner is rejected 400, never assigned",
          "[pg][rest][rbac][a2]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);

    auto res = h.assign_rest("ITServiceOwner",
                             R"({"principal_type":"user","principal_id":"jane"})");
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(h.rbac->get_principal_roles("user", "jane").empty());
}

TEST_CASE("REST assign: unknown role rejected 400 with the SAME message as "
          "ITServiceOwner (M1 uniform reject)",
          "[pg][rest][rbac][a2]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);

    auto its = h.assign_rest("ITServiceOwner",
                             R"({"principal_type":"user","principal_id":"jane"})");
    auto unk = h.assign_rest("NoSuchRole",
                             R"({"principal_type":"user","principal_id":"jane"})");
    REQUIRE(its);
    REQUIRE(unk);
    CHECK(its->status == 400);
    CHECK(unk->status == 400);
    // Both land on the SAME uniform client-facing phrase (M1 — no role-
    // catalog oracle): the specific reason (ITServiceOwner-vs-unknown) is
    // never distinguishable from the response body, only from the audit log.
    const bool its_uniform = its->body.find("cannot be assigned") != std::string::npos;
    const bool unk_uniform = unk->body.find("cannot be assigned") != std::string::npos;
    CHECK(its_uniform);
    CHECK(unk_uniform);
}

TEST_CASE("REST assign: non-\"user\" principal_type rejected 400",
          "[pg][rest][rbac][a2]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);

    auto res = h.assign_rest("Operator",
                             R"({"principal_type":"group","principal_id":"engineers"})");
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(h.rbac->get_principal_roles("group", "engineers").empty());
}

// ── REST: durable-admin gate (not perm_fn) ──────────────────────────────────

TEST_CASE("REST assign: a non-admin caller is denied 403 (RBAC off, no durable "
          "admin row)",
          "[pg][rest][rbac][a2]") {
    RbacRoleHarness h;
    REQUIRE(h.auth_db->upsert_user("plainuser", "hash", "salt", auth::Role::user).has_value());
    h.session_user = "plainuser";

    auto res = h.assign_rest("Operator",
                             R"({"principal_type":"user","principal_id":"jane"})");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(h.rbac->get_principal_roles("user", "jane").empty());
}

TEST_CASE("REST assign: a non-admin caller is denied 403 (RBAC on, no "
          "principal_roles Administrator row)",
          "[pg][rest][rbac][a2]") {
    RbacRoleHarness h;
    h.rbac->set_rbac_enabled(true);
    REQUIRE(h.rbac->assign_role({"user", "vieweronly", "Viewer"}).has_value());
    h.session_user = "vieweronly";

    auto res = h.assign_rest("Operator",
                             R"({"principal_type":"user","principal_id":"jane"})");
    REQUIRE(res);
    CHECK(res->status == 403);
}

TEST_CASE("REST assign: a service-scoped token is denied even for a durable "
          "admin user",
          "[pg][rest][rbac][a2]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    h.session_token_scope_service = "some-service";

    auto res = h.assign_rest("Operator",
                             R"({"principal_type":"user","principal_id":"jane"})");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(h.rbac->get_principal_roles("user", "jane").empty());
}

// ── REST: self-target + last-Administrator guards ───────────────────────────

TEST_CASE("REST unassign: a caller may not remove their own Administrator "
          "assignment",
          "[pg][rest][rbac][a2]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    REQUIRE(h.rbac->assign_role({"user", "admin", "Administrator"}).has_value());
    REQUIRE(h.rbac->assign_role({"user", "otheradmin", "Administrator"}).has_value());

    auto res = h.unassign_rest("Administrator", "admin"); // session_user == "admin"
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(h.rbac->get_principal_roles("user", "admin").size() == 1);
}

TEST_CASE("REST unassign: removing the fleet's last remaining Administrator "
          "grant is refused 409",
          "[pg][rest][rbac][a2]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    REQUIRE(h.rbac->assign_role({"user", "soleadmin", "Administrator"}).has_value());

    auto res = h.unassign_rest("Administrator", "soleadmin");
    REQUIRE(res);
    CHECK(res->status == 409);
    CHECK(h.rbac->get_principal_roles("user", "soleadmin").size() == 1);
}

// ── REST: audit fail-closed ──────────────────────────────────────────────────

TEST_CASE("REST assign: fails CLOSED (503) when its audit write drops",
          "[pg][rest][rbac][a2][audit_failclose]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    h.audit_allow = false;

    auto res = h.assign_rest("Operator",
                             R"({"principal_type":"user","principal_id":"jane"})");
    REQUIRE(res);
    CHECK(res->status == 503);
    // The grant itself committed — fail-closed is about the RESPONSE.
    CHECK(h.rbac->get_principal_roles("user", "jane").size() == 1);
}

TEST_CASE("REST unassign: fails CLOSED (503) when its audit write drops",
          "[pg][rest][rbac][a2][audit_failclose]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    REQUIRE(h.assign_rest("Operator", R"({"principal_type":"user","principal_id":"jane"})")
               ->status == 201);
    // Precondition: the grant is live before the fail-closed unassign.
    REQUIRE(h.rbac->get_principal_roles("user", "jane").size() == 1);

    h.audit_allow = false;
    auto res = h.unassign_rest("Operator", "jane");
    REQUIRE(res);
    CHECK(res->status == 503);
    // Attribution: the unassign COMMITTED — the grant is gone — though its
    // audit dropped; the 503 is the audit failure, not a failed mutation.
    CHECK(h.rbac->get_principal_roles("user", "jane").empty());
}

// ── MCP twins ────────────────────────────────────────────────────────────────

TEST_CASE("MCP assign_rbac_role/unassign_rbac_role: happy path, RBAC-off "
          "durable admin",
          "[pg][mcp][rbac][a2]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);

    auto res = h.mcp_call_tool_approved(
        "assign_rbac_role",
        {{"principal_type", "user"}, {"principal_id", "jane"}, {"role", "Operator"}});
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("\"error\"") == std::string::npos);
    CHECK(h.rbac->get_principal_roles("user", "jane").size() == 1);

    auto un = h.mcp_call_tool_approved("unassign_rbac_role",
                                       {{"principal_id", "jane"}, {"role", "Operator"}});
    REQUIRE(un);
    CHECK(un->status == 200);
    CHECK(un->body.find("\"unassigned\":true") != std::string::npos);
    CHECK(h.rbac->get_principal_roles("user", "jane").empty());
}

TEST_CASE("MCP assign_rbac_role: an out-of-enum role (ITServiceOwner or "
          "unknown) is rejected by the tool's own input schema, before a "
          "ticket is even minted",
          "[pg][mcp][rbac][a2]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);

    // #2405: a schema-invalid call must neither mint a ticket nor reach the
    // handler — role is a closed enum (rbac_assignable_roles.hpp) as of the
    // round-2 fix, so "ITServiceOwner" (and any unknown/custom role) now
    // fails HERE, not at the handler's own M1 is_rbac_assignable_role()
    // check (still reachable, and still exercised, via REST — see the REST
    // ITServiceOwner/unknown-role tests above, which have no schema layer).
    // No ticket-then-recall needed: the call never gets that far.
    for (const std::string bad_role : {"ITServiceOwner", "NoSuchRole"}) {
        auto res = h.mcp_call_tool(
            "assign_rbac_role",
            {{"principal_type", "user"}, {"principal_id", "jane"}, {"role", bad_role}});
        REQUIRE(res);
        CHECK(res->body.find("\"error\"") != std::string::npos);
        CHECK(res->body.find("do not match the tool input schema") != std::string::npos);
        CHECK(h.appr->pending_count() == 0); // no ticket minted
    }
    CHECK(h.rbac->get_principal_roles("user", "jane").empty());
}

TEST_CASE("MCP assign_rbac_role: a non-admin caller is denied",
          "[pg][mcp][rbac][a2]") {
    RbacRoleHarness h;
    REQUIRE(h.auth_db->upsert_user("plainuser", "hash", "salt", auth::Role::user).has_value());
    h.session_user = "plainuser";

    // The ticket mint/approve itself has no notion of RBAC admin status —
    // only the RECALL reaches is_rbac_administrator and denies.
    auto res = h.mcp_call_tool_approved(
        "assign_rbac_role",
        {{"principal_type", "user"}, {"principal_id", "jane"}, {"role", "Operator"}});
    REQUIRE(res);
    CHECK(res->body.find("\"error\"") != std::string::npos);
    CHECK(h.rbac->get_principal_roles("user", "jane").empty());
}

TEST_CASE("MCP unassign_rbac_role: last-Administrator refusal is a JSON-RPC "
          "error, grant stays",
          "[pg][mcp][rbac][a2]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    REQUIRE(h.rbac->assign_role({"user", "soleadmin", "Administrator"}).has_value());

    auto res = h.mcp_call_tool_approved(
        "unassign_rbac_role", {{"principal_id", "soleadmin"}, {"role", "Administrator"}});
    REQUIRE(res);
    CHECK(res->body.find("\"error\"") != std::string::npos);
    CHECK(h.rbac->get_principal_roles("user", "soleadmin").size() == 1);
}

// ── MCP: empty mcp_tier deny-outright guard (#4309, adversarial-review
// PR1/A2 round-2) ────────────────────────────────────────────────────────

TEST_CASE("MCP assign_rbac_role: an empty mcp_tier caller is denied outright, "
          "even a durable Administrator",
          "[pg][mcp][rbac][a2]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    h.session_mcp_tier = ""; // "not an MCP token" — a cookie session or untiered API token

    auto res = h.mcp_call_tool(
        "assign_rbac_role",
        {{"principal_type", "user"}, {"principal_id", "jane"}, {"role", "Operator"}});
    REQUIRE(res);
    CHECK(res->body.find("\"error\"") != std::string::npos);
    CHECK(res->body.find("requires an MCP-tier bearer token") != std::string::npos);
    CHECK(h.rbac->get_principal_roles("user", "jane").empty());
    bool found = false;
    for (const auto& a : h.audit_log)
        if (a.action == "rbac.role.assigned" && a.result == "denied" &&
            a.detail.find("empty mcp_tier") != std::string::npos)
            found = true;
    CHECK(found);
}

TEST_CASE("MCP unassign_rbac_role: an empty mcp_tier caller is denied "
          "outright, even a durable Administrator",
          "[pg][mcp][rbac][a2]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    REQUIRE(h.rbac->assign_role({"user", "jane", "Operator"}).has_value());
    h.session_mcp_tier = "";

    auto res =
        h.mcp_call_tool("unassign_rbac_role", {{"principal_id", "jane"}, {"role", "Operator"}});
    REQUIRE(res);
    CHECK(res->body.find("\"error\"") != std::string::npos);
    CHECK(res->body.find("requires an MCP-tier bearer token") != std::string::npos);
    // Nothing changed — the guard fired before the store was ever touched.
    CHECK(h.rbac->get_principal_roles("user", "jane").size() == 1);
    bool found = false;
    for (const auto& a : h.audit_log)
        if (a.action == "rbac.role.unassigned" && a.result == "denied" &&
            a.detail.find("empty mcp_tier") != std::string::npos)
            found = true;
    CHECK(found);
}

// ── MCP: audit fail-closed (#2466/#2406 parity, mirrors
// test_mcp_engine_principal_roles.cpp's assign/unassign pair) ──────────────

TEST_CASE("MCP assign_rbac_role: fails CLOSED on a dropped audit (grant still "
          "committed)",
          "[pg][mcp][rbac][a2][audit_failclose]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    REQUIRE(h.rbac->get_principal_roles("user", "jane").empty());

    const nlohmann::json args = {
        {"principal_type", "user"}, {"principal_id", "jane"}, {"role", "Operator"}};
    const std::string approval_id = h.mcp_mint_and_approve("assign_rbac_role", args);
    h.audit_allow = false;
    nlohmann::json recall = args;
    recall["approval_id"] = approval_id;
    auto res = h.mcp_call_tool("assign_rbac_role", recall);
    REQUIRE(res);
    CHECK(res->status == 200); // JSON-RPC transport-level 200; the error is in the body
    CHECK(res->body.find("\"error\"") != std::string::npos);
    CHECK(res->body.find("\"result\"") == std::string::npos);
    CHECK(res->body.find("could not be persisted") != std::string::npos);
    CHECK(res->body.find("\"audit_persisted\":false") != std::string::npos);
    // Attribution: the grant DID commit though the audit dropped.
    CHECK(h.rbac->get_principal_roles("user", "jane").size() == 1);
}

TEST_CASE("MCP unassign_rbac_role: fails CLOSED on a dropped audit (grant "
          "still removed)",
          "[pg][mcp][rbac][a2][audit_failclose]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    REQUIRE(h.rbac->assign_role({"user", "jane", "Operator"}).has_value());
    REQUIRE(h.rbac->get_principal_roles("user", "jane").size() == 1);

    const nlohmann::json args = {{"principal_id", "jane"}, {"role", "Operator"}};
    const std::string approval_id = h.mcp_mint_and_approve("unassign_rbac_role", args);
    h.audit_allow = false;
    nlohmann::json recall = args;
    recall["approval_id"] = approval_id;
    auto res = h.mcp_call_tool("unassign_rbac_role", recall);
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("\"error\"") != std::string::npos);
    CHECK(res->body.find("\"result\"") == std::string::npos);
    CHECK(res->body.find("\"audit_persisted\":false") != std::string::npos);
    // Attribution: the grant WAS removed though the audit dropped.
    CHECK(h.rbac->get_principal_roles("user", "jane").empty());
}

TEST_CASE("MCP: assign_rbac_role / unassign_rbac_role are advertised in "
          "tools/list",
          "[pg][mcp][rbac][a2][integration]") {
    RbacRoleHarness h;
    auto res = h.mcp_call(R"({"jsonrpc":"2.0","method":"tools/list","id":1})");
    REQUIRE(res);
    CHECK(res->body.find("\"assign_rbac_role\"") != std::string::npos);
    CHECK(res->body.find("\"unassign_rbac_role\"") != std::string::npos);
}
