/**
 * test_rest_guaranteed_state.cpp — HTTP-level coverage for the
 * /api/v1/guaranteed-state/ surface added in Guardian PR 2.
 *
 * Pattern matches test_rest_api_tokens.cpp: register RestApiV1 routes
 * against an in-process TestRouteSink and dispatch synthesised
 * httplib::Request objects through the captured handlers. No real HTTP
 * server, no acceptor thread, no #438 TSan trap.
 *
 * Coverage focuses on the wire contract that downstream tooling
 * (dashboard, MCP, CLI) will exercise:
 *   - 201 on create, with rule_id echoed in `data.rule_id`
 *   - 409 (kConflictPrefix mapping) on duplicate name / rule_id
 *   - 200 round-trip GET / list / PUT / DELETE
 *   - 202 on push (PR 2 placeholder; real fan-out is PR 3)
 *   - audit_fn fires for every mutating endpoint
 *
 * Not covered here: agent-side dispatch (test_guardian_engine.cpp), the
 * scope expansion that PR 3 wires into /push.
 */

#include "guaranteed_state_store.hpp"
#include "rest_api_v1.hpp"
#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include "../test_helpers.hpp"

#include <filesystem>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using namespace yuzu::server;

namespace {

// Delegates to the shared salt + atomic counter helper — the stale
// `thread::id hash ^ steady_clock::now()` pattern that flaked on Windows
// MSVC debug + Defender (#473) is now extinct across the test tree (#482).
fs::path unique_temp_path(const std::string& prefix) {
    return yuzu::test::unique_temp_path(prefix + "-");
}

struct AuditRecord {
    std::string action;
    std::string result;
    std::string target_type;
    std::string target_id;
    std::string detail;
};

struct RestGsHarness {
    yuzu::server::test::TestRouteSink sink;

    fs::path db_path;
    std::unique_ptr<GuaranteedStateStore> store;

    std::string session_user{"alice"};
    auth::Role session_role{auth::Role::admin};

    std::vector<AuditRecord> audit_log;

    RestApiV1 api;

    RestGsHarness() : db_path(unique_temp_path("rest-gs")) {
        fs::remove(db_path);
        // retention=0 keeps the reaper out of the way for ingest tests.
        store = std::make_unique<GuaranteedStateStore>(db_path, /*retention_days=*/0,
                                                       /*cleanup_interval_min=*/60);
        REQUIRE(store->is_open());

        auto auth_fn = [this](const httplib::Request&, httplib::Response&)
            -> std::optional<auth::Session> {
            if (session_user.empty()) return std::nullopt;
            auth::Session s;
            s.username = session_user;
            s.role = session_role;
            return s;
        };

        // perm_fn always grants — RBAC is exercised in test_rbac_store.cpp.
        auto perm_fn = [](const httplib::Request&, httplib::Response&,
                          const std::string&, const std::string&) -> bool {
            return true;
        };

        auto audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string& target_type,
                               const std::string& target_id, const std::string& detail) {
            audit_log.push_back({action, result, target_type, target_id, detail});
        };

        api.register_routes(sink, auth_fn, perm_fn, audit_fn,
                            /*rbac_store=*/nullptr,
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
                            store.get());
    }

    ~RestGsHarness() {
        store.reset();
        fs::remove(db_path);
        // sqlite WAL/SHM siblings
        fs::remove(db_path.string() + "-wal");
        fs::remove(db_path.string() + "-shm");
    }

    static std::string make_rule_body(const std::string& rule_id,
                                       const std::string& name,
                                       const std::string& yaml = "name: example\n") {
        nlohmann::json j;
        j["rule_id"]          = rule_id;
        j["name"]             = name;
        j["yaml_source"]      = yaml;
        j["enabled"]          = true;
        j["enforcement_mode"] = "enforce";
        j["severity"]         = "high";
        j["os_target"]        = "windows";
        j["scope_expr"]       = "tag:env=prod";
        return j.dump();
    }
};

} // namespace

TEST_CASE("REST gs.rules: create returns 201 and echoes rule_id",
          "[rest][guaranteed_state][create]") {
    RestGsHarness h;
    auto res = h.sink.Post("/api/v1/guaranteed-state/rules",
                            RestGsHarness::make_rule_body("r-001", "block-rdp"));
    REQUIRE(res);
    CHECK(res->status == 201);
    CHECK(res->body.find("\"rule_id\":\"r-001\"") != std::string::npos);

    auto stored = h.store->get_rule("r-001");
    REQUIRE(stored.has_value());
    CHECK(stored->name == "block-rdp");
    CHECK(stored->severity == "high");
    CHECK(stored->os_target == "windows");
    CHECK(stored->created_by == "alice");
    CHECK(stored->updated_by == "alice");

    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "guaranteed_state.rule.create");
    CHECK(h.audit_log[0].result == "success");
    CHECK(h.audit_log[0].target_id == "r-001");
}

TEST_CASE("REST gs.rules: missing required fields → 400",
          "[rest][guaranteed_state][create][validation]") {
    RestGsHarness h;
    nlohmann::json bad;
    bad["rule_id"] = "r-bad";
    // name + yaml_source missing
    auto res = h.sink.Post("/api/v1/guaranteed-state/rules", bad.dump());
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(res->body.find("required") != std::string::npos);
    CHECK(h.audit_log.empty());
}

TEST_CASE("REST gs.rules: duplicate name → 409 via kConflictPrefix",
          "[rest][guaranteed_state][conflict]") {
    RestGsHarness h;
    REQUIRE(h.sink.Post("/api/v1/guaranteed-state/rules",
                         RestGsHarness::make_rule_body("r-001", "dup-name"))->status == 201);
    auto res = h.sink.Post("/api/v1/guaranteed-state/rules",
                            RestGsHarness::make_rule_body("r-002", "dup-name"));
    REQUIRE(res);
    CHECK(res->status == 409);
    // Body must NOT carry the kConflictPrefix marker — that's an internal
    // wire convention; the operator-facing message is the cleaned form.
    CHECK(res->body.find("conflict:") == std::string::npos);
    CHECK(res->body.find("dup-name") != std::string::npos);

    REQUIRE(h.audit_log.size() == 2);
    CHECK(h.audit_log[1].result == "denied");
}

TEST_CASE("REST gs.rules: list, get, update, delete round-trip",
          "[rest][guaranteed_state][crud]") {
    RestGsHarness h;
    REQUIRE(h.sink.Post("/api/v1/guaranteed-state/rules",
                         RestGsHarness::make_rule_body("r-001", "rule-a"))->status == 201);
    REQUIRE(h.sink.Post("/api/v1/guaranteed-state/rules",
                         RestGsHarness::make_rule_body("r-002", "rule-b"))->status == 201);

    auto list = h.sink.Get("/api/v1/guaranteed-state/rules");
    REQUIRE(list);
    CHECK(list->status == 200);
    auto list_json = nlohmann::json::parse(list->body);
    REQUIRE(list_json["data"].is_array());
    CHECK(list_json["data"].size() == 2);
    CHECK(list_json["pagination"]["total"].get<int>() == 2);

    auto got = h.sink.Get("/api/v1/guaranteed-state/rules/r-001");
    REQUIRE(got);
    CHECK(got->status == 200);
    auto got_json = nlohmann::json::parse(got->body);
    CHECK(got_json["data"]["name"].get<std::string>() == "rule-a");
    CHECK(got_json["data"]["version"].get<int>() == 1);

    nlohmann::json patch;
    patch["enabled"] = false;
    patch["severity"] = "critical";
    auto upd = h.sink.Put("/api/v1/guaranteed-state/rules/r-001", patch.dump());
    REQUIRE(upd);
    CHECK(upd->status == 200);

    auto refetched = h.store->get_rule("r-001");
    REQUIRE(refetched.has_value());
    CHECK_FALSE(refetched->enabled);
    CHECK(refetched->severity == "critical");
    CHECK(refetched->version == 2);  // bumped by handler

    auto del = h.sink.Delete("/api/v1/guaranteed-state/rules/r-001");
    REQUIRE(del);
    CHECK(del->status == 200);
    CHECK_FALSE(h.store->get_rule("r-001").has_value());
}

TEST_CASE("REST gs.rules: get unknown id → 404",
          "[rest][guaranteed_state][not_found]") {
    RestGsHarness h;
    auto got = h.sink.Get("/api/v1/guaranteed-state/rules/nope");
    REQUIRE(got);
    CHECK(got->status == 404);
}

TEST_CASE("REST gs.rules: delete unknown id → 404 + denied audit",
          "[rest][guaranteed_state][not_found]") {
    RestGsHarness h;
    auto del = h.sink.Delete("/api/v1/guaranteed-state/rules/nope");
    REQUIRE(del);
    CHECK(del->status == 404);
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].result == "denied");
}

TEST_CASE("REST gs.push: returns 202 + audits the operator action",
          "[rest][guaranteed_state][push]") {
    RestGsHarness h;
    REQUIRE(h.sink.Post("/api/v1/guaranteed-state/rules",
                         RestGsHarness::make_rule_body("r-001", "rule-a"))->status == 201);
    nlohmann::json push;
    push["scope"] = "tag:env=prod";
    push["full_sync"] = true;
    auto res = h.sink.Post("/api/v1/guaranteed-state/push", push.dump());
    REQUIRE(res);
    CHECK(res->status == 202);
    CHECK(res->body.find("\"queued\":true") != std::string::npos);
    // Response body uses a stable operational phrase, not an engineer-facing
    // roadmap reference (BL-6 / ER-Dep2).
    CHECK(res->body.find("agent delivery is asynchronous") != std::string::npos);

    REQUIRE(h.audit_log.size() == 2);  // create + push
    const auto& push_audit = h.audit_log[1];
    CHECK(push_audit.action == "guaranteed_state.push");
    // Vocabulary matches sibling handlers: "success" (not the prior novel
    // "accepted"), target_id is empty because a push is fleet-level rather
    // than per-entity, and the scope expression lives in detail alongside
    // the fan-out-deferred marker so SIEM correlation rules can filter on it.
    CHECK(push_audit.result == "success");
    CHECK(push_audit.target_id == "");
    CHECK(push_audit.target_type == "GuaranteedState");
    CHECK(push_audit.detail.find("rules=1") != std::string::npos);
    CHECK(push_audit.detail.find("full_sync=true") != std::string::npos);
    CHECK(push_audit.detail.find("scope=\"tag:env=prod\"") != std::string::npos);
    CHECK(push_audit.detail.find("fan_out_deferred_pr3=true") != std::string::npos);
}

TEST_CASE("REST gs.push: sanitizes scope before embedding in audit detail",
          "[rest][guaranteed_state][push][security]") {
    // UP-R3 regression guard. A scope containing raw quotes, control bytes,
    // or backslashes must not corrupt the audit detail string that SIEM
    // parsers consume. Attacker with GuaranteedState:Push could otherwise
    // forge audit fragments by injecting `" result="denied" fake="`.
    RestGsHarness h;
    nlohmann::json push;
    // Adversarial scope: embedded quote + CR + LF + NUL + backslash + tab.
    // Built by append so there is no risk of buffer-size mismatch with
    // std::string(const char*, size_t) and the embedded NUL.
    std::string adversarial;
    adversarial += "evil\" result=\"denied\" injected=\"yes\"";
    adversarial += "\r\n\t";
    adversarial += "foo";
    adversarial.push_back('\0');
    adversarial += "bar\\";
    push["scope"] = adversarial;
    push["full_sync"] = false;
    auto res = h.sink.Post("/api/v1/guaranteed-state/push", push.dump());
    REQUIRE(res);
    CHECK(res->status == 202);

    REQUIRE(h.audit_log.size() == 1);
    const auto& push_audit = h.audit_log[0];
    CHECK(push_audit.action == "guaranteed_state.push");
    CHECK(push_audit.result == "success");
    // Control bytes (CR/LF/NUL/TAB and the rest of C0) are dropped entirely
    // so no visual line-split survives the round-trip.
    const auto& d = push_audit.detail;
    CHECK(d.find("\r") == std::string::npos);
    CHECK(d.find("\n") == std::string::npos);
    CHECK(d.find("\t") == std::string::npos);
    CHECK(d.find('\0') == std::string::npos);
    // Quotes inside the attacker-controlled value are backslash-escaped so
    // SIEM parsers that tokenise on quoted strings see them inside the
    // scope value, not as delimiters.
    CHECK(d.find("\\\"") != std::string::npos);
    // Backslashes are doubled so they cannot escape the closing scope
    // delimiter.
    CHECK(d.find("bar\\\\") != std::string::npos);
    // The original adversarial payload's injected fields do not appear as
    // unescaped top-level tokens in the detail string.
    CHECK(d.find(" result=\"denied\"") == std::string::npos);
    CHECK(d.find(" injected=\"yes\"") == std::string::npos);
    // The structural frame of the detail is intact.
    CHECK(d.find("rules=0") != std::string::npos);
    CHECK(d.find("full_sync=false") != std::string::npos);
    CHECK(d.find("fan_out_deferred_pr3=true") != std::string::npos);
}

TEST_CASE("REST gs.events: filter + limit pagination",
          "[rest][guaranteed_state][events]") {
    RestGsHarness h;
    GuaranteedStateEventRow ev;
    ev.event_id = "e-1";
    ev.rule_id  = "r-001";
    ev.agent_id = "agent-A";
    ev.event_type = "drift.detected";
    ev.severity = "high";
    ev.guard_type = "registry";
    ev.guard_category = "event";
    ev.detected_value = "0";
    ev.expected_value = "1";
    ev.timestamp = "2026-04-21T00:00:00Z";
    REQUIRE(h.store->insert_event(ev).has_value());

    auto res = h.sink.Get("/api/v1/guaranteed-state/events?rule_id=r-001&limit=10");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    REQUIRE(j["data"].is_array());
    CHECK(j["data"].size() == 1);
    CHECK(j["data"][0]["event_id"].get<std::string>() == "e-1");
}

TEST_CASE("REST gs.events: invalid limit → 400",
          "[rest][guaranteed_state][events][validation]") {
    RestGsHarness h;
    auto res = h.sink.Get("/api/v1/guaranteed-state/events?limit=-7");
    REQUIRE(res);
    CHECK(res->status == 400);
}

TEST_CASE("REST gs.status: returns store rule_count rollup",
          "[rest][guaranteed_state][status]") {
    RestGsHarness h;
    REQUIRE(h.sink.Post("/api/v1/guaranteed-state/rules",
                         RestGsHarness::make_rule_body("r-001", "rule-a"))->status == 201);

    auto res = h.sink.Get("/api/v1/guaranteed-state/status");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["data"]["total_rules"].get<int>() == 1);
    // Field names match the agent-side proto GuaranteedStateStatus so REST and
    // proto schemas don't diverge when PR 4 wires real aggregation (BL-7 /
    // consistency-auditor F1). Previously emitted `compliant`/`drifted`/`errored`.
    CHECK(j["data"].contains("compliant_rules"));
    CHECK(j["data"].contains("drifted_rules"));
    CHECK(j["data"].contains("errored_rules"));
    CHECK_FALSE(j["data"].contains("compliant"));
    CHECK_FALSE(j["data"].contains("drifted"));
    CHECK_FALSE(j["data"].contains("errored"));
}

TEST_CASE("REST gs.alerts: empty list placeholder",
          "[rest][guaranteed_state][alerts]") {
    RestGsHarness h;
    auto res = h.sink.Get("/api/v1/guaranteed-state/alerts");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    REQUIRE(j["data"].is_array());
    CHECK(j["data"].empty());
}
