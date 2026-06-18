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
#include "response_store.hpp"
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

    // Live-info dispatch/poll deps. resp_store is a real ResponseStore the live
    // endpoint polls; the dispatch stub returns a deterministic command_id so a test
    // can pre-insert the matching response row. live_sent toggles the offline path.
    fs::path resp_db_path;
    std::unique_ptr<ResponseStore> resp_store;
    int live_sent{1};
    std::string last_live_plugin, last_live_action;

    std::string session_user{"alice"};
    auth::Role session_role{auth::Role::admin};

    // When false, perm_fn denies (403) — lets a test prove the permission gate
    // runs BEFORE any audit emission on the DEX read surface (default grants,
    // preserving every other test's behaviour).
    bool grant_perms{true};

    // When non-empty, the scoped per-device gate denies (403) this agent_id — lets a
    // test prove the per-device scope is enforced on /api/v1/dex/devices/{id}.
    std::string deny_scoped_agent;

    std::vector<AuditRecord> audit_log;

    RestApiV1 api;

    RestGsHarness() : db_path(unique_temp_path("rest-gs")) {
        fs::remove(db_path);
        // retention=0 keeps the reaper out of the way for ingest tests.
        store = std::make_unique<GuaranteedStateStore>(db_path, /*retention_days=*/0,
                                                       /*cleanup_interval_min=*/60);
        REQUIRE(store->is_open());

        resp_db_path = unique_temp_path("rest-gs-resp");
        fs::remove(resp_db_path);
        resp_store = std::make_unique<ResponseStore>(resp_db_path, /*retention_days=*/0);

        // Deterministic dispatch stub: command_id = "<plugin>-live" so a test can
        // pre-insert the matching response row; live_sent toggles offline (0).
        auto command_dispatch_fn =
            [this](const std::string& plugin, const std::string& action,
                   const std::vector<std::string>&, const std::string&,
                   const std::unordered_map<std::string, std::string>&,
                   const std::string&) -> std::pair<std::string, int> {
            last_live_plugin = plugin;
            last_live_action = action;
            return {plugin + "-live", live_sent};
        };

        auto auth_fn = [this](const httplib::Request&,
                              httplib::Response&) -> std::optional<auth::Session> {
            if (session_user.empty())
                return std::nullopt;
            auth::Session s;
            s.username = session_user;
            s.role = session_role;
            return s;
        };

        // perm_fn grants unless grant_perms is flipped off (then 403, mirroring
        // the production perm_fn) — RBAC proper is exercised in test_rbac_store.cpp.
        auto perm_fn = [this](const httplib::Request&, httplib::Response& res, const std::string&,
                              const std::string&) -> bool {
            if (grant_perms)
                return true;
            res.status = 403;
            return false;
        };

        // Per-device scope gate (require_scoped_permission stand-in): grants unless
        // grant_perms is off OR the agent matches deny_scoped_agent.
        auto scoped_perm_fn = [this](const httplib::Request&, httplib::Response& res,
                                     const std::string&, const std::string&,
                                     const std::string& agent_id) -> bool {
            if (!grant_perms || (!deny_scoped_agent.empty() && agent_id == deny_scoped_agent)) {
                res.status = 403;
                return false;
            }
            return true;
        };

        // PR W1.1 UP-H1: AuditFn typedef → std::function<bool(...)>.
        auto audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string& target_type,
                               const std::string& target_id, const std::string& detail) -> bool {
            audit_log.push_back({action, result, target_type, target_id, detail});
            return true;
        };

        api.register_routes(sink, auth_fn, perm_fn, audit_fn,
                            /*rbac_store=*/nullptr,
                            /*mgmt_store=*/nullptr,
                            /*token_store=*/nullptr,
                            /*quarantine_store=*/nullptr,
                            resp_store.get(),
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
                            /*license_store=*/nullptr, store.get(),
                            /*metrics_registry=*/nullptr,
                            /*session_revoke_fn=*/{},
                            /*execution_event_bus=*/nullptr,
                            /*result_set_store=*/nullptr,
                            command_dispatch_fn,
                            /*step_up_fn=*/{},
                            /*guardian_push_fn=*/{},
                            /*dex_perf_fn=*/{},
                            /*net_perf_fn=*/{},
                            scoped_perm_fn);
    }

    ~RestGsHarness() {
        store.reset();
        fs::remove(db_path);
        // sqlite WAL/SHM siblings
        fs::remove(db_path.string() + "-wal");
        fs::remove(db_path.string() + "-shm");
        resp_store.reset();
        fs::remove(resp_db_path);
        fs::remove(resp_db_path.string() + "-wal");
        fs::remove(resp_db_path.string() + "-shm");
    }

    // Seed one ruleless DEX observation (the __observation__ projection the DEX
    // aggregations read — matches seed_signal in test_dex_routes.cpp). subject +
    // platform land in detail_json so dex_signal_subjects / _by_os pick them up.
    void seed_obs(const std::string& id, const std::string& agent, const std::string& obs_type,
                  const std::string& subject, const std::string& platform, const std::string& ts) {
        GuaranteedStateEventRow e;
        e.event_id = id;
        e.rule_id = "__observation__";
        e.agent_id = agent;
        e.event_type = obs_type;
        e.severity = "info";
        e.detail_json =
            "{\"subject\":\"" + subject + "\",\"platform\":\"" + platform + "\"}";
        e.timestamp = ts;
        REQUIRE(store->insert_event(e).has_value());
    }

    static std::string make_rule_body(const std::string& rule_id, const std::string& name,
                                      const std::string& yaml = "name: example\n") {
        nlohmann::json j;
        j["rule_id"] = rule_id;
        j["name"] = name;
        j["yaml_source"] = yaml;
        j["enabled"] = true;
        j["enforcement_mode"] = "enforce";
        j["severity"] = "high";
        j["os_target"] = "windows";
        j["scope_expr"] = "tag:env=prod";
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
    REQUIRE(h.sink
                .Post("/api/v1/guaranteed-state/rules",
                      RestGsHarness::make_rule_body("r-001", "dup-name"))
                ->status == 201);
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

TEST_CASE("REST gs.rules: list, get, update, delete round-trip", "[rest][guaranteed_state][crud]") {
    RestGsHarness h;
    REQUIRE(h.sink
                .Post("/api/v1/guaranteed-state/rules",
                      RestGsHarness::make_rule_body("r-001", "rule-a"))
                ->status == 201);
    REQUIRE(h.sink
                .Post("/api/v1/guaranteed-state/rules",
                      RestGsHarness::make_rule_body("r-002", "rule-b"))
                ->status == 201);

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
    CHECK(refetched->version == 2); // bumped by handler

    auto del = h.sink.Delete("/api/v1/guaranteed-state/rules/r-001");
    REQUIRE(del);
    CHECK(del->status == 200);
    CHECK_FALSE(h.store->get_rule("r-001").has_value());
}

TEST_CASE("REST gs.rules: get unknown id → 404", "[rest][guaranteed_state][not_found]") {
    RestGsHarness h;
    auto got = h.sink.Get("/api/v1/guaranteed-state/rules/nope");
    REQUIRE(got);
    CHECK(got->status == 404);
}

TEST_CASE("REST gs.rules: PUT with malformed body → 400 + denied audit",
          "[rest][guaranteed_state][crud]") {
    // UP-R1 regression guard. The PUT invalid-body 400 branch must emit a
    // denied audit, matching the sibling /push 400 branch. Asymmetric audit
    // coverage across sibling rejection paths was the original finding.
    RestGsHarness h;
    REQUIRE(h.sink
                .Post("/api/v1/guaranteed-state/rules",
                      RestGsHarness::make_rule_body("r-001", "rule-a"))
                ->status == 201);
    // Non-object body (top-level array) — body.is_object() is false.
    auto upd = h.sink.Put("/api/v1/guaranteed-state/rules/r-001", "[1,2,3]");
    REQUIRE(upd);
    CHECK(upd->status == 400);

    // Audit log: [0] create, [1] denied update.
    REQUIRE(h.audit_log.size() == 2);
    const auto& denied = h.audit_log[1];
    CHECK(denied.action == "guaranteed_state.rule.update");
    CHECK(denied.result == "denied");
    CHECK(denied.target_type == "GuaranteedState");
    CHECK(denied.target_id == "r-001");
    CHECK(denied.detail.find("invalid JSON") != std::string::npos);
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
    REQUIRE(h.sink
                .Post("/api/v1/guaranteed-state/rules",
                      RestGsHarness::make_rule_body("r-001", "rule-a"))
                ->status == 201);
    nlohmann::json push;
    push["scope"] = "tag:env=prod";
    push["full_sync"] = true;
    auto res = h.sink.Post("/api/v1/guaranteed-state/push", push.dump());
    REQUIRE(res);
    CHECK(res->status == 202);
    CHECK(res->body.find("\"queued\":true") != std::string::npos);
    // Real fan-out landed: the body reports the rule count and the number of
    // in-scope agents the push was dispatched to (direct + gateway transports).
    // The old "agent delivery is asynchronous / deferred" phrasing is gone —
    // see docs/user-manual/guaranteed-state.md.
    CHECK(res->body.find("\"rules\":1") != std::string::npos);
    CHECK(res->body.find("\"agents\":") != std::string::npos);

    REQUIRE(h.audit_log.size() == 2); // create + push
    const auto& push_audit = h.audit_log[1];
    CHECK(push_audit.action == "guaranteed_state.push");
    // Vocabulary matches sibling handlers: "success" (not the prior novel
    // "accepted"), target_id is empty because a push is fleet-level rather
    // than per-entity, and the scope expression lives in detail alongside the
    // agents=<count> fan-out result so SIEM correlation rules can filter on it.
    CHECK(push_audit.result == "success");
    CHECK(push_audit.target_id == "");
    CHECK(push_audit.target_type == "GuaranteedState");
    CHECK(push_audit.detail.find("rules=1") != std::string::npos);
    CHECK(push_audit.detail.find("full_sync=true") != std::string::npos);
    CHECK(push_audit.detail.find("scope=\"tag:env=prod\"") != std::string::npos);
    // Audit detail records the dispatched agent count, not the retired
    // fan_out_deferred_pr3 marker (push now actually delivers).
    CHECK(push_audit.detail.find("agents=") != std::string::npos);
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
    CHECK(d.find("agents=") != std::string::npos);
}

TEST_CASE("REST gs.events: filter + limit pagination", "[rest][guaranteed_state][events]") {
    RestGsHarness h;
    GuaranteedStateEventRow ev;
    ev.event_id = "e-1";
    ev.rule_id = "r-001";
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

TEST_CASE("REST gs.events: invalid limit → 400", "[rest][guaranteed_state][events][validation]") {
    RestGsHarness h;
    auto res = h.sink.Get("/api/v1/guaranteed-state/events?limit=-7");
    REQUIRE(res);
    CHECK(res->status == 400);
}

TEST_CASE("REST gs.status: returns store rule_count rollup", "[rest][guaranteed_state][status]") {
    RestGsHarness h;
    REQUIRE(h.sink
                .Post("/api/v1/guaranteed-state/rules",
                      RestGsHarness::make_rule_body("r-001", "rule-a"))
                ->status == 201);

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

TEST_CASE("REST gs.alerts: empty list placeholder", "[rest][guaranteed_state][alerts]") {
    RestGsHarness h;
    auto res = h.sink.Get("/api/v1/guaranteed-state/alerts");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    REQUIRE(j["data"].is_array());
    CHECK(j["data"].empty());
}

// ── C3b: structured authoring + resilience validation + schema discovery ─────

namespace {
// A full structured Guard body (spark + assertion + remediation). `resilience`
// is the remediation.params object carrying the C3b resilience policy.
std::string make_structured_body(const std::string& rule_id, const std::string& name,
                                 const std::string& remediation_type, nlohmann::json resilience) {
    nlohmann::json j;
    j["rule_id"] = rule_id;
    j["name"] = name;
    j["enforcement_mode"] = "enforce";
    j["severity"] = "high";
    j["spark"] = {{"type", "registry-change"}, {"params", nlohmann::json::object()}};
    j["assertion"] = {{"type", "registry-value-equals"},
                      {"params",
                       {{"hive", "HKLM"},
                        {"key", "SOFTWARE\\YuzuTest"},
                        {"value_name", "Flag"},
                        {"value_type", "REG_DWORD"},
                        {"expected", "1"}}}};
    j["remediation"] = {{"type", remediation_type}, {"params", std::move(resilience)}};
    return j.dump();
}
} // namespace

TEST_CASE("REST gs.rules: structured create validates + canonicalises resilience params",
          "[rest][guaranteed_state][create][resilience]") {
    RestGsHarness h;
    auto res = h.sink.Post(
        "/api/v1/guaranteed-state/rules",
        make_structured_body("r-res", "bounded-guard", "enforce",
                             {{"mode", "BOUNDED"}, {"max_attempts", 3}}));
    REQUIRE(res);
    CHECK(res->status == 201);

    auto stored = h.store->get_rule("r-res");
    REQUIRE(stored.has_value());
    REQUIRE_FALSE(stored->spec_json.empty());
    auto spec = nlohmann::json::parse(stored->spec_json);
    const auto& params = spec["remediation"]["params"];
    // Canonical-out: mode lowercased, numeric stored as a decimal string.
    CHECK(params["mode"].get<std::string>() == "bounded");
    CHECK(params["max_attempts"].get<std::string>() == "3");
}

TEST_CASE("REST gs.rules: invalid resilience params → 400 A4 envelope + denied audit",
          "[rest][guaranteed_state][create][resilience][validation]") {
    RestGsHarness h;
    auto res = h.sink.Post(
        "/api/v1/guaranteed-state/rules",
        make_structured_body("r-bad", "bad-guard", "enforce",
                             {{"mode", "bounded"}, {"max_attempts", 0}})); // 0 invalid
    REQUIRE(res);
    CHECK(res->status == 400);
    auto j = nlohmann::json::parse(res->body);
    // A4 envelope shape (contract decision 3).
    REQUIRE(j.contains("error"));
    CHECK(j["error"]["code"].get<int>() == 400);
    CHECK(j["error"].contains("correlation_id"));
    CHECK(j["error"].contains("remediation"));
    CHECK(j["meta"]["api_version"].get<std::string>() == "v1");
    // Rule not persisted; reject audited.
    CHECK_FALSE(h.store->get_rule("r-bad").has_value());
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "guaranteed_state.rule.create");
    CHECK(h.audit_log[0].result == "denied");
}

TEST_CASE("REST gs.rules: PUT re-authors structured spec (no silent drop)",
          "[rest][guaranteed_state][crud][resilience]") {
    RestGsHarness h;
    REQUIRE(h.sink
                .Post("/api/v1/guaranteed-state/rules",
                      make_structured_body("r-edit", "edit-guard", "enforce",
                                           {{"mode", "persist"}}))
                ->status == 201);

    // Tune the resilience policy via PUT — the pre-C3b PUT returned 200 but
    // silently dropped structured blocks. Now it must re-derive the spec.
    auto upd = h.sink.Put("/api/v1/guaranteed-state/rules/r-edit",
                          make_structured_body("r-edit", "edit-guard", "enforce",
                                               {{"mode", "bounded"}, {"max_attempts", 2}}));
    REQUIRE(upd);
    CHECK(upd->status == 200);

    auto stored = h.store->get_rule("r-edit");
    REQUIRE(stored.has_value());
    auto spec = nlohmann::json::parse(stored->spec_json);
    CHECK(spec["remediation"]["params"]["mode"].get<std::string>() == "bounded");
    CHECK(spec["remediation"]["params"]["max_attempts"].get<std::string>() == "2");
    CHECK(stored->version == 2);
}

TEST_CASE("REST gs.rules: PUT with an incomplete structured body → 400 (not silently dropped)",
          "[rest][guaranteed_state][crud][resilience]") {
    RestGsHarness h;
    REQUIRE(h.sink
                .Post("/api/v1/guaranteed-state/rules",
                      RestGsHarness::make_rule_body("r-meta", "meta-guard"))
                ->status == 201);
    // A remediation block with no spark/assertion is an incomplete structured
    // edit — rejected explicitly rather than 200-and-drop.
    nlohmann::json partial;
    partial["remediation"] = {{"type", "enforce"}, {"params", {{"mode", "bounded"}}}};
    auto upd = h.sink.Put("/api/v1/guaranteed-state/rules/r-meta", partial.dump());
    REQUIRE(upd);
    CHECK(upd->status == 400);
    auto j = nlohmann::json::parse(upd->body);
    CHECK(j["error"]["message"].get<std::string>().find("spark") != std::string::npos);
}

TEST_CASE("REST gs.rules: metadata-only PUT preserves the existing structured spec",
          "[rest][guaranteed_state][crud][resilience]") {
    RestGsHarness h;
    REQUIRE(h.sink
                .Post("/api/v1/guaranteed-state/rules",
                      make_structured_body("r-keep", "keep-guard", "enforce",
                                           {{"mode", "backoff"}, {"backoff_initial_ms", 500}}))
                ->status == 201);
    // Toggle enabled only — must not wipe spec_json.
    nlohmann::json meta;
    meta["enabled"] = false;
    auto upd = h.sink.Put("/api/v1/guaranteed-state/rules/r-keep", meta.dump());
    REQUIRE(upd);
    CHECK(upd->status == 200);
    auto stored = h.store->get_rule("r-keep");
    REQUIRE(stored.has_value());
    REQUIRE_FALSE(stored->spec_json.empty());
    auto spec = nlohmann::json::parse(stored->spec_json);
    CHECK(spec["remediation"]["params"]["mode"].get<std::string>() == "backoff");
}

TEST_CASE("REST gs.schemas: catalog + ETag revalidation", "[rest][guaranteed_state][schemas]") {
    RestGsHarness h;
    auto res = h.sink.Get("/api/v1/guaranteed-state/schemas");
    REQUIRE(res);
    CHECK(res->status == 200);
    const std::string etag = res->get_header_value("ETag");
    CHECK_FALSE(etag.empty());
    auto j = nlohmann::json::parse(res->body);
    REQUIRE(j.contains("schemas"));
    CHECK(j["schemas"].is_array());

    // Conditional GET with the matching ETag → 304 Not Modified.
    auto cached = h.sink.Get("/api/v1/guaranteed-state/schemas",
                             {{"If-None-Match", etag}});
    REQUIRE(cached);
    CHECK(cached->status == 304);
}

// ── DEX read-model aggregation surface (/api/v1/dex/*) — ar-S1 agentic parity ─
//
// The audit BOUNDARY is the load-bearing contract: the catalogue rollup and the
// per-OS scope are fleet aggregates and must NOT audit; the per-signal drill-down
// returns a most-affected DEVICES list (agent_ids — behavioral) and MUST emit the
// same dex.signal.view verb the dashboard fragment does. Both halves are asserted.

TEST_CASE("REST dex.signals: catalogue rollup returns seeded signals, NOT audited",
          "[rest][dex][signals]") {
    RestGsHarness h;
    h.seed_obs("o1", "WS-1", "process.crashed", "chrome.exe", "windows", "2026-06-10T10:00:00Z");
    h.seed_obs("o2", "WS-2", "process.crashed", "chrome.exe", "windows", "2026-06-10T11:00:00Z");
    h.seed_obs("o3", "WS-1", "os.boot", "boot", "windows", "2026-06-10T08:00:00Z");

    auto res = h.sink.Get("/api/v1/dex/signals?window=all");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    REQUIRE(j["data"].is_array());

    int64_t crashed_count = -1, crashed_devices = -1;
    bool saw_boot = false;
    for (const auto& row : j["data"]) {
        if (row["obs_type"].get<std::string>() == "process.crashed") {
            crashed_count = row["count"].get<int64_t>();
            crashed_devices = row["distinct_devices"].get<int64_t>();
        }
        if (row["obs_type"].get<std::string>() == "os.boot")
            saw_boot = true;
    }
    CHECK(crashed_count == 2);
    CHECK(crashed_devices == 2);
    CHECK(saw_boot);
    // Fleet aggregate — no individual-identifying access, so no audit.
    CHECK(h.audit_log.empty());
}

TEST_CASE("REST dex/devices/{id}: per-device read model — score + THIS device's signals, audited",
          "[rest][dex][device]") {
    RestGsHarness h;
    h.seed_obs("o1", "WS-1", "process.crashed", "chrome.exe", "windows", "2026-06-10T10:00:00Z");
    h.seed_obs("o2", "WS-1", "process.crashed", "chrome.exe", "windows", "2026-06-10T11:00:00Z");
    h.seed_obs("o3", "WS-2", "os.boot", "boot", "windows", "2026-06-10T08:00:00Z"); // other device

    auto res = h.sink.Get("/api/v1/dex/devices/WS-1?window=all");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["data"]["agent_id"].get<std::string>() == "WS-1");
    REQUIRE(j["data"]["signals"].is_array());
    bool saw_crashed = false, saw_other = false;
    int64_t crashed_count = -1;
    for (const auto& s : j["data"]["signals"]) {
        if (s["obs_type"].get<std::string>() == "process.crashed") {
            saw_crashed = true;
            crashed_count = s["count"].get<int64_t>();
        }
        if (s["obs_type"].get<std::string>() == "os.boot")
            saw_other = true; // belongs to WS-2
    }
    CHECK(saw_crashed);
    CHECK(crashed_count == 2);
    CHECK_FALSE(saw_other); // WS-2's signal must not leak into WS-1's per-device summary
    // Per-device behavioral read → audited dex.device.view (parity with the lens).
    bool audited = false;
    for (const auto& a : h.audit_log)
        if (a.action == "dex.device.view" && a.target_id == "WS-1")
            audited = true;
    CHECK(audited);
}

TEST_CASE("OpenAPI lists /dex/devices/{id} and the whole spec still parses",
          "[rest][dex][device][a2]") {
    RestGsHarness h;
    auto res = h.sink.Get("/api/v1/openapi.json");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    // A2 discovery: the per-device DEX endpoint is enumerable from the live server.
    REQUIRE(res->body.find(R"("/dex/devices/{id}":)") != std::string::npos);
    // And the embedded spec remains valid JSON after the insertion.
    REQUIRE_NOTHROW(nlohmann::json::parse(res->body));
}

TEST_CASE("REST dex/devices/{id}: out-of-scope device → 403, no data leak, no audit",
          "[rest][dex][device][scope]") {
    RestGsHarness h;
    h.seed_obs("o1", "WS-9", "process.crashed", "chrome.exe", "windows", "2026-06-10T10:00:00Z");
    h.deny_scoped_agent = "WS-9"; // the per-device scope gate denies this agent
    auto res = h.sink.Get("/api/v1/dex/devices/WS-9?window=all");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(h.audit_log.empty()); // the scope gate runs BEFORE any audit emission
}

TEST_CASE("REST dex/devices/{id}/live uptime: dispatches + returns parsed JSON, audited",
          "[rest][dex][device][live]") {
    RestGsHarness h;
    // Pre-insert the agent's response for the deterministic command_id the stub mints.
    StoredResponse r;
    r.instruction_id = "os_info-live";
    r.agent_id = "WS-1";
    r.status = 0; // RUNNING row carries the output
    r.output = "uptime_seconds|181740\nuptime_display|2d 2h 29m";
    h.resp_store->store(r);

    auto res = h.sink.Post("/api/v1/dex/devices/WS-1/live?kind=uptime", "");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(h.last_live_plugin == "os_info");
    CHECK(h.last_live_action == "uptime");
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["data"]["kind"].get<std::string>() == "uptime");
    CHECK(j["data"]["uptime_display"].get<std::string>() == "2d 2h 29m");
    CHECK(j["data"]["uptime_seconds"].get<int64_t>() == 181740);
    // UP-8: the dispatch audit result must be "dispatched" (not "success") — the
    // outcome isn't known at dispatch time. Lock it so a revert to "success" fails.
    bool audited = false;
    for (const auto& a : h.audit_log)
        if (a.action == "device.live.uptime" && a.result == "dispatched" && a.target_id == "WS-1")
            audited = true;
    CHECK(audited);
}

TEST_CASE("REST dex/devices/{id}/live processes: parses proc|pid|name|sha256|path rows",
          "[rest][dex][device][live]") {
    RestGsHarness h;
    StoredResponse r;
    r.instruction_id = "processes-live";
    r.agent_id = "WS-1";
    r.status = 0;
    r.output =
        "proc|0|[System Process]||\n"
        "proc|123|sh|deadbeefcafe0000111122223333444455556666777788889999aaaabbbbccccdddd|/bin/sh";
    h.resp_store->store(r);

    auto res = h.sink.Post("/api/v1/dex/devices/WS-1/live?kind=processes", "");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(h.last_live_action == "list_hashed"); // the hashed variant
    auto j = nlohmann::json::parse(res->body);
    REQUIRE(j["data"]["processes"].is_array());
    REQUIRE(j["data"]["processes"].size() == 2);
    const auto& sh = j["data"]["processes"][1];
    CHECK(sh["pid"].get<int64_t>() == 123);
    CHECK(sh["name"].get<std::string>() == "sh");
    CHECK(sh["sha256"].get<std::string>().rfind("deadbeefcafe0000", 0) == 0);
    CHECK(sh["path"].get<std::string>() == "/bin/sh");
    bool audited = false; // UP-8: result is "dispatched", not "success"
    for (const auto& a : h.audit_log)
        if (a.action == "device.live.processes" && a.result == "dispatched")
            audited = true;
    CHECK(audited);
}

TEST_CASE("REST dex/devices/{id}/live: offline device (sent=0) → 503, audited no_agents",
          "[rest][dex][device][live]") {
    RestGsHarness h;
    h.live_sent = 0; // dispatch reaches no connected agent
    auto res = h.sink.Post("/api/v1/dex/devices/WS-1/live?kind=uptime", "");
    REQUIRE(res);
    CHECK(res->status == 503);
    bool audited = false;
    for (const auto& a : h.audit_log)
        if (a.action == "device.live.uptime" && a.result == "no_agents")
            audited = true;
    CHECK(audited);
}

TEST_CASE("REST dex/devices/{id}/live: unknown kind → 400, no dispatch",
          "[rest][dex][device][live]") {
    RestGsHarness h;
    auto res = h.sink.Post("/api/v1/dex/devices/WS-1/live?kind=bogus", "");
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(h.last_live_plugin.empty()); // never dispatched
}

TEST_CASE("REST dex/devices/{id}/live: out-of-scope device → 403, no dispatch",
          "[rest][dex][device][live][scope]") {
    RestGsHarness h;
    h.deny_scoped_agent = "WS-9";
    auto res = h.sink.Post("/api/v1/dex/devices/WS-9/live?kind=uptime", "");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(h.last_live_plugin.empty()); // gate denied before any dispatch
}

// ── Governance hardening-round coverage (R1) ──────────────────────────────

namespace {
// StoredResponse::status mirrors CommandResponse::Status; name the values the /live
// poll branches on so a proto enum shuffle breaks these tests loudly (quality S4).
constexpr int kStatusPending = 0;
constexpr int kStatusSuccess = 1;
constexpr int kStatusFailure = 2;
constexpr int kStatusFatal = 3;

// Exception-safe save/restore for a process-global test-seam atomic: restores in the
// dtor so a throwing REQUIRE between mutate and restore can't poison later tests
// (quality S1 / cpp-safety SHOULD).
struct AtomicSave {
    std::atomic<int>& ref;
    int saved;
    explicit AtomicSave(std::atomic<int>& a) : ref(a), saved(a.load()) {}
    ~AtomicSave() { ref.store(saved); }
    AtomicSave(const AtomicSave&) = delete;
    AtomicSave& operator=(const AtomicSave&) = delete;
};
} // namespace


TEST_CASE("REST dex/devices/{id}: off-enum window → 400, no audit, no data",
          "[rest][dex][device]") {
    RestGsHarness h;
    h.seed_obs("o1", "WS-1", "process.crashed", "chrome.exe", "windows", "2026-06-10T10:00:00Z");
    auto res = h.sink.Get("/api/v1/dex/devices/WS-1?window=banana");
    REQUIRE(res);
    CHECK(res->status == 400);          // not a silent default to 7d
    CHECK(h.audit_log.empty());         // validated before any audit emission
}

TEST_CASE("REST dex/devices/{id}/live: terminal failure WINS over a partial-output row → 502",
          "[rest][dex][device][live]") {
    RestGsHarness h;
    // A single frame that carries BOTH partial output AND a failure status — the
    // pre-fix poll returned 200 with the partial data (UP-4). Failure must 502.
    StoredResponse r;
    r.instruction_id = "os_info-live";
    r.agent_id = "WS-1";
    r.status = kStatusFailure;
    r.output = "uptime_display|2d 2h"; // partial output present alongside the failure
    r.error_detail = "agent aborted";
    h.resp_store->store(r);
    auto res = h.sink.Post("/api/v1/dex/devices/WS-1/live?kind=uptime", "");
    REQUIRE(res);
    CHECK(res->status == 502);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["error"]["code"].get<int>() == 502);
    CHECK(j["error"]["message"].get<std::string>().find("device query failed") != std::string::npos);
}

TEST_CASE("REST dex/devices/{id}/live: device error| output → 502",
          "[rest][dex][device][live]") {
    RestGsHarness h;
    StoredResponse r;
    r.instruction_id = "os_info-live";
    r.agent_id = "WS-1";
    r.status = kStatusPending;
    r.output = "error|disk subsystem offline";
    h.resp_store->store(r);
    auto res = h.sink.Post("/api/v1/dex/devices/WS-1/live?kind=uptime", "");
    REQUIRE(res);
    CHECK(res->status == 502);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["error"]["code"].get<int>() == 502);
    CHECK(j["error"]["message"].get<std::string>().find("device reported an error") !=
          std::string::npos);
}

TEST_CASE("REST dex/devices/{id}/live: terminal failure, no output → 502",
          "[rest][dex][device][live]") {
    RestGsHarness h;
    StoredResponse r;
    r.instruction_id = "os_info-live";
    r.agent_id = "WS-1";
    r.status = kStatusFatal; // FAILURE, no output
    r.error_detail = "plugin crashed";
    h.resp_store->store(r);
    auto res = h.sink.Post("/api/v1/dex/devices/WS-1/live?kind=uptime", "");
    REQUIRE(res);
    CHECK(res->status == 502);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["error"]["code"].get<int>() == 502);
}

TEST_CASE("REST dex/devices/{id}/live: success terminal, no output → 200 empty (not a 504)",
          "[rest][dex][device][live]") {
    RestGsHarness h;
    StoredResponse r;
    r.instruction_id = "processes-live";
    r.agent_id = "WS-1";
    r.status = kStatusSuccess; // no output rows
    h.resp_store->store(r);
    auto res = h.sink.Post("/api/v1/dex/devices/WS-1/live?kind=processes", "");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["data"]["kind"].get<std::string>() == "processes");
    REQUIRE(j["data"]["processes"].is_array());
    CHECK(j["data"]["processes"].empty());
}

TEST_CASE("REST dex/devices/{id}/live: over the concurrency cap → 429, no dispatch",
          "[rest][dex][device][live]") {
    RestGsHarness h;
    AtomicSave cap_save{yuzu::server::detail::live_max_inflight()};
    yuzu::server::detail::live_max_inflight().store(0); // any call is over budget
    auto res = h.sink.Post("/api/v1/dex/devices/WS-1/live?kind=uptime", "");
    REQUIRE(res);
    CHECK(res->status == 429);
    CHECK(h.last_live_plugin.empty()); // 429'd before dispatch — no command sent
}

TEST_CASE("REST dex/devices/{id}/live: agent never responds → 504",
          "[rest][dex][device][live]") {
    RestGsHarness h;
    AtomicSave mp_save{yuzu::server::detail::live_poll_max_polls()};
    AtomicSave iv_save{yuzu::server::detail::live_poll_interval_ms()};
    yuzu::server::detail::live_poll_max_polls().store(2);
    yuzu::server::detail::live_poll_interval_ms().store(1); // ~2ms not ~20s; no row inserted
    auto res = h.sink.Post("/api/v1/dex/devices/WS-1/live?kind=uptime", "");
    REQUIRE(res);
    CHECK(res->status == 504);
}

TEST_CASE("REST dex/devices/{id}/live: GET is not routed (POST-only side effect)",
          "[rest][dex][device][live]") {
    RestGsHarness h;
    // The endpoint is POST-only (it dispatches a command). A GET must NOT reach the
    // handler — the TestRouteSink returns nullptr when no route matches the method,
    // mirroring httplib's 404. Locks the GET->POST migration (architect B1).
    auto res = h.sink.Get("/api/v1/dex/devices/WS-1/live?kind=uptime");
    CHECK(res == nullptr);
    CHECK(h.last_live_plugin.empty()); // never dispatched
}

TEST_CASE("REST dex.scope: per-OS coverage returned, NOT audited", "[rest][dex][scope]") {
    RestGsHarness h;
    h.seed_obs("o1", "WS-1", "process.crashed", "chrome.exe", "windows", "2026-06-10T10:00:00Z");
    h.seed_obs("o2", "MB-1", "process.crashed", "Safari", "macos", "2026-06-10T11:00:00Z");
    h.seed_obs("o3", "MB-1", "storage.low", "disk", "macos", "2026-06-10T12:00:00Z");

    auto res = h.sink.Get("/api/v1/dex/scope?window=all");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    REQUIRE(j["data"].is_array());

    int64_t macos_types = -1;
    for (const auto& row : j["data"]) {
        if (row["platform"].get<std::string>() == "macos")
            macos_types = row["distinct_types"].get<int64_t>();
    }
    CHECK(macos_types == 2); // process.crashed + storage.low
    CHECK(h.audit_log.empty());
}

TEST_CASE("REST dex.signals/{type}: drill-down fires dex.signal.view audit + returns the shape",
          "[rest][dex][signals][audit]") {
    RestGsHarness h;
    h.seed_obs("o1", "WS-1", "process.crashed", "chrome.exe", "windows", "2026-06-10T10:00:00Z");
    h.seed_obs("o2", "WS-2", "process.crashed", "chrome.exe", "windows", "2026-06-10T11:00:00Z");

    auto res = h.sink.Get("/api/v1/dex/signals/process.crashed?window=all");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    REQUIRE(j["data"]["obs_type"].get<std::string>() == "process.crashed");
    REQUIRE(j["data"]["subjects"].is_array());
    REQUIRE(j["data"]["by_os"].is_array());
    REQUIRE(j["data"]["devices"].is_array());
    REQUIRE(j["data"]["by_day"].is_array());
    CHECK(j["data"]["devices"].size() == 2); // WS-1 + WS-2
    CHECK(j["data"]["subjects"][0]["subject"].get<std::string>() == "chrome.exe");

    // Behavioral-PII access → exactly one dex.signal.view, same target shape as
    // the /fragments/dex/catalogue/signal route (governance B4).
    REQUIRE(h.audit_log.size() == 1);
    const auto& a = h.audit_log[0];
    CHECK(a.action == "dex.signal.view");
    CHECK(a.result == "success");
    CHECK(a.target_type == "ObsType");
    CHECK(a.target_id == "process.crashed");
}

TEST_CASE("REST dex.signals/{type}: well-formed but absent type → 200 empty arrays (still audited)",
          "[rest][dex][signals]") {
    RestGsHarness h; // empty store
    auto res = h.sink.Get("/api/v1/dex/signals/process.crashed?window=all");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["data"]["subjects"].empty());
    CHECK(j["data"]["devices"].empty());
    // The operator requested an individual-identifying view; audit the access
    // regardless of whether the read-model happened to hold matching rows.
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "dex.signal.view");
}

TEST_CASE("REST dex.signals/{type}: malformed obs_type → 400, no audit", "[rest][dex][signals]") {
    RestGsHarness h;
    auto res = h.sink.Get("/api/v1/dex/signals/foo!bar?window=all");
    REQUIRE(res);
    CHECK(res->status == 400);
    // Validation precedes audit — a rejected malformed request leaves no trace
    // of a behavioral-view access that never happened.
    CHECK(h.audit_log.empty());
}

TEST_CASE("REST dex.signals/{type}: invalid limit → 400", "[rest][dex][signals]") {
    RestGsHarness h;
    auto res = h.sink.Get("/api/v1/dex/signals/process.crashed?limit=-3");
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(h.audit_log.empty());
}

TEST_CASE("REST dex: permission gate runs before audit on the per-signal view",
          "[rest][dex][rbac]") {
    RestGsHarness h;
    h.grant_perms = false; // perm_fn denies → 403
    auto res = h.sink.Get("/api/v1/dex/signals/process.crashed?window=all");
    REQUIRE(res);
    CHECK(res->status == 403);
    // No audit emission on a denied request — the permission check is the first
    // statement in the handler, before the dex.signal.view audit.
    CHECK(h.audit_log.empty());
}
