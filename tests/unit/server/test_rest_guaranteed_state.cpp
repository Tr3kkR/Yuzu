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

#include "baseline_store.hpp"
#include "guaranteed_state_store.hpp"
#include "response_store.hpp"
#include "rest_api_v1.hpp"
#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include "../test_helpers.hpp"

#include <filesystem>
#include <stdexcept>
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

    // BaselineStore for the baseline-anchored per-device status route.
    fs::path bl_db_path;
    std::unique_ptr<BaselineStore> baseline_store;

    std::string session_user{"alice"};
    auth::Role session_role{auth::Role::admin};

    // When false, perm_fn denies (403) — lets a test prove the permission gate
    // runs BEFORE any audit emission on the DEX read surface (default grants,
    // preserving every other test's behaviour).
    bool grant_perms{true};

    // When non-empty, the scoped per-device gate denies (403) this agent_id — lets a
    // test prove the per-device scope is enforced on /api/v1/dex/devices/{id}.
    std::string deny_scoped_agent;

    // When non-empty, the scoped gate denies (403) only this operation (e.g.
    // "Execute") — lets a test isolate the Execute floor on /live from the Read
    // floor (#1549 review LOW: the gaps didn't isolate Execute-denied-but-Read-OK).
    std::string deny_scoped_op;

    // When false, audit_fn returns false (simulating a dropped evidence row) so a
    // test can prove audit-on-open fails CLOSED on the REST PII / dispatch surface
    // (#1549 review HIGH). Default true preserves every other test's behaviour.
    bool audit_succeeds{true};

    // When true, audit_fn THROWS (a bad_alloc-class failure) so a test can prove
    // the shared #1647 helper catches it (the throw arm was previously silent) and
    // still fails closed with Sec-Audit-Failed rather than letting it escape.
    bool audit_throws{false};

    // When false, the live deps (response_store + command_dispatch_fn) are left
    // unwired so a test can prove /live → 503 when the substrate is unavailable.
    bool wire_live_deps{true};

    // Per-device scoped-permission simulation for the baseline-anchored route.
    // scoped_deny_agent (when non-empty) is treated as OUT OF SCOPE → 403; every
    // other agent is in scope. last_scoped_agent_id records the agent_id the route
    // handed the scoped check (proves the route scopes by the right device).
    std::string scoped_deny_agent;
    std::string last_scoped_agent_id;

    std::vector<AuditRecord> audit_log;

    yuzu::MetricsRegistry metrics;
    RestApiV1 api;

    // live_deps=false leaves the live substrate (response_store + command_dispatch_fn)
    // unwired so a test can prove /live → 503. wire_scoped_perm=false registers the
    // baseline-device route with an EMPTY ScopedPermFn, exercising its fail-closed-503
    // path. Both default true so every existing test is unchanged.
    explicit RestGsHarness(bool live_deps = true, bool wire_scoped_perm = true)
        : db_path(unique_temp_path("rest-gs")), bl_db_path(unique_temp_path("rest-gs-bl")),
          wire_live_deps(live_deps) {
        fs::remove(db_path);
        fs::remove(bl_db_path);
        // retention=0 keeps the reaper out of the way for ingest tests.
        store = std::make_unique<GuaranteedStateStore>(db_path, /*retention_days=*/0,
                                                       /*cleanup_interval_min=*/60);
        REQUIRE(store->is_open());
        baseline_store = std::make_unique<BaselineStore>(bl_db_path);
        REQUIRE(baseline_store->is_open());

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
        // When wire_live_deps is off, leave the dispatch closure empty so the /live
        // handler hits its "substrate unavailable → 503" branch.
        RestApiV1::CommandDispatchFn dispatch_arg =
            wire_live_deps ? RestApiV1::CommandDispatchFn{command_dispatch_fn}
                           : RestApiV1::CommandDispatchFn{};

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

        // Scoped per-device permission (require_scoped_permission stand-in): records
        // the agent_id, then denies (403) when grant_perms is off OR the agent matches
        // either deny knob (deny_scoped_agent / dev's scoped_deny_agent) OR the
        // operation matches deny_scoped_op (Execute-vs-Read isolation, #1549). Mirrors
        // require_scoped_permission's contract (global passes; otherwise in-scope);
        // last_scoped_agent_id proves the route scopes by the right device.
        auto scoped_perm_fn = [this](const httplib::Request&, httplib::Response& res,
                                     const std::string&, const std::string& operation,
                                     const std::string& agent_id) -> bool {
            last_scoped_agent_id = agent_id;
            if (!grant_perms || (!deny_scoped_agent.empty() && agent_id == deny_scoped_agent) ||
                (!scoped_deny_agent.empty() && agent_id == scoped_deny_agent) ||
                (!deny_scoped_op.empty() && operation == deny_scoped_op)) {
                res.status = 403;
                return false;
            }
            return true;
        };

        // PR W1.1 UP-H1: AuditFn typedef → std::function<bool(...)>. Returns
        // audit_succeeds so a test can simulate a dropped evidence row (#1549).
        auto audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string& target_type,
                               const std::string& target_id, const std::string& detail) -> bool {
            audit_log.push_back({action, result, target_type, target_id, detail});
            if (audit_throws)
                throw std::runtime_error("audit DB write blew up");
            return audit_succeeds;
        };

        api.register_routes(sink, auth_fn, perm_fn, audit_fn,
                            /*rbac_store=*/nullptr,
                            /*mgmt_store=*/nullptr,
                            /*token_store=*/nullptr,
                            /*quarantine_store=*/nullptr,
                            wire_live_deps ? resp_store.get() : nullptr,
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
                            /*metrics_registry=*/&metrics,
                            /*session_revoke_fn=*/{},
                            /*execution_event_bus=*/nullptr,
                            /*result_set_store=*/nullptr,
                            dispatch_arg,
                            /*step_up_fn=*/{},
                            /*guardian_push_fn=*/{},
                            /*dex_perf_fn=*/{},
                            /*net_perf_fn=*/{},
                            /*lockout_clear_fn=*/{},
                            baseline_store.get(),
                            wire_scoped_perm ? RestApiV1::ScopedPermFn{scoped_perm_fn}
                                             : RestApiV1::ScopedPermFn{});
    }

    ~RestGsHarness() {
        store.reset();
        baseline_store.reset();
        resp_store.reset();
        for (const auto& p : {db_path, bl_db_path, resp_db_path}) {
            fs::remove(p);
            // sqlite WAL/SHM siblings
            fs::remove(p.string() + "-wal");
            fs::remove(p.string() + "-shm");
        }
    }

    // Seed a Guard rule (name resolves in the route's list_rules() lookup).
    void seed_rule(const std::string& rule_id, const std::string& name) {
        GuaranteedStateRuleRow r;
        r.rule_id = rule_id;
        r.name = name;
        REQUIRE(store->create_rule(r).has_value());
    }

    // Seed one device's reported verdict for a Guard via the status feed
    // (insert_event → upsert_rule_status). event_type maps to state per
    // event_state_from_type: guard.compliant→compliant, drift.detected→drifted,
    // guard.unhealthy→errored. NOTE: the upsert keeps the row only when
    // excluded.updated_at >= the existing updated_at, so re-seeding the same
    // (agent, rule_id) with an EARLIER (or equal-then-different-state) timestamp
    // is silently dropped — use strictly increasing ts when overwriting a verdict.
    void seed_status(const std::string& event_id, const std::string& agent,
                     const std::string& rule_id, const std::string& event_type,
                     const std::string& ts) {
        GuaranteedStateEventRow e;
        e.event_id = event_id;
        e.rule_id = rule_id;
        e.agent_id = agent;
        e.event_type = event_type;
        e.severity = "info";
        e.timestamp = ts;
        REQUIRE(store->insert_event(e).has_value());
    }

    // Write a RAW guardian_agent_rule_status row (arbitrary `state`) directly via
    // a second SQLite connection — the public ingest path (insert_event →
    // event_state_from_type) can only ever write "compliant"/"drifted"/"errored",
    // so this is the only way to exercise the handler's defensive "unrecognized
    // state → pending" fallthrough (e.g. a corrupt DB or a future state token).
    void seed_raw_status(const std::string& agent, const std::string& rule_id,
                         const std::string& state, const std::string& ts) {
        sqlite3* raw = nullptr;
        REQUIRE(sqlite3_open(db_path.string().c_str(), &raw) == SQLITE_OK);
        sqlite3_stmt* st = nullptr;
        REQUIRE(sqlite3_prepare_v2(
                    raw,
                    "INSERT OR REPLACE INTO guardian_agent_rule_status"
                    "(agent_id, rule_id, state, updated_at) VALUES(?1,?2,?3,?4)",
                    -1, &st, nullptr) == SQLITE_OK);
        sqlite3_bind_text(st, 1, agent.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, rule_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3, state.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 4, ts.c_str(), -1, SQLITE_TRANSIENT);
        REQUIRE(sqlite3_step(st) == SQLITE_DONE);
        sqlite3_finalize(st);
        REQUIRE(sqlite3_close(raw) == SQLITE_OK);
    }

    // Create + deploy a Baseline with the given member Guards (snapshot = members,
    // lifecycle = deployed). Returns the generated baseline_id.
    std::string seed_deployed_baseline(const std::string& name,
                                       const std::vector<std::string>& member_rule_ids) {
        Baseline b;
        b.name = name;
        auto bid = baseline_store->create_baseline(b);
        REQUIRE(bid.has_value());
        REQUIRE(baseline_store->set_members(*bid, member_rule_ids).has_value());
        Baseline deployed = *baseline_store->get_baseline(*bid);
        deployed.deployed_snapshot = nlohmann::json(member_rule_ids).dump();
        deployed.lifecycle = kBaselineDeployed;
        REQUIRE(baseline_store->update_baseline(deployed).has_value());
        return *bid;
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
    // #1549 audit-on-open: the audit fires BEFORE dispatch with result "requested"
    // (the works-council event = operator asked for live data), not the old
    // post-dispatch "dispatched". Lock it so a revert to post-dispatch auditing
    // (which would dispatch before durable evidence) fails.
    bool audited = false;
    for (const auto& a : h.audit_log)
        if (a.action == "device.live.uptime" && a.result == "requested" && a.target_id == "WS-1")
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
    bool audited = false; // #1549: pre-dispatch audit, result "requested"
    for (const auto& a : h.audit_log)
        if (a.action == "device.live.processes" && a.result == "requested")
            audited = true;
    CHECK(audited);
}

TEST_CASE("REST dex/devices/{id}/live: offline device (sent=0) → 503, audited requested",
          "[rest][dex][device][live]") {
    RestGsHarness h;
    h.live_sent = 0; // dispatch reaches no connected agent
    auto res = h.sink.Post("/api/v1/dex/devices/WS-1/live?kind=uptime", "");
    REQUIRE(res);
    CHECK(res->status == 503);
    // #1549: the audit fires "requested" BEFORE dispatch — the works-council event
    // is the operator's request, recorded regardless of whether an agent was reached
    // (the 503 carries the no-agent outcome). The dispatch still happened (audit
    // persisted), so the evidence row exists.
    bool audited = false;
    for (const auto& a : h.audit_log)
        if (a.action == "device.live.uptime" && a.result == "requested")
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

TEST_CASE("REST dex/devices/{id}/live: emits outcome counter + in-flight gauge",
          "[rest][dex][device][live][metrics]") {
    RestGsHarness h;
    StoredResponse r;
    r.instruction_id = "os_info-live";
    r.agent_id = "WS-1";
    r.status = kStatusSuccess;
    r.output = "uptime_display|1d";
    h.resp_store->store(r);

    auto ok = h.sink.Post("/api/v1/dex/devices/WS-1/live?kind=uptime", "");
    REQUIRE(ok);
    CHECK(ok->status == 200);
    // One uptime/200 counted; the in-flight gauge returns to 0 after the call.
    CHECK(h.metrics
              .counter("yuzu_server_live_requests_total", {{"kind", "uptime"}, {"outcome", "200"}})
              .value() == 1.0);
    CHECK(h.metrics.gauge("yuzu_server_live_inflight").value() == 0.0);

    // A 429 (cap exhausted) is counted under its own outcome label, no dispatch.
    AtomicSave cap_save{yuzu::server::detail::live_max_inflight()};
    yuzu::server::detail::live_max_inflight().store(0);
    auto rej = h.sink.Post("/api/v1/dex/devices/WS-1/live?kind=uptime", "");
    REQUIRE(rej);
    CHECK(rej->status == 429);
    CHECK(h.metrics
              .counter("yuzu_server_live_requests_total", {{"kind", "uptime"}, {"outcome", "429"}})
              .value() == 1.0);
}

// ── #1549 review hardening: audit-on-open fail-closed, A4 denials, headers ──

TEST_CASE("REST dex/devices/{id}: audit persistence failure → 503, no PII served, Sec-Audit-Failed",
          "[rest][dex][device][audit]") {
    RestGsHarness h;
    h.seed_obs("o1", "WS-1", "process.crashed", "chrome.exe", "windows", "2026-06-10T10:00:00Z");
    h.audit_succeeds = false; // the audit row cannot persist (DB locked/full/corrupt)
    auto res = h.sink.Get("/api/v1/dex/devices/WS-1?window=all");
    REQUIRE(res);
    // FAIL-CLOSED: behavioral PII must not be served when the evidence row is known
    // to have been lost (SOC 2 CC7.2 / works-council).
    CHECK(res->status == 503);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    CHECK_FALSE(res->get_header_value("X-Correlation-Id").empty()); // echoed on the error path too
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["error"]["code"].get<int>() == 503);
    // No device data leaked onto the body — assert the structural keys AND the actual
    // seeded PII content (an app-identity leak under a different key would harm the
    // works-council/SOC 2 evidence review).
    CHECK(res->body.find("\"signals\"") == std::string::npos);
    CHECK(res->body.find("\"score\"") == std::string::npos);
    CHECK(res->body.find("chrome.exe") == std::string::npos);
}

TEST_CASE("REST dex/devices/{id}: success echoes X-Correlation-Id header",
          "[rest][dex][device][a3]") {
    RestGsHarness h;
    h.seed_obs("o1", "WS-1", "process.crashed", "chrome.exe", "windows", "2026-06-10T10:00:00Z");
    auto res = h.sink.Get("/api/v1/dex/devices/WS-1?window=all");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK_FALSE(res->get_header_value("X-Correlation-Id").empty());
}

TEST_CASE("REST dex/devices/{id}/live: audit persistence failure → 503, NO dispatch, "
          "Sec-Audit-Failed",
          "[rest][dex][device][live][audit]") {
    RestGsHarness h;
    h.audit_succeeds = false; // evidence row cannot persist
    auto res = h.sink.Post("/api/v1/dex/devices/WS-1/live?kind=uptime", "");
    REQUIRE(res);
    // The probe must NOT be dispatched without durable evidence.
    CHECK(res->status == 503);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    CHECK_FALSE(res->get_header_value("X-Correlation-Id").empty()); // echoed on the error path too
    CHECK(h.last_live_plugin.empty()); // audit failed BEFORE dispatch → no command sent
}

TEST_CASE("REST dex/devices/{id}/live: success echoes X-Correlation-Id header",
          "[rest][dex][device][live][a3]") {
    RestGsHarness h;
    StoredResponse r;
    r.instruction_id = "os_info-live";
    r.agent_id = "WS-1";
    r.status = kStatusSuccess;
    r.output = "uptime_display|1d";
    h.resp_store->store(r);
    auto res = h.sink.Post("/api/v1/dex/devices/WS-1/live?kind=uptime", "");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK_FALSE(res->get_header_value("X-Correlation-Id").empty());
}

TEST_CASE("REST dex/devices/{id}/live: Execute denied but Read allowed → 403, no dispatch",
          "[rest][dex][device][live][scope]") {
    RestGsHarness h;
    h.deny_scoped_op = "Execute"; // Read floor passes; Execute floor denies
    auto res = h.sink.Post("/api/v1/dex/devices/WS-1/live?kind=uptime", "");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(h.last_live_plugin.empty()); // the Execute gate denied before any dispatch
}

TEST_CASE("REST dex/devices/{id}/live: live substrate unavailable → 503",
          "[rest][dex][device][live]") {
    RestGsHarness h{/*live_deps=*/false}; // no response_store + no command_dispatch_fn
    auto res = h.sink.Post("/api/v1/dex/devices/WS-1/live?kind=uptime", "");
    REQUIRE(res);
    CHECK(res->status == 503);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["error"]["code"].get<int>() == 503);
}

TEST_CASE("REST dex/devices/{id}/live: device output over the cap → 502",
          "[rest][dex][device][live]") {
    RestGsHarness h;
    StoredResponse r;
    r.instruction_id = "processes-live";
    r.agent_id = "WS-1";
    r.status = kStatusSuccess;
    r.output = std::string(5 * 1024 * 1024, 'x'); // > 4 MiB cap
    h.resp_store->store(r);
    auto res = h.sink.Post("/api/v1/dex/devices/WS-1/live?kind=processes", "");
    REQUIRE(res);
    CHECK(res->status == 502);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["error"]["message"].get<std::string>().find("too large") != std::string::npos);
}

TEST_CASE("REST dex/devices/{id}/live: a different agent's response row is never rendered → 504",
          "[rest][dex][device][live][scope]") {
    RestGsHarness h;
    AtomicSave mp_save{yuzu::server::detail::live_poll_max_polls()};
    AtomicSave iv_save{yuzu::server::detail::live_poll_interval_ms()};
    yuzu::server::detail::live_poll_max_polls().store(2);
    yuzu::server::detail::live_poll_interval_ms().store(1);
    // A row under the SAME command_id but for a DIFFERENT agent must be ignored —
    // never returned as WS-1's data. With no WS-1 row, the poll times out (504).
    StoredResponse other;
    other.instruction_id = "os_info-live";
    other.agent_id = "OTHER";
    other.status = kStatusSuccess;
    other.output = "uptime_display|99d";
    h.resp_store->store(other);
    auto res = h.sink.Post("/api/v1/dex/devices/WS-1/live?kind=uptime", "");
    REQUIRE(res);
    CHECK(res->status == 504);
    CHECK(res->body.find("99d") == std::string::npos); // OTHER's data never leaked
}

TEST_CASE("REST dex/devices/{id}/live uptime: success terminal, no output → 200 empty",
          "[rest][dex][device][live]") {
    RestGsHarness h;
    StoredResponse r;
    r.instruction_id = "os_info-live";
    r.agent_id = "WS-1";
    r.status = kStatusSuccess; // no output rows
    h.resp_store->store(r);
    auto res = h.sink.Post("/api/v1/dex/devices/WS-1/live?kind=uptime", "");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["data"]["kind"].get<std::string>() == "uptime");
}

TEST_CASE("REST dex/devices/{id}: scoped denial carries the A4 envelope (correlation_id + "
          "permission)",
          "[rest][dex][device][scope][a4]") {
    // The scoped gate is wired in production to require_scoped_permission, whose
    // denial now emits the A4 envelope. Here the harness's scoped_perm_fn stands in
    // for the gate and writes only a 403 status — so this test asserts the handler
    // surfaces the gate's status untouched (no data leak); the A4 *body* shape is
    // pinned at the helper level in test_auth_routes.cpp.
    // KNOWN GAP (governance #1549 QE-SHOULD): this test does NOT prove the
    // /api/v1/dex/devices/{id} handler is wired to the A4-emitting
    // require_scoped_permission — that binding is accepted as untested at this unit
    // boundary (the harness stub stands in for the gate).
    RestGsHarness h;
    h.deny_scoped_agent = "WS-9";
    auto res = h.sink.Get("/api/v1/dex/devices/WS-9?window=all");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(h.audit_log.empty());
}

// #1549 governance consistency-B1: the per-device PII REST siblings must fail closed
// on a dropped audit row, same as GET /dex/devices/{id}.

TEST_CASE("REST guaranteed-state/events: agent-scoped audit failure → 503, no PII, Sec-Audit-Failed",
          "[rest][dex][events][audit]") {
    RestGsHarness h;
    h.seed_obs("o1", "WS-1", "process.crashed", "chrome.exe", "windows", "2026-06-10T10:00:00Z");
    h.audit_succeeds = false;
    // agent_id filter = individual-identifying behavioral PII → audited + fail-closed.
    auto res = h.sink.Get("/api/v1/guaranteed-state/events?agent_id=WS-1");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    CHECK(res->body.find("chrome.exe") == std::string::npos); // no PII leaked
    // A4 envelope on the fail-closed body (#1651 review K2): correlation_id + retry_after_ms,
    // parity with the /dex/devices/{id} + baseline siblings.
    CHECK_FALSE(res->get_header_value("X-Correlation-Id").empty());
    auto j = nlohmann::json::parse(res->body);
    CHECK_FALSE(j["error"]["correlation_id"].get<std::string>().empty());
    CHECK(j["error"]["retry_after_ms"].get<int>() == 5000);
}

// #1651 review K5: the converted route's catch arm (a throwing audit_fn) was only
// covered by the helper unit test, not end-to-end here. Pin it at the route level.
TEST_CASE("REST guaranteed-state/events: agent-scoped throwing audit → 503, A4, Sec-Audit-Failed",
          "[rest][dex][events][audit]") {
    RestGsHarness h;
    h.seed_obs("o1", "WS-1", "process.crashed", "chrome.exe", "windows", "2026-06-10T10:00:00Z");
    h.audit_throws = true; // bad_alloc-class throw — caught by the shared helper
    auto res = h.sink.Get("/api/v1/guaranteed-state/events?agent_id=WS-1");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    CHECK(res->body.find("chrome.exe") == std::string::npos);
}

TEST_CASE("REST guaranteed-state/events: NO agent_id filter is a bulk query — not gated by audit",
          "[rest][dex][events][audit]") {
    RestGsHarness h;
    h.seed_obs("o1", "WS-1", "process.crashed", "chrome.exe", "windows", "2026-06-10T10:00:00Z");
    h.audit_succeeds = false; // would fail-close IF it were audited
    // No agent_id → bulk operational query, deliberately not individual-audited → serves.
    auto res = h.sink.Get("/api/v1/guaranteed-state/events");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->get_header_value("Sec-Audit-Failed").empty());
}

TEST_CASE("REST dex/signals/{obs_type}: audit failure → 503, no device list, Sec-Audit-Failed",
          "[rest][dex][signals][audit]") {
    RestGsHarness h;
    h.seed_obs("o1", "WS-1", "process.crashed", "chrome.exe", "windows", "2026-06-10T10:00:00Z");
    h.audit_succeeds = false;
    auto res = h.sink.Get("/api/v1/dex/signals/process.crashed?window=all");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    CHECK(res->body.find("WS-1") == std::string::npos); // the agent_id list must not leak
    // A4 envelope on the fail-closed body (#1651 review K2).
    CHECK_FALSE(res->get_header_value("X-Correlation-Id").empty());
    auto j = nlohmann::json::parse(res->body);
    CHECK_FALSE(j["error"]["correlation_id"].get<std::string>().empty());
    CHECK(j["error"]["retry_after_ms"].get<int>() == 5000);
}

// #1651 review K5: route-level catch-arm coverage for the converted dex.signal route.
TEST_CASE("REST dex/signals/{obs_type}: throwing audit → 503, A4, Sec-Audit-Failed",
          "[rest][dex][signals][audit]") {
    RestGsHarness h;
    h.seed_obs("o1", "WS-1", "process.crashed", "chrome.exe", "windows", "2026-06-10T10:00:00Z");
    h.audit_throws = true; // caught by the shared helper, must still fail closed
    auto res = h.sink.Get("/api/v1/dex/signals/process.crashed?window=all");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    CHECK(res->body.find("WS-1") == std::string::npos);
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

// ── Baseline-anchored per-device Guardian status ─────────────────────────────
// GET /api/v1/guaranteed-state/baselines/{baseline_id}/devices/{agent_id}

TEST_CASE("REST gs.baseline-device: deployed baseline returns per-guard verdicts + counts",
          "[rest][guaranteed_state][baseline]") {
    RestGsHarness h;
    h.seed_rule("r1", "Firewall on");
    h.seed_rule("r2", "RDP NLA");
    h.seed_rule("r3", "BitLocker");
    const auto bid = h.seed_deployed_baseline("ServiceNow Compliance", {"r1", "r2", "r3"});
    // WS-1: r1 compliant, r2 drifted, r3 unreported (→ pending).
    h.seed_status("e1", "WS-1", "r1", "guard.compliant", "2026-06-20T10:00:00Z");
    h.seed_status("e2", "WS-1", "r2", "drift.detected", "2026-06-20T11:00:00Z");

    auto res = h.sink.Get("/api/v1/guaranteed-state/baselines/" + bid + "/devices/WS-1");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    // A1 envelope: ok_json() wraps the payload as {data:..., meta:...}.
    CHECK(j.contains("data"));
    CHECK(j.contains("meta"));
    auto& d = j["data"];
    CHECK(d["baseline"]["name"].get<std::string>() == "ServiceNow Compliance");
    CHECK(d["baseline"]["baseline_id"].get<std::string>() == bid);
    CHECK(d["deployed"].get<bool>() == true);
    CHECK(d["agent_id"].get<std::string>() == "WS-1");
    CHECK(d["total_guards"].get<int>() == 3);
    CHECK(d["compliant"].get<int>() == 1);
    CHECK(d["drifted"].get<int>() == 1);
    CHECK(d["errored"].get<int>() == 0);
    CHECK(d["pending"].get<int>() == 1);
    CHECK(d["total_guards"].get<int>() == d["compliant"].get<int>() + d["drifted"].get<int>()
                                             + d["errored"].get<int>() + d["pending"].get<int>());
    // last_updated = newest reported verdict (the pending guard contributes nothing).
    CHECK(d["last_updated"].get<std::string>() == "2026-06-20T11:00:00Z");
    REQUIRE(d["guards"].is_array());
    CHECK(d["guards"].size() == 3);
    bool saw_pending = false, saw_named = false;
    for (auto& g : d["guards"]) {
        if (g["rule_id"].get<std::string>() == "r3")
            saw_pending =
                g["status"].get<std::string>() == "pending" && g["updated_at"].is_null();
        if (g["rule_id"].get<std::string>() == "r1")
            saw_named = g["name"].get<std::string>() == "Firewall on"
                        && g["status"].get<std::string>() == "compliant"
                        && !g["updated_at"].is_null();
    }
    CHECK(saw_pending);
    CHECK(saw_named);
    bool audited = false;
    for (auto& a : h.audit_log)
        if (a.action == "guardian.device.view" && a.target_id == "WS-1")
            audited = true;
    CHECK(audited);
}

TEST_CASE("REST gs.baseline-device: verdicts are isolated per agent (WHERE agent_id)",
          "[rest][guaranteed_state][baseline]") {
    RestGsHarness h;
    h.seed_rule("r1", "G1");
    h.seed_rule("r2", "G2");
    const auto bid = h.seed_deployed_baseline("B", {"r1", "r2"});
    // WS-1 all compliant; WS-2 all errored — the WS-2 rows must not bleed into WS-1.
    h.seed_status("a1", "WS-1", "r1", "guard.compliant", "2026-06-20T10:00:00Z");
    h.seed_status("a2", "WS-1", "r2", "guard.compliant", "2026-06-20T10:00:00Z");
    h.seed_status("b1", "WS-2", "r1", "guard.unhealthy", "2026-06-20T10:00:00Z");
    h.seed_status("b2", "WS-2", "r2", "guard.unhealthy", "2026-06-20T10:00:00Z");

    auto res = h.sink.Get("/api/v1/guaranteed-state/baselines/" + bid + "/devices/WS-1");
    REQUIRE(res);
    auto j = nlohmann::json::parse(res->body);
    auto& d = j["data"];
    CHECK(d["compliant"].get<int>() == 2);
    CHECK(d["errored"].get<int>() == 0); // WS-2's errored verdicts must not leak here
    CHECK(d["pending"].get<int>() == 0);

    // The same data, queried for WS-2, positively exercises the errored bucket
    // (guard.unhealthy -> "errored" via event_state_from_type) and confirms the
    // counts are isolated in both directions.
    auto res2 = h.sink.Get("/api/v1/guaranteed-state/baselines/" + bid + "/devices/WS-2");
    REQUIRE(res2);
    auto j2 = nlohmann::json::parse(res2->body);
    auto& d2 = j2["data"];
    CHECK(d2["errored"].get<int>() == 2);
    CHECK(d2["compliant"].get<int>() == 0);
    CHECK(d2["pending"].get<int>() == 0);
}

TEST_CASE("REST gs.baseline-device: unknown agent on a deployed baseline → all pending",
          "[rest][guaranteed_state][baseline]") {
    RestGsHarness h;
    h.seed_rule("r1", "G1");
    h.seed_rule("r2", "G2");
    const auto bid = h.seed_deployed_baseline("B", {"r1", "r2"});
    auto res = h.sink.Get("/api/v1/guaranteed-state/baselines/" + bid + "/devices/ghost");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    auto& d = j["data"];
    CHECK(d["total_guards"].get<int>() == 2);
    CHECK(d["pending"].get<int>() == 2);
    CHECK(d["last_updated"].is_null());
}

TEST_CASE("REST gs.baseline-device: draft baseline → deployed:false, no guards",
          "[rest][guaranteed_state][baseline]") {
    RestGsHarness h;
    h.seed_rule("r1", "G1");
    // Members set but never deployed → empty deployed_snapshot.
    Baseline b;
    b.name = "Draft B";
    auto bid = h.baseline_store->create_baseline(b);
    REQUIRE(bid.has_value());
    REQUIRE(h.baseline_store->set_members(*bid, {"r1"}).has_value());

    auto res = h.sink.Get("/api/v1/guaranteed-state/baselines/" + *bid + "/devices/WS-1");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    auto& d = j["data"];
    CHECK(d["deployed"].get<bool>() == false);
    CHECK(d["total_guards"].get<int>() == 0);
    REQUIRE(d["guards"].is_array());
    CHECK(d["guards"].empty());
}

TEST_CASE("REST gs.baseline-device: unknown baseline_id → 404 + not_found audit",
          "[rest][guaranteed_state][baseline]") {
    RestGsHarness h;
    auto res = h.sink.Get("/api/v1/guaranteed-state/baselines/nope123abc/devices/WS-1");
    REQUIRE(res);
    CHECK(res->status == 404);
    // The attempt is still audited (enumeration trail), but result reflects the
    // miss — not "success" — so a 404 probe stream stays distinguishable.
    bool not_found_audited = false;
    for (auto& a : h.audit_log)
        if (a.action == "guardian.device.view" && a.target_id == "WS-1" &&
            a.result == "not_found")
            not_found_audited = true;
    CHECK(not_found_audited);
}

// #1647: the baseline-device route serves per-device behavioural-compliance PII
// over REST (machine consumers — CMDB/ServiceNow). It previously DISCARDED the
// AuditFn bool; it now fails closed (parity with the dex.device.view REST siblings)
// so evidence-less PII is never served as audited.
TEST_CASE("REST gs.baseline-device: audit persistence failure → 503, no PII served, Sec-Audit-Failed",
          "[rest][guaranteed_state][baseline][audit]") {
    RestGsHarness h;
    h.seed_rule("r1", "Defender on");
    const auto bid = h.seed_deployed_baseline("Endpoint Hardening", {"r1"});
    h.seed_status("a1", "WS-1", "r1", "guard.compliant", "2026-06-20T10:00:00Z");
    h.audit_succeeds = false; // the evidence row cannot persist
    auto res = h.sink.Get("/api/v1/guaranteed-state/baselines/" + bid + "/devices/WS-1");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    // No compliance PII leaked — neither the guard rollup nor the guard name.
    CHECK(res->body.find("\"guards\"") == std::string::npos);
    CHECK(res->body.find("Defender on") == std::string::npos);
}

// #1647 item 1: a bad_alloc-class throw out of audit_fn was previously silent on
// this route (no try/catch). The shared helper catches it → fail closed, never lets
// it escape into a bare 500.
TEST_CASE("REST gs.baseline-device: a throwing audit_fn is caught → 503 fail-closed",
          "[rest][guaranteed_state][baseline][audit]") {
    RestGsHarness h;
    h.seed_rule("r1", "Defender on");
    const auto bid = h.seed_deployed_baseline("Endpoint Hardening", {"r1"});
    h.seed_status("a1", "WS-1", "r1", "guard.compliant", "2026-06-20T10:00:00Z");
    h.audit_throws = true;
    auto res = h.sink.Get("/api/v1/guaranteed-state/baselines/" + bid + "/devices/WS-1");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    CHECK(res->body.find("Defender on") == std::string::npos);
}

TEST_CASE("REST gs.baseline-device: deployed-but-empty baseline → deployed:true, no guards",
          "[rest][guaranteed_state][baseline]") {
    RestGsHarness h;
    // A genuinely deployed Baseline with zero members (snapshot "[]") — distinct
    // from a draft (deployed:false). A consumer must branch on `deployed`, not on
    // total_guards, to decide "No Baseline Deployed".
    const auto bid = h.seed_deployed_baseline("Empty Deployed", {});
    auto res = h.sink.Get("/api/v1/guaranteed-state/baselines/" + bid + "/devices/WS-1");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    auto& d = j["data"];
    CHECK(d["deployed"].get<bool>() == true);
    CHECK(d["total_guards"].get<int>() == 0);
    REQUIRE(d["guards"].is_array());
    CHECK(d["guards"].empty());
}

TEST_CASE("REST gs.baseline-device: permission gate runs before audit",
          "[rest][guaranteed_state][baseline][rbac]") {
    RestGsHarness h;
    h.seed_rule("r1", "G1");
    const auto bid = h.seed_deployed_baseline("B", {"r1"});
    h.grant_perms = false; // scoped_perm_fn denies → 403
    auto res = h.sink.Get("/api/v1/guaranteed-state/baselines/" + bid + "/devices/WS-1");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(h.audit_log.empty());
}

TEST_CASE("REST gs.baseline-device: per-device scope — out-of-scope agent 403, in-scope 200",
          "[rest][guaranteed_state][baseline][rbac]") {
    RestGsHarness h;
    h.seed_rule("r1", "G1");
    const auto bid = h.seed_deployed_baseline("B", {"r1"});
    h.seed_status("e1", "WS-1", "r1", "guard.compliant", "2026-06-20T10:00:00Z");
    h.seed_status("e2", "WS-2", "r1", "guard.compliant", "2026-06-20T10:00:00Z");

    // WS-1 is outside the caller's management-group scope → 403, and the gate runs
    // before the store read + audit (no leak, no audit row). Also proves the route
    // hands the scoped check the RIGHT device id (regression net vs flat perm_fn).
    h.scoped_deny_agent = "WS-1";
    auto denied = h.sink.Get("/api/v1/guaranteed-state/baselines/" + bid + "/devices/WS-1");
    REQUIRE(denied);
    CHECK(denied->status == 403);
    CHECK(h.last_scoped_agent_id == "WS-1");
    CHECK(h.audit_log.empty());

    // WS-2 is in scope → 200.
    auto ok = h.sink.Get("/api/v1/guaranteed-state/baselines/" + bid + "/devices/WS-2");
    REQUIRE(ok);
    CHECK(ok->status == 200);
    CHECK(h.last_scoped_agent_id == "WS-2");
}

TEST_CASE("REST gs.baseline-device: unwired scoped_perm_fn → fail-closed 503 (A4)",
          "[rest][guaranteed_state][baseline][rbac]") {
    RestGsHarness h{/*live_deps=*/true, /*wire_scoped_perm=*/false};
    h.seed_rule("r1", "G1");
    const auto bid = h.seed_deployed_baseline("B", {"r1"});
    // With no scoped_perm_fn wired the route MUST fail closed (503) — never silently
    // fall back to the flat gate that would re-introduce the group-scoped lockout.
    auto res = h.sink.Get("/api/v1/guaranteed-state/baselines/" + bid + "/devices/WS-1");
    REQUIRE(res);
    CHECK(res->status == 503);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["error"]["code"].get<int>() == 503);
    CHECK(j["error"].contains("correlation_id"));
    CHECK(j["meta"]["api_version"] == "v1");
    CHECK(h.audit_log.empty()); // fail-closed before any audit
}

TEST_CASE("REST gs.baseline-device: path-param length cap at kMaxAgentIdLength (256)",
          "[rest][guaranteed_state][baseline]") {
    RestGsHarness h;
    h.seed_rule("r1", "G1");
    const auto bid = h.seed_deployed_baseline("B", {"r1"});

    // 256-char baseline_id is AT the cap → passes → reaches the store → 404 (unknown
    // id), proving the cap did not bite a valid-length id.
    const std::string id256(256, 'x');
    auto ok_b = h.sink.Get("/api/v1/guaranteed-state/baselines/" + id256 + "/devices/WS-1");
    REQUIRE(ok_b);
    CHECK(ok_b->status == 404);

    // 257-char baseline_id is past the cap → 400 A4.
    const std::string id257(257, 'x');
    auto bad_b = h.sink.Get("/api/v1/guaranteed-state/baselines/" + id257 + "/devices/WS-1");
    REQUIRE(bad_b);
    CHECK(bad_b->status == 400);
    auto jb = nlohmann::json::parse(bad_b->body);
    CHECK(jb["error"]["code"].get<int>() == 400);
    CHECK(jb["error"].contains("correlation_id"));

    // 257-char agent_id is independently capped → 400 A4.
    const std::string a257(257, 'a');
    auto bad_a = h.sink.Get("/api/v1/guaranteed-state/baselines/" + bid + "/devices/" + a257);
    REQUIRE(bad_a);
    CHECK(bad_a->status == 400);
    CHECK(nlohmann::json::parse(bad_a->body)["error"].contains("correlation_id"));

    // 256-char agent_id is AT the cap → passes → deployed baseline → 200 (all pending).
    const std::string a256(256, 'a');
    auto ok_a = h.sink.Get("/api/v1/guaranteed-state/baselines/" + bid + "/devices/" + a256);
    REQUIRE(ok_a);
    CHECK(ok_a->status == 200);
}

TEST_CASE("REST gs.baseline-device: 404 uses the A4 envelope (code + correlation_id)",
          "[rest][guaranteed_state][baseline]") {
    RestGsHarness h;
    auto res = h.sink.Get("/api/v1/guaranteed-state/baselines/does-not-exist/devices/WS-1");
    REQUIRE(res);
    CHECK(res->status == 404);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["error"]["code"].get<int>() == 404);
    CHECK(j["error"].contains("correlation_id"));
    CHECK(j["error"]["message"].get<std::string>() == "baseline not found");
    CHECK(j["meta"]["api_version"] == "v1");
}

TEST_CASE("REST gs.baseline-device: route + schema are in the OpenAPI spec (A1 discoverability)",
          "[rest][guaranteed_state][baseline][discovery]") {
    RestGsHarness h;
    auto res = h.sink.Get("/api/v1/openapi.json");
    REQUIRE(res);
    CHECK(res->status == 200);
    nlohmann::json spec;
    // Parsing validates the spec survived the C2026 string-literal split.
    REQUIRE_NOTHROW(spec = nlohmann::json::parse(res->body));
    REQUIRE(spec.contains("paths"));
    CHECK(spec["paths"].contains("/guaranteed-state/baselines/{baseline_id}/devices/{agent_id}"));
    REQUIRE(spec.contains("components"));
    REQUIRE(spec["components"].contains("schemas"));
    CHECK(spec["components"]["schemas"].contains("GuaranteedStateBaselineDeviceStatus"));
}

TEST_CASE("REST gs.baseline-device: unrecognized stored state folds into pending (invariant holds)",
          "[rest][guaranteed_state][baseline]") {
    RestGsHarness h;
    h.seed_rule("r1", "G1");
    const auto bid = h.seed_deployed_baseline("B", {"r1"});
    // A corrupt/future state token the public ingest path can never write.
    h.seed_raw_status("WS-1", "r1", "weird-future-state", "2026-06-20T10:00:00Z");

    auto res = h.sink.Get("/api/v1/guaranteed-state/baselines/" + bid + "/devices/WS-1");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    auto& d = j["data"];
    CHECK(d["total_guards"].get<int>() == 1);
    CHECK(d["compliant"].get<int>() == 0);
    CHECK(d["drifted"].get<int>() == 0);
    CHECK(d["errored"].get<int>() == 0);
    CHECK(d["pending"].get<int>() == 1); // unrecognized state -> pending
    CHECK(d["total_guards"].get<int>() == d["compliant"].get<int>() + d["drifted"].get<int>()
                                             + d["errored"].get<int>() + d["pending"].get<int>());
    CHECK(d["last_updated"].is_null()); // only recognized verdicts contribute
    REQUIRE(d["guards"].is_array());
    CHECK(d["guards"].size() == 1);
    CHECK(d["guards"][0]["status"].get<std::string>() == "pending");
    CHECK(d["guards"][0]["updated_at"].is_null());
}

TEST_CASE("REST gs.baseline-device: snapshot guard with no rule row falls back to rule_id name",
          "[rest][guaranteed_state][baseline]") {
    RestGsHarness h;
    h.seed_rule("r1", "Real Guard");
    // r-gone is in the deployed snapshot but its rule row was never created
    // (e.g. the Guard was deleted after deploy) -> name falls back to the rule_id.
    const auto bid = h.seed_deployed_baseline("B", {"r1", "r-gone"});
    h.seed_status("e1", "WS-1", "r1", "guard.compliant", "2026-06-20T10:00:00Z");

    auto res = h.sink.Get("/api/v1/guaranteed-state/baselines/" + bid + "/devices/WS-1");
    REQUIRE(res);
    auto j = nlohmann::json::parse(res->body);
    auto& d = j["data"];
    CHECK(d["total_guards"].get<int>() == 2);
    bool saw_fallback = false;
    for (auto& g : d["guards"]) {
        if (g["rule_id"].get<std::string>() == "r-gone") {
            CHECK(g["name"].get<std::string>() == "r-gone"); // fallback to rule_id
            CHECK(g["status"].get<std::string>() == "pending");
            saw_fallback = true;
        }
    }
    CHECK(saw_fallback);
}
