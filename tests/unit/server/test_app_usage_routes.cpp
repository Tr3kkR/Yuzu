/// @file test_app_usage_routes.cpp
/// Tests for the /api/v1/forensics/agents/{id}/app-usage in-server read route
/// (wave 7 PR7.2) — driven in-process through TestRouteSink (no httplib
/// acceptor, #438). Mirrors test_sle_routes.cpp's drill coverage: the scoped
/// Forensics:Read gate (in-scope 200 / out-of-scope 403), the fail-closed
/// gate-unwired 503, the fail-closed per-open behavioural audit (503 +
/// Sec-Audit-Failed on a persist failure), and 503-on-degrade (never an
/// empty 200).

#include "app_usage_routes.hpp"
#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

using namespace yuzu::server;
using nlohmann::json;

namespace {

bool contains(const std::string& hay, const std::string& needle) {
    return hay.find(needle) != std::string::npos;
}

AgentLastUsedRow row(std::string exe_key, std::int64_t first_seen, std::int64_t last_seen,
                     std::int64_t run_count = 1, std::int64_t total_seconds = 60,
                     std::int64_t collected_at = 1700000000) {
    AgentLastUsedRow r;
    r.exe_key = std::move(exe_key);
    r.first_seen = first_seen;
    r.last_seen = last_seen;
    r.run_count_30d = run_count;
    r.total_seconds_30d = total_seconds;
    r.collected_at = collected_at;
    return r;
}

// ── Route harness — all providers injected, every flag re-read per call ──────────
struct AppUsageHarness {
    yuzu::server::test::TestRouteSink sink;
    AppUsageRoutes routes;

    bool allow_scoped_all = false;          // scoped gate admits every agent
    std::vector<std::string> scoped_agents; // ...or just these agents (in-scope set)
    bool degrade_agent = false;
    bool audit_should_fail = false;
    // omit the scoped gate entirely (fail-closed 503). Read only in the constructor
    // below (register_routes decides WHICH closure to install at construction time,
    // not per-request), so it must be passed to the constructor — setting the member
    // after construction is a no-op, the gate is already wired by then.
    const bool gate_unwired;

    std::vector<AgentLastUsedRow> agent_rows;

    std::vector<std::string> audits;     // "action|result"
    std::vector<std::string> audit_full; // "action|result|target_type|target_id"
    // The (securable_type, operation, agent_id) each SCOPED gate check was ASKED.
    std::vector<std::string> scoped_calls; // "type|op|agent_id"

    explicit AppUsageHarness(bool gate_unwired_ = false) : gate_unwired(gate_unwired_) {
        auto scoped = [this](const httplib::Request&, httplib::Response& res,
                             const std::string& type, const std::string& op,
                             const std::string& agent_id) {
            scoped_calls.push_back(type + "|" + op + "|" + agent_id);
            bool ok = allow_scoped_all;
            for (const auto& a : scoped_agents)
                if (a == agent_id)
                    ok = true;
            if (!ok) {
                res.status = 403;
                res.set_content(R"({"error":{"code":403,"permission":")" + type + ":" + op +
                                    R"("}})",
                                "application/json");
            }
            return ok;
        };
        auto agents_fn =
            [this](const std::string&) -> std::optional<std::vector<AgentLastUsedRow>> {
            if (degrade_agent)
                return std::nullopt;
            return agent_rows;
        };
        auto audit = [this](const httplib::Request&, const std::string& a, const std::string& r,
                            const std::string& tt, const std::string& tid, const std::string&) {
            audits.push_back(a + "|" + r);
            audit_full.push_back(a + "|" + r + "|" + tt + "|" + tid);
            return !audit_should_fail;
        };
        routes.register_routes(sink, gate_unwired ? AppUsageRoutes::ScopedPermFn{} : scoped,
                               agents_fn, audit);
    }

    bool audited(const std::string& tok) const {
        for (const auto& a : audits)
            if (a == tok)
                return true;
        return false;
    }
};

} // namespace

TEST_CASE("app-usage: 401/403 via the scoped gate — out-of-scope denied", "[app_usage_routes]") {
    AppUsageHarness h; // allow_scoped_all=false, empty set → every agent out of scope
    auto res = h.sink.Get("/api/v1/forensics/agents/agent-out/app-usage");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK_FALSE(contains(res->body, "apps"));
}

TEST_CASE("app-usage: demands exactly Forensics:Read via the scoped gate", "[app_usage_routes]") {
    AppUsageHarness h;
    h.allow_scoped_all = true;
    h.sink.Get("/api/v1/forensics/agents/agent-77/app-usage");
    REQUIRE(h.scoped_calls.size() == 1);
    CHECK(h.scoped_calls[0] == "Forensics|Read|agent-77");
}

TEST_CASE("app-usage: scoped gate — in-scope 200, out-of-scope 403", "[app_usage_routes]") {
    AppUsageHarness h;
    h.scoped_agents = {"agent-in"};
    h.agent_rows = {row("chrome.exe", 1699000000, 1700000500, 12, 43200)};

    auto in = h.sink.Get("/api/v1/forensics/agents/agent-in/app-usage");
    REQUIRE(in);
    CHECK(in->status == 200);
    CHECK(contains(in->body, "chrome.exe"));

    auto out = h.sink.Get("/api/v1/forensics/agents/agent-out/app-usage");
    REQUIRE(out);
    CHECK(out->status == 403);
    CHECK_FALSE(contains(out->body, "chrome.exe"));
}

TEST_CASE("app-usage: gate unwired → fail-closed 503, never a legacy-open read",
          "[app_usage_routes]") {
    AppUsageHarness h(/*gate_unwired_=*/true);
    h.agent_rows = {row("chrome.exe", 1699000000, 1700000500)};
    auto res = h.sink.Get("/api/v1/forensics/agents/agent-1/app-usage");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK_FALSE(contains(res->body, "chrome.exe"));
}

TEST_CASE("app-usage: 200 body pinned — field-for-field shape + collected_at hoisted",
          "[app_usage_routes]") {
    AppUsageHarness h;
    h.allow_scoped_all = true;
    h.agent_rows = {row("chrome.exe", 1699000000, 1700000500, 12, 43200, 1700000600),
                    row("word.exe", 1698000000, 1700000600, 3, 900, 1700000600)};
    auto res = h.sink.Get("/api/v1/forensics/agents/agent-9/app-usage");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    auto j = json::parse(res->body)["data"];
    CHECK(j["agent_id"] == "agent-9");
    CHECK(j["collected_at"] == 1700000600);
    REQUIRE(j["apps"].size() == 2);
    CHECK(j["apps"][0]["exe_key"] == "chrome.exe");
    CHECK(j["apps"][0]["first_seen"] == 1699000000);
    CHECK(j["apps"][0]["last_seen"] == 1700000500);
    CHECK(j["apps"][0]["run_count_30d"] == 12);
    CHECK(j["apps"][0]["total_seconds_30d"] == 43200);
    // No collected_at inside the per-app object — it is hoisted to the top level.
    CHECK_FALSE(j["apps"][0].contains("collected_at"));
}

TEST_CASE("app-usage: empty result → collected_at 0, apps empty (never nullopt)",
          "[app_usage_routes]") {
    AppUsageHarness h;
    h.allow_scoped_all = true;
    h.agent_rows = {};
    auto res = h.sink.Get("/api/v1/forensics/agents/agent-9/app-usage");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    auto j = json::parse(res->body)["data"];
    CHECK(j["collected_at"] == 0);
    CHECK(j["apps"].empty());
}

TEST_CASE("app-usage: per-open behavioural audit is emitted (app_usage.agent.view)",
          "[app_usage_routes]") {
    AppUsageHarness h;
    h.allow_scoped_all = true;
    h.agent_rows = {row("chrome.exe", 1699000000, 1700000500)};
    auto res = h.sink.Get("/api/v1/forensics/agents/agent-9/app-usage");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    CHECK(h.audited("app_usage.agent.view|success"));
    bool target_ok = false;
    for (const auto& a : h.audit_full)
        if (a == "app_usage.agent.view|success|Agent|agent-9")
            target_ok = true;
    CHECK(target_ok);
}

TEST_CASE("app-usage: audit FAILS CLOSED — 503 + Sec-Audit-Failed, data withheld",
          "[app_usage_routes]") {
    AppUsageHarness h;
    h.allow_scoped_all = true;
    h.audit_should_fail = true;
    h.agent_rows = {row("chrome.exe", 1699000000, 1700000500)};
    auto res = h.sink.Get("/api/v1/forensics/agents/agent-9/app-usage");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(res->has_header("Sec-Audit-Failed"));
    CHECK_FALSE(contains(res->body, "chrome.exe"));
}

TEST_CASE("app-usage: scoped gate runs BEFORE the audit + read (out-of-scope → no audit)",
          "[app_usage_routes]") {
    AppUsageHarness h; // scoped gate denies everything
    h.agent_rows = {row("chrome.exe", 1699000000, 1700000500)};
    auto res = h.sink.Get("/api/v1/forensics/agents/agent-out/app-usage");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(h.audits.empty());
}

TEST_CASE("app-usage: store degrade → 503 + audited failure, never an empty 200, "
          "and never a phantom success row",
          "[app_usage_routes]") {
    AppUsageHarness h;
    h.allow_scoped_all = true;
    h.degrade_agent = true;
    auto res = h.sink.Get("/api/v1/forensics/agents/agent-1/app-usage");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(contains(res->body, "unavailable"));
    // The read is confirmed BEFORE the audit fires (matches the MCP twin's
    // ordering and the sle.agent.decommission pattern): a degraded read never
    // reaches the audit call at all, so there is no "success" row left behind
    // for a later "failure" row to sit alongside — the phantom-audit-row bug
    // this ordering fixes.
    CHECK_FALSE(h.audited("app_usage.agent.view|success"));
    CHECK(h.audited("app_usage.agent.view|failure"));
}
