/**
 * test_response_scope_wiring.cpp -- #1712 regression guard: the two response
 * readers this issue fixed must stay WIRED to the production per-agent scope
 * predicate in server.cpp.
 *
 * WHY THIS GUARD EXISTS. The #1712 behaviour tests
 * (test_dashboard_results_columns.cpp, test_workflow_routes.cpp,
 * test_response_scope_filter.cpp) all install their OWN predicate -- a
 * hand-written deny-all or mixed lambda -- because neither route owner can
 * reach a real `RbacStore` from a unit test. They therefore prove the FILTER
 * MECHANICS and nothing about whether production actually hands those readers
 * `ServerImpl::response_agent_in_scope`. Delete either wiring block in
 * server.cpp and every one of those tests still passes, while both readers
 * silently revert to fail-OPEN on a corrupt rbac.db -- which is the entire
 * defect #1712 exists to close.
 *
 * That gap is structural, not an oversight in those tests: `ServerImpl` is not
 * unit-constructible (see test_default_certs.cpp and test_store_wiring_order.cpp,
 * which states the same for its own concern), and the established-correct
 * sibling `response_agent_in_scope` call sites have no runtime test either
 * (test_list_read_confinement.cpp says so explicitly). So this follows the
 * pattern those files already set for exactly this class of invisible drift:
 * scan the real source text at test run time.
 *
 * MECHANISM. Opens server.cpp via `YUZU_SERVER_SRC_DIR` (injected by
 * tests/meson.build -- the same seam test_store_wiring_order.cpp and
 * test_body_cap_route_inventory.cpp use; absolute and CWD-independent) and
 * asserts that each of the two wiring sites passes a lambda whose body calls
 * `response_agent_in_scope`. `//` line comments are stripped first, so a
 * commented-out wiring block cannot satisfy the guard -- the failure mode this
 * test is most likely to face is someone commenting a block out while
 * debugging.
 *
 * WHAT THIS DOES NOT CLAIM. It is a lexical guard, not a runtime proof: it
 * cannot show the predicate returns the right answer (that is
 * test_list_read_confinement.cpp's job at the store level, and
 * test_response_scope_filter.cpp's at the loop level). It shows only that the
 * two readers are still connected to the one shared fail-closed helper rather
 * than to nothing.
 */

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>
#include <regex>
#include <sstream>
#include <string>

#ifndef YUZU_SERVER_SRC_DIR
#error "YUZU_SERVER_SRC_DIR must be injected by tests/meson.build (see test_store_wiring_order.cpp's identical guard)."
#endif

namespace {

/// Strip `//` line comments so a commented-out wiring block cannot satisfy the
/// guard. Deliberately naive (no string-literal awareness) -- matching
/// test_store_wiring_order.cpp's approach, and sufficient because every
/// pattern below is plain code with no `//` inside a literal.
std::string strip_line_comments(const std::string& src) {
    std::istringstream in(src);
    std::string line;
    std::string out;
    while (std::getline(in, line)) {
        const auto pos = line.find("//");
        if (pos != std::string::npos)
            line.erase(pos);
        out += line;
        out += '\n';
    }
    return out;
}

std::string read_server_cpp() {
    const std::filesystem::path p = std::filesystem::path{YUZU_SERVER_SRC_DIR} / "server.cpp";
    std::ifstream f(p);
    REQUIRE(f.good());
    std::ostringstream ss;
    ss << f.rdbuf();
    return strip_line_comments(ss.str());
}

} // namespace

TEST_CASE("#1712: both new response readers are wired to response_agent_in_scope in server.cpp",
          "[server][wiring][1712][lexical]") {
    const std::string src = read_server_cpp();

    // Sanity: the helper the wiring must point at still exists. If it is ever
    // renamed, this fails first and names the real cause rather than letting
    // the two site checks below fail confusingly.
    CHECK(src.find("bool response_agent_in_scope(") != std::string::npos);

    SECTION("DashboardRoutes /fragments/results is handed the predicate") {
        // ANCHORED to the DashboardRoutes registration, deliberately.
        //
        // This section previously searched the WHOLE file for the bare lambda
        // body. That text is not unique — the identical delegating lambda
        // appears at four sites in server.cpp (the dashboard wiring, the
        // WorkflowRoutes wiring, and two more) — so deleting the
        // DashboardRoutes argument left `/fragments/results` unwired and
        // fail-open while this guard still matched one of its siblings and
        // stayed GREEN. Every behaviour test installs its own predicate, so
        // they stayed green too: the exact false-green this file exists to
        // prevent, reproduced inside the guard itself.
        //
        // Anchor on the registration call, then require the delegation within
        // that call's own text.
        // NB: `src` is comment-stripped, so both bounds must be CODE, not a
        // section comment. `WorkflowRoutes::Deps` is the first statement after
        // the dashboard registration closes, which makes it a stable end
        // bound that excludes the workflow lambda.
        const auto reg_at = src.find("dashboard_routes_->register_routes(");
        REQUIRE(reg_at != std::string::npos);
        const auto reg_end = src.find("WorkflowRoutes::Deps", reg_at);
        REQUIRE(reg_end != std::string::npos);
        REQUIRE(reg_end > reg_at);
        const std::string dashboard_block = src.substr(reg_at, reg_end - reg_at);
        // Guard the guard: if this block ever swallowed the workflow wiring,
        // the section would be back to matching a sibling.
        REQUIRE(dashboard_block.find("wf_deps.response_scope_fn") == std::string::npos);
        const std::regex dashboard_wiring(
            R"(\[this\]\(const std::string& username, const std::string& agent_id\) -> bool \{\s*return response_agent_in_scope\(username, agent_id\);)");
        std::smatch m;
        CHECK(std::regex_search(dashboard_block, m, dashboard_wiring));
    }

    SECTION("WorkflowRoutes executions drawer is handed the predicate") {
        const std::regex workflow_wiring(
            R"(wf_deps\.response_scope_fn\s*=\s*\[this\]\(const std::string& username, const std::string& agent_id\) -> bool \{\s*return response_agent_in_scope\(username, agent_id\);)");
        std::smatch m;
        CHECK(std::regex_search(src, m, workflow_wiring));
    }

    SECTION("the wiring delegates, never re-implements the fail-closed decision") {
        // A wiring site that inlined `check_scoped_permission` directly would
        // bypass `rbac_enforcement_in_effect` and reintroduce the exact
        // fail-OPEN this issue closed (a corrupt store leaves the RBAC flag
        // reading false, which an inlined check would treat as "RBAC off").
        // `response_agent_in_scope` is the ONE place that decision may live.
        // BOTH wiring sites, not one. This previously declared a variable
        // named `dashboard_marker` whose value was the WORKFLOW marker
        // ("wf_deps.response_scope_fn"), so the dashboard wiring was never
        // inspected at all: a dashboard site that inlined
        // `check_scoped_permission` would have passed this section unnoticed.
        const std::string workflow_marker = "wf_deps.response_scope_fn";
        const std::string dashboard_marker = "dashboard_routes_->register_routes(";
        for (const auto& marker : {dashboard_marker, workflow_marker}) {
            INFO("wiring site: " << marker);
            const auto at = src.find(marker);
            REQUIRE(at != std::string::npos);
            const std::string wiring_block = src.substr(at, 400);
            CHECK(wiring_block.find("check_scoped_permission") == std::string::npos);
            CHECK(wiring_block.find("is_rbac_enabled") == std::string::npos);
        }
    }
}
