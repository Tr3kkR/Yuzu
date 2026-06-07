/**
 * test_result_sets_ui.cpp — Render-function tests for the result-sets dashboard
 * surface. Pure rendering (no store I/O): asserts the scope token, lineage
 * breadcrumb, pin/unpin action selection, and — critically — that operator-
 * supplied names and device IDs are HTML-escaped (XSS).
 */

#include "result_sets_ui.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

using namespace yuzu::server;

namespace {

ResultSet make(const std::string& id, const std::string& name, int64_t devices, bool pinned,
               ResultSetStatus status = ResultSetStatus::Materialized) {
    ResultSet r;
    r.id = id;
    r.name = name;
    r.owner_principal = "alice";
    r.device_count = devices;
    r.pinned = pinned;
    r.status = status;
    r.source_kind = std::string(source_kind::kInventoryQuery);
    return r;
}

} // namespace

TEST_CASE("result_sets_ui: sidebar lists sets with hx-get targets", "[result_set][ui]") {
    std::vector<ResultSet> sets = {make("rs_aaa", "win-fleet", 12, false),
                                   make("rs_bbb", "suspects", 3, true)};
    auto html = render_result_sets_sidebar(sets, "rs_bbb");

    CHECK(html.find("win-fleet") != std::string::npos);
    CHECK(html.find("suspects") != std::string::npos);
    CHECK(html.find("/fragments/result-sets/rs_aaa/detail") != std::string::npos);
    CHECK(html.find("12 devices") != std::string::npos);
    CHECK(html.find("3 devices") != std::string::npos);
    // Selected set carries the active class; pinned set shows the star.
    CHECK(html.find("active") != std::string::npos);
    CHECK(html.find("★") != std::string::npos);
}

TEST_CASE("result_sets_ui: empty sidebar shows empty state", "[result_set][ui]") {
    auto html = render_result_sets_sidebar({}, "");
    CHECK(html.find("No result sets yet") != std::string::npos);
}

TEST_CASE("result_sets_ui: sidebar escapes a malicious name (XSS)", "[result_set][ui][security]") {
    std::vector<ResultSet> sets = {make("rs_xss", "<script>alert(1)</script>", 1, false)};
    auto html = render_result_sets_sidebar(sets, "");
    // The raw script tag must not appear; the escaped form must.
    CHECK(html.find("<script>alert(1)</script>") == std::string::npos);
    CHECK(html.find("&lt;script&gt;") != std::string::npos);
}

TEST_CASE("result_sets_ui: detail shows scope token + actions", "[result_set][ui]") {
    auto rs = make("rs_leaf", "compromised", 29, false);
    std::vector<LineageNode> chain = {{"rs_root", "all-windows", "inventory_query", 4011},
                                      {"rs_mid", "chrome", "inventory_query", 412},
                                      {"rs_leaf", "compromised", "instruction_result", 29}};
    auto html = render_result_set_detail(rs, chain);

    // Copyable scope token is present.
    CHECK(html.find("from_result_set:rs_leaf") != std::string::npos);
    // Breadcrumb renders all three nodes with the leaf marked current.
    CHECK(html.find("all-windows") != std::string::npos);
    CHECK(html.find("chrome") != std::string::npos);
    CHECK(html.find("current") != std::string::npos);
    // Unpinned set offers Pin (not Unpin) + Delete.
    CHECK(html.find("/fragments/result-sets/rs_leaf/pin") != std::string::npos);
    CHECK(html.find("/fragments/result-sets/rs_leaf/delete") != std::string::npos);
}

TEST_CASE("result_sets_ui: pinned set offers Unpin", "[result_set][ui]") {
    auto rs = make("rs_pin", "kept", 5, true);
    auto html = render_result_set_detail(rs, {});
    CHECK(html.find("/fragments/result-sets/rs_pin/unpin") != std::string::npos);
    CHECK(html.find("★ pinned") != std::string::npos);
}

TEST_CASE("result_sets_ui: detail empty state", "[result_set][ui]") {
    auto html = render_result_set_detail_empty();
    CHECK(html.find("Select a result set") != std::string::npos);
}
