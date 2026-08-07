/**
 * test_body_cap_policy.cpp — coverage for the #2407 pre-auth body-cap policy
 * table (`body_cap_policy.hpp`'s `kBodyCapTable` / `resolve_body_cap`).
 *
 * This header is a PURE table + lookup — the enforcement chokepoint
 * (server.cpp's pre-routing handler, generalized from the existing #2437
 * `/mcp/` gate) is wired by a sibling change. This file locks the table
 * itself: every entry's cap, every entry's `requires_measurable` bit, the
 * segment-boundary matching rule that stops `/api/v1/bundlesevil` from
 * matching the `/api/v1/bundles` entry, method discrimination on a shared
 * prefix, longest-match precedence, and the catch-all default.
 *
 * Expected values below are an INDEPENDENT copy of the table, not derived
 * from it — mirroring `test_authz_topology_floor.cpp`'s `kExpectedFloorPairs`
 * pattern. A test that iterates `kBodyCapTable` to build its own
 * expectations would shrink in lockstep with an accidentally-shrunk or
 * silently-changed table and stop catching the very regression this file
 * exists to catch.
 */

#include "body_cap_policy.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <set>
#include <string>
#include <string_view>

using yuzu::server::BodyCapMatch;
using yuzu::server::body_cap_prefix_matches;
using yuzu::server::kBodyCapAnyMethod;
using yuzu::server::kBodyCapTable;
using yuzu::server::resolve_body_cap;

namespace {

/// One expected `(method, path)` -> `(cap, requires_measurable, class)`
/// resolution, hand-copied independently of `kBodyCapTable`.
struct ExpectedResolution {
    std::string_view method;
    std::string_view path;
    std::size_t max_body_bytes;
    bool requires_measurable;
    std::string_view path_class;
};

// clang-format off
constexpr ExpectedResolution kExpected[] = {
    // mcp_jsonrpc.hpp:63 kMcpMaxRequestBodyBytes. ANY method.
    {"GET",    "/mcp/v1/",                                4u * 1024 * 1024,   true,  "mcp"},
    {"POST",   "/mcp/v1/",                                4u * 1024 * 1024,   true,  "mcp"},
    {"DELETE", "/mcp/v1/",                                4u * 1024 * 1024,   true,  "mcp"},
    // bundle_service.hpp:24-33 / rest_api_v1.cpp:1417.
    {"POST",   "/api/v1/bundles",                         70u * 1024 * 1024,  false, "bundles"},
    // settings_routes.cpp:5146,:5206 — keeps httplib's 100 MiB backstop.
    {"POST",   "/api/settings/updates/upload",            100u * 1024 * 1024, false, "ota_upload"},
    // ca_routes.cpp:24,:516.
    {"POST",   "/api/v1/ca/import-chain",                 256u * 1024,        false, "ca_import_chain"},
    // ca_routes.cpp:727 dashboard twin, doubled for form-encoding overhead.
    {"POST",   "/api/settings/ca/import-chain",           512u * 1024,        false, "ca_import_chain_dashboard"},
    // settings_routes.cpp:3445,:3461, doubled for multipart framing overhead.
    {"POST",   "/api/settings/plugin-signing/upload",     512u * 1024,        false, "plugin_trust_bundle"},
    // scim_routes.cpp:65 kMaxBodyBytes, three mutating methods.
    {"POST",   "/scim/v2/Users",                          64u * 1024,         false, "scim"},
    {"PUT",    "/scim/v2/Users/deadbeef",                 64u * 1024,         false, "scim"},
    {"PATCH",  "/scim/v2/Users/deadbeef",                 64u * 1024,         false, "scim"},
    {"POST",   "/scim/v2/Groups",                         64u * 1024,         false, "scim"},
    {"PUT",    "/scim/v2/Groups/deadbeef",                64u * 1024,         false, "scim"},
    {"PATCH",  "/scim/v2/Groups/deadbeef",                64u * 1024,         false, "scim"},
    // auth_routes.cpp:2794-2798 kSamlMaxBodyBytes.
    {"POST",   "/saml/acs",                                1u * 1024 * 1024,  false, "saml_acs"},
    // rest_api_v1.cpp:4237 kRtMaxBodyBytes.
    {"POST",   "/api/v1/definitions/def-1/response-templates",             64u * 1024, false, "response_templates"},
    {"PUT",    "/api/v1/definitions/def-1/response-templates/tmpl-1",      64u * 1024, false, "response_templates"},
    // dashboard_routes.cpp `sql.size() > 4096`.
    {"POST",   "/api/dashboard/tar-execute",              4u * 1024,          false, "tar_dashboard_sql"},
    // rest_api_v1.cpp:6797 `sql.size() > 100000`.
    {"POST",   "/api/v1/result-sets/from-tar-query",      100u * 1024,        false, "tar_result_set_sql"},
    // rest_api_v1.cpp:7759,:7842 — explicit generous, no contract yet.
    {"POST",   "/api/v1/guaranteed-state/rules",          16u * 1024 * 1024,  false, "guardian_rule_authoring"},
    // workflow_routes.cpp:1023.
    {"POST",   "/api/workflows",                          16u * 1024 * 1024,  false, "workflow_yaml"},
    // workflow_routes.cpp:1746 / product_pack_store.cpp:122.
    {"POST",   "/api/product-packs",                      16u * 1024 * 1024,  false, "product_pack_yaml"},
    // Catch-all default — ordinary JSON/form traffic.
    {"POST",   "/api/v1/some-ordinary-mutation-route",    4u * 1024 * 1024,   false, "default"},
    {"GET",    "/api/v1/devices",                         4u * 1024 * 1024,   false, "default"},
};
// clang-format on

/// Independent list of every distinct metric label the table is expected to
/// emit — locks metric cardinality separately from the per-row cap values.
constexpr std::string_view kExpectedPathClasses[] = {
    "mcp",
    "bundles",
    "ota_upload",
    "ca_import_chain",
    "ca_import_chain_dashboard",
    "plugin_trust_bundle",
    "scim",
    "saml_acs",
    "response_templates",
    "tar_dashboard_sql",
    "tar_result_set_sql",
    "guardian_rule_authoring",
    "workflow_yaml",
    "product_pack_yaml",
    "default",
};

} // namespace

// ── 1. Every table entry resolves to its own cap ─────────────────────────

TEST_CASE("resolve_body_cap: every documented route class resolves to its own measured cap",
          "[body_cap]") {
    for (const auto& exp : kExpected) {
        INFO("method=" << exp.method << " path=" << exp.path);
        const auto got = resolve_body_cap(exp.method, exp.path);
        CHECK(got.max_body_bytes == exp.max_body_bytes);
        CHECK(got.requires_measurable == exp.requires_measurable);
        CHECK(got.path_class == exp.path_class);
    }
}

// ── 2. Segment-boundary matching ──────────────────────────────────────────

TEST_CASE("resolve_body_cap: /api/v1/bundlesevil is NOT the bundles entry — segment boundary",
          "[body_cap]") {
    // The architect-named collision: a plain starts_with would let this
    // through onto the 70 MiB bundles cap instead of the 4 MiB default.
    const auto got = resolve_body_cap("POST", "/api/v1/bundlesevil");
    CHECK(got.path_class == "default");
    CHECK(got.max_body_bytes == 4u * 1024 * 1024);
}

TEST_CASE("body_cap_prefix_matches: exact length, boundary, and non-boundary cases",
          "[body_cap]") {
    CHECK(body_cap_prefix_matches("/api/v1/bundles", "/api/v1/bundles"));       // exact
    CHECK(body_cap_prefix_matches("/api/v1/bundles/abc", "/api/v1/bundles"));   // '/' boundary
    CHECK_FALSE(body_cap_prefix_matches("/api/v1/bundlesevil", "/api/v1/bundles")); // no boundary
    CHECK(body_cap_prefix_matches("/scim/v2/Users", "/scim/v2/"));              // prefix ends in '/'
    CHECK_FALSE(body_cap_prefix_matches("/api/v1", "/api/v1/bundles"));         // too short
}

// ── 3. Method discrimination ──────────────────────────────────────────────

TEST_CASE("resolve_body_cap: same prefix, different method -> different entry",
          "[body_cap]") {
    // The motivating real-world case (file header, and the intro to this
    // brief): rest_api_v1.cpp:7759 POST vs :7904 regex PUT on the SAME
    // guaranteed-state prefix. Only POST has an explicit entry in the
    // table; GET on the identical literal prefix must NOT inherit it.
    const auto post = resolve_body_cap("POST", "/api/v1/guaranteed-state/rules");
    CHECK(post.path_class == "guardian_rule_authoring");
    CHECK(post.max_body_bytes == 16u * 1024 * 1024);

    const auto get = resolve_body_cap("GET", "/api/v1/guaranteed-state/rules");
    CHECK(get.path_class == "default");
    CHECK(get.max_body_bytes == 4u * 1024 * 1024);

    // SCIM: PATCH and PUT are in the table; DELETE (no route-registered
    // body) is not, and must fall through rather than silently inherit.
    const auto scim_patch = resolve_body_cap("PATCH", "/scim/v2/Users/deadbeef");
    CHECK(scim_patch.path_class == "scim");
    const auto scim_delete = resolve_body_cap("DELETE", "/scim/v2/Users/deadbeef");
    CHECK(scim_delete.path_class == "default");
}

// ── 4. Longest match wins ─────────────────────────────────────────────────

TEST_CASE("resolve_body_cap: longest matching prefix wins over the catch-all default",
          "[body_cap]") {
    // "/scim/v2/" (64 KiB, method-specific) and "" (the catch-all default,
    // ANY method, 4 MiB) BOTH match "/scim/v2/Users" for POST — the longer,
    // more specific entry must win.
    const auto got = resolve_body_cap("POST", "/scim/v2/Users");
    CHECK(got.path_class == "scim");
    CHECK(got.max_body_bytes == 64u * 1024);

    // Same principle for /mcp/ vs the default.
    const auto mcp = resolve_body_cap("PUT", "/mcp/v1/");
    CHECK(mcp.path_class == "mcp");
}

// ── 5. Unlisted path -> non-zero catch-all default ────────────────────────

TEST_CASE("resolve_body_cap: an unlisted path resolves to the non-zero catch-all default",
          "[body_cap]") {
    const auto got = resolve_body_cap("POST", "/api/v1/totally-unknown-route-xyz");
    CHECK(got.path_class == "default");
    CHECK(got.max_body_bytes > 0);
    CHECK(got.max_body_bytes == 4u * 1024 * 1024);
    CHECK_FALSE(got.requires_measurable);
}

// ── 6. Every cap is non-zero; the path_class label set is finite and locked ──

TEST_CASE("kBodyCapTable: every entry's cap is non-zero", "[body_cap]") {
    for (const auto& entry : kBodyCapTable) {
        INFO("path_class=" << entry.path_class);
        CHECK(entry.max_body_bytes > 0);
    }
}

TEST_CASE("kBodyCapTable: the path_class label set is exactly the documented, finite set",
          "[body_cap]") {
    std::set<std::string> got;
    for (const auto& entry : kBodyCapTable)
        got.insert(std::string(entry.path_class));

    std::set<std::string> expected;
    for (auto label : kExpectedPathClasses)
        expected.insert(std::string(label));

    CHECK(got == expected);
}

TEST_CASE("kBodyCapTable: the row count is locked", "[body_cap]") {
    // Independent of the label-set check above: a new row using an EXISTING
    // label (e.g. a second SCIM method already covered) would pass that
    // check while still silently growing the table. 18 = mcp(1) +
    // bundles(1) + ota_upload(1) + ca_import_chain(1) +
    // ca_import_chain_dashboard(1) + plugin_trust_bundle(1) + scim(3:
    // POST/PUT/PATCH) + saml_acs(1) + response_templates(2: POST/PUT) +
    // tar_dashboard_sql(1) + tar_result_set_sql(1) +
    // guardian_rule_authoring(1) + workflow_yaml(1) + product_pack_yaml(1) +
    // default(1).
    CHECK(std::size(kBodyCapTable) == 18);
}

// ── 7. requires_measurable: ON for /mcp/, OFF for the named public classes ──

TEST_CASE("resolve_body_cap: requires_measurable is ON only for /mcp/", "[body_cap]") {
    CHECK(resolve_body_cap("POST", "/mcp/v1/").requires_measurable);
    CHECK(resolve_body_cap("GET", "/mcp/v1/").requires_measurable);

    // Public REST (bundles), SCIM, certificate import (REST + dashboard),
    // product-pack/workflow authoring, and OTA upload all default OFF — see
    // the file header's rationale (chunked is legal HTTP; no client
    // population has been tested against a hard Content-Length contract on
    // these routes yet).
    CHECK_FALSE(resolve_body_cap("POST", "/api/v1/bundles").requires_measurable);
    CHECK_FALSE(resolve_body_cap("POST", "/scim/v2/Users").requires_measurable);
    CHECK_FALSE(resolve_body_cap("POST", "/api/v1/ca/import-chain").requires_measurable);
    CHECK_FALSE(resolve_body_cap("POST", "/api/settings/ca/import-chain").requires_measurable);
    CHECK_FALSE(resolve_body_cap("POST", "/api/workflows").requires_measurable);
    CHECK_FALSE(resolve_body_cap("POST", "/api/product-packs").requires_measurable);
    CHECK_FALSE(resolve_body_cap("POST", "/api/settings/updates/upload").requires_measurable);
    CHECK_FALSE(resolve_body_cap("POST", "/api/v1/totally-unknown-route-xyz").requires_measurable);
}
