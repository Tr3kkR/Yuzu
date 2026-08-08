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
#include "web_utils.hpp"

#include <httplib.h>

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <set>
#include <string>
#include <string_view>
#include <thread>

#if defined(__has_feature)
#  if __has_feature(thread_sanitizer)
#    define YUZU_TSAN_BUILD 1
#  endif
#endif
#if defined(__SANITIZE_THREAD__)
#  define YUZU_TSAN_BUILD 1
#endif

#ifndef _WIN32
#  include <netinet/in.h>
#  include <sys/socket.h>
#  include <sys/time.h>
#  include <unistd.h>
#endif

using yuzu::server::BodyCapMatch;
using yuzu::server::body_cap_prefix_matches;
using yuzu::server::body_unmeasurable;
using yuzu::server::content_length_for_body_cap;
using yuzu::server::has_non_identity_content_encoding;
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
    // server.cpp:10809 — unbounded by design, kept at httplib's backstop.
    {"POST",   "/api/export/json-to-csv",                 100u * 1024 * 1024, false, "json_to_csv_export"},
    // server.cpp:9258 — no aggregate contract, reasoned to realistic scale.
    {"POST",   "/api/nvd/match",                          8u * 1024 * 1024,   false, "nvd_match"},
    // ca_routes.cpp:24,:516.
    {"POST",   "/api/v1/ca/import-chain",                 256u * 1024,        false, "ca_import_chain"},
    // ca_routes.cpp:24 kMaxRevokeBody,:394.
    {"POST",   "/api/v1/ca/revoke",                       64u * 1024,         false, "ca_revoke"},
    // kek_routes.cpp:46 kMaxKekBody,:54 validate_empty_body — shared by rotate+rewrap.
    {"POST",   "/api/v1/secrets/kek/rotate",               64u * 1024,        false, "kek_ops"},
    {"POST",   "/api/v1/secrets/kek/rewrap",               64u * 1024,        false, "kek_ops"},
    // ca_routes.cpp:727 dashboard twin, doubled for form-encoding overhead.
    {"POST",   "/api/settings/ca/import-chain",           512u * 1024,        false, "ca_import_chain_dashboard"},
    // settings_routes.cpp:3445,:3461, doubled for multipart framing overhead.
    {"POST",   "/api/settings/plugin-signing/upload",     512u * 1024,        false, "plugin_trust_bundle"},
    // scim_routes.cpp:65 kMaxBodyBytes. ANY method — see the method-independence
    // case below for why this is deliberately not scoped to the mutating verbs.
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
    // dashboard_routes.cpp:866 `sql.size() > 4096` on the DECODED field;
    // 16 KiB = 3x4096 worst-case percent-encoding + 4 KiB field/framing margin.
    {"POST",   "/api/dashboard/tar-execute",              16u * 1024,         false, "tar_dashboard_sql"},
    // rest_api_v1.cpp:6802 `sql.size() > 100000` on the JSON-parsed field;
    // 200 KiB = 2x100000 for JSON-escaping headroom plus the other JSON keys.
    {"POST",   "/api/v1/result-sets/from-tar-query",      200u * 1024,        false, "tar_result_set_sql"},
    // rest_api_v1.cpp:7759,:7842 — explicit generous, no contract yet.
    {"POST",   "/api/v1/guaranteed-state/rules",          16u * 1024 * 1024,  false, "guardian_rule_authoring"},
    // rest_api_v1.cpp:7904 regex PUT update — same class, same bound.
    {"PUT",    "/api/v1/guaranteed-state/rules/rule-1",   16u * 1024 * 1024,  false, "guardian_rule_authoring"},
    // workflow_routes.cpp:1023.
    {"POST",   "/api/workflows",                          16u * 1024 * 1024,  false, "workflow_yaml"},
    // workflow_routes.cpp:1746 / product_pack_store.cpp:122.
    {"POST",   "/api/product-packs",                      16u * 1024 * 1024,  false, "product_pack_yaml"},
    // server.cpp:11130 -> instruction_store.cpp:954,:434 — no aggregate
    // contract (yaml_source is capped but responseTemplates-as-array is not).
    {"POST",   "/api/instructions/import",                16u * 1024 * 1024,  false, "instruction_import"},
    // instruction_yaml.cpp:165 `yaml_source.size() > 1048576` on the
    // DECODED field; 3149824 = 3x1048576 worst-case percent-encoding +
    // 4 KiB field/framing margin. Three form-encoded routes, one check.
    {"POST",   "/api/instructions/yaml",                  3149824u,           false, "instruction_yaml"},
    {"POST",   "/api/instructions/validate-yaml",          3149824u,           false, "instruction_yaml"},
    {"POST",   "/fragments/instructions/yaml-preview",    3149824u,           false, "instruction_yaml"},
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
    "json_to_csv_export",
    "nvd_match",
    "ca_import_chain",
    "ca_revoke",
    "kek_ops",
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
    "instruction_import",
    "instruction_yaml",
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

    // SCIM is the DELIBERATE COUNTER-EXAMPLE: its row is kBodyCapAnyMethod,
    // so every verb on the prefix resolves to the same 64 KiB class.
    //
    // This previously asserted the opposite — that DELETE "must fall through
    // rather than silently inherit", on the stated grounds that DELETE has no
    // route-registered body. Both halves were wrong. SCIM DELETE routes are
    // real (scim_routes.cpp:1577, :2316), and an adversarial review showed the
    // method-scoping let any verb switch drop the whole prefix to the 4 MiB
    // catch-all, 64x this class's bound, on a prefix that is session-auth-
    // exempt and buffered before the in-handler bearer check. The test had
    // frozen that as intent. Kept inverted as a regression guard: narrowing
    // the row back to the mutating verbs re-breaks here.
    for (const auto* method : {"POST", "PUT", "PATCH", "DELETE", "OPTIONS", "GET"}) {
        const auto scim = resolve_body_cap(method, "/scim/v2/Users/deadbeef");
        INFO("method=" << method);
        CHECK(scim.path_class == "scim");
        CHECK(scim.max_body_bytes == 64u * 1024);
    }
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
    // check while still silently growing the table. 27 = mcp(1) +
    // bundles(1) + ota_upload(1) + json_to_csv_export(1) + nvd_match(1) +
    // ca_import_chain(1) + ca_revoke(1) +
    // kek_ops(1: one prefix entry covers both rotate and rewrap) +
    // ca_import_chain_dashboard(1) + plugin_trust_bundle(1) + scim(3:
    // POST/PUT/PATCH) + saml_acs(1) + response_templates(2: POST/PUT) +
    // tar_dashboard_sql(1) + tar_result_set_sql(1) +
    // guardian_rule_authoring(2: POST create + PUT update) +
    // workflow_yaml(1) + product_pack_yaml(1) + instruction_import(1) +
    // instruction_yaml(3: save/validate/preview) + default(1).
    CHECK(std::size(kBodyCapTable) == 25);
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

// ── 8. On-the-wire coverage for the D1-D4 hardening of the pre-routing
//       chokepoint (server.cpp `set_pre_routing_handler`) ───────────────────
//
// SKIPPED UNDER ThreadSanitizer (#438), same reasoning as
// test_mcp_body_cap.cpp: this deliberately exercises httplib::Server's
// middleware wiring, which crashes the TSan build.
//
// This fixture replicates the UNIFIED pre-routing decision server.cpp now
// makes (D1: one branch for every path, including /mcp/) using the same pure
// functions the production chokepoint calls — `resolve_body_cap`
// (body_cap_policy.hpp) and `body_unmeasurable` /
// `has_non_identity_content_encoding` (web_utils.hpp) — instead of the
// server.cpp lambda itself (which has no seam for in-process testing; see
// test_mcp_body_cap.cpp's header comment for why that gap is accepted). It
// deliberately does NOT reproduce the metric/log/A4-envelope/SCIM-envelope
// side effects — those are review-only at the call site, same convention as
// test_mcp_body_cap.cpp's own fixture — only the STATUS the decision reaches.
//
// D3 is additionally modelled by placing a probe-style early return (Get
// "/health" answers 200 unconditionally) AFTER this cap check, so a fixture
// bug that put the cap check back BELOW a probe exemption would show up as a
// false-negative here too. This models ONE of production's two call sites —
// `enforce_pre_auth_body_cap` is invoked inside server.cpp's probe branch
// (the shape mirrored here) and again after the on-behalf-of guard and rate
// limiter for every other route. The second call site is not modelled: those
// two guards are out of this fixture's scope.
#ifndef YUZU_TSAN_BUILD

namespace {

constexpr std::uint64_t kUnifiedTestCap = 4u * 1024 * 1024; // matches the real default cap

struct UnifiedBodyCapTestServer {
    httplib::Server svr;
    std::thread server_thread;
    int port{0};
    std::atomic<int> handler_calls{0};

    void start() {
        auto ok_handler = [this](const httplib::Request&, httplib::Response& res) {
            handler_calls.fetch_add(1);
            res.set_content(R"({"ok":true})", "application/json");
        };
        svr.Get("/api/v1/devices", ok_handler);
        svr.Post("/api/v1/devices", ok_handler);
        svr.Get("/health", ok_handler);
        svr.Post("/health", ok_handler);
        svr.Post("/mcp/v1/", ok_handler);

        svr.set_pre_routing_handler([this](const httplib::Request& req, httplib::Response& res)
                                        -> httplib::Server::HandlerResponse {
            // D1-D4, GENUINELY replicated (#2407 R2 hardening,
            // 2026-08-07): unified resolve_body_cap for EVERY method/path
            // (D2: no GET/HEAD exclusion), checked BEFORE the probe-style
            // early return below (D3). The Content-Length VALUE is read
            // via `content_length_for_body_cap` — the EXACT SAME function
            // server.cpp's production pre-routing handler calls — not a
            // second, independently-written expression that happens to
            // look similar. A prior version of this fixture called
            // `req.get_header_value_u64` directly here while production
            // hand-rolled a `std::from_chars` parse; the two disagreed on
            // an all-digit Content-Length above 2^64-1, and this fixture's
            // 777 assertions passed green with that CRITICAL bypass live
            // in the code it claimed to replicate. Routing both through
            // the one shared function makes that divergence structurally
            // impossible instead of something to keep re-verifying by
            // hand.
            const auto cap_match = resolve_body_cap(req.method, req.path);
            if (has_non_identity_content_encoding(req.get_header_value("Content-Encoding"))) {
                res.status = 415;
                return httplib::Server::HandlerResponse::Handled;
            }
            const bool unmeasurable = body_unmeasurable(
                req.method, req.has_header("Content-Length"),
                req.get_header_value("Transfer-Encoding"));
            const bool refuse_unmeasurable = unmeasurable && cap_match.requires_measurable;
            const bool oversize =
                !unmeasurable && content_length_for_body_cap(req) > cap_match.max_body_bytes;
            if (refuse_unmeasurable || oversize) {
                res.status = refuse_unmeasurable ? 411 : 413;
                return httplib::Server::HandlerResponse::Handled;
            }
            // Everything below this point (onbehalf-of, rate limiting, the
            // real probe exemption in production) is out of scope for this
            // fixture — /health falls through to the SAME Unhandled as any
            // other admitted path. What matters is that it only gets here
            // AFTER the cap check above ran unconditionally (D3).
            return httplib::Server::HandlerResponse::Unhandled;
        });
        port = svr.bind_to_any_port("127.0.0.1");
        REQUIRE(port > 0);
        server_thread = std::thread([this]() { svr.listen_after_bind(); });
        svr.wait_until_ready();
        REQUIRE(svr.is_running());
    }

    ~UnifiedBodyCapTestServer() {
        // Ordering mirrors test_mcp_body_cap.cpp's BodyCapTestServer dtor —
        // see that file's comment for why the naive version deadlocks.
        if (server_thread.joinable()) {
            svr.wait_until_ready();
            svr.stop();
            server_thread.join();
        }
    }
};

#ifndef _WIN32
/// Send a raw request declaring `Content-Length` without ever sending that
/// many body bytes, and return the first bytes of the response. Proves the
/// REJECTION happens before the (never-sent) body would be read — the same
/// technique test_mcp_body_cap.cpp uses, needed here because httplib::Client
/// has no `Get(path, body, ...)` overload to declare a body on a GET.
std::string raw_request_status_line(int port, const std::string& request_head) {
    struct Fd {
        int v;
        explicit Fd(int f) : v(f) {}
        ~Fd() {
            if (v >= 0)
                ::close(v);
        }
        Fd(const Fd&) = delete;
        Fd& operator=(const Fd&) = delete;
    } sock{::socket(AF_INET, SOCK_STREAM, 0)};
    REQUIRE(sock.v >= 0);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    REQUIRE(::connect(sock.v, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);

    timeval tv{};
    tv.tv_sec = 10;
    REQUIRE(::setsockopt(sock.v, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0);

    REQUIRE(::send(sock.v, request_head.data(), request_head.size(), 0) ==
            static_cast<ssize_t>(request_head.size()));

    char buf[256] = {};
    const ssize_t n = ::recv(sock.v, buf, sizeof(buf) - 1, 0);
    INFO("recv returned " << n << " bytes: " << std::string(buf, n > 0 ? n : 0));
    REQUIRE(n > 0);
    return std::string(buf, static_cast<size_t>(n));
}
#endif // !_WIN32

} // namespace

#ifndef _WIN32
TEST_CASE("Pre-routing body cap: a GET with an oversized declared Content-Length is "
          "rejected (D2)",
          "[body_cap][mcp][bounds][integration]") {
    // The exclusion this pins the removal of was justified in-code by "GET
    // never carries a body" — false (web_utils.hpp already documented the
    // opposite; httplib's expect_content() is true for any method with
    // Content-Length > 0). A GET declaring an oversized Content-Length must
    // be rejected exactly like a POST, and — same load-bearing assumption as
    // the MCP raw-socket test — WITHOUT ever reading the (unsent) body.
    UnifiedBodyCapTestServer ts;
    ts.start();

    const std::string req = "GET /api/v1/devices HTTP/1.1\r\n"
                            "Host: 127.0.0.1\r\n"
                            "Content-Length: 104857600\r\n"
                            "\r\n"; // ...and then nothing.
    const auto resp = raw_request_status_line(ts.port, req);
    CHECK(resp.starts_with("HTTP/1.1 413"));
    CHECK(ts.handler_calls.load() == 0);
}

TEST_CASE("Pre-routing body cap: POST /health with an oversized declared Content-Length "
          "is rejected (D3)",
          "[body_cap][mcp][bounds][integration]") {
    // /health is one of the four paths that ALSO skip the 401 gate — before
    // D3 moved the cap ahead of that exemption, this was the last
    // unauthenticated 100 MiB buffer on the server. The fixture's probe-style
    // Unhandled return for "/health" only fires below the cap check, so this
    // proves the ORDERING, not just that some cap exists somewhere.
    UnifiedBodyCapTestServer ts;
    ts.start();

    const std::string req = "POST /health HTTP/1.1\r\n"
                            "Host: 127.0.0.1\r\n"
                            "Content-Length: 104857600\r\n"
                            "\r\n";
    const auto resp = raw_request_status_line(ts.port, req);
    CHECK(resp.starts_with("HTTP/1.1 413"));
    CHECK(ts.handler_calls.load() == 0);
}
#endif // !_WIN32

TEST_CASE("Pre-routing body cap: a non-identity Content-Encoding is refused regardless "
          "of class (D4)",
          "[body_cap][mcp][bounds][integration]") {
    UnifiedBodyCapTestServer ts;
    ts.start();

    httplib::Client cli("127.0.0.1", ts.port);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);

    // A class with requires_measurable == false (the "default" catch-all,
    // matched by /api/v1/devices) — proves D4 does NOT gate on that bit.
    auto r1 = cli.Post("/api/v1/devices", {{"Content-Encoding", "gzip"}}, "small body",
                       "application/json");
    REQUIRE(r1);
    CHECK(r1->status == 415);
    CHECK(ts.handler_calls.load() == 0);

    // /mcp/ (requires_measurable == true) reaches the SAME refusal via the
    // SAME first check, not the class-specific unmeasurable path (411).
    auto r2 = cli.Post("/mcp/v1/", {{"Content-Encoding", "br"}}, "small body",
                       "application/json");
    REQUIRE(r2);
    CHECK(r2->status == 415);
    CHECK(ts.handler_calls.load() == 0);

    // A request with NO Content-Encoding header (ordinary traffic) is still
    // admitted (sanity: the check is encoding-VALUE aware, not "any
    // Content-Encoding header present"). Deliberately NOT tested by sending
    // an EXPLICIT `Content-Encoding: identity` end-to-end here: doing so
    // during development surfaced a SEPARATE, PRE-EXISTING httplib quirk,
    // unrelated to this change — `detail::create_decompressor` (httplib.h:
    // 6717) recognises only gzip/deflate/br/zstd and returns null for
    // anything else INCLUDING the literal string "identity", so httplib's
    // own content-reader 415s an explicit `identity` value for any ordinary
    // route's body read (`prepare_content_receiver`, httplib.h:6980-6986) —
    // completely independent of `has_non_identity_content_encoding`, which
    // correctly does NOT refuse it at THIS (pre-routing) chokepoint. That
    // downstream quirk is out of scope for #2407 and worth its own follow-up
    // (an explicit `identity` is a materially different declaration from
    // omitting the header, and RFC 7231 §3.1.2.1 lists it as valid), but
    // asserting past it here would make this test depend on unrelated
    // httplib internals rather than on the D4 decision under test.
    auto r3 = cli.Post("/api/v1/devices", "small body", "application/json");
    REQUIRE(r3);
    CHECK(r3->status == 200);
    CHECK(ts.handler_calls.load() == 1);
}

#ifndef _WIN32
TEST_CASE("Pre-routing body cap: /mcp/ still behaves as before through the unified path "
          "(rejections)",
          "[body_cap][mcp][bounds][integration]") {
    // Raw socket, not httplib::Client, for BOTH sub-cases below — declaring
    // a real 4 MiB+ Content-Length and then actually writing that many bytes
    // would block the client's write once the kernel socket buffers fill,
    // because (D5) a REJECTED request's body is never drained by the
    // server; the client can only finish writing once the server reads,
    // which for a 413/411 it never does. (Measured while writing this test:
    // that exact shape made an earlier version of this test time out.)
    // Declaring-without-sending sidesteps the deadlock and is the same
    // technique test_mcp_body_cap.cpp's own ordering test uses.
    UnifiedBodyCapTestServer ts;
    ts.start();

    {
        // Over the cap -> 413.
        const std::string req = "POST /mcp/v1/ HTTP/1.1\r\n"
                                "Host: 127.0.0.1\r\n"
                                "Content-Type: application/json\r\n"
                                "Content-Length: " +
                                std::to_string(kUnifiedTestCap + 1) + "\r\n\r\n";
        const auto resp = raw_request_status_line(ts.port, req);
        CHECK(resp.starts_with("HTTP/1.1 413"));
    }
    {
        // requires_measurable is still ON for /mcp/: chunked framing (no
        // Content-Length) is refused 411, not admitted up to the 100 MiB
        // backstop (the behaviour every OTHER class keeps, unchanged by D1).
        const std::string req = "POST /mcp/v1/ HTTP/1.1\r\n"
                                "Host: 127.0.0.1\r\n"
                                "Content-Type: application/json\r\n"
                                "Transfer-Encoding: chunked\r\n\r\n";
        const auto resp = raw_request_status_line(ts.port, req);
        CHECK(resp.starts_with("HTTP/1.1 411"));
    }
    CHECK(ts.handler_calls.load() == 0);
}
#endif // !_WIN32

TEST_CASE("Pre-routing body cap: /mcp/ still behaves as before through the unified path "
          "(admits exactly at the cap)",
          "[body_cap][mcp][bounds][integration]") {
    UnifiedBodyCapTestServer ts;
    ts.start();

    httplib::Client cli("127.0.0.1", ts.port);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);

    auto at_cap = cli.Post("/mcp/v1/", std::string(kUnifiedTestCap, 'x'), "application/json");
    REQUIRE(at_cap);
    CHECK(at_cap->status == 200);
    CHECK(ts.handler_calls.load() == 1);
}

#ifndef _WIN32
TEST_CASE("Pre-routing body cap: an all-digit Content-Length above 2^64-1 is refused as "
          "oversize, not silently admitted as absent (#2407 R2 — the CRITICAL bypass)",
          "[body_cap][bounds][integration]") {
    // The defect this pins: `std::from_chars` reports
    // `result_out_of_range` for these two values and the pre-#2407-R1 code
    // folded that to `content_length = 0` ("no header present, don't
    // cap") — while httplib's own `is_numeric()` + `strtoull()` parser
    // (httplib.h:2769-2789) accepts the same all-digit string and returns
    // `SIZE_MAX`, which is what it ALSO uses to decide what it buffers.
    // `content_length_for_body_cap` (web_utils.hpp) now delegates to that
    // same accessor, so both values must resolve to "oversize" (413), on
    // the plain catch-all class, not just /mcp/.
    UnifiedBodyCapTestServer ts;
    ts.start();

    for (const std::string& overflow_value :
         {std::string("99999999999999999999999"), std::string("18446744073709551616")}) {
        const std::string req = "POST /api/v1/devices HTTP/1.1\r\n"
                                "Host: 127.0.0.1\r\n"
                                "Content-Type: application/json\r\n"
                                "Content-Length: " +
                                overflow_value + "\r\n\r\n";
        INFO("Content-Length: " << overflow_value);
        const auto resp = raw_request_status_line(ts.port, req);
        CHECK(resp.starts_with("HTTP/1.1 413"));
    }
    CHECK(ts.handler_calls.load() == 0);
}

TEST_CASE("Pre-routing body cap: a malformed (non-numeric) Content-Length is never "
          "silently admitted — refused end-to-end even where this gate alone reads it "
          "as absent (#2407 R2)",
          "[body_cap][bounds][integration]") {
    // `is_numeric()` (httplib.h:2769-2773) requires EVERY character to be
    // an ASCII digit, so each of these fails it and
    // `content_length_for_body_cap` reads them as 0 — matching httplib's
    // OWN accessor exactly (that is the point of #2407 R1/R2: one shared
    // function, not two that might disagree). A 0 reading is NOT oversize,
    // so THIS gate alone lets the request past as Unhandled. That is fine,
    // not a re-opened gap: httplib's own body reader
    // (`detail::read_content`, httplib.h:7057-7063) independently rejects
    // the SAME malformed header with its own `is_invalid_value` check and
    // answers 400 before any route handler runs — this test asserts THAT
    // end-to-end outcome, proving the request is refused somewhere in the
    // pipeline, never silently processed with an unbounded/unmeasured
    // body.
    UnifiedBodyCapTestServer ts;
    ts.start();

    for (const std::string& malformed_value :
         {std::string("-1"), std::string("+5"), std::string(" 12"), std::string("abc"),
          std::string("")}) {
        const std::string req = "POST /api/v1/devices HTTP/1.1\r\n"
                                "Host: 127.0.0.1\r\n"
                                "Content-Type: application/json\r\n"
                                "Content-Length: " +
                                malformed_value + "\r\n\r\n";
        INFO("Content-Length: '" << malformed_value << "'");
        const auto resp = raw_request_status_line(ts.port, req);
        // httplib itself answers 400 for an invalid Content-Length value
        // it cannot parse (is_invalid_value branch) before any handler
        // runs — accept a 4xx broadly (never 200/2xx) so this stays
        // resilient to which layer of the pipeline answers, while still
        // failing if the request were ever admitted through to the
        // handler.
        CHECK(!resp.starts_with("HTTP/1.1 2"));
    }
    CHECK(ts.handler_calls.load() == 0);
}

TEST_CASE("Pre-routing body cap: duplicate Content-Length headers cannot desync the "
          "gate's decision from httplib's own body read (#2407 R2)",
          "[body_cap][bounds][integration]") {
    // httplib's `Headers` is `std::unordered_multimap<..., case_ignore::hash,
    // case_ignore::equal_to>` (httplib.h:778-780) — an UNORDERED container,
    // not the ordered `std::multimap` an RFC 7230 "first occurrence" framing
    // might suggest. WHICH of two duplicate `Content-Length` values
    // `get_header_value_u64("Content-Length", 0, /*id=*/0)` resolves to is
    // therefore UNSPECIFIED by the C++ standard (hash-bucket insertion
    // order, not header-line order). Measured empirically against this
    // vcpkg baseline while writing this test (a standalone reproduction
    // against a real httplib::Server): `id=0` resolved to the LAST header
    // LINE sent, not the first — the opposite of what an ordered container,
    // or an RFC-literal reading, would give. This test deliberately does
    // NOT assert on that specific measurement, because it is an
    // IMPLEMENTATION detail that could shift with a future vcpkg bump, not
    // a contract. What it asserts instead is the SAFETY property that holds
    // regardless of which duplicate value httplib's bucket order happens to
    // prefer: `content_length_for_body_cap` (this gate) and httplib's own
    // body reader (httplib.h:7057-7061) call the IDENTICAL accessor with
    // the IDENTICAL id against the SAME already-parsed `Headers` object,
    // for the SAME single request — so whichever value "wins" is the SAME
    // value at BOTH call sites, deterministically, every time. There is no
    // pair of duplicate values where this gate's admit/refuse decision and
    // httplib's actual buffering decision can disagree.
    UnifiedBodyCapTestServer ts;
    ts.start();

    const std::string small_body = "ok";
    const std::string req = "POST /api/v1/devices HTTP/1.1\r\n"
                            "Host: 127.0.0.1\r\n"
                            "Content-Type: application/json\r\n"
                            "Content-Length: " +
                            std::to_string(small_body.size()) +
                            "\r\n"
                            "Content-Length: 99999999999999999999999\r\n\r\n" +
                            small_body;
    const auto resp = raw_request_status_line(ts.port, req);
    // Whichever duplicate value httplib's unordered_multimap resolves as
    // id=0: either it is the oversize one — refused here, 413, handler
    // never runs — or it is the small one — admitted, and httplib's ACTUAL
    // body read is then bounded to those `small_body.size()` bytes we
    // genuinely sent, so the handler runs normally, 200. Anything else
    // (a hang waiting on unsent bytes, a mid-read reset, a status neither
    // of these) would mean the gate and the real reader disagreed about
    // which duplicate to trust — the split-brain this test exists to rule
    // out.
    const bool refused = resp.starts_with("HTTP/1.1 413");
    const bool admitted = resp.starts_with("HTTP/1.1 200");
    INFO("response: " << resp);
    CHECK((refused || admitted));
    CHECK(ts.handler_calls.load() == (admitted ? 1 : 0));
}
#endif // !_WIN32

#endif // !YUZU_TSAN_BUILD
