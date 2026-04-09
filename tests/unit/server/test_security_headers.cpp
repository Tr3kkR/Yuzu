/**
 * test_security_headers.cpp — Unit tests for HTTP security response headers (SOC2-C1, #310).
 *
 * Covers:
 *   - validate_csp_extra_sources: accept/reject grammar
 *   - build_csp: default + extras + HTTPS gating
 *   - build_permissions_policy: deny-all baseline
 *   - build_referrer_policy: strict-origin-when-cross-origin
 *
 * The pure-function shape of these helpers makes the tests double as a
 * regression guard for the documented CSP string in
 * docs/user-manual/security-hardening.md (CA-1 from governance review).
 */

#include "security_headers.hpp"

#include <httplib.h>

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <chrono>
#include <string>
#include <string_view>
#include <thread>

using namespace yuzu::server::security;
using Catch::Matchers::ContainsSubstring;

// ── validate_csp_extra_sources: accept ──────────────────────────────────────

TEST_CASE("validate_csp_extra_sources: empty input is accepted",
          "[security-headers][csp][validate]") {
    auto r = validate_csp_extra_sources("");
    REQUIRE(r.has_value());
    CHECK(r->empty());
}

TEST_CASE("validate_csp_extra_sources: single https URL",
          "[security-headers][csp][validate]") {
    auto r = validate_csp_extra_sources("https://cdn.example.com");
    REQUIRE(r.has_value());
    CHECK(*r == "https://cdn.example.com");
}

TEST_CASE("validate_csp_extra_sources: multiple URLs are normalised",
          "[security-headers][csp][validate]") {
    auto r = validate_csp_extra_sources("https://cdn.example.com   https://beacon.example.com");
    REQUIRE(r.has_value());
    CHECK(*r == "https://cdn.example.com https://beacon.example.com");
}

TEST_CASE("validate_csp_extra_sources: leading/trailing whitespace trimmed",
          "[security-headers][csp][validate]") {
    auto r = validate_csp_extra_sources("   https://example.com   ");
    REQUIRE(r.has_value());
    CHECK(*r == "https://example.com");
}

TEST_CASE("validate_csp_extra_sources: whitespace-only input is treated as empty",
          "[security-headers][csp][validate]") {
    auto r = validate_csp_extra_sources("    ");
    REQUIRE(r.has_value());
    CHECK(r->empty());
}

TEST_CASE("validate_csp_extra_sources: tab is valid whitespace",
          "[security-headers][csp][validate]") {
    auto r = validate_csp_extra_sources("https://a.example\thttps://b.example");
    REQUIRE(r.has_value());
    CHECK(*r == "https://a.example https://b.example");
}

TEST_CASE("validate_csp_extra_sources: scheme-only sources",
          "[security-headers][csp][validate]") {
    for (auto scheme : {"https:", "http:", "data:", "blob:", "ws:", "wss:"}) {
        auto r = validate_csp_extra_sources(scheme);
        REQUIRE(r.has_value());
        CHECK(*r == scheme);
    }
}

TEST_CASE("validate_csp_extra_sources: wildcard hosts",
          "[security-headers][csp][validate]") {
    auto r = validate_csp_extra_sources("*.googleusercontent.com *.cdn.example.com");
    REQUIRE(r.has_value());
    CHECK(*r == "*.googleusercontent.com *.cdn.example.com");
}

TEST_CASE("validate_csp_extra_sources: bare hosts and host:port",
          "[security-headers][csp][validate]") {
    auto r = validate_csp_extra_sources("api.example.com cdn.example.com:8443");
    REQUIRE(r.has_value());
    CHECK(*r == "api.example.com cdn.example.com:8443");
}

TEST_CASE("validate_csp_extra_sources: 'self' and 'none' keywords",
          "[security-headers][csp][validate]") {
    auto r = validate_csp_extra_sources("'self' 'none'");
    REQUIRE(r.has_value());
    CHECK(*r == "'self' 'none'");
}

TEST_CASE("validate_csp_extra_sources: hash and nonce expressions",
          "[security-headers][csp][validate]") {
    auto r = validate_csp_extra_sources(
        "'sha256-abc123==' 'sha384-def456==' 'sha512-ghi789==' 'nonce-rAnd0m'");
    REQUIRE(r.has_value());
    CHECK(*r == "'sha256-abc123==' 'sha384-def456==' 'sha512-ghi789==' 'nonce-rAnd0m'");
}

// ── validate_csp_extra_sources: reject ──────────────────────────────────────

TEST_CASE("validate_csp_extra_sources: rejects CR control byte",
          "[security-headers][csp][validate][security]") {
    auto r = validate_csp_extra_sources("https://example.com\rInjected: header");
    REQUIRE_FALSE(r.has_value());
    CHECK_THAT(r.error(), ContainsSubstring("control byte"));
}

TEST_CASE("validate_csp_extra_sources: rejects LF control byte",
          "[security-headers][csp][validate][security]") {
    auto r = validate_csp_extra_sources("https://example.com\nInjected: header");
    REQUIRE_FALSE(r.has_value());
    CHECK_THAT(r.error(), ContainsSubstring("control byte"));
}

TEST_CASE("validate_csp_extra_sources: rejects NUL byte",
          "[security-headers][csp][validate][security]") {
    std::string input = "https://example.com";
    input.push_back('\0');
    input += "extra";
    auto r = validate_csp_extra_sources(input);
    REQUIRE_FALSE(r.has_value());
    CHECK_THAT(r.error(), ContainsSubstring("control byte"));
}

TEST_CASE("validate_csp_extra_sources: rejects DEL byte",
          "[security-headers][csp][validate][security]") {
    std::string input = "https://example.com";
    input.push_back(0x7F);
    auto r = validate_csp_extra_sources(input);
    REQUIRE_FALSE(r.has_value());
    CHECK_THAT(r.error(), ContainsSubstring("control byte"));
}

TEST_CASE("validate_csp_extra_sources: control-byte error reports correct position",
          "[security-headers][csp][validate][security]") {
    // Regression test: an earlier draft computed the position from a copy
    // of the byte in a range-for loop, producing garbage offsets.
    auto r = validate_csp_extra_sources("ab\rcd");
    REQUIRE_FALSE(r.has_value());
    CHECK_THAT(r.error(), ContainsSubstring("0x0d"));
    CHECK_THAT(r.error(), ContainsSubstring("at position 2"));
}

TEST_CASE("validate_csp_extra_sources: rejects semicolon (CSP directive injection)",
          "[security-headers][csp][validate][security]") {
    auto r = validate_csp_extra_sources("https://ok.example;form-action 'none'");
    REQUIRE_FALSE(r.has_value());
    CHECK_THAT(r.error(), ContainsSubstring("not a valid CSP source"));
}

TEST_CASE("validate_csp_extra_sources: rejects comma",
          "[security-headers][csp][validate][security]") {
    auto r = validate_csp_extra_sources("https://a.example,https://b.example");
    REQUIRE_FALSE(r.has_value());
    CHECK_THAT(r.error(), ContainsSubstring("not a valid CSP source"));
}

TEST_CASE("validate_csp_extra_sources: rejects 'unsafe-eval' keyword",
          "[security-headers][csp][validate][security]") {
    auto r = validate_csp_extra_sources("'unsafe-eval'");
    REQUIRE_FALSE(r.has_value());
    CHECK_THAT(r.error(), ContainsSubstring("not a valid CSP source"));
}

TEST_CASE("validate_csp_extra_sources: rejects 'unsafe-inline' keyword",
          "[security-headers][csp][validate][security]") {
    // Operators must not be able to weaken the default 'unsafe-inline'
    // posture via this flag — it's already in the baked-in default for
    // script-src and style-src, but allowing operators to add it elsewhere
    // would be a foot-gun.
    auto r = validate_csp_extra_sources("'unsafe-inline'");
    REQUIRE_FALSE(r.has_value());
    CHECK_THAT(r.error(), ContainsSubstring("not a valid CSP source"));
}

TEST_CASE("validate_csp_extra_sources: rejects 'strict-dynamic' keyword",
          "[security-headers][csp][validate][security]") {
    auto r = validate_csp_extra_sources("'strict-dynamic'");
    REQUIRE_FALSE(r.has_value());
    CHECK_THAT(r.error(), ContainsSubstring("not a valid CSP source"));
}

TEST_CASE("validate_csp_extra_sources: rejects unbalanced quotes",
          "[security-headers][csp][validate][security]") {
    auto r = validate_csp_extra_sources("'self");
    REQUIRE_FALSE(r.has_value());
    CHECK_THAT(r.error(), ContainsSubstring("not a valid CSP source"));
}

TEST_CASE("validate_csp_extra_sources: rejects stray quote in unquoted token",
          "[security-headers][csp][validate][security]") {
    auto r = validate_csp_extra_sources("https://exa'mple.com");
    REQUIRE_FALSE(r.has_value());
    CHECK_THAT(r.error(), ContainsSubstring("not a valid CSP source"));
}

// ── build_csp: default ──────────────────────────────────────────────────────

TEST_CASE("build_csp: default produces all expected directives",
          "[security-headers][csp][build]") {
    const std::string csp = build_csp("", false);

    CHECK_THAT(csp, ContainsSubstring("default-src 'self'"));
    // HTMX is served from /static/htmx.js (embedded via static_js_bundle.cpp),
    // so script-src does NOT need to whitelist any external CDN.
    CHECK_THAT(csp, ContainsSubstring("script-src 'self' 'unsafe-inline'"));
    CHECK_THAT(csp, !ContainsSubstring("https://unpkg.com"));
    CHECK_THAT(csp, ContainsSubstring("style-src 'self' 'unsafe-inline'"));
    CHECK_THAT(csp, ContainsSubstring("img-src 'self' data:"));
    CHECK_THAT(csp, ContainsSubstring("connect-src 'self'"));
    CHECK_THAT(csp, ContainsSubstring("font-src 'self' data:"));
    CHECK_THAT(csp, ContainsSubstring("object-src 'none'"));
    CHECK_THAT(csp, ContainsSubstring("frame-ancestors 'none'"));
    CHECK_THAT(csp, ContainsSubstring("base-uri 'self'"));
    CHECK_THAT(csp, ContainsSubstring("form-action 'self'"));
}

TEST_CASE("build_csp: HTTPS adds upgrade-insecure-requests",
          "[security-headers][csp][build]") {
    const std::string http = build_csp("", false);
    const std::string https = build_csp("", true);

    CHECK_THAT(http, !ContainsSubstring("upgrade-insecure-requests"));
    CHECK_THAT(https, ContainsSubstring("upgrade-insecure-requests"));
}

TEST_CASE("build_csp: extras append to script/style/img/connect only",
          "[security-headers][csp][build]") {
    const std::string csp = build_csp("https://cdn.example.com", false);

    CHECK_THAT(csp, ContainsSubstring("script-src 'self' 'unsafe-inline' https://cdn.example.com;"));
    CHECK_THAT(csp, ContainsSubstring("style-src 'self' 'unsafe-inline' https://cdn.example.com;"));
    CHECK_THAT(csp, ContainsSubstring("img-src 'self' data: https://cdn.example.com;"));
    CHECK_THAT(csp, ContainsSubstring("connect-src 'self' https://cdn.example.com;"));

    // Extras must NOT leak into directives that don't take a source list
    CHECK_THAT(csp, !ContainsSubstring("font-src 'self' data: https://cdn.example.com"));
    CHECK_THAT(csp, !ContainsSubstring("object-src 'none' https://cdn.example.com"));
    CHECK_THAT(csp, !ContainsSubstring("frame-ancestors 'none' https://cdn.example.com"));
}

TEST_CASE("build_csp: multiple extras propagate to all four directives",
          "[security-headers][csp][build]") {
    const std::string csp =
        build_csp("https://cdn.example.com https://beacon.example.com", true);

    for (auto directive : {
             "script-src 'self' 'unsafe-inline' https://cdn.example.com https://beacon.example.com",
             "style-src 'self' 'unsafe-inline' https://cdn.example.com https://beacon.example.com",
             "img-src 'self' data: https://cdn.example.com https://beacon.example.com",
             "connect-src 'self' https://cdn.example.com https://beacon.example.com",
         }) {
        CHECK_THAT(csp, ContainsSubstring(directive));
    }
}

TEST_CASE("build_csp: empty extras leaves no stray whitespace",
          "[security-headers][csp][build]") {
    const std::string csp = build_csp("", false);
    CHECK_THAT(csp, !ContainsSubstring("'unsafe-inline' ;"));
    CHECK_THAT(csp, !ContainsSubstring("data: ;"));
    CHECK_THAT(csp, !ContainsSubstring("'self' ;"));
    CHECK_THAT(csp, !ContainsSubstring("  "));
}

TEST_CASE("build_csp: deterministic — same input → same output",
          "[security-headers][csp][build]") {
    CHECK(build_csp("", false) == build_csp("", false));
    CHECK(build_csp("https://x.example", true) == build_csp("https://x.example", true));
}

// ── build_permissions_policy ────────────────────────────────────────────────

TEST_CASE("build_permissions_policy: denies privileged hardware APIs",
          "[security-headers][permissions]") {
    const std::string pp = build_permissions_policy();

    for (auto api : {"camera=()", "microphone=()", "geolocation=()", "usb=()",
                     "payment=()", "magnetometer=()", "gyroscope=()",
                     "accelerometer=()", "midi=()"}) {
        CHECK_THAT(pp, ContainsSubstring(api));
    }
}

TEST_CASE("build_permissions_policy: permits same-origin fullscreen",
          "[security-headers][permissions]") {
    const std::string pp = build_permissions_policy();
    CHECK_THAT(pp, ContainsSubstring("fullscreen=(self)"));
}

// ── build_referrer_policy ───────────────────────────────────────────────────

TEST_CASE("build_referrer_policy: returns strict-origin-when-cross-origin",
          "[security-headers][referrer]") {
    CHECK(build_referrer_policy() == "strict-origin-when-cross-origin");
}

// ── HeaderBundle ────────────────────────────────────────────────────────────

TEST_CASE("HeaderBundle::make: builds all components",
          "[security-headers][bundle]") {
    auto bundle = HeaderBundle::make("https://cdn.example.com", true);

    CHECK(bundle.https_enabled);
    CHECK_THAT(bundle.csp, ContainsSubstring("https://cdn.example.com"));
    CHECK_THAT(bundle.csp, ContainsSubstring("upgrade-insecure-requests"));
    CHECK_THAT(bundle.permissions_policy, ContainsSubstring("camera=()"));
    CHECK(bundle.referrer_policy == "strict-origin-when-cross-origin");
}

TEST_CASE("HeaderBundle::apply: sets all six headers (HTTPS)",
          "[security-headers][bundle]") {
    auto bundle = HeaderBundle::make("", true);
    httplib::Response res;
    bundle.apply(res);

    CHECK(res.has_header("Content-Security-Policy"));
    CHECK(res.has_header("X-Frame-Options"));
    CHECK(res.has_header("X-Content-Type-Options"));
    CHECK(res.has_header("Referrer-Policy"));
    CHECK(res.has_header("Permissions-Policy"));
    CHECK(res.has_header("Strict-Transport-Security"));

    CHECK(res.get_header_value("X-Frame-Options") == "DENY");
    CHECK(res.get_header_value("X-Content-Type-Options") == "nosniff");
    CHECK(res.get_header_value("Strict-Transport-Security")
          == "max-age=31536000; includeSubDomains");
}

TEST_CASE("HeaderBundle::apply: omits HSTS on HTTP",
          "[security-headers][bundle]") {
    auto bundle = HeaderBundle::make("", false);
    httplib::Response res;
    bundle.apply(res);

    CHECK(res.has_header("Content-Security-Policy"));
    CHECK(res.has_header("X-Frame-Options"));
    CHECK(res.has_header("X-Content-Type-Options"));
    CHECK(res.has_header("Referrer-Policy"));
    CHECK(res.has_header("Permissions-Policy"));
    CHECK_FALSE(res.has_header("Strict-Transport-Security"));
}

// ── End-to-end integration: HeaderBundle through real httplib ──────────────
//
// Spins up a minimal httplib::Server with a /livez handler, registers a
// post-routing handler that calls HeaderBundle::apply (the same code path
// the production server uses in server.cpp), then sends a real HTTP request
// via httplib::Client and asserts every header is on the wire.
//
// This is the QA-2 regression guard from governance review: any future
// change that drops a header from HeaderBundle::apply will be caught here.

namespace {

struct HeadersTestServer {
    httplib::Server svr;
    std::thread server_thread;
    int port{0};

    void start(const HeaderBundle& bundle) {
        svr.Get("/livez", [](const httplib::Request&, httplib::Response& res) {
            res.set_content(R"({"status":"ok"})", "application/json");
        });
        svr.set_post_routing_handler(
            [bundle](const httplib::Request&, httplib::Response& res) {
                bundle.apply(res);
            });
        port = svr.bind_to_any_port("127.0.0.1");
        REQUIRE(port > 0);
        server_thread = std::thread([this]() { svr.listen_after_bind(); });
        for (int i = 0; i < 100; ++i) {
            if (svr.is_running()) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        REQUIRE(svr.is_running());
    }

    ~HeadersTestServer() {
        svr.stop();
        if (server_thread.joinable())
            server_thread.join();
    }
};

} // namespace

TEST_CASE("Integration: GET /livez carries all six headers (HTTPS bundle)",
          "[security-headers][integration]") {
    HeadersTestServer ts;
    ts.start(HeaderBundle::make("", true));

    httplib::Client cli("127.0.0.1", ts.port);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);

    auto r = cli.Get("/livez");
    REQUIRE(r);
    CHECK(r->status == 200);

    CHECK(r->has_header("Content-Security-Policy"));
    CHECK_THAT(r->get_header_value("Content-Security-Policy"),
               ContainsSubstring("default-src 'self'"));
    CHECK_THAT(r->get_header_value("Content-Security-Policy"),
               ContainsSubstring("upgrade-insecure-requests"));

    CHECK(r->get_header_value("X-Frame-Options") == "DENY");
    CHECK(r->get_header_value("X-Content-Type-Options") == "nosniff");
    CHECK(r->get_header_value("Referrer-Policy") == "strict-origin-when-cross-origin");

    CHECK(r->has_header("Permissions-Policy"));
    CHECK_THAT(r->get_header_value("Permissions-Policy"),
               ContainsSubstring("camera=()"));

    CHECK(r->get_header_value("Strict-Transport-Security")
          == "max-age=31536000; includeSubDomains");
}

TEST_CASE("Integration: HTTP-mode response omits HSTS",
          "[security-headers][integration]") {
    HeadersTestServer ts;
    ts.start(HeaderBundle::make("", false));

    httplib::Client cli("127.0.0.1", ts.port);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);

    auto r = cli.Get("/livez");
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK_FALSE(r->has_header("Strict-Transport-Security"));

    // Sanity-check the other five headers are still present
    CHECK(r->has_header("Content-Security-Policy"));
    CHECK(r->has_header("X-Frame-Options"));
    CHECK(r->has_header("X-Content-Type-Options"));
    CHECK(r->has_header("Referrer-Policy"));
    CHECK(r->has_header("Permissions-Policy"));
}

TEST_CASE("Integration: --csp-extra-sources surfaces in HTTP response CSP",
          "[security-headers][integration]") {
    HeadersTestServer ts;
    ts.start(HeaderBundle::make("https://cdn.example.com https://beacon.example.com", true));

    httplib::Client cli("127.0.0.1", ts.port);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);

    auto r = cli.Get("/livez");
    REQUIRE(r);
    auto csp = r->get_header_value("Content-Security-Policy");
    CHECK_THAT(csp, ContainsSubstring("https://cdn.example.com"));
    CHECK_THAT(csp, ContainsSubstring("https://beacon.example.com"));
}
