/**
 * test_static_js_bundle.cpp — Unit tests for the embedded HTMX + HTMX-SSE
 * runtime bundles in server/core/src/static_js_bundle.cpp.
 *
 * Guards against:
 *   - Chunk-boundary corruption (size drift)
 *   - IDE reformatting that breaks raw-string-literal continuity
 *   - Accidental tampering with the embedded payload
 *   - Drift from upstream byte-identity (the served bundle should match
 *     what upstream HTMX 2.0.4 minified ships)
 *
 * Pinned upstream sizes (HTMX 2.0.4 minified, htmx-ext-sse 2.2.2):
 *   kHtmxJs = 50918 bytes
 *   kSseJs  = 8897 bytes
 *
 * If you intentionally update HTMX or htmx-ext-sse, regenerate
 * static_js_bundle.cpp via the chunking script and update the constants
 * below in lock-step.
 */

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <string>
#include <string_view>

// External symbols from server/core/src/static_js_bundle.cpp.
extern const std::string kHtmxJs;
extern const std::string kSseJs;

using Catch::Matchers::ContainsSubstring;

namespace {
constexpr std::size_t kExpectedHtmxBytes = 50918;
constexpr std::size_t kExpectedSseBytes  = 8897;
} // namespace

// ── HTMX core ───────────────────────────────────────────────────────────────

TEST_CASE("static_js_bundle: kHtmxJs has expected pinned size",
          "[static-js][htmx]") {
    CHECK(kHtmxJs.size() == kExpectedHtmxBytes);
}

TEST_CASE("static_js_bundle: kHtmxJs starts with HTMX 2.0.4 IIFE preamble",
          "[static-js][htmx]") {
    // The minified bundle starts with `var htmx=function(){"use strict";...`
    REQUIRE(kHtmxJs.size() >= 30);
    CHECK(std::string_view(kHtmxJs).substr(0, 9) == "var htmx=");
    CHECK_THAT(kHtmxJs, ContainsSubstring("\"use strict\""));
}

TEST_CASE("static_js_bundle: kHtmxJs contains the version string",
          "[static-js][htmx]") {
    CHECK_THAT(kHtmxJs, ContainsSubstring("version:\"2.0.4\""));
}

TEST_CASE("static_js_bundle: kHtmxJs contains core public API symbols",
          "[static-js][htmx]") {
    // Sanity-check that core HTMX surface is present and the chunk
    // boundaries didn't lose anything mid-payload. The minified runtime
    // assigns the public API onto a Q object via `Q.<name>=<short>;`
    // statements after the IIFE body, so we look for those exact tokens.
    for (auto needle : {
             "Q.onLoad",
             "Q.process",
             "Q.ajax",
             "Q.swap",
             "Q.defineExtension",
             "Q.removeExtension",
             "Q.find",
             "Q.closest",
         }) {
        CAPTURE(needle);
        CHECK_THAT(kHtmxJs, ContainsSubstring(needle));
    }
}

TEST_CASE("static_js_bundle: kHtmxJs has no embedded NULs or unexpected delimiter",
          "[static-js][htmx]") {
    // Raw string literal delimiter must not appear inside the payload —
    // would silently corrupt the file. The static-init concat is also a
    // place where a stray NUL would terminate the std::string early.
    CHECK(kHtmxJs.find('\0') == std::string::npos);
    CHECK(kHtmxJs.find(")HTMXEOF") == std::string::npos);
}

TEST_CASE("static_js_bundle: kHtmxJs has no leading whitespace",
          "[static-js][htmx]") {
    // Regression guard: an earlier draft preserved a `\n` at byte 0
    // because `R"HTMXEOF(` was followed by a newline before the payload.
    // The reassembled bundle should be byte-identical to upstream, which
    // begins with `var` directly.
    REQUIRE_FALSE(kHtmxJs.empty());
    CHECK(kHtmxJs.front() == 'v');
    CHECK(kHtmxJs.front() != '\n');
    CHECK(kHtmxJs.front() != ' ');
}

// ── HTMX-SSE extension ──────────────────────────────────────────────────────

TEST_CASE("static_js_bundle: kSseJs has expected pinned size",
          "[static-js][sse]") {
    CHECK(kSseJs.size() == kExpectedSseBytes);
}

TEST_CASE("static_js_bundle: kSseJs starts with the SSE banner comment",
          "[static-js][sse]") {
    REQUIRE(kSseJs.size() >= 30);
    CHECK(std::string_view(kSseJs).substr(0, 2) == "/*");
    CHECK_THAT(kSseJs, ContainsSubstring("Server Sent Events Extension"));
}

TEST_CASE("static_js_bundle: kSseJs registers the 'sse' extension",
          "[static-js][sse]") {
    // The extension self-registers via htmx.defineExtension('sse', {...}).
    CHECK_THAT(kSseJs, ContainsSubstring("htmx.defineExtension"));
    CHECK_THAT(kSseJs, ContainsSubstring("'sse'"));
}

TEST_CASE("static_js_bundle: kSseJs has no embedded NULs or stray delimiter",
          "[static-js][sse]") {
    CHECK(kSseJs.find('\0') == std::string::npos);
    CHECK(kSseJs.find(")SSEEOF") == std::string::npos);
}

TEST_CASE("static_js_bundle: kSseJs has no leading whitespace",
          "[static-js][sse]") {
    REQUIRE_FALSE(kSseJs.empty());
    CHECK(kSseJs.front() == '/');
    CHECK(kSseJs.front() != '\n');
}
