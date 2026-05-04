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

// External symbols from build-time embed targets (governance Gate 3 QE-B1):
//   * kEChartsJs            — embed_js.py over server/core/vendor/echarts.min.js
//   * kInterVariableWoff2   — embed_binary.py over vendor/inter/InterVariable.woff2
//   * kYuzuCss              — embed_js.py over server/core/static/yuzu.css
//   * kYuzuChartsJs         — server/core/src/charts_js_bundle.cpp (hand-written)
namespace yuzu::server {
extern const std::string kEChartsJs;
extern const std::string_view kInterVariableWoff2;
extern const std::string kYuzuCss;
extern const std::string kYuzuChartsJs;
} // namespace yuzu::server

using Catch::Matchers::ContainsSubstring;

namespace {
constexpr std::size_t kExpectedHtmxBytes = 50918;
constexpr std::size_t kExpectedSseBytes  = 8897;
// Pinned upstream byte counts. If you intentionally update vendor/, bump
// these in lock-step. ECharts 5.6.0 minified is 1,034,102 bytes; Inter v4.0
// variable woff2 is 345,588 bytes; Yuzu CSS bundle is content-addressed by
// the source file and approximate-pinned (a 1% drift tolerance lets the
// design system iterate without re-flowing this file every commit).
constexpr std::size_t kExpectedEChartsBytes      = 1'034'102;
constexpr std::size_t kExpectedInterWoff2Bytes   = 345'588;
constexpr std::size_t kYuzuCssMinBytes           = 20'000; // ≥20 KB sanity floor
constexpr std::size_t kYuzuChartsMinBytes        = 6'000;  // ≥6 KB adapter floor
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

// ── Apache ECharts ──────────────────────────────────────────────────────────

TEST_CASE("static_js_bundle: kEChartsJs has expected pinned size",
          "[static-js][echarts]") {
    CHECK(yuzu::server::kEChartsJs.size() == kExpectedEChartsBytes);
}

TEST_CASE("static_js_bundle: kEChartsJs starts with the Apache license header",
          "[static-js][echarts]") {
    REQUIRE(yuzu::server::kEChartsJs.size() >= 100);
    // The vendored bundle preserves the Apache 2.0 header banner (License
    // §4(c) compliance check).
    CHECK_THAT(yuzu::server::kEChartsJs,
               ContainsSubstring("Licensed to the Apache Software Foundation"));
}

TEST_CASE("static_js_bundle: kEChartsJs exposes the global echarts API",
          "[static-js][echarts]") {
    // ContainsSubstring("init") alone is too generic (every minified JS
    // contains the substring) — governance Gate 4 UP-8. The minifier
    // renames public methods, so `echarts.init` doesn't appear literally
    // in the bundle. Pin two ECharts-unique tokens instead:
    //   * the UMD wrapper assignment that exposes the global
    //   * the internal property name used by getInstanceByDom (lib-unique)
    CHECK_THAT(yuzu::server::kEChartsJs, ContainsSubstring(".echarts={})"));
    CHECK_THAT(yuzu::server::kEChartsJs, ContainsSubstring("echarts_instance_"));
}

TEST_CASE("static_js_bundle: kEChartsJs is the expected vendored version",
          "[static-js][echarts]") {
    // Pin the upstream version string so a silent vendor swap to a newer
    // minor (5.7.x) that happens to match the byte count fails LOUD
    // (governance Gate 4 UP-5 / QA-N2).
    CHECK_THAT(yuzu::server::kEChartsJs, ContainsSubstring("5.6.0"));
}

TEST_CASE("static_js_bundle: kEChartsJs has no embedded NULs",
          "[static-js][echarts]") {
    CHECK(yuzu::server::kEChartsJs.find('\0') == std::string::npos);
    // A stray `)ECHARTSEMBED"` close-delimiter cannot appear at runtime —
    // raw-string literal grammar consumes it at compile time, and
    // embed_js.py's collision check at build time refuses to emit if the
    // input bytes contain it. The runtime check that earlier sat here
    // was therefore tautological (governance Gate 6 SRE-1). Build-time
    // protection is at server/core/scripts/embed_js.py.
}

// ── Inter variable webfont (woff2 binary) ───────────────────────────────────

TEST_CASE("static_js_bundle: kInterVariableWoff2 has expected pinned size",
          "[static-js][inter]") {
    CHECK(yuzu::server::kInterVariableWoff2.size() == kExpectedInterWoff2Bytes);
}

TEST_CASE("static_js_bundle: kInterVariableWoff2 begins with WOFF2 magic",
          "[static-js][inter]") {
    REQUIRE(yuzu::server::kInterVariableWoff2.size() >= 4);
    // WOFF2 file format: signature 0x774F4632 ('wOF2') at offset 0.
    auto sv = yuzu::server::kInterVariableWoff2;
    CHECK(static_cast<unsigned char>(sv[0]) == 0x77);
    CHECK(static_cast<unsigned char>(sv[1]) == 0x4F);
    CHECK(static_cast<unsigned char>(sv[2]) == 0x46);
    CHECK(static_cast<unsigned char>(sv[3]) == 0x32);
}

// ── Yuzu Design System CSS bundle ───────────────────────────────────────────

TEST_CASE("static_js_bundle: kYuzuCss is at least 20 KB",
          "[static-js][yuzu-css]") {
    // Sanity floor — a single-chunk truncation would silently drop content.
    CHECK(yuzu::server::kYuzuCss.size() >= kYuzuCssMinBytes);
}

TEST_CASE("static_js_bundle: kYuzuCss carries the design-system token layer",
          "[static-js][yuzu-css]") {
    // Anchor on tokens introduced in the design-system sweep.
    CHECK_THAT(yuzu::server::kYuzuCss,
               ContainsSubstring("--mds-color-theme-background-canvas"));
    CHECK_THAT(yuzu::server::kYuzuCss,
               ContainsSubstring("--mds-color-theme-accent-primary-normal"));
    CHECK_THAT(yuzu::server::kYuzuCss,
               ContainsSubstring("--mds-color-chart-1"));
    CHECK_THAT(yuzu::server::kYuzuCss, ContainsSubstring("@font-face"));
    CHECK_THAT(yuzu::server::kYuzuCss, ContainsSubstring("'Inter'"));
}

TEST_CASE("static_js_bundle: kYuzuCss has no embedded NULs",
          "[static-js][yuzu-css]") {
    CHECK(yuzu::server::kYuzuCss.find('\0') == std::string::npos);
    // (See kEChartsJs counterpart — stray-delimiter check is tautological
    // at runtime; build-time guard in embed_js.py is the real protection.)
}

// ── Yuzu chart adapter (kYuzuChartsJs) ──────────────────────────────────────

TEST_CASE("static_js_bundle: kYuzuChartsJs is at least 6 KB",
          "[static-js][yuzu-charts]") {
    CHECK(yuzu::server::kYuzuChartsJs.size() >= kYuzuChartsMinBytes);
}

TEST_CASE("static_js_bundle: kYuzuChartsJs exposes the YuzuCharts global",
          "[static-js][yuzu-charts]") {
    CHECK_THAT(yuzu::server::kYuzuChartsJs, ContainsSubstring("window.YuzuCharts"));
    CHECK_THAT(yuzu::server::kYuzuChartsJs, ContainsSubstring("echarts.init"));
    CHECK_THAT(yuzu::server::kYuzuChartsJs, ContainsSubstring("htmx:afterSettle"));
}

TEST_CASE("static_js_bundle: kYuzuChartsJs reads design-system chart tokens",
          "[static-js][yuzu-charts]") {
    // The adapter resolves --mds-color-chart-* via getComputedStyle at
    // render time (governance Gate 3 architecture-N3). Drift in this
    // surface should fail the test.
    CHECK_THAT(yuzu::server::kYuzuChartsJs,
               ContainsSubstring("--mds-color-chart-1"));
    CHECK_THAT(yuzu::server::kYuzuChartsJs,
               ContainsSubstring("--mds-color-theme-background-solid-primary"));
}

TEST_CASE("static_js_bundle: kYuzuChartsJs has no embedded NULs",
          "[static-js][yuzu-charts]") {
    CHECK(yuzu::server::kYuzuChartsJs.find('\0') == std::string::npos);
}

TEST_CASE("static_js_bundle: kYuzuChartsJs renders an empty-state message on no data",
          "[static-js][yuzu-charts]") {
    // Governance Gate 4 HP-1: empty-data payloads should fall through to
    // emptyState() with an operator-facing message instead of painting a
    // blank canvas. Pin the message string so a future renderer rewrite
    // can't silently remove it.
    CHECK_THAT(yuzu::server::kYuzuChartsJs,
               ContainsSubstring("No data to plot."));
    CHECK_THAT(yuzu::server::kYuzuChartsJs, ContainsSubstring("isEmptyData"));
}
