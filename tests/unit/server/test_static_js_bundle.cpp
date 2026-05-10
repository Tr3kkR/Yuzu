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
extern const std::string kThreeJs;
extern const std::string kThreeOrbitControlsJs;
extern const std::string kYuzuVizJs;
extern const std::string_view kInterVariableWoff2;
extern const std::string kYuzuCss;
extern const std::string kYuzuChartsJs;
} // namespace yuzu::server

// Page HTML constants (separate TUs at namespace scope -- not in
// yuzu::server like the JS bundles).
extern const char* const kVizFleetPageHtml;

using Catch::Matchers::ContainsSubstring;

namespace {
constexpr std::size_t kExpectedHtmxBytes = 50918;
constexpr std::size_t kExpectedSseBytes = 8897;
// Pinned upstream byte counts. If you intentionally update vendor/, bump
// these in lock-step. ECharts 5.6.0 minified is 1,034,102 bytes; Inter v4.0
// variable woff2 is 345,588 bytes; Yuzu CSS bundle is content-addressed by
// the source file and approximate-pinned (a 1% drift tolerance lets the
// design system iterate without re-flowing this file every commit).
constexpr std::size_t kExpectedEChartsBytes = 1'034'102;
constexpr std::size_t kExpectedInterWoff2Bytes = 345'588;
constexpr std::size_t kYuzuCssMinBytes = 20'000;   // ≥20 KB sanity floor
constexpr std::size_t kYuzuChartsMinBytes = 6'000; // ≥6 KB adapter floor
// Three.js r168 ES-module minified bundle + OrbitControls ES module
// (PR 4 of feat/viz-engine ladder). Both pinned to upstream byte counts;
// any change here must coincide with a deliberate vendor refresh.
constexpr std::size_t kExpectedThreeJsBytes = 685'408;
constexpr std::size_t kExpectedThreeOrbitJsBytes = 32'134;
} // namespace

// ── HTMX core ───────────────────────────────────────────────────────────────

TEST_CASE("static_js_bundle: kHtmxJs has expected pinned size", "[static-js][htmx]") {
    CHECK(kHtmxJs.size() == kExpectedHtmxBytes);
}

TEST_CASE("static_js_bundle: kHtmxJs starts with HTMX 2.0.4 IIFE preamble", "[static-js][htmx]") {
    // The minified bundle starts with `var htmx=function(){"use strict";...`
    REQUIRE(kHtmxJs.size() >= 30);
    CHECK(std::string_view(kHtmxJs).substr(0, 9) == "var htmx=");
    CHECK_THAT(kHtmxJs, ContainsSubstring("\"use strict\""));
}

TEST_CASE("static_js_bundle: kHtmxJs contains the version string", "[static-js][htmx]") {
    CHECK_THAT(kHtmxJs, ContainsSubstring("version:\"2.0.4\""));
}

TEST_CASE("static_js_bundle: kHtmxJs contains core public API symbols", "[static-js][htmx]") {
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

TEST_CASE("static_js_bundle: kHtmxJs has no leading whitespace", "[static-js][htmx]") {
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

TEST_CASE("static_js_bundle: kSseJs has expected pinned size", "[static-js][sse]") {
    CHECK(kSseJs.size() == kExpectedSseBytes);
}

TEST_CASE("static_js_bundle: kSseJs starts with the SSE banner comment", "[static-js][sse]") {
    REQUIRE(kSseJs.size() >= 30);
    CHECK(std::string_view(kSseJs).substr(0, 2) == "/*");
    CHECK_THAT(kSseJs, ContainsSubstring("Server Sent Events Extension"));
}

TEST_CASE("static_js_bundle: kSseJs registers the 'sse' extension", "[static-js][sse]") {
    // The extension self-registers via htmx.defineExtension('sse', {...}).
    CHECK_THAT(kSseJs, ContainsSubstring("htmx.defineExtension"));
    CHECK_THAT(kSseJs, ContainsSubstring("'sse'"));
}

TEST_CASE("static_js_bundle: kSseJs has no embedded NULs or stray delimiter", "[static-js][sse]") {
    CHECK(kSseJs.find('\0') == std::string::npos);
    CHECK(kSseJs.find(")SSEEOF") == std::string::npos);
}

TEST_CASE("static_js_bundle: kSseJs has no leading whitespace", "[static-js][sse]") {
    REQUIRE_FALSE(kSseJs.empty());
    CHECK(kSseJs.front() == '/');
    CHECK(kSseJs.front() != '\n');
}

// ── Apache ECharts ──────────────────────────────────────────────────────────

TEST_CASE("static_js_bundle: kEChartsJs has expected pinned size", "[static-js][echarts]") {
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

TEST_CASE("static_js_bundle: kEChartsJs exposes the global echarts API", "[static-js][echarts]") {
    // ContainsSubstring("init") alone is too generic (every minified JS
    // contains the substring) — governance Gate 4 UP-8. The minifier
    // renames public methods, so `echarts.init` doesn't appear literally
    // in the bundle. Pin two ECharts-unique tokens instead:
    //   * the UMD wrapper assignment that exposes the global
    //   * the internal property name used by getInstanceByDom (lib-unique)
    CHECK_THAT(yuzu::server::kEChartsJs, ContainsSubstring(".echarts={})"));
    CHECK_THAT(yuzu::server::kEChartsJs, ContainsSubstring("echarts_instance_"));
}

TEST_CASE("static_js_bundle: kEChartsJs is the expected vendored version", "[static-js][echarts]") {
    // Pin the upstream version string so a silent vendor swap to a newer
    // minor (5.7.x) that happens to match the byte count fails LOUD
    // (governance Gate 4 UP-5 / QA-N2).
    CHECK_THAT(yuzu::server::kEChartsJs, ContainsSubstring("5.6.0"));
}

TEST_CASE("static_js_bundle: kEChartsJs has no embedded NULs", "[static-js][echarts]") {
    CHECK(yuzu::server::kEChartsJs.find('\0') == std::string::npos);
    // A stray `)ECHARTSEMBED"` close-delimiter cannot appear at runtime —
    // raw-string literal grammar consumes it at compile time, and
    // embed_js.py's collision check at build time refuses to emit if the
    // input bytes contain it. The runtime check that earlier sat here
    // was therefore tautological (governance Gate 6 SRE-1). Build-time
    // protection is at server/core/scripts/embed_js.py.
}

// ── Three.js r168 + OrbitControls (PR 4 of feat/viz-engine ladder) ──────────

TEST_CASE("static_js_bundle: kThreeJs has expected pinned size", "[static-js][three]") {
    CHECK(yuzu::server::kThreeJs.size() == kExpectedThreeJsBytes);
}

TEST_CASE("static_js_bundle: kThreeJs starts with the MIT license header", "[static-js][three]") {
    REQUIRE(yuzu::server::kThreeJs.size() >= 100);
    // The vendored ES-module minified bundle preserves the SPDX/MIT header
    // at the top of build/three.module.min.js (license attribution).
    CHECK_THAT(yuzu::server::kThreeJs, ContainsSubstring("Three.js Authors"));
    CHECK_THAT(yuzu::server::kThreeJs, ContainsSubstring("SPDX-License-Identifier: MIT"));
}

TEST_CASE("static_js_bundle: kThreeJs is the expected vendored release", "[static-js][three]") {
    // gov R4 QA-B1: pin the QUOTED form `"168"` rather than the bare
    // substring `168`. Bare-digit search hits arbitrary numeric tokens
    // throughout 685 KB of minified JS (a silent r169 swap would still
    // contain `168` somewhere). The bundle exposes `REVISION = "168"`
    // exactly once -- pin that.
    CHECK_THAT(yuzu::server::kThreeJs, ContainsSubstring("\"168\""));
    // Sanity: confirm exactly one occurrence so the assertion above
    // remains discriminating across future minor refreshes that may
    // happen to embed the digit pattern elsewhere.
    auto pos = yuzu::server::kThreeJs.find("\"168\"");
    REQUIRE(pos != std::string::npos);
    CHECK(yuzu::server::kThreeJs.find("\"168\"", pos + 1) == std::string::npos);
}

TEST_CASE("static_js_bundle: kThreeJs has no embedded NULs", "[static-js][three]") {
    CHECK(yuzu::server::kThreeJs.find('\0') == std::string::npos);
}

TEST_CASE("static_js_bundle: kThreeOrbitControlsJs has expected pinned size",
          "[static-js][three]") {
    CHECK(yuzu::server::kThreeOrbitControlsJs.size() == kExpectedThreeOrbitJsBytes);
}

TEST_CASE("static_js_bundle: kThreeOrbitControlsJs imports from 'three'", "[static-js][three]") {
    REQUIRE(yuzu::server::kThreeOrbitControlsJs.size() >= 50);
    // The unmodified ES-module file uses a bare specifier `from 'three'`
    // that the page's importmap resolves to `/static/three.module.min.js`.
    // Without this top-level import, the importmap contract in PR 5 is
    // broken; pin the substring so a vendor refresh that swaps the
    // import path fails the build instead of producing a runtime
    // ReferenceError on Quaternion / Spherical / Vector3.
    CHECK_THAT(yuzu::server::kThreeOrbitControlsJs, ContainsSubstring("from 'three'"));
    // Public class still named OrbitControls.
    CHECK_THAT(yuzu::server::kThreeOrbitControlsJs, ContainsSubstring("class OrbitControls"));
}

TEST_CASE("static_js_bundle: kThreeOrbitControlsJs has no embedded NULs", "[static-js][three]") {
    CHECK(yuzu::server::kThreeOrbitControlsJs.find('\0') == std::string::npos);
}

// ── Yuzu fleet renderer (PR 5 of feat/viz-engine ladder) ────────────────────

TEST_CASE("static_js_bundle: kYuzuVizJs is a non-empty ES module", "[static-js][viz]") {
    REQUIRE(yuzu::server::kYuzuVizJs.size() >= 1000);
    // ES module top-level imports are the load contract that the
    // /viz/fleet page's importmap maps. Without these substrings the
    // module wouldn't be loadable as a module at all.
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("import * as THREE from 'three'"));
    CHECK_THAT(yuzu::server::kYuzuVizJs,
               ContainsSubstring("import { OrbitControls } "
                                 "from 'three/addons/controls/OrbitControls.js'"));
}

TEST_CASE("static_js_bundle: kYuzuVizJs registers htmx:afterSettle mount", "[static-js][viz]") {
    // Mount-once on htmx:afterSettle is the canvas-survival contract --
    // an HTMX swap of the overlay panel must not blow away the renderer.
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("htmx:afterSettle"));
}

TEST_CASE("static_js_bundle: kYuzuVizJs idempotency guard present", "[static-js][viz]") {
    // The mount-once guard reads root.dataset.yuzuVizMounted; any future
    // refactor that drops this leaves the door open for double-mount on
    // HTMX swap (two WebGLRenderer instances on the same canvas).
    // gov R4 QA-S2: pin BOTH sides of the sentinel so a regression that
    // changes the assignment to `'true'` while the check stays `'1'`
    // breaks idempotency silently. The bare-substring assertion alone
    // would pass either way.
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("yuzuVizMounted === '1'"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("yuzuVizMounted = '1'"));
}

TEST_CASE("static_js_bundle: kYuzuVizJs registers webglcontextlost handler", "[static-js][viz]") {
    // gov R4 UP-3 / CHAOS-2: WebGL context loss must be handled or the
    // rAF loop spams "context-lost" warnings on every frame after a GPU
    // sleep/wake. Pin both event-name listeners so a refactor that drops
    // either fails the test instead of producing silent freezes.
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("'webglcontextlost'"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("'webglcontextrestored'"));
}

TEST_CASE("static_js_bundle: kYuzuVizJs guards WASD against editable targets", "[static-js][viz]") {
    // gov R4 sec-M1 / UP-6: WASD preventDefault MUST NOT fire when a
    // text-editable element is focused, or typing W/A/S/D into a future
    // overlay-panel <input> silently eats the keystroke.
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("isEditableTarget"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("isContentEditable"));
}

TEST_CASE("static_js_bundle: kYuzuVizJs disables OrbitControls panning", "[static-js][viz]") {
    // OrbitControls.enablePan = false is the WASD-owns-translation
    // contract. Built-in pan steals the mouse event from rotate; pin the
    // disable.
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("controls.enablePan = false"));
}

TEST_CASE("static_js_bundle: kYuzuVizJs has no embedded NULs", "[static-js][viz]") {
    CHECK(yuzu::server::kYuzuVizJs.find('\0') == std::string::npos);
}

// ── PR 6: cube layer ────────────────────────────────────────────────────────

TEST_CASE("static_js_bundle: kYuzuVizJs declares per-OS palette for linux/darwin/windows",
          "[static-js][viz]") {
    // PR 6 colour palette. The hex values double as a contract: changing
    // the palette is a deliberate UX decision, not a stealth refactor.
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("OS_PALETTE"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("linux:"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("darwin:"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("windows:"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("pickOsColor"));
}

TEST_CASE("static_js_bundle: kYuzuVizJs uses FNV-1a 32-bit hash for stable layout",
          "[static-js][viz]") {
    // Stable per-agent positions across reloads require a deterministic
    // hash. FNV-1a 32-bit is identifiable by the 0x811c9dc5 offset basis
    // and the 0x01000193 prime; pin both so a refactor that swaps to a
    // randomised hash (and breaks the "same fleet renders the same way"
    // contract) fails the test.
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("0x811c9dc5"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("0x01000193"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("Math.imul"));
}

TEST_CASE("static_js_bundle: kYuzuVizJs lays machines out on a ceil(sqrt(N)) grid",
          "[static-js][viz]") {
    // The grid layout is the placement contract -- without ceil(sqrt(N))
    // the cubes pile up at the origin or fly off-screen at high N. Pin
    // the function name + the ceil/sqrt math so a refactor to a different
    // packing breaks the test rather than silently regressing UX.
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("layoutMachines"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("Math.ceil(Math.sqrt"));
}

TEST_CASE("static_js_bundle: kYuzuVizJs builds translucent cubes with MeshPhysicalMaterial",
          "[static-js][viz]") {
    // gov R6 PR-6: the cube material contract -- transparent + opacity
    // 0.18 (live) / 0.08 (stale). A refactor that swaps to opaque cubes
    // would obscure interior process nodes (PR 7+) and break the visual
    // model.
    //
    // gov R6 QE SHOULD-1/SHOULD-2: bare `0.08` substring matches
    // `dampingFactor=0.08` elsewhere in the bundle (false positive); bare
    // `0.18` has no positional context. Pin the full ternary so the test
    // measures the live-vs-stale opacity *relationship*, not just two
    // numeric tokens that happen to appear somewhere.
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("MeshPhysicalMaterial"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("transparent: true"));
    CHECK_THAT(yuzu::server::kYuzuVizJs,
               ContainsSubstring("opacity: machine && machine.stale ? 0.08 : 0.18"));
}

TEST_CASE("static_js_bundle: kYuzuVizJs builds Sprite hostname labels", "[static-js][viz]") {
    // Hostname labels via Sprite + CanvasTexture so they always face the
    // camera. Pin both Three classes so a swap to TextGeometry (which
    // doesn't billboard) fails the test.
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("THREE.Sprite"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("THREE.CanvasTexture"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("buildHostnameLabel"));
}

TEST_CASE("static_js_bundle: kYuzuVizJs uses Raycaster for hover tooltip", "[static-js][viz]") {
    // Hover tooltip is the discovery affordance for a cube's hostname /
    // OS / counts. Without the raycaster wiring the tooltip never fires.
    // Pin both the class and the listener.
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("THREE.Raycaster"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("'mousemove'"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("intersectObjects"));
}

TEST_CASE("static_js_bundle: kYuzuVizJs creates #viz-tooltip dynamically", "[static-js][viz]") {
    // The tooltip element is created lazily by the renderer (not
    // pre-existing in the page HTML) so the page shell stays minimal.
    // Pin the id so a refactor that renames it doesn't break the
    // tooltip without anybody noticing.
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("'viz-tooltip'"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("ensureTooltip"));
}

TEST_CASE("static_js_bundle: kYuzuVizJs escapes HTML in tooltip content", "[static-js][viz]") {
    // gov R6 sec-M1: hostname / os come from agent-controlled fields.
    // The tooltip uses .innerHTML for layout convenience, so the values
    // MUST be escaped or an agent-controlled hostname like
    // `<img onerror=alert()>` would execute. Pin both the helper and the
    // mention of escaped chars.
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("escapeHtml"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("&amp;"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("&lt;"));
}

TEST_CASE("static_js_bundle: kYuzuVizJs fetches with same-origin credentials", "[static-js][viz]") {
    // Same-origin credentials are required so the session cookie travels
    // with the fetch. Without it a logged-in operator would see 401 even
    // though their browser cookie is set.
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("data-yuzu-viz-url"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("credentials: 'same-origin'"));
}

TEST_CASE("static_js_bundle: kYuzuVizJs handles 401 / 403 / 503 fetch outcomes",
          "[static-js][viz]") {
    // gov R5 UP-17: an admin who is demoted mid-session must see an
    // explicit access-denied message rather than a blank scene. 503
    // covers --viz-disable kill switch flipping under the operator's
    // feet. Pin all three status codes; a refactor that collapses them
    // into a generic catch-all breaks the granular UX.
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("r.status === 401"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("r.status === 403"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("r.status === 503"));
}

TEST_CASE("static_js_bundle: kYuzuVizJs validates fleet_topology.v1 schema string",
          "[static-js][viz]") {
    // The renderer must reject anything that isn't fleet_topology.v1 --
    // a future schema bump (v2) would land at the same URL during a
    // staged rollout, and rendering with the wrong shape gives nonsense.
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("fleet_topology.v1"));
}

TEST_CASE("static_js_bundle: kYuzuVizJs guards camera position against NaN/Infinity",
          "[static-js][viz]") {
    // gov R5 UP-7: a single bad input that pushes camera.position into
    // NaN cascades through every subsequent frame (renderer.render with
    // NaN matrices crashes WebGL on some drivers). The render loop must
    // detect and reset to a safe default.
    //
    // gov R6 architect NICE-2: the reset must cover BOTH camera.position
    // and controls.target -- the latter feeds back into camera.position
    // via controls.update() each frame, so resetting only one would
    // re-poison within one frame.
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("Number.isFinite"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("camera.position.set"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("controls.target.set"));
}

// ── Fleet viz page HTML scaffold ────────────────────────────────────────────

TEST_CASE("viz page: contains the persistent canvas + viz-root structure", "[viz][page]") {
    REQUIRE(kVizFleetPageHtml != nullptr);
    std::string html(kVizFleetPageHtml);
    REQUIRE(html.size() >= 500);
    // The yuzu-viz.js mount contract relies on these three exact
    // attributes/ids; pinning them here means a future refactor that
    // renames either side fails the test instead of producing a
    // working-on-localhost-broken-on-server-restart silent regression.
    CHECK_THAT(html, ContainsSubstring("data-yuzu-viz-url=\"/api/v1/viz/fleet/topology\""));
    CHECK_THAT(html, ContainsSubstring("id=\"viz-root\""));
    CHECK_THAT(html, ContainsSubstring("id=\"viz-canvas\""));
    CHECK_THAT(html, ContainsSubstring("id=\"viz-overlay-panel\""));
}

TEST_CASE("viz page: declares importmap for three + addons", "[viz][page]") {
    // Three.js (r150+) is ES-module-only upstream; the importmap resolves
    // the bare `import 'three'` specifier in OrbitControls and yuzu-viz.js
    // to the vendored bundle. Without this map, the module network request
    // would 404 against the bare name.
    std::string html(kVizFleetPageHtml);
    CHECK_THAT(html, ContainsSubstring("type=\"importmap\""));
    CHECK_THAT(html, ContainsSubstring("\"three\": \"/static/three.module.min.js\""));
    CHECK_THAT(html, ContainsSubstring("/static/three-orbit-controls.js"));
}

TEST_CASE("viz page: importmap appears EXACTLY ONCE", "[viz][page]") {
    // gov R4 sec-L2 / QA-S3 / CHAOS-1: HTML spec allows only one
    // importmap per document. A second declaration is silently ignored
    // by the browser. Pin exactly-one occurrence so a future refactor
    // that accidentally inserts a second importmap (e.g. a copy-paste
    // into a sibling page shell) fails this test instead of breaking
    // module resolution at runtime.
    std::string html(kVizFleetPageHtml);
    auto first = html.find("type=\"importmap\"");
    REQUIRE(first != std::string::npos);
    CHECK(html.find("type=\"importmap\"", first + 1) == std::string::npos);
}

TEST_CASE("viz page: yuzu-viz.js module loader appears EXACTLY ONCE", "[viz][page]") {
    // Two `<script type="module" src="/static/yuzu-viz.js">` tags would
    // load the renderer twice. The mount() guard absorbs double-mount
    // for HTMX swaps but the duplicate load itself wastes 6 KB and
    // duplicates the global `htmx:afterSettle` listener registration
    // (UP-5 amplifier). Pin singleton.
    std::string html(kVizFleetPageHtml);
    auto needle = "<script type=\"module\" src=\"/static/yuzu-viz.js\">";
    auto first = html.find(needle);
    REQUIRE(first != std::string::npos);
    CHECK(html.find(needle, first + 1) == std::string::npos);
}

TEST_CASE("viz page: importmap precedes the type=module loader", "[viz][page]") {
    // gov R4 UP-1 / CHAOS-1: HTML spec requires the importmap to be
    // parsed BEFORE any `<script type="module">` that depends on it.
    // A future refactor that moves the importmap into <body>, or
    // injects a module-script ahead of it, would silently break module
    // resolution. Assert the position invariant directly.
    std::string html(kVizFleetPageHtml);
    auto importmap_pos = html.find("type=\"importmap\"");
    auto module_pos = html.find("<script type=\"module\" src=\"/static/yuzu-viz.js\">");
    REQUIRE(importmap_pos != std::string::npos);
    REQUIRE(module_pos != std::string::npos);
    CHECK(importmap_pos < module_pos);
}

TEST_CASE("viz page: importmap-support detection runs before importmap", "[viz][page]") {
    // gov R4 UP-16 / ER-SHOULD-1: browsers without importmap support
    // need a non-module fallback that surfaces a visible error rather
    // than leaving a blank canvas. Detection uses
    // HTMLScriptElement.supports('importmap'); pin the substring AND
    // its position relative to the importmap so a refactor can't move
    // it after.
    std::string html(kVizFleetPageHtml);
    auto detect_pos = html.find("HTMLScriptElement.supports");
    auto importmap_pos = html.find("type=\"importmap\"");
    REQUIRE(detect_pos != std::string::npos);
    REQUIRE(importmap_pos != std::string::npos);
    CHECK(detect_pos < importmap_pos);
    CHECK_THAT(html, ContainsSubstring("__yuzuVizImportmapSupported"));
}

TEST_CASE("viz page: loads yuzu-viz.js as type=module", "[viz][page]") {
    // type="module" is required so the ES imports resolve. A
    // type="text/javascript" (or omitted-type) tag would parse the file
    // as a classic script and the `import` statements at the top would
    // be SyntaxErrors at parse time.
    std::string html(kVizFleetPageHtml);
    CHECK_THAT(html, ContainsSubstring("<script type=\"module\" src=\"/static/yuzu-viz.js\">"));
}

TEST_CASE("viz page: nav highlights Fleet Viz when on the page", "[viz][page]") {
    std::string html(kVizFleetPageHtml);
    CHECK_THAT(html, ContainsSubstring("href=\"/viz/fleet\" class=\"nav-link active\""));
}

// ── Inter variable webfont (woff2 binary) ───────────────────────────────────

TEST_CASE("static_js_bundle: kInterVariableWoff2 has expected pinned size", "[static-js][inter]") {
    CHECK(yuzu::server::kInterVariableWoff2.size() == kExpectedInterWoff2Bytes);
}

TEST_CASE("static_js_bundle: kInterVariableWoff2 begins with WOFF2 magic", "[static-js][inter]") {
    REQUIRE(yuzu::server::kInterVariableWoff2.size() >= 4);
    // WOFF2 file format: signature 0x774F4632 ('wOF2') at offset 0.
    auto sv = yuzu::server::kInterVariableWoff2;
    CHECK(static_cast<unsigned char>(sv[0]) == 0x77);
    CHECK(static_cast<unsigned char>(sv[1]) == 0x4F);
    CHECK(static_cast<unsigned char>(sv[2]) == 0x46);
    CHECK(static_cast<unsigned char>(sv[3]) == 0x32);
}

// ── Yuzu Design System CSS bundle ───────────────────────────────────────────

TEST_CASE("static_js_bundle: kYuzuCss is at least 20 KB", "[static-js][yuzu-css]") {
    // Sanity floor — a single-chunk truncation would silently drop content.
    CHECK(yuzu::server::kYuzuCss.size() >= kYuzuCssMinBytes);
}

TEST_CASE("static_js_bundle: kYuzuCss carries the design-system token layer",
          "[static-js][yuzu-css]") {
    // Anchor on tokens introduced in the design-system sweep.
    CHECK_THAT(yuzu::server::kYuzuCss, ContainsSubstring("--mds-color-theme-background-canvas"));
    CHECK_THAT(yuzu::server::kYuzuCss,
               ContainsSubstring("--mds-color-theme-accent-primary-normal"));
    CHECK_THAT(yuzu::server::kYuzuCss, ContainsSubstring("--mds-color-chart-1"));
    CHECK_THAT(yuzu::server::kYuzuCss, ContainsSubstring("@font-face"));
    CHECK_THAT(yuzu::server::kYuzuCss, ContainsSubstring("'Inter'"));
}

TEST_CASE("static_js_bundle: kYuzuCss has no embedded NULs", "[static-js][yuzu-css]") {
    CHECK(yuzu::server::kYuzuCss.find('\0') == std::string::npos);
    // (See kEChartsJs counterpart — stray-delimiter check is tautological
    // at runtime; build-time guard in embed_js.py is the real protection.)
}

// ── Yuzu chart adapter (kYuzuChartsJs) ──────────────────────────────────────

TEST_CASE("static_js_bundle: kYuzuChartsJs is at least 6 KB", "[static-js][yuzu-charts]") {
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
    CHECK_THAT(yuzu::server::kYuzuChartsJs, ContainsSubstring("--mds-color-chart-1"));
    CHECK_THAT(yuzu::server::kYuzuChartsJs,
               ContainsSubstring("--mds-color-theme-background-solid-primary"));
}

TEST_CASE("static_js_bundle: kYuzuChartsJs has no embedded NULs", "[static-js][yuzu-charts]") {
    CHECK(yuzu::server::kYuzuChartsJs.find('\0') == std::string::npos);
}

TEST_CASE("static_js_bundle: kYuzuChartsJs renders an empty-state message on no data",
          "[static-js][yuzu-charts]") {
    // Governance Gate 4 HP-1: empty-data payloads should fall through to
    // emptyState() with an operator-facing message instead of painting a
    // blank canvas. Pin the message string so a future renderer rewrite
    // can't silently remove it.
    CHECK_THAT(yuzu::server::kYuzuChartsJs, ContainsSubstring("No data to plot."));
    CHECK_THAT(yuzu::server::kYuzuChartsJs, ContainsSubstring("isEmptyData"));
}
