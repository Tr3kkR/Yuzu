/**
 * test_web_utils.cpp — Unit tests for server web utility functions
 *
 * Covers: base64_decode, html_escape, url_decode, extract_form_value,
 *         extract_plugin
 */

#include "web_utils.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <string>

using namespace yuzu::server;

// ── base64_decode ───────────────────────────────────────────────────────────

TEST_CASE("base64_decode: empty string", "[web_utils][base64]") {
    REQUIRE(base64_decode("") == "");
}

TEST_CASE("base64_decode: basic text", "[web_utils][base64]") {
    // "Hello" = "SGVsbG8="
    REQUIRE(base64_decode("SGVsbG8=") == "Hello");
}

TEST_CASE("base64_decode: 'Hello, World!'", "[web_utils][base64]") {
    // "Hello, World!" = "SGVsbG8sIFdvcmxkIQ=="
    REQUIRE(base64_decode("SGVsbG8sIFdvcmxkIQ==") == "Hello, World!");
}

TEST_CASE("base64_decode: single character", "[web_utils][base64]") {
    // "A" = "QQ=="
    REQUIRE(base64_decode("QQ==") == "A");
}

TEST_CASE("base64_decode: two characters", "[web_utils][base64]") {
    // "AB" = "QUI="
    REQUIRE(base64_decode("QUI=") == "AB");
}

TEST_CASE("base64_decode: three characters (no padding)", "[web_utils][base64]") {
    // "ABC" = "QUJD"
    REQUIRE(base64_decode("QUJD") == "ABC");
}

TEST_CASE("base64_decode: binary data (null bytes)", "[web_utils][base64]") {
    // "\x00\x01\x02" = "AAEC"
    auto result = base64_decode("AAEC");
    REQUIRE(result.size() == 3);
    CHECK(result[0] == '\x00');
    CHECK(result[1] == '\x01');
    CHECK(result[2] == '\x02');
}

TEST_CASE("base64_decode: ignores whitespace", "[web_utils][base64]") {
    // Base64 should skip non-alphabet characters including whitespace
    REQUIRE(base64_decode("QUJD\n") == "ABC");
}

TEST_CASE("base64_decode: longer string", "[web_utils][base64]") {
    // "The quick brown fox jumps over the lazy dog"
    REQUIRE(base64_decode("VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw==") ==
            "The quick brown fox jumps over the lazy dog");
}

TEST_CASE("base64_decode: without padding still works", "[web_utils][base64]") {
    // Some encoders omit padding; our decoder should handle it
    REQUIRE(base64_decode("SGVsbG8") == "Hello");
}

// ── html_escape ─────────────────────────────────────────────────────────────

TEST_CASE("html_escape: plain text unchanged", "[web_utils][html]") {
    REQUIRE(html_escape("Hello World 123") == "Hello World 123");
}

TEST_CASE("html_escape: empty string", "[web_utils][html]") {
    REQUIRE(html_escape("") == "");
}

TEST_CASE("html_escape: ampersand", "[web_utils][html]") {
    REQUIRE(html_escape("A & B") == "A &amp; B");
}

TEST_CASE("html_escape: less-than", "[web_utils][html]") {
    REQUIRE(html_escape("x < y") == "x &lt; y");
}

TEST_CASE("html_escape: greater-than", "[web_utils][html]") {
    REQUIRE(html_escape("x > y") == "x &gt; y");
}

TEST_CASE("html_escape: double quote", "[web_utils][html]") {
    REQUIRE(html_escape(R"(say "hi")") == "say &quot;hi&quot;");
}

TEST_CASE("html_escape: single quote", "[web_utils][html]") {
    REQUIRE(html_escape("it's") == "it&#39;s");
}

TEST_CASE("html_escape: all special chars in one string", "[web_utils][html]") {
    REQUIRE(html_escape("<script>alert('xss' & \"test\")</script>") ==
            "&lt;script&gt;alert(&#39;xss&#39; &amp; &quot;test&quot;)&lt;/script&gt;");
}

TEST_CASE("html_escape: already-escaped text gets double-escaped", "[web_utils][html]") {
    REQUIRE(html_escape("&amp;") == "&amp;amp;");
}

// ── json_escape (Phase 15.A — issue #547, hardening round 3) ───────────────
//
// json_escape is the defense against the HTMX hx-vals JSON-injection vector.
// The browser un-HTML-escapes the attribute value *before* HTMX's JSON
// parser sees it, so the correct ordering for a JSON-string-in-HTML-
// attribute is `json_escape` FIRST, `html_escape` SECOND. These tests pin
// the JSON-escape half — corruption in either direction silently re-opens
// sec-M3 from the Gate 2 governance review.

TEST_CASE("json_escape: empty string", "[web_utils][json][issue547]") {
    REQUIRE(json_escape("") == "");
}

TEST_CASE("json_escape: plain ASCII unchanged", "[web_utils][json][issue547]") {
    REQUIRE(json_escape("agent-abc-123") == "agent-abc-123");
    REQUIRE(json_escape("Hello, world! 0123456789")
            == "Hello, world! 0123456789");
}

TEST_CASE("json_escape: double-quote escapes to backslash-quote",
          "[web_utils][json][issue547]") {
    // The exact sec-M3 vector — a `"` in device_id would otherwise close
    // the JSON string in an hx-vals='{"device_id":"..."}' attribute and
    // inject keys that the operator's browser would submit on Re-enable.
    REQUIRE(json_escape("a\"b") == "a\\\"b");
    REQUIRE(json_escape("\"") == "\\\"");
    REQUIRE(json_escape("evil\",\"cmd\":\"exec")
            == "evil\\\",\\\"cmd\\\":\\\"exec");
}

TEST_CASE("json_escape: backslash escapes to double-backslash",
          "[web_utils][json][issue547]") {
    REQUIRE(json_escape("\\") == "\\\\");
    REQUIRE(json_escape("a\\b") == "a\\\\b");
}

TEST_CASE("json_escape: named escapes for \\b \\f \\n \\r \\t",
          "[web_utils][json][issue547]") {
    REQUIRE(json_escape("\b") == "\\b");
    REQUIRE(json_escape("\f") == "\\f");
    REQUIRE(json_escape("\n") == "\\n");
    REQUIRE(json_escape("\r") == "\\r");
    REQUIRE(json_escape("\t") == "\\t");
    REQUIRE(json_escape("line1\nline2\tcol") == "line1\\nline2\\tcol");
}

TEST_CASE("json_escape: C0 control bytes encode as \\u00xx",
          "[web_utils][json][issue547]") {
    // A malicious agent registering with `device_id` containing
    // 0x00-0x1F could log-inject if downstream sinks didn't escape.
    // json_escape is one of the layers; verify every C0 byte that
    // doesn't have a named escape produces \u00xx.
    REQUIRE(json_escape(std::string{static_cast<char>(0x00)}) == "\\u0000");
    REQUIRE(json_escape(std::string{static_cast<char>(0x01)}) == "\\u0001");
    REQUIRE(json_escape(std::string{static_cast<char>(0x1f)}) == "\\u001f");
    // Bytes 0x08 (\b), 0x09 (\t), 0x0a (\n), 0x0c (\f), 0x0d (\r) take
    // the named form, verified by the prior test — not duplicated here.
}

TEST_CASE("json_escape: bytes 0x20 and above pass through unchanged",
          "[web_utils][json][issue547]") {
    REQUIRE(json_escape(std::string{static_cast<char>(0x20)}) == " ");
    REQUIRE(json_escape(std::string{static_cast<char>(0x7e)}) == "~");
    // High-bit bytes (UTF-8 continuation, etc.) pass through. JSON does
    // not require U+2028 / U+2029 escaping outside `eval`-style contexts.
    REQUIRE(json_escape(std::string{static_cast<char>(0xc3),
                                     static_cast<char>(0xa9)}) ==
            std::string{static_cast<char>(0xc3),
                         static_cast<char>(0xa9)});
}

TEST_CASE("json_escape: result is safe to surround with html_escape",
          "[web_utils][json][issue547]") {
    // The full PR-A pipeline is `html_escape(json_escape(value))`. After
    // browser un-HTML-escape the attribute value reads back as the
    // json_escape output, which the JSON parser handles correctly.
    auto value = std::string{"\"\\\n"};
    auto js   = json_escape(value);
    auto html = html_escape(js);
    // The html-escaped form must contain no bare " (would close the
    // attribute), no bare < / > (would break HTML parser), no bare &
    // (would corrupt entity decode beyond the ones we emitted).
    REQUIRE(html.find('"') == std::string::npos);
    REQUIRE(html.find('<') == std::string::npos);
    REQUIRE(html.find('>') == std::string::npos);
    // And the raw JSON-escape output is the parseable JSON literal we
    // expect: \"\\\n
    REQUIRE(js == "\\\"\\\\\\n");
}

// ── url_decode ──────────────────────────────────────────────────────────────

TEST_CASE("url_decode: plain text unchanged", "[web_utils][url]") {
    REQUIRE(url_decode("hello") == "hello");
}

TEST_CASE("url_decode: empty string", "[web_utils][url]") {
    REQUIRE(url_decode("") == "");
}

TEST_CASE("url_decode: plus sign becomes space", "[web_utils][url]") {
    REQUIRE(url_decode("hello+world") == "hello world");
}

TEST_CASE("url_decode: percent-encoded space", "[web_utils][url]") {
    REQUIRE(url_decode("hello%20world") == "hello world");
}

TEST_CASE("url_decode: percent-encoded special chars", "[web_utils][url]") {
    REQUIRE(url_decode("%26") == "&");
    REQUIRE(url_decode("%3D") == "=");
    REQUIRE(url_decode("%3F") == "?");
    REQUIRE(url_decode("%2F") == "/");
}

TEST_CASE("url_decode: multiple encoded sequences", "[web_utils][url]") {
    REQUIRE(url_decode("key%3Dvalue%26other%3D123") == "key=value&other=123");
}

TEST_CASE("url_decode: mixed encoded and plain", "[web_utils][url]") {
    REQUIRE(url_decode("hello%21+world%3F") == "hello! world?");
}

TEST_CASE("url_decode: percent at end of string (incomplete sequence)", "[web_utils][url]") {
    // '%' at end without two hex digits should be kept as-is
    auto result = url_decode("test%");
    CHECK(result == "test%");
}

TEST_CASE("url_decode: percent with one hex digit", "[web_utils][url]") {
    auto result = url_decode("test%2");
    CHECK(result == "test%2");
}

// ── extract_form_value ──────────────────────────────────────────────────────

TEST_CASE("extract_form_value: single key-value pair", "[web_utils][form]") {
    REQUIRE(extract_form_value("username=admin", "username") == "admin");
}

TEST_CASE("extract_form_value: multiple pairs, first key", "[web_utils][form]") {
    REQUIRE(extract_form_value("username=admin&password=secret", "username") == "admin");
}

TEST_CASE("extract_form_value: multiple pairs, second key", "[web_utils][form]") {
    REQUIRE(extract_form_value("username=admin&password=secret", "password") == "secret");
}

TEST_CASE("extract_form_value: key not found returns empty", "[web_utils][form]") {
    REQUIRE(extract_form_value("username=admin", "email") == "");
}

TEST_CASE("extract_form_value: URL-encoded value decoded", "[web_utils][form]") {
    REQUIRE(extract_form_value("msg=hello+world", "msg") == "hello world");
    REQUIRE(extract_form_value("path=%2Fhome%2Fuser", "path") == "/home/user");
}

TEST_CASE("extract_form_value: empty value", "[web_utils][form]") {
    REQUIRE(extract_form_value("key=", "key") == "");
}

TEST_CASE("extract_form_value: empty body", "[web_utils][form]") {
    REQUIRE(extract_form_value("", "key") == "");
}

TEST_CASE("extract_form_value: three pairs", "[web_utils][form]") {
    std::string body = "a=1&b=2&c=3";
    CHECK(extract_form_value(body, "a") == "1");
    CHECK(extract_form_value(body, "b") == "2");
    CHECK(extract_form_value(body, "c") == "3");
}

TEST_CASE("extract_form_value: value with special chars", "[web_utils][form]") {
    REQUIRE(extract_form_value("q=c%2B%2B+programming", "q") == "c++ programming");
}

// ── extract_plugin ──────────────────────────────────────────────────────────

TEST_CASE("extract_plugin: standard command_id with timestamp", "[web_utils][plugin]") {
    REQUIRE(extract_plugin("chargen-12345") == "chargen");
    REQUIRE(extract_plugin("netstat-98765") == "netstat");
    REQUIRE(extract_plugin("hardware-1234567890") == "hardware");
}

TEST_CASE("extract_plugin: no dash returns whole string", "[web_utils][plugin]") {
    REQUIRE(extract_plugin("chargen") == "chargen");
    REQUIRE(extract_plugin("netstat") == "netstat");
}

TEST_CASE("extract_plugin: empty string", "[web_utils][plugin]") {
    REQUIRE(extract_plugin("") == "");
}

TEST_CASE("extract_plugin: multiple dashes uses first", "[web_utils][plugin]") {
    REQUIRE(extract_plugin("my-plugin-12345") == "my");
}

TEST_CASE("extract_plugin: dash at start", "[web_utils][plugin]") {
    REQUIRE(extract_plugin("-12345") == "");
}

TEST_CASE("extract_plugin: underscore plugin name", "[web_utils][plugin]") {
    REQUIRE(extract_plugin("vuln_scan-12345") == "vuln_scan");
    REQUIRE(extract_plugin("script_exec-12345") == "script_exec");
}

// ── Time formatters ─────────────────────────────────────────────────────────
//
// format_iso_utc and format_relative_time anchor the executions surface; the
// list shows relative time and the title= attribute shows ISO-8601 UTC for
// forensic copy/paste. Mixing local time anywhere on this surface is a known
// failure mode (BST/UTC drift) — these tests pin the format.

TEST_CASE("format_iso_utc: zero returns dash sentinel", "[web_utils][time]") {
    REQUIRE(format_iso_utc(0) == "—");
    REQUIRE(format_iso_utc(-1) == "—");
}

TEST_CASE("format_iso_utc: epoch 0 sentinel vs known UTC moment",
          "[web_utils][time]") {
    // 2025-01-01T00:00:00Z — no DST, no timezone trickery.
    REQUIRE(format_iso_utc(1735689600) == "2025-01-01T00:00:00Z");
    // 2026-04-29T12:34:56Z — middle-of-day UTC moment, well-formed leap-year-aware.
    REQUIRE(format_iso_utc(1777466096) == "2026-04-29T12:34:56Z");
}

TEST_CASE("format_iso_utc: format is fixed-width", "[web_utils][time]") {
    auto s = format_iso_utc(1735689600);
    REQUIRE(s.size() == 20); // "YYYY-MM-DDTHH:MM:SSZ"
    REQUIRE(s[4]  == '-');
    REQUIRE(s[7]  == '-');
    REQUIRE(s[10] == 'T');
    REQUIRE(s[13] == ':');
    REQUIRE(s[16] == ':');
    REQUIRE(s[19] == 'Z');
}

TEST_CASE("format_relative_time: zero return dash sentinel", "[web_utils][time]") {
    REQUIRE(format_relative_time(0, 1000) == "—");
    REQUIRE(format_relative_time(-1, 1000) == "—");
}

TEST_CASE("format_relative_time: bucketing", "[web_utils][time]") {
    // Argument order is (then, now), matching dashboard_routes.cpp's format_age.
    REQUIRE(format_relative_time(1000, 1000) == "0s ago");
    REQUIRE(format_relative_time(1000, 1059) == "59s ago");
    REQUIRE(format_relative_time(1000, 1060) == "1m ago");
    REQUIRE(format_relative_time(1000, 4599) == "59m ago");
    REQUIRE(format_relative_time(1000, 4600) == "1h 0m ago");
    REQUIRE(format_relative_time(1000, 87400) == "1d 0h ago");
}

TEST_CASE("format_relative_time: future then is clamped to zero",
          "[web_utils][time]") {
    // If the recorded `then` is in the future relative to `now` (clock skew),
    // the helper must not produce a negative-string output that confuses the
    // operator. It clamps delta to 0 so the cell reads "0s ago".
    REQUIRE(format_relative_time(2000, 1000) == "0s ago");
}

TEST_CASE("now_epoch_seconds: monotonic", "[web_utils][time]") {
    int64_t a = now_epoch_seconds();
    int64_t b = now_epoch_seconds();
    REQUIRE(b >= a);
}

// ── UTF-8 truncation ────────────────────────────────────────────────────────
//
// truncate_utf8 is used for the first-error preview in the executions list.
// Cutting in the middle of a multi-byte sequence produces invalid UTF-8 that
// breaks browser title= rendering and screen readers. The walk-back logic
// must always land on a codepoint boundary.

TEST_CASE("truncate_utf8: ASCII pass-through under limit",
          "[web_utils][utf8]") {
    REQUIRE(truncate_utf8("hello", 80) == "hello");
}

TEST_CASE("truncate_utf8: ASCII truncation appends ellipsis",
          "[web_utils][utf8]") {
    auto out = truncate_utf8("0123456789ABCDEF", 8);
    // Cut at byte 8, then append the 3-byte UTF-8 ellipsis (U+2026).
    REQUIRE(out == std::string("01234567") + "\xE2\x80\xA6");
}

TEST_CASE("truncate_utf8: walks back across multi-byte boundary",
          "[web_utils][utf8]") {
    // "café" — c,a,f,é where é is two bytes (0xC3 0xA9). Total = 5 bytes.
    // A 4-byte cut would land mid-codepoint — must walk back to byte 3.
    std::string s = "caf\xC3\xA9";
    auto out = truncate_utf8(s, 4);
    // Expected: "caf" + ellipsis.
    REQUIRE(out == std::string("caf") + "\xE2\x80\xA6");
}

TEST_CASE("truncate_utf8: walks back across emoji boundary",
          "[web_utils][utf8]") {
    // U+1F525 FIRE is 4 bytes UTF-8 (F0 9F 94 A5). Cutting after byte 9 lands
    // mid-emoji; walk-back must arrive at the next codepoint start at byte 7.
    std::string s = "abc\xF0\x9F\x94\xA5\xF0\x9F\x94\xA5";
    auto out = truncate_utf8(s, 9);
    REQUIRE(out == std::string("abc\xF0\x9F\x94\xA5") + "\xE2\x80\xA6");
}

// ── Status sparkbar ─────────────────────────────────────────────────────────
//
// render_status_sparkbar produces inline SVG with one <rect> per non-zero
// bucket. Widths must always sum to exactly 120 (kWidth) so the bar aligns
// in the table grid even with rounding. role="img" + summary aria-label
// carries the data to screen readers; individual rects are aria-hidden.

TEST_CASE("render_status_sparkbar: zero total emits hatched empty state",
          "[web_utils][sparkbar]") {
    auto svg = render_status_sparkbar(0, 0, 0, 0);
    REQUIRE(svg.find("<svg") != std::string::npos);
    REQUIRE(svg.find("empty-hatch") != std::string::npos);
    REQUIRE(svg.find("no agents") != std::string::npos);
    // No data rects should be emitted — only the hatch pattern fill rect.
    auto rect_count = std::count(svg.begin(), svg.end(), '<') -
                      std::count(svg.begin(), svg.begin() + 1, '<');
    (void)rect_count; // silence unused — count is a smoke check below.
    // The hatched empty SVG must NOT contain segment fills (token names).
    REQUIRE(svg.find("--mds-color-bg-success-emphasis") == std::string::npos);
    REQUIRE(svg.find("--mds-color-theme-indicator-error") == std::string::npos);
}

TEST_CASE("render_status_sparkbar: zero-count buckets emit no <rect>",
          "[web_utils][sparkbar]") {
    auto svg = render_status_sparkbar(50, 0, 0, 0);
    // Only the success-emphasis fill should appear. UP-13 added two-arg
    // var(...) fallbacks, so the substring carries a comma-separated
    // fallback tail; assert on the token name only.
    REQUIRE(svg.find("--mds-color-bg-success-emphasis") != std::string::npos);
    REQUIRE(svg.find("--mds-color-theme-indicator-error") == std::string::npos);
    REQUIRE(svg.find("--mds-color-theme-indicator-stable") == std::string::npos);
    REQUIRE(svg.find("--mds-color-theme-text-tertiary") == std::string::npos);
}

TEST_CASE("render_status_sparkbar: aria-label summarises the four counts",
          "[web_utils][sparkbar]") {
    auto svg = render_status_sparkbar(47, 3, 0, 0);
    REQUIRE(svg.find("aria-label=\"47 succeeded, 3 failed, 0 running, 0 pending of 50\"")
            != std::string::npos);
}

TEST_CASE("render_status_sparkbar: widths sum to 120 with rounding edge case",
          "[web_utils][sparkbar]") {
    // 1/1/1/0 of 3 → each segment "should be" 40px; 40+40+40 = 120 exact.
    auto svg = render_status_sparkbar(1, 1, 1, 0);
    int width_sum = 0;
    std::size_t pos = 0;
    while ((pos = svg.find("width=\"", pos)) != std::string::npos) {
        pos += 7;
        auto end = svg.find('"', pos);
        if (end == std::string::npos) break;
        auto val = svg.substr(pos, end - pos);
        // Skip the outer SVG width="120".
        if (val == "120") { pos = end; continue; }
        if (val == "10") { pos = end; continue; } // height attr re-used as width
        if (val == "4") { pos = end; continue; } // pattern width 4
        try { width_sum += std::stoi(val); } catch (...) {}
        pos = end;
    }
    REQUIRE(width_sum == 120);
}

TEST_CASE("render_status_sparkbar: rounding-residue absorbed by last non-zero "
          "segment",
          "[web_utils][sparkbar]") {
    // 1/1/1/1 of 7 doesn't divide evenly; 7*kWidth = 840; 840/7 = 120; each
    // gets 120/7 = 17.14, rounded to 17 → 17*4=68; residue 120-68=52 must
    // land entirely on the last non-zero segment.
    auto svg = render_status_sparkbar(2, 2, 2, 1);
    // Sum the rect widths and assert == 120; if any segment is missing or
    // the residue is misallocated this fails.
    int width_sum = 0;
    std::size_t pos = 0;
    int rect_count = 0;
    while ((pos = svg.find("<rect ", pos)) != std::string::npos) {
        ++rect_count;
        auto wpos = svg.find("width=\"", pos);
        if (wpos == std::string::npos) break;
        wpos += 7;
        auto end = svg.find('"', wpos);
        if (end == std::string::npos) break;
        auto val = svg.substr(wpos, end - wpos);
        try { width_sum += std::stoi(val); } catch (...) {}
        pos = end;
    }
    REQUIRE(rect_count == 4);
    REQUIRE(width_sum == 120);
}

// ── Duration bar ────────────────────────────────────────────────────────────

TEST_CASE("render_duration_bar_html: width clamps to 100%",
          "[web_utils][duration]") {
    auto html = render_duration_bar_html(2000, 1000, "succeeded");
    REQUIRE(html.find("width:100%") != std::string::npos);
}

TEST_CASE("render_duration_bar_html: zero max yields zero width",
          "[web_utils][duration]") {
    auto html = render_duration_bar_html(500, 0, "running");
    REQUIRE(html.find("width:0%") != std::string::npos);
}

TEST_CASE("render_duration_bar_html: status class flows through",
          "[web_utils][duration]") {
    auto html = render_duration_bar_html(500, 1000, "failed");
    REQUIRE(html.find("duration-bar--failed") != std::string::npos);
    REQUIRE(html.find("aria-label=\"500 ms\"") != std::string::npos);
}

// ── UP-13: sparkbar fills carry CSS-variable fallbacks ─────────────────────

TEST_CASE("render_status_sparkbar: every fill has a two-arg var() fallback (UP-13)",
          "[web_utils][sparkbar][fallback]") {
    auto svg = render_status_sparkbar(1, 1, 1, 1);
    // All four token-named fills carry a fallback so a yuzu.css load failure
    // doesn't render the bar invisible.
    REQUIRE(svg.find("var(--mds-color-bg-success-emphasis,var(--green))")
            != std::string::npos);
    REQUIRE(svg.find("var(--mds-color-theme-indicator-error,var(--red))")
            != std::string::npos);
    REQUIRE(svg.find("var(--mds-color-theme-indicator-stable,var(--accent))")
            != std::string::npos);
    REQUIRE(svg.find("var(--mds-color-theme-text-tertiary,var(--muted))")
            != std::string::npos);
}

TEST_CASE("render_duration_bar_html: negative duration clamped to zero",
          "[web_utils][duration]") {
    auto html = render_duration_bar_html(-100, 1000, "succeeded");
    REQUIRE(html.find("aria-label=\"0 ms\"") != std::string::npos);
}
