/**
 * test_web_utils.cpp — Unit tests for server web utility functions
 *
 * Covers: base64_decode, html_escape, url_decode, extract_form_value,
 *         extract_plugin
 */

#include "web_utils.hpp"

#include <catch2/catch_test_macros.hpp>

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
