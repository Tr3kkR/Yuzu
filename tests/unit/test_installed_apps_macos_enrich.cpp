/**
 * test_installed_apps_macos_enrich.cpp -- pure fixture vectors for
 * installed_apps_macos_enrich.hpp's `system_profiler -json` parse and
 * operator `list` row-assembly (#2273/1.10).
 *
 * Everything here runs against fixture strings -- no system_profiler,
 * codesign, or plutil on the test host -- because the header is pure by
 * design (same "impure collection / pure mapping" split as
 * test_filesystem_macos_sig.cpp, whose classify_codesign_result /
 * classify_plutil_extract this enrichment reuses). The signed-app fixtures
 * are trimmed from a real `system_profiler -json SPApplicationsDataType`
 * capture on a live macOS box; key order and values are otherwise untouched.
 * A couple of edge cases (no usable `path`; `obtained_from` with no
 * `signed_by`) are constructed rather than captured live, since the schema
 * does not guarantee either key is present for every entry -- each is
 * labelled below.
 */

#include <catch2/catch_test_macros.hpp>

#include "installed_apps_macos_enrich.hpp"

#include "filesystem_macos_sig.hpp"

#include <yuzu/agent/subprocess_runner.hpp>

#include <optional>
#include <string>
#include <string_view>

using namespace yuzu::installed_apps::macos_enrich;
using namespace yuzu::filesystem_macos;
using yuzu::agent::SubprocessResult;

// ── Real system_profiler -json SPApplicationsDataType captures ─────────────

// Three real, differently-signed apps in one listing: an Apple system app
// (obtained_from apple), a Mac App Store app (obtained_from mac_app_store),
// and a third-party Developer ID app (obtained_from identified_developer) --
// all three carry `signed_by`, leaf certificate first.
static const char* kRealSignedAppsJson = R"json({
  "SPApplicationsDataType": [
    {
      "_name": "App Store",
      "arch_kind": "arch_arm_i64",
      "lastModified": "2026-06-25T02:29:03Z",
      "obtained_from": "apple",
      "path": "/System/Applications/App Store.app",
      "signed_by": [
        "Software Signing",
        "Apple Code Signing Certification Authority",
        "Apple Root CA"
      ],
      "version": "3.0"
    },
    {
      "_name": "Pages",
      "arch_kind": "arch_arm_i64",
      "lastModified": "2022-10-08T21:33:16Z",
      "obtained_from": "mac_app_store",
      "path": "/Applications/Pages.app",
      "signed_by": [
        "Apple Mac OS Application Signing",
        "Apple Worldwide Developer Relations Certification Authority",
        "Apple Root CA"
      ],
      "version": "12.0"
    },
    {
      "_name": "Spotify",
      "arch_kind": "arch_ios",
      "lastModified": "2022-12-05T16:17:16Z",
      "obtained_from": "identified_developer",
      "path": "/Applications/Spotify.app",
      "signed_by": [
        "Developer ID Application: Spotify (2FNC3A47ZF)",
        "Developer ID Certification Authority",
        "Apple Root CA"
      ],
      "version": "1.2.0.1165.gabf054ab"
    }
  ]
})json";

// Real entry with obtained_from "unknown" and NO signed_by key at all, but a
// real path -- distinct from the constructed no-path fixture below.
static const char* kRealNoSignedByJson = R"json({
  "SPApplicationsDataType": [
    {
      "_name": "Automator Application Stub",
      "arch_kind": "arch_arm_i64",
      "lastModified": "2026-06-25T02:29:03Z",
      "obtained_from": "unknown",
      "path": "/System/Library/CoreServices/Automator Application Stub.app",
      "version": "1.3"
    }
  ]
})json";

// Real entry with no "version" key at all (system_profiler omits it for a
// handful of bundleless-Info.plist system helpers).
static const char* kRealNoVersionJson = R"json({
  "SPApplicationsDataType": [
    {
      "_name": "liquiddetectiond",
      "arch_kind": "arch_arm_i64",
      "lastModified": "2026-06-25T02:29:03Z",
      "obtained_from": "apple",
      "path": "/System/Library/CoreServices/liquiddetectiond.app",
      "signed_by": [
        "Software Signing",
        "Apple Code Signing Certification Authority",
        "Apple Root CA"
      ]
    }
  ]
})json";

// ── Constructed edge cases (not observed in a live capture -- see header
// comment) ───────────────────────────────────────────────────────────────

// No "path" key at all, and no "signed_by" -- PLAN-05's "an app whose JSON
// record lacks a usable path" case.
static const char* kNoPathAppJson = R"json({
  "SPApplicationsDataType": [
    {
      "_name": "Orphaned Helper",
      "obtained_from": "unknown",
      "lastModified": "2023-01-08T13:31:33Z"
    }
  ]
})json";

// obtained_from present with NO signed_by -- every real mac_app_store entry
// observed live carries signed_by too, but the JSON schema does not
// guarantee that pairing, so the raw-obtained_from-echo fallback needs its
// own direct coverage.
static const char* kObtainedFromFallbackJson = R"json({
  "SPApplicationsDataType": [
    {
      "_name": "Hypothetical MAS App",
      "obtained_from": "mac_app_store",
      "path": "/Applications/Hypothetical MAS App.app",
      "version": "1.0",
      "lastModified": "2024-01-01T00:00:00Z"
    }
  ]
})json";

// ── parse_system_profiler_apps_json ─────────────────────────────────────────

TEST_CASE("parse_system_profiler_apps_json: three differently-signed real apps parse correctly",
          "[installed_apps][macos][enrich]") {
    auto apps = parse_system_profiler_apps_json(kRealSignedAppsJson);
    REQUIRE(apps.size() == 3);

    CHECK(apps[0].name == "App Store");
    CHECK(apps[0].version == "3.0");
    CHECK(apps[0].path == "/System/Applications/App Store.app");
    CHECK(apps[0].last_modified == "2026-06-25T02:29:03Z");
    CHECK(apps[0].publisher == "Software Signing"); // signed_by leaf

    CHECK(apps[1].name == "Pages");
    CHECK(apps[1].path == "/Applications/Pages.app");
    CHECK(apps[1].publisher == "Apple Mac OS Application Signing");

    CHECK(apps[2].name == "Spotify");
    CHECK(apps[2].version == "1.2.0.1165.gabf054ab");
    CHECK(apps[2].path == "/Applications/Spotify.app");
    CHECK(apps[2].publisher == "Developer ID Application: Spotify (2FNC3A47ZF)");
}

TEST_CASE("parse_system_profiler_apps_json: obtained_from=unknown with no signed_by "
          "maps publisher to '-', never echoed verbatim",
          "[installed_apps][macos][enrich]") {
    auto apps = parse_system_profiler_apps_json(kRealNoSignedByJson);
    REQUIRE(apps.size() == 1);
    CHECK(apps[0].name == "Automator Application Stub");
    CHECK(apps[0].path == "/System/Library/CoreServices/Automator Application Stub.app");
    CHECK(apps[0].publisher == "-");
}

TEST_CASE("parse_system_profiler_apps_json: a missing version key parses with version empty",
          "[installed_apps][macos][enrich]") {
    auto apps = parse_system_profiler_apps_json(kRealNoVersionJson);
    REQUIRE(apps.size() == 1);
    CHECK(apps[0].name == "liquiddetectiond");
    CHECK(apps[0].version.empty());
    CHECK(apps[0].publisher == "Software Signing");
}

TEST_CASE("parse_system_profiler_apps_json: no usable path degrades to an empty path, "
          "never a synthesised /Applications/<name>.app",
          "[installed_apps][macos][enrich]") {
    auto apps = parse_system_profiler_apps_json(kNoPathAppJson);
    REQUIRE(apps.size() == 1);
    CHECK(apps[0].name == "Orphaned Helper");
    CHECK(apps[0].path.empty()); // PLAN-05: never fabricated
    CHECK(apps[0].publisher == "-");
}

TEST_CASE("parse_system_profiler_apps_json: obtained_from is the publisher fallback "
          "when signed_by is absent",
          "[installed_apps][macos][enrich]") {
    auto apps = parse_system_profiler_apps_json(kObtainedFromFallbackJson);
    REQUIRE(apps.size() == 1);
    CHECK(apps[0].publisher == "mac_app_store");
}

TEST_CASE("parse_system_profiler_apps_json: malformed JSON degrades to an empty vector, "
          "never throws",
          "[installed_apps][macos][enrich]") {
    auto apps = parse_system_profiler_apps_json("{not valid json");
    CHECK(apps.empty());
}

TEST_CASE("parse_system_profiler_apps_json: a missing SPApplicationsDataType key "
          "degrades to an empty vector",
          "[installed_apps][macos][enrich]") {
    auto apps = parse_system_profiler_apps_json(R"({"SomeOtherDataType": []})");
    CHECK(apps.empty());
}

TEST_CASE("parse_system_profiler_apps_json: a non-array SPApplicationsDataType "
          "degrades to an empty vector",
          "[installed_apps][macos][enrich]") {
    auto apps = parse_system_profiler_apps_json(R"({"SPApplicationsDataType": "oops"})");
    CHECK(apps.empty());
}

TEST_CASE("parse_system_profiler_apps_json: a non-object array element is skipped, "
          "not fatal to the rest of the listing",
          "[installed_apps][macos][enrich]") {
    auto apps = parse_system_profiler_apps_json(
        R"({"SPApplicationsDataType": [42, {"_name": "Real", "path": "/Applications/Real.app"}]})");
    REQUIRE(apps.size() == 1);
    CHECK(apps[0].name == "Real");
}

TEST_CASE("parse_system_profiler_apps_json: an element with no (or empty) _name is dropped",
          "[installed_apps][macos][enrich]") {
    auto apps = parse_system_profiler_apps_json(
        R"({"SPApplicationsDataType": [
              {"path": "/Applications/NoNameKey.app"},
              {"_name": "", "path": "/Applications/EmptyName.app"},
              {"_name": "Named", "path": "/Applications/Named.app"}
        ]})");
    REQUIRE(apps.size() == 1);
    CHECK(apps[0].name == "Named");
}

// ── BR-06: non-string/null field values never throw ────────────────────────
//
// Runtime-confirmed crash: json::value("_name", "") on a JSON number throws
// json::exception::type_error.302 -- these fixtures cover a non-string
// _name (record dropped, matching the empty/missing-name contract) and
// non-string version/path/lastModified (record kept, those fields degrade
// to "").

TEST_CASE("parse_system_profiler_apps_json: a numeric _name is dropped, never throws",
          "[installed_apps][macos][enrich]") {
    auto apps = parse_system_profiler_apps_json(
        R"({"SPApplicationsDataType": [
              {"_name": 42, "path": "/Applications/Numeric.app"},
              {"_name": "Named", "path": "/Applications/Named.app"}
        ]})");
    REQUIRE(apps.size() == 1);
    CHECK(apps[0].name == "Named");
}

TEST_CASE("parse_system_profiler_apps_json: a null _name is dropped, never throws",
          "[installed_apps][macos][enrich]") {
    auto apps = parse_system_profiler_apps_json(
        R"({"SPApplicationsDataType": [{"_name": null, "path": "/Applications/Null.app"}]})");
    CHECK(apps.empty());
}

TEST_CASE("parse_system_profiler_apps_json: non-string version/path/lastModified degrade "
          "to empty rather than throwing, the record survives",
          "[installed_apps][macos][enrich]") {
    auto apps = parse_system_profiler_apps_json(
        R"({"SPApplicationsDataType": [
              {"_name": "Weird", "version": 1, "path": true, "lastModified": {}}
        ]})");
    REQUIRE(apps.size() == 1);
    CHECK(apps[0].name == "Weird");
    CHECK(apps[0].version.empty());
    CHECK(apps[0].path.empty());
    CHECK(apps[0].last_modified.empty());
}

TEST_CASE("parse_system_profiler_apps_json: an array _name is dropped, never throws",
          "[installed_apps][macos][enrich]") {
    auto apps = parse_system_profiler_apps_json(
        R"({"SPApplicationsDataType": [{"_name": ["not", "a", "string"]}]})");
    CHECK(apps.empty());
}

// ── BR-05: a truncated system_profiler capture never parses to a false
// empty success -- the plugin (not this pure parser) is what turns
// output_truncated into the honest nonzero path, but the parser itself
// must survive genuinely truncated (invalid) JSON without throwing, same
// as any other malformed-JSON case above.

TEST_CASE("parse_system_profiler_apps_json: JSON truncated mid-object degrades to an "
          "empty vector, never throws",
          "[installed_apps][macos][enrich]") {
    // A realistic truncation: capture cut off mid-way through a record,
    // same shape run_bounded_subprocess's output_truncated cap produces.
    auto apps = parse_system_profiler_apps_json(
        R"json({"SPApplicationsDataType": [{"_name": "App Store", "path": "/System/Applications/App)json");
    CHECK(apps.empty());
}

TEST_CASE("truncated_listing_outcome: output_truncated=true yields the honest sentinel "
          "row and nonzero rc, never the empty-success 'No applications found' rc 0",
          "[installed_apps][macos][enrich]") {
    // Pure fixture -- no subprocess spawned. Mirrors what do_list_macos sees
    // when run_bounded_subprocess's internal size cap truncates a >1MB
    // system_profiler capture: tool_ran/exit_code still look like a clean
    // success, only output_truncated flags the honest partial.
    SubprocessResult sp_result{
        .tool_ran = true, .exit_code = 0, .timed_out = false, .output_truncated = true};

    auto outcome = truncated_listing_outcome(sp_result);
    REQUIRE(outcome.has_value());
    CHECK(outcome->second != 0);
    CHECK(outcome->first != "app|No applications found|-|-|-|-|-");
    CHECK(outcome->first.find("truncated") != std::string::npos);
}

TEST_CASE("truncated_listing_outcome: output_truncated=false defers to the caller's own "
          "empty/populated handling",
          "[installed_apps][macos][enrich]") {
    SubprocessResult sp_result{.tool_ran = true, .exit_code = 0, .timed_out = false};
    CHECK_FALSE(truncated_listing_outcome(sp_result).has_value());
}

// ── signature_status_from / bundle_id_from (PLAN-02 short-circuit) ─────────

TEST_CASE("signature_status_from: nullopt (never attempted) is honest unknown",
          "[installed_apps][macos][enrich]") {
    CHECK(signature_status_from(std::nullopt) == SignatureStatus::unknown);
}

TEST_CASE("signature_status_from: a completed successful run classifies normally",
          "[installed_apps][macos][enrich]") {
    SubprocessResult result{.tool_ran = true, .exit_code = 0, .timed_out = false};
    CHECK(signature_status_from(result) == SignatureStatus::valid);
}

TEST_CASE("signature_status_from: timed_out short-circuits to unknown even though "
          "tool_ran/exit_code look like a clean success",
          "[installed_apps][macos][enrich]") {
    // PLAN-02: a codesign call killed at its deadline must never be trusted
    // for a verdict, even though -- as here -- exit_code/tool_ran alone
    // would otherwise read as a clean pass.
    SubprocessResult result{.tool_ran = true, .exit_code = 0, .timed_out = true};
    CHECK(signature_status_from(result) == SignatureStatus::unknown);
}

TEST_CASE("bundle_id_from: nullopt (never attempted) is honest not-available",
          "[installed_apps][macos][enrich]") {
    auto bundle_id = bundle_id_from(std::nullopt);
    CHECK_FALSE(bundle_id.available);
    CHECK(bundle_id.value.empty());
}

TEST_CASE("bundle_id_from: a completed successful run extracts the value",
          "[installed_apps][macos][enrich]") {
    SubprocessResult result{
        .tool_ran = true, .exit_code = 0, .timed_out = false, .output = "com.spotify.client\n"};
    auto bundle_id = bundle_id_from(result);
    CHECK(bundle_id.available);
    CHECK(bundle_id.value == "com.spotify.client");
}

TEST_CASE("bundle_id_from: timed_out short-circuits to not-available even though the "
          "captured output looks like a real value",
          "[installed_apps][macos][enrich]") {
    // PLAN-02: mirrors the signature_status_from timed_out case above -- a
    // plutil call killed at its deadline must never be trusted, even though
    // -- as here -- it happened to capture what looks like a clean value
    // before being killed.
    SubprocessResult result{
        .tool_ran = true, .exit_code = 0, .timed_out = true, .output = "com.spotify.client\n"};
    auto bundle_id = bundle_id_from(result);
    CHECK_FALSE(bundle_id.available);
    CHECK(bundle_id.value.empty());
}

// ── format_operator_list_row ────────────────────────────────────────────────

TEST_CASE("format_operator_list_row: both results nullopt (never attempted) "
          "renders unknown signature_status and absent bundle_id",
          "[installed_apps][macos][enrich]") {
    MacAppRecord app{.name = "Foo",
                     .version = "1.0",
                     .path = "/Applications/Foo.app",
                     .publisher = "Foo Inc",
                     .last_modified = "2024-01-01T00:00:00Z"};
    auto row = format_operator_list_row(app, std::nullopt, std::nullopt);
    CHECK(row == "app|Foo|1.0|Foo Inc|2024-01-01T00:00:00Z|unknown|-");
}

TEST_CASE("format_operator_list_row: a no-path app (never eligible for enrichment) "
          "renders the same honest unknown/absent shape",
          "[installed_apps][macos][enrich]") {
    // End-to-end: parse a record with no usable path, then format it exactly
    // as do_list_macos() would -- it never calls codesign/plutil for an
    // empty path, so both results stay nullopt.
    auto apps = parse_system_profiler_apps_json(kNoPathAppJson);
    REQUIRE(apps.size() == 1);
    REQUIRE(apps[0].path.empty());

    auto row = format_operator_list_row(apps[0], std::nullopt, std::nullopt);
    CHECK(row == "app|Orphaned Helper|-|-|2023-01-08T13:31:33Z|unknown|-");
}

TEST_CASE("format_operator_list_row: a fully enriched valid, signed app renders both columns",
          "[installed_apps][macos][enrich]") {
    MacAppRecord app{.name = "Spotify",
                     .version = "1.2.0",
                     .path = "/Applications/Spotify.app",
                     .publisher = "Developer ID Application: Spotify (2FNC3A47ZF)",
                     .last_modified = "2022-12-05T16:17:16Z"};
    SubprocessResult codesign_result{.tool_ran = true, .exit_code = 0, .timed_out = false};
    SubprocessResult plutil_result{.tool_ran = true,
                                   .exit_code = 0,
                                   .timed_out = false,
                                   .output = "com.spotify.client\n"};

    auto row = format_operator_list_row(app, codesign_result, plutil_result);
    CHECK(row == "app|Spotify|1.2.0|Developer ID Application: Spotify (2FNC3A47ZF)|"
                "2022-12-05T16:17:16Z|valid|com.spotify.client");
}

TEST_CASE("format_operator_list_row: a timed-out codesign call short-circuits "
          "signature_status to unknown, not the misleadingly-clean exit_code=0",
          "[installed_apps][macos][enrich]") {
    MacAppRecord app{.name = "Foo", .path = "/Applications/Foo.app"};
    // exit_code 0 would classify as "valid" if timed_out were ignored --
    // this is the PLAN-02 short-circuit's whole point.
    SubprocessResult codesign_result{.tool_ran = true, .exit_code = 0, .timed_out = true};

    auto row = format_operator_list_row(app, codesign_result, std::nullopt);
    CHECK(row == "app|Foo|-|-|-|unknown|-");
}

TEST_CASE("format_operator_list_row: a timed-out plutil call short-circuits bundle_id "
          "to absent, not the misleadingly-clean captured value",
          "[installed_apps][macos][enrich]") {
    MacAppRecord app{.name = "Foo", .path = "/Applications/Foo.app"};
    SubprocessResult plutil_result{
        .tool_ran = true, .exit_code = 0, .timed_out = true, .output = "com.example.app\n"};

    auto row = format_operator_list_row(app, std::nullopt, plutil_result);
    CHECK(row == "app|Foo|-|-|-|unknown|-");
}

TEST_CASE("format_operator_list_row: empty version/publisher/last_modified each "
          "render as the '-' placeholder",
          "[installed_apps][macos][enrich]") {
    MacAppRecord app{.name = "Bare", .path = "/Applications/Bare.app"};
    auto row = format_operator_list_row(app, std::nullopt, std::nullopt);
    CHECK(row == "app|Bare|-|-|-|unknown|-");
}

// ── BR-07: dynamic fields are escaped via safe_output_field ────────────────
//
// A hostile app name (or, via plutil, bundle id) carrying '|' or CR/LF
// could otherwise inject a column or a fabricated row into the
// pipe-delimited output stream; every dynamic field goes through
// yuzu::util::safe_output_field, matching the escaping other pipe-row
// producers in this codebase already apply to untrusted strings.

TEST_CASE("format_operator_list_row: a name/publisher/last_modified carrying '|' and "
          "CR/LF is escaped, never injects a column or row",
          "[installed_apps][macos][enrich]") {
    MacAppRecord app{.name = "Evil|App\r\nInjected",
                     .version = "1.0|beta",
                     .path = "/Applications/Evil.app",
                     .publisher = "Bad\nActor|Inc",
                     .last_modified = "2024-01-01T00:00:00Z\r|extra"};
    auto row = format_operator_list_row(app, std::nullopt, std::nullopt);
    CHECK(row == "app|Evil\\|App  Injected|1.0\\|beta|Bad Actor\\|Inc|"
                "2024-01-01T00:00:00Z \\|extra|unknown|-");
}

TEST_CASE("format_operator_list_row: a bundle_id carrying '|' and CR/LF is escaped",
          "[installed_apps][macos][enrich]") {
    MacAppRecord app{.name = "Foo", .path = "/Applications/Foo.app"};
    SubprocessResult plutil_result{.tool_ran = true,
                                   .exit_code = 0,
                                   .timed_out = false,
                                   .output = "com.example|evil\r\napp\n"};

    auto row = format_operator_list_row(app, std::nullopt, plutil_result);
    CHECK(row == "app|Foo|-|-|-|unknown|com.example\\|evil  app");
}
