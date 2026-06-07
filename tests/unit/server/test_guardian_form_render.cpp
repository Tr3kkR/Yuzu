/**
 * test_guardian_form_render.cpp — the schema→form decode half of the Guardian
 * "New Guard" authoring modal (guardian_form_render.hpp).
 *
 * assemble_spark_assertion() is the load-bearing logic: it reads exactly the
 * chosen trigger's param keys from the compiled-in schema catalog (namespaced
 * field names), validates required keys, omits empty optionals so downstream
 * defaults apply, and derives the paired spark from the assertion family. These
 * tests pin that mapping so a catalog change or a refactor cannot silently drift
 * the dashboard create away from what the REST create / agent expect.
 *
 * NOTE the boundary: this covers the decode contract, NOT the htmx form
 * submission itself (namespacing + disabled-fieldset behaviour live only in the
 * browser path and are verified live).
 */

#include "guardian_form_render.hpp"

#include <catch2/catch_test_macros.hpp>

#include <nlohmann/json.hpp>

#include <functional>
#include <map>
#include <string>

using yuzu::server::guardian::assemble_spark_assertion;
using yuzu::server::guardian::form_field_name;
using yuzu::server::guardian::render_baseline_form;
using yuzu::server::guardian::render_guard_form;

namespace {

// A form-value getter backed by a flat map (missing key → ""), matching the
// httplib param getter the route passes in.
std::function<std::string(const std::string&)> getter(std::map<std::string, std::string> form) {
    return [form = std::move(form)](const std::string& k) -> std::string {
        auto it = form.find(k);
        return it == form.end() ? std::string{} : it->second;
    };
}

} // namespace

TEST_CASE("assemble registry-value-equals: params + implied registry-change spark",
          "[guardian][form]") {
    const std::string t = "registry-value-equals";
    auto sa = assemble_spark_assertion(
        t, getter({
               {form_field_name(t, "hive"), "HKLM"},
               {form_field_name(t, "key"), "SOFTWARE\\YuzuTest"},
               {form_field_name(t, "value_name"), "Flag"},
               {form_field_name(t, "value_type"), "REG_DWORD"},
               {form_field_name(t, "expected"), "1"},
           }));

    REQUIRE_FALSE(sa.error.has_value());
    CHECK(sa.spark["type"] == "registry-change");
    CHECK(sa.spark["params"].empty()); // spark target comes from the assertion
    CHECK(sa.assertion["type"] == t);
    const auto& p = sa.assertion["params"];
    CHECK(p["hive"] == "HKLM");
    CHECK(p["key"] == "SOFTWARE\\YuzuTest");
    CHECK(p["value_name"] == "Flag");
    CHECK(p["value_type"] == "REG_DWORD");
    CHECK(p["expected"] == "1");
}

TEST_CASE("assemble file-exists: file-change spark; only path required", "[guardian][form]") {
    const std::string t = "file-exists";

    SECTION("path + desired state") {
        auto sa = assemble_spark_assertion(t, getter({
                                                  {form_field_name(t, "path"), "C:\\App\\config.json"},
                                                  {form_field_name(t, "expected"), "absent"},
                                              }));
        REQUIRE_FALSE(sa.error.has_value());
        CHECK(sa.spark["type"] == "file-change");
        CHECK(sa.assertion["type"] == "file-exists");
        CHECK(sa.assertion["params"]["path"] == "C:\\App\\config.json");
        CHECK(sa.assertion["params"]["expected"] == "absent");
    }

    SECTION("missing required path → named error, not a silent empty assertion") {
        auto sa = assemble_spark_assertion(t, getter({}));
        REQUIRE(sa.error.has_value());
        CHECK(sa.error->find("Path") != std::string::npos);
    }
}

TEST_CASE("assemble file-hash-equals: omit empty optionals so agent defaults apply",
          "[guardian][form]") {
    const std::string t = "file-hash-equals";

    SECTION("path only — expected_hash/max_bytes/settle_ms omitted when blank") {
        auto sa = assemble_spark_assertion(t, getter({
                                                  {form_field_name(t, "path"), "C:\\App\\app.exe"},
                                                  {form_field_name(t, "expected_hash"), ""},
                                                  {form_field_name(t, "max_bytes"), ""},
                                                  {form_field_name(t, "settle_ms"), ""},
                                              }));
        REQUIRE_FALSE(sa.error.has_value());
        CHECK(sa.spark["type"] == "file-change");
        const auto& p = sa.assertion["params"];
        CHECK(p["path"] == "C:\\App\\app.exe");
        CHECK_FALSE(p.contains("expected_hash")); // blank baseline → absent → captured on arm
        CHECK_FALSE(p.contains("max_bytes"));     // absent → agent default (67108864)
        CHECK_FALSE(p.contains("settle_ms"));     // absent → agent default (750)
    }

    SECTION("provided optionals are carried through") {
        const std::string hash(64, 'a');
        auto sa = assemble_spark_assertion(t, getter({
                                                  {form_field_name(t, "path"), "C:\\App\\app.exe"},
                                                  {form_field_name(t, "expected_hash"), hash},
                                                  {form_field_name(t, "settle_ms"), "1500"},
                                              }));
        REQUIRE_FALSE(sa.error.has_value());
        CHECK(sa.assertion["params"]["expected_hash"] == hash);
        CHECK(sa.assertion["params"]["settle_ms"] == "1500");
    }
}

TEST_CASE("assemble rejects an unknown trigger type", "[guardian][form]") {
    auto sa = assemble_spark_assertion("not-a-real-type", getter({}));
    REQUIRE(sa.error.has_value());
    CHECK(sa.error->find("Unknown trigger type") != std::string::npos);
}

TEST_CASE("namespaced field names keep same-named params from colliding", "[guardian][form]") {
    // Both registry-value-equals and file-exists declare an "expected" param. The
    // namespacing means a getter carrying BOTH cannot let one shadow the other.
    auto form = getter({
        {form_field_name("registry-value-equals", "expected"), "1"},
        {form_field_name("file-exists", "path"), "C:\\App\\config.json"},
        {form_field_name("file-exists", "expected"), "present"},
    });
    auto reg = assemble_spark_assertion("registry-value-equals",
                                        getter({
                                            {form_field_name("registry-value-equals", "hive"), "HKLM"},
                                            {form_field_name("registry-value-equals", "key"), "K"},
                                            {form_field_name("registry-value-equals", "value_type"), "REG_SZ"},
                                            {form_field_name("registry-value-equals", "expected"), "1"},
                                        }));
    auto fil = assemble_spark_assertion("file-exists", form);
    REQUIRE_FALSE(reg.error.has_value());
    REQUIRE_FALSE(fil.error.has_value());
    CHECK(reg.assertion["params"]["expected"] == "1");        // the registry value
    CHECK(fil.assertion["params"]["expected"] == "present");  // the file desired-state
}

TEST_CASE("render_guard_form emits the schema-driven trigger surface", "[guardian][form]") {
    const std::string html = render_guard_form();
    CHECK(html.find("trigger_type") != std::string::npos);
    CHECK(html.find("guardianPickTrigger") != std::string::npos);
    // Each catalog trigger is reachable as an option + its namespaced fields.
    CHECK(html.find("value=\"registry-value-equals\"") != std::string::npos);
    CHECK(html.find("value=\"file-hash-equals\"") != std::string::npos);
    CHECK(html.find(form_field_name("file-hash-equals", "path")) != std::string::npos);
    CHECK(html.find("Resilience policy") != std::string::npos);
    // Single Mode control (Watch | Enforce) drives the enforce-only remediation block.
    CHECK(html.find("name=\"mode\"") != std::string::npos);
    CHECK(html.find("guardianPickMode") != std::string::npos);
    CHECK(html.find("gs-enforce-only") != std::string::npos);
    // The old redundant fields are gone.
    CHECK(html.find("name=\"enforcement_mode\"") == std::string::npos);
    CHECK(html.find("name=\"remediation_action\"") == std::string::npos);
    // An injected error banner appears in the re-render path.
    CHECK(render_guard_form("<div id=\"boom\"></div>").find("boom") != std::string::npos);
}

TEST_CASE("render_baseline_form: guard datalist typeahead + deferred targeting note",
          "[guardian][form]") {
    const std::string html = render_baseline_form({"block-smb-445", "edr-running"});
    // Member guards is a native type-to-filter datalist seeded with existing guards.
    CHECK(html.find("<datalist id=\"bl-guard-datalist\">") != std::string::npos);
    CHECK(html.find("value=\"block-smb-445\"") != std::string::npos);
    CHECK(html.find("value=\"edr-running\"") != std::string::npos);
    CHECK(html.find("guardianAddGuardChip") != std::string::npos);
    // Targeting moved to management-group assignment on the detail panel — the old
    // single-Scope-DSL text field is gone (superseded; see guardian-baseline-model.md).
    CHECK(html.find("name=\"scope\"") == std::string::npos);
    CHECK(html.find("management groups") != std::string::npos);
    CHECK(html.find("hx-post=\"/fragments/guardian/baselines\"") != std::string::npos);
    // Empty guard set still renders an honest hint, no crash.
    CHECK(render_baseline_form({}).find("No Guards defined yet") != std::string::npos);
}
