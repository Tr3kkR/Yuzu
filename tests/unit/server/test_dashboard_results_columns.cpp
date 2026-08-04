/**
 * test_dashboard_results_columns.cpp -- render harness for
 * DashboardRoutes::resolve_render_columns / render_results (PR1.7
 * remediation).
 *
 * `columns_for_plugin` (result_parsing.hpp) resolves a fixed column schema
 * per PLUGIN name, with no notion of ACTION. registry's `list_profiles`
 * action has no entry there, so before this fix its rows (4 named fields:
 * sid, profile_name, profile_path, hive_state) rendered under the 2-column
 * default {"Agent","Output"} -- and once a response-template resolved, the
 * header/data mismatch became total suppression: every profile field was
 * hidden, leaving only the Agent column. The fix adds
 * `resolve_render_columns`, which derives columns from a resolved
 * InstructionDefinition's `result_schema` via
 * `ResponseTemplatesEngine::synthesise_default` when one is available,
 * falling back to `columns_for_plugin` otherwise.
 *
 * Only `ResponseTemplatesEngine::synthesise_default` itself was previously
 * pinned (test_response_templates_engine.cpp) -- this file closes the gap at
 * the layer the actual bug lived: render_results' header AND row-visibility
 * logic (`is_visible()`), which is what the pre-fix `is_visible()` check
 * actually suppressed against.
 *
 * render_results and its inputs (instruction_store_, response_store_) are
 * private; the DashboardResultsColumnsTestAccess friend seam
 * (dashboard_routes.hpp) wires them without standing up an HTTP server, same
 * shape as test_dashboard_tar_retention.cpp's seam.
 */

#include "dashboard_routes.hpp"
#include "instruction_store.hpp"
#include "response_store.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

namespace yuzu::server {

// Test-only accessor for the private schema-aware column resolution +
// render_results, and their store inputs (PR1.7 remediation, Gate 3).
struct DashboardResultsColumnsTestAccess {
    DashboardRoutes routes;

    void set_stores(InstructionStore* is, ResponseStore* rs) {
        routes.instruction_store_ = is;
        routes.response_store_ = rs;
    }
    std::string render(const std::string& command_id, const std::string& plugin,
                       const std::string& definition_id = {}) {
        return routes.render_results(command_id, plugin, /*sort_col=*/"agent",
                                     /*sort_dir=*/"asc", /*page=*/1, /*per_page=*/50,
                                     /*filters=*/{}, /*text_query=*/"", definition_id);
    }
};

namespace {

bool contains(const std::string& hay, std::string_view needle) {
    return hay.find(needle) != std::string::npos;
}

// registry.yaml's list_profiles result_schema, byte-shaped as
// embed_content.py's `json.dumps(spec["result"])` actually emits it: an
// object with a top-level "columns" key, not the bare array
// legacy_shim.cpp's auto-generated definitions use.
constexpr const char* kListProfilesSchema = R"({"columns":[
    {"name":"sid","type":"string"},
    {"name":"profile_name","type":"string"},
    {"name":"profile_path","type":"string"},
    {"name":"hive_state","type":"string"}
]})";

InstructionDefinition make_list_profiles_definition() {
    InstructionDefinition def;
    def.name = "List User Profiles";
    def.version = "1.0.0";
    def.plugin = "registry";
    def.action = "list_profiles";
    def.type = "question";
    def.description = "Enumerate local Windows user profiles.";
    def.enabled = true;
    def.result_schema = kListProfilesSchema;
    return def;
}

constexpr const char* kAliceSid = "S-1-5-21-1-2-3-1001";

StoredResponse mk_list_profiles_response(const std::string& command_id) {
    StoredResponse r;
    r.instruction_id = command_id; // render_results queries the store by this
    r.agent_id = "agent-1";
    r.received_at_ms = 1000;
    r.status = 0;
    // render_profile_row's real wire shape (user_profile_model.hpp): raw
    // pipe-joined fields, no leading discriminator tag.
    r.output = std::string{kAliceSid} + "|alice|C:\\Users\\alice|loaded";
    return r;
}

std::size_t count_occurrences(const std::string& hay, std::string_view needle) {
    std::size_t n = 0, pos = 0;
    while ((pos = hay.find(needle, pos)) != std::string::npos) {
        ++n;
        pos += needle.size();
    }
    return n;
}

} // namespace

TEST_CASE("render_results: a schema-only definition (no visualization) resolves "
          "real columns instead of the plugin-only fallback (PR1.7 remediation)",
          "[server][dashboard][render_results]") {
    InstructionStore is{":memory:"};
    REQUIRE(is.is_open());
    auto created = is.create_definition(make_list_profiles_definition());
    REQUIRE(created.has_value());
    const std::string definition_id = *created;

    ResponseStore rs{":memory:"};
    const std::string command_id = "cmd-list-profiles-1";
    rs.store(mk_list_profiles_response(command_id));

    DashboardResultsColumnsTestAccess acc;
    acc.set_stores(&is, &rs);
    const std::string html = acc.render(command_id, "registry", definition_id);

    // Header: the real schema-derived column names, not "Output".
    CHECK(contains(html, "sid"));
    CHECK(contains(html, "profile_name"));
    CHECK(contains(html, "profile_path"));
    CHECK(contains(html, "hive_state"));
    CHECK_FALSE(contains(html, ">Output<"));

    // Data: every real field value renders in its OWN correctly-formed
    // <td>, not shifted into the wrong column. A substring-containment
    // check alone (contains(html, "alice")) would pass even if the row
    // were column-shifted -- this pins the exact cell markup instead
    // (Gate 4 happy-path finding: a since-removed leading tag on
    // render_profile_row's wire format shifted every field one column
    // right, and a weaker version of this test did not catch it).
    CHECK(contains(html, "<td title=\"" + std::string{kAliceSid} + "\">" +
                             kAliceSid + "</td>"));
    CHECK(contains(html, "<td title=\"alice\">alice</td>"));
    CHECK(contains(html, "<td title=\"loaded\">loaded</td>"));
    // "profile" must never appear as a rendered cell value now that the
    // tag is gone.
    CHECK_FALSE(contains(html, "<td title=\"profile\">profile</td>"));

    // Column count: Agent + 4 real fields == 5 <td> in the primary row, plus
    // 1 more for the detail-drawer row's own single colspan <td> wrapper
    // (its contents use <div>, but the wrapper itself is a <td>).
    CHECK(count_occurrences(html, "<td ") == 6);
}

TEST_CASE("render_results: no definition_id falls back to columns_for_plugin "
          "unchanged (regression pin for every other plugin/action)",
          "[server][dashboard][render_results]") {
    InstructionStore is{":memory:"};
    REQUIRE(is.is_open());

    ResponseStore rs{":memory:"};
    const std::string command_id = "cmd-no-def-1";
    StoredResponse r;
    r.instruction_id = command_id;
    r.agent_id = "agent-1";
    r.received_at_ms = 1000;
    r.status = 0;
    r.output = "some plain output line";
    rs.store(r);

    DashboardResultsColumnsTestAccess acc;
    acc.set_stores(&is, &rs);
    // No definition_id -- resolve_render_columns must fall back to
    // columns_for_plugin("registry"), which has no entry for "registry" and
    // resolves kDefaultColumns {"Agent","Output"}.
    const std::string html = acc.render(command_id, "registry");

    CHECK(contains(html, ">Output<"));
    CHECK_FALSE(contains(html, "profile_name"));
}

} // namespace yuzu::server
