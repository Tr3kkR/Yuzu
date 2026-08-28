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
#include "pg/pg_pool.hpp"
#include "response_store.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

namespace yuzu::server {

using yuzu::server::pg::PgPool;

namespace {
// ResponseStore is now a migrated Postgres store (ADR-0039) — shares the
// "responsestore" template key with test_response_store.cpp (identical setup).
yuzu::test::PgTestTemplate responsestore_tpl{"responsestore", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    ResponseStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("responsestore template: store failed to migrate");
}};
// InstructionStore is now a migrated Postgres store (ADR-0058).
yuzu::test::PgTestTemplate dashboard_cols_instr_tpl{
    "dashcolsinstr", [](const std::string& dsn) {
        PgPool pool{{.conninfo = dsn, .size = 1}};
        InstructionStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("dashboard_cols_instr template: store failed to migrate");
    }};
} // namespace

// Test-only accessor for the private schema-aware column resolution +
// render_results, and their store inputs (PR1.7 remediation, Gate 3).
struct DashboardResultsColumnsTestAccess {
    DashboardRoutes routes;

    void set_stores(InstructionStore* is, ResponseStore* rs) {
        routes.instruction_store_ = is;
        routes.response_store_ = rs;
    }
    // #1712: test-only access to the private per-agent scope predicate.
    // Unset (default) means render_results applies NO filter, matching
    // every pre-existing test in this file.
    void set_response_scope_fn(DashboardRoutes::ResponseScopeFn fn) {
        routes.response_scope_fn_ = std::move(fn);
    }
    /// #1712: captured audit rows, so the scope-drop CC7.2 evidence branch is
    /// reachable from this seam. `render_results` only audits when it is given
    /// a non-null request AND an audit callback — `render()` below supplies
    /// neither, which is why every pre-existing test in this file is
    /// unaffected; `render_with_audit()` supplies both.
    struct AuditCall {
        std::string action, result, target_type, target_id, detail;
    };
    std::vector<AuditCall> audit_calls;

    void capture_audit() {
        routes.audit_fn_ = [this](const httplib::Request&, const std::string& action,
                                  const std::string& result, const std::string& target_type,
                                  const std::string& target_id, const std::string& detail) {
            audit_calls.push_back({action, result, target_type, target_id, detail});
        };
    }
    std::string render(const std::string& command_id, const std::string& plugin,
                       const std::string& definition_id = {},
                       const std::string& username = {}) {
        return routes.render_results(command_id, plugin, /*sort_col=*/"agent",
                                     /*sort_dir=*/"asc", /*page=*/1, /*per_page=*/50,
                                     /*filters=*/{}, /*text_query=*/"", definition_id,
                                     /*template_id=*/{}, /*visible_columns=*/{}, username);
    }
    /// Same render, but through the audit-capable path (non-null request).
    std::string render_with_audit(const std::string& command_id, const std::string& plugin,
                                  const std::string& username) {
        httplib::Request req;
        return routes.render_results(command_id, plugin, /*sort_col=*/"agent",
                                     /*sort_dir=*/"asc", /*page=*/1, /*per_page=*/50,
                                     /*filters=*/{}, /*text_query=*/"", /*definition_id=*/{},
                                     /*template_id=*/{}, /*visible_columns=*/{}, username, &req);
    }
    std::string render_filter_bar(const std::string& command_id, const std::string& plugin) {
        return routes.render_filter_bar(command_id, plugin);
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
          "[pg][server][dashboard][render_results]") {
    YUZU_REQUIRE_PG_DB_TPL(db_instr, dashboard_cols_instr_tpl);
    PgPool instr_pool{{.conninfo = db_instr.dsn(), .size = 2}};
    InstructionStore is{instr_pool};
    REQUIRE(is.is_open());
    auto created = is.create_definition(make_list_profiles_definition());
    REQUIRE(created.has_value());
    const std::string definition_id = *created;

    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore rs{pool};
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
          "[pg][server][dashboard][render_results]") {
    YUZU_REQUIRE_PG_DB_TPL(db_instr, dashboard_cols_instr_tpl);
    PgPool instr_pool{{.conninfo = db_instr.dsn(), .size = 2}};
    InstructionStore is{instr_pool};
    REQUIRE(is.is_open());

    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore rs{pool};
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

// #2691 (Doomgoose finding #7): a degraded response-store read must render
// distinguishably from a genuine zero-match answer — "No results match your
// filters" is a false claim when the store just couldn't be read.
TEST_CASE("render_results: a degraded store read renders the degrade banner "
          "not \"no results match your filters\"",
          "[server][dashboard][render_results]") {
    YUZU_REQUIRE_PG_DB_TPL(db_instr, dashboard_cols_instr_tpl);
    PgPool instr_pool{{.conninfo = db_instr.dsn(), .size = 2}};
    InstructionStore is{instr_pool};
    REQUIRE(is.is_open());

    PgPool bad_pool{{.conninfo = "host=192.0.2.1 port=1 connect_timeout=1", .size = 1}};
    ResponseStore bad_rs{bad_pool};
    REQUIRE_FALSE(bad_rs.is_open());

    DashboardResultsColumnsTestAccess acc;
    acc.set_stores(&is, &bad_rs);
    const std::string html = acc.render("cmd-degraded", "registry");

    CHECK(contains(html, "result-degrade-banner"));
    CHECK(contains(html, "Results unavailable"));
    CHECK_FALSE(contains(html, "No results match your filters"));
}

// #2691 (Gate 4 consistency-auditor): the per-column filter dropdown must not
// silently render "All" with zero options on a degraded facet_values() read —
// indistinguishable from "this column genuinely has no other values", right
// next to a results table that correctly banners the same degrade.
TEST_CASE("render_filter_bar: a degraded facet read disables the dropdown "
          "instead of rendering an empty All",
          "[server][dashboard][render_filter_bar]") {
    YUZU_REQUIRE_PG_DB_TPL(db_instr, dashboard_cols_instr_tpl);
    PgPool instr_pool{{.conninfo = db_instr.dsn(), .size = 2}};
    InstructionStore is{instr_pool};
    REQUIRE(is.is_open());

    PgPool bad_pool{{.conninfo = "host=192.0.2.1 port=1 connect_timeout=1", .size = 1}};
    ResponseStore bad_rs{bad_pool};
    REQUIRE_FALSE(bad_rs.is_open());

    DashboardResultsColumnsTestAccess acc;
    acc.set_stores(&is, &bad_rs);
    const std::string html = acc.render_filter_bar("cmd-degraded", "registry");

    CHECK(contains(html, "disabled"));
    CHECK(contains(html, "(unavailable)"));
    CHECK(contains(html, "response store degraded"));
}

// ── #1712: per-agent response-scope filter on /fragments/results ──────────
//
// Mirrors PR #1711's fix for the sibling REST/MCP response readers: a
// corrupt/load-failed rbac.db must yield ZERO response rows here, never the
// whole fleet's output. A deny-all response_scope_fn_ simulates exactly what
// response_agent_in_scope (server.cpp) returns for every agent when
// rbac_enforcement_in_effect is true and the store can't answer
// check_scoped_permission.

TEST_CASE("render_results #1712: a deny-all response scope (corrupt-rbac "
          "simulation) yields zero rows, not the agent's output",
          "[pg][server][dashboard][render_results][1712]") {
    InstructionStore is{":memory:"};
    REQUIRE(is.is_open());

    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore rs{pool};
    const std::string command_id = "cmd-scope-deny";
    StoredResponse r;
    r.instruction_id = command_id;
    r.agent_id = "agent-secret";
    r.received_at_ms = 1000;
    r.status = 0;
    r.output = "sensitive-output";
    rs.store(r);

    DashboardResultsColumnsTestAccess acc;
    acc.set_stores(&is, &rs);
    acc.set_response_scope_fn([](const std::string&, const std::string&) { return false; });
    const std::string html = acc.render(command_id, "registry", /*definition_id=*/{},
                                        /*username=*/"confined-operator");

    CHECK_FALSE(contains(html, "sensitive-output"));
    CHECK_FALSE(contains(html, "agent-secret"));
}

TEST_CASE("render_results #1712: out-of-scope agent's row is dropped while an "
          "in-scope agent's row is kept",
          "[pg][server][dashboard][render_results][1712]") {
    InstructionStore is{":memory:"};
    REQUIRE(is.is_open());

    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore rs{pool};
    const std::string command_id = "cmd-scope-mix";
    StoredResponse in_scope;
    in_scope.instruction_id = command_id;
    in_scope.agent_id = "agent-in-scope";
    in_scope.received_at_ms = 1000;
    in_scope.status = 0;
    in_scope.output = "visible-output";
    rs.store(in_scope);
    StoredResponse out_of_scope;
    out_of_scope.instruction_id = command_id;
    out_of_scope.agent_id = "agent-out-of-scope";
    out_of_scope.received_at_ms = 1001;
    out_of_scope.status = 0;
    out_of_scope.output = "hidden-output";
    rs.store(out_of_scope);

    DashboardResultsColumnsTestAccess acc;
    acc.set_stores(&is, &rs);
    acc.set_response_scope_fn([](const std::string&, const std::string& agent_id) {
        return agent_id == "agent-in-scope";
    });
    const std::string html = acc.render(command_id, "registry", /*definition_id=*/{},
                                        /*username=*/"confined-operator");

    CHECK(contains(html, "visible-output"));
    CHECK_FALSE(contains(html, "hidden-output"));
    CHECK_FALSE(contains(html, "agent-out-of-scope"));
}

TEST_CASE("render_results #1712: a scope drop emits the CC7.2 denied audit row",
          "[pg][server][dashboard][render_results][1712]") {
    // Parity with the executions drawer, which already asserts its own
    // scope_dropped audit row. Without this the dashboard's audit branch was
    // unreachable from any test: the seam always passed a null request, so
    // `dropped > 0 && req && audit_fn_` could never be true.
    InstructionStore is{":memory:"};
    REQUIRE(is.is_open());

    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore rs{pool};
    const std::string command_id = "cmd-scope-audit";
    for (const auto& [agent, out] : std::vector<std::pair<std::string, std::string>>{
             {"agent-in-scope", "visible-output"},
             {"agent-out-a", "hidden-a"},
             {"agent-out-b", "hidden-b"}}) {
        StoredResponse r;
        r.instruction_id = command_id;
        r.agent_id = agent;
        r.received_at_ms = 1000;
        r.status = 0;
        r.output = out;
        rs.store(r);
    }

    DashboardResultsColumnsTestAccess acc;
    acc.set_stores(&is, &rs);
    acc.capture_audit();
    acc.set_response_scope_fn([](const std::string&, const std::string& agent_id) {
        return agent_id == "agent-in-scope";
    });
    const std::string html =
        acc.render_with_audit(command_id, "registry", /*username=*/"confined-operator");

    CHECK(contains(html, "visible-output"));
    CHECK_FALSE(contains(html, "hidden-a"));
    CHECK_FALSE(contains(html, "hidden-b"));

    bool found = false;
    for (const auto& c : acc.audit_calls) {
        if (c.action == "response.read" && c.result == "denied" && c.target_id == command_id &&
            contains(c.detail, "surface=fragments_results")) {
            found = true;
            // TWO distinct agents were dropped across two rows — the count is
            // per distinct agent, not per row.
            CHECK(contains(c.detail, "scope_dropped=2"));
        }
    }
    CHECK(found);
}

TEST_CASE("render_results #1712: the summary agent count describes only in-scope agents",
          "[pg][server][dashboard][render_results][1712]") {
    // The rows were filtered but `total_agent_count` was computed from the
    // UNFILTERED read and rendered as "N results across M agents", disclosing
    // to a confined operator how many agents outside their management group
    // answered the command. The full deny-all case hid this incidentally
    // (an empty result set skips the summary block entirely), so only the
    // MIXED case exposes it — which is why this test is mixed-scope.
    InstructionStore is{":memory:"};
    REQUIRE(is.is_open());

    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore rs{pool};
    const std::string command_id = "cmd-scope-count";
    // One in-scope agent, four out-of-scope: an unreconciled count renders
    // "across 5 agents"; the reconciled one renders "across 1 agent".
    for (int i = 0; i < 5; ++i) {
        StoredResponse r;
        r.instruction_id = command_id;
        r.agent_id = (i == 0) ? "agent-in-scope" : ("agent-out-" + std::to_string(i));
        r.received_at_ms = 1000 + i;
        r.status = 0;
        r.output = (i == 0) ? "visible-output" : "hidden-output";
        rs.store(r);
    }

    DashboardResultsColumnsTestAccess acc;
    acc.set_stores(&is, &rs);
    acc.set_response_scope_fn([](const std::string&, const std::string& agent_id) {
        return agent_id == "agent-in-scope";
    });
    const std::string html = acc.render(command_id, "registry", /*definition_id=*/{},
                                        /*username=*/"confined-operator");

    CHECK(contains(html, "visible-output"));
    CHECK_FALSE(contains(html, "hidden-output"));
    // The fleet-wide magnitude must not survive into the summary.
    CHECK_FALSE(contains(html, "across 5 agents"));
    CHECK_FALSE(contains(html, "Create Group from 5 Agents"));
}

} // namespace yuzu::server
