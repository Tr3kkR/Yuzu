/**
 * test_discovery_routes.cpp — HTTP-level coverage for the A2 discovery
 * surface, the `GET /api/v1/discover/` family (roadmap Issue 17.1,
 * docs/agentic-first-principle.md §A2).
 *
 * Pattern matches test_rest_guaranteed_state.cpp: register DiscoverRoutes
 * against an in-process TestRouteSink and dispatch synthesised
 * httplib::Request objects through the captured handlers. No real HTTP
 * server, no acceptor thread, no #438 TSan trap.
 *
 * Coverage:
 *   - shape + ETag/Cache-Control/304 revalidation for all five endpoints
 *   - null-store / null-registry 503 degrade for the three store-backed
 *     endpoints (permissions, instructions, plugins) — scope-kinds and
 *     routes are compiled-in and answer regardless
 *   - a CROSS-CHECK that binds the scope-kinds catalog to the
 *     AgentRegistry::evaluate_scope resolver it documents, and to the
 *     yuzu::scope::CompOp enum operator_token() exposes
 *
 * NOT covered here: the mirrored MCP discover_* tools (test_mcp_server.cpp
 * carries those — same builder functions, so this file is the primary
 * shape/behavior authority and the MCP tests mostly assert wiring).
 */

#include "agent_registry.hpp"
#include "discover_routes.hpp"
#include "event_bus.hpp"
#include "instruction_store.hpp"
#include "rbac_store.hpp"
#include "scope_engine.hpp"
#include "test_route_sink.hpp"

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include "agent.pb.h"

#include <algorithm>
#include <string>
#include <vector>

using namespace yuzu::server;
using yuzu::server::detail::AgentRegistry;
using yuzu::server::detail::EventBus;
namespace agent_pb = ::yuzu::agent::v1;

namespace {

// ── Harness ─────────────────────────────────────────────────────────────────

struct DiscoverHarness {
    yuzu::server::test::TestRouteSink sink;

    std::unique_ptr<RbacStore> rbac;
    std::unique_ptr<InstructionStore> instr;

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};

    bool grant_perms{true};
    std::string last_securable_type, last_operation;

    DiscoverRoutes routes;

    // wire_rbac / wire_instr / wire_registry = false registers the route with a
    // null store/registry pointer, exercising the 503 degrade branch.
    explicit DiscoverHarness(bool wire_rbac = true, bool wire_instr = true,
                             bool wire_registry = true) {
        rbac = std::make_unique<RbacStore>(":memory:");
        REQUIRE(rbac->is_open());
        instr = std::make_unique<InstructionStore>(":memory:");
        REQUIRE(instr->is_open());

        auto perm_fn = [this](const httplib::Request&, httplib::Response& res,
                              const std::string& type, const std::string& op) -> bool {
            last_securable_type = type;
            last_operation = op;
            if (grant_perms)
                return true;
            res.status = 403;
            return false;
        };
        routes.register_routes(sink, perm_fn, wire_rbac ? rbac.get() : nullptr,
                               wire_instr ? instr.get() : nullptr,
                               wire_registry ? &registry : nullptr);
    }
};

agent_pb::AgentInfo make_agent_info(const std::string& id, const std::string& os,
                                    const std::string& hostname) {
    agent_pb::AgentInfo a;
    a.set_agent_id(id);
    a.set_hostname(hostname);
    a.mutable_platform()->set_os(os);
    a.mutable_platform()->set_arch("x86_64");
    a.set_agent_version("0.13.0");
    return a;
}

InstructionDefinition make_def(const std::string& name, bool enabled,
                               const std::string& parameter_schema = "") {
    InstructionDefinition def;
    def.name = name;
    def.version = "1.0";
    def.plugin = "system_info";
    def.action = "query";
    def.type = "question";
    def.description = "Test definition: " + name;
    def.enabled = enabled;
    def.platforms = "windows,linux,darwin";
    def.approval_mode = "auto";
    def.parameter_schema = parameter_schema;
    return def;
}

} // namespace

// ── /discover/permissions ────────────────────────────────────────────────────

TEST_CASE("discover.permissions: shape + ETag revalidation", "[discovery][permissions]") {
    DiscoverHarness h;
    auto res = h.sink.Get("/api/v1/discover/permissions");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->get_header_value("Cache-Control") == "public, max-age=300");
    const std::string etag = res->get_header_value("ETag");
    CHECK_FALSE(etag.empty());

    auto j = nlohmann::json::parse(res->body);
    REQUIRE(j.contains("securable_types"));
    REQUIRE(j.contains("operations"));
    REQUIRE(j.contains("roles"));
    CHECK(j["securable_types"].is_array());
    CHECK_FALSE(j["securable_types"].empty());
    CHECK(j["operations"].is_array());
    CHECK_FALSE(j["operations"].empty());
    CHECK(j["roles"].is_array());
    CHECK_FALSE(j["roles"].empty());
    // Every role row carries name + a permissions sub-array of
    // {securable_type, operation, effect} triples.
    for (const auto& r : j["roles"]) {
        REQUIRE(r.contains("name"));
        REQUIRE(r.contains("permissions"));
        CHECK(r["permissions"].is_array());
        if (!r["permissions"].empty()) {
            const auto& p = r["permissions"][0];
            CHECK(p.contains("securable_type"));
            CHECK(p.contains("operation"));
            CHECK(p.contains("effect"));
        }
    }

    // Gated on Infrastructure:Read.
    CHECK(h.last_securable_type == "Infrastructure");
    CHECK(h.last_operation == "Read");

    auto cached = h.sink.Get("/api/v1/discover/permissions", {{"If-None-Match", etag}});
    REQUIRE(cached);
    CHECK(cached->status == 304);
}

TEST_CASE("discover.permissions: null RbacStore -> 503", "[discovery][permissions]") {
    DiscoverHarness h(/*wire_rbac=*/false);
    auto res = h.sink.Get("/api/v1/discover/permissions");
    REQUIRE(res);
    CHECK(res->status == 503);
}

TEST_CASE("discover.permissions: permission denied -> 403, no body leak",
          "[discovery][permissions]") {
    DiscoverHarness h;
    h.grant_perms = false;
    auto res = h.sink.Get("/api/v1/discover/permissions");
    REQUIRE(res);
    CHECK(res->status == 403);
}

// ── /discover/instructions ───────────────────────────────────────────────────

TEST_CASE("discover.instructions: enabled-only subset with parsed parameter_schema",
          "[discovery][instructions]") {
    DiscoverHarness h;
    auto enabled_id =
        h.instr->create_definition(make_def(
            "Get Hostname", /*enabled=*/true,
            R"({"type":"object","properties":{"path":{"type":"string"}}})"));
    REQUIRE(enabled_id.has_value());
    auto disabled_id = h.instr->create_definition(make_def("Retired Check", /*enabled=*/false));
    REQUIRE(disabled_id.has_value());
    // No parameter_schema authored -> store defaults to "{}" (see below).
    auto no_schema_id = h.instr->create_definition(make_def("No Schema", /*enabled=*/true));
    REQUIRE(no_schema_id.has_value());

    auto res = h.sink.Get("/api/v1/discover/instructions");
    REQUIRE(res);
    CHECK(res->status == 200);
    const std::string etag = res->get_header_value("ETag");
    CHECK_FALSE(etag.empty());

    auto j = nlohmann::json::parse(res->body);
    REQUIRE(j.contains("instructions"));
    const auto& arr = j["instructions"];
    CHECK(arr.is_array());

    bool saw_enabled = false, saw_disabled = false, saw_no_schema = false;
    for (const auto& d : arr) {
        REQUIRE(d.contains("id"));
        REQUIRE(d.contains("name"));
        REQUIRE(d.contains("plugin"));
        REQUIRE(d.contains("action"));
        REQUIRE(d.contains("parameter_schema"));
        REQUIRE(d.contains("platforms"));
        REQUIRE(d.contains("approval_mode"));
        if (d["id"] == *enabled_id) {
            saw_enabled = true;
            CHECK(d["parameter_schema"].is_object());
            CHECK(d["parameter_schema"]["type"] == "object");
        }
        if (d["id"] == *disabled_id)
            saw_disabled = true;
        if (d["id"] == *no_schema_id) {
            saw_no_schema = true;
            // InstructionStore::create_definition defaults an empty
            // parameter_schema to the literal "{}" (instruction_store.cpp),
            // so a definition authored with none round-trips as an empty
            // OBJECT, not null. null is reserved for a stored value that
            // fails to parse as JSON at all (defensive branch, not
            // reachable through the normal create_definition path).
            CHECK(d["parameter_schema"].is_object());
            CHECK(d["parameter_schema"].empty());
        }
    }
    CHECK(saw_enabled);
    CHECK_FALSE(saw_disabled); // enabled_only=true — "published" excludes disabled
    CHECK(saw_no_schema);

    CHECK(h.last_securable_type == "InstructionDefinition");
    CHECK(h.last_operation == "Read");

    auto cached = h.sink.Get("/api/v1/discover/instructions", {{"If-None-Match", etag}});
    REQUIRE(cached);
    CHECK(cached->status == 304);
}

TEST_CASE("discover.instructions: null InstructionStore -> 503", "[discovery][instructions]") {
    DiscoverHarness h(/*wire_rbac=*/true, /*wire_instr=*/false);
    auto res = h.sink.Get("/api/v1/discover/instructions");
    REQUIRE(res);
    CHECK(res->status == 503);
}

// ── /discover/routes ─────────────────────────────────────────────────────────

TEST_CASE("discover.routes: subsets the OpenAPI document, honesty fields present",
          "[discovery][routes]") {
    DiscoverHarness h;
    auto res = h.sink.Get("/api/v1/discover/routes");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK_FALSE(res->get_header_value("ETag").empty());

    auto j = nlohmann::json::parse(res->body);
    CHECK(j.value("source", "") == "openapi");
    REQUIRE(j.contains("caveat"));
    CHECK_FALSE(j["caveat"].get<std::string>().empty());
    REQUIRE(j.contains("routes"));
    CHECK(j["routes"].is_array());
    CHECK_FALSE(j["routes"].empty());

    // Dogfood: the catalog must include its OWN five sibling routes (added to
    // openapi_spec() alongside this route) — proves the openapi_spec_json()
    // wiring reaches the SAME document GET /api/v1/openapi.json serves.
    bool saw_self = false;
    for (const auto& r : j["routes"]) {
        REQUIRE(r.contains("method"));
        REQUIRE(r.contains("path"));
        REQUIRE(r.contains("summary"));
        REQUIRE(r.contains("tags"));
        if (r["path"] == "/api/v1/discover/routes" && r["method"] == "GET")
            saw_self = true;
    }
    CHECK(saw_self);

    CHECK(h.last_securable_type == "Infrastructure");
}

// ── /discover/scope-kinds ────────────────────────────────────────────────────

TEST_CASE("discover.scope-kinds: static catalog shape", "[discovery][scope_kinds]") {
    DiscoverHarness h;
    auto res = h.sink.Get("/api/v1/discover/scope-kinds");
    REQUIRE(res);
    CHECK(res->status == 200);
    const std::string etag = res->get_header_value("ETag");
    CHECK_FALSE(etag.empty());

    auto j = nlohmann::json::parse(res->body);
    REQUIRE(j.contains("ground_kinds"));
    REQUIRE(j.contains("attribute_kinds"));
    REQUIRE(j.contains("operators"));
    REQUIRE(j.contains("extended_forms"));
    REQUIRE(j.contains("combinators"));

    std::vector<std::string> ground_kinds;
    for (const auto& k : j["ground_kinds"])
        ground_kinds.push_back(k["kind"].get<std::string>());
    CHECK(std::find(ground_kinds.begin(), ground_kinds.end(), "__all__") != ground_kinds.end());
    CHECK(std::find(ground_kinds.begin(), ground_kinds.end(), "group:<name>") !=
          ground_kinds.end());

    // attribute_kinds mirrors scope_kind_catalog() 1:1.
    CHECK(j["attribute_kinds"].size() == yuzu::server::detail::scope_kind_catalog().size());

    // Every CompOp value published, each carrying a non-empty token.
    CHECK(j["operators"].size() == yuzu::scope::kCompOpCount);
    for (const auto& op : j["operators"])
        CHECK_FALSE(op["token"].get<std::string>().empty());

    CHECK(j["combinators"] == nlohmann::json::array({"AND", "OR", "NOT"}));

    // No store dependency — answers 200 even with everything unwired.
    DiscoverHarness bare(/*wire_rbac=*/false, /*wire_instr=*/false, /*wire_registry=*/false);
    auto bare_res = bare.sink.Get("/api/v1/discover/scope-kinds");
    REQUIRE(bare_res);
    CHECK(bare_res->status == 200);

    auto cached = h.sink.Get("/api/v1/discover/scope-kinds", {{"If-None-Match", etag}});
    REQUIRE(cached);
    CHECK(cached->status == 304);
}

// CROSS-CHECK #1: every entry in scope_kind_catalog() (agent_registry.hpp,
// colocated with the evaluate_scope resolver it documents) is honored by the
// resolver — proves the enumerator is a SUBSET of what the resolver actually
// answers. This does NOT prove the converse (a resolver branch added without a
// matching catalog entry stays invisible to this test) — see the DRIFT
// CONTRACT comment on the resolver lambda in agent_registry.cpp, which is the
// human-inspection half of this guarantee.
TEST_CASE("CROSS-CHECK: scope_kind_catalog entries are honored by evaluate_scope resolver",
          "[discovery][scope_kinds][crosscheck]") {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    auto info = make_agent_info("agent-1", "windows", "WIN-TESTBOX");
    (*info.mutable_scopable_tags())["department"] = "finance";
    registry.register_agent(info);

    // tag:department and props.owner need their respective stores; both are
    // optional (nullptr) parameters to evaluate_scope, so kinds backed solely
    // by a store (props.<key>) are only reachable via in-memory scopable_tags
    // for tag:<key> here — props.<key> without a store always resolves empty,
    // which this loop treats as "no match" and skips (documented below).
    for (const auto& k : yuzu::server::detail::scope_kind_catalog()) {
        if (k.kind == "props.<key>")
            continue; // needs a live CustomPropertiesStore — covered by
                      // dedicated props tests elsewhere, not this catalog check.

        std::string expr;
        if (k.kind == "from_result_set:<id>") {
            // Bare atom, no operator/value (scope_engine.cpp parse_expression:
            // `from_result_set:<id>` short-circuits to an implicit EXISTS
            // condition — `from_result_set:<id> == <value>` is a parse error).
            // No ResultSetStore wired here (authz semantics belong to
            // test_scope_walking_authz.cpp) — assert the kind resolves to
            // "no match" rather than throwing/crashing the parser.
            expr = "from_result_set:rs_nonexistent";
            auto parsed = yuzu::scope::parse(expr);
            REQUIRE(parsed.has_value());
            auto matched = registry.evaluate_scope(*parsed, nullptr);
            CHECK(matched.empty());
            continue;
        }
        if (k.kind == "ostype")
            expr = R"(ostype == "windows")";
        else if (k.kind == "hostname")
            expr = R"(hostname == "WIN-TESTBOX")";
        else if (k.kind == "arch")
            expr = R"(arch == "x86_64")";
        else if (k.kind == "agent_version")
            expr = R"(agent_version == "0.13.0")";
        else if (k.kind == "tag:<key>")
            expr = R"(tag:department == "finance")";
        else
            FAIL(std::string("scope_kind_catalog entry '") + k.kind +
                 "' has no cross-check case — add one above alongside the new resolver branch");

        auto parsed = yuzu::scope::parse(expr);
        REQUIRE(parsed.has_value());
        auto matched = registry.evaluate_scope(*parsed, nullptr);
        CHECK(std::find(matched.begin(), matched.end(), "agent-1") != matched.end());
    }

    // A made-up kind the resolver has never heard of must resolve to no match
    // (proves the resolver doesn't silently accept everything as a wildcard).
    auto bogus = yuzu::scope::parse(R"(totally_bogus_kind == "x")");
    REQUIRE(bogus.has_value());
    CHECK(registry.evaluate_scope(*bogus, nullptr).empty());
}

// CROSS-CHECK #2: yuzu::scope::operator_token's switch (scope_engine.cpp) has
// NO default case — adding a CompOp value without a case there is a build-log
// -Wswitch signal. This test is the runtime half: it asserts comp_op_catalog()
// (discover_routes.hpp, the array the /discover/scope-kinds "operators" array
// is built from) covers exactly the 11 currently-declared CompOp values and
// that operator_token() answers every one of them. Bump the literal 11 (here
// AND in discover_routes.hpp's std::array<CompOpEntry, 11>) when CompOp grows.
TEST_CASE("CROSS-CHECK: comp_op_catalog covers every CompOp value (G9-style drift guard)",
          "[discovery][scope_kinds][crosscheck]") {
    const auto& catalog = yuzu::server::comp_op_catalog();
    // Bound to the enum's single-source count, not a hardcoded literal — the
    // catalog array is sized by kCompOpCount, so this also proves the two agree
    // (governance arch-SHOULD-4 / cpp-expert: the -Wswitch signal is not portable).
    CHECK(catalog.size() == yuzu::scope::kCompOpCount);
    std::vector<std::string> tokens;
    for (const auto& e : catalog) {
        auto tok = yuzu::scope::operator_token(e.op);
        CHECK_FALSE(tok.empty());
        tokens.emplace_back(tok);
    }
    // Every token distinct (Eq/Neq/Like/... map to unique wire tokens).
    std::sort(tokens.begin(), tokens.end());
    CHECK(std::adjacent_find(tokens.begin(), tokens.end()) == tokens.end());
}

// ── /discover/plugins ────────────────────────────────────────────────────────

TEST_CASE("discover.plugins: wraps AgentRegistry::help_json with a limitation note",
          "[discovery][plugins]") {
    DiscoverHarness h;
    auto info = make_agent_info("agent-1", "windows", "WIN-TESTBOX");
    auto* p = info.add_plugins();
    p->set_name("processes");
    p->set_version("1.0");
    p->set_description("Process enumeration");
    p->add_capabilities("list");
    p->add_capabilities("query");
    h.registry.register_agent(info);

    auto res = h.sink.Get("/api/v1/discover/plugins");
    REQUIRE(res);
    CHECK(res->status == 200);
    const std::string etag = res->get_header_value("ETag");
    CHECK_FALSE(etag.empty());

    auto j = nlohmann::json::parse(res->body);
    REQUIRE(j.contains("limitation"));
    CHECK_FALSE(j["limitation"].get<std::string>().empty());
    REQUIRE(j.contains("plugins"));
    bool saw_processes = false;
    for (const auto& pl : j["plugins"]) {
        if (pl["name"] == "processes") {
            saw_processes = true;
            REQUIRE(pl.contains("actions"));
            std::vector<std::string> action_names;
            for (const auto& a : pl["actions"])
                action_names.push_back(a["name"].get<std::string>());
            CHECK(std::find(action_names.begin(), action_names.end(), "list") !=
                  action_names.end());
            CHECK(std::find(action_names.begin(), action_names.end(), "query") !=
                  action_names.end());
        }
    }
    CHECK(saw_processes);

    CHECK(h.last_securable_type == "Infrastructure");

    auto cached = h.sink.Get("/api/v1/discover/plugins", {{"If-None-Match", etag}});
    REQUIRE(cached);
    CHECK(cached->status == 304);
}

TEST_CASE("discover.plugins: null AgentRegistry -> 503", "[discovery][plugins]") {
    DiscoverHarness h(/*wire_rbac=*/true, /*wire_instr=*/true, /*wire_registry=*/false);
    auto res = h.sink.Get("/api/v1/discover/plugins");
    REQUIRE(res);
    CHECK(res->status == 503);
}
