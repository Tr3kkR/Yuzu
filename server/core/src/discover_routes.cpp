#include "discover_routes.hpp"

#include "agent_registry.hpp"
#include "http_route_sink.hpp"
#include "openapi_spec_access.hpp"
#include "rest_a4_envelope_http.hpp"

#include <cstdint>
#include <cstdio>
#include <unordered_map>

namespace yuzu::server {

namespace {

using json = nlohmann::json;

// FNV-1a 64-bit content hash -> a strong ETag, same idiom as
// guardian_schema_registry.cpp's content_etag (not shared directly — that
// helper is TU-local to a different file and the two catalogs have no other
// coupling reason to share a translation unit).
std::string content_etag(const std::string& body) {
    std::uint64_t h = 1469598103934665603ull;
    for (unsigned char c : body) {
        h ^= c;
        h *= 1099511628211ull;
    }
    char buf[19];
    int n = std::snprintf(buf, sizeof(buf), "\"%016llx\"", static_cast<unsigned long long>(h));
    return std::string(buf, static_cast<std::size_t>(n));
}

DiscoveryDoc build_discovery_doc(json body) {
    DiscoveryDoc doc;
    doc.json = body.dump();
    doc.etag = content_etag(doc.json);
    return doc;
}

// Serve `doc` through the standard ETag / Cache-Control / 304 contract
// (mirrors GET /api/v1/guaranteed-state/schemas, rest_api_v1.cpp).
void serve_doc(const httplib::Request& req, httplib::Response& res, const DiscoveryDoc& doc) {
    res.set_header("ETag", doc.etag);
    res.set_header("Cache-Control", "public, max-age=300");
    if (req.get_header_value("If-None-Match") == doc.etag) {
        res.status = 304;
        return;
    }
    res.set_content(doc.json, "application/json");
}

} // namespace

// ── /discover/permissions ──────────────────────────────────────────────────

DiscoveryDoc build_permissions_catalog(RbacStore& rbac_store) {
    json roles_arr = json::array();
    for (const auto& role : rbac_store.list_roles()) {
        json perms_arr = json::array();
        for (const auto& p : rbac_store.get_role_permissions(role.name)) {
            perms_arr.push_back({{"securable_type", p.securable_type},
                                 {"operation", p.operation},
                                 {"effect", p.effect}});
        }
        roles_arr.push_back({{"name", role.name},
                             {"description", role.description},
                             {"is_system", role.is_system},
                             {"permissions", std::move(perms_arr)}});
    }

    json body = {
        {"version", 1},
        {"description",
         "RBAC permission catalog: every securable_type x operation pair the RBAC "
         "store recognizes, plus the full role -> allowed-operations grid. "
         "Agentic-first (A1/A2) discovery — docs/agentic-first-principle.md."},
        {"securable_types", rbac_store.list_securable_types()},
        {"operations", rbac_store.list_operations()},
        {"roles", std::move(roles_arr)},
    };
    return build_discovery_doc(std::move(body));
}

// ── /discover/instructions ─────────────────────────────────────────────────

DiscoveryDoc build_instructions_catalog(InstructionStore& instruction_store) {
    InstructionQuery q;
    q.enabled_only = true; // "published" == invokable; a disabled definition with
                           // no visible flag would be the misleading option here.
    q.limit = 5000;        // generous ceiling for a catalog read, not a paged list.

    auto defs = instruction_store.query_definitions(q);

    json arr = json::array();
    for (const auto& d : defs) {
        json param_schema; // null unless the stored value parses as JSON
        auto parsed = json::parse(d.parameter_schema, nullptr, /*allow_exceptions=*/false);
        if (!parsed.is_discarded())
            param_schema = std::move(parsed);

        arr.push_back({
            {"id", d.id},
            {"name", d.name},
            {"plugin", d.plugin},
            {"action", d.action},
            {"description", d.description},
            {"parameter_schema", std::move(param_schema)},
            {"platforms", d.platforms},
            {"approval_mode", d.approval_mode},
        });
    }

    json body = {
        {"version", 1},
        {"description",
         "Published (enabled) InstructionDefinition catalog — the commands an "
         "agentic worker may dispatch via execute_instruction / "
         "POST /api/v1/instructions/execute. parameter_schema is a nested JSON "
         "Schema object when the stored value parses, else null."},
        {"count", arr.size()},
        {"truncated", defs.size() >= static_cast<std::size_t>(q.limit)},
        {"instructions", std::move(arr)},
    };
    return build_discovery_doc(std::move(body));
}

// ── /discover/routes ───────────────────────────────────────────────────────

DiscoveryDoc build_routes_catalog(const std::string& openapi_json) {
    static constexpr const char* kMethods[] = {"get", "post", "put", "delete", "patch", "options"};

    json routes_arr = json::array();
    auto spec = json::parse(openapi_json, nullptr, /*allow_exceptions=*/false);
    if (!spec.is_discarded() && spec.contains("paths") && spec["paths"].is_object()) {
        for (const auto& [path, ops] : spec["paths"].items()) {
            if (!ops.is_object())
                continue;
            for (const char* method : kMethods) {
                if (!ops.contains(method) || !ops[method].is_object())
                    continue;
                const auto& op = ops[method];
                json tags = op.value("tags", json::array());
                routes_arr.push_back({
                    {"method", std::string(method) == "get" ? "GET"
                              : std::string(method) == "post" ? "POST"
                              : std::string(method) == "put" ? "PUT"
                              : std::string(method) == "delete" ? "DELETE"
                              : std::string(method) == "patch" ? "PATCH"
                                                                : "OPTIONS"},
                    {"path", "/api/v1" + path},
                    {"summary", op.value("summary", "")},
                    {"tags", std::move(tags)},
                    {"description", op.value("description", "")},
                });
            }
        }
    }

    json body = {
        {"version", 1},
        {"source", "openapi"},
        {"description",
         "REST route catalog, subset of the SAME document GET /api/v1/openapi.json "
         "serves — the two can never disagree."},
        {"caveat",
         "This catalog is derived from the hand-maintained OpenAPI document, NOT "
         "generated from the live route table. A route that exists but was never "
         "documented in the OpenAPI spec will be under-reported here too. Per-route "
         "RBAC requirement is embedded in each entry's free-text 'description' "
         "(no structured field yet)."},
        {"count", routes_arr.size()},
        {"routes", std::move(routes_arr)},
    };
    return build_discovery_doc(std::move(body));
}

// ── /discover/scope-kinds ──────────────────────────────────────────────────

// Bind the catalog size to the enum's single-source count so adding a CompOp
// without a catalog entry is a portable BUILD failure (governance arch-SHOULD-4).
const std::array<CompOpEntry, yuzu::scope::kCompOpCount>& comp_op_catalog() {
    using yuzu::scope::CompOp;
    static const std::array<CompOpEntry, yuzu::scope::kCompOpCount> catalog = {{
        {CompOp::Eq, "Eq", "Case-insensitive equality."},
        {CompOp::Neq, "Neq", "Case-insensitive inequality."},
        {CompOp::Like, "Like", "SQL-style wildcard match (% and _)."},
        {CompOp::Lt, "Lt", "Numeric (falls back to string) less-than."},
        {CompOp::Gt, "Gt", "Numeric (falls back to string) greater-than."},
        {CompOp::Le, "Le", "Numeric (falls back to string) less-than-or-equal."},
        {CompOp::Ge, "Ge", "Numeric (falls back to string) greater-than-or-equal."},
        {CompOp::In, "In", "Value is one of a comma-separated list: `x IN (\"a\",\"b\")`."},
        {CompOp::Contains, "Contains", "Case-insensitive substring match."},
        {CompOp::Matches, "Matches",
         "RE2 regular-expression partial match (case-insensitive, ReDoS-safe, "
         "value capped at 256 chars)."},
        {CompOp::Exists, "Exists", "Unary — true iff the resolved attribute is non-empty."},
    }};
    return catalog;
}

const DiscoveryDoc& scope_kinds_catalog() {
    static const DiscoveryDoc doc = [] {
        json ground_kinds = json::array({
            {{"kind", "__all__"},
             {"syntax", "__all__"},
             {"example", "__all__"},
             {"description",
              "Every enrolled agent. Short-circuits per-device evaluation — never "
              "reaches the Scope Engine parser/resolver."}},
            {{"kind", "group:<name>"},
             {"syntax", "group:<name>"},
             {"example", "group:finance-laptops"},
             {"description",
              "Every device in the named management group. Short-circuits "
              "per-device evaluation, same as __all__."}},
        });

        json attribute_kinds = json::array();
        for (const auto& k : yuzu::server::detail::scope_kind_catalog()) {
            attribute_kinds.push_back({{"kind", k.kind},
                                       {"syntax", k.syntax},
                                       {"example", k.example},
                                       {"description", k.description}});
        }

        json operators = json::array();
        for (const auto& e : comp_op_catalog()) {
            operators.push_back({{"token", std::string(yuzu::scope::operator_token(e.op))},
                                 {"name", e.name},
                                 {"description", e.description}});
        }

        json extended_forms = json::array({
            {{"form", "EXISTS <attr>"},
             {"example", "EXISTS tag:department"},
             {"description",
              "Unary prefix form of the Exists operator (equivalent to `<attr> "
              "EXISTS`, listed for parser-grammar completeness)."}},
            {{"form", "LEN(<attr>) <op> <value>"},
             {"example", "LEN(hostname) > 5"},
             {"description",
              "Resolves <attr>, compares its string length using any of the base "
              "comparison operators (not a distinct CompOp — sugar over Eq/Neq/"
              "numeric compare)."}},
            {{"form", "STARTSWITH(<attr>, <value>)"},
             {"example", "STARTSWITH(hostname, \"WIN-\")"},
             {"description", "Case-insensitive prefix check on <attr>."}},
        });

        json body = {
            {"version", 1},
            {"description",
             "Scope DSL kinds and operators recognized by the Scope Engine "
             "(server/core/src/scope_engine.hpp) and the AgentRegistry::evaluate_scope "
             "resolver (server/core/src/agent_registry.cpp). See "
             "docs/scope-walking-design.md and docs/asset-tagging-guide.md."},
            {"ground_kinds", std::move(ground_kinds)},
            {"attribute_kinds", std::move(attribute_kinds)},
            {"operators", std::move(operators)},
            {"extended_forms", std::move(extended_forms)},
            {"combinators", json::array({"AND", "OR", "NOT"})},
        };
        return build_discovery_doc(std::move(body));
    }();
    return doc;
}

// ── /discover/plugins ───────────────────────────────────────────────────────

DiscoveryDoc build_plugins_catalog(const yuzu::server::detail::AgentRegistry& agent_registry,
                                   InstructionStore* instruction_store) {
    auto help = json::parse(agent_registry.help_json(), nullptr, /*allow_exceptions=*/false);
    bool help_ok = !help.is_discarded() && help.is_object();
    json plugins = help_ok ? help.value("plugins", json::array()) : json::array();
    json commands = help_ok ? help.value("commands", json::array()) : json::array();

    // Join published InstructionDefinitions by "pluginaction" so each action
    // that has one is enriched with its parameter_schema inline (the model learns
    // HOW to call an action, not just that it exists — the #1 anti-bumble fix).
    int enriched = 0;
    if (instruction_store) {
        std::unordered_map<std::string, json> schema_by_action;
        InstructionQuery q;
        q.enabled_only = true;
        q.limit = 5000;
        for (const auto& d : instruction_store->query_definitions(q)) {
            if (d.plugin.empty() || d.action.empty())
                continue;
            auto parsed = json::parse(d.parameter_schema, nullptr, /*allow_exceptions=*/false);
            if (!parsed.is_discarded())
                schema_by_action.emplace(d.plugin + "\x01" + d.action, std::move(parsed));
        }
        if (plugins.is_array()) {
            for (auto& p : plugins) {
                if (!p.is_object() || !p.contains("actions") || !p["actions"].is_array())
                    continue;
                const std::string pname = p.value("name", "");
                for (auto& a : p["actions"]) {
                    if (!a.is_object())
                        continue;
                    auto it = schema_by_action.find(pname + "\x01" + a.value("name", ""));
                    if (it != schema_by_action.end()) {
                        a["parameter_schema"] = it->second;
                        ++enriched;
                    }
                }
            }
        }
    }

    json body = {
        {"version", 2},
        {"description",
         "Plugin/action catalog observed across currently-connected agents "
         "(deduplicated by plugin name; the richest reported action list wins). "
         "NOT a build-time manifest — a plugin no currently-connected agent "
         "reports is absent from this list. To dispatch an action, call "
         "execute_instruction / POST /api/v1/instructions/execute with its "
         "plugin+action; supply the params from parameter_schema where present."},
        {"limitation",
         "An action carries an inline parameter_schema ONLY when it has a "
         "published InstructionDefinition (matched on plugin+action). Actions "
         "without one report name+description only — no per-action JSON Schema "
         "(agents report bare action names). GET /discover/instructions is the "
         "full schema-bearing catalog."},
        {"actions_enriched_with_schema", enriched},
        {"plugins", std::move(plugins)},
        {"commands", std::move(commands)},
    };
    return build_discovery_doc(std::move(body));
}

// ── Route registration ──────────────────────────────────────────────────────

namespace {

// A4-shaped 503 for the discovery surface. This surface exists to *teach* the
// A4 envelope to agentic workers, so its own degraded path must speak A4 (govern-
// ance: docs-writer BLOCKING + arch/unhappy/consistency SHOULD). a4_error mints
// the X-Correlation-Id header and derives the body `code` from res.status.
void discover_503(httplib::Response& res, std::string_view message) {
    res.status = 503;
    res.set_content(detail::a4_error(res, message,
                                     detail::A4ErrorOpts{.retry_after_ms = 5000,
                                                         .remediation = "retry after server "
                                                                        "warmup; the discovery "
                                                                        "store initialises "
                                                                        "during startup"}),
                    "application/json");
}

void register_on_sink(HttpRouteSink& sink, DiscoverRoutes::PermFn perm_fn, RbacStore* rbac_store,
                      InstructionStore* instruction_store,
                      yuzu::server::detail::AgentRegistry* agent_registry) {
    sink.Get("/api/v1/discover/permissions",
             [perm_fn, rbac_store](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn(req, res, "Infrastructure", "Read"))
                     return;
                 if (!rbac_store || !rbac_store->is_open()) {
                     discover_503(res, "discovery store unavailable");
                     return;
                 }
                 // A corrupt/locked store row can throw mid-scan — a raw 500 would
                 // break the A4 contract this surface teaches (governance UP-11).
                 try {
                     serve_doc(req, res, build_permissions_catalog(*rbac_store));
                 } catch (const std::exception&) {
                     discover_503(res, "discovery store read failed");
                 }
             });

    sink.Get("/api/v1/discover/instructions",
             [perm_fn, instruction_store](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn(req, res, "InstructionDefinition", "Read"))
                     return;
                 if (!instruction_store || !instruction_store->is_open()) {
                     discover_503(res, "discovery store unavailable");
                     return;
                 }
                 try {
                     serve_doc(req, res, build_instructions_catalog(*instruction_store));
                 } catch (const std::exception&) {
                     discover_503(res, "discovery store read failed");
                 }
             });

    sink.Get("/api/v1/discover/routes",
             [perm_fn](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn(req, res, "Infrastructure", "Read"))
                     return;
                 // openapi_spec_json() is compiled-in — no store dependency, always
                 // answerable (matches the scope-kinds "answers even when everything
                 // else is down" property).
                 serve_doc(req, res, build_routes_catalog(openapi_spec_json()));
             });

    sink.Get("/api/v1/discover/scope-kinds",
             [perm_fn](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn(req, res, "Infrastructure", "Read"))
                     return;
                 serve_doc(req, res, scope_kinds_catalog());
             });

    sink.Get("/api/v1/discover/plugins",
             [perm_fn, agent_registry,
              instruction_store](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn(req, res, "Infrastructure", "Read"))
                     return;
                 if (!agent_registry) {
                     discover_503(res, "discovery store unavailable");
                     return;
                 }
                 try {
                     serve_doc(req, res, build_plugins_catalog(*agent_registry, instruction_store));
                 } catch (const std::exception&) {
                     discover_503(res, "discovery store read failed");
                 }
             });
}

} // namespace

void DiscoverRoutes::register_routes(httplib::Server& svr, PermFn perm_fn, RbacStore* rbac_store,
                                     InstructionStore* instruction_store,
                                     yuzu::server::detail::AgentRegistry* agent_registry) {
    HttplibRouteSink sink(svr);
    register_on_sink(sink, std::move(perm_fn), rbac_store, instruction_store, agent_registry);
}

void DiscoverRoutes::register_routes(HttpRouteSink& sink, PermFn perm_fn, RbacStore* rbac_store,
                                     InstructionStore* instruction_store,
                                     yuzu::server::detail::AgentRegistry* agent_registry) {
    register_on_sink(sink, std::move(perm_fn), rbac_store, instruction_store, agent_registry);
}

} // namespace yuzu::server
