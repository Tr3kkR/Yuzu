#include "mcp_server.hpp"
#include "mcp_jsonrpc.hpp"
#include "mcp_policy.hpp"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <cstdio>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>

namespace yuzu::server::mcp {
namespace {

// ── Lightweight JSON string builder (same pattern as rest_api_v1.cpp) ─────
// Uses direct string building to avoid nlohmann template-instantiation bloat.

void json_escape(std::string& out, std::string_view sv) {
    out.reserve(out.size() + sv.size());
    for (char c : sv) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char hex[8];
                    std::snprintf(hex, sizeof(hex), "\\u%04x",
                                  static_cast<unsigned>(static_cast<unsigned char>(c)));
                    out += hex;
                } else {
                    out += c;
                }
        }
    }
}

class JObj {
    std::string buf_;
    int n_ = 0;
    void pre() { buf_ += (n_++ ? ',' : '{'); }
    void key(std::string_view k) { pre(); buf_ += '"'; json_escape(buf_, k); buf_ += "\":"; }

public:
    JObj() = default;
    JObj& add(std::string_view k, std::string_view v) {
        key(k); buf_ += '"'; json_escape(buf_, v); buf_ += '"'; return *this;
    }
    JObj& add(std::string_view k, const std::string& v) { return add(k, std::string_view(v)); }
    JObj& add(std::string_view k, const char* v) { return add(k, std::string_view(v)); }
    JObj& add(std::string_view k, int64_t v) {
        key(k); buf_ += std::to_string(v); return *this;
    }
    JObj& add(std::string_view k, int v) { return add(k, static_cast<int64_t>(v)); }
    JObj& add(std::string_view k, double v) {
        key(k); char b[32]; std::snprintf(b, sizeof(b), "%.2f", v); buf_ += b; return *this;
    }
    JObj& add(std::string_view k, bool v) {
        key(k); buf_ += v ? "true" : "false"; return *this;
    }
    JObj& raw(std::string_view k, std::string_view json) {
        key(k); buf_ += json; return *this;
    }
    [[nodiscard]] std::string str() const { return n_ ? buf_ + '}' : "{}"; }
};

class JArr {
    std::string buf_;
    int n_ = 0;
public:
    JArr() = default;
    JArr& add(const JObj& obj) {
        buf_ += (n_++ ? ',' : '['); buf_ += obj.str(); return *this;
    }
    JArr& add(std::string_view s) {
        buf_ += (n_++ ? ',' : '[');
        buf_ += '"'; json_escape(buf_, s); buf_ += '"';
        return *this;
    }
    JArr& add_raw(std::string_view json) {
        buf_ += (n_++ ? ',' : '['); buf_ += json; return *this;
    }
    [[nodiscard]] std::string str() const { return n_ ? buf_ + ']' : "[]"; }
    [[nodiscard]] int size() const { return n_; }
};

// ── Helper to get optional string param from JSON ─────────────────────────

std::string param_str(const nlohmann::json& params, const char* key, const char* def = "") {
    if (params.contains(key) && params[key].is_string())
        return params[key].get<std::string>();
    return def;
}

int64_t param_int(const nlohmann::json& params, const char* key, int64_t def = 0) {
    if (params.contains(key) && params[key].is_number_integer())
        return params[key].get<int64_t>();
    return def;
}

int param_int32(const nlohmann::json& params, const char* key, int def = 0) {
    return static_cast<int>(param_int(params, key, def));
}

// ── Tool schema definition helper ─────────────────────────────────────────

struct ToolDef {
    const char* name;
    const char* description;
    const char* input_schema_json; // Pre-serialized JSON Schema
};

// All 22 Phase 1 read-only tools.
static const ToolDef kTools[] = {
    {"list_agents",
     "List all connected agents with hostname, OS, architecture, and version.",
     R"({"type":"object","properties":{}})"},

    {"get_agent_details",
     "Get detailed info for a single agent including tags and inventory.",
     R"({"type":"object","properties":{"agent_id":{"type":"string","description":"Agent ID"}},"required":["agent_id"]})"},

    {"query_audit_log",
     "Query the audit log with filters. Returns timestamped entries showing who did what, when.",
     R"({"type":"object","properties":{"principal":{"type":"string"},"action":{"type":"string"},"target_type":{"type":"string"},"since":{"type":"integer","description":"Unix epoch lower bound"},"until":{"type":"integer","description":"Unix epoch upper bound"},"limit":{"type":"integer","default":50,"maximum":500}}})"},

    {"list_definitions",
     "List available instruction definitions (commands that can be dispatched to agents).",
     R"({"type":"object","properties":{"plugin":{"type":"string"},"type":{"type":"string","enum":["question","action"]},"enabled":{"type":"boolean"}}})"},

    {"get_definition",
     "Get a single instruction definition with its parameter and result schemas.",
     R"({"type":"object","properties":{"id":{"type":"string","description":"Definition ID"}},"required":["id"]})"},

    {"query_responses",
     "Query command response data with filters.",
     R"j({"type":"object","properties":{"instruction_id":{"type":"string","description":"Instruction ID (required)"},"agent_id":{"type":"string"},"status":{"type":"string"},"limit":{"type":"integer","default":100,"maximum":1000}},"required":["instruction_id"]})j"},

    {"aggregate_responses",
     "Aggregate response data (COUNT, SUM, AVG) grouped by a column.",
     R"({"type":"object","properties":{"instruction_id":{"type":"string"},"group_by":{"type":"string"},"aggregate":{"type":"string","enum":["count","sum","avg","min","max"]}},"required":["instruction_id","group_by"]})"},

    {"query_inventory",
     "Query inventory data across agents. Filter by agent or plugin.",
     R"({"type":"object","properties":{"agent_id":{"type":"string"},"plugin":{"type":"string"},"limit":{"type":"integer","default":100}}})"},

    {"list_inventory_tables",
     "List available inventory data types with agent counts.",
     R"({"type":"object","properties":{}})"},

    {"get_agent_inventory",
     "Get all inventory data for a specific agent.",
     R"({"type":"object","properties":{"agent_id":{"type":"string","description":"Agent ID"}},"required":["agent_id"]})"},

    {"get_tags",
     "Get all tags for a specific agent.",
     R"({"type":"object","properties":{"agent_id":{"type":"string","description":"Agent ID"}},"required":["agent_id"]})"},

    {"search_agents_by_tag",
     "Find agents that have a specific tag key (and optionally value).",
     R"({"type":"object","properties":{"key":{"type":"string","description":"Tag key"},"value":{"type":"string","description":"Optional tag value filter"}},"required":["key"]})"},

    {"list_policies",
     "List compliance policies.",
     R"({"type":"object","properties":{"enabled":{"type":"boolean"}}})"},

    {"get_compliance_summary",
     "Get per-policy compliance breakdown (compliant/non-compliant/unknown counts).",
     R"({"type":"object","properties":{"policy_id":{"type":"string","description":"Policy ID"}},"required":["policy_id"]})"},

    {"get_fleet_compliance",
     "Get fleet-wide compliance percentages across all policies.",
     R"({"type":"object","properties":{}})"},

    {"list_management_groups",
     "List management groups (hierarchical device grouping).",
     R"({"type":"object","properties":{}})"},

    {"get_execution_status",
     "Check status of a running or completed command execution.",
     R"({"type":"object","properties":{"execution_id":{"type":"string","description":"Execution ID"}},"required":["execution_id"]})"},

    {"list_executions",
     "List recent command executions.",
     R"({"type":"object","properties":{"definition_id":{"type":"string"},"status":{"type":"string"},"limit":{"type":"integer","default":50}}})"},

    {"list_schedules",
     "List scheduled (recurring) instructions.",
     R"({"type":"object","properties":{}})"},

    {"validate_scope",
     "Validate a scope expression without executing it. Returns parse errors if invalid.",
     R"({"type":"object","properties":{"expression":{"type":"string","description":"Scope expression to validate"}},"required":["expression"]})"},

    {"preview_scope_targets",
     "Show which agents match a scope expression.",
     R"({"type":"object","properties":{"expression":{"type":"string","description":"Scope expression"}},"required":["expression"]})"},

    {"list_pending_approvals",
     "List pending approval requests.",
     R"({"type":"object","properties":{"status":{"type":"string","enum":["pending","approved","rejected"]},"submitted_by":{"type":"string"}}})"},

    // Phase 2 write tool
    {"execute_instruction",
     "Execute a plugin action on one or more agents. Returns a command_id; poll results with query_responses. "
     "WARNING: If neither scope nor agent_ids is provided, the command targets ALL connected agents.",
     R"j({"type":"object","properties":{)j"
     R"j("plugin":{"type":"string","description":"Plugin name (e.g. os_info, hardware)"},)j"
     R"j("action":{"type":"string","description":"Action name (e.g. version, list)"},)j"
     R"j("params":{"type":"object","additionalProperties":{"type":"string"},"description":"Key-value parameters"},)j"
     R"j("scope":{"type":"string","description":"Scope expression. Use __all__ for all agents, group:<id> for a group, or a scope DSL expression. If omitted and agent_ids is empty, defaults to __all__."},)j"
     R"j("agent_ids":{"type":"array","items":{"type":"string"},"description":"Specific agent IDs to target (alternative to scope)"})j"
     R"j(},"required":["plugin","action"]})j"},
};

static constexpr int kToolCount = sizeof(kTools) / sizeof(kTools[0]);

// ── Write/execute tools (blocked by read_only_mode) ──────────────────────
// These tool names perform Write/Execute/Delete operations.
// The read_only_mode guard rejects them proactively.
//   Implemented: set_tag, delete_tag, execute_instruction
//   Planned:     approve_request, reject_request, quarantine_device
static const std::unordered_set<std::string> kWriteTools = {
    "set_tag", "delete_tag", "execute_instruction",
    "approve_request", "reject_request", "quarantine_device",
};

// ── Tool → (securable_type, operation) mapping for generic policy checks ──
// Every tool declares its securable type and operation so that tier_allows()
// and requires_approval() can be evaluated generically before dispatch.
struct ToolSecurity {
    const char* securable_type;
    const char* operation;
};

static const std::unordered_map<std::string, ToolSecurity> kToolSecurity = {
    // Phase 1 read-only tools
    {"list_agents",            {"Infrastructure",          "Read"}},
    {"get_agent_details",      {"Infrastructure",          "Read"}},
    {"query_audit_log",        {"AuditLog",                "Read"}},
    {"list_definitions",       {"InstructionDefinition",   "Read"}},
    {"get_definition",         {"InstructionDefinition",   "Read"}},
    {"query_responses",        {"Response",                "Read"}},
    {"aggregate_responses",    {"Response",                "Read"}},
    {"query_inventory",        {"Infrastructure",          "Read"}},
    {"list_inventory_tables",  {"Infrastructure",          "Read"}},
    {"get_agent_inventory",    {"Infrastructure",          "Read"}},
    {"get_tags",               {"Tag",                     "Read"}},
    {"search_agents_by_tag",   {"Tag",                     "Read"}},
    {"list_policies",          {"Policy",                  "Read"}},
    {"get_compliance_summary", {"Policy",                  "Read"}},
    {"get_fleet_compliance",   {"Policy",                  "Read"}},
    {"list_management_groups", {"ManagementGroup",         "Read"}},
    {"get_execution_status",   {"Execution",               "Read"}},
    {"list_executions",        {"Execution",               "Read"}},
    {"list_schedules",         {"Schedule",                "Read"}},
    {"validate_scope",         {"Infrastructure",          "Read"}},
    {"preview_scope_targets",  {"Infrastructure",          "Read"}},
    {"list_pending_approvals", {"Approval",                "Read"}},
    // Implemented write tools
    {"set_tag",                {"Tag",                     "Write"}},
    {"delete_tag",             {"Tag",                     "Delete"}},
    {"execute_instruction",    {"Execution",               "Execute"}},
    // Planned write tools (security metadata pre-registered)
    {"approve_request",        {"Approval",                "Write"}},
    {"reject_request",         {"Approval",                "Write"}},
    {"quarantine_device",      {"Security",                "Write"}},
};

// ── Resource definitions ──────────────────────────────────────────────────

struct ResourceDef {
    const char* uri;
    const char* name;
    const char* description;
    const char* mime_type;
};

static const ResourceDef kResources[] = {
    {"yuzu://server/health", "Server Health", "Server health and version info", "application/json"},
    {"yuzu://compliance/fleet", "Fleet Compliance", "Fleet-wide compliance overview", "application/json"},
    {"yuzu://audit/recent", "Recent Audit", "Last 50 audit events", "application/json"},
};

static constexpr int kResourceCount = sizeof(kResources) / sizeof(kResources[0]);

// ── Prompt definitions ────────────────────────────────────────────────────

struct PromptDef {
    const char* name;
    const char* description;
    const char* args_json; // Pre-serialized argument schema array
};

static const PromptDef kPrompts[] = {
    {"fleet_overview",
     "Give a summary of the fleet: how many agents, OS breakdown, compliance status.",
     "[]"},
    {"investigate_agent",
     "Deep-dive on a specific agent: inventory, compliance, recent commands, tags.",
     R"([{"name":"agent_id","description":"Agent ID to investigate","required":true}])"},
    {"compliance_report",
     "Generate a compliance report for a specific policy or fleet-wide.",
     R"j([{"name":"policy_id","description":"Policy ID (omit for fleet-wide)","required":false}])j"},
    {"audit_investigation",
     "Show all actions by a principal in a given timeframe.",
     R"j([{"name":"principal","description":"Username to investigate","required":true},{"name":"hours","description":"Lookback hours (default 24)","required":false}])j"},
};

static constexpr int kPromptCount = sizeof(kPrompts) / sizeof(kPrompts[0]);

} // anonymous namespace

// ── Route registration ────────────────────────────────────────────────────

void McpServer::register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn,
                                AuditFn audit_fn, AgentsJsonFn agents_fn,
                                RbacStore* rbac_store,
                                InstructionStore* instruction_store,
                                ExecutionTracker* execution_tracker,
                                ResponseStore* response_store,
                                AuditStore* audit_store,
                                TagStore* tag_store,
                                InventoryStore* inventory_store,
                                PolicyStore* policy_store,
                                ManagementGroupStore* mgmt_store,
                                ApprovalManager* approval_manager,
                                ScheduleEngine* schedule_engine,
                                const bool& read_only_mode,
                                const bool& mcp_disabled,
                                DispatchFn dispatch_fn) {

    // Capture by reference so runtime changes (e.g., settings UI toggle)
    // take effect without server restart. The references point to cfg_ members
    // which outlive the lambda (owned by the server impl).
    const bool& is_read_only = read_only_mode;
    const bool& is_disabled  = mcp_disabled;

    // ── POST /mcp/v1/ — Main JSON-RPC 2.0 endpoint ───────────────────────
    svr.Post("/mcp/v1/", [=](const httplib::Request& req, httplib::Response& res) {
        res.set_header("Content-Type", "application/json");

        // Runtime kill switch check (G4-UHP-MCP-003) — evaluated on every request
        if (is_disabled) {
            res.set_content(error_response_null(kMcpDisabled, "MCP is disabled on this server"),
                            "application/json");
            return;
        }

        // Auth check — reuses the server's existing auth middleware pipeline
        auto session = auth_fn(req, res);
        if (!session) return; // auth_fn already set 401

        // Parse JSON-RPC envelope
        auto parsed = parse_request(req.body);
        if (!parsed) {
            res.set_content(parsed.error(), "application/json");
            return;
        }
        auto& rpc = *parsed;
        auto id = rpc.id.value_or(nlohmann::json(nullptr));

        // ── Notification (no id → no response) ───────────────────────────
        if (!rpc.id.has_value()) {
            // notifications/initialized — acknowledge and return empty
            res.status = 204;
            return;
        }

        const auto& method = rpc.method;
        const auto& params = rpc.params;

        // ── MCP protocol methods ──────────────────────────────────────────

        // ── initialize ────────────────────────────────────────────────────
        if (method == "initialize") {
            auto result = JObj()
                .add("protocolVersion", "2025-03-26")
                .raw("capabilities", JObj()
                    .raw("tools", R"({"listChanged":false})")
                    .raw("resources", R"({"subscribe":false,"listChanged":false})")
                    .raw("prompts", R"({"listChanged":false})")
                    .str())
                .raw("serverInfo", JObj()
                    .add("name", "yuzu-server")
                    .add("version", "0.1.3")
                    .str())
                .str();
            res.set_content(success_response(id, result), "application/json");
            return;
        }

        // ── ping ──────────────────────────────────────────────────────────
        if (method == "ping") {
            res.set_content(success_response(id, "{}"), "application/json");
            return;
        }

        // ── tools/list ────────────────────────────────────────────────────
        if (method == "tools/list") {
            JArr arr;
            for (int i = 0; i < kToolCount; ++i) {
                arr.add(JObj()
                    .add("name", kTools[i].name)
                    .add("description", kTools[i].description)
                    .raw("inputSchema", kTools[i].input_schema_json));
            }
            auto result = JObj().raw("tools", arr.str()).str();
            res.set_content(success_response(id, result), "application/json");
            return;
        }

        // ── resources/list ────────────────────────────────────────────────
        if (method == "resources/list") {
            JArr arr;
            for (int i = 0; i < kResourceCount; ++i) {
                arr.add(JObj()
                    .add("uri", kResources[i].uri)
                    .add("name", kResources[i].name)
                    .add("description", kResources[i].description)
                    .add("mimeType", kResources[i].mime_type));
            }
            auto result = JObj().raw("resources", arr.str()).str();
            res.set_content(success_response(id, result), "application/json");
            return;
        }

        // ── prompts/list ──────────────────────────────────────────────────
        if (method == "prompts/list") {
            JArr arr;
            for (int i = 0; i < kPromptCount; ++i) {
                arr.add(JObj()
                    .add("name", kPrompts[i].name)
                    .add("description", kPrompts[i].description)
                    .raw("arguments", kPrompts[i].args_json));
            }
            auto result = JObj().raw("prompts", arr.str()).str();
            res.set_content(success_response(id, result), "application/json");
            return;
        }

        // ── prompts/get ───────────────────────────────────────────────────
        if (method == "prompts/get") {
            auto prompt_name = param_str(params, "name");
            std::string prompt_text;
            if (prompt_name == "fleet_overview") {
                prompt_text = "Give me a summary of the fleet: how many agents are connected, "
                              "OS breakdown (Windows/Linux/macOS), and overall compliance status. "
                              "Use the list_agents and get_fleet_compliance tools.";
            } else if (prompt_name == "investigate_agent") {
                auto agent_id = param_str(params, "agent_id", "UNKNOWN");
                prompt_text = "Investigate agent '" + agent_id + "': show its inventory, "
                              "compliance status, recent command results, and tags. Use "
                              "get_agent_details, get_agent_inventory, get_tags, and query_responses.";
            } else if (prompt_name == "compliance_report") {
                auto policy_id = param_str(params, "policy_id");
                if (policy_id.empty())
                    prompt_text = "Generate a fleet-wide compliance report. Use get_fleet_compliance "
                                  "and list_policies to show per-policy breakdown.";
                else
                    prompt_text = "Generate a compliance report for policy '" + policy_id + "'. "
                                  "Use get_compliance_summary with that policy_id.";
            } else if (prompt_name == "audit_investigation") {
                auto principal = param_str(params, "principal", "UNKNOWN");
                auto hours = param_int(params, "hours", 24);
                prompt_text = "Show all actions by '" + principal + "' in the last " +
                              std::to_string(hours) + " hours. Use query_audit_log with principal "
                              "and since filters.";
            } else {
                res.set_content(error_response(id, kInvalidParams, "Unknown prompt: " + prompt_name),
                                "application/json");
                return;
            }
            JArr messages;
            messages.add(JObj()
                .add("role", "user")
                .raw("content", JObj().add("type", "text").add("text", prompt_text).str()));
            auto result = JObj()
                .add("description", prompt_text)
                .raw("messages", messages.str())
                .str();
            res.set_content(success_response(id, result), "application/json");
            return;
        }

        // ── resources/read ────────────────────────────────────────────────
        if (method == "resources/read") {
            auto uri = param_str(params, "uri");

            if (uri == "yuzu://server/health") {
                if (!perm_fn(req, res, "Server", "Read")) return;
                auto agents = agents_fn();
                auto content = JObj().add("status", "ok").add("agents_connected", static_cast<int64_t>(agents.size())).str();
                JArr contents;
                contents.add(JObj().add("uri", uri).add("mimeType", "application/json").add("text", content));
                res.set_content(success_response(id, JObj().raw("contents", contents.str()).str()), "application/json");
                return;
            }
            if (uri == "yuzu://compliance/fleet" && policy_store) {
                if (!perm_fn(req, res, "Policy", "Read")) return;
                auto fc = policy_store->get_fleet_compliance();
                auto content = JObj()
                    .add("total_checks", fc.total_checks)
                    .add("compliant", fc.compliant)
                    .add("non_compliant", fc.non_compliant)
                    .add("unknown", fc.unknown)
                    .add("compliance_pct", fc.compliance_pct)
                    .str();
                JArr contents;
                contents.add(JObj().add("uri", uri).add("mimeType", "application/json").add("text", content));
                res.set_content(success_response(id, JObj().raw("contents", contents.str()).str()), "application/json");
                return;
            }
            if (uri == "yuzu://audit/recent" && audit_store) {
                if (!perm_fn(req, res, "AuditLog", "Read")) return;
                AuditQuery aq;
                aq.limit = 50;
                auto events = audit_store->query(aq);
                JArr arr;
                for (const auto& e : events) {
                    arr.add(JObj()
                        .add("timestamp", e.timestamp)
                        .add("principal", e.principal)
                        .add("action", e.action)
                        .add("target_type", e.target_type)
                        .add("target_id", e.target_id)
                        .add("result", e.result));
                }
                JArr contents;
                contents.add(JObj().add("uri", uri).add("mimeType", "application/json").add("text", arr.str()));
                res.set_content(success_response(id, JObj().raw("contents", contents.str()).str()), "application/json");
                return;
            }

            res.set_content(error_response(id, kInvalidParams, "Unknown resource URI: " + uri),
                            "application/json");
            return;
        }

        // ── tools/call ────────────────────────────────────────────────────
        if (method == "tools/call") {
            auto tool_name = param_str(params, "name");
            auto args = params.value("arguments", nlohmann::json::object());

            // MCP tier check — applied before RBAC
            auto& tier = session->mcp_tier;

            // Lazy-cached agent registry — fetched at most once per request.
            // Avoids copy-by-value on every tool call (H14).
            std::optional<nlohmann::json> cached_agents;
            auto get_agents = [&]() -> const nlohmann::json& {
                if (!cached_agents) cached_agents = agents_fn();
                return *cached_agents;
            };

            // Audit helper
            auto mcp_audit = [&](const std::string& result_status, const std::string& detail = {}) {
                audit_fn(req, "mcp." + tool_name, result_status, "mcp_tool", tool_name, detail);
            };

            // ── C7: read_only_mode enforcement ──────────────────────────
            // When the server is in read-only mode, reject any tool that
            // performs a Write/Execute/Delete operation.
            if (is_read_only && kWriteTools.contains(tool_name)) {
                mcp_audit("denied", "read-only mode");
                res.set_content(error_response(id, kTierDenied, "MCP is in read-only mode"),
                                "application/json");
                return;
            }

            // ── C8: Generic tier + approval checks via kToolSecurity ────
            // Look up the tool's (securable_type, operation) pair and run
            // tier_allows() / requires_approval() generically.  This fires
            // for EVERY tool so Phase 2 write tools get policy enforcement
            // the moment they are registered in kToolSecurity.
            auto sec_it = kToolSecurity.find(tool_name);
            if (sec_it != kToolSecurity.end()) {
                const auto& [sec_type, sec_op] = sec_it->second;

                if (!tier_allows(tier, sec_type, sec_op)) {
                    mcp_audit("denied", "tier=" + std::string(tier));
                    res.set_content(error_response(id, kTierDenied,
                                   "MCP tier does not allow this operation"),
                                   "application/json");
                    return;
                }

                if (requires_approval(tier, sec_type, sec_op)) {
                    // Approval-gated MCP execution is not yet implemented:
                    // the approval workflow can record the request but has no
                    // re-dispatch path to resume execution after admin approval.
                    // Return an explicit error rather than silently queuing.
                    res.set_content(error_response(id, kApprovalRequired,
                        "This operation requires approval, but approval-gated "
                        "MCP execution is not yet implemented. Use the REST API "
                        "or dashboard for operations that require the supervised tier."),
                        "application/json");
                    mcp_audit("approval_required", "approval-gated execution not implemented");
                    return;
                }
            }

            // ── list_agents ───────────────────────────────────────────────
            if (tool_name == "list_agents") {
                if (!tier_allows(tier, "Infrastructure", "Read")) {
                    res.set_content(error_response(id, kTierDenied, "MCP tier does not allow this operation"), "application/json");
                    return;
                }
                if (!perm_fn(req, res, "Infrastructure", "Read")) return;
                const auto& agents = get_agents();
                JArr arr;
                for (const auto& a : agents) {
                    arr.add(JObj()
                        .add("agent_id", a.value("agent_id", ""))
                        .add("hostname", a.value("hostname", ""))
                        .add("os", a.value("os", ""))
                        .add("arch", a.value("arch", ""))
                        .add("agent_version", a.value("agent_version", "")));
                }
                auto result = JObj().raw("content", JArr().add(JObj().add("type", "text").add("text", arr.str())).str()).str();
                mcp_audit("success");
                res.set_content(success_response(id, result), "application/json");
                return;
            }

            // ── get_agent_details ─────────────────────────────────────────
            if (tool_name == "get_agent_details") {
                if (!tier_allows(tier, "Infrastructure", "Read")) {
                    res.set_content(error_response(id, kTierDenied, "MCP tier does not allow this operation"), "application/json");
                    return;
                }
                if (!perm_fn(req, res, "Infrastructure", "Read")) return;
                auto agent_id = param_str(args, "agent_id");
                if (agent_id.empty()) {
                    res.set_content(error_response(id, kInvalidParams, "agent_id is required"), "application/json");
                    return;
                }
                // Find agent in registry
                const auto& agents = get_agents();
                JObj agent_obj;
                bool found = false;
                for (const auto& a : agents) {
                    if (a.value("agent_id", "") == agent_id) {
                        agent_obj.add("agent_id", a.value("agent_id", ""))
                                 .add("hostname", a.value("hostname", ""))
                                 .add("os", a.value("os", ""))
                                 .add("arch", a.value("arch", ""))
                                 .add("agent_version", a.value("agent_version", ""));
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    res.set_content(error_response(id, kInvalidParams, "Agent not found: " + agent_id), "application/json");
                    return;
                }
                // Add tags
                if (tag_store) {
                    auto tags = tag_store->get_all_tags(agent_id);
                    JArr tag_arr;
                    for (const auto& t : tags)
                        tag_arr.add(JObj().add("key", t.key).add("value", t.value).add("source", t.source));
                    agent_obj.raw("tags", tag_arr.str());
                }
                auto result = JObj().raw("content", JArr().add(JObj().add("type", "text").add("text", agent_obj.str())).str()).str();
                mcp_audit("success", agent_id);
                res.set_content(success_response(id, result), "application/json");
                return;
            }

            // ── query_audit_log ───────────────────────────────────────────
            if (tool_name == "query_audit_log") {
                if (!tier_allows(tier, "AuditLog", "Read")) {
                    res.set_content(error_response(id, kTierDenied, "MCP tier does not allow this operation"), "application/json");
                    return;
                }
                if (!perm_fn(req, res, "AuditLog", "Read")) return;
                if (!audit_store) {
                    res.set_content(error_response(id, kInternalError, "Audit store unavailable"), "application/json");
                    return;
                }
                AuditQuery aq;
                aq.principal = param_str(args, "principal");
                aq.action = param_str(args, "action");
                aq.target_type = param_str(args, "target_type");
                aq.since = param_int(args, "since");
                aq.until = param_int(args, "until");
                aq.limit = std::min(param_int32(args, "limit", 50), 500);
                auto events = audit_store->query(aq);
                JArr arr;
                for (const auto& e : events) {
                    arr.add(JObj()
                        .add("id", e.id)
                        .add("timestamp", e.timestamp)
                        .add("principal", e.principal)
                        .add("action", e.action)
                        .add("target_type", e.target_type)
                        .add("target_id", e.target_id)
                        .add("detail", e.detail)
                        .add("result", e.result));
                }
                auto result = JObj().raw("content", JArr().add(JObj().add("type", "text").add("text", arr.str())).str()).str();
                mcp_audit("success");
                res.set_content(success_response(id, result), "application/json");
                return;
            }

            // ── list_definitions ──────────────────────────────────────────
            if (tool_name == "list_definitions") {
                if (!tier_allows(tier, "InstructionDefinition", "Read")) {
                    res.set_content(error_response(id, kTierDenied, "MCP tier does not allow this operation"), "application/json");
                    return;
                }
                if (!perm_fn(req, res, "InstructionDefinition", "Read")) return;
                if (!instruction_store) {
                    res.set_content(error_response(id, kInternalError, "Instruction store unavailable"), "application/json");
                    return;
                }
                InstructionQuery iq;
                iq.plugin_filter = param_str(args, "plugin");
                iq.type_filter = param_str(args, "type");
                auto defs = instruction_store->query_definitions(iq);
                JArr arr;
                for (const auto& d : defs) {
                    arr.add(JObj()
                        .add("id", d.id)
                        .add("name", d.name)
                        .add("version", d.version)
                        .add("type", d.type)
                        .add("plugin", d.plugin)
                        .add("action", d.action)
                        .add("description", d.description)
                        .add("enabled", d.enabled));
                }
                auto result = JObj().raw("content", JArr().add(JObj().add("type", "text").add("text", arr.str())).str()).str();
                mcp_audit("success");
                res.set_content(success_response(id, result), "application/json");
                return;
            }

            // ── get_definition ────────────────────────────────────────────
            if (tool_name == "get_definition") {
                if (!tier_allows(tier, "InstructionDefinition", "Read")) {
                    res.set_content(error_response(id, kTierDenied, "MCP tier does not allow this operation"), "application/json");
                    return;
                }
                if (!perm_fn(req, res, "InstructionDefinition", "Read")) return;
                if (!instruction_store) {
                    res.set_content(error_response(id, kInternalError, "Instruction store unavailable"), "application/json");
                    return;
                }
                auto def_id = param_str(args, "id");
                auto def = instruction_store->get_definition(def_id);
                if (!def) {
                    res.set_content(error_response(id, kInvalidParams, "Definition not found: " + def_id), "application/json");
                    return;
                }
                auto obj = JObj()
                    .add("id", def->id)
                    .add("name", def->name)
                    .add("version", def->version)
                    .add("type", def->type)
                    .add("plugin", def->plugin)
                    .add("action", def->action)
                    .add("description", def->description)
                    .add("approval_mode", def->approval_mode)
                    .add("parameter_schema", def->parameter_schema)
                    .add("result_schema", def->result_schema)
                    .add("yaml_source", def->yaml_source);
                auto result = JObj().raw("content", JArr().add(JObj().add("type", "text").add("text", obj.str())).str()).str();
                mcp_audit("success", def_id);
                res.set_content(success_response(id, result), "application/json");
                return;
            }

            // ── query_responses ───────────────────────────────────────────
            if (tool_name == "query_responses") {
                if (!tier_allows(tier, "Response", "Read")) {
                    res.set_content(error_response(id, kTierDenied, "MCP tier does not allow this operation"), "application/json");
                    return;
                }
                if (!perm_fn(req, res, "Response", "Read")) return;
                if (!response_store) {
                    res.set_content(error_response(id, kInternalError, "Response store unavailable"), "application/json");
                    return;
                }
                auto instr_id = param_str(args, "instruction_id");
                if (instr_id.empty()) {
                    res.set_content(error_response(id, kInvalidParams, "instruction_id is required"), "application/json");
                    return;
                }
                ResponseQuery rq;
                rq.agent_id = param_str(args, "agent_id");
                rq.status = param_int32(args, "status", -1);
                rq.limit = std::min(param_int32(args, "limit", 100), 1000);
                auto responses = response_store->query(instr_id, rq);
                JArr arr;
                for (const auto& r : responses) {
                    arr.add(JObj()
                        .add("agent_id", r.agent_id)
                        .add("status", r.status)
                        .add("output", r.output)
                        .add("timestamp", r.timestamp));
                }
                auto result = JObj().raw("content", JArr().add(JObj().add("type", "text").add("text", arr.str())).str()).str();
                mcp_audit("success", instr_id);
                res.set_content(success_response(id, result), "application/json");
                return;
            }

            // ── aggregate_responses ───────────────────────────────────────
            if (tool_name == "aggregate_responses") {
                if (!tier_allows(tier, "Response", "Read")) {
                    res.set_content(error_response(id, kTierDenied, "MCP tier does not allow this operation"), "application/json");
                    return;
                }
                if (!perm_fn(req, res, "Response", "Read")) return;
                if (!response_store) {
                    res.set_content(error_response(id, kInternalError, "Response store unavailable"), "application/json");
                    return;
                }
                auto instr_id = param_str(args, "instruction_id");
                AggregationQuery aq;
                aq.group_by = param_str(args, "group_by");
                auto agg_str = param_str(args, "aggregate", "count");
                if (agg_str == "sum") aq.op = AggregateOp::Sum;
                else if (agg_str == "avg") aq.op = AggregateOp::Avg;
                else if (agg_str == "min") aq.op = AggregateOp::Min;
                else if (agg_str == "max") aq.op = AggregateOp::Max;
                else aq.op = AggregateOp::Count;
                auto results = response_store->aggregate(instr_id, aq);
                JArr arr;
                for (const auto& r : results) {
                    arr.add(JObj()
                        .add("group_value", r.group_value)
                        .add("count", r.count)
                        .add("aggregate_value", r.aggregate_value));
                }
                auto result = JObj().raw("content", JArr().add(JObj().add("type", "text").add("text", arr.str())).str()).str();
                mcp_audit("success", instr_id);
                res.set_content(success_response(id, result), "application/json");
                return;
            }

            // ── query_inventory ───────────────────────────────────────────
            if (tool_name == "query_inventory") {
                if (!tier_allows(tier, "Infrastructure", "Read")) {
                    res.set_content(error_response(id, kTierDenied, "MCP tier does not allow this operation"), "application/json");
                    return;
                }
                if (!perm_fn(req, res, "Infrastructure", "Read")) return;
                if (!inventory_store) {
                    res.set_content(error_response(id, kInternalError, "Inventory store unavailable"), "application/json");
                    return;
                }
                InventoryQuery iq;
                iq.agent_id = param_str(args, "agent_id");
                iq.plugin = param_str(args, "plugin");
                iq.limit = std::min(param_int32(args, "limit", 100), 1000);
                auto records = inventory_store->query(iq);
                JArr arr;
                for (const auto& r : records) {
                    arr.add(JObj()
                        .add("agent_id", r.agent_id)
                        .add("plugin", r.plugin)
                        .add("data", r.data_json)
                        .add("collected_at", r.collected_at));
                }
                auto result = JObj().raw("content", JArr().add(JObj().add("type", "text").add("text", arr.str())).str()).str();
                mcp_audit("success");
                res.set_content(success_response(id, result), "application/json");
                return;
            }

            // ── list_inventory_tables ─────────────────────────────────────
            if (tool_name == "list_inventory_tables") {
                if (!tier_allows(tier, "Infrastructure", "Read")) {
                    res.set_content(error_response(id, kTierDenied, "MCP tier does not allow this operation"), "application/json");
                    return;
                }
                if (!perm_fn(req, res, "Infrastructure", "Read")) return;
                if (!inventory_store) {
                    res.set_content(error_response(id, kInternalError, "Inventory store unavailable"), "application/json");
                    return;
                }
                auto tables = inventory_store->list_tables();
                JArr arr;
                for (const auto& t : tables) {
                    arr.add(JObj()
                        .add("plugin", t.plugin)
                        .add("agent_count", t.agent_count)
                        .add("last_collected", t.last_collected));
                }
                auto result = JObj().raw("content", JArr().add(JObj().add("type", "text").add("text", arr.str())).str()).str();
                mcp_audit("success");
                res.set_content(success_response(id, result), "application/json");
                return;
            }

            // ── get_agent_inventory ───────────────────────────────────────
            if (tool_name == "get_agent_inventory") {
                if (!tier_allows(tier, "Infrastructure", "Read")) {
                    res.set_content(error_response(id, kTierDenied, "MCP tier does not allow this operation"), "application/json");
                    return;
                }
                if (!perm_fn(req, res, "Infrastructure", "Read")) return;
                if (!inventory_store) {
                    res.set_content(error_response(id, kInternalError, "Inventory store unavailable"), "application/json");
                    return;
                }
                auto agent_id = param_str(args, "agent_id");
                if (agent_id.empty()) {
                    res.set_content(error_response(id, kInvalidParams, "agent_id is required"), "application/json");
                    return;
                }
                auto records = inventory_store->get_agent_inventory(agent_id);
                JArr arr;
                for (const auto& r : records) {
                    arr.add(JObj()
                        .add("plugin", r.plugin)
                        .add("data", r.data_json)
                        .add("collected_at", r.collected_at));
                }
                auto result = JObj().raw("content", JArr().add(JObj().add("type", "text").add("text", arr.str())).str()).str();
                mcp_audit("success", agent_id);
                res.set_content(success_response(id, result), "application/json");
                return;
            }

            // ── get_tags ──────────────────────────────────────────────────
            if (tool_name == "get_tags") {
                if (!tier_allows(tier, "Tag", "Read")) {
                    res.set_content(error_response(id, kTierDenied, "MCP tier does not allow this operation"), "application/json");
                    return;
                }
                if (!perm_fn(req, res, "Tag", "Read")) return;
                if (!tag_store) {
                    res.set_content(error_response(id, kInternalError, "Tag store unavailable"), "application/json");
                    return;
                }
                auto agent_id = param_str(args, "agent_id");
                auto tags = tag_store->get_all_tags(agent_id);
                JArr arr;
                for (const auto& t : tags) {
                    arr.add(JObj()
                        .add("key", t.key)
                        .add("value", t.value)
                        .add("source", t.source)
                        .add("updated_at", t.updated_at));
                }
                auto result = JObj().raw("content", JArr().add(JObj().add("type", "text").add("text", arr.str())).str()).str();
                mcp_audit("success", agent_id);
                res.set_content(success_response(id, result), "application/json");
                return;
            }

            // ── search_agents_by_tag ──────────────────────────────────────
            if (tool_name == "search_agents_by_tag") {
                if (!tier_allows(tier, "Tag", "Read")) {
                    res.set_content(error_response(id, kTierDenied, "MCP tier does not allow this operation"), "application/json");
                    return;
                }
                if (!perm_fn(req, res, "Tag", "Read")) return;
                if (!tag_store) {
                    res.set_content(error_response(id, kInternalError, "Tag store unavailable"), "application/json");
                    return;
                }
                auto key = param_str(args, "key");
                auto value = param_str(args, "value");
                auto agent_ids = tag_store->agents_with_tag(key, value);
                JArr arr;
                for (const auto& aid : agent_ids)
                    arr.add(aid);
                auto result = JObj().raw("content", JArr().add(JObj().add("type", "text").add("text", arr.str())).str()).str();
                mcp_audit("success", key);
                res.set_content(success_response(id, result), "application/json");
                return;
            }

            // ── list_policies ─────────────────────────────────────────────
            if (tool_name == "list_policies") {
                if (!tier_allows(tier, "Policy", "Read")) {
                    res.set_content(error_response(id, kTierDenied, "MCP tier does not allow this operation"), "application/json");
                    return;
                }
                if (!perm_fn(req, res, "Policy", "Read")) return;
                if (!policy_store) {
                    res.set_content(error_response(id, kInternalError, "Policy store unavailable"), "application/json");
                    return;
                }
                PolicyQuery pq;
                auto policies = policy_store->query_policies(pq);
                JArr arr;
                for (const auto& p : policies) {
                    arr.add(JObj()
                        .add("id", p.id)
                        .add("name", p.name)
                        .add("description", p.description)
                        .add("enabled", p.enabled)
                        .add("scope_expression", p.scope_expression));
                }
                auto result = JObj().raw("content", JArr().add(JObj().add("type", "text").add("text", arr.str())).str()).str();
                mcp_audit("success");
                res.set_content(success_response(id, result), "application/json");
                return;
            }

            // ── get_compliance_summary ────────────────────────────────────
            if (tool_name == "get_compliance_summary") {
                if (!tier_allows(tier, "Policy", "Read")) {
                    res.set_content(error_response(id, kTierDenied, "MCP tier does not allow this operation"), "application/json");
                    return;
                }
                if (!perm_fn(req, res, "Policy", "Read")) return;
                if (!policy_store) {
                    res.set_content(error_response(id, kInternalError, "Policy store unavailable"), "application/json");
                    return;
                }
                auto policy_id = param_str(args, "policy_id");
                auto cs = policy_store->get_compliance_summary(policy_id);
                auto obj = JObj()
                    .add("policy_id", cs.policy_id)
                    .add("compliant", cs.compliant)
                    .add("non_compliant", cs.non_compliant)
                    .add("unknown", cs.unknown)
                    .add("fixing", cs.fixing)
                    .add("error", cs.error)
                    .add("total", cs.total);
                auto result = JObj().raw("content", JArr().add(JObj().add("type", "text").add("text", obj.str())).str()).str();
                mcp_audit("success", policy_id);
                res.set_content(success_response(id, result), "application/json");
                return;
            }

            // ── get_fleet_compliance ──────────────────────────────────────
            if (tool_name == "get_fleet_compliance") {
                if (!tier_allows(tier, "Policy", "Read")) {
                    res.set_content(error_response(id, kTierDenied, "MCP tier does not allow this operation"), "application/json");
                    return;
                }
                if (!perm_fn(req, res, "Policy", "Read")) return;
                if (!policy_store) {
                    res.set_content(error_response(id, kInternalError, "Policy store unavailable"), "application/json");
                    return;
                }
                auto fc = policy_store->get_fleet_compliance();
                auto obj = JObj()
                    .add("total_checks", fc.total_checks)
                    .add("compliant", fc.compliant)
                    .add("non_compliant", fc.non_compliant)
                    .add("unknown", fc.unknown)
                    .add("compliance_pct", fc.compliance_pct);
                auto result = JObj().raw("content", JArr().add(JObj().add("type", "text").add("text", obj.str())).str()).str();
                mcp_audit("success");
                res.set_content(success_response(id, result), "application/json");
                return;
            }

            // ── list_management_groups ────────────────────────────────────
            if (tool_name == "list_management_groups") {
                if (!tier_allows(tier, "ManagementGroup", "Read")) {
                    res.set_content(error_response(id, kTierDenied, "MCP tier does not allow this operation"), "application/json");
                    return;
                }
                if (!perm_fn(req, res, "ManagementGroup", "Read")) return;
                if (!mgmt_store) {
                    res.set_content(error_response(id, kInternalError, "Management group store unavailable"), "application/json");
                    return;
                }
                auto groups = mgmt_store->list_groups();
                JArr arr;
                for (const auto& g : groups) {
                    arr.add(JObj()
                        .add("id", g.id)
                        .add("name", g.name)
                        .add("description", g.description)
                        .add("parent_id", g.parent_id)
                        .add("membership_type", g.membership_type)
                        .add("scope_expression", g.scope_expression));
                }
                auto result = JObj().raw("content", JArr().add(JObj().add("type", "text").add("text", arr.str())).str()).str();
                mcp_audit("success");
                res.set_content(success_response(id, result), "application/json");
                return;
            }

            // ── get_execution_status ──────────────────────────────────────
            if (tool_name == "get_execution_status") {
                if (!tier_allows(tier, "Execution", "Read")) {
                    res.set_content(error_response(id, kTierDenied, "MCP tier does not allow this operation"), "application/json");
                    return;
                }
                if (!perm_fn(req, res, "Execution", "Read")) return;
                if (!execution_tracker) {
                    res.set_content(error_response(id, kInternalError, "Execution tracker unavailable"), "application/json");
                    return;
                }
                auto exec_id = param_str(args, "execution_id");
                auto exec = execution_tracker->get_execution(exec_id);
                if (!exec) {
                    res.set_content(error_response(id, kInvalidParams, "Execution not found: " + exec_id), "application/json");
                    return;
                }
                auto summary = execution_tracker->get_summary(exec_id);
                auto obj = JObj()
                    .add("id", exec->id)
                    .add("definition_id", exec->definition_id)
                    .add("status", exec->status)
                    .add("scope_expression", exec->scope_expression)
                    .add("dispatched_by", exec->dispatched_by)
                    .add("dispatched_at", exec->dispatched_at)
                    .add("agents_targeted", static_cast<int64_t>(exec->agents_targeted))
                    .add("agents_responded", static_cast<int64_t>(exec->agents_responded))
                    .add("agents_success", static_cast<int64_t>(exec->agents_success))
                    .add("agents_failure", static_cast<int64_t>(exec->agents_failure))
                    .add("progress_pct", static_cast<int64_t>(summary.progress_pct));
                auto result = JObj().raw("content", JArr().add(JObj().add("type", "text").add("text", obj.str())).str()).str();
                mcp_audit("success", exec_id);
                res.set_content(success_response(id, result), "application/json");
                return;
            }

            // ── list_executions ───────────────────────────────────────────
            if (tool_name == "list_executions") {
                if (!tier_allows(tier, "Execution", "Read")) {
                    res.set_content(error_response(id, kTierDenied, "MCP tier does not allow this operation"), "application/json");
                    return;
                }
                if (!perm_fn(req, res, "Execution", "Read")) return;
                if (!execution_tracker) {
                    res.set_content(error_response(id, kInternalError, "Execution tracker unavailable"), "application/json");
                    return;
                }
                ExecutionQuery eq;
                eq.definition_id = param_str(args, "definition_id");
                eq.status = param_str(args, "status");
                eq.limit = std::min(param_int32(args, "limit", 50), 500);
                auto execs = execution_tracker->query_executions(eq);
                JArr arr;
                for (const auto& e : execs) {
                    arr.add(JObj()
                        .add("id", e.id)
                        .add("definition_id", e.definition_id)
                        .add("status", e.status)
                        .add("dispatched_by", e.dispatched_by)
                        .add("dispatched_at", e.dispatched_at)
                        .add("agents_targeted", static_cast<int64_t>(e.agents_targeted))
                        .add("agents_responded", static_cast<int64_t>(e.agents_responded)));
                }
                auto result = JObj().raw("content", JArr().add(JObj().add("type", "text").add("text", arr.str())).str()).str();
                mcp_audit("success");
                res.set_content(success_response(id, result), "application/json");
                return;
            }

            // ── list_schedules ────────────────────────────────────────────
            if (tool_name == "list_schedules") {
                if (!tier_allows(tier, "Schedule", "Read")) {
                    res.set_content(error_response(id, kTierDenied, "MCP tier does not allow this operation"), "application/json");
                    return;
                }
                if (!perm_fn(req, res, "Schedule", "Read")) return;
                if (!schedule_engine) {
                    res.set_content(error_response(id, kInternalError, "Schedule engine unavailable"), "application/json");
                    return;
                }
                ScheduleQuery sq;
                auto schedules = schedule_engine->query_schedules(sq);
                JArr arr;
                for (const auto& s : schedules) {
                    arr.add(JObj()
                        .add("id", s.id)
                        .add("name", s.name)
                        .add("definition_id", s.definition_id)
                        .add("frequency_type", s.frequency_type)
                        .add("enabled", s.enabled)
                        .add("next_execution_at", s.next_execution_at));
                }
                auto result = JObj().raw("content", JArr().add(JObj().add("type", "text").add("text", arr.str())).str()).str();
                mcp_audit("success");
                res.set_content(success_response(id, result), "application/json");
                return;
            }

            // ── validate_scope ────────────────────────────────────────────
            if (tool_name == "validate_scope") {
                auto expression = param_str(args, "expression");
                if (expression.empty()) {
                    res.set_content(error_response(id, kInvalidParams, "expression is required"), "application/json");
                    return;
                }
                auto valid = yuzu::scope::validate(expression);
                JObj obj;
                if (valid) {
                    obj.add("valid", true).add("expression", expression);
                } else {
                    obj.add("valid", false).add("error", valid.error());
                }
                auto result = JObj().raw("content", JArr().add(JObj().add("type", "text").add("text", obj.str())).str()).str();
                mcp_audit("success");
                res.set_content(success_response(id, result), "application/json");
                return;
            }

            // ── preview_scope_targets ─────────────────────────────────────
            if (tool_name == "preview_scope_targets") {
                if (!tier_allows(tier, "Infrastructure", "Read")) {
                    res.set_content(error_response(id, kTierDenied, "MCP tier does not allow this operation"), "application/json");
                    return;
                }
                if (!perm_fn(req, res, "Infrastructure", "Read")) return;
                auto expression = param_str(args, "expression");
                if (expression.empty()) {
                    res.set_content(error_response(id, kInvalidParams, "expression is required"), "application/json");
                    return;
                }
                // Validate first
                auto valid = yuzu::scope::validate(expression);
                if (!valid) {
                    res.set_content(error_response(id, kInvalidParams, "Invalid scope: " + valid.error()), "application/json");
                    return;
                }
                // Parse the expression into an AST
                auto parsed_expr = yuzu::scope::parse(expression);
                if (!parsed_expr) {
                    res.set_content(error_response(id, kInvalidParams, "Parse error: " + parsed_expr.error()), "application/json");
                    return;
                }
                // Evaluate against all agents
                const auto& agents = get_agents();
                JArr matching;
                for (const auto& a : agents) {
                    auto agent_id = a.value("agent_id", "");
                    std::unordered_map<std::string, std::string> attrs;
                    attrs["os"] = a.value("os", "");
                    attrs["arch"] = a.value("arch", "");
                    attrs["hostname"] = a.value("hostname", "");
                    attrs["agent_version"] = a.value("agent_version", "");
                    if (tag_store) {
                        auto tag_map = tag_store->get_tag_map(agent_id);
                        for (const auto& [k, v] : tag_map)
                            attrs["tag:" + k] = v;
                    }
                    auto resolver = [&](std::string_view attr) -> std::string {
                        auto it = attrs.find(std::string(attr));
                        return it != attrs.end() ? it->second : "";
                    };
                    if (yuzu::scope::evaluate(*parsed_expr, resolver))
                        matching.add(agent_id);
                }
                // Blast-radius guard: warn when scope matches many agents (G4-UHP-MCP-011)
                constexpr size_t kMcpScopeWarnThreshold = 50;
                bool scope_warning = matching.size() > kMcpScopeWarnThreshold;

                auto obj = JObj()
                    .add("expression", expression)
                    .add("matched_count", static_cast<int64_t>(matching.size()))
                    .raw("matched_agents", matching.str());
                if (scope_warning)
                    obj.add("warning", "scope matches " + std::to_string(matching.size()) +
                            " agents (>" + std::to_string(kMcpScopeWarnThreshold) +
                            "). Phase 2 write operations targeting this scope will require approval.");
                auto result = JObj().raw("content", JArr().add(JObj().add("type", "text").add("text", obj.str())).str()).str();
                mcp_audit("success", expression);
                res.set_content(success_response(id, result), "application/json");
                return;
            }

            // ── list_pending_approvals ────────────────────────────────────
            if (tool_name == "list_pending_approvals") {
                if (!tier_allows(tier, "Approval", "Read")) {
                    res.set_content(error_response(id, kTierDenied, "MCP tier does not allow this operation"), "application/json");
                    return;
                }
                if (!perm_fn(req, res, "Approval", "Read")) return;
                if (!approval_manager) {
                    res.set_content(error_response(id, kInternalError, "Approval manager unavailable"), "application/json");
                    return;
                }
                ApprovalQuery aq;
                aq.status = param_str(args, "status", "pending");
                aq.submitted_by = param_str(args, "submitted_by");
                auto approvals = approval_manager->query(aq);
                JArr arr;
                for (const auto& a : approvals) {
                    arr.add(JObj()
                        .add("id", a.id)
                        .add("definition_id", a.definition_id)
                        .add("status", a.status)
                        .add("submitted_by", a.submitted_by)
                        .add("submitted_at", a.submitted_at)
                        .add("scope_expression", a.scope_expression));
                }
                auto result = JObj().raw("content", JArr().add(JObj().add("type", "text").add("text", arr.str())).str()).str();
                mcp_audit("success");
                res.set_content(success_response(id, result), "application/json");
                return;
            }

            // ── execute_instruction ───────────────────────────────────────
            // Tier check handled by generic C8 block above (kToolSecurity).
            if (tool_name == "execute_instruction") {
                if (!perm_fn(req, res, "Execution", "Execute")) return;
                if (!dispatch_fn) {
                    res.set_content(error_response(id, kInternalError, "Command dispatch unavailable"), "application/json");
                    return;
                }

                auto plugin = param_str(args, "plugin");
                auto action = param_str(args, "action");
                // Agent plugins register actions in lowercase and match
                // case-sensitively. Normalize to prevent silent dispatch misses
                // when an AI model sends mixed-case action names.
                std::transform(plugin.begin(), plugin.end(), plugin.begin(),
                               [](unsigned char c) { return std::tolower(c); });
                std::transform(action.begin(), action.end(), action.begin(),
                               [](unsigned char c) { return std::tolower(c); });
                if (plugin.empty() || action.empty()) {
                    res.set_content(error_response(id, kInvalidParams, "plugin and action are required"), "application/json");
                    return;
                }

                // Extract params as string map
                std::unordered_map<std::string, std::string> params;
                if (args.contains("params") && args["params"].is_object()) {
                    for (auto& [k, v] : args["params"].items()) {
                        params[k] = v.is_string() ? v.get<std::string>() : v.dump();
                    }
                }

                auto scope = param_str(args, "scope");
                std::vector<std::string> agent_ids;
                if (args.contains("agent_ids") && args["agent_ids"].is_array()) {
                    for (const auto& v : args["agent_ids"]) {
                        if (v.is_string()) agent_ids.push_back(v.get<std::string>());
                    }
                }

                // Default scope to __all__ if neither scope nor agent_ids provided
                if (scope.empty() && agent_ids.empty()) scope = "__all__";

                auto [command_id, agents_reached] = dispatch_fn(plugin, action, agent_ids, scope, params);

                if (agents_reached == 0) {
                    auto result = JObj().raw("content", JArr().add(
                        JObj().add("type", "text").add("text", "No agents reachable for command dispatch")).str()).str();
                    mcp_audit("failure", "no agents reachable");
                    res.set_content(success_response(id, result), "application/json");
                    return;
                }

                auto result_obj = JObj()
                    .add("command_id", command_id)
                    .add("agents_reached", agents_reached)
                    .add("plugin", plugin)
                    .add("action", action);
                auto result = JObj().raw("content", JArr().add(
                    JObj().add("type", "text").add("text", result_obj.str())).str()).str();
                mcp_audit("success");
                res.set_content(success_response(id, result), "application/json");
                return;
            }

            // ── Unknown tool ──────────────────────────────────────────────
            mcp_audit("failure", "unknown tool");
            res.set_content(error_response(id, kMethodNotFound, "Unknown tool: " + tool_name),
                            "application/json");
            return;
        }

        // ── Unknown method ────────────────────────────────────────────────
        res.set_content(error_response(id, kMethodNotFound, "Unknown method: " + method),
                        "application/json");
    });

    spdlog::info("MCP: registered JSON-RPC endpoint at POST /mcp/v1/ ({} tools, {} resources, {} prompts{})",
                 kToolCount, kResourceCount, kPromptCount,
                 is_read_only ? ", read-only mode" : "");
}

} // namespace yuzu::server::mcp
