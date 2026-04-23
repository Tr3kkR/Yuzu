#include "rest_api_v1.hpp"
#include "http_route_sink.hpp"
#include "inventory_eval.hpp"
#include "store_errors.hpp"

// nlohmann/json is retained ONLY for parsing request bodies (json::parse).
// All response JSON is built via the lightweight JObj/JArr helpers below,
// which produce strings directly and avoid the template-instantiation
// explosion that caused 56 GB+ compiler memory usage.
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <string>
#include <string_view>
#include <system_error>

namespace yuzu::server {
namespace {

// ── Lightweight JSON string builder ─────────────────────────────────────
// Produces JSON output strings directly, bypassing nlohmann::json template
// instantiation for construction.  Only ~80 lines vs 23 000 lines of
// template machinery — compiles in milliseconds, not minutes.

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
                                  static_cast<unsigned int>(static_cast<unsigned char>(c)));
                    out += hex;
                } else {
                    out += c;
                }
        }
    }
}

/// JSON object builder.  Usage: JObj().add("k",v).add("k2",v2).str()
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
    JObj& add(std::string_view k, const char* v)        { return add(k, std::string_view(v)); }
    JObj& add(std::string_view k, int64_t v) {
        key(k); buf_ += std::to_string(v); return *this;
    }
    JObj& add(std::string_view k, int v)    { return add(k, static_cast<int64_t>(v)); }
    JObj& add(std::string_view k, double v) {
        key(k); buf_ += std::format("{:.2f}", v); return *this;
    }
    JObj& add(std::string_view k, bool v) {
        key(k); buf_ += v ? "true" : "false"; return *this;
    }
    /// Embed a pre-serialized JSON fragment (object, array, literal).
    JObj& raw(std::string_view k, std::string_view json) {
        key(k); buf_ += json; return *this;
    }

    [[nodiscard]] std::string str() const { return n_ ? buf_ + '}' : "{}"; }
};

/// JSON array builder.
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
    [[nodiscard]] int64_t size() const { return n_; }
};

/// Quote a string as a JSON value: "escaped content"
std::string json_quoted(std::string_view sv) {
    std::string out;
    out.reserve(sv.size() + 2);
    out += '"';
    json_escape(out, sv);
    out += '"';
    return out;
}

// ── Envelope helpers ────────────────────────────────────────────────────

std::string ok_json(std::string_view data_json) {
    return JObj().raw("data", data_json).raw("meta", R"({"api_version":"v1"})").str();
}

std::string error_json(std::string_view message, int code = 0) {
    JObj j;
    if (code != 0) {
        auto err = JObj().add("code", code).add("message", message).str();
        j.raw("error", err);
    } else {
        j.add("error", message);
    }
    j.raw("meta", R"({"api_version":"v1"})");
    return j.str();
}

std::string list_json(std::string_view data_json, int64_t total, int64_t start = 0,
                       int64_t page_size = 50) {
    auto pag = JObj().add("total", total).add("start", start).add("page_size", page_size).str();
    return JObj()
        .raw("data", data_json)
        .raw("pagination", pag)
        .raw("meta", R"({"api_version":"v1"})")
        .str();
}

// ── CORS helpers ────────────────────────────────────────────────────────

void add_cors_headers(httplib::Response& res, const httplib::Request& /* req */) {
    // Do NOT reflect arbitrary Origin — that defeats CORS.
    // API is same-origin by design; external integrations use API tokens.
    res.set_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    res.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Yuzu-Token");
    res.set_header("Access-Control-Max-Age", "86400");
}

// ── OpenAPI 3.0 spec ────────────────────────────────────────────────────
// Returned as a static raw string — zero template instantiation at compile
// time.  Previously this was a 365-line nested nlohmann::json initializer
// list that required 56 GB+ of compiler memory.

const std::string& openapi_spec() {
    static const std::string spec = R"json({
  "openapi": "3.0.3",
  "info": {
    "title": "Yuzu Server REST API",
    "version": "1.0.0",
    "description": "Enterprise endpoint management REST API. All endpoints require authentication via session cookie, Bearer token, or X-Yuzu-Token header.",
    "contact": {"name": "Yuzu Project"},
    "license": {"name": "AGPL-3.0-or-later", "url": "https://www.gnu.org/licenses/agpl-3.0.html"}
  },
  "servers": [{"url": "/api/v1", "description": "API v1 base path"}],
  "components": {
    "securitySchemes": {
      "bearerAuth": {"type": "http", "scheme": "bearer", "description": "API token via Authorization: Bearer <token>"},
      "apiKeyHeader": {"type": "apiKey", "in": "header", "name": "X-Yuzu-Token", "description": "API token via X-Yuzu-Token header"},
      "cookieAuth": {"type": "apiKey", "in": "cookie", "name": "session", "description": "Session cookie from /login"}
    },
    "schemas": {
      "ApiEnvelope": {
        "type": "object",
        "properties": {
          "data": {"description": "Response payload"},
          "meta": {"type": "object", "properties": {"api_version": {"type": "string"}}},
          "error": {"type": "string", "description": "Error message (present only on error)"},
          "pagination": {"type": "object", "properties": {
            "total": {"type": "integer"},
            "start": {"type": "integer"},
            "page_size": {"type": "integer"}
          }}
        }
      },
      "ManagementGroup": {
        "type": "object",
        "properties": {
          "id": {"type": "string"},
          "name": {"type": "string"},
          "description": {"type": "string"},
          "parent_id": {"type": "string"},
          "membership_type": {"type": "string", "enum": ["static", "dynamic"]},
          "scope_expression": {"type": "string"},
          "created_by": {"type": "string"},
          "created_at": {"type": "integer"},
          "updated_at": {"type": "integer"}
        }
      },
      "ApiToken": {
        "type": "object",
        "properties": {
          "token_id": {"type": "string"},
          "name": {"type": "string"},
          "principal_id": {"type": "string"},
          "created_at": {"type": "integer"},
          "expires_at": {"type": "integer"},
          "last_used_at": {"type": "integer"},
          "revoked": {"type": "boolean"}
        }
      },
      "Tag": {
        "type": "object",
        "properties": {
          "agent_id": {"type": "string"},
          "key": {"type": "string"},
          "value": {"type": "string"}
        }
      },
      "AuditEvent": {
        "type": "object",
        "properties": {
          "timestamp": {"type": "integer"},
          "principal": {"type": "string"},
          "action": {"type": "string"},
          "result": {"type": "string"},
          "target_type": {"type": "string"},
          "target_id": {"type": "string"},
          "detail": {"type": "string"}
        }
      },
      "InventoryRecord": {
        "type": "object",
        "properties": {
          "agent_id": {"type": "string"},
          "plugin": {"type": "string"},
          "data_json": {"type": "string", "description": "Structured JSON blob from the plugin"},
          "collected_at": {"type": "integer"}
        }
      },
      "InventoryTable": {
        "type": "object",
        "properties": {
          "plugin": {"type": "string"},
          "agent_count": {"type": "integer"},
          "last_collected": {"type": "integer"}
        }
      },
      "ProductPack": {
        "type": "object",
        "properties": {
          "id": {"type": "string"},
          "name": {"type": "string"},
          "version": {"type": "string"},
          "description": {"type": "string"},
          "installed_at": {"type": "integer"},
          "verified": {"type": "boolean", "description": "Whether the pack signature was verified"}
        }
      },
      "GuaranteedStateRule": {
        "type": "object",
        "properties": {
          "rule_id": {"type": "string", "description": "Stable operator-chosen id ([A-Za-z0-9._-]+)"},
          "name": {"type": "string"},
          "yaml_source": {"type": "string", "description": "Authoritative rule body (kind: GuaranteedStateRule)"},
          "version": {"type": "integer"},
          "enabled": {"type": "boolean"},
          "enforcement_mode": {"type": "string", "enum": ["enforce", "audit"]},
          "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
          "os_target": {"type": "string", "description": "Empty (any) or one of windows|linux|macos"},
          "scope_expr": {"type": "string", "description": "Scope DSL expression selecting target agents"},
          "created_at": {"type": "string", "format": "date-time"},
          "updated_at": {"type": "string", "format": "date-time"},
          "created_by": {"type": "string"},
          "updated_by": {"type": "string"}
        }
      },
      "GuaranteedStateStatus": {
        "type": "object",
        "properties": {
          "total_rules": {"type": "integer"},
          "compliant_rules": {"type": "integer"},
          "drifted_rules": {"type": "integer"},
          "errored_rules": {"type": "integer"}
        }
      },
      "GuaranteedStateEvent": {
        "type": "object",
        "properties": {
          "event_id": {"type": "string"},
          "rule_id": {"type": "string"},
          "agent_id": {"type": "string"},
          "event_type": {"type": "string"},
          "severity": {"type": "string"},
          "guard_type": {"type": "string"},
          "guard_category": {"type": "string", "enum": ["event", "condition"]},
          "detected_value": {"type": "string"},
          "expected_value": {"type": "string"},
          "remediation_action": {"type": "string"},
          "remediation_success": {"type": "boolean"},
          "detection_latency_us": {"type": "integer"},
          "remediation_latency_us": {"type": "integer"},
          "timestamp": {"type": "string", "format": "date-time"}
        }
      }
    }
  },
  "security": [{"bearerAuth": [], "apiKeyHeader": [], "cookieAuth": []}],
  "paths": {
    "/me": {
      "get": {"summary": "Get current user info", "tags": ["Authentication"], "responses": {"200": {"description": "Current user details"}}}
    },
    "/management-groups": {
      "get": {"summary": "List management groups", "tags": ["Management Groups"], "responses": {"200": {"description": "List of management groups"}}},
      "post": {"summary": "Create a management group", "tags": ["Management Groups"], "requestBody": {"required": true, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ManagementGroup"}}}}, "responses": {"201": {"description": "Group created"}}}
    },
    "/management-groups/{id}": {
      "get": {"summary": "Get a management group with members", "tags": ["Management Groups"], "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}], "responses": {"200": {"description": "Management group details"}, "404": {"description": "Group not found"}}},
      "put": {"summary": "Update a management group", "tags": ["Management Groups"], "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}], "responses": {"200": {"description": "Group updated"}}},
      "delete": {"summary": "Delete a management group", "tags": ["Management Groups"], "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}], "responses": {"200": {"description": "Group deleted"}}}
    },
    "/management-groups/{id}/members": {
      "post": {"summary": "Add member to management group", "tags": ["Management Groups"], "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}], "responses": {"201": {"description": "Member added"}}}
    },
    "/management-groups/{id}/members/{agent_id}": {
      "delete": {"summary": "Remove member from management group", "tags": ["Management Groups"], "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}, {"name": "agent_id", "in": "path", "required": true, "schema": {"type": "string"}}], "responses": {"200": {"description": "Member removed"}}}
    },
    "/management-groups/{id}/roles": {
      "get": {"summary": "List roles assigned to a management group", "tags": ["Management Groups"], "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}], "responses": {"200": {"description": "List of role assignments"}}},
      "post": {"summary": "Assign a role on a management group", "tags": ["Management Groups"], "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}], "responses": {"201": {"description": "Role assigned"}}},
      "delete": {"summary": "Unassign a role from a management group", "tags": ["Management Groups"], "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}], "responses": {"200": {"description": "Role unassigned"}}}
    },
    "/tokens": {
      "get": {"summary": "List API tokens for current user", "tags": ["API Tokens"], "responses": {"200": {"description": "List of API tokens"}}},
      "post": {"summary": "Create a new API token", "tags": ["API Tokens"], "requestBody": {"required": true, "content": {"application/json": {"schema": {"type": "object", "properties": {"name": {"type": "string"}, "expires_at": {"type": "integer"}, "scope_service": {"type": "string"}}}}}}, "responses": {"201": {"description": "Token created, includes plaintext token (shown once)"}}}
    },
    "/tokens/{token_id}": {
      "delete": {"summary": "Revoke an API token", "tags": ["API Tokens"], "parameters": [{"name": "token_id", "in": "path", "required": true, "schema": {"type": "string"}}], "responses": {"200": {"description": "Token revoked"}}}
    },
    "/quarantine": {
      "get": {"summary": "List quarantined devices", "tags": ["Security"], "responses": {"200": {"description": "List of quarantined devices"}}},
      "post": {"summary": "Quarantine a device", "tags": ["Security"], "requestBody": {"required": true, "content": {"application/json": {"schema": {"type": "object", "properties": {"agent_id": {"type": "string"}, "reason": {"type": "string"}, "whitelist": {"type": "string"}}}}}}, "responses": {"201": {"description": "Device quarantined"}}}
    },
    "/quarantine/{agent_id}": {
      "delete": {"summary": "Release a device from quarantine", "tags": ["Security"], "parameters": [{"name": "agent_id", "in": "path", "required": true, "schema": {"type": "string"}}], "responses": {"200": {"description": "Device released"}}}
    },
    "/rbac/roles": {
      "get": {"summary": "List RBAC roles", "tags": ["RBAC"], "responses": {"200": {"description": "List of roles"}}}
    },
    "/rbac/roles/{role}/permissions": {
      "get": {"summary": "Get permissions for a role", "tags": ["RBAC"], "parameters": [{"name": "role", "in": "path", "required": true, "schema": {"type": "string"}}], "responses": {"200": {"description": "List of permissions"}}}
    },
    "/rbac/check": {
      "post": {"summary": "Check if current user has a permission", "tags": ["RBAC"], "requestBody": {"required": true, "content": {"application/json": {"schema": {"type": "object", "properties": {"securable_type": {"type": "string"}, "operation": {"type": "string"}}}}}}, "responses": {"200": {"description": "Permission check result"}}}
    },
    "/tag-categories": {
      "get": {"summary": "List tag categories and allowed values", "tags": ["Tags"], "responses": {"200": {"description": "List of tag categories"}}}
    },
    "/tag-compliance": {
      "get": {"summary": "Get tag compliance gaps", "tags": ["Tags"], "responses": {"200": {"description": "Agents with missing required tags"}}}
    },
    "/tags": {
      "get": {"summary": "Get tags for an agent", "tags": ["Tags"], "parameters": [{"name": "agent_id", "in": "query", "required": true, "schema": {"type": "string"}}], "responses": {"200": {"description": "Tag key-value map"}}},
      "put": {"summary": "Set a tag on an agent", "tags": ["Tags"], "requestBody": {"required": true, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Tag"}}}}, "responses": {"200": {"description": "Tag set"}}}
    },
    "/tags/{agent_id}/{key}": {
      "delete": {"summary": "Delete a tag from an agent", "tags": ["Tags"], "parameters": [{"name": "agent_id", "in": "path", "required": true, "schema": {"type": "string"}}, {"name": "key", "in": "path", "required": true, "schema": {"type": "string"}}], "responses": {"200": {"description": "Tag deleted"}}}
    },
    "/definitions": {
      "get": {"summary": "List instruction definitions", "tags": ["Instructions"], "responses": {"200": {"description": "List of instruction definitions"}}}
    },
    "/audit": {
      "get": {"summary": "Query audit log", "tags": ["Audit"], "parameters": [{"name": "limit", "in": "query", "schema": {"type": "integer", "default": 100}}, {"name": "principal", "in": "query", "schema": {"type": "string"}}, {"name": "action", "in": "query", "schema": {"type": "string"}}], "responses": {"200": {"description": "List of audit events"}}}
    },
    "/inventory/tables": {
      "get": {"summary": "List available inventory data types", "tags": ["Inventory"], "description": "Lists distinct plugins that have reported inventory data, with agent counts and last collection timestamps.", "responses": {"200": {"description": "List of inventory tables", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/InventoryTable"}}}}}}
    },
    "/inventory/{agent_id}/{plugin}": {
      "get": {"summary": "Get inventory data for a specific agent and plugin", "tags": ["Inventory"], "parameters": [{"name": "agent_id", "in": "path", "required": true, "schema": {"type": "string"}}, {"name": "plugin", "in": "path", "required": true, "schema": {"type": "string"}}], "responses": {"200": {"description": "Inventory record"}, "404": {"description": "No inventory data found"}}}
    },
    "/inventory/query": {
      "post": {"summary": "Query inventory across agents with filter expression", "tags": ["Inventory"], "requestBody": {"required": true, "content": {"application/json": {"schema": {"type": "object", "properties": {"agent_id": {"type": "string", "description": "Filter by agent ID"}, "plugin": {"type": "string", "description": "Filter by plugin name"}, "since": {"type": "integer", "description": "Only records after this epoch"}, "until": {"type": "integer", "description": "Only records before this epoch"}, "limit": {"type": "integer", "default": 100}}}}}}, "responses": {"200": {"description": "Matching inventory records"}}}
    },
    "/openapi.json": {
      "get": {"summary": "OpenAPI 3.0 specification", "tags": ["Documentation"], "security": [], "responses": {"200": {"description": "OpenAPI 3.0 JSON spec"}}}
    },
    "/guaranteed-state/rules": {
      "get": {"summary": "List Guaranteed State rules", "tags": ["Guaranteed State"], "description": "Requires GuaranteedState:Read.", "responses": {"200": {"description": "List of rules", "content": {"application/json": {"schema": {"type": "array", "items": {"$ref": "#/components/schemas/GuaranteedStateRule"}}}}}, "503": {"description": "service unavailable"}}},
      "post": {"summary": "Create a Guaranteed State rule", "tags": ["Guaranteed State"], "description": "Requires GuaranteedState:Write. rule_id must match [A-Za-z0-9._-]+.", "requestBody": {"required": true, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/GuaranteedStateRule"}}}}, "responses": {"201": {"description": "Rule created"}, "400": {"description": "Missing required fields or invalid JSON"}, "409": {"description": "Conflicting rule_id or name"}, "503": {"description": "service unavailable"}}}
    },
    "/guaranteed-state/rules/{rule_id}": {
      "get": {"summary": "Get a Guaranteed State rule", "tags": ["Guaranteed State"], "description": "Requires GuaranteedState:Read.", "parameters": [{"name": "rule_id", "in": "path", "required": true, "schema": {"type": "string"}}], "responses": {"200": {"description": "Rule", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/GuaranteedStateRule"}}}}, "404": {"description": "Rule not found"}}},
      "put": {"summary": "Update a Guaranteed State rule", "tags": ["Guaranteed State"], "description": "Requires GuaranteedState:Write. Version is incremented on every successful update.", "parameters": [{"name": "rule_id", "in": "path", "required": true, "schema": {"type": "string"}}], "requestBody": {"required": true, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/GuaranteedStateRule"}}}}, "responses": {"200": {"description": "Rule updated"}, "400": {"description": "Invalid JSON"}, "404": {"description": "Rule not found"}, "409": {"description": "Conflicting name"}}},
      "delete": {"summary": "Delete a Guaranteed State rule", "tags": ["Guaranteed State"], "description": "Requires GuaranteedState:Delete.", "parameters": [{"name": "rule_id", "in": "path", "required": true, "schema": {"type": "string"}}], "responses": {"200": {"description": "Rule deleted"}, "404": {"description": "Rule not found"}}}
    },
    "/guaranteed-state/push": {
      "post": {"summary": "Queue a Guaranteed State rule push to agents", "tags": ["Guaranteed State"], "description": "Requires GuaranteedState:Push. Returns 202 Accepted — agent delivery is asynchronous and fan-out is not wired in PR 2 (landed in PR 3).", "requestBody": {"content": {"application/json": {"schema": {"type": "object", "properties": {"scope": {"type": "string", "description": "Scope DSL selector (empty = all agents)"}, "full_sync": {"type": "boolean", "default": false}}}}}}, "responses": {"202": {"description": "Push queued"}, "400": {"description": "Invalid JSON body"}, "503": {"description": "service unavailable"}}}
    },
    "/guaranteed-state/events": {
      "get": {"summary": "Query Guaranteed State events", "tags": ["Guaranteed State"], "description": "Requires GuaranteedState:Read. Limit is capped at 1000 at the REST boundary.", "parameters": [{"name": "rule_id", "in": "query", "schema": {"type": "string"}}, {"name": "agent_id", "in": "query", "schema": {"type": "string"}}, {"name": "severity", "in": "query", "schema": {"type": "string"}}, {"name": "limit", "in": "query", "schema": {"type": "integer", "default": 100, "maximum": 1000}}, {"name": "offset", "in": "query", "schema": {"type": "integer", "default": 0}}], "responses": {"200": {"description": "Matching events", "content": {"application/json": {"schema": {"type": "array", "items": {"$ref": "#/components/schemas/GuaranteedStateEvent"}}}}}, "400": {"description": "Invalid limit or offset"}}}
    },
    "/guaranteed-state/status": {
      "get": {"summary": "Fleet Guaranteed State status rollup", "tags": ["Guaranteed State"], "description": "Requires GuaranteedState:Read. PR 2 returns a placeholder with zero compliant/drifted/errored counts; real fleet aggregation lands in Guardian PR 4.", "responses": {"200": {"description": "Status rollup", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/GuaranteedStateStatus"}}}}}}
    },
    "/guaranteed-state/status/{agent_id}": {
      "get": {"summary": "Per-agent Guaranteed State status", "tags": ["Guaranteed State"], "description": "Requires GuaranteedState:Read. Placeholder — per-agent aggregation lands in Guardian PR 4.", "parameters": [{"name": "agent_id", "in": "path", "required": true, "schema": {"type": "string"}}], "responses": {"200": {"description": "Agent status"}}}
    },
    "/guaranteed-state/alerts": {
      "get": {"summary": "Guaranteed State alerts", "tags": ["Guaranteed State"], "description": "Requires GuaranteedState:Read. Placeholder — alert aggregation lands in Guardian PR 11.", "responses": {"200": {"description": "Alerts list (empty in PR 2)"}}}
    }
  }
})json";
    return spec;
}

} // anonymous namespace

// ── Route registration ───────────────────────────────────────────────────────

// Production overload — wraps httplib::Server in an HttplibRouteSink and
// delegates to the sink-based implementation below. Tests bypass this and
// call the sink overload directly with their own TestRouteSink (#438).
void RestApiV1::register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn,
                                AuditFn audit_fn, RbacStore* rbac_store,
                                ManagementGroupStore* mgmt_store, ApiTokenStore* token_store,
                                QuarantineStore* quarantine_store, ResponseStore* response_store,
                                InstructionStore* instruction_store,
                                ExecutionTracker* execution_tracker,
                                ScheduleEngine* schedule_engine, ApprovalManager* approval_manager,
                                TagStore* tag_store, AuditStore* audit_store,
                                ServiceGroupFn service_group_fn, TagPushFn tag_push_fn,
                                InventoryStore* inventory_store,
                                ProductPackStore* product_pack_store,
                                SoftwareDeploymentStore* sw_deploy_store,
                                DeviceTokenStore* device_token_store,
                                LicenseStore* license_store,
                                GuaranteedStateStore* guaranteed_state_store) {
    HttplibRouteSink sink(svr);
    register_routes(sink, std::move(auth_fn), std::move(perm_fn), std::move(audit_fn),
                    rbac_store, mgmt_store, token_store, quarantine_store, response_store,
                    instruction_store, execution_tracker, schedule_engine, approval_manager,
                    tag_store, audit_store, std::move(service_group_fn), std::move(tag_push_fn),
                    inventory_store, product_pack_store, sw_deploy_store, device_token_store,
                    license_store, guaranteed_state_store);
}

void RestApiV1::register_routes(HttpRouteSink& sink, AuthFn auth_fn, PermFn perm_fn,
                                AuditFn audit_fn, RbacStore* rbac_store,
                                ManagementGroupStore* mgmt_store, ApiTokenStore* token_store,
                                QuarantineStore* quarantine_store, ResponseStore* response_store,
                                InstructionStore* instruction_store,
                                ExecutionTracker* execution_tracker,
                                ScheduleEngine* schedule_engine, ApprovalManager* approval_manager,
                                TagStore* tag_store, AuditStore* audit_store,
                                ServiceGroupFn service_group_fn, TagPushFn tag_push_fn,
                                InventoryStore* inventory_store,
                                ProductPackStore* product_pack_store,
                                SoftwareDeploymentStore* sw_deploy_store,
                                DeviceTokenStore* device_token_store,
                                LicenseStore* license_store,
                                GuaranteedStateStore* guaranteed_state_store) {

    spdlog::info("REST API v1: registering routes");

    // ── CORS preflight handler for /api/v1/* ─────────────────────────────
    // Actual CORS headers are added by the post-routing handler in server.cpp
    // with origin allowlist validation.
    sink.Options(R"(/api/v1/.*)", [](const httplib::Request&, httplib::Response& res) {
        res.status = 204;
    });

    // ── OpenAPI spec endpoint (/api/v1/openapi.json) ─────────────────────
    sink.Get("/api/v1/openapi.json", [](const httplib::Request&, httplib::Response& res) {
        res.set_content(openapi_spec(), "application/json");
    });

    // ── /api/v1/me ───────────────────────────────────────────────────────

    sink.Get("/api/v1/me", [auth_fn, rbac_store](const httplib::Request& req, httplib::Response& res) {
        auto session = auth_fn(req, res);
        if (!session)
            return;

        JObj data;
        data.add("username", session->username)
            .add("role", auth::role_to_string(session->role));

        if (rbac_store && rbac_store->is_rbac_enabled()) {
            data.add("rbac_enabled", true);
            auto roles = rbac_store->get_principal_roles("user", session->username);
            if (!roles.empty()) {
                data.add("rbac_role", roles[0].role_name);
            } else {
                data.add("rbac_role",
                         session->role == auth::Role::admin ? "Administrator" : "Viewer");
            }
        } else {
            data.add("rbac_enabled", false);
            data.add("rbac_role",
                     session->role == auth::Role::admin ? "Administrator" : "Viewer");
        }
        res.set_content(ok_json(data.str()), "application/json");
    });

    // ── Management Groups (/api/v1/management-groups) ────────────────────

    sink.Get("/api/v1/management-groups",
            [auth_fn, perm_fn, mgmt_store](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn(req, res, "ManagementGroup", "Read"))
                    return;
                if (!mgmt_store) {
                    res.status = 503;
                    res.set_content(error_json("service unavailable", 503), "application/json");
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
                                .add("scope_expression", g.scope_expression)
                                .add("created_by", g.created_by)
                                .add("created_at", g.created_at)
                                .add("updated_at", g.updated_at));
                }
                res.set_content(list_json(arr.str(), static_cast<int64_t>(groups.size())),
                                "application/json");
            });

    sink.Post("/api/v1/management-groups", [auth_fn, perm_fn, audit_fn, mgmt_store](
                                              const httplib::Request& req, httplib::Response& res) {
        if (!perm_fn(req, res, "ManagementGroup", "Write"))
            return;
        if (!mgmt_store) {
            res.status = 503;
            res.set_content(error_json("service unavailable", 503), "application/json");
            return;
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded()) {
            res.status = 400;
            res.set_content(error_json("invalid JSON"), "application/json");
            return;
        }

        ManagementGroup g;
        g.name = body.value("name", "");
        g.description = body.value("description", "");
        g.parent_id = body.value("parent_id", "");
        g.membership_type = body.value("membership_type", "static");
        g.scope_expression = body.value("scope_expression", "");

        auto session = auth_fn(req, res);
        if (session)
            g.created_by = session->username;

        auto result = mgmt_store->create_group(g);
        if (!result) {
            res.status = 400;
            res.set_content(error_json(result.error()), "application/json");
            return;
        }
        audit_fn(req, "management_group.create", "success", "ManagementGroup", *result, g.name);
        res.status = 201;
        res.set_content(ok_json(JObj().add("id", *result).str()), "application/json");
    });

    sink.Get(R"(/api/v1/management-groups/([a-f0-9]+))",
            [auth_fn, perm_fn, mgmt_store](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn(req, res, "ManagementGroup", "Read"))
                    return;
                if (!mgmt_store) {
                    res.status = 503;
                    res.set_content(error_json("service unavailable", 503), "application/json");
                    return;
                }

                auto id = req.matches[1].str();
                auto g = mgmt_store->get_group(id);
                if (!g) {
                    res.status = 404;
                    res.set_content(error_json("group not found"), "application/json");
                    return;
                }
                auto members = mgmt_store->get_members(id);
                JArr member_arr;
                for (const auto& m : members)
                    member_arr.add(JObj()
                                       .add("agent_id", m.agent_id)
                                       .add("source", m.source)
                                       .add("added_at", m.added_at));

                auto data = JObj()
                                .add("id", g->id)
                                .add("name", g->name)
                                .add("description", g->description)
                                .add("parent_id", g->parent_id)
                                .add("membership_type", g->membership_type)
                                .add("scope_expression", g->scope_expression)
                                .add("created_by", g->created_by)
                                .add("created_at", g->created_at)
                                .add("updated_at", g->updated_at)
                                .raw("members", member_arr.str());
                res.set_content(ok_json(data.str()), "application/json");
            });

    // Update group (rename, re-parent, change description/membership)
    sink.Put(R"(/api/v1/management-groups/([a-f0-9]+))",
            [auth_fn, perm_fn, audit_fn, mgmt_store](const httplib::Request& req,
                                                      httplib::Response& res) {
                if (!perm_fn(req, res, "ManagementGroup", "Write"))
                    return;
                if (!mgmt_store) {
                    res.status = 503;
                    res.set_content(error_json("service unavailable", 503), "application/json");
                    return;
                }

                auto id = req.matches[1].str();
                auto existing = mgmt_store->get_group(id);
                if (!existing) {
                    res.status = 404;
                    res.set_content(error_json("group not found"), "application/json");
                    return;
                }

                auto body = nlohmann::json::parse(req.body, nullptr, false);
                if (body.is_discarded()) {
                    res.status = 400;
                    res.set_content(error_json("invalid JSON"), "application/json");
                    return;
                }

                auto updated = *existing;
                if (body.contains("name"))
                    updated.name = body["name"].get<std::string>();
                if (body.contains("description"))
                    updated.description = body["description"].get<std::string>();
                if (body.contains("parent_id"))
                    updated.parent_id = body["parent_id"].get<std::string>();
                if (body.contains("membership_type"))
                    updated.membership_type = body["membership_type"].get<std::string>();
                if (body.contains("scope_expression"))
                    updated.scope_expression = body["scope_expression"].get<std::string>();

                if (id == ManagementGroupStore::kRootGroupId && !updated.parent_id.empty()) {
                    res.status = 400;
                    res.set_content(error_json("cannot re-parent root group"), "application/json");
                    return;
                }

                if (!updated.parent_id.empty() && updated.parent_id != existing->parent_id) {
                    auto descendants = mgmt_store->get_descendant_ids(id);
                    if (std::find(descendants.begin(), descendants.end(), updated.parent_id) !=
                        descendants.end()) {
                        res.status = 400;
                        res.set_content(error_json("re-parenting would create a cycle"),
                                        "application/json");
                        return;
                    }
                    auto ancestors = mgmt_store->get_ancestor_ids(updated.parent_id);
                    if (ancestors.size() >= 4) {
                        res.status = 400;
                        res.set_content(error_json("maximum hierarchy depth (5) exceeded"),
                                        "application/json");
                        return;
                    }
                }

                auto result = mgmt_store->update_group(updated);
                if (!result) {
                    res.status = 400;
                    res.set_content(error_json(result.error()), "application/json");
                    return;
                }
                audit_fn(req, "management_group.update", "success", "ManagementGroup", id,
                         updated.name);
                res.set_content(ok_json(JObj().add("updated", true).str()), "application/json");
            });

    sink.Delete(
        R"(/api/v1/management-groups/([a-f0-9]+))",
        [perm_fn, audit_fn, mgmt_store](const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn(req, res, "ManagementGroup", "Delete"))
                return;
            if (!mgmt_store) {
                res.status = 503;
                res.set_content(error_json("service unavailable", 503), "application/json");
                return;
            }

            auto id = req.matches[1].str();
            auto result = mgmt_store->delete_group(id);
            if (!result) {
                res.status = (result.error() == "cannot delete root group") ? 403 : 404;
                res.set_content(error_json(result.error()), "application/json");
                return;
            }
            audit_fn(req, "management_group.delete", "success", "ManagementGroup", id, "");
            res.set_content(ok_json(JObj().add("deleted", true).str()), "application/json");
        });

    // Members
    sink.Post(R"(/api/v1/management-groups/([a-f0-9]+)/members)",
             [perm_fn, audit_fn, mgmt_store](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn(req, res, "ManagementGroup", "Write"))
                     return;
                 if (!mgmt_store) {
                     res.status = 503;
                     res.set_content(error_json("service unavailable", 503), "application/json");
                     return;
                 }

                 auto group_id = req.matches[1].str();
                 auto body = nlohmann::json::parse(req.body, nullptr, false);
                 auto agent_id = body.value("agent_id", "");
                 if (agent_id.empty()) {
                     res.status = 400;
                     res.set_content(error_json("agent_id required"), "application/json");
                     return;
                 }
                 mgmt_store->add_member(group_id, agent_id);
                 audit_fn(req, "management_group.add_member", "success", "ManagementGroup",
                          group_id, agent_id);
                 res.status = 201;
                 res.set_content(ok_json(JObj().add("added", true).str()), "application/json");
             });

    sink.Delete(
        R"(/api/v1/management-groups/([a-f0-9]+)/members/(.+))",
        [perm_fn, audit_fn, mgmt_store](const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn(req, res, "ManagementGroup", "Write"))
                return;
            if (!mgmt_store) {
                res.status = 503;
                res.set_content(error_json("service unavailable", 503), "application/json");
                return;
            }

            auto group_id = req.matches[1].str();
            auto agent_id = req.matches[2].str();
            mgmt_store->remove_member(group_id, agent_id);
            audit_fn(req, "management_group.remove_member", "success", "ManagementGroup", group_id,
                     agent_id);
            res.set_content(ok_json(JObj().add("removed", true).str()), "application/json");
        });

    // ── Management Group Roles (/api/v1/management-groups/:id/roles) ────

    sink.Get(R"(/api/v1/management-groups/([a-f0-9]+)/roles)",
            [perm_fn, mgmt_store](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn(req, res, "ManagementGroup", "Read"))
                    return;
                if (!mgmt_store) {
                    res.status = 503;
                    res.set_content(error_json("service unavailable", 503), "application/json");
                    return;
                }

                auto group_id = req.matches[1].str();
                auto roles = mgmt_store->get_group_roles(group_id);
                JArr arr;
                for (const auto& r : roles) {
                    arr.add(JObj()
                                .add("group_id", r.group_id)
                                .add("principal_type", r.principal_type)
                                .add("principal_id", r.principal_id)
                                .add("role_name", r.role_name));
                }
                res.set_content(ok_json(arr.str()), "application/json");
            });

    sink.Post(
        R"(/api/v1/management-groups/([a-f0-9]+)/roles)",
        [auth_fn, perm_fn, audit_fn, mgmt_store, rbac_store](const httplib::Request& req,
                                                              httplib::Response& res) {
            auto session = auth_fn(req, res);
            if (!session)
                return;
            if (!mgmt_store || !rbac_store) {
                res.status = 503;
                res.set_content(error_json("service unavailable", 503), "application/json");
                return;
            }

            auto group_id = req.matches[1].str();
            auto body = nlohmann::json::parse(req.body, nullptr, false);
            if (body.is_discarded()) {
                res.status = 400;
                res.set_content(error_json("invalid JSON"), "application/json");
                return;
            }

            auto principal_type = body.value("principal_type", "user");
            auto principal_id = body.value("principal_id", "");
            auto role_name = body.value("role_name", "");

            if (principal_id.empty() || role_name.empty()) {
                res.status = 400;
                res.set_content(error_json("principal_id and role_name required"),
                                "application/json");
                return;
            }

            if (role_name != "Operator" && role_name != "Viewer") {
                res.status = 403;
                res.set_content(
                    error_json("only Operator and Viewer roles can be delegated"),
                    "application/json");
                return;
            }

            bool authorized = rbac_store->check_permission(session->username, "ManagementGroup",
                                                           "Write");
            if (!authorized) {
                auto group_roles = mgmt_store->get_group_roles(group_id);
                for (const auto& gr : group_roles) {
                    if (gr.principal_type == "user" && gr.principal_id == session->username &&
                        gr.role_name == "ITServiceOwner") {
                        authorized = true;
                        break;
                    }
                }
            }
            if (!authorized) {
                res.status = 403;
                res.set_content(error_json("forbidden"), "application/json");
                return;
            }

            GroupRoleAssignment assignment;
            assignment.group_id = group_id;
            assignment.principal_type = principal_type;
            assignment.principal_id = principal_id;
            assignment.role_name = role_name;

            auto result = mgmt_store->assign_role(assignment);
            if (!result) {
                res.status = 400;
                res.set_content(error_json(result.error()), "application/json");
                return;
            }
            audit_fn(req, "management_group.assign_role", "success", "ManagementGroup", group_id,
                     principal_id + ":" + role_name);
            res.status = 201;
            res.set_content(ok_json(JObj().add("assigned", true).str()), "application/json");
        });

    sink.Delete(
        R"(/api/v1/management-groups/([a-f0-9]+)/roles)",
        [auth_fn, perm_fn, audit_fn, mgmt_store, rbac_store](const httplib::Request& req,
                                                              httplib::Response& res) {
            auto session = auth_fn(req, res);
            if (!session)
                return;
            if (!mgmt_store || !rbac_store) {
                res.status = 503;
                res.set_content(error_json("service unavailable", 503), "application/json");
                return;
            }

            auto group_id = req.matches[1].str();
            auto body = nlohmann::json::parse(req.body, nullptr, false);
            if (body.is_discarded()) {
                res.status = 400;
                res.set_content(error_json("invalid JSON"), "application/json");
                return;
            }

            auto principal_type = body.value("principal_type", "user");
            auto principal_id = body.value("principal_id", "");
            auto role_name = body.value("role_name", "");

            bool authorized = rbac_store->check_permission(session->username, "ManagementGroup",
                                                           "Write");
            if (!authorized) {
                auto group_roles = mgmt_store->get_group_roles(group_id);
                for (const auto& gr : group_roles) {
                    if (gr.principal_type == "user" && gr.principal_id == session->username &&
                        gr.role_name == "ITServiceOwner") {
                        authorized = true;
                        break;
                    }
                }
            }
            if (!authorized) {
                res.status = 403;
                res.set_content(error_json("forbidden"), "application/json");
                return;
            }

            mgmt_store->unassign_role(group_id, principal_type, principal_id, role_name);
            audit_fn(req, "management_group.unassign_role", "success", "ManagementGroup", group_id,
                     principal_id + ":" + role_name);
            res.set_content(ok_json(JObj().add("unassigned", true).str()), "application/json");
        });

    // ── API Tokens (/api/v1/tokens) ──────────────────────────────────────

    sink.Get("/api/v1/tokens",
            [auth_fn, perm_fn, token_store](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn(req, res, "ApiToken", "Read"))
                    return;
                if (!token_store) {
                    res.status = 503;
                    res.set_content(error_json("service unavailable", 503), "application/json");
                    return;
                }

                auto session = auth_fn(req, res);
                if (!session)
                    return;

                auto tokens = token_store->list_tokens(session->username);
                JArr arr;
                for (const auto& t : tokens) {
                    JObj item;
                    item.add("token_id", t.token_id)
                        .add("name", t.name)
                        .add("principal_id", t.principal_id)
                        .add("created_at", t.created_at)
                        .add("expires_at", t.expires_at)
                        .add("last_used_at", t.last_used_at)
                        .add("revoked", t.revoked);
                    if (!t.scope_service.empty())
                        item.add("scope_service", t.scope_service);
                    arr.add(item);
                }
                res.set_content(list_json(arr.str(), static_cast<int64_t>(tokens.size())),
                                "application/json");
            });

    sink.Post("/api/v1/tokens", [auth_fn, perm_fn, audit_fn, token_store, rbac_store, mgmt_store,
                                tag_store](const httplib::Request& req, httplib::Response& res) {
        if (!perm_fn(req, res, "ApiToken", "Write"))
            return;
        if (!token_store) {
            res.status = 503;
            res.set_content(error_json("service unavailable", 503), "application/json");
            return;
        }

        auto session = auth_fn(req, res);
        if (!session)
            return;

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        auto name = body.value("name", "");
        auto expires_at = body.value("expires_at", int64_t{0});
        auto scope_service = body.value("scope_service", "");

        if (!scope_service.empty()) {
            if (!rbac_store || !rbac_store->is_rbac_enabled()) {
                res.status = 400;
                res.set_content(
                    error_json("service-scoped tokens require RBAC to be enabled"),
                    "application/json");
                return;
            }
            bool authorized =
                rbac_store->check_permission(session->username, "ManagementGroup", "Write");
            if (!authorized && mgmt_store) {
                auto svc_group = mgmt_store->find_group_by_name("Service: " + scope_service);
                if (svc_group) {
                    auto group_roles = mgmt_store->get_group_roles(svc_group->id);
                    for (const auto& gr : group_roles) {
                        if (gr.principal_type == "user" && gr.principal_id == session->username &&
                            gr.role_name == "ITServiceOwner") {
                            authorized = true;
                            break;
                        }
                    }
                }
            }
            if (!authorized) {
                res.status = 403;
                res.set_content(
                    error_json("ITServiceOwner authority required for service '" +
                               scope_service + "'"),
                    "application/json");
                return;
            }
        }

        auto result =
            token_store->create_token(name, session->username, expires_at, scope_service);
        if (!result) {
            res.status = 400;
            res.set_content(error_json(result.error()), "application/json");
            return;
        }
        auto detail = scope_service.empty() ? "" : "scope_service=" + scope_service;
        audit_fn(req, "api_token.create", "success", "ApiToken", name, detail);
        res.status = 201;
        JObj resp;
        resp.add("token", *result).add("name", name);
        if (!scope_service.empty())
            resp.add("scope_service", scope_service);
        res.set_content(ok_json(resp.str()), "application/json");
    });

    sink.Delete(R"(/api/v1/tokens/(.+))", [auth_fn, perm_fn, audit_fn, token_store](
                                             const httplib::Request& req, httplib::Response& res) {
        if (!perm_fn(req, res, "ApiToken", "Delete"))
            return;
        if (!token_store) {
            res.status = 503;
            res.set_content(error_json("service unavailable", 503), "application/json");
            return;
        }

        auto session = auth_fn(req, res);
        if (!session)
            return;

        auto token_id = req.matches[1].str();

        // Owner-scoped revocation (fixes #222). `ApiToken:Delete` alone is
        // not sufficient — callers must either own the token or hold the
        // global admin role. Without this a user with Delete permission
        // could enumerate and revoke any other user's tokens (IDOR).
        //
        // Both the missing-id and the not-owner cases return 404 with an
        // identical response body so the endpoint does not become an
        // enumeration oracle (gov-Gate2 sec-M3). The audit log still
        // distinguishes the two cases via the `result` field (`denied`
        // vs. no event) and the `owner=` detail so forensics can see who
        // tried to revoke whose token.
        auto existing = token_store->get_token(token_id);
        bool denied =
            existing && existing->principal_id != session->username &&
            session->role != auth::Role::admin;
        if (!existing || denied) {
            if (denied) {
                audit_fn(req, "api_token.revoke", "denied", "ApiToken", token_id,
                         "owner=" + existing->principal_id);
            }
            res.status = 404;
            res.set_content(error_json("token not found"), "application/json");
            return;
        }

        bool revoked = token_store->revoke_token(token_id);
        if (!revoked) {
            // Either the token vanished between get and revoke, or the
            // revoke call itself failed. Treat as not-found for the client.
            res.status = 404;
            res.set_content(error_json("token not found"), "application/json");
            return;
        }
        audit_fn(req, "api_token.revoke", "success", "ApiToken", token_id,
                 "owner=" + existing->principal_id);
        res.set_content(ok_json(JObj().add("revoked", true).str()), "application/json");
    });

    // ── Quarantine (/api/v1/quarantine) ──────────────────────────────────

    sink.Get("/api/v1/quarantine",
            [perm_fn, quarantine_store](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn(req, res, "Security", "Read"))
                    return;
                if (!quarantine_store) {
                    res.status = 503;
                    res.set_content(error_json("service unavailable", 503), "application/json");
                    return;
                }

                auto records = quarantine_store->list_quarantined();
                JArr arr;
                for (const auto& r : records) {
                    arr.add(JObj()
                                .add("agent_id", r.agent_id)
                                .add("status", r.status)
                                .add("quarantined_by", r.quarantined_by)
                                .add("quarantined_at", r.quarantined_at)
                                .add("whitelist", r.whitelist)
                                .add("reason", r.reason));
                }
                res.set_content(list_json(arr.str(), static_cast<int64_t>(records.size())),
                                "application/json");
            });

    sink.Post("/api/v1/quarantine", [auth_fn, perm_fn, audit_fn, quarantine_store](
                                       const httplib::Request& req, httplib::Response& res) {
        if (!perm_fn(req, res, "Security", "Execute"))
            return;
        if (!quarantine_store) {
            res.status = 503;
            res.set_content(error_json("service unavailable", 503), "application/json");
            return;
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        auto agent_id = body.value("agent_id", "");
        auto reason = body.value("reason", "");
        auto whitelist = body.value("whitelist", "");

        auto session = auth_fn(req, res);
        std::string by = session ? session->username : "system";

        auto result = quarantine_store->quarantine_device(agent_id, by, reason, whitelist);
        if (!result) {
            res.status = 400;
            res.set_content(error_json(result.error()), "application/json");
            return;
        }
        audit_fn(req, "quarantine.enable", "success", "Security", agent_id, reason);
        res.status = 201;
        res.set_content(ok_json(JObj().add("quarantined", true).str()), "application/json");
    });

    sink.Delete(
        R"(/api/v1/quarantine/(.+))",
        [perm_fn, audit_fn, quarantine_store](const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn(req, res, "Security", "Execute"))
                return;
            if (!quarantine_store) {
                res.status = 503;
                res.set_content(error_json("service unavailable", 503), "application/json");
                return;
            }

            auto agent_id = req.matches[1].str();
            auto result = quarantine_store->release_device(agent_id);
            if (!result) {
                res.status = 400;
                res.set_content(error_json(result.error()), "application/json");
                return;
            }
            audit_fn(req, "quarantine.disable", "success", "Security", agent_id, "");
            res.set_content(ok_json(JObj().add("released", true).str()), "application/json");
        });

    // ── RBAC (/api/v1/rbac) ──────────────────────────────────────────────

    sink.Get("/api/v1/rbac/roles",
            [perm_fn, rbac_store](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn(req, res, "UserManagement", "Read"))
                    return;
                if (!rbac_store) {
                    res.status = 503;
                    res.set_content(error_json("service unavailable", 503), "application/json");
                    return;
                }

                auto roles = rbac_store->list_roles();
                JArr arr;
                for (const auto& r : roles) {
                    arr.add(JObj()
                                .add("name", r.name)
                                .add("description", r.description)
                                .add("is_system", r.is_system)
                                .add("created_at", r.created_at));
                }
                res.set_content(list_json(arr.str(), static_cast<int64_t>(roles.size())),
                                "application/json");
            });

    sink.Get(R"(/api/v1/rbac/roles/(.+)/permissions)",
            [perm_fn, rbac_store](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn(req, res, "UserManagement", "Read"))
                    return;
                if (!rbac_store) {
                    res.status = 503;
                    res.set_content(error_json("service unavailable", 503), "application/json");
                    return;
                }

                auto role_name = req.matches[1].str();
                auto perms = rbac_store->get_role_permissions(role_name);
                JArr arr;
                for (const auto& p : perms) {
                    arr.add(JObj()
                                .add("securable_type", p.securable_type)
                                .add("operation", p.operation)
                                .add("effect", p.effect));
                }
                res.set_content(ok_json(arr.str()), "application/json");
            });

    sink.Post("/api/v1/rbac/check", [auth_fn, rbac_store](const httplib::Request& req,
                                                         httplib::Response& res) {
        auto session = auth_fn(req, res);
        if (!session)
            return;
        if (!rbac_store) {
            res.status = 503;
            res.set_content(error_json("service unavailable", 503), "application/json");
            return;
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        auto securable_type = body.value("securable_type", "");
        auto operation = body.value("operation", "");
        bool allowed = rbac_store->check_permission(session->username, securable_type, operation);
        res.set_content(ok_json(JObj().add("allowed", allowed).str()), "application/json");
    });

    // ── Tag Categories (/api/v1/tag-categories) ────────────────────────

    sink.Get("/api/v1/tag-categories",
            [perm_fn](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn(req, res, "Tag", "Read"))
                    return;

                const auto& categories = get_tag_categories();
                JArr arr;
                for (const auto& cat : categories) {
                    JArr vals;
                    for (auto v : cat.allowed_values)
                        vals.add(v);
                    arr.add(JObj()
                                .add("key", cat.key)
                                .add("display_name", cat.display_name)
                                .raw("allowed_values", vals.str()));
                }
                res.set_content(ok_json(arr.str()), "application/json");
            });

    // ── Tag Compliance (/api/v1/tag-compliance) ──────────────────────────

    sink.Get("/api/v1/tag-compliance",
            [perm_fn, tag_store](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn(req, res, "Tag", "Read"))
                    return;
                if (!tag_store) {
                    res.status = 503;
                    res.set_content(error_json("service unavailable", 503), "application/json");
                    return;
                }

                auto gaps = tag_store->get_compliance_gaps();
                JArr arr;
                for (const auto& [agent_id, missing] : gaps) {
                    JArr m;
                    for (const auto& k : missing)
                        m.add(k);
                    arr.add(JObj().add("agent_id", agent_id).raw("missing_tags", m.str()));
                }
                res.set_content(ok_json(arr.str()), "application/json");
            });

    // ── Tags (/api/v1/tags) ──────────────────────────────────────────────

    sink.Get("/api/v1/tags",
            [perm_fn, tag_store](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn(req, res, "Tag", "Read"))
                    return;
                if (!tag_store) {
                    res.status = 503;
                    res.set_content(error_json("service unavailable", 503), "application/json");
                    return;
                }

                auto agent_id = req.get_param_value("agent_id");
                if (agent_id.empty()) {
                    res.status = 400;
                    res.set_content(error_json("agent_id parameter required"), "application/json");
                    return;
                }
                auto tags = tag_store->get_all_tags(agent_id);
                JObj obj;
                for (size_t i = 0; i < tags.size(); ++i)
                    obj.add(tags[i].key, tags[i].value);
                res.set_content(ok_json(obj.str()), "application/json");
            });

    sink.Put("/api/v1/tags",
            [perm_fn, audit_fn, tag_store, service_group_fn,
             tag_push_fn](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn(req, res, "Tag", "Write"))
                    return;
                if (!tag_store) {
                    res.status = 503;
                    res.set_content(error_json("service unavailable", 503), "application/json");
                    return;
                }

                auto body = nlohmann::json::parse(req.body, nullptr, false);
                if (body.is_discarded()) {
                    res.status = 400;
                    res.set_content(error_json("invalid JSON"), "application/json");
                    return;
                }
                auto agent_id = body.value("agent_id", "");
                auto key = body.value("key", "");
                auto value = body.value("value", "");

                // Normalize category keys to lowercase for consistent lookups
                std::string lower_key = key;
                std::transform(lower_key.begin(), lower_key.end(), lower_key.begin(),
                    [](unsigned char c) { return std::tolower(c); });
                for (auto cat : {"role", "environment", "location", "service"}) {
                    if (lower_key == cat) { key = lower_key; break; }
                }

                if (agent_id.empty() || key.empty()) {
                    res.status = 400;
                    res.set_content(error_json("agent_id and key required"), "application/json");
                    return;
                }

                auto result = tag_store->set_tag_checked(agent_id, key, value, "api");
                if (!result) {
                    res.status = 400;
                    res.set_content(error_json(result.error()), "application/json");
                    return;
                }
                if (key == "service" && service_group_fn)
                    service_group_fn(value);
                if (tag_push_fn)
                    tag_push_fn(agent_id, key);
                audit_fn(req, "tag.set", "success", "Tag", agent_id + ":" + key, value);
                res.set_content(ok_json(JObj().add("set", true).str()), "application/json");
            });

    sink.Delete(
        R"(/api/v1/tags/([^/]+)/([^/]+))",
        [perm_fn, audit_fn, tag_store](const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn(req, res, "Tag", "Delete"))
                return;
            if (!tag_store) {
                res.status = 503;
                res.set_content(error_json("service unavailable", 503), "application/json");
                return;
            }

            auto agent_id = req.matches[1].str();
            auto key = req.matches[2].str();
            bool deleted = tag_store->delete_tag(agent_id, key);
            if (!deleted) {
                res.status = 404;
                res.set_content(error_json("tag not found"), "application/json");
                return;
            }
            audit_fn(req, "tag.delete", "success", "Tag", agent_id + ":" + key, "");
            res.set_content(ok_json(JObj().add("deleted", true).str()), "application/json");
        });

    // ── Instructions (/api/v1/definitions) ───────────────────────────────

    sink.Get("/api/v1/definitions",
            [perm_fn, instruction_store](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn(req, res, "InstructionDefinition", "Read"))
                    return;
                if (!instruction_store) {
                    res.status = 503;
                    res.set_content(error_json("service unavailable", 503), "application/json");
                    return;
                }

                auto defs = instruction_store->query_definitions();
                JArr arr;
                for (size_t i = 0; i < defs.size(); ++i) {
                    const auto& d = defs[i];
                    arr.add(JObj()
                                .add("id", d.id)
                                .add("name", d.name)
                                .add("description", d.description)
                                .add("plugin", d.plugin)
                                .add("action", d.action)
                                .add("version", d.version)
                                .add("created_at", d.created_at));
                }
                res.set_content(list_json(arr.str(), static_cast<int64_t>(defs.size())),
                                "application/json");
            });

    // ── Audit (/api/v1/audit) ────────────────────────────────────────────

    sink.Get("/api/v1/audit",
            [perm_fn, audit_store](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn(req, res, "AuditLog", "Read"))
                    return;
                if (!audit_store) {
                    res.status = 503;
                    res.set_content(error_json("service unavailable", 503), "application/json");
                    return;
                }

                AuditQuery q;
                auto limit_str = req.get_param_value("limit");
                if (!limit_str.empty()) {
                    try {
                        q.limit = std::stoi(limit_str);
                    } catch (...) {}
                }
                if (q.limit > 1000)
                    q.limit = 1000;
                q.principal = req.get_param_value("principal");
                q.action = req.get_param_value("action");

                auto events = audit_store->query(q);
                JArr arr;
                for (size_t i = 0; i < events.size(); ++i) {
                    const auto& e = events[i];
                    arr.add(JObj()
                                .add("timestamp", e.timestamp)
                                .add("principal", e.principal)
                                .add("action", e.action)
                                .add("result", e.result)
                                .add("target_type", e.target_type)
                                .add("target_id", e.target_id)
                                .add("detail", e.detail));
                }
                res.set_content(list_json(arr.str(), static_cast<int64_t>(events.size())),
                                "application/json");
            });

    // ── Inventory (/api/v1/inventory) ──────────────────────────────────

    sink.Get("/api/v1/inventory/tables",
            [perm_fn, inventory_store](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn(req, res, "Inventory", "Read"))
                    return;
                if (!inventory_store || !inventory_store->is_open()) {
                    res.status = 503;
                    res.set_content(error_json("inventory store not available"), "application/json");
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
                res.set_content(list_json(arr.str(), static_cast<int64_t>(tables.size())),
                                "application/json");
            });

    sink.Get(R"(/api/v1/inventory/([^/]+)/([^/]+))",
            [perm_fn, inventory_store](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn(req, res, "Inventory", "Read"))
                    return;
                if (!inventory_store || !inventory_store->is_open()) {
                    res.status = 503;
                    res.set_content(error_json("inventory store not available"), "application/json");
                    return;
                }

                auto agent_id = req.matches[1].str();
                auto plugin = req.matches[2].str();

                auto record = inventory_store->get(agent_id, plugin);
                if (!record) {
                    res.status = 404;
                    res.set_content(error_json("no inventory data found"), "application/json");
                    return;
                }

                // Embed data_json as raw JSON if valid, otherwise as a quoted string
                auto parsed = nlohmann::json::parse(record->data_json, nullptr, false);
                JObj data;
                data.add("agent_id", record->agent_id)
                    .add("plugin", record->plugin);
                if (!parsed.is_discarded()) {
                    data.raw("data", record->data_json);
                } else {
                    data.add("data", record->data_json);
                }
                data.add("collected_at", record->collected_at);
                res.set_content(ok_json(data.str()), "application/json");
            });

    sink.Post("/api/v1/inventory/query",
             [perm_fn, inventory_store](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn(req, res, "Inventory", "Read"))
                     return;
                 if (!inventory_store || !inventory_store->is_open()) {
                     res.status = 503;
                     res.set_content(error_json("inventory store not available"),
                                     "application/json");
                     return;
                 }

                 auto body = nlohmann::json::parse(req.body, nullptr, false);
                 if (body.is_discarded()) {
                     res.status = 400;
                     res.set_content(error_json("invalid JSON"), "application/json");
                     return;
                 }

                 InventoryQuery q;
                 q.agent_id = body.value("agent_id", "");
                 q.plugin = body.value("plugin", "");
                 q.since = body.value("since", int64_t{0});
                 q.until = body.value("until", int64_t{0});
                 q.limit = body.value("limit", 100);
                 if (q.limit > 1000)
                     q.limit = 1000;

                 auto records = inventory_store->query(q);
                 JArr arr;
                 for (const auto& r : records) {
                     auto parsed = nlohmann::json::parse(r.data_json, nullptr, false);
                     JObj item;
                     item.add("agent_id", r.agent_id).add("plugin", r.plugin);
                     if (!parsed.is_discarded()) {
                         item.raw("data", r.data_json);
                     } else {
                         item.add("data", r.data_json);
                     }
                     item.add("collected_at", r.collected_at);
                     arr.add(item);
                 }
                 res.set_content(list_json(arr.str(), static_cast<int64_t>(records.size())),
                                 "application/json");
             });

    // ── Execution Statistics (capability 1.9) ────────────────────────────

    sink.Get("/api/v1/execution-statistics",
            [perm_fn, execution_tracker](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn(req, res, "Execution", "Read")) return;
                auto summary = execution_tracker->get_fleet_summary();
                auto data = JObj()
                    .add("total_executions", summary.total_executions)
                    .add("executions_today", summary.executions_today)
                    .add("active_agents", summary.active_agents)
                    .add("overall_success_rate", summary.overall_success_rate)
                    .add("avg_duration_seconds", summary.avg_duration_seconds)
                    .str();
                res.set_content(ok_json(data), "application/json");
            });

    sink.Get("/api/v1/execution-statistics/agents",
            [perm_fn, execution_tracker](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn(req, res, "Execution", "Read")) return;
                ExecutionStatsQuery q;
                if (req.has_param("agent_id")) q.agent_id = req.get_param_value("agent_id");
                if (req.has_param("since")) try { q.since = std::stoll(req.get_param_value("since")); } catch (...) {}
                if (req.has_param("limit")) try { q.limit = std::stoi(req.get_param_value("limit")); } catch (...) {}
                if (q.limit > 1000) q.limit = 1000;
                auto stats = execution_tracker->get_agent_statistics(q);
                JArr arr;
                for (const auto& s : stats) {
                    arr.add(JObj()
                        .add("agent_id", s.agent_id)
                        .add("total_executions", s.total_executions)
                        .add("success_count", s.success_count)
                        .add("failure_count", s.failure_count)
                        .add("success_rate", s.success_rate)
                        .add("avg_duration_seconds", s.avg_duration_seconds)
                        .add("last_execution_at", s.last_execution_at));
                }
                res.set_content(list_json(arr.str(), static_cast<int64_t>(stats.size())),
                                "application/json");
            });

    sink.Get("/api/v1/execution-statistics/definitions",
            [perm_fn, execution_tracker](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn(req, res, "Execution", "Read")) return;
                ExecutionStatsQuery q;
                if (req.has_param("definition_id")) q.definition_id = req.get_param_value("definition_id");
                if (req.has_param("since")) try { q.since = std::stoll(req.get_param_value("since")); } catch (...) {}
                if (req.has_param("limit")) try { q.limit = std::stoi(req.get_param_value("limit")); } catch (...) {}
                if (q.limit > 1000) q.limit = 1000;
                auto stats = execution_tracker->get_definition_statistics(q);
                JArr arr;
                for (const auto& s : stats) {
                    arr.add(JObj()
                        .add("definition_id", s.definition_id)
                        .add("total_executions", s.total_executions)
                        .add("total_agents", s.total_agents)
                        .add("success_rate", s.success_rate)
                        .add("avg_duration_seconds", s.avg_duration_seconds));
                }
                res.set_content(list_json(arr.str(), static_cast<int64_t>(stats.size())),
                                "application/json");
            });

    // ── Inventory Evaluation (capability 15.4) ────────────────────────────

    if (inventory_store) {
        sink.Post("/api/v1/inventory/evaluate",
                 [perm_fn, inventory_store](const httplib::Request& req, httplib::Response& res) {
                     if (!perm_fn(req, res, "Inventory", "Read")) return;
                     auto body = nlohmann::json::parse(req.body, nullptr, false);
                     if (body.is_discarded()) {
                         res.status = 400;
                         res.set_content(error_json("invalid JSON"), "application/json");
                         return;
                     }

                     InventoryEvalRequest eval_req;
                     if (body.contains("agent_id")) eval_req.agent_id = body["agent_id"].get<std::string>();
                     if (body.contains("combine")) eval_req.combine = body["combine"].get<std::string>();
                     if (body.contains("conditions") && body["conditions"].is_array()) {
                         for (const auto& c : body["conditions"]) {
                             InventoryCondition cond;
                             if (c.contains("plugin")) cond.plugin = c["plugin"].get<std::string>();
                             if (c.contains("field")) cond.field = c["field"].get<std::string>();
                             if (c.contains("op")) cond.op = c["op"].get<std::string>();
                             if (c.contains("value")) cond.value = c["value"].get<std::string>();
                             eval_req.conditions.push_back(std::move(cond));
                         }
                     }

                     // Fetch inventory records
                     InventoryQuery iq;
                     if (!eval_req.agent_id.empty()) iq.agent_id = eval_req.agent_id;
                     iq.limit = 5000;
                     auto records_raw = inventory_store->query(iq);
                     std::vector<std::pair<std::string, std::string>> records;
                     for (const auto& r : records_raw) {
                         records.emplace_back(r.agent_id + "|" + r.plugin, r.data_json);
                     }

                     auto results = evaluate_inventory(eval_req, records);
                     JArr arr;
                     for (const auto& r : results) {
                         arr.add(JObj()
                             .add("agent_id", r.agent_id)
                             .add("match", r.match)
                             .add("matched_value", r.matched_value)
                             .add("plugin", r.plugin)
                             .add("collected_at", r.collected_at));
                     }
                     res.set_content(list_json(arr.str(), static_cast<int64_t>(results.size())),
                                     "application/json");
                 });
    }

    // ── Device Authorization Tokens (capability 18.8) ─────────────────────

    if (device_token_store) {
        sink.Get("/api/v1/device-tokens",
                [auth_fn, perm_fn, device_token_store](const httplib::Request& req, httplib::Response& res) {
                    if (!perm_fn(req, res, "DeviceToken", "Read")) return;
                    auto session = auth_fn(req, res);
                    if (!session) return;
                    auto tokens = device_token_store->list_tokens();
                    JArr arr;
                    for (const auto& t : tokens) {
                        arr.add(JObj()
                            .add("token_id", t.token_id)
                            .add("name", t.name)
                            .add("principal_id", t.principal_id)
                            .add("device_id", t.device_id)
                            .add("definition_id", t.definition_id)
                            .add("created_at", t.created_at)
                            .add("expires_at", t.expires_at)
                            .add("last_used_at", t.last_used_at)
                            .add("revoked", t.revoked));
                    }
                    res.set_content(list_json(arr.str(), static_cast<int64_t>(tokens.size())),
                                    "application/json");
                });

        sink.Post("/api/v1/device-tokens",
                 [auth_fn, perm_fn, audit_fn, device_token_store](const httplib::Request& req, httplib::Response& res) {
                     auto session = auth_fn(req, res);
                     if (!session) return;
                     if (!perm_fn(req, res, "DeviceToken", "Write")) return;
                     auto body = nlohmann::json::parse(req.body, nullptr, false);
                     if (body.is_discarded()) {
                         res.status = 400;
                         res.set_content(error_json("invalid JSON"), "application/json");
                         return;
                     }
                     auto name = body.value("name", "");
                     auto device_id = body.value("device_id", "");
                     auto definition_id = body.value("definition_id", "");
                     int64_t expires_at = body.value("expires_at", int64_t{0});

                     auto result = device_token_store->create_token(name, session->username,
                                                                     device_id, definition_id, expires_at);
                     if (!result) {
                         res.status = 400;
                         res.set_content(error_json(result.error()), "application/json");
                         return;
                     }
                     audit_fn(req, "device_token.create", "success", "DeviceToken", "", name);
                     res.status = 201;
                     res.set_content(ok_json(JObj().add("raw_token", *result).str()), "application/json");
                 });

        sink.Delete(R"(/api/v1/device-tokens/([a-f0-9]+))",
                   [auth_fn, perm_fn, audit_fn, device_token_store](const httplib::Request& req, httplib::Response& res) {
                       auto session = auth_fn(req, res);
                       if (!session) return;
                       if (!perm_fn(req, res, "DeviceToken", "Delete")) return;
                       auto token_id = req.matches[1].str();
                       if (device_token_store->revoke_token(token_id)) {
                           audit_fn(req, "device_token.revoke", "success", "DeviceToken", token_id, "");
                           res.set_content(ok_json(JObj().add("revoked", true).str()), "application/json");
                       } else {
                           res.status = 404;
                           res.set_content(error_json("token not found"), "application/json");
                       }
                   });
    }

    // ── Software Deployment (capability 7.6) ──────────────────────────────

    if (sw_deploy_store) {
        sink.Get("/api/v1/software-packages",
                [perm_fn, sw_deploy_store](const httplib::Request& req, httplib::Response& res) {
                    if (!perm_fn(req, res, "SoftwareDeployment", "Read")) return;
                    auto pkgs = sw_deploy_store->list_packages();
                    JArr arr;
                    for (const auto& p : pkgs) {
                        arr.add(JObj()
                            .add("id", p.id).add("name", p.name).add("version", p.version)
                            .add("platform", p.platform).add("installer_type", p.installer_type)
                            .add("content_hash", p.content_hash).add("size_bytes", p.size_bytes)
                            .add("created_at", p.created_at).add("created_by", p.created_by));
                    }
                    res.set_content(list_json(arr.str(), static_cast<int64_t>(pkgs.size())),
                                    "application/json");
                });

        sink.Post("/api/v1/software-packages",
                 [auth_fn, perm_fn, audit_fn, sw_deploy_store](const httplib::Request& req, httplib::Response& res) {
                     auto session = auth_fn(req, res);
                     if (!session) return;
                     if (!perm_fn(req, res, "SoftwareDeployment", "Write")) return;
                     auto body = nlohmann::json::parse(req.body, nullptr, false);
                     if (body.is_discarded()) {
                         res.status = 400;
                         res.set_content(error_json("invalid JSON"), "application/json");
                         return;
                     }
                     auto pkg_name = body.value("name", "");
                     auto pkg_version = body.value("version", "");
                     if (pkg_name.empty() || pkg_version.empty()) {
                         res.status = 400;
                         res.set_content(error_json("name and version are required"), "application/json");
                         return;
                     }
                     SoftwarePackage pkg;
                     pkg.name = pkg_name;
                     pkg.version = pkg_version;
                     pkg.platform = body.value("platform", "windows");
                     pkg.installer_type = body.value("installer_type", "msi");
                     pkg.content_hash = body.value("content_hash", "");
                     pkg.content_url = body.value("content_url", "");
                     pkg.silent_args = body.value("silent_args", "");
                     pkg.verify_command = body.value("verify_command", "");
                     pkg.rollback_command = body.value("rollback_command", "");
                     pkg.size_bytes = body.value("size_bytes", int64_t{0});
                     pkg.created_by = session->username;

                     auto result = sw_deploy_store->create_package(pkg);
                     if (!result) {
                         res.status = 400;
                         res.set_content(error_json(result.error()), "application/json");
                         return;
                     }
                     audit_fn(req, "software_package.create", "success", "SoftwarePackage", *result, pkg.name);
                     res.status = 201;
                     res.set_content(ok_json(JObj().add("id", *result).str()), "application/json");
                 });

        sink.Get("/api/v1/software-deployments",
                [perm_fn, sw_deploy_store](const httplib::Request& req, httplib::Response& res) {
                    if (!perm_fn(req, res, "SoftwareDeployment", "Read")) return;
                    auto status = req.has_param("status") ? req.get_param_value("status") : std::string{};
                    auto deps = sw_deploy_store->list_deployments(status);
                    JArr arr;
                    for (const auto& d : deps) {
                        arr.add(JObj()
                            .add("id", d.id).add("package_id", d.package_id)
                            .add("status", d.status).add("created_by", d.created_by)
                            .add("created_at", d.created_at).add("started_at", d.started_at)
                            .add("completed_at", d.completed_at)
                            .add("agents_targeted", static_cast<int64_t>(d.agents_targeted))
                            .add("agents_success", static_cast<int64_t>(d.agents_success))
                            .add("agents_failure", static_cast<int64_t>(d.agents_failure)));
                    }
                    res.set_content(list_json(arr.str(), static_cast<int64_t>(deps.size())),
                                    "application/json");
                });

        sink.Post("/api/v1/software-deployments",
                 [auth_fn, perm_fn, audit_fn, sw_deploy_store](const httplib::Request& req, httplib::Response& res) {
                     auto session = auth_fn(req, res);
                     if (!session) return;
                     if (!perm_fn(req, res, "SoftwareDeployment", "Execute")) return;
                     auto body = nlohmann::json::parse(req.body, nullptr, false);
                     if (body.is_discarded()) {
                         res.status = 400;
                         res.set_content(error_json("invalid JSON"), "application/json");
                         return;
                     }
                     SoftwareDeployment dep;
                     dep.package_id = body.value("package_id", "");
                     dep.scope_expression = body.value("scope_expression", "");
                     dep.created_by = session->username;
                     auto result = sw_deploy_store->create_deployment(dep);
                     if (!result) {
                         res.status = 400;
                         res.set_content(error_json(result.error()), "application/json");
                         return;
                     }
                     audit_fn(req, "software_deployment.create", "success", "SoftwareDeployment", *result, "");
                     res.status = 201;
                     res.set_content(ok_json(JObj().add("id", *result).str()), "application/json");
                 });

        sink.Post(R"(/api/v1/software-deployments/([a-f0-9]+)/start)",
                 [auth_fn, perm_fn, audit_fn, sw_deploy_store](const httplib::Request& req, httplib::Response& res) {
                     auto session = auth_fn(req, res);
                     if (!session) return;
                     if (!perm_fn(req, res, "SoftwareDeployment", "Execute")) return;
                     auto id = req.matches[1].str();
                     if (sw_deploy_store->start_deployment(id)) {
                         audit_fn(req, "software_deployment.start", "success", "SoftwareDeployment", id, "");
                         res.set_content(ok_json(JObj().add("started", true).str()), "application/json");
                     } else {
                         res.status = 400;
                         res.set_content(error_json("cannot start deployment"), "application/json");
                     }
                 });

        sink.Post(R"(/api/v1/software-deployments/([a-f0-9]+)/rollback)",
                 [auth_fn, perm_fn, audit_fn, sw_deploy_store](const httplib::Request& req, httplib::Response& res) {
                     auto session = auth_fn(req, res);
                     if (!session) return;
                     if (!perm_fn(req, res, "SoftwareDeployment", "Execute")) return;
                     auto id = req.matches[1].str();
                     if (sw_deploy_store->rollback_deployment(id)) {
                         audit_fn(req, "software_deployment.rollback", "success", "SoftwareDeployment", id, "");
                         res.set_content(ok_json(JObj().add("rolled_back", true).str()), "application/json");
                     } else {
                         res.status = 400;
                         res.set_content(error_json("cannot rollback deployment"), "application/json");
                     }
                 });

        sink.Post(R"(/api/v1/software-deployments/([a-f0-9]+)/cancel)",
                 [auth_fn, perm_fn, audit_fn, sw_deploy_store](const httplib::Request& req, httplib::Response& res) {
                     auto session = auth_fn(req, res);
                     if (!session) return;
                     if (!perm_fn(req, res, "SoftwareDeployment", "Execute")) return;
                     auto id = req.matches[1].str();
                     if (sw_deploy_store->cancel_deployment(id)) {
                         audit_fn(req, "software_deployment.cancel", "success", "SoftwareDeployment", id, "");
                         res.set_content(ok_json(JObj().add("cancelled", true).str()), "application/json");
                     } else {
                         res.status = 400;
                         res.set_content(error_json("cannot cancel deployment"), "application/json");
                     }
                 });
    }

    // ── License Management (capability 22.3) ──────────────────────────────

    if (license_store) {
        sink.Get("/api/v1/license",
                [perm_fn, license_store](const httplib::Request& req, httplib::Response& res) {
                    if (!perm_fn(req, res, "License", "Read")) return;
                    auto lic = license_store->get_active_license();
                    if (!lic) {
                        res.set_content(ok_json(JObj().add("status", "none").str()), "application/json");
                        return;
                    }
                    auto data = JObj()
                        .add("id", lic->id)
                        .add("organization", lic->organization)
                        .add("seat_count", lic->seat_count)
                        .add("seats_used", lic->seats_used)
                        .add("issued_at", lic->issued_at)
                        .add("expires_at", lic->expires_at)
                        .add("edition", lic->edition)
                        .add("status", lic->status)
                        .add("days_remaining", license_store->days_remaining())
                        .str();
                    res.set_content(ok_json(data), "application/json");
                });

        sink.Post("/api/v1/license",
                 [auth_fn, perm_fn, audit_fn, license_store](const httplib::Request& req, httplib::Response& res) {
                     auto session = auth_fn(req, res);
                     if (!session) return;
                     if (!perm_fn(req, res, "License", "Write")) return;
                     auto body = nlohmann::json::parse(req.body, nullptr, false);
                     if (body.is_discarded()) {
                         res.status = 400;
                         res.set_content(error_json("invalid JSON"), "application/json");
                         return;
                     }
                     License lic;
                     lic.organization = body.value("organization", "");
                     lic.seat_count = body.value("seat_count", int64_t{0});
                     lic.edition = body.value("edition", "community");
                     lic.expires_at = body.value("expires_at", int64_t{0});
                     lic.features_json = body.value("features_json", "[]");
                     auto key = body.value("license_key", "");

                     auto result = license_store->activate_license(lic, key);
                     if (!result) {
                         res.status = 400;
                         res.set_content(error_json(result.error()), "application/json");
                         return;
                     }
                     audit_fn(req, "license.activate", "success", "License", *result, lic.organization);
                     res.status = 201;
                     res.set_content(ok_json(JObj().add("id", *result).str()), "application/json");
                 });

        sink.Delete(R"(/api/v1/license/([a-f0-9]+))",
                   [auth_fn, perm_fn, audit_fn, license_store](const httplib::Request& req, httplib::Response& res) {
                       auto session = auth_fn(req, res);
                       if (!session) return;
                       if (!perm_fn(req, res, "License", "Write")) return;
                       auto id = req.matches[1].str();
                       if (license_store->remove_license(id)) {
                           audit_fn(req, "license.remove", "success", "License", id, "");
                           res.set_content(ok_json(JObj().add("removed", true).str()), "application/json");
                       } else {
                           res.status = 404;
                           res.set_content(error_json("license not found"), "application/json");
                       }
                   });

        sink.Get("/api/v1/license/alerts",
                [perm_fn, license_store](const httplib::Request& req, httplib::Response& res) {
                    if (!perm_fn(req, res, "License", "Read")) return;
                    bool unack = req.has_param("unacknowledged");
                    auto alerts = license_store->list_alerts(unack);
                    JArr arr;
                    for (const auto& a : alerts) {
                        arr.add(JObj()
                            .add("id", a.id)
                            .add("alert_type", a.alert_type)
                            .add("message", a.message)
                            .add("triggered_at", a.triggered_at)
                            .add("acknowledged", a.acknowledged));
                    }
                    res.set_content(list_json(arr.str(), static_cast<int64_t>(alerts.size())),
                                    "application/json");
                });
    }

    // ── Topology (capability 22.2) ─ REST endpoint ────────────────────────

    sink.Get("/api/v1/topology",
            [perm_fn](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn(req, res, "Infrastructure", "Read")) return;
                // Topology data is assembled from in-memory agent registry in server.cpp
                // fragment routes. The REST endpoint returns a placeholder for external callers.
                auto data = JObj()
                    .add("message", "Use /frag/topology-data for HTMX or query individual stores")
                    .str();
                res.set_content(ok_json(data), "application/json");
            });

    // ── Statistics (capability 22.6) ─ REST endpoint ──────────────────────

    sink.Get("/api/v1/statistics",
            [perm_fn, execution_tracker](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn(req, res, "Infrastructure", "Read")) return;
                auto fleet = execution_tracker->get_fleet_summary();
                auto data = JObj()
                    .raw("executions", JObj()
                        .add("total", fleet.total_executions)
                        .add("today", fleet.executions_today)
                        .add("success_rate", fleet.overall_success_rate)
                        .add("avg_duration_seconds", fleet.avg_duration_seconds)
                        .str())
                    .add("active_agents", fleet.active_agents)
                    .str();
                res.set_content(ok_json(data), "application/json");
            });

    // ── File Retrieval (capability 10.13) ────────────────────────────────
    // Receives files uploaded by the content_dist plugin's upload_file action.
    sink.Post("/api/v1/file-retrieval",
            [auth_fn, perm_fn, audit_fn](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn(req, res, "FileRetrieval", "Write")) return;

                // Extract form fields from the request body (JSON)
                auto body = nlohmann::json::parse(req.body, nullptr, false);
                if (body.is_discarded() || !body.contains("agent_id")) {
                    res.status = 400;
                    res.set_content(error_json("invalid request body"), "application/json");
                    return;
                }
                auto agent_id = body.value("agent_id", "");
                auto original_path = body.value("original_path", "");
                auto sha256 = body.value("sha256", "");
                auto file_size = body.value("size", int64_t{0});

                // Store the uploaded file (implementation: write to a configurable
                // retrieval directory, keyed by agent_id and timestamp)
                spdlog::info("FileRetrieval: received {} bytes from agent={}, path={}",
                             file_size, agent_id, original_path);

                audit_fn(req, "file_retrieval.upload", "success", "FileRetrieval", agent_id,
                          "path=" + original_path + ", size=" + std::to_string(file_size));

                auto data = JObj()
                    .add("status", "received")
                    .add("bytes", file_size)
                    .add("agent_id", agent_id)
                    .add("sha256", sha256)
                    .str();
                res.set_content(ok_json(data), "application/json");
            });

    // ── Guardian / Guaranteed State (/api/v1/guaranteed-state) ────────────
    // PR 2 of the Guardian Windows-first rollout. Endpoints follow design
    // doc §9.2. RBAC securable type is "GuaranteedState" with operations
    // Read/Write/Delete/Push (Push is a new op seeded by rbac_store).
    //
    // Re-parsing YAML for the denormalised columns is intentionally NOT
    // done here — yaml-cpp is not a server-side dep. Callers pass severity
    // / os_target / scope_expr alongside yaml_source in the JSON body
    // (matches how `instruction_store` ingests YAML from the dashboard).

    auto iso_now = []() {
        auto now = std::chrono::system_clock::now();
        std::time_t t = std::chrono::system_clock::to_time_t(now);
        std::tm tm{};
#if defined(_WIN32)
        gmtime_s(&tm, &t);
#else
        gmtime_r(&t, &tm);
#endif
        char buf[32];
        std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
        return std::string(buf);
    };

    auto rule_to_jobj = [](const GuaranteedStateRuleRow& r) {
        JObj o;
        o.add("rule_id", r.rule_id)
            .add("name", r.name)
            .add("yaml_source", r.yaml_source)
            .add("version", static_cast<int64_t>(r.version))
            .add("enabled", r.enabled)
            .add("enforcement_mode", r.enforcement_mode)
            .add("severity", r.severity)
            .add("os_target", r.os_target)
            .add("scope_expr", r.scope_expr)
            .add("created_at", r.created_at)
            .add("updated_at", r.updated_at)
            .add("created_by", r.created_by)
            .add("updated_by", r.updated_by);
        return o;
    };

    sink.Get("/api/v1/guaranteed-state/rules",
        [perm_fn, guaranteed_state_store, rule_to_jobj](const httplib::Request& req,
                                                         httplib::Response& res) {
            if (!perm_fn(req, res, "GuaranteedState", "Read")) return;
            if (!guaranteed_state_store) {
                res.status = 503;
                res.set_content(error_json("service unavailable", 503),
                                "application/json");
                return;
            }
            auto rows = guaranteed_state_store->list_rules();
            JArr arr;
            for (const auto& r : rows) arr.add(rule_to_jobj(r));
            res.set_content(list_json(arr.str(), static_cast<int64_t>(rows.size())),
                            "application/json");
        });

    sink.Post("/api/v1/guaranteed-state/rules",
        [auth_fn, perm_fn, audit_fn, guaranteed_state_store, iso_now](
            const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn(req, res, "GuaranteedState", "Write")) return;
            if (!guaranteed_state_store) {
                res.status = 503;
                res.set_content(error_json("service unavailable", 503),
                                "application/json");
                return;
            }
            auto body = nlohmann::json::parse(req.body, nullptr, false);
            if (body.is_discarded() || !body.is_object()) {
                res.status = 400;
                res.set_content(error_json("invalid JSON"), "application/json");
                return;
            }
            GuaranteedStateRuleRow row;
            row.rule_id          = body.value("rule_id", "");
            row.name             = body.value("name", "");
            row.yaml_source      = body.value("yaml_source", "");
            row.version          = body.value("version", int64_t{1});
            row.enabled          = body.value("enabled", true);
            row.enforcement_mode = body.value("enforcement_mode", std::string{"enforce"});
            row.severity         = body.value("severity", std::string{"medium"});
            row.os_target        = body.value("os_target", std::string{""});
            row.scope_expr       = body.value("scope_expr", std::string{""});
            if (row.rule_id.empty() || row.name.empty() || row.yaml_source.empty()) {
                res.status = 400;
                res.set_content(error_json("rule_id, name, and yaml_source are required"),
                                "application/json");
                return;
            }
            auto session = auth_fn(req, res);
            if (session) {
                row.created_by = session->username;
                row.updated_by = session->username;
            }
            row.created_at = iso_now();
            row.updated_at = row.created_at;

            auto result = guaranteed_state_store->create_rule(row);
            if (!result) {
                if (is_conflict_error(result.error())) {
                    res.status = 409;
                    res.set_content(error_json(strip_conflict_prefix(result.error()), 409),
                                    "application/json");
                } else {
                    res.status = 400;
                    res.set_content(error_json(result.error()), "application/json");
                }
                audit_fn(req, "guaranteed_state.rule.create", "denied", "GuaranteedState",
                         row.rule_id, result.error());
                return;
            }
            audit_fn(req, "guaranteed_state.rule.create", "success", "GuaranteedState",
                     row.rule_id, row.name);
            res.status = 201;
            res.set_content(ok_json(JObj().add("rule_id", row.rule_id).str()),
                            "application/json");
        });

    sink.Get(R"(/api/v1/guaranteed-state/rules/([A-Za-z0-9._\-]+))",
        [perm_fn, guaranteed_state_store, rule_to_jobj](const httplib::Request& req,
                                                         httplib::Response& res) {
            if (!perm_fn(req, res, "GuaranteedState", "Read")) return;
            if (!guaranteed_state_store) {
                res.status = 503;
                res.set_content(error_json("service unavailable", 503),
                                "application/json");
                return;
            }
            auto id = req.matches[1].str();
            auto row = guaranteed_state_store->get_rule(id);
            if (!row) {
                res.status = 404;
                res.set_content(error_json("rule not found"), "application/json");
                return;
            }
            res.set_content(ok_json(rule_to_jobj(*row).str()), "application/json");
        });

    sink.Put(R"(/api/v1/guaranteed-state/rules/([A-Za-z0-9._\-]+))",
        [auth_fn, perm_fn, audit_fn, guaranteed_state_store, iso_now](
            const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn(req, res, "GuaranteedState", "Write")) return;
            if (!guaranteed_state_store) {
                res.status = 503;
                res.set_content(error_json("service unavailable", 503),
                                "application/json");
                return;
            }
            auto id = req.matches[1].str();
            auto existing = guaranteed_state_store->get_rule(id);
            if (!existing) {
                res.status = 404;
                res.set_content(error_json("rule not found"), "application/json");
                return;
            }
            auto body = nlohmann::json::parse(req.body, nullptr, false);
            if (body.is_discarded() || !body.is_object()) {
                res.status = 400;
                res.set_content(error_json("invalid JSON"), "application/json");
                // Mirror the /push handler's invalid-body audit (BL-6): a
                // mutating REST path that rejects a malformed body should
                // leave a denied audit trail so SIEM sees the probe/fuzz
                // attempt. Asymmetric audit coverage across sibling branches
                // was flagged as UP-R1 in the Guardian PR 2 governance re-run.
                audit_fn(req, "guaranteed_state.rule.update", "denied",
                         "GuaranteedState", id, "invalid JSON body");
                return;
            }
            auto updated = *existing;
            // Use body.value<T>(k, default) rather than body["k"].get<T>()
            // so a type-mismatched JSON field (e.g. {"enabled": "yes"})
            // falls back to the existing value rather than throwing
            // nlohmann::json::type_error. nlohmann throws from get<T>() on
            // mismatch; without a server-wide set_exception_handler on
            // web_server_ (none installed), httplib's default path returns
            // HTTP 500 with an empty body. That converts a client-error
            // request-shape mistake into a server-error alertable event.
            // Mirrors the POST handler's body.value(...) pattern.
            updated.name             = body.value("name", updated.name);
            updated.yaml_source      = body.value("yaml_source", updated.yaml_source);
            updated.enabled          = body.value("enabled", updated.enabled);
            updated.enforcement_mode = body.value("enforcement_mode", updated.enforcement_mode);
            updated.severity         = body.value("severity", updated.severity);
            updated.os_target        = body.value("os_target", updated.os_target);
            updated.scope_expr       = body.value("scope_expr", updated.scope_expr);
            updated.version = existing->version + 1;
            updated.updated_at = iso_now();
            auto session = auth_fn(req, res);
            if (session) updated.updated_by = session->username;

            auto result = guaranteed_state_store->update_rule(updated);
            if (!result) {
                if (is_conflict_error(result.error())) {
                    res.status = 409;
                    res.set_content(error_json(strip_conflict_prefix(result.error()), 409),
                                    "application/json");
                } else {
                    res.status = 400;
                    res.set_content(error_json(result.error()), "application/json");
                }
                audit_fn(req, "guaranteed_state.rule.update", "denied", "GuaranteedState",
                         id, result.error());
                return;
            }
            audit_fn(req, "guaranteed_state.rule.update", "success", "GuaranteedState",
                     id, updated.name);
            res.set_content(ok_json(JObj().add("updated", true)
                                          .add("version", static_cast<int64_t>(updated.version)).str()),
                            "application/json");
        });

    sink.Delete(R"(/api/v1/guaranteed-state/rules/([A-Za-z0-9._\-]+))",
        [perm_fn, audit_fn, guaranteed_state_store](const httplib::Request& req,
                                                     httplib::Response& res) {
            if (!perm_fn(req, res, "GuaranteedState", "Delete")) return;
            if (!guaranteed_state_store) {
                res.status = 503;
                res.set_content(error_json("service unavailable", 503),
                                "application/json");
                return;
            }
            auto id = req.matches[1].str();
            auto result = guaranteed_state_store->delete_rule(id);
            if (!result) {
                res.status = 404;
                res.set_content(error_json(result.error()), "application/json");
                audit_fn(req, "guaranteed_state.rule.delete", "denied", "GuaranteedState",
                         id, result.error());
                return;
            }
            audit_fn(req, "guaranteed_state.rule.delete", "success", "GuaranteedState",
                     id, "");
            res.set_content(ok_json(JObj().add("deleted", true).str()),
                            "application/json");
        });

    // POST /push — fan-out is wired in PR 3 (agent-side dispatch + scope
    // expansion). PR 2 acks the request and audits the operator action so
    // dashboards and audit-trail tooling can be exercised end-to-end now.
    sink.Post("/api/v1/guaranteed-state/push",
        [perm_fn, audit_fn, guaranteed_state_store](const httplib::Request& req,
                                                     httplib::Response& res) {
            if (!perm_fn(req, res, "GuaranteedState", "Push")) return;
            if (!guaranteed_state_store) {
                res.status = 503;
                res.set_content(error_json("service unavailable", 503),
                                "application/json");
                return;
            }
            auto body = nlohmann::json::parse(req.body, nullptr, false);
            if (body.is_discarded() || (!body.is_null() && !body.is_object())) {
                res.status = 400;
                res.set_content(error_json("invalid JSON"), "application/json");
                audit_fn(req, "guaranteed_state.push", "denied", "GuaranteedState", "",
                         "invalid JSON body");
                return;
            }
            if (body.is_null()) body = nlohmann::json::object();
            std::string scope = body.value("scope", std::string{""});
            bool full_sync = body.value("full_sync", false);
            const auto rule_count = guaranteed_state_store->rule_count();
            // Sanitize scope before embedding in the audit detail: operators
            // with GuaranteedState:Push can otherwise post a scope containing
            // raw quotes, CR/LF, NULs, or pipes, which appear verbatim in the
            // detail string and corrupt SIEM parsers that tokenise on quoted
            // strings or split on newlines (log-injection, SOC 2 audit-trail
            // integrity). Dropping control bytes and backslash-escaping `"`
            // and `\` preserves every printable scope DSL expression while
            // neutering the injection vector. audit_store stores the string
            // as an opaque column, so the sanitization is defensive at the
            // SIEM layer only — but that is the layer SOC 2 Workstream F
            // evidence is reconstructed from.
            auto sanitize_audit_string = [](const std::string& s) {
                std::string out;
                out.reserve(s.size());
                for (char c : s) {
                    if (c == '"' || c == '\\') {
                        out += '\\';
                        out += c;
                    } else if (static_cast<unsigned char>(c) < 0x20 ||
                               static_cast<unsigned char>(c) == 0x7F) {
                        // Drop control bytes (CR/LF/NUL/TAB and all C0/DEL).
                        // Keeping them as escapes would still let an attacker
                        // embed "\\n\\n" to visually split a SIEM view; better
                        // to erase. Non-ASCII UTF-8 (>= 0x80) is preserved.
                    } else {
                        out += c;
                    }
                }
                return out;
            };
            // target_id is reserved for a concrete entity id across every other
            // audit emission in this file (rule_id, agent_id, group_id, token_id).
            // The push scope expression is a fleet-level selector, not an entity
            // id, so emit it in `detail` and leave target_id empty to preserve
            // the SIEM join semantics. Result vocabulary stays "success" (202 is
            // still a success); the PR-2 fan-out-deferral is surfaced in detail.
            audit_fn(req, "guaranteed_state.push", "success", "GuaranteedState", "",
                     "rules=" + std::to_string(rule_count) +
                     " full_sync=" + (full_sync ? "true" : "false") +
                     " scope=\"" + sanitize_audit_string(scope) + "\"" +
                     " fan_out_deferred_pr3=true");
            res.status = 202;
            res.set_content(ok_json(JObj()
                                        .add("queued", true)
                                        .add("rules", static_cast<int64_t>(rule_count))
                                        .add("scope", scope)
                                        .add("note", "push accepted; agent delivery is asynchronous").str()),
                            "application/json");
        });

    // GET /events — query events with optional filters. Mirrors
    // `audit_store` query semantics. Caps `limit` at 1000 at the REST
    // boundary; the store enforces a hard upper bound at kMaxEventsLimit.
    sink.Get("/api/v1/guaranteed-state/events",
        [perm_fn, guaranteed_state_store](const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn(req, res, "GuaranteedState", "Read")) return;
            if (!guaranteed_state_store) {
                res.status = 503;
                res.set_content(error_json("service unavailable", 503),
                                "application/json");
                return;
            }
            GuaranteedStateEventQuery q;
            q.rule_id  = req.has_param("rule_id")  ? req.get_param_value("rule_id")  : "";
            q.agent_id = req.has_param("agent_id") ? req.get_param_value("agent_id") : "";
            q.severity = req.has_param("severity") ? req.get_param_value("severity") : "";
            if (req.has_param("limit")) {
                int v = 0;
                auto s = req.get_param_value("limit");
                auto [_, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
                if (ec != std::errc{} || v < 0) {
                    res.status = 400;
                    res.set_content(error_json("invalid limit"), "application/json");
                    return;
                }
                q.limit = std::min(v, 1000);
            }
            if (req.has_param("offset")) {
                int v = 0;
                auto s = req.get_param_value("offset");
                auto [_, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
                if (ec != std::errc{} || v < 0) {
                    res.status = 400;
                    res.set_content(error_json("invalid offset"), "application/json");
                    return;
                }
                q.offset = v;
            }
            auto rows = guaranteed_state_store->query_events(q);
            JArr arr;
            for (const auto& e : rows) {
                arr.add(JObj()
                            .add("event_id", e.event_id)
                            .add("rule_id", e.rule_id)
                            .add("agent_id", e.agent_id)
                            .add("event_type", e.event_type)
                            .add("severity", e.severity)
                            .add("guard_type", e.guard_type)
                            .add("guard_category", e.guard_category)
                            .add("detected_value", e.detected_value)
                            .add("expected_value", e.expected_value)
                            .add("remediation_action", e.remediation_action)
                            .add("remediation_success", e.remediation_success)
                            .add("detection_latency_us",
                                 static_cast<int64_t>(e.detection_latency_us))
                            .add("remediation_latency_us",
                                 static_cast<int64_t>(e.remediation_latency_us))
                            .add("timestamp", e.timestamp));
            }
            res.set_content(list_json(arr.str(), static_cast<int64_t>(rows.size()),
                                      static_cast<int64_t>(q.offset)),
                            "application/json");
        });

    // GET /status, /status/:agent_id, /alerts — placeholders that respond
    // with empty rollups for PR 2. Real fleet aggregation arrives in PR 4
    // (status) and PR 11 (alerts). Returning empty structures now keeps
    // dashboard fragments and audit tooling exercisable against the API.
    // Field names match the agent-side proto `GuaranteedStateStatus`
    // (compliant_rules / drifted_rules / errored_rules) so REST and proto
    // schemas do not diverge when PR 4 wires real aggregation.
    sink.Get("/api/v1/guaranteed-state/status",
        [perm_fn, guaranteed_state_store](const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn(req, res, "GuaranteedState", "Read")) return;
            const auto rules = guaranteed_state_store ? guaranteed_state_store->rule_count() : 0;
            res.set_content(ok_json(JObj()
                                        .add("total_rules", static_cast<int64_t>(rules))
                                        .add("compliant_rules", 0)
                                        .add("drifted_rules", 0)
                                        .add("errored_rules", 0)
                                        .add("note", "fleet aggregation lands in Guardian PR 4")
                                        .str()),
                            "application/json");
        });

    sink.Get(R"(/api/v1/guaranteed-state/status/([A-Za-z0-9._\-]+))",
        [perm_fn](const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn(req, res, "GuaranteedState", "Read")) return;
            auto agent_id = req.matches[1].str();
            res.set_content(ok_json(JObj()
                                        .add("agent_id", agent_id)
                                        .add("total_rules", 0)
                                        .add("compliant_rules", 0)
                                        .add("drifted_rules", 0)
                                        .add("errored_rules", 0)
                                        .add("note", "per-agent status lands in Guardian PR 4")
                                        .str()),
                            "application/json");
        });

    sink.Get("/api/v1/guaranteed-state/alerts",
        [perm_fn](const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn(req, res, "GuaranteedState", "Read")) return;
            res.set_content(list_json("[]", 0), "application/json");
        });

    spdlog::info("REST API v1: registered all routes at /api/v1/*");
}

} // namespace yuzu::server
