#include "rest_api_v1.hpp"
#include "rest_api_v1_helpers.hpp"

#include "rbac_store.hpp"

#include <spdlog/spdlog.h>

#include <string>

namespace yuzu::server {

// ── Domain registration functions (defined in separate TUs) ─────────────────

void register_group_routes(httplib::Server& svr, RestApiV1::AuthFn auth_fn,
                           RestApiV1::PermFn perm_fn, RestApiV1::AuditFn audit_fn,
                           ManagementGroupStore* mgmt_store, RbacStore* rbac_store);

void register_security_routes(httplib::Server& svr, RestApiV1::AuthFn auth_fn,
                              RestApiV1::PermFn perm_fn, RestApiV1::AuditFn audit_fn,
                              ApiTokenStore* token_store, QuarantineStore* quarantine_store,
                              RbacStore* rbac_store, ManagementGroupStore* mgmt_store,
                              TagStore* tag_store);

void register_data_routes(httplib::Server& svr, RestApiV1::AuthFn auth_fn,
                          RestApiV1::PermFn perm_fn, RestApiV1::AuditFn audit_fn,
                          TagStore* tag_store, InstructionStore* instruction_store,
                          AuditStore* audit_store, InventoryStore* inventory_store,
                          RestApiV1::ServiceGroupFn service_group_fn,
                          RestApiV1::TagPushFn tag_push_fn);

// ── CORS helpers ────────────────────────────────────────────────────────────

void add_cors_headers(httplib::Response& res, const httplib::Request& req) {
    auto origin = req.get_header_value("Origin");
    if (!origin.empty()) {
        res.set_header("Access-Control-Allow-Origin", origin);
        res.set_header("Access-Control-Allow-Credentials", "true");
    }
    res.set_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    res.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Yuzu-Token");
    res.set_header("Access-Control-Max-Age", "86400");
}

// ── JSON envelope helpers ────────────────────────────────────────────────────

nlohmann::json ok_response(const nlohmann::json& data) {
    return {{"data", data}, {"meta", {{"api_version", "v1"}}}};
}

nlohmann::json error_response(const std::string& message, int code) {
    nlohmann::json j = {{"error", message}, {"meta", {{"api_version", "v1"}}}};
    if (code != 0)
        j["code"] = code;
    return j;
}

nlohmann::json list_response(const nlohmann::json& data, int64_t total, int64_t start,
                             int64_t page_size) {
    return {{"data", data},
            {"pagination", {{"total", total}, {"start", start}, {"page_size", page_size}}},
            {"meta", {{"api_version", "v1"}}}};
}

// ── OpenAPI 3.0 spec ────────────────────────────────────────────────────────
// Returned as a pre-built raw JSON string to avoid the massive nlohmann::json
// nested initializer_list template instantiation that was consuming ~56 GB of
// compiler memory.

static std::string generate_openapi_spec() {
    static const std::string spec =
        R"openapi({
  "openapi": "3.0.3",
  "info": {
    "title": "Yuzu Server REST API",
    "version": "1.0.0",
    "description": "Enterprise endpoint management REST API. All endpoints require authentication via session cookie, Bearer token, or X-Yuzu-Token header.",
    "contact": {"name": "Yuzu Project"},
    "license": {"name": "Apache-2.0"}
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
          "pagination": {"type": "object", "properties": {"total": {"type": "integer"}, "start": {"type": "integer"}, "page_size": {"type": "integer"}}}
        }
      },
      "ManagementGroup": {
        "type": "object",
        "properties": {
          "id": {"type": "string"}, "name": {"type": "string"}, "description": {"type": "string"},
          "parent_id": {"type": "string"}, "membership_type": {"type": "string", "enum": ["static", "dynamic"]},
          "scope_expression": {"type": "string"}, "created_by": {"type": "string"},
          "created_at": {"type": "integer"}, "updated_at": {"type": "integer"}
        }
      },
      "ApiToken": {
        "type": "object",
        "properties": {
          "token_id": {"type": "string"}, "name": {"type": "string"}, "principal_id": {"type": "string"},
          "created_at": {"type": "integer"}, "expires_at": {"type": "integer"},
          "last_used_at": {"type": "integer"}, "revoked": {"type": "boolean"}
        }
      },
      "Tag": {
        "type": "object",
        "properties": {"agent_id": {"type": "string"}, "key": {"type": "string"}, "value": {"type": "string"}}
      },
      "AuditEvent": {
        "type": "object",
        "properties": {
          "timestamp": {"type": "integer"}, "principal": {"type": "string"}, "action": {"type": "string"},
          "result": {"type": "string"}, "target_type": {"type": "string"},
          "target_id": {"type": "string"}, "detail": {"type": "string"}
        }
      },
      "InventoryRecord": {
        "type": "object",
        "properties": {
          "agent_id": {"type": "string"}, "plugin": {"type": "string"},
          "data_json": {"type": "string", "description": "Structured JSON blob from the plugin"},
          "collected_at": {"type": "integer"}
        }
      },
      "InventoryTable": {
        "type": "object",
        "properties": {"plugin": {"type": "string"}, "agent_count": {"type": "integer"}, "last_collected": {"type": "integer"}}
      },
      "ProductPack": {
        "type": "object",
        "properties": {
          "id": {"type": "string"}, "name": {"type": "string"}, "version": {"type": "string"},
          "description": {"type": "string"}, "installed_at": {"type": "integer"},
          "verified": {"type": "boolean", "description": "Whether the pack signature was verified"}
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
    }
  }
})openapi";
    return spec;
}

// ── Route registration ───────────────────────────────────────────────────────

void RestApiV1::register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn,
                                AuditFn audit_fn, RbacStore* rbac_store,
                                ManagementGroupStore* mgmt_store, ApiTokenStore* token_store,
                                QuarantineStore* quarantine_store, ResponseStore* /*response_store*/,
                                InstructionStore* instruction_store,
                                ExecutionTracker* /*execution_tracker*/,
                                ScheduleEngine* /*schedule_engine*/,
                                ApprovalManager* /*approval_manager*/,
                                TagStore* tag_store, AuditStore* audit_store,
                                ServiceGroupFn service_group_fn, TagPushFn tag_push_fn,
                                InventoryStore* inventory_store,
                                ProductPackStore* /*product_pack_store*/) {

    spdlog::info("REST API v1: registering routes");

    // ── CORS preflight handler for /api/v1/* ─────────────────────────────
    svr.Options(R"(/api/v1/.*)", [](const httplib::Request& req, httplib::Response& res) {
        add_cors_headers(res, req);
        res.status = 204;
    });

    // ── OpenAPI spec endpoint (/api/v1/openapi.json) ─────────────────────
    svr.Get("/api/v1/openapi.json", [](const httplib::Request& req, httplib::Response& res) {
        add_cors_headers(res, req);
        res.set_content(generate_openapi_spec(), "application/json");
    });

    // ── /api/v1/me ───────────────────────────────────────────────────────
    svr.Get("/api/v1/me", [auth_fn, rbac_store](const httplib::Request& req, httplib::Response& res) {
        auto session = auth_fn(req, res);
        if (!session)
            return;
        auto data = nlohmann::json({{"username", session->username},
                                     {"role", auth::role_to_string(session->role)}});
        if (rbac_store && rbac_store->is_rbac_enabled()) {
            data["rbac_enabled"] = true;
            auto roles = rbac_store->get_principal_roles("user", session->username);
            if (!roles.empty()) {
                data["rbac_role"] = roles[0].role_name;
            } else {
                data["rbac_role"] = session->role == auth::Role::admin ? "Administrator" : "Viewer";
            }
        } else {
            data["rbac_enabled"] = false;
            data["rbac_role"] = session->role == auth::Role::admin ? "Administrator" : "Viewer";
        }
        res.set_content(ok_response(data).dump(), "application/json");
    });

    // ── Delegate to domain files ─────────────────────────────────────────
    register_group_routes(svr, auth_fn, perm_fn, audit_fn, mgmt_store, rbac_store);
    register_security_routes(svr, auth_fn, perm_fn, audit_fn, token_store, quarantine_store,
                             rbac_store, mgmt_store, tag_store);
    register_data_routes(svr, auth_fn, perm_fn, audit_fn, tag_store, instruction_store,
                         audit_store, inventory_store, service_group_fn, tag_push_fn);

    spdlog::info("REST API v1: registered all routes at /api/v1/*");
}

} // namespace yuzu::server
