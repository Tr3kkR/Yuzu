/**
 * test_mcp_server.cpp — Unit + integration tests for MCP (Model Context Protocol) server
 *
 * Unit tests cover: JSON-RPC parsing, MCP tier policy, MCP tool dispatch,
 * MCP token integration with ApiTokenStore, audit trail for MCP operations.
 *
 * Integration tests (bottom of file) cover: full HTTP dispatch through McpServer
 * with an httplib::Server on a random port, mock callbacks, real HTTP POST
 * requests with JSON-RPC payloads, and response verification.  Addresses
 * CRITICAL C6: "No integration test through HTTP dispatch."
 */

#include "mcp_jsonrpc.hpp"
#include "mcp_policy.hpp"

#include "api_token_store.hpp"
#include "audit_store.hpp"
#include "instruction_store.hpp"
#include "response_store.hpp"
#include "scope_engine.hpp"
#include "tag_store.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <filesystem>
#include <set>
#include <string>
#include <unordered_map>

using namespace yuzu::server::mcp;
using namespace yuzu::server;

// ── JSON-RPC 2.0 parsing ─────────────────────────────────────────────────

TEST_CASE("MCP JSON-RPC: parse valid request", "[mcp][jsonrpc]") {
    auto result = parse_request(R"({"jsonrpc":"2.0","method":"initialize","id":1})");
    REQUIRE(result.has_value());
    CHECK(result->method == "initialize");
    CHECK(result->id.has_value());
    CHECK(result->id->get<int>() == 1);
}

TEST_CASE("MCP JSON-RPC: parse request with params", "[mcp][jsonrpc]") {
    auto result = parse_request(
        R"({"jsonrpc":"2.0","method":"tools/call","params":{"name":"list_agents"},"id":"abc"})");
    REQUIRE(result.has_value());
    CHECK(result->method == "tools/call");
    CHECK(result->params.contains("name"));
    CHECK(result->params["name"] == "list_agents");
}

TEST_CASE("MCP JSON-RPC: parse notification (no id)", "[mcp][jsonrpc]") {
    auto result = parse_request(R"({"jsonrpc":"2.0","method":"notifications/initialized"})");
    REQUIRE(result.has_value());
    CHECK(result->method == "notifications/initialized");
    CHECK(!result->id.has_value());
}

TEST_CASE("MCP JSON-RPC: reject invalid JSON", "[mcp][jsonrpc]") {
    auto result = parse_request("{not valid json");
    REQUIRE(!result.has_value());
    CHECK(result.error().find("Parse error") != std::string::npos);
}

TEST_CASE("MCP JSON-RPC: reject missing jsonrpc field", "[mcp][jsonrpc]") {
    auto result = parse_request(R"({"method":"ping","id":1})");
    REQUIRE(!result.has_value());
    CHECK(result.error().find("jsonrpc") != std::string::npos);
}

TEST_CASE("MCP JSON-RPC: reject wrong jsonrpc version", "[mcp][jsonrpc]") {
    auto result = parse_request(R"({"jsonrpc":"1.0","method":"ping","id":1})");
    REQUIRE(!result.has_value());
}

TEST_CASE("MCP JSON-RPC: reject missing method", "[mcp][jsonrpc]") {
    auto result = parse_request(R"({"jsonrpc":"2.0","id":1})");
    REQUIRE(!result.has_value());
    CHECK(result.error().find("method") != std::string::npos);
}

TEST_CASE("MCP JSON-RPC: success response format", "[mcp][jsonrpc]") {
    nlohmann::json id = 42;
    auto resp = success_response(id, R"({"status":"ok"})");
    auto parsed = nlohmann::json::parse(resp);
    CHECK(parsed["jsonrpc"] == "2.0");
    CHECK(parsed["id"] == 42);
    CHECK(parsed["result"]["status"] == "ok");
    CHECK(!parsed.contains("error"));
}

TEST_CASE("MCP JSON-RPC: error response format", "[mcp][jsonrpc]") {
    nlohmann::json id = "req-1";
    auto resp = error_response(id, kMethodNotFound, "Unknown method");
    auto parsed = nlohmann::json::parse(resp);
    CHECK(parsed["jsonrpc"] == "2.0");
    CHECK(parsed["id"] == "req-1");
    CHECK(parsed["error"]["code"] == kMethodNotFound);
    CHECK(parsed["error"]["message"] == "Unknown method");
    CHECK(!parsed.contains("result"));
}

TEST_CASE("MCP JSON-RPC: error response with data", "[mcp][jsonrpc]") {
    nlohmann::json id = 1;
    auto resp = error_response(id, kInvalidParams, "bad param", R"({"field":"name"})");
    auto parsed = nlohmann::json::parse(resp);
    CHECK(parsed["error"]["data"]["field"] == "name");
}

TEST_CASE("MCP JSON-RPC: null id error response", "[mcp][jsonrpc]") {
    auto resp = error_response_null(kParseError, "Parse error");
    auto parsed = nlohmann::json::parse(resp);
    CHECK(parsed["id"].is_null());
    CHECK(parsed["error"]["code"] == kParseError);
}

// ── MCP tier policy ───────────────────────────────────────────────────────

TEST_CASE("MCP Policy: empty tier allows everything", "[mcp][policy]") {
    CHECK(tier_allows("", "Infrastructure", "Read"));
    CHECK(tier_allows("", "Execution", "Execute"));
    CHECK(tier_allows("", "Policy", "Delete"));
}

TEST_CASE("MCP Policy: readonly tier allows only Read", "[mcp][policy]") {
    CHECK(tier_allows("readonly", "Infrastructure", "Read"));
    CHECK(tier_allows("readonly", "AuditLog", "Read"));
    CHECK(tier_allows("readonly", "Tag", "Read"));
    CHECK(tier_allows("readonly", "Policy", "Read"));

    CHECK(!tier_allows("readonly", "Tag", "Write"));
    CHECK(!tier_allows("readonly", "Execution", "Execute"));
    CHECK(!tier_allows("readonly", "Infrastructure", "Delete"));
    CHECK(!tier_allows("readonly", "Policy", "Write"));
}

TEST_CASE("MCP Policy: operator tier allows Read + Tag Write + Execute", "[mcp][policy]") {
    // Read on everything
    CHECK(tier_allows("operator", "Infrastructure", "Read"));
    CHECK(tier_allows("operator", "AuditLog", "Read"));

    // Tag Write/Delete
    CHECK(tier_allows("operator", "Tag", "Write"));
    CHECK(tier_allows("operator", "Tag", "Delete"));

    // Execution
    CHECK(tier_allows("operator", "Execution", "Execute"));

    // But NOT policy write, user management, etc.
    CHECK(!tier_allows("operator", "Policy", "Write"));
    CHECK(!tier_allows("operator", "UserManagement", "Write"));
    CHECK(!tier_allows("operator", "Security", "Write"));
    CHECK(!tier_allows("operator", "ManagementGroup", "Write"));
}

TEST_CASE("MCP Policy: supervised tier allows everything", "[mcp][policy]") {
    CHECK(tier_allows("supervised", "Infrastructure", "Read"));
    CHECK(tier_allows("supervised", "Execution", "Execute"));
    CHECK(tier_allows("supervised", "Policy", "Write"));
    CHECK(tier_allows("supervised", "Policy", "Delete"));
    CHECK(tier_allows("supervised", "UserManagement", "Write"));
    CHECK(tier_allows("supervised", "Security", "Write"));
}

TEST_CASE("MCP Policy: unknown tier denies everything", "[mcp][policy]") {
    CHECK(!tier_allows("bogus", "Infrastructure", "Read"));
    CHECK(!tier_allows("bogus", "Tag", "Write"));
}

TEST_CASE("MCP Policy: readonly never requires approval", "[mcp][policy]") {
    CHECK(!requires_approval("readonly", "Infrastructure", "Read"));
    CHECK(!requires_approval("readonly", "Execution", "Execute"));
}

TEST_CASE("MCP Policy: operator auto-approves Execute, requires approval for Tag Delete", "[mcp][policy]") {
    CHECK(!requires_approval("operator", "Execution", "Execute")); // auto-approved
    CHECK(requires_approval("operator", "Tag", "Delete"));
    CHECK(!requires_approval("operator", "Tag", "Write"));
    CHECK(!requires_approval("operator", "Infrastructure", "Read"));
}

TEST_CASE("MCP Policy: supervised requires approval for destructive ops", "[mcp][policy]") {
    CHECK(requires_approval("supervised", "Execution", "Execute"));
    CHECK(requires_approval("supervised", "Policy", "Write"));
    CHECK(requires_approval("supervised", "Security", "Write"));
    CHECK(requires_approval("supervised", "UserManagement", "Write"));
    CHECK(requires_approval("supervised", "ManagementGroup", "Write"));

    // Delete on any type
    CHECK(requires_approval("supervised", "Tag", "Delete"));
    CHECK(requires_approval("supervised", "Policy", "Delete"));
    CHECK(requires_approval("supervised", "Infrastructure", "Delete"));

    // Read does not require approval
    CHECK(!requires_approval("supervised", "Infrastructure", "Read"));
    CHECK(!requires_approval("supervised", "AuditLog", "Read"));
}

TEST_CASE("MCP Policy: is_valid_tier", "[mcp][policy]") {
    CHECK(is_valid_tier(""));
    CHECK(is_valid_tier("readonly"));
    CHECK(is_valid_tier("operator"));
    CHECK(is_valid_tier("supervised"));
    CHECK(!is_valid_tier("admin"));
    CHECK(!is_valid_tier("root"));
}

// ── MCP token integration with ApiTokenStore ──────────────────────────────

namespace {

struct TempDb {
    std::filesystem::path path;
    TempDb() : path(std::filesystem::temp_directory_path() / "test_mcp_tokens.db") {
        std::filesystem::remove(path);
    }
    ~TempDb() { std::filesystem::remove(path); }
};

int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

} // namespace

TEST_CASE("MCP Token: create MCP token with tier", "[mcp][token]") {
    TempDb tmp;
    ApiTokenStore store(tmp.path);
    REQUIRE(store.is_open());

    auto expires = now_epoch() + 86400; // 24 hours
    auto raw = store.create_token("MCP Readonly", "admin", expires, "", "readonly");
    REQUIRE(raw.has_value());

    auto validated = store.validate_token(*raw);
    REQUIRE(validated.has_value());
    CHECK(validated->name == "MCP Readonly");
    CHECK(validated->mcp_tier == "readonly");
}

TEST_CASE("MCP Token: MCP token requires expiration", "[mcp][token]") {
    TempDb tmp;
    ApiTokenStore store(tmp.path);
    REQUIRE(store.is_open());

    // MCP token with no expiration should be rejected
    auto raw = store.create_token("No Expiry MCP", "admin", 0, "", "operator");
    CHECK(!raw.has_value());
}

TEST_CASE("MCP Token: regular token has empty mcp_tier", "[mcp][token]") {
    TempDb tmp;
    ApiTokenStore store(tmp.path);
    REQUIRE(store.is_open());

    auto raw = store.create_token("Regular Token", "admin");
    REQUIRE(raw.has_value());

    auto validated = store.validate_token(*raw);
    REQUIRE(validated.has_value());
    CHECK(validated->mcp_tier.empty());
}

TEST_CASE("MCP Token: list includes mcp_tier", "[mcp][token]") {
    TempDb tmp;
    ApiTokenStore store(tmp.path);
    REQUIRE(store.is_open());

    auto expires = now_epoch() + 86400;
    store.create_token("Regular", "admin");
    store.create_token("MCP Read", "admin", expires, "", "readonly");
    store.create_token("MCP Supervised", "admin", expires, "", "supervised");

    auto tokens = store.list_tokens();
    REQUIRE(tokens.size() == 3);

    int mcp_count = 0;
    for (const auto& t : tokens) {
        if (!t.mcp_tier.empty()) ++mcp_count;
    }
    CHECK(mcp_count == 2);
}

TEST_CASE("MCP Token: 90-day max TTL enforced", "[mcp][token]") {
    TempDb tmp;
    ApiTokenStore store(tmp.path);
    REQUIRE(store.is_open());

    // 91 days from now should be rejected
    auto expires_91d = now_epoch() + 91 * 24 * 3600;
    auto raw = store.create_token("Too Long MCP", "admin", expires_91d, "", "readonly");
    CHECK(!raw.has_value());
    CHECK(raw.error().find("90 days") != std::string::npos);

    // 89 days from now should be accepted
    auto expires_89d = now_epoch() + 89 * 24 * 3600;
    auto raw_ok = store.create_token("OK MCP", "admin", expires_89d, "", "readonly");
    CHECK(raw_ok.has_value());
}

// ── MCP audit event field ─────────────────────────────────────────────────

TEST_CASE("MCP Audit: mcp_tool field on AuditEvent", "[mcp][audit]") {
    AuditEvent evt;
    evt.principal = "admin";
    evt.action = "mcp.list_agents";
    evt.mcp_tool = "list_agents";
    evt.result = "success";

    CHECK(evt.mcp_tool == "list_agents");
    CHECK(evt.action == "mcp.list_agents");
}

// ── Scope engine integration (used by validate_scope tool) ────────────────

TEST_CASE("MCP ScopeValidation: valid expression accepted", "[mcp][scope]") {
    auto result = yuzu::scope::validate(R"(os == "linux")");
    CHECK(result.has_value());
}

TEST_CASE("MCP ScopeValidation: invalid expression rejected", "[mcp][scope]") {
    auto result = yuzu::scope::validate("os ==== broken");
    CHECK(!result.has_value());
}

TEST_CASE("MCP ScopeValidation: complex expression", "[mcp][scope]") {
    auto result = yuzu::scope::validate(
        R"(os == "windows" AND arch == "x64" AND NOT hostname LIKE "test-*")");
    CHECK(result.has_value());
}

// ── JSON-RPC error code constants ─────────────────────────────────────────

TEST_CASE("MCP error codes are in valid JSON-RPC range", "[mcp][jsonrpc]") {
    // Standard JSON-RPC errors: -32700 to -32600
    CHECK(kParseError == -32700);
    CHECK(kInvalidRequest == -32600);
    CHECK(kMethodNotFound == -32601);
    CHECK(kInvalidParams == -32602);
    CHECK(kInternalError == -32603);

    // Application-defined errors: -32000 to -32099
    CHECK(kPermissionDenied < 0);
    CHECK(kTierDenied < 0);
    CHECK(kMcpDisabled < 0);
    CHECK(kApprovalRequired < 0);
}

// ── JSON-RPC escaping edge cases ──────────────────────────────────────────

TEST_CASE("MCP JSON-RPC: special characters in error message", "[mcp][jsonrpc]") {
    nlohmann::json id = 1;
    auto resp = error_response(id, kInternalError, "Error with \"quotes\" and \\backslash");
    auto parsed = nlohmann::json::parse(resp);
    CHECK(parsed["error"]["message"] == "Error with \"quotes\" and \\backslash");
}

TEST_CASE("MCP JSON-RPC: unicode control chars escaped", "[mcp][jsonrpc]") {
    nlohmann::json id = 1;
    std::string msg = "tab\there\nnewline";
    auto resp = error_response(id, kInternalError, msg);
    // Should parse without error — control chars must be escaped
    auto parsed = nlohmann::json::parse(resp);
    CHECK(parsed["error"]["message"] == msg);
}

// ── Tag store integration (used by get_tags / search_agents_by_tag) ───────

TEST_CASE("MCP TagStore: get_all_tags and agents_with_tag", "[mcp][tag]") {
    TagStore store(":memory:");
    REQUIRE(store.is_open());

    store.set_tag("agent-1", "env", "prod", "server");
    store.set_tag("agent-1", "role", "web", "server");
    store.set_tag("agent-2", "env", "prod", "server");
    store.set_tag("agent-3", "env", "staging", "server");

    // get_all_tags
    auto tags = store.get_all_tags("agent-1");
    CHECK(tags.size() == 2);

    // agents_with_tag (key only)
    auto prod_agents = store.agents_with_tag("env");
    CHECK(prod_agents.size() >= 2);

    // agents_with_tag (key + value)
    auto staging_agents = store.agents_with_tag("env", "staging");
    CHECK(staging_agents.size() == 1);
    CHECK(staging_agents[0] == "agent-3");
}

// ── Response store integration (used by query_responses) ──────────────────

TEST_CASE("MCP ResponseStore: query with filters", "[mcp][response]") {
    ResponseStore store(":memory:");
    REQUIRE(store.is_open());

    StoredResponse r1;
    r1.instruction_id = "instr-1";
    r1.agent_id = "agent-1";
    r1.status = 0; // success
    r1.output = "OK";
    store.store(r1);

    StoredResponse r2;
    r2.instruction_id = "instr-1";
    r2.agent_id = "agent-2";
    r2.status = 1; // failure
    r2.output = "Error";
    store.store(r2);

    // Query all for instruction
    ResponseQuery rq;
    auto results = store.query("instr-1", rq);
    CHECK(results.size() == 2);

    // Query filtered by agent
    rq.agent_id = "agent-1";
    results = store.query("instr-1", rq);
    CHECK(results.size() == 1);
    CHECK(results[0].agent_id == "agent-1");
}

// ── Instruction store integration (used by list_definitions) ──────────────

TEST_CASE("MCP InstructionStore: query definitions", "[mcp][instruction]") {
    InstructionStore store(":memory:");
    REQUIRE(store.is_open());

    InstructionDefinition def;
    def.id = "test.ping";
    def.name = "Ping";
    def.version = "1.0.0";
    def.type = "question";
    def.plugin = "example";
    def.action = "ping";
    def.description = "Test ping";
    def.yaml_source = "apiVersion: yuzu.io/v1alpha1\nkind: InstructionDefinition\n";
    store.create_definition(def);

    InstructionQuery iq;
    auto defs = store.query_definitions(iq);
    CHECK(defs.size() >= 1);

    auto found = store.get_definition("test.ping");
    REQUIRE(found.has_value());
    CHECK(found->plugin == "example");
    CHECK(found->action == "ping");
}

// ── Audit store integration (used by query_audit_log) ─────────────────────

TEST_CASE("MCP AuditStore: query with mcp_tool field", "[mcp][audit]") {
    AuditStore store(":memory:");
    REQUIRE(store.is_open());

    AuditEvent evt;
    evt.principal = "mcp-admin";
    evt.action = "mcp.list_agents";
    evt.target_type = "mcp_tool";
    evt.target_id = "list_agents";
    evt.result = "success";
    evt.mcp_tool = "list_agents";
    store.log(evt);

    AuditQuery aq;
    aq.principal = "mcp-admin";
    auto events = store.query(aq);
    REQUIRE(events.size() >= 1);
    CHECK(events[0].action == "mcp.list_agents");
}

// ═══════════════════════════════════════════════════════════════════════════
// Integration tests — full HTTP dispatch through McpServer
//
// Addresses CRITICAL C6: "No integration test through HTTP dispatch —
// 0 of 23 tools tested end-to-end."
//
// Each test starts an httplib::Server on a random port, registers MCP routes
// with mock callbacks, sends actual HTTP POST requests with JSON-RPC payloads,
// and verifies the responses.
// ═══════════════════════════════════════════════════════════════════════════

#include "mcp_server.hpp"

#include <httplib.h>

#include <atomic>
#include <thread>
#include <vector>

namespace {

/// RAII test fixture that starts an httplib::Server with MCP routes and
/// mock callbacks.  Automatically stops the server on destruction.
struct McpTestServer {
    httplib::Server svr;
    std::thread server_thread;
    int port{0};

    // Mock state
    std::string mock_tier;           // MCP tier for mock auth
    bool mock_auth_enabled{true};    // false -> auth_fn returns nullopt (401)
    std::vector<std::string> audit_log; // records "action|result" pairs
    bool read_only_mode_{false};     // Must outlive register_routes (captured by ref)
    bool mcp_disabled_{false};       // Must outlive register_routes (captured by ref)

    // Dispatch mock state — captured args from last dispatch call
    std::string last_dispatch_plugin;
    std::string last_dispatch_action;
    std::vector<std::string> last_dispatch_agent_ids;
    std::string last_dispatch_scope;
    std::unordered_map<std::string, std::string> last_dispatch_params;

    yuzu::server::mcp::McpServer mcp;

    void start(const std::string& tier = "") {
        mock_tier = tier;

        // Mock auth: returns a session with the configured tier (or nullopt)
        auto auth_fn = [this](const httplib::Request& /*req*/,
                              httplib::Response& res)
            -> std::optional<yuzu::server::auth::Session> {
            if (!mock_auth_enabled) {
                res.status = 401;
                res.set_content(R"({"error":"unauthorized"})", "application/json");
                return std::nullopt;
            }
            yuzu::server::auth::Session s;
            s.username = "test-user";
            s.role = yuzu::server::auth::Role::admin;
            s.mcp_tier = mock_tier;
            return s;
        };

        // Mock permission: always allow
        auto perm_fn = [](const httplib::Request&, httplib::Response&,
                          const std::string& /*securable_type*/,
                          const std::string& /*operation*/) -> bool {
            return true;
        };

        // Mock audit: record calls
        auto audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string& /*target_type*/,
                               const std::string& /*target_id*/,
                               const std::string& /*detail*/) {
            audit_log.push_back(action + "|" + result);
        };

        // Mock agents: return two test agents
        auto agents_fn = []() -> nlohmann::json {
            return nlohmann::json::array({
                {{"agent_id", "agent-001"}, {"hostname", "web-01"}, {"os", "linux"},
                 {"arch", "x64"}, {"agent_version", "0.1.3"}},
                {{"agent_id", "agent-002"}, {"hostname", "db-01"}, {"os", "windows"},
                 {"arch", "x64"}, {"agent_version", "0.1.3"}}
            });
        };

        // Register routes with nullptr for stores we don't need in basic tests
        mcp.register_routes(svr, auth_fn, perm_fn, audit_fn, agents_fn,
                            /*rbac_store=*/nullptr,
                            /*instruction_store=*/nullptr,
                            /*execution_tracker=*/nullptr,
                            /*response_store=*/nullptr,
                            /*audit_store=*/nullptr,
                            /*tag_store=*/nullptr,
                            /*inventory_store=*/nullptr,
                            /*policy_store=*/nullptr,
                            /*mgmt_store=*/nullptr,
                            /*approval_manager=*/nullptr,
                            /*schedule_engine=*/nullptr,
                            read_only_mode_,
                            mcp_disabled_);

        bind_and_listen();
    }

    /// Start with a dispatch function (for execute_instruction tests).
    void start_with_dispatch(yuzu::server::mcp::McpServer::DispatchFn dispatch_fn,
                             const std::string& tier = "") {
        mock_tier = tier;

        auto auth_fn = [this](const httplib::Request& /*req*/,
                              httplib::Response& res)
            -> std::optional<yuzu::server::auth::Session> {
            if (!mock_auth_enabled) {
                res.status = 401;
                res.set_content(R"({"error":"unauthorized"})", "application/json");
                return std::nullopt;
            }
            yuzu::server::auth::Session s;
            s.username = "test-user";
            s.role = yuzu::server::auth::Role::admin;
            s.mcp_tier = mock_tier;
            return s;
        };

        auto perm_fn = [](const httplib::Request&, httplib::Response&,
                          const std::string& /*securable_type*/,
                          const std::string& /*operation*/) -> bool {
            return true;
        };

        auto audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string& /*target_type*/,
                               const std::string& /*target_id*/,
                               const std::string& /*detail*/) {
            audit_log.push_back(action + "|" + result);
        };

        auto agents_fn = []() -> nlohmann::json {
            return nlohmann::json::array({
                {{"agent_id", "agent-001"}, {"hostname", "web-01"}, {"os", "linux"},
                 {"arch", "x64"}, {"agent_version", "0.1.3"}},
                {{"agent_id", "agent-002"}, {"hostname", "db-01"}, {"os", "windows"},
                 {"arch", "x64"}, {"agent_version", "0.1.3"}}
            });
        };

        mcp.register_routes(svr, auth_fn, perm_fn, audit_fn, agents_fn,
                            /*rbac_store=*/nullptr,
                            /*instruction_store=*/nullptr,
                            /*execution_tracker=*/nullptr,
                            /*response_store=*/nullptr,
                            /*audit_store=*/nullptr,
                            /*tag_store=*/nullptr,
                            /*inventory_store=*/nullptr,
                            /*policy_store=*/nullptr,
                            /*mgmt_store=*/nullptr,
                            /*approval_manager=*/nullptr,
                            /*schedule_engine=*/nullptr,
                            read_only_mode_,
                            mcp_disabled_,
                            dispatch_fn);

        bind_and_listen();
    }

private:
    void bind_and_listen() {
        // Bind to a random available port
        port = svr.bind_to_any_port("127.0.0.1");
        REQUIRE(port > 0);

        // Start listening in a background thread
        server_thread = std::thread([this]() { svr.listen_after_bind(); });

        // Wait for server to be ready (poll with short sleeps)
        for (int i = 0; i < 100; ++i) {
            if (svr.is_running()) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        REQUIRE(svr.is_running());
    }

public:

    ~McpTestServer() {
        svr.stop();
        if (server_thread.joinable())
            server_thread.join();
    }

    /// Send a JSON-RPC request body and return the result.
    httplib::Result call(const std::string& json_body) {
        httplib::Client cli("127.0.0.1", port);
        cli.set_connection_timeout(5);
        cli.set_read_timeout(5);
        return cli.Post("/mcp/v1/", json_body, "application/json");
    }
};

} // namespace

// ── 1. initialize handshake ─────────────────────────────────────────────────

TEST_CASE("MCP Integration: initialize handshake", "[mcp][integration]") {
    McpTestServer ts;
    ts.start();

    auto res = ts.call(R"({"jsonrpc":"2.0","method":"initialize","id":1,"params":{"clientInfo":{"name":"test"}}})");
    REQUIRE(res);
    CHECK(res->status == 200);

    auto body = nlohmann::json::parse(res->body);
    CHECK(body["jsonrpc"] == "2.0");
    CHECK(body["id"] == 1);
    REQUIRE(body.contains("result"));

    auto& result = body["result"];
    CHECK(result.contains("serverInfo"));
    CHECK(result["serverInfo"]["name"] == "yuzu-server");
    CHECK(result.contains("protocolVersion"));
    CHECK(result.contains("capabilities"));
    CHECK(result["capabilities"].contains("tools"));
    CHECK(result["capabilities"].contains("resources"));
    CHECK(result["capabilities"].contains("prompts"));
}

// ── 2. ping ─────────────────────────────────────────────────────────────────

TEST_CASE("MCP Integration: ping returns empty result", "[mcp][integration]") {
    McpTestServer ts;
    ts.start();

    auto res = ts.call(R"({"jsonrpc":"2.0","method":"ping","id":2})");
    REQUIRE(res);
    CHECK(res->status == 200);

    auto body = nlohmann::json::parse(res->body);
    CHECK(body["jsonrpc"] == "2.0");
    CHECK(body["id"] == 2);
    CHECK(body["result"].empty()); // {}
}

// ── 3. tools/list — verify 23 tools ─────────────────────────────────────────

TEST_CASE("MCP Integration: tools/list returns expected tools", "[mcp][integration]") {
    McpTestServer ts;
    ts.start();

    auto res = ts.call(R"({"jsonrpc":"2.0","method":"tools/list","id":3})");
    REQUIRE(res);
    CHECK(res->status == 200);

    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body.contains("result"));
    auto& result = body["result"];
    REQUIRE(result.contains("tools"));
    auto& tools = result["tools"];
    REQUIRE(tools.is_array());
    CHECK(tools.size() >= 23);  // At least 23; don't break when new tools are added

    // Verify key tools are present
    std::set<std::string> names;
    for (const auto& t : tools) names.insert(t["name"].get<std::string>());
    CHECK(names.count("list_agents") == 1);
    CHECK(names.count("execute_instruction") == 1);
    CHECK(names.count("query_responses") == 1);

    // Verify each tool has required fields
    for (const auto& tool : tools) {
        CHECK(tool.contains("name"));
        CHECK(tool["name"].is_string());
        CHECK(tool.contains("inputSchema"));
        CHECK(tool["inputSchema"].is_object());
        CHECK(tool["inputSchema"].contains("type"));
    }

    // Spot-check specific tool names are present
    std::vector<std::string> expected_names = {
        "list_agents", "get_agent_details", "query_audit_log",
        "list_definitions", "get_definition", "query_responses",
        "validate_scope", "preview_scope_targets", "list_pending_approvals"
    };
    for (const auto& name : expected_names) {
        bool found = false;
        for (const auto& tool : tools) {
            if (tool["name"] == name) { found = true; break; }
        }
        CHECK(found);
    }
}

// ── 4. tools/call with list_agents — verify mock agent data ─────────────────

TEST_CASE("MCP Integration: tools/call list_agents", "[mcp][integration]") {
    McpTestServer ts;
    ts.start();

    auto res = ts.call(R"({"jsonrpc":"2.0","method":"tools/call","id":4,"params":{"name":"list_agents"}})");
    REQUIRE(res);
    CHECK(res->status == 200);

    auto body = nlohmann::json::parse(res->body);
    CHECK(body["jsonrpc"] == "2.0");
    CHECK(body["id"] == 4);
    REQUIRE(body.contains("result"));

    auto& result = body["result"];
    REQUIRE(result.contains("content"));
    REQUIRE(result["content"].is_array());
    REQUIRE(result["content"].size() >= 1);

    // The content[0].text is a JSON-encoded array of agents
    auto& content_item = result["content"][0];
    CHECK(content_item["type"] == "text");
    auto agents = nlohmann::json::parse(content_item["text"].get<std::string>());
    REQUIRE(agents.is_array());
    CHECK(agents.size() == 2);
    CHECK(agents[0]["agent_id"] == "agent-001");
    CHECK(agents[0]["hostname"] == "web-01");
    CHECK(agents[1]["agent_id"] == "agent-002");
    CHECK(agents[1]["os"] == "windows");

    // Verify audit was recorded
    REQUIRE(ts.audit_log.size() >= 1);
    CHECK(ts.audit_log.back() == "mcp.list_agents|success");
}

// ── 5. tools/call with unknown tool — kMethodNotFound ───────────────────────

TEST_CASE("MCP Integration: tools/call unknown tool returns error", "[mcp][integration]") {
    McpTestServer ts;
    ts.start();

    auto res = ts.call(
        R"({"jsonrpc":"2.0","method":"tools/call","id":5,"params":{"name":"nonexistent_tool"}})");
    REQUIRE(res);
    CHECK(res->status == 200);

    auto body = nlohmann::json::parse(res->body);
    CHECK(body["jsonrpc"] == "2.0");
    CHECK(body["id"] == 5);
    REQUIRE(body.contains("error"));
    CHECK(body["error"]["code"] == yuzu::server::mcp::kMethodNotFound);
    CHECK(body["error"]["message"].get<std::string>().find("nonexistent_tool") != std::string::npos);
    CHECK(!body.contains("result"));
}

// ── 6. Tier denied — readonly tier blocks a read on a tool that needs stores ─

TEST_CASE("MCP Integration: tier denied for unknown tier", "[mcp][integration]") {
    McpTestServer ts;
    ts.start("bogus_tier");

    // With a bogus tier, tier_allows() returns false for everything
    auto res = ts.call(
        R"({"jsonrpc":"2.0","method":"tools/call","id":6,"params":{"name":"list_agents"}})");
    REQUIRE(res);
    CHECK(res->status == 200);

    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body.contains("error"));
    CHECK(body["error"]["code"] == yuzu::server::mcp::kTierDenied);
}

// ── 7. Unauthenticated — auth_fn returns nullopt, verify 401 ────────────────

TEST_CASE("MCP Integration: unauthenticated returns 401", "[mcp][integration]") {
    McpTestServer ts;
    ts.start();
    ts.mock_auth_enabled = false;

    auto res = ts.call(R"({"jsonrpc":"2.0","method":"ping","id":7})");
    REQUIRE(res);
    CHECK(res->status == 401);
}

// ── 8. Notification (no id) — verify 204 response ──────────────────────────

TEST_CASE("MCP Integration: notification returns 204", "[mcp][integration]") {
    McpTestServer ts;
    ts.start();

    // A JSON-RPC notification has no "id" field
    auto res = ts.call(R"({"jsonrpc":"2.0","method":"notifications/initialized"})");
    REQUIRE(res);
    CHECK(res->status == 204);
}

// ── 9. Invalid JSON — verify parse error ────────────────────────────────────

TEST_CASE("MCP Integration: invalid JSON returns parse error", "[mcp][integration]") {
    McpTestServer ts;
    ts.start();

    auto res = ts.call("{not valid json at all!}}}");
    REQUIRE(res);
    CHECK(res->status == 200);

    auto body = nlohmann::json::parse(res->body);
    CHECK(body["jsonrpc"] == "2.0");
    CHECK(body["id"].is_null());
    REQUIRE(body.contains("error"));
    CHECK(body["error"]["code"] == yuzu::server::mcp::kParseError);
}

// ── 10. resources/list — verify resource count ──────────────────────────────

TEST_CASE("MCP Integration: resources/list returns 3 resources", "[mcp][integration]") {
    McpTestServer ts;
    ts.start();

    auto res = ts.call(R"({"jsonrpc":"2.0","method":"resources/list","id":10})");
    REQUIRE(res);
    CHECK(res->status == 200);

    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body.contains("result"));
    auto& result = body["result"];
    REQUIRE(result.contains("resources"));
    auto& resources = result["resources"];
    REQUIRE(resources.is_array());
    CHECK(resources.size() == 3);

    // Each resource should have uri, name, description, mimeType
    for (const auto& r : resources) {
        CHECK(r.contains("uri"));
        CHECK(r.contains("name"));
        CHECK(r.contains("description"));
        CHECK(r.contains("mimeType"));
    }
}

// ── 11. Unknown method — verify kMethodNotFound ─────────────────────────────

TEST_CASE("MCP Integration: unknown method returns MethodNotFound", "[mcp][integration]") {
    McpTestServer ts;
    ts.start();

    auto res = ts.call(R"({"jsonrpc":"2.0","method":"completions/list","id":11})");
    REQUIRE(res);
    CHECK(res->status == 200);

    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body.contains("error"));
    CHECK(body["error"]["code"] == yuzu::server::mcp::kMethodNotFound);
    CHECK(body["error"]["message"].get<std::string>().find("completions/list") != std::string::npos);
}

// ── 12. readonly tier allows list_agents (read) ─────────────────────────────

TEST_CASE("MCP Integration: readonly tier allows read tools", "[mcp][integration]") {
    McpTestServer ts;
    ts.start("readonly");

    auto res = ts.call(
        R"({"jsonrpc":"2.0","method":"tools/call","id":12,"params":{"name":"list_agents"}})");
    REQUIRE(res);
    CHECK(res->status == 200);

    auto body = nlohmann::json::parse(res->body);
    // Should succeed — readonly can read Infrastructure
    REQUIRE(body.contains("result"));
    CHECK(!body.contains("error"));
}

// ── 13. prompts/list — verify prompt count ──────────────────────────────────

TEST_CASE("MCP Integration: prompts/list returns prompts", "[mcp][integration]") {
    McpTestServer ts;
    ts.start();

    auto res = ts.call(R"({"jsonrpc":"2.0","method":"prompts/list","id":13})");
    REQUIRE(res);
    CHECK(res->status == 200);

    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body.contains("result"));
    auto& result = body["result"];
    REQUIRE(result.contains("prompts"));
    auto& prompts = result["prompts"];
    REQUIRE(prompts.is_array());
    CHECK(prompts.size() == 4);

    // Check each prompt has name, description, arguments
    for (const auto& p : prompts) {
        CHECK(p.contains("name"));
        CHECK(p.contains("description"));
        CHECK(p.contains("arguments"));
    }
}

// ── 14. validate_scope tool via HTTP ────────────────────────────────────────

TEST_CASE("MCP Integration: tools/call validate_scope", "[mcp][integration]") {
    McpTestServer ts;
    ts.start();

    // Valid scope expression
    auto res = ts.call(
        R"({"jsonrpc":"2.0","method":"tools/call","id":14,"params":{"name":"validate_scope","arguments":{"expression":"os == \"linux\""}}})");
    REQUIRE(res);
    CHECK(res->status == 200);

    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body.contains("result"));
    auto& content = body["result"]["content"];
    REQUIRE(content.is_array());
    REQUIRE(content.size() >= 1);

    auto text = nlohmann::json::parse(content[0]["text"].get<std::string>());
    CHECK(text["valid"] == true);
}

// ── 15. validate_scope with invalid expression ──────────────────────────────

TEST_CASE("MCP Integration: tools/call validate_scope invalid expression", "[mcp][integration]") {
    McpTestServer ts;
    ts.start();

    auto res = ts.call(
        R"({"jsonrpc":"2.0","method":"tools/call","id":15,"params":{"name":"validate_scope","arguments":{"expression":"==== broken"}}})");
    REQUIRE(res);
    CHECK(res->status == 200);

    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body.contains("result"));
    auto& content = body["result"]["content"];
    REQUIRE(content.is_array());

    auto text = nlohmann::json::parse(content[0]["text"].get<std::string>());
    CHECK(text["valid"] == false);
    CHECK(text.contains("error"));
}

// ── 16. Missing jsonrpc version field through HTTP ──────────────────────────

TEST_CASE("MCP Integration: missing jsonrpc field returns InvalidRequest", "[mcp][integration]") {
    McpTestServer ts;
    ts.start();

    auto res = ts.call(R"({"method":"ping","id":16})");
    REQUIRE(res);
    CHECK(res->status == 200);

    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body.contains("error"));
    CHECK(body["error"]["code"] == yuzu::server::mcp::kInvalidRequest);
}

// ── 17. String id preserved in response ─────────────────────────────────────

TEST_CASE("MCP Integration: string id preserved in response", "[mcp][integration]") {
    McpTestServer ts;
    ts.start();

    auto res = ts.call(R"({"jsonrpc":"2.0","method":"ping","id":"request-abc-123"})");
    REQUIRE(res);
    CHECK(res->status == 200);

    auto body = nlohmann::json::parse(res->body);
    CHECK(body["id"] == "request-abc-123");
}

// ── 18. Content-Type header is application/json ─────────────────────────────

TEST_CASE("MCP Integration: response Content-Type is application/json", "[mcp][integration]") {
    McpTestServer ts;
    ts.start();

    auto res = ts.call(R"({"jsonrpc":"2.0","method":"ping","id":18})");
    REQUIRE(res);
    CHECK(res->status == 200);

    // httplib normalizes header names to lowercase
    auto ct = res->get_header_value("Content-Type");
    CHECK(ct.find("application/json") != std::string::npos);
}

// ── 19. get_agent_details via HTTP ──────────────────────────────────────────

TEST_CASE("MCP Integration: tools/call get_agent_details", "[mcp][integration]") {
    McpTestServer ts;
    ts.start();

    auto res = ts.call(
        R"({"jsonrpc":"2.0","method":"tools/call","id":19,"params":{"name":"get_agent_details","arguments":{"agent_id":"agent-001"}}})");
    REQUIRE(res);
    CHECK(res->status == 200);

    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body.contains("result"));
    auto& content = body["result"]["content"];
    REQUIRE(content.is_array());
    REQUIRE(content.size() >= 1);

    auto text = nlohmann::json::parse(content[0]["text"].get<std::string>());
    CHECK(text["agent_id"] == "agent-001");
    CHECK(text["hostname"] == "web-01");
    CHECK(text["os"] == "linux");
}

// ── 20. get_agent_details with unknown agent ────────────────────────────────

TEST_CASE("MCP Integration: tools/call get_agent_details unknown agent", "[mcp][integration]") {
    McpTestServer ts;
    ts.start();

    auto res = ts.call(
        R"({"jsonrpc":"2.0","method":"tools/call","id":20,"params":{"name":"get_agent_details","arguments":{"agent_id":"no-such-agent"}}})");
    REQUIRE(res);
    CHECK(res->status == 200);

    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body.contains("error"));
    CHECK(body["error"]["code"] == yuzu::server::mcp::kInvalidParams);
    CHECK(body["error"]["message"].get<std::string>().find("no-such-agent") != std::string::npos);
}

// ── 21. preview_scope_targets via HTTP ──────────────────────────────────────

TEST_CASE("MCP Integration: tools/call preview_scope_targets", "[mcp][integration]") {
    McpTestServer ts;
    ts.start();

    auto res = ts.call(
        R"({"jsonrpc":"2.0","method":"tools/call","id":21,"params":{"name":"preview_scope_targets","arguments":{"expression":"os == \"linux\""}}})");
    REQUIRE(res);
    CHECK(res->status == 200);

    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body.contains("result"));
    auto& content = body["result"]["content"];
    REQUIRE(content.is_array());
    REQUIRE(content.size() >= 1);

    auto text = nlohmann::json::parse(content[0]["text"].get<std::string>());
    CHECK(text["expression"] == "os == \"linux\"");
    CHECK(text["matched_count"] == 1);
    REQUIRE(text["matched_agents"].is_array());
    CHECK(text["matched_agents"][0] == "agent-001");
}

// ── 22. Multiple sequential requests on same server ─────────────────────────

TEST_CASE("MCP Integration: multiple requests on same server", "[mcp][integration]") {
    McpTestServer ts;
    ts.start();

    // Request 1: initialize
    auto r1 = ts.call(R"({"jsonrpc":"2.0","method":"initialize","id":100})");
    REQUIRE(r1);
    CHECK(r1->status == 200);
    auto b1 = nlohmann::json::parse(r1->body);
    CHECK(b1.contains("result"));

    // Request 2: ping
    auto r2 = ts.call(R"({"jsonrpc":"2.0","method":"ping","id":101})");
    REQUIRE(r2);
    CHECK(r2->status == 200);

    // Request 3: tools/list
    auto r3 = ts.call(R"({"jsonrpc":"2.0","method":"tools/list","id":102})");
    REQUIRE(r3);
    CHECK(r3->status == 200);
    auto b3 = nlohmann::json::parse(r3->body);
    CHECK(b3["result"]["tools"].size() >= 23);

    // Request 4: tools/call
    auto r4 = ts.call(R"({"jsonrpc":"2.0","method":"tools/call","id":103,"params":{"name":"list_agents"}})");
    REQUIRE(r4);
    CHECK(r4->status == 200);
    auto b4 = nlohmann::json::parse(r4->body);
    CHECK(b4.contains("result"));
}

// ═══════════════════════════════════════════════════════════════════════════
// execute_instruction — Phase 2 write tool tests
//
// Tests cover: happy dispatch, null dispatch_fn, validation, scope defaults,
// agent_ids forwarding, params forwarding, tier enforcement, and audit trail.
// ═══════════════════════════════════════════════════════════════════════════

// ── 23. Happy dispatch ────────────────────────────────────────────────────

TEST_CASE("MCP Integration: execute_instruction happy dispatch", "[mcp][integration][execute]") {
    McpTestServer ts;
    auto dispatch = [&](const std::string& plugin, const std::string& action,
                        const std::vector<std::string>& agent_ids,
                        const std::string& scope_expr,
                        const std::unordered_map<std::string, std::string>& params)
        -> std::pair<std::string, int> {
        ts.last_dispatch_plugin = plugin;
        ts.last_dispatch_action = action;
        ts.last_dispatch_agent_ids = agent_ids;
        ts.last_dispatch_scope = scope_expr;
        ts.last_dispatch_params = params;
        return {"cmd-abc", 2};
    };
    ts.start_with_dispatch(dispatch, "operator");

    auto res = ts.call(
        R"({"jsonrpc":"2.0","method":"tools/call","id":23,"params":{"name":"execute_instruction","arguments":{"plugin":"os_info","action":"version"}}})");
    REQUIRE(res);
    CHECK(res->status == 200);

    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body.contains("result"));
    auto& content = body["result"]["content"];
    REQUIRE(content.is_array());
    REQUIRE(content.size() >= 1);

    auto text = nlohmann::json::parse(content[0]["text"].get<std::string>());
    CHECK(text["command_id"] == "cmd-abc");
    CHECK(text["agents_reached"] == 2);
    CHECK(text["plugin"] == "os_info");
    CHECK(text["action"] == "version");
}

// ── 24. Null dispatch_fn ──────────────────────────────────────────────────

TEST_CASE("MCP Integration: execute_instruction null dispatch_fn", "[mcp][integration][execute]") {
    McpTestServer ts;
    // Use start() which does not pass a dispatch_fn (defaults to nullptr)
    ts.start("operator");

    auto res = ts.call(
        R"({"jsonrpc":"2.0","method":"tools/call","id":24,"params":{"name":"execute_instruction","arguments":{"plugin":"os_info","action":"version"}}})");
    REQUIRE(res);
    CHECK(res->status == 200);

    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body.contains("error"));
    CHECK(body["error"]["code"] == yuzu::server::mcp::kInternalError);
    CHECK(body["error"]["message"].get<std::string>().find("Command dispatch unavailable") != std::string::npos);
}

// ── 25. Missing plugin ───────────────────────────────────────────────────

TEST_CASE("MCP Integration: execute_instruction missing plugin", "[mcp][integration][execute]") {
    McpTestServer ts;
    auto dispatch = [](const std::string&, const std::string&,
                       const std::vector<std::string>&, const std::string&,
                       const std::unordered_map<std::string, std::string>&)
        -> std::pair<std::string, int> { return {"", 0}; };
    ts.start_with_dispatch(dispatch, "operator");

    // Only action, no plugin
    auto res = ts.call(
        R"({"jsonrpc":"2.0","method":"tools/call","id":25,"params":{"name":"execute_instruction","arguments":{"action":"version"}}})");
    REQUIRE(res);
    CHECK(res->status == 200);

    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body.contains("error"));
    CHECK(body["error"]["code"] == yuzu::server::mcp::kInvalidParams);
    CHECK(body["error"]["message"].get<std::string>().find("plugin") != std::string::npos);
}

// ── 26. Missing action ───────────────────────────────────────────────────

TEST_CASE("MCP Integration: execute_instruction missing action", "[mcp][integration][execute]") {
    McpTestServer ts;
    auto dispatch = [](const std::string&, const std::string&,
                       const std::vector<std::string>&, const std::string&,
                       const std::unordered_map<std::string, std::string>&)
        -> std::pair<std::string, int> { return {"", 0}; };
    ts.start_with_dispatch(dispatch, "operator");

    // Only plugin, no action
    auto res = ts.call(
        R"({"jsonrpc":"2.0","method":"tools/call","id":26,"params":{"name":"execute_instruction","arguments":{"plugin":"os_info"}}})");
    REQUIRE(res);
    CHECK(res->status == 200);

    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body.contains("error"));
    CHECK(body["error"]["code"] == yuzu::server::mcp::kInvalidParams);
    CHECK(body["error"]["message"].get<std::string>().find("action") != std::string::npos);
}

// ── 27. Zero agents reached ──────────────────────────────────────────────

TEST_CASE("MCP Integration: execute_instruction zero agents reached", "[mcp][integration][execute]") {
    McpTestServer ts;
    auto dispatch = [&](const std::string&, const std::string&,
                        const std::vector<std::string>&, const std::string&,
                        const std::unordered_map<std::string, std::string>&)
        -> std::pair<std::string, int> { return {"cmd-xyz", 0}; };
    ts.start_with_dispatch(dispatch, "operator");

    auto res = ts.call(
        R"({"jsonrpc":"2.0","method":"tools/call","id":27,"params":{"name":"execute_instruction","arguments":{"plugin":"os_info","action":"version"}}})");
    REQUIRE(res);
    CHECK(res->status == 200);

    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body.contains("result"));
    auto& content = body["result"]["content"];
    REQUIRE(content.is_array());
    REQUIRE(content.size() >= 1);

    auto text_str = content[0]["text"].get<std::string>();
    CHECK(text_str.find("No agents reachable") != std::string::npos);
}

// ── 28. Default scope to __all__ ─────────────────────────────────────────

TEST_CASE("MCP Integration: execute_instruction default scope __all__", "[mcp][integration][execute]") {
    McpTestServer ts;
    auto dispatch = [&](const std::string& plugin, const std::string& action,
                        const std::vector<std::string>& agent_ids,
                        const std::string& scope_expr,
                        const std::unordered_map<std::string, std::string>& params)
        -> std::pair<std::string, int> {
        ts.last_dispatch_scope = scope_expr;
        ts.last_dispatch_agent_ids = agent_ids;
        return {"cmd-default", 1};
    };
    ts.start_with_dispatch(dispatch, "operator");

    // Neither scope nor agent_ids provided
    auto res = ts.call(
        R"({"jsonrpc":"2.0","method":"tools/call","id":28,"params":{"name":"execute_instruction","arguments":{"plugin":"os_info","action":"version"}}})");
    REQUIRE(res);
    CHECK(res->status == 200);

    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body.contains("result"));
    CHECK(ts.last_dispatch_scope == "__all__");
    CHECK(ts.last_dispatch_agent_ids.empty());
}

// ── 29. Explicit agent_ids ───────────────────────────────────────────────

TEST_CASE("MCP Integration: execute_instruction explicit agent_ids", "[mcp][integration][execute]") {
    McpTestServer ts;
    auto dispatch = [&](const std::string&, const std::string&,
                        const std::vector<std::string>& agent_ids,
                        const std::string& scope_expr,
                        const std::unordered_map<std::string, std::string>&)
        -> std::pair<std::string, int> {
        ts.last_dispatch_agent_ids = agent_ids;
        ts.last_dispatch_scope = scope_expr;
        return {"cmd-agents", 2};
    };
    ts.start_with_dispatch(dispatch, "operator");

    auto res = ts.call(
        R"({"jsonrpc":"2.0","method":"tools/call","id":29,"params":{"name":"execute_instruction","arguments":{"plugin":"os_info","action":"version","agent_ids":["a1","a2"]}}})");
    REQUIRE(res);
    CHECK(res->status == 200);

    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body.contains("result"));
    REQUIRE(ts.last_dispatch_agent_ids.size() == 2);
    CHECK(ts.last_dispatch_agent_ids[0] == "a1");
    CHECK(ts.last_dispatch_agent_ids[1] == "a2");
}

// ── 30. Params forwarding ────────────────────────────────────────────────

TEST_CASE("MCP Integration: execute_instruction params forwarding", "[mcp][integration][execute]") {
    McpTestServer ts;
    auto dispatch = [&](const std::string&, const std::string&,
                        const std::vector<std::string>&, const std::string&,
                        const std::unordered_map<std::string, std::string>& params)
        -> std::pair<std::string, int> {
        ts.last_dispatch_params = params;
        return {"cmd-params", 1};
    };
    ts.start_with_dispatch(dispatch, "operator");

    auto res = ts.call(
        R"({"jsonrpc":"2.0","method":"tools/call","id":30,"params":{"name":"execute_instruction","arguments":{"plugin":"os_info","action":"version","params":{"key":"val"}}}})");
    REQUIRE(res);
    CHECK(res->status == 200);

    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body.contains("result"));
    REQUIRE(ts.last_dispatch_params.size() == 1);
    CHECK(ts.last_dispatch_params.at("key") == "val");
}

// ── 31. Non-string params (v.dump()) ─────────────────────────────────────

TEST_CASE("MCP Integration: execute_instruction non-string params", "[mcp][integration][execute]") {
    McpTestServer ts;
    auto dispatch = [&](const std::string&, const std::string&,
                        const std::vector<std::string>&, const std::string&,
                        const std::unordered_map<std::string, std::string>& params)
        -> std::pair<std::string, int> {
        ts.last_dispatch_params = params;
        return {"cmd-nonstr", 1};
    };
    ts.start_with_dispatch(dispatch, "operator");

    auto res = ts.call(
        R"({"jsonrpc":"2.0","method":"tools/call","id":31,"params":{"name":"execute_instruction","arguments":{"plugin":"os_info","action":"version","params":{"count":5}}}})");
    REQUIRE(res);
    CHECK(res->status == 200);

    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body.contains("result"));
    REQUIRE(ts.last_dispatch_params.count("count") == 1);
    CHECK(ts.last_dispatch_params.at("count") == "5");
}

// ── 32. read_only_mode blocks ────────────────────────────────────────────

TEST_CASE("MCP Integration: execute_instruction blocked by read_only_mode", "[mcp][integration][execute]") {
    McpTestServer ts;
    ts.read_only_mode_ = true;
    auto dispatch = [](const std::string&, const std::string&,
                       const std::vector<std::string>&, const std::string&,
                       const std::unordered_map<std::string, std::string>&)
        -> std::pair<std::string, int> { return {"cmd-ro", 1}; };
    ts.start_with_dispatch(dispatch, "operator");

    auto res = ts.call(
        R"({"jsonrpc":"2.0","method":"tools/call","id":32,"params":{"name":"execute_instruction","arguments":{"plugin":"os_info","action":"version"}}})");
    REQUIRE(res);
    CHECK(res->status == 200);

    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body.contains("error"));
    CHECK(body["error"]["code"] == yuzu::server::mcp::kTierDenied);
    CHECK(body["error"]["message"].get<std::string>().find("read-only") != std::string::npos);
}

// ── 33. readonly tier blocked ────────────────────────────────────────────

TEST_CASE("MCP Integration: execute_instruction blocked by readonly tier", "[mcp][integration][execute]") {
    McpTestServer ts;
    auto dispatch = [](const std::string&, const std::string&,
                       const std::vector<std::string>&, const std::string&,
                       const std::unordered_map<std::string, std::string>&)
        -> std::pair<std::string, int> { return {"cmd-ro", 1}; };
    ts.start_with_dispatch(dispatch, "readonly");

    auto res = ts.call(
        R"({"jsonrpc":"2.0","method":"tools/call","id":33,"params":{"name":"execute_instruction","arguments":{"plugin":"os_info","action":"version"}}})");
    REQUIRE(res);
    CHECK(res->status == 200);

    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body.contains("error"));
    CHECK(body["error"]["code"] == yuzu::server::mcp::kTierDenied);
}

// ── 34. operator tier allowed ────────────────────────────────────────────

TEST_CASE("MCP Integration: execute_instruction operator tier proceeds", "[mcp][integration][execute]") {
    McpTestServer ts;
    auto dispatch = [&](const std::string& plugin, const std::string& action,
                        const std::vector<std::string>&, const std::string&,
                        const std::unordered_map<std::string, std::string>&)
        -> std::pair<std::string, int> {
        ts.last_dispatch_plugin = plugin;
        ts.last_dispatch_action = action;
        return {"cmd-op", 3};
    };
    ts.start_with_dispatch(dispatch, "operator");

    auto res = ts.call(
        R"({"jsonrpc":"2.0","method":"tools/call","id":34,"params":{"name":"execute_instruction","arguments":{"plugin":"hardware","action":"list"}}})");
    REQUIRE(res);
    CHECK(res->status == 200);

    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body.contains("result"));
    CHECK(!body.contains("error"));

    auto& content = body["result"]["content"];
    REQUIRE(content.is_array());
    auto text = nlohmann::json::parse(content[0]["text"].get<std::string>());
    CHECK(text["command_id"] == "cmd-op");
    CHECK(text["agents_reached"] == 3);
    CHECK(ts.last_dispatch_plugin == "hardware");
    CHECK(ts.last_dispatch_action == "list");
}

// ── 35. supervised tier returns not-implemented ──────────────────────────

TEST_CASE("MCP Integration: execute_instruction supervised tier approval-gated", "[mcp][integration][execute]") {
    McpTestServer ts;
    auto dispatch = [](const std::string&, const std::string&,
                       const std::vector<std::string>&, const std::string&,
                       const std::unordered_map<std::string, std::string>&)
        -> std::pair<std::string, int> { return {"cmd-sup", 1}; };
    ts.start_with_dispatch(dispatch, "supervised");

    auto res = ts.call(
        R"({"jsonrpc":"2.0","method":"tools/call","id":35,"params":{"name":"execute_instruction","arguments":{"plugin":"os_info","action":"version"}}})");
    REQUIRE(res);
    CHECK(res->status == 200);

    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body.contains("error"));
    CHECK(body["error"]["code"] == yuzu::server::mcp::kApprovalRequired);
    CHECK(body["error"]["message"].get<std::string>().find("approval") != std::string::npos);
}

// ── 36. Audit on success ─────────────────────────────────────────────────

TEST_CASE("MCP Integration: execute_instruction audit on success", "[mcp][integration][execute]") {
    McpTestServer ts;
    auto dispatch = [](const std::string&, const std::string&,
                       const std::vector<std::string>&, const std::string&,
                       const std::unordered_map<std::string, std::string>&)
        -> std::pair<std::string, int> { return {"cmd-audit", 2}; };
    ts.start_with_dispatch(dispatch, "operator");

    auto res = ts.call(
        R"({"jsonrpc":"2.0","method":"tools/call","id":36,"params":{"name":"execute_instruction","arguments":{"plugin":"os_info","action":"version"}}})");
    REQUIRE(res);
    CHECK(res->status == 200);

    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body.contains("result"));

    REQUIRE(ts.audit_log.size() >= 1);
    CHECK(ts.audit_log.back() == "mcp.execute_instruction|success");
}

// ── 37. Audit on no-agents ───────────────────────────────────────────────

TEST_CASE("MCP Integration: execute_instruction audit on no-agents", "[mcp][integration][execute]") {
    McpTestServer ts;
    auto dispatch = [](const std::string&, const std::string&,
                       const std::vector<std::string>&, const std::string&,
                       const std::unordered_map<std::string, std::string>&)
        -> std::pair<std::string, int> { return {"cmd-empty", 0}; };
    ts.start_with_dispatch(dispatch, "operator");

    auto res = ts.call(
        R"({"jsonrpc":"2.0","method":"tools/call","id":37,"params":{"name":"execute_instruction","arguments":{"plugin":"os_info","action":"version"}}})");
    REQUIRE(res);
    CHECK(res->status == 200);

    REQUIRE(ts.audit_log.size() >= 1);
    CHECK(ts.audit_log.back() == "mcp.execute_instruction|failure");
}
