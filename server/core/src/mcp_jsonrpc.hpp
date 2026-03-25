#pragma once

#include <nlohmann/json.hpp>

#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>

namespace yuzu::server::mcp {

// ── JSON-RPC 2.0 error codes ─────────────────────────────────────────────
constexpr int kParseError      = -32700;
constexpr int kInvalidRequest  = -32600;
constexpr int kMethodNotFound  = -32601;
constexpr int kInvalidParams   = -32602;
constexpr int kInternalError   = -32603;
// Application-defined codes
constexpr int kPermissionDenied = -32003;
constexpr int kTierDenied       = -32004;
constexpr int kMcpDisabled      = -32005;
constexpr int kApprovalRequired = -32006;

// ── Request ───────────────────────────────────────────────────────────────

struct JsonRpcRequest {
    std::string method;
    nlohmann::json params;                // object or array (default: empty object)
    std::optional<nlohmann::json> id;     // null → notification (no response expected)
};

// ── Parsing ───────────────────────────────────────────────────────────────

/// Parse a JSON-RPC 2.0 request from the raw HTTP body.
/// Returns the parsed request, or an error-response string ready to send.
inline std::expected<JsonRpcRequest, std::string> parse_request(std::string_view body) {
    nlohmann::json doc;
    try {
        doc = nlohmann::json::parse(body);
    } catch (...) {
        return std::unexpected(
            R"({"jsonrpc":"2.0","error":{"code":-32700,"message":"Parse error"},"id":null})");
    }

    if (!doc.is_object() || !doc.contains("jsonrpc") || doc["jsonrpc"] != "2.0") {
        return std::unexpected(
            R"({"jsonrpc":"2.0","error":{"code":-32600,"message":"Invalid Request: missing jsonrpc 2.0"},"id":null})");
    }
    if (!doc.contains("method") || !doc["method"].is_string()) {
        return std::unexpected(
            R"({"jsonrpc":"2.0","error":{"code":-32600,"message":"Invalid Request: missing method"},"id":null})");
    }

    JsonRpcRequest req;
    req.method = doc["method"].get<std::string>();
    req.params = doc.value("params", nlohmann::json::object());
    if (doc.contains("id"))
        req.id = doc["id"];
    return req;
}

// ── Response building (string-based, no nlohmann template bloat) ──────────

namespace detail {

inline void json_escape(std::string& out, std::string_view sv) {
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

inline std::string json_quoted(std::string_view sv) {
    std::string out;
    out.reserve(sv.size() + 2);
    out += '"';
    json_escape(out, sv);
    out += '"';
    return out;
}

} // namespace detail

/// Build a JSON-RPC 2.0 success response.  `result_json` is a pre-serialized JSON fragment.
inline std::string success_response(const nlohmann::json& id, std::string_view result_json) {
    std::string r = R"({"jsonrpc":"2.0","result":)";
    r += result_json;
    r += R"(,"id":)";
    r += id.dump();
    r += '}';
    return r;
}

/// Build a JSON-RPC 2.0 error response.
inline std::string error_response(const nlohmann::json& id, int code, std::string_view message,
                                  std::string_view data_json = {}) {
    std::string r = R"({"jsonrpc":"2.0","error":{"code":)";
    r += std::to_string(code);
    r += R"(,"message":)";
    r += detail::json_quoted(message);
    if (!data_json.empty()) {
        r += R"(,"data":)";
        r += data_json;
    }
    r += R"(},"id":)";
    r += id.dump();
    r += '}';
    return r;
}

/// Build an error response for notifications (no id → id is null).
inline std::string error_response_null(int code, std::string_view message) {
    std::string r = R"({"jsonrpc":"2.0","error":{"code":)";
    r += std::to_string(code);
    r += R"(,"message":)";
    r += detail::json_quoted(message);
    r += R"(},"id":null})";
    return r;
}

} // namespace yuzu::server::mcp
