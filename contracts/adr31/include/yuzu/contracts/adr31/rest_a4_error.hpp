#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace yuzu::contracts::adr31 {

/// REST v1 A4 error value. This is not an MCP/JSON-RPC error contract, and a
/// decoded value is not proof that the error is bound to any request.
struct A4ErrorEnvelope {
    std::int32_t code;
    std::string message;
    std::string correlation_id;
    std::optional<std::int64_t> retry_after_ms;
    std::optional<std::string> remediation;
    std::optional<std::string> permission;
    std::optional<std::string> approval_id;
    std::optional<std::string> status_url;

    friend bool operator==(const A4ErrorEnvelope&, const A4ErrorEnvelope&) = default;
};

} // namespace yuzu::contracts::adr31
