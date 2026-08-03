#pragma once

#include "contract_error.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <variant>

namespace yuzu::contracts::adr31 {

enum class CoreOperation : std::uint8_t {
    Read,
    Write,
    Execute,
    Delete,
    Approve,
    Push,
};

[[nodiscard]] constexpr std::string_view to_string(CoreOperation operation) noexcept {
    switch (operation) {
    case CoreOperation::Read: return "Read";
    case CoreOperation::Write: return "Write";
    case CoreOperation::Execute: return "Execute";
    case CoreOperation::Delete: return "Delete";
    case CoreOperation::Approve: return "Approve";
    case CoreOperation::Push: return "Push";
    }
    return {};
}

struct B3PlatformRequest {
    std::string correlation_id;
    std::string securable;
    CoreOperation operation;
    nlohmann::json scope;
};

struct B3PlatformResult {
    std::string correlation_id;
    nlohmann::json data;

    friend bool operator==(const B3PlatformResult&, const B3PlatformResult&) = default;
};

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

using B3PlatformResponse = std::variant<B3PlatformResult, A4ErrorEnvelope>;

[[nodiscard]] std::expected<std::string, ContractError>
encode_b3_platform_request(const B3PlatformRequest& request);

[[nodiscard]] std::expected<B3PlatformRequest, ContractError>
decode_b3_platform_request(std::string_view wire_json);

// The failure arm carries the established A4 members and semantics. Object
// members use this package's deterministic sorted JSON order; legacy REST
// builder byte order is not part of the JSON contract.
[[nodiscard]] std::expected<std::string, ContractError>
encode_b3_platform_response(const B3PlatformResponse& response);

[[nodiscard]] std::expected<B3PlatformResponse, ContractError>
decode_b3_platform_response(std::string_view wire_json);

/// Consumer-side binding check. Correlation is diagnostic rather than
/// authority, but a mismatched response must never be delivered to a caller.
[[nodiscard]] std::expected<void, ContractError>
validate_b3_platform_exchange(const B3PlatformRequest& request,
                              const B3PlatformResponse& response);

} // namespace yuzu::contracts::adr31
