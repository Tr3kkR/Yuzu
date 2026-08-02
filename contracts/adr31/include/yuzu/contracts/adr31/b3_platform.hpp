#pragma once

#include "contract_error.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <expected>
#include <string>
#include <string_view>

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

[[nodiscard]] std::expected<std::string, ContractError>
encode_b3_platform_request(const B3PlatformRequest& request);

[[nodiscard]] std::expected<B3PlatformRequest, ContractError>
decode_b3_platform_request(std::string_view wire_json);

} // namespace yuzu::contracts::adr31
