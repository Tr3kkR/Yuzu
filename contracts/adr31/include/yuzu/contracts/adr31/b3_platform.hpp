#pragma once

#include "contract_error.hpp"

#include <nlohmann/json.hpp>

#include <expected>
#include <string>
#include <string_view>

namespace yuzu::contracts::adr31 {

struct B3PlatformRequest {
    std::string correlation_id;
    std::string securable;
    std::string operation;
    nlohmann::json scope;
};

[[nodiscard]] std::expected<std::string, ContractError>
encode_b3_platform_request(const B3PlatformRequest& request);

[[nodiscard]] std::expected<B3PlatformRequest, ContractError>
decode_b3_platform_request(std::string_view wire_json);

} // namespace yuzu::contracts::adr31
