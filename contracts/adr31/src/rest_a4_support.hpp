#pragma once

#include <yuzu/contracts/adr31/contract_error.hpp>
#include <yuzu/contracts/adr31/rest_a4_error.hpp>

#include <nlohmann/json.hpp>

#include <expected>

namespace yuzu::contracts::adr31::detail {

[[nodiscard]] std::expected<void, ContractError>
validate_rest_a4_error(const A4ErrorEnvelope& envelope);

[[nodiscard]] std::expected<void, ContractError>
validate_rest_v1_response_meta(const nlohmann::json& root);

[[nodiscard]] std::expected<nlohmann::json, ContractError>
encode_rest_a4_error_document(const A4ErrorEnvelope& envelope);

[[nodiscard]] std::expected<A4ErrorEnvelope, ContractError>
decode_rest_a4_error_document(const nlohmann::json& root);

} // namespace yuzu::contracts::adr31::detail
