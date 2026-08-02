#pragma once

#include <yuzu/contracts/adr31/contract_error.hpp>

#include <nlohmann/json_fwd.hpp>

#include <expected>

namespace yuzu::contracts::adr31::detail {

[[nodiscard]] std::expected<void, ContractError>
reject_forbidden_authority_fields(const nlohmann::json& root);

} // namespace yuzu::contracts::adr31::detail
