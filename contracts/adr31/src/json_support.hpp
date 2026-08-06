#pragma once

#include <yuzu/contracts/adr31/contract_error.hpp>
#include <yuzu/contracts/adr31/contract_version.hpp>

#include <nlohmann/json.hpp>

#include <expected>
#include <string>
#include <string_view>

namespace yuzu::contracts::adr31::detail {

[[nodiscard]] std::expected<nlohmann::json, ContractError>
parse_contract_json(std::string_view wire_json);

[[nodiscard]] std::expected<std::string, ContractError>
encode_contract_json(const nlohmann::json& document);

[[nodiscard]] std::expected<std::string, ContractError>
required_string(const nlohmann::json& object, std::string_view name,
                std::string_view parent_path = {});

[[nodiscard]] std::expected<ContractVersion, ContractError>
decode_contract_header(const nlohmann::json& root, const ContractDescriptor& descriptor);

[[nodiscard]] std::expected<void, ContractError>
validate_opaque_run_id(std::string_view value, std::string_view path);

[[nodiscard]] std::expected<void, ContractError>
validate_correlation_id(std::string_view value, std::string_view path = "/correlation_id");

[[nodiscard]] std::expected<void, ContractError>
reject_forbidden_authority_fields(const nlohmann::json& root);

[[nodiscard]] std::expected<void, ContractError>
reject_forbidden_authority_fields_recursive(const nlohmann::json& value,
                                             std::string_view parent_path = {});

/// Reject authentication and represented-operator metadata inside an opaque
/// domain payload without reserving ordinary domain words such as `subject`,
/// `identity`, or `user`.
[[nodiscard]] std::expected<void, ContractError>
reject_forbidden_transport_authority_fields_recursive(const nlohmann::json& value,
                                                      std::string_view parent_path = {});

} // namespace yuzu::contracts::adr31::detail
