#include <yuzu/contracts/adr31/b2_use_case.hpp>

#include <yuzu/contracts/adr31/contract_version.hpp>

#include "json_support.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <expected>
#include <limits>
#include <string>
#include <string_view>
#include <utility>

namespace yuzu::contracts::adr31 {
namespace {

[[nodiscard]] ContractError error(ContractErrorCode code, std::string path,
                                  std::string message) {
    return ContractError{code, std::move(path), std::move(message)};
}

[[nodiscard]] std::expected<std::string, ContractError>
required_string(const nlohmann::json& object, std::string_view name,
                std::string_view parent_path = {}) {
    const auto it = object.find(name);
    const auto path = std::string{parent_path} + "/" + std::string{name};
    if (it == object.end()) {
        return std::unexpected(error(ContractErrorCode::MissingField, path,
                                     std::string{name} + " is required"));
    }
    if (it->is_null()) {
        return std::unexpected(
            error(ContractErrorCode::NullField, path, std::string{name} + " must not be null"));
    }
    if (!it->is_string()) {
        return std::unexpected(
            error(ContractErrorCode::WrongType, path, std::string{name} + " must be a string"));
    }
    auto value = it->get<std::string>();
    if (value.empty()) {
        return std::unexpected(
            error(ContractErrorCode::InvalidValue, path, std::string{name} + " must not be empty"));
    }
    return value;
}

[[nodiscard]] std::expected<std::uint16_t, ContractError>
version_part(const nlohmann::json& object, std::string_view name) {
    const auto it = object.find(name);
    const auto path = "/contract/version/" + std::string{name};
    if (it == object.end()) {
        return std::unexpected(error(ContractErrorCode::MissingField, path,
                                     std::string{name} + " is required"));
    }
    if (it->is_null()) {
        return std::unexpected(
            error(ContractErrorCode::NullField, path, std::string{name} + " must not be null"));
    }
    if (!it->is_number_unsigned()) {
        return std::unexpected(error(ContractErrorCode::WrongType, path,
                                     std::string{name} + " must be an unsigned integer"));
    }
    const auto value = it->get<std::uint64_t>();
    if (value > std::numeric_limits<std::uint16_t>::max()) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, path,
                                     std::string{name} + " is outside the supported range"));
    }
    return static_cast<std::uint16_t>(value);
}

[[nodiscard]] std::expected<void, ContractError>
decode_contract_header(const nlohmann::json& root) {
    const auto contract_it = root.find("contract");
    if (contract_it == root.end()) {
        return std::unexpected(
            error(ContractErrorCode::MissingField, "/contract", "contract is required"));
    }
    if (contract_it->is_null()) {
        return std::unexpected(
            error(ContractErrorCode::NullField, "/contract", "contract must not be null"));
    }
    if (!contract_it->is_object()) {
        return std::unexpected(
            error(ContractErrorCode::WrongType, "/contract", "contract must be an object"));
    }

    const auto id = required_string(*contract_it, "id", "/contract");
    if (!id) return std::unexpected(id.error());
    if (*id != kB2UseCaseRequest.identifier) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "/contract/id",
                                     "unexpected contract identifier"));
    }

    const auto version_it = contract_it->find("version");
    if (version_it == contract_it->end()) {
        return std::unexpected(error(ContractErrorCode::MissingField, "/contract/version",
                                     "version is required"));
    }
    if (version_it->is_null()) {
        return std::unexpected(error(ContractErrorCode::NullField, "/contract/version",
                                     "version must not be null"));
    }
    if (!version_it->is_object()) {
        return std::unexpected(error(ContractErrorCode::WrongType, "/contract/version",
                                     "version must be an object"));
    }

    const auto major = version_part(*version_it, "major");
    if (!major) return std::unexpected(major.error());
    const auto minor = version_part(*version_it, "minor");
    if (!minor) return std::unexpected(minor.error());
    if (!supports(kB2UseCaseRequest, ContractVersion{*major, *minor})) {
        return std::unexpected(error(ContractErrorCode::UnsupportedVersion, "/contract/version",
                                     "unsupported contract version"));
    }
    return {};
}

[[nodiscard]] std::expected<VersionedIdentity, ContractError>
decode_versioned_identity(const nlohmann::json& root, std::string_view name) {
    const auto it = root.find(name);
    const auto path = "/" + std::string{name};
    if (it == root.end()) {
        return std::unexpected(
            error(ContractErrorCode::MissingField, path, std::string{name} + " is required"));
    }
    if (it->is_null()) {
        return std::unexpected(
            error(ContractErrorCode::NullField, path, std::string{name} + " must not be null"));
    }
    if (!it->is_object()) {
        return std::unexpected(
            error(ContractErrorCode::WrongType, path, std::string{name} + " must be an object"));
    }

    auto id = required_string(*it, "id", path);
    if (!id) return std::unexpected(id.error());
    auto version = required_string(*it, "version", path);
    if (!version) return std::unexpected(version.error());
    return VersionedIdentity{.id = std::move(*id), .version = std::move(*version)};
}

[[nodiscard]] std::expected<void, ContractError> validate_request(const B2UseCaseRequest& request) {
    if (request.request_id.empty()) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "/request_id",
                                     "request_id must not be empty"));
    }
    if (request.use_case_run_id.empty()) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "/use_case_run_id",
                                     "use_case_run_id must not be empty"));
    }
    if (request.use_case.id.empty() || request.use_case.version.empty()) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "/use_case",
                                     "use_case id and version must not be empty"));
    }
    if (request.module.id.empty() || request.module.version.empty()) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "/module",
                                     "module id and version must not be empty"));
    }
    if (!request.normalised_inputs.is_object()) {
        return std::unexpected(error(ContractErrorCode::WrongType, "/normalised_inputs",
                                     "normalised_inputs must be an object"));
    }
    return {};
}

} // namespace

std::expected<std::string, ContractError>
encode_b2_use_case_request(const B2UseCaseRequest& request) {
    if (const auto valid = validate_request(request); !valid) {
        return std::unexpected(valid.error());
    }

    const nlohmann::json root{
        {"contract",
         {{"id", kB2UseCaseRequest.identifier},
          {"version", {{"major", kB2UseCaseRequest.current.major},
                       {"minor", kB2UseCaseRequest.current.minor}}}}},
        {"request_id", request.request_id},
        {"use_case_run_id", request.use_case_run_id},
        {"use_case", {{"id", request.use_case.id}, {"version", request.use_case.version}}},
        {"module", {{"id", request.module.id}, {"version", request.module.version}}},
        {"normalised_inputs", request.normalised_inputs},
    };
    return detail::encode_contract_json(root);
}

std::expected<B2UseCaseRequest, ContractError>
decode_b2_use_case_request(std::string_view wire_json) {
    auto root = detail::parse_contract_json(wire_json);
    if (!root) return std::unexpected(root.error());
    if (!root->is_object()) {
        return std::unexpected(
            error(ContractErrorCode::RootNotObject, "", "contract body must be an object"));
    }
    if (const auto authority_fields = detail::reject_forbidden_authority_fields(*root);
        !authority_fields) {
        return std::unexpected(authority_fields.error());
    }
    if (const auto header = decode_contract_header(*root); !header) {
        return std::unexpected(header.error());
    }

    auto request_id = required_string(*root, "request_id");
    if (!request_id) return std::unexpected(request_id.error());
    auto run_id = required_string(*root, "use_case_run_id");
    if (!run_id) return std::unexpected(run_id.error());
    auto use_case = decode_versioned_identity(*root, "use_case");
    if (!use_case) return std::unexpected(use_case.error());
    auto module = decode_versioned_identity(*root, "module");
    if (!module) return std::unexpected(module.error());

    const auto inputs_it = root->find("normalised_inputs");
    if (inputs_it == root->end()) {
        return std::unexpected(error(ContractErrorCode::MissingField, "/normalised_inputs",
                                     "normalised_inputs is required"));
    }
    if (inputs_it->is_null()) {
        return std::unexpected(error(ContractErrorCode::NullField, "/normalised_inputs",
                                     "normalised_inputs must not be null"));
    }
    if (!inputs_it->is_object()) {
        return std::unexpected(error(ContractErrorCode::WrongType, "/normalised_inputs",
                                     "normalised_inputs must be an object"));
    }

    return B2UseCaseRequest{
        .request_id = std::move(*request_id),
        .use_case_run_id = std::move(*run_id),
        .use_case = std::move(*use_case),
        .module = std::move(*module),
        .normalised_inputs = *inputs_it,
    };
}

} // namespace yuzu::contracts::adr31
