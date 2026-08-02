#include <yuzu/contracts/adr31/b2_use_case.hpp>

#include <yuzu/contracts/adr31/contract_version.hpp>

#include "json_support.hpp"

#include <nlohmann/json.hpp>

#include <expected>
#include <string>
#include <string_view>
#include <utility>

namespace yuzu::contracts::adr31 {
namespace {

[[nodiscard]] ContractError error(ContractErrorCode code, std::string path,
                                  std::string message) {
    return ContractError{code, std::move(path), std::move(message)};
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

    auto id = detail::required_string(*it, "id", path);
    if (!id) return std::unexpected(id.error());
    auto version = detail::required_string(*it, "version", path);
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
    if (const auto header = detail::decode_contract_header(*root, kB2UseCaseRequest); !header) {
        return std::unexpected(header.error());
    }

    auto request_id = detail::required_string(*root, "request_id");
    if (!request_id) return std::unexpected(request_id.error());
    auto run_id = detail::required_string(*root, "use_case_run_id");
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
