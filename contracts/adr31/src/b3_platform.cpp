#include <yuzu/contracts/adr31/b3_platform.hpp>

#include <yuzu/contracts/adr31/contract_version.hpp>

#include "json_support.hpp"

#include <nlohmann/json.hpp>

#include <string>
#include <utility>

namespace yuzu::contracts::adr31 {
namespace {

ContractError error(ContractErrorCode code, std::string path, std::string message) {
    return ContractError{code, std::move(path), std::move(message)};
}

std::expected<void, ContractError> validate_request(const B3PlatformRequest& request) {
    if (request.correlation_id.empty()) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "/correlation_id",
                                     "correlation_id must not be empty"));
    }
    if (request.securable.empty()) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "/securable",
                                     "securable must not be empty"));
    }
    if (to_string(request.operation).empty()) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "/operation",
                                     "operation is not a supported Core operation"));
    }
    if (!request.scope.is_object()) {
        return std::unexpected(
            error(ContractErrorCode::WrongType, "/scope", "scope must be an object"));
    }
    return {};
}

} // namespace

std::expected<std::string, ContractError>
encode_b3_platform_request(const B3PlatformRequest& request) {
    if (const auto valid = validate_request(request); !valid) {
        return std::unexpected(valid.error());
    }

    const nlohmann::json root{
        {"contract",
         {{"id", kB3PlatformRequest.identifier},
          {"version", {{"major", kB3PlatformRequest.current.major},
                       {"minor", kB3PlatformRequest.current.minor}}}}},
        {"correlation_id", request.correlation_id},
        {"operation", to_string(request.operation)},
        {"scope", request.scope},
        {"securable", request.securable},
    };
    return detail::encode_contract_json(root);
}

std::expected<B3PlatformRequest, ContractError>
decode_b3_platform_request(std::string_view wire_json) {
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

    const auto version = detail::decode_contract_header(*root, kB3PlatformRequest);
    if (!version) return std::unexpected(version.error());

    auto correlation_id = detail::required_string(*root, "correlation_id");
    if (!correlation_id) return std::unexpected(correlation_id.error());
    auto securable = detail::required_string(*root, "securable");
    if (!securable) return std::unexpected(securable.error());
    auto operation = detail::required_string(*root, "operation");
    if (!operation) return std::unexpected(operation.error());

    const auto typed_operation = [&]() -> std::expected<CoreOperation, ContractError> {
        if (*operation == "Read") return CoreOperation::Read;
        if (*operation == "Write") return CoreOperation::Write;
        if (*operation == "Execute") return CoreOperation::Execute;
        if (*operation == "Delete") return CoreOperation::Delete;
        if (*operation == "Approve") return CoreOperation::Approve;
        if (*operation == "Push") return CoreOperation::Push;
        return std::unexpected(error(ContractErrorCode::InvalidValue, "/operation",
                                     "operation is not a supported Core operation"));
    }();
    if (!typed_operation) return std::unexpected(typed_operation.error());

    const auto scope_it = root->find("scope");
    if (scope_it == root->end()) {
        return std::unexpected(
            error(ContractErrorCode::MissingField, "/scope", "scope is required"));
    }
    if (scope_it->is_null()) {
        return std::unexpected(
            error(ContractErrorCode::NullField, "/scope", "scope must not be null"));
    }
    if (!scope_it->is_object()) {
        return std::unexpected(
            error(ContractErrorCode::WrongType, "/scope", "scope must be an object"));
    }

    return B3PlatformRequest{
        .correlation_id = std::move(*correlation_id),
        .securable = std::move(*securable),
        .operation = *typed_operation,
        .scope = *scope_it,
    };
}

} // namespace yuzu::contracts::adr31
