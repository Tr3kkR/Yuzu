#include <yuzu/contracts/adr31/b3_platform.hpp>

#include <yuzu/contracts/adr31/contract_version.hpp>

#include "json_support.hpp"
#include "rest_a4_support.hpp"

#include <nlohmann/json.hpp>

#include <string>
#include <utility>
#include <variant>

namespace yuzu::contracts::adr31 {
namespace {

ContractError error(ContractErrorCode code, std::string path, std::string message) {
    return ContractError{code, std::move(path), std::move(message)};
}

std::expected<void, ContractError> validate_request(const B3PlatformRequest& request) {
    if (const auto correlation = detail::validate_correlation_id(request.correlation_id);
        !correlation) {
        return std::unexpected(correlation.error());
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

std::expected<void, ContractError> validate_result(const B3PlatformResult& result) {
    if (const auto correlation = detail::validate_correlation_id(result.correlation_id);
        !correlation) {
        return std::unexpected(correlation.error());
    }
    if (!result.data.is_object() && !result.data.is_array()) {
        return std::unexpected(error(ContractErrorCode::WrongType, "/data",
                                     "data must be an object or array"));
    }
    return {};
}

std::string_view response_correlation_id(const B3PlatformResponse& response) {
    if (const auto* result = std::get_if<B3PlatformResult>(&response)) {
        return result->correlation_id;
    }
    return std::get<A4ErrorEnvelope>(response).correlation_id;
}

std::expected<std::string, ContractError>
encode_platform_request(const B3PlatformRequest& request) {
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

} // namespace

B3PlatformCall::B3PlatformCall(std::string body,
                               TransportAuthSlot authentication) noexcept
    : body_(std::move(body)), authentication_(std::move(authentication)) {}

std::expected<B3PlatformCall, B3PlatformCallError>
make_b3_platform_call(B3PlatformRequest request, TransportAuthSlot authentication) {
    if (!authentication.valid()) {
        return std::unexpected(
            B3PlatformCallError{B3AuthBindingError::MissingAuthentication});
    }
    if (authentication.kind() != TransportAuthKind::CallerCredential) {
        return std::unexpected(
            B3PlatformCallError{B3AuthBindingError::WrongAuthenticationKind});
    }
    auto body = encode_platform_request(request);
    if (!body) {
        return std::unexpected(B3PlatformCallError{std::in_place_type<ContractError>,
                                                   std::move(body.error())});
    }
    return B3PlatformCall{std::move(*body), std::move(authentication)};
}

std::expected<B3PlatformRequest, ContractError>
decode_b3_platform_request(std::string_view wire_json) {
    auto root = detail::parse_contract_json(wire_json);
    if (!root) return std::unexpected(root.error());
    if (!root->is_object()) {
        return std::unexpected(
            error(ContractErrorCode::RootNotObject, "", "contract body must be an object"));
    }

    const auto version = detail::decode_contract_header(*root, kB3PlatformRequest);
    if (!version) return std::unexpected(version.error());

    if (const auto authority_fields = detail::reject_forbidden_authority_fields(*root);
        !authority_fields) {
        return std::unexpected(authority_fields.error());
    }

    auto correlation_id = detail::required_string(*root, "correlation_id");
    if (!correlation_id) return std::unexpected(correlation_id.error());
    if (const auto valid_correlation = detail::validate_correlation_id(*correlation_id);
        !valid_correlation) {
        return std::unexpected(valid_correlation.error());
    }
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

std::expected<std::string, ContractError>
encode_b3_platform_response(const B3PlatformResponse& response) {
    if (const auto* result = std::get_if<B3PlatformResult>(&response)) {
        if (const auto valid = validate_result(*result); !valid) {
            return std::unexpected(valid.error());
        }
        const nlohmann::json root{
            {"contract",
             {{"id", kB3PlatformResult.identifier},
              {"version", {{"major", kB3PlatformResult.current.major},
                           {"minor", kB3PlatformResult.current.minor}}}}},
            {"correlation_id", result->correlation_id},
            {"data", result->data},
            {"meta", {{"api_version", "v1"}}},
        };
        return detail::encode_contract_json(root);
    }

    const auto& envelope = std::get<A4ErrorEnvelope>(response);
    auto document = detail::encode_rest_a4_error_document(envelope);
    if (!document) return std::unexpected(document.error());
    return detail::encode_contract_json(*document);
}

std::expected<B3PlatformResponse, ContractError>
decode_b3_platform_response(std::string_view wire_json) {
    auto root = detail::parse_contract_json(wire_json);
    if (!root) return std::unexpected(root.error());
    if (!root->is_object()) {
        return std::unexpected(
            error(ContractErrorCode::RootNotObject, "", "contract body must be an object"));
    }

    const bool has_data = root->contains("data");
    const bool has_error = root->contains("error");
    if (!has_data && !has_error) {
        return std::unexpected(error(ContractErrorCode::MissingField, "",
                                     "response must contain data or error"));
    }
    if (has_data && has_error) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "",
                                     "response must contain exactly one of data or error"));
    }

    if (has_error) {
        if (root->contains("contract")) {
            return std::unexpected(error(ContractErrorCode::InvalidValue, "/contract",
                                         "A4 errors do not carry a B3 contract header"));
        }
        auto envelope = detail::decode_rest_a4_error_document(*root);
        if (!envelope) return std::unexpected(envelope.error());
        return B3PlatformResponse{std::in_place_type<A4ErrorEnvelope>, std::move(*envelope)};
    }

    if (const auto header = detail::decode_contract_header(*root, kB3PlatformResult); !header) {
        return std::unexpected(header.error());
    }
    if (const auto authority_fields = detail::reject_forbidden_authority_fields(*root);
        !authority_fields) {
        return std::unexpected(authority_fields.error());
    }
    if (const auto meta = detail::validate_rest_v1_response_meta(*root); !meta) {
        return std::unexpected(meta.error());
    }

    auto correlation = detail::required_string(*root, "correlation_id");
    if (!correlation) return std::unexpected(correlation.error());
    const auto data_it = root->find("data");
    if (data_it->is_null()) {
        return std::unexpected(
            error(ContractErrorCode::NullField, "/data", "data must not be null"));
    }
    B3PlatformResult result{
        .correlation_id = std::move(*correlation),
        .data = *data_it,
    };
    if (const auto valid = validate_result(result); !valid) {
        return std::unexpected(valid.error());
    }
    return B3PlatformResponse{std::in_place_type<B3PlatformResult>, std::move(result)};
}

std::expected<void, ContractError>
validate_b3_platform_exchange(const B3PlatformRequest& request,
                              const B3PlatformResponse& response) {
    if (const auto request_valid = validate_request(request); !request_valid) {
        return std::unexpected(request_valid.error());
    }
    if (const auto* result = std::get_if<B3PlatformResult>(&response)) {
        if (const auto response_valid = validate_result(*result); !response_valid) {
            return std::unexpected(response_valid.error());
        }
    } else if (const auto response_valid =
                   detail::validate_rest_a4_error(std::get<A4ErrorEnvelope>(response));
               !response_valid) {
        return std::unexpected(response_valid.error());
    }
    if (request.correlation_id != response_correlation_id(response)) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "/correlation_id",
                                     "response correlation does not match the request"));
    }
    if (const auto* envelope = std::get_if<A4ErrorEnvelope>(&response);
        envelope && envelope->permission) {
        const auto expected_permission = request.securable + ":" + std::string{to_string(request.operation)};
        if (*envelope->permission != expected_permission) {
            return std::unexpected(error(ContractErrorCode::InvalidValue, "/error/permission",
                                         "permission does not match the request"));
        }
    }
    return {};
}

} // namespace yuzu::contracts::adr31
