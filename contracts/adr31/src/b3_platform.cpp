#include <yuzu/contracts/adr31/b3_platform.hpp>

#include <yuzu/contracts/adr31/contract_version.hpp>

#include "json_support.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <limits>
#include <optional>
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

std::expected<void, ContractError> validate_error(const A4ErrorEnvelope& envelope) {
    if (envelope.code != 202 && (envelope.code < 400 || envelope.code > 599)) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "/error/code",
                                     "A4 code must be HTTP 202 or an error status"));
    }
    if (envelope.message.empty()) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "/error/message",
                                     "A4 message must not be empty"));
    }
    if (const auto correlation =
            detail::validate_correlation_id(envelope.correlation_id, "/error/correlation_id");
        !correlation) {
        return std::unexpected(correlation.error());
    }
    if (envelope.retry_after_ms && *envelope.retry_after_ms < 0) {
        return std::unexpected(error(ContractErrorCode::InvalidValue,
                                     "/error/retry_after_ms",
                                     "retry_after_ms must not be negative"));
    }

    const auto require_nonempty = [&](const std::optional<std::string>& value,
                                      std::string_view name) -> std::expected<void, ContractError> {
        if (value && value->empty()) {
            return std::unexpected(error(ContractErrorCode::InvalidValue,
                                         "/error/" + std::string{name},
                                         std::string{name} + " must not be empty"));
        }
        return {};
    };
    for (const auto [value, name] :
         {std::pair{&envelope.remediation, std::string_view{"remediation"}},
          std::pair{&envelope.permission, std::string_view{"permission"}},
          std::pair{&envelope.approval_id, std::string_view{"approval_id"}},
          std::pair{&envelope.status_url, std::string_view{"status_url"}}}) {
        if (const auto valid = require_nonempty(*value, name); !valid) {
            return std::unexpected(valid.error());
        }
    }

    if (envelope.approval_id.has_value() != envelope.status_url.has_value()) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "/error",
                                     "approval_id and status_url must appear together"));
    }
    if (envelope.code == 202 && !envelope.approval_id) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "/error/approval_id",
                                     "approval-required errors need a pollable approval"));
    }
    if (envelope.code != 202 && envelope.approval_id) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "/error/approval_id",
                                     "approval fields require HTTP 202"));
    }
    if (envelope.permission && envelope.code != 403) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "/error/permission",
                                     "permission is valid only on HTTP 403"));
    }
    return {};
}

std::expected<void, ContractError> validate_meta(const nlohmann::json& root) {
    const auto meta_it = root.find("meta");
    if (meta_it == root.end()) {
        return std::unexpected(
            error(ContractErrorCode::MissingField, "/meta", "meta is required"));
    }
    if (meta_it->is_null()) {
        return std::unexpected(
            error(ContractErrorCode::NullField, "/meta", "meta must not be null"));
    }
    if (!meta_it->is_object()) {
        return std::unexpected(
            error(ContractErrorCode::WrongType, "/meta", "meta must be an object"));
    }
    const auto api_version = detail::required_string(*meta_it, "api_version", "/meta");
    if (!api_version) return std::unexpected(api_version.error());
    if (*api_version != "v1") {
        return std::unexpected(error(ContractErrorCode::UnsupportedVersion, "/meta/api_version",
                                     "unsupported REST API version"));
    }
    return {};
}

std::expected<std::optional<std::string>, ContractError>
decode_optional_string(const nlohmann::json& object, std::string_view name) {
    const auto it = object.find(name);
    if (it == object.end() || it->is_null()) return std::optional<std::string>{};
    const auto path = "/error/" + std::string{name};
    if (!it->is_string()) {
        return std::unexpected(error(ContractErrorCode::WrongType, path,
                                     std::string{name} + " must be a string or null"));
    }
    auto value = it->get<std::string>();
    if (value.empty()) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, path,
                                     std::string{name} + " must not be empty"));
    }
    return std::optional<std::string>{std::move(value)};
}

std::expected<std::int32_t, ContractError> decode_error_code(const nlohmann::json& error_object) {
    const auto it = error_object.find("code");
    if (it == error_object.end()) {
        return std::unexpected(
            error(ContractErrorCode::MissingField, "/error/code", "code is required"));
    }
    if (it->is_null()) {
        return std::unexpected(
            error(ContractErrorCode::NullField, "/error/code", "code must not be null"));
    }
    if (!it->is_number_integer() && !it->is_number_unsigned()) {
        return std::unexpected(error(ContractErrorCode::WrongType, "/error/code",
                                     "code must be an integer"));
    }
    if (it->is_number_unsigned()) {
        const auto value = it->get<std::uint64_t>();
        if (value > static_cast<std::uint64_t>(std::numeric_limits<std::int32_t>::max())) {
            return std::unexpected(error(ContractErrorCode::InvalidValue, "/error/code",
                                         "code is outside the supported range"));
        }
        return static_cast<std::int32_t>(value);
    }
    const auto value = it->get<std::int64_t>();
    if (value < std::numeric_limits<std::int32_t>::min() ||
        value > std::numeric_limits<std::int32_t>::max()) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "/error/code",
                                     "code is outside the supported range"));
    }
    return static_cast<std::int32_t>(value);
}

std::expected<std::optional<std::int64_t>, ContractError>
decode_retry_after(const nlohmann::json& error_object) {
    const auto it = error_object.find("retry_after_ms");
    if (it == error_object.end()) {
        return std::unexpected(error(ContractErrorCode::MissingField, "/error/retry_after_ms",
                                     "retry_after_ms is required"));
    }
    if (it->is_null()) return std::optional<std::int64_t>{};
    if (!it->is_number_integer() && !it->is_number_unsigned()) {
        return std::unexpected(error(ContractErrorCode::WrongType, "/error/retry_after_ms",
                                     "retry_after_ms must be an integer or null"));
    }
    if (it->is_number_unsigned()) {
        const auto value = it->get<std::uint64_t>();
        if (value > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
            return std::unexpected(error(ContractErrorCode::InvalidValue,
                                         "/error/retry_after_ms",
                                         "retry_after_ms is outside the supported range"));
        }
        return std::optional<std::int64_t>{static_cast<std::int64_t>(value)};
    }
    const auto value = it->get<std::int64_t>();
    if (value < 0) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "/error/retry_after_ms",
                                     "retry_after_ms must not be negative"));
    }
    return std::optional<std::int64_t>{value};
}

std::expected<A4ErrorEnvelope, ContractError> decode_a4_error(const nlohmann::json& root) {
    const auto error_it = root.find("error");
    if (error_it == root.end()) {
        return std::unexpected(
            error(ContractErrorCode::MissingField, "/error", "error is required"));
    }
    if (error_it->is_null()) {
        return std::unexpected(
            error(ContractErrorCode::NullField, "/error", "error must not be null"));
    }
    if (!error_it->is_object()) {
        return std::unexpected(
            error(ContractErrorCode::WrongType, "/error", "error must be an object"));
    }

    auto code = decode_error_code(*error_it);
    if (!code) return std::unexpected(code.error());
    auto message = detail::required_string(*error_it, "message", "/error");
    if (!message) return std::unexpected(message.error());
    auto correlation = detail::required_string(*error_it, "correlation_id", "/error");
    if (!correlation) return std::unexpected(correlation.error());
    auto retry = decode_retry_after(*error_it);
    if (!retry) return std::unexpected(retry.error());
    auto remediation = decode_optional_string(*error_it, "remediation");
    if (!remediation) return std::unexpected(remediation.error());
    auto permission = decode_optional_string(*error_it, "permission");
    if (!permission) return std::unexpected(permission.error());
    auto approval_id = decode_optional_string(*error_it, "approval_id");
    if (!approval_id) return std::unexpected(approval_id.error());
    auto status_url = decode_optional_string(*error_it, "status_url");
    if (!status_url) return std::unexpected(status_url.error());

    A4ErrorEnvelope envelope{
        .code = *code,
        .message = std::move(*message),
        .correlation_id = std::move(*correlation),
        .retry_after_ms = *retry,
        .remediation = std::move(*remediation),
        .permission = std::move(*permission),
        .approval_id = std::move(*approval_id),
        .status_url = std::move(*status_url),
    };
    if (const auto valid = validate_error(envelope); !valid) {
        return std::unexpected(valid.error());
    }
    return envelope;
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
    if (const auto valid = validate_error(envelope); !valid) {
        return std::unexpected(valid.error());
    }
    nlohmann::json error_object{
        {"code", envelope.code},
        {"message", envelope.message},
        {"correlation_id", envelope.correlation_id},
        {"retry_after_ms", nullptr},
    };
    if (envelope.retry_after_ms) error_object["retry_after_ms"] = *envelope.retry_after_ms;
    if (envelope.remediation) error_object["remediation"] = *envelope.remediation;
    if (envelope.permission) error_object["permission"] = *envelope.permission;
    if (envelope.approval_id) error_object["approval_id"] = *envelope.approval_id;
    if (envelope.status_url) error_object["status_url"] = *envelope.status_url;

    const nlohmann::json root{
        {"error", std::move(error_object)},
        {"meta", {{"api_version", "v1"}}},
    };
    return detail::encode_contract_json(root);
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
        if (const auto authority_fields = detail::reject_forbidden_authority_fields(*root);
            !authority_fields) {
            return std::unexpected(authority_fields.error());
        }
        if (const auto meta = validate_meta(*root); !meta) {
            return std::unexpected(meta.error());
        }
        auto envelope = decode_a4_error(*root);
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
    if (const auto meta = validate_meta(*root); !meta) {
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
    } else if (const auto response_valid = validate_error(std::get<A4ErrorEnvelope>(response));
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
