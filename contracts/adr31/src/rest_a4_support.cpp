#include "rest_a4_support.hpp"

#include "json_support.hpp"

#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace yuzu::contracts::adr31::detail {
namespace {

ContractError error(ContractErrorCode code, std::string path, std::string message) {
    return ContractError{code, std::move(path), std::move(message)};
}

std::expected<std::optional<std::string>, ContractError>
decode_optional_string(const nlohmann::json& object, std::string_view name) {
    const auto it = object.find(name);
    if (it == object.end() || it->is_null())
        return std::optional<std::string>{};
    const auto path = "/error/" + std::string{name};
    if (!it->is_string()) {
        return std::unexpected(error(ContractErrorCode::WrongType, path,
                                     std::string{name} + " must be a string or null"));
    }
    auto value = it->get<std::string>();
    if (value.empty()) {
        return std::unexpected(
            error(ContractErrorCode::InvalidValue, path, std::string{name} + " must not be empty"));
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
        return std::unexpected(
            error(ContractErrorCode::WrongType, "/error/code", "code must be an integer"));
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
    if (it->is_null())
        return std::optional<std::int64_t>{};
    if (!it->is_number_integer() && !it->is_number_unsigned()) {
        return std::unexpected(error(ContractErrorCode::WrongType, "/error/retry_after_ms",
                                     "retry_after_ms must be an integer or null"));
    }
    if (it->is_number_unsigned()) {
        const auto value = it->get<std::uint64_t>();
        if (value > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
            return std::unexpected(error(ContractErrorCode::InvalidValue, "/error/retry_after_ms",
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

} // namespace

std::expected<void, ContractError> validate_rest_a4_error(const A4ErrorEnvelope& envelope) {
    if (envelope.code != 202 && (envelope.code < 400 || envelope.code > 599)) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "/error/code",
                                     "A4 code must be HTTP 202 or an error status"));
    }
    if (envelope.message.empty()) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "/error/message",
                                     "A4 message must not be empty"));
    }
    if (const auto correlation =
            validate_correlation_id(envelope.correlation_id, "/error/correlation_id");
        !correlation) {
        return std::unexpected(correlation.error());
    }
    if (envelope.retry_after_ms && *envelope.retry_after_ms < 0) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "/error/retry_after_ms",
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

std::expected<void, ContractError> validate_rest_v1_response_meta(const nlohmann::json& root) {
    const auto meta_it = root.find("meta");
    if (meta_it == root.end()) {
        return std::unexpected(error(ContractErrorCode::MissingField, "/meta", "meta is required"));
    }
    if (meta_it->is_null()) {
        return std::unexpected(
            error(ContractErrorCode::NullField, "/meta", "meta must not be null"));
    }
    if (!meta_it->is_object()) {
        return std::unexpected(
            error(ContractErrorCode::WrongType, "/meta", "meta must be an object"));
    }
    const auto api_version = required_string(*meta_it, "api_version", "/meta");
    if (!api_version)
        return std::unexpected(api_version.error());
    if (*api_version != "v1") {
        return std::unexpected(error(ContractErrorCode::UnsupportedVersion, "/meta/api_version",
                                     "unsupported REST API version"));
    }
    return {};
}

std::expected<nlohmann::json, ContractError>
encode_rest_a4_error_document(const A4ErrorEnvelope& envelope) {
    if (const auto valid = validate_rest_a4_error(envelope); !valid) {
        return std::unexpected(valid.error());
    }
    nlohmann::json error_object{
        {"code", envelope.code},
        {"message", envelope.message},
        {"correlation_id", envelope.correlation_id},
        {"retry_after_ms", nullptr},
    };
    if (envelope.retry_after_ms)
        error_object["retry_after_ms"] = *envelope.retry_after_ms;
    if (envelope.remediation)
        error_object["remediation"] = *envelope.remediation;
    if (envelope.permission)
        error_object["permission"] = *envelope.permission;
    if (envelope.approval_id)
        error_object["approval_id"] = *envelope.approval_id;
    if (envelope.status_url)
        error_object["status_url"] = *envelope.status_url;

    return nlohmann::json{
        {"error", std::move(error_object)},
        {"meta", {{"api_version", "v1"}}},
    };
}

std::expected<A4ErrorEnvelope, ContractError>
decode_rest_a4_error_document(const nlohmann::json& root) {
    if (!root.is_object()) {
        return std::unexpected(
            error(ContractErrorCode::RootNotObject, "", "contract body must be an object"));
    }
    if (root.contains("contract")) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "/contract",
                                     "A4 errors do not carry a contract header"));
    }
    if (const auto authority_fields = reject_forbidden_authority_fields(root);
        !authority_fields) {
        return std::unexpected(authority_fields.error());
    }
    if (const auto meta = validate_rest_v1_response_meta(root); !meta) {
        return std::unexpected(meta.error());
    }
    // Unknown error members may carry domain details; meta is the control-only
    // extension point where authority-shaped additions are never valid.
    if (const auto authority_fields =
            reject_forbidden_authority_fields_recursive(*root.find("meta"), "/meta");
        !authority_fields) {
        return std::unexpected(authority_fields.error());
    }

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
    if (!code)
        return std::unexpected(code.error());
    auto message = required_string(*error_it, "message", "/error");
    if (!message)
        return std::unexpected(message.error());
    auto correlation = required_string(*error_it, "correlation_id", "/error");
    if (!correlation)
        return std::unexpected(correlation.error());
    auto retry = decode_retry_after(*error_it);
    if (!retry)
        return std::unexpected(retry.error());
    auto remediation = decode_optional_string(*error_it, "remediation");
    if (!remediation)
        return std::unexpected(remediation.error());
    auto permission = decode_optional_string(*error_it, "permission");
    if (!permission)
        return std::unexpected(permission.error());
    auto approval_id = decode_optional_string(*error_it, "approval_id");
    if (!approval_id)
        return std::unexpected(approval_id.error());
    auto status_url = decode_optional_string(*error_it, "status_url");
    if (!status_url)
        return std::unexpected(status_url.error());

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
    if (const auto valid = validate_rest_a4_error(envelope); !valid) {
        return std::unexpected(valid.error());
    }
    return envelope;
}

} // namespace yuzu::contracts::adr31::detail
