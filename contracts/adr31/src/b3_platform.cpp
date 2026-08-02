#include <yuzu/contracts/adr31/b3_platform.hpp>

#include <yuzu/contracts/adr31/contract_version.hpp>

#include <nlohmann/json.hpp>

#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <utility>

namespace yuzu::contracts::adr31 {
namespace {

constexpr std::size_t kMaxWireBytes = 64 * 1024;

ContractError error(ContractErrorCode code, std::string path, std::string message) {
    return ContractError{code, std::move(path), std::move(message)};
}

std::expected<std::string, ContractError> required_string(const nlohmann::json& object,
                                                          std::string_view name,
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

std::expected<std::uint16_t, ContractError> version_part(const nlohmann::json& object,
                                                         std::string_view name) {
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

std::expected<ContractVersion, ContractError>
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
    if (*id != kB3PlatformRequest.identifier) {
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

    const ContractVersion version{*major, *minor};
    if (!supports(kB3PlatformRequest, version)) {
        return std::unexpected(error(ContractErrorCode::UnsupportedVersion, "/contract/version",
                                     "unsupported contract version"));
    }
    return version;
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
    return root.dump();
}

std::expected<B3PlatformRequest, ContractError>
decode_b3_platform_request(std::string_view wire_json) {
    if (wire_json.size() > kMaxWireBytes) {
        return std::unexpected(
            error(ContractErrorCode::TooLarge, "", "contract body exceeds 65536 bytes"));
    }

    const auto root = nlohmann::json::parse(wire_json, nullptr, false);
    if (root.is_discarded()) {
        return std::unexpected(
            error(ContractErrorCode::MalformedJson, "", "contract body is not valid JSON"));
    }
    if (!root.is_object()) {
        return std::unexpected(
            error(ContractErrorCode::RootNotObject, "", "contract body must be an object"));
    }

    const auto version = decode_contract_header(root);
    if (!version) return std::unexpected(version.error());

    auto correlation_id = required_string(root, "correlation_id");
    if (!correlation_id) return std::unexpected(correlation_id.error());
    auto securable = required_string(root, "securable");
    if (!securable) return std::unexpected(securable.error());
    auto operation = required_string(root, "operation");
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

    const auto scope_it = root.find("scope");
    if (scope_it == root.end()) {
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
