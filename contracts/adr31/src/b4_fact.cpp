#include <yuzu/contracts/adr31/b4_fact.hpp>

#include <yuzu/contracts/adr31/contract_version.hpp>

#include "json_support.hpp"

#include <nlohmann/json.hpp>

#include <array>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace yuzu::contracts::adr31 {
namespace {

ContractError error(ContractErrorCode code, std::string path, std::string message) {
    return ContractError{code, std::move(path), std::move(message)};
}

std::expected<void, ContractError> validate_reference(const VersionedIdentity& reference,
                                                      std::string_view path) {
    if (reference.id.empty() || reference.version.empty()) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, std::string{path},
                                     "id and version must not be empty"));
    }
    return {};
}

std::expected<void, ContractError> reject_control_authority(const nlohmann::json& value,
                                                            std::string_view path = {}) {
    if (const auto authority = detail::reject_forbidden_authority_fields_recursive(value, path);
        !authority) {
        return std::unexpected(authority.error());
    }
    return detail::reject_forbidden_transport_authority_fields_recursive(value, path);
}

std::expected<void, ContractError> validate_request(const B4FactRequest& request) {
    if (const auto correlation = detail::validate_correlation_id(request.correlation_id);
        !correlation) {
        return std::unexpected(correlation.error());
    }
    if (const auto run_id =
            detail::validate_opaque_run_id(request.use_case_run_id, "/use_case_run_id");
        !run_id) {
        return std::unexpected(run_id.error());
    }
    if (const auto module = validate_reference(request.module, "/module"); !module) {
        return std::unexpected(module.error());
    }
    if (request.module_manifest_hash.empty()) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "/module_manifest_hash",
                                     "module_manifest_hash must not be empty"));
    }
    if (const auto capability = validate_reference(request.capability, "/capability");
        !capability) {
        return std::unexpected(capability.error());
    }
    if (request.input_hash && request.input_hash->empty()) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "/input_hash",
                                     "input_hash must not be empty when present"));
    }
    if (!request.parameters.is_object()) {
        return std::unexpected(
            error(ContractErrorCode::WrongType, "/parameters", "parameters must be an object"));
    }
    if (!request.scope.is_object()) {
        return std::unexpected(
            error(ContractErrorCode::WrongType, "/scope", "scope must be an object"));
    }
    if (const auto authority = reject_control_authority(request.scope, "/scope"); !authority) {
        return std::unexpected(authority.error());
    }
    if (const auto authority = detail::reject_forbidden_transport_authority_fields_recursive(
            request.parameters, "/parameters");
        !authority) {
        return std::unexpected(authority.error());
    }
    return {};
}

nlohmann::json reference_json(const VersionedIdentity& reference) {
    return nlohmann::json{{"id", reference.id}, {"version", reference.version}};
}

std::expected<VersionedIdentity, ContractError> decode_reference(const nlohmann::json& root,
                                                                 std::string_view name) {
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
    if (const auto authority = reject_control_authority(*it, path); !authority) {
        return std::unexpected(authority.error());
    }

    auto id = detail::required_string(*it, "id", path);
    if (!id)
        return std::unexpected(id.error());
    auto version = detail::required_string(*it, "version", path);
    if (!version)
        return std::unexpected(version.error());
    VersionedIdentity reference{.id = std::move(*id), .version = std::move(*version)};
    if (const auto valid = validate_reference(reference, path); !valid) {
        return std::unexpected(valid.error());
    }
    return reference;
}

std::expected<nlohmann::json, ContractError> decode_required_object(const nlohmann::json& root,
                                                                    std::string_view name) {
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
    return *it;
}

std::expected<std::optional<std::string>, ContractError>
decode_optional_string(const nlohmann::json& root, std::string_view name) {
    const auto it = root.find(name);
    const auto path = "/" + std::string{name};
    if (it == root.end())
        return std::optional<std::string>{};
    if (it->is_null()) {
        return std::unexpected(error(ContractErrorCode::NullField, path,
                                     std::string{name} + " must not be null when present"));
    }
    if (!it->is_string()) {
        return std::unexpected(
            error(ContractErrorCode::WrongType, path, std::string{name} + " must be a string"));
    }
    return std::optional<std::string>{it->get<std::string>()};
}

std::expected<void, ContractError> reject_control_extension_authority(const nlohmann::json& root) {
    auto extensions = root;
    constexpr std::array<std::string_view, 9> known_fields{
        "contract",   "correlation_id", "use_case_run_id", "module", "module_manifest_hash",
        "capability", "input_hash",     "parameters",      "scope",
    };
    for (const auto field : known_fields)
        extensions.erase(field);
    return reject_control_authority(extensions);
}

std::expected<std::string, ContractError> encode_fact_request(const B4FactRequest& request) {
    if (const auto valid = validate_request(request); !valid) {
        return std::unexpected(valid.error());
    }
    nlohmann::json root{
        {"contract",
         {{"id", kB4Fact.identifier},
          {"version", {{"major", kB4Fact.current.major}, {"minor", kB4Fact.current.minor}}}}},
        {"correlation_id", request.correlation_id},
        {"use_case_run_id", request.use_case_run_id},
        {"module", reference_json(request.module)},
        {"module_manifest_hash", request.module_manifest_hash},
        {"capability", reference_json(request.capability)},
        {"parameters", request.parameters},
        {"scope", request.scope},
    };
    if (request.input_hash)
        root["input_hash"] = *request.input_hash;
    return detail::encode_contract_json(root);
}

} // namespace

B4FactCall::B4FactCall(std::string body, B4FactTransportAuth authentication) noexcept
    : body_(std::move(body)), engine_credential_(std::move(authentication.engine_credential)) {
    if (authentication.invocation_start) {
        invocation_grant_.emplace(std::move(authentication.invocation_start->invocation_grant));
    }
}

std::expected<B4FactCall, B4FactCallError> make_b4_fact_call(B4FactRequest request,
                                                             B4FactTransportAuth authentication) {
    if (!authentication.engine_credential.valid()) {
        return std::unexpected(B4FactCallError{B4FactAuthBindingError::MissingEngineCredential});
    }
    if (authentication.engine_credential.kind() != TransportAuthKind::EngineCredential) {
        return std::unexpected(B4FactCallError{B4FactAuthBindingError::WrongEngineCredentialKind});
    }
    if (authentication.invocation_start &&
        !authentication.invocation_start->invocation_grant.valid()) {
        return std::unexpected(B4FactCallError{B4FactAuthBindingError::InvalidInvocationGrant});
    }
    if (authentication.invocation_start &&
        authentication.invocation_start->invocation_grant.kind() !=
            TransportAuthKind::InvocationGrant) {
        return std::unexpected(B4FactCallError{B4FactAuthBindingError::WrongInvocationGrantKind});
    }
    if (request.input_hash) {
        return std::unexpected(B4FactCallError{B4FactAuthBindingError::CallerAuthoredInputHash});
    }
    if (authentication.invocation_start) {
        const auto& b2_request = authentication.invocation_start->received_b2_request;
        if (request.use_case_run_id != b2_request.use_case_run_id) {
            return std::unexpected(B4FactCallError{B4FactAuthBindingError::StartRunMismatch});
        }
        if (request.module != b2_request.module) {
            return std::unexpected(B4FactCallError{B4FactAuthBindingError::StartModuleMismatch});
        }
        auto input_hash = canonical_b2_input_hash(b2_request);
        if (!input_hash) {
            return std::unexpected(
                B4FactCallError{std::in_place_type<ContractError>, std::move(input_hash.error())});
        }
        request.input_hash = std::move(*input_hash);
    }

    auto body = encode_fact_request(request);
    if (!body) {
        return std::unexpected(
            B4FactCallError{std::in_place_type<ContractError>, std::move(body.error())});
    }
    return B4FactCall{std::move(*body), std::move(authentication)};
}

std::expected<B4FactRequest, ContractError> decode_b4_fact_request(std::string_view wire_json) {
    auto root = detail::parse_contract_json(wire_json);
    if (!root)
        return std::unexpected(root.error());
    if (!root->is_object()) {
        return std::unexpected(
            error(ContractErrorCode::RootNotObject, "", "contract body must be an object"));
    }
    if (const auto header = detail::decode_contract_header(*root, kB4Fact); !header) {
        return std::unexpected(header.error());
    }
    if (const auto authority = detail::reject_forbidden_authority_fields(*root); !authority) {
        return std::unexpected(authority.error());
    }
    if (const auto authority = reject_control_authority(root->at("contract"), "/contract");
        !authority) {
        return std::unexpected(authority.error());
    }
    if (const auto authority = reject_control_extension_authority(*root); !authority) {
        return std::unexpected(authority.error());
    }

    auto correlation = detail::required_string(*root, "correlation_id");
    if (!correlation)
        return std::unexpected(correlation.error());
    auto run_id = detail::required_string(*root, "use_case_run_id");
    if (!run_id)
        return std::unexpected(run_id.error());
    auto module = decode_reference(*root, "module");
    if (!module)
        return std::unexpected(module.error());
    auto manifest_hash = detail::required_string(*root, "module_manifest_hash");
    if (!manifest_hash)
        return std::unexpected(manifest_hash.error());
    auto capability = decode_reference(*root, "capability");
    if (!capability)
        return std::unexpected(capability.error());
    auto input_hash = decode_optional_string(*root, "input_hash");
    if (!input_hash)
        return std::unexpected(input_hash.error());
    auto parameters = decode_required_object(*root, "parameters");
    if (!parameters)
        return std::unexpected(parameters.error());
    auto scope = decode_required_object(*root, "scope");
    if (!scope)
        return std::unexpected(scope.error());

    B4FactRequest request{
        .correlation_id = std::move(*correlation),
        .use_case_run_id = std::move(*run_id),
        .module = std::move(*module),
        .module_manifest_hash = std::move(*manifest_hash),
        .capability = std::move(*capability),
        .input_hash = std::move(*input_hash),
        .parameters = std::move(*parameters),
        .scope = std::move(*scope),
    };
    if (const auto valid = validate_request(request); !valid) {
        return std::unexpected(valid.error());
    }
    return request;
}

} // namespace yuzu::contracts::adr31
