#include <yuzu/contracts/adr31/b2_use_case.hpp>

#include <yuzu/contracts/adr31/contract_version.hpp>

#include "json_support.hpp"

#include <nlohmann/json.hpp>

#include <openssl/evp.h>

#include <array>
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace yuzu::contracts::adr31 {
namespace {

constexpr std::array<std::string_view, 9> kCoverageFields{
    "intended", "contacted",   "responded",    "failed", "timed_out",
    "offline",  "scope_basis", "completeness", "policy",
};
constexpr std::array<std::string_view, 2> kPolicyFields{
    "minimum_response_percent",
    "blocks_next_step_when_incomplete",
};
constexpr std::array<std::string_view, 5> kResultFields{
    "facts", "coverage", "provenance", "decisions", "proposed_plan_reference",
};

[[nodiscard]] ContractError error(ContractErrorCode code, std::string path,
                                  std::string message) {
    return ContractError{code, std::move(path), std::move(message)};
}

[[nodiscard]] std::expected<std::string, ContractError>
sha256_hash(std::string_view canonical, std::string_view error_path,
            std::string_view error_message) {
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int digest_size = 0;
    if (EVP_Digest(canonical.data(), canonical.size(), digest.data(), &digest_size, EVP_sha256(),
                   nullptr) != 1 ||
        digest_size != 32) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, std::string{error_path},
                                     std::string{error_message}));
    }

    constexpr std::string_view hex = "0123456789abcdef";
    std::string encoded{"sha256:"};
    encoded.reserve(7 + digest_size * 2);
    for (unsigned int index = 0; index < digest_size; ++index) {
        encoded.push_back(hex[digest[index] >> 4]);
        encoded.push_back(hex[digest[index] & 0x0f]);
    }
    return encoded;
}

template <std::size_t Size>
[[nodiscard]] bool is_known_field(std::string_view name,
                                  const std::array<std::string_view, Size>& known_fields) {
    for (const auto known : known_fields) {
        if (name == known)
            return true;
    }
    return false;
}

template <std::size_t Size>
[[nodiscard]] nlohmann::json
extract_extensions(const nlohmann::json& object,
                   const std::array<std::string_view, Size>& known_fields) {
    auto extensions = nlohmann::json::object();
    for (auto it = object.begin(); it != object.end(); ++it) {
        if (!is_known_field(it.key(), known_fields))
            extensions[it.key()] = *it;
    }
    return extensions;
}

template <std::size_t Size>
[[nodiscard]] std::expected<void, ContractError>
validate_extensions(const nlohmann::json& extensions,
                    const std::array<std::string_view, Size>& known_fields,
                    std::string_view parent_path) {
    if (!extensions.is_object()) {
        return std::unexpected(error(ContractErrorCode::WrongType, std::string{parent_path},
                                     "contract extensions must be an object"));
    }
    for (auto it = extensions.begin(); it != extensions.end(); ++it) {
        if (is_known_field(it.key(), known_fields)) {
            return std::unexpected(error(ContractErrorCode::InvalidValue,
                                         std::string{parent_path} + "/" + it.key(),
                                         "an extension cannot replace a contract field"));
        }
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
    if (const auto run_id =
            detail::validate_opaque_run_id(request.use_case_run_id, "/use_case_run_id");
        !run_id) {
        return std::unexpected(run_id.error());
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
    if (const auto authority = detail::reject_forbidden_transport_authority_fields_recursive(
            request.normalised_inputs, "/normalised_inputs");
        !authority) {
        return std::unexpected(authority.error());
    }
    return {};
}

[[nodiscard]] std::expected<void, ContractError>
reject_request_control_authority(const nlohmann::json& root) {
    auto control = root;
    control.erase("normalised_inputs");
    if (const auto authority = detail::reject_forbidden_authority_fields_recursive(control);
        !authority) {
        return std::unexpected(authority.error());
    }
    return detail::reject_forbidden_transport_authority_fields_recursive(control);
}

[[nodiscard]] constexpr std::string_view to_string(ScopeBasis value) noexcept {
    switch (value) {
    case ScopeBasis::Global:
        return "global";
    case ScopeBasis::AuthorityScoped:
        return "authority_scoped";
    }
    return {};
}

[[nodiscard]] constexpr std::string_view to_string(Completeness value) noexcept {
    switch (value) {
    case Completeness::Complete:
        return "complete";
    case Completeness::Partial:
        return "partial";
    case Completeness::Insufficient:
        return "insufficient";
    case Completeness::Unknown:
        return "unknown";
    }
    return {};
}

[[nodiscard]] std::expected<void, ContractError>
validate_coverage(const CoverageEnvelope& coverage) {
    constexpr std::string_view path = "/result/coverage";
    if (coverage.contacted > coverage.intended) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, std::string{path},
                                     "contacted cannot exceed intended"));
    }

    std::uint64_t classified = 0;
    // Responded, failed and timed-out endpoints were contacted. Offline is a
    // distinct known non-response, but the ADR does not require an attempted
    // delivery before Core classifies an endpoint as offline.
    for (const auto count : {coverage.responded, coverage.failed, coverage.timed_out}) {
        if (count > coverage.contacted - classified) {
            return std::unexpected(error(ContractErrorCode::InvalidValue, std::string{path},
                                         "coverage outcomes cannot exceed contacted"));
        }
        classified += count;
    }
    if (coverage.offline > coverage.intended - classified) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, std::string{path},
                                     "coverage outcomes cannot exceed intended"));
    }
    if (to_string(coverage.scope_basis).empty()) {
        return std::unexpected(error(ContractErrorCode::InvalidValue,
                                     "/result/coverage/scope_basis",
                                     "scope_basis is not a supported value"));
    }
    if (to_string(coverage.completeness).empty()) {
        return std::unexpected(error(ContractErrorCode::InvalidValue,
                                     "/result/coverage/completeness",
                                     "completeness is not a supported value"));
    }
    if (coverage.policy.minimum_response_percent == 0 ||
        coverage.policy.minimum_response_percent > 100) {
        return std::unexpected(error(ContractErrorCode::InvalidValue,
                                     "/result/coverage/policy/minimum_response_percent",
                                     "minimum_response_percent must be between 1 and 100"));
    }
    if (const auto valid_extensions = validate_extensions(coverage.policy.extensions, kPolicyFields,
                                                          "/result/coverage/policy");
        !valid_extensions) {
        return std::unexpected(valid_extensions.error());
    }
    if (const auto authority = detail::reject_forbidden_authority_fields_recursive(
            coverage.policy.extensions, "/result/coverage/policy");
        !authority) {
        return std::unexpected(authority.error());
    }
    if (const auto valid_extensions =
            validate_extensions(coverage.extensions, kCoverageFields, path);
        !valid_extensions) {
        return std::unexpected(valid_extensions.error());
    }
    if (const auto authority =
            detail::reject_forbidden_authority_fields_recursive(coverage.extensions, path);
        !authority) {
        return std::unexpected(authority.error());
    }
    if (coverage.completeness == Completeness::Complete &&
        (coverage.contacted != coverage.intended || coverage.responded != coverage.intended ||
         coverage.failed != 0 || coverage.timed_out != 0 || coverage.offline != 0)) {
        return std::unexpected(
            error(ContractErrorCode::InvalidValue, "/result/coverage/completeness",
                  "complete coverage requires every intended endpoint to respond"));
    }
    return {};
}

[[nodiscard]] std::expected<void, ContractError>
validate_result_payload(const B2UseCaseResultPayload& result) {
    if (!result.facts.is_array() && !result.facts.is_object()) {
        return std::unexpected(error(ContractErrorCode::WrongType, "/result/facts",
                                     "facts must be an array or object"));
    }
    if (!result.provenance.is_object()) {
        return std::unexpected(error(ContractErrorCode::WrongType, "/result/provenance",
                                     "provenance must be an object"));
    }
    if (!result.decisions.is_array()) {
        return std::unexpected(
            error(ContractErrorCode::WrongType, "/result/decisions", "decisions must be an array"));
    }
    if (result.proposed_plan_reference && !result.proposed_plan_reference->is_object()) {
        return std::unexpected(error(ContractErrorCode::WrongType,
                                     "/result/proposed_plan_reference",
                                     "proposed_plan_reference must be an object"));
    }
    if (const auto valid_extensions =
            validate_extensions(result.extensions, kResultFields, "/result");
        !valid_extensions) {
        return std::unexpected(valid_extensions.error());
    }
    for (const auto [value, path] :
         {std::pair{&result.provenance, std::string_view{"/result/provenance"}},
          std::pair{&result.extensions, std::string_view{"/result"}}}) {
        if (const auto authority =
                detail::reject_forbidden_authority_fields_recursive(*value, path);
            !authority) {
            return std::unexpected(authority.error());
        }
    }
    if (result.proposed_plan_reference) {
        if (const auto authority = detail::reject_forbidden_authority_fields_recursive(
                *result.proposed_plan_reference, "/result/proposed_plan_reference");
            !authority) {
            return std::unexpected(authority.error());
        }
    }
    return validate_coverage(result.coverage);
}

[[nodiscard]] std::expected<void, ContractError> validate_result(const B2UseCaseResult& result) {
    if (result.request_id.empty()) {
        return std::unexpected(
            error(ContractErrorCode::InvalidValue, "/request_id", "request_id must not be empty"));
    }
    if (const auto run_id =
            detail::validate_opaque_run_id(result.use_case_run_id, "/use_case_run_id");
        !run_id) {
        return std::unexpected(run_id.error());
    }
    if (result.result_schema_version.empty()) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "/result_schema_version",
                                     "result_schema_version must not be empty"));
    }
    if (result.finalisation_receipt.empty()) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "/finalisation_receipt",
                                     "finalisation_receipt must not be empty"));
    }
    return validate_result_payload(result.result);
}

[[nodiscard]] nlohmann::json policy_json(const CompletenessPolicy& policy) {
    auto document = policy.extensions;
    document["minimum_response_percent"] = policy.minimum_response_percent;
    document["blocks_next_step_when_incomplete"] = policy.blocks_next_step_when_incomplete;
    return document;
}

[[nodiscard]] nlohmann::json coverage_json(const CoverageEnvelope& coverage) {
    auto document = coverage.extensions;
    document["intended"] = coverage.intended;
    document["contacted"] = coverage.contacted;
    document["responded"] = coverage.responded;
    document["failed"] = coverage.failed;
    document["timed_out"] = coverage.timed_out;
    document["offline"] = coverage.offline;
    document["scope_basis"] = to_string(coverage.scope_basis);
    document["completeness"] = to_string(coverage.completeness);
    document["policy"] = policy_json(coverage.policy);
    return document;
}

[[nodiscard]] nlohmann::json result_payload_json(const B2UseCaseResultPayload& result) {
    auto payload = result.extensions;
    payload["facts"] = result.facts;
    payload["coverage"] = coverage_json(result.coverage);
    payload["provenance"] = result.provenance;
    payload["decisions"] = result.decisions;
    if (result.proposed_plan_reference) {
        payload["proposed_plan_reference"] = *result.proposed_plan_reference;
    }
    return payload;
}

[[nodiscard]] std::expected<std::uint64_t, ContractError>
required_unsigned(const nlohmann::json& object, std::string_view name,
                  std::string_view parent_path) {
    const auto it = object.find(name);
    const auto path = std::string{parent_path} + "/" + std::string{name};
    if (it == object.end()) {
        return std::unexpected(
            error(ContractErrorCode::MissingField, path, std::string{name} + " is required"));
    }
    if (it->is_null()) {
        return std::unexpected(
            error(ContractErrorCode::NullField, path, std::string{name} + " must not be null"));
    }
    if (!it->is_number_unsigned()) {
        return std::unexpected(error(ContractErrorCode::WrongType, path,
                                     std::string{name} + " must be an unsigned integer"));
    }
    return it->get<std::uint64_t>();
}

[[nodiscard]] std::expected<bool, ContractError>
required_bool(const nlohmann::json& object, std::string_view name, std::string_view parent_path) {
    const auto it = object.find(name);
    const auto path = std::string{parent_path} + "/" + std::string{name};
    if (it == object.end()) {
        return std::unexpected(
            error(ContractErrorCode::MissingField, path, std::string{name} + " is required"));
    }
    if (it->is_null()) {
        return std::unexpected(
            error(ContractErrorCode::NullField, path, std::string{name} + " must not be null"));
    }
    if (!it->is_boolean()) {
        return std::unexpected(
            error(ContractErrorCode::WrongType, path, std::string{name} + " must be a boolean"));
    }
    return it->get<bool>();
}

[[nodiscard]] std::expected<CompletenessPolicy, ContractError>
decode_policy(const nlohmann::json& coverage) {
    constexpr std::string_view path = "/result/coverage/policy";
    const auto policy_it = coverage.find("policy");
    if (policy_it == coverage.end()) {
        return std::unexpected(
            error(ContractErrorCode::MissingField, std::string{path}, "policy is required"));
    }
    if (policy_it->is_null()) {
        return std::unexpected(
            error(ContractErrorCode::NullField, std::string{path}, "policy must not be null"));
    }
    if (!policy_it->is_object()) {
        return std::unexpected(
            error(ContractErrorCode::WrongType, std::string{path}, "policy must be an object"));
    }

    const auto minimum = required_unsigned(*policy_it, "minimum_response_percent", path);
    if (!minimum)
        return std::unexpected(minimum.error());
    if (*minimum > 100) {
        return std::unexpected(error(ContractErrorCode::InvalidValue,
                                     "/result/coverage/policy/minimum_response_percent",
                                     "minimum_response_percent must be between 1 and 100"));
    }
    const auto blocks = required_bool(*policy_it, "blocks_next_step_when_incomplete", path);
    if (!blocks)
        return std::unexpected(blocks.error());

    return CompletenessPolicy{
        .minimum_response_percent = static_cast<std::uint8_t>(*minimum),
        .blocks_next_step_when_incomplete = *blocks,
        .extensions = extract_extensions(*policy_it, kPolicyFields),
    };
}

[[nodiscard]] std::expected<CoverageEnvelope, ContractError>
decode_coverage(const nlohmann::json& result) {
    const auto coverage_it = result.find("coverage");
    if (coverage_it == result.end()) {
        return std::unexpected(
            error(ContractErrorCode::MissingField, "/result/coverage", "coverage is required"));
    }
    if (coverage_it->is_null()) {
        return std::unexpected(
            error(ContractErrorCode::NullField, "/result/coverage", "coverage must not be null"));
    }
    if (!coverage_it->is_object()) {
        return std::unexpected(
            error(ContractErrorCode::WrongType, "/result/coverage", "coverage must be an object"));
    }

    const auto intended = required_unsigned(*coverage_it, "intended", "/result/coverage");
    if (!intended)
        return std::unexpected(intended.error());
    const auto contacted = required_unsigned(*coverage_it, "contacted", "/result/coverage");
    if (!contacted)
        return std::unexpected(contacted.error());
    const auto responded = required_unsigned(*coverage_it, "responded", "/result/coverage");
    if (!responded)
        return std::unexpected(responded.error());
    const auto failed = required_unsigned(*coverage_it, "failed", "/result/coverage");
    if (!failed)
        return std::unexpected(failed.error());
    const auto timed_out = required_unsigned(*coverage_it, "timed_out", "/result/coverage");
    if (!timed_out)
        return std::unexpected(timed_out.error());
    const auto offline = required_unsigned(*coverage_it, "offline", "/result/coverage");
    if (!offline)
        return std::unexpected(offline.error());

    const auto scope_basis_text =
        detail::required_string(*coverage_it, "scope_basis", "/result/coverage");
    if (!scope_basis_text)
        return std::unexpected(scope_basis_text.error());
    std::optional<ScopeBasis> scope_basis;
    if (*scope_basis_text == "global")
        scope_basis = ScopeBasis::Global;
    if (*scope_basis_text == "authority_scoped")
        scope_basis = ScopeBasis::AuthorityScoped;
    if (!scope_basis) {
        return std::unexpected(error(ContractErrorCode::InvalidValue,
                                     "/result/coverage/scope_basis",
                                     "scope_basis is not a supported value"));
    }

    const auto completeness_text =
        detail::required_string(*coverage_it, "completeness", "/result/coverage");
    if (!completeness_text)
        return std::unexpected(completeness_text.error());
    std::optional<Completeness> completeness;
    if (*completeness_text == "complete")
        completeness = Completeness::Complete;
    if (*completeness_text == "partial")
        completeness = Completeness::Partial;
    if (*completeness_text == "insufficient")
        completeness = Completeness::Insufficient;
    if (*completeness_text == "unknown")
        completeness = Completeness::Unknown;
    if (!completeness) {
        return std::unexpected(error(ContractErrorCode::InvalidValue,
                                     "/result/coverage/completeness",
                                     "completeness is not a supported value"));
    }

    auto policy = decode_policy(*coverage_it);
    if (!policy)
        return std::unexpected(policy.error());

    CoverageEnvelope coverage{
        .intended = *intended,
        .contacted = *contacted,
        .responded = *responded,
        .failed = *failed,
        .timed_out = *timed_out,
        .offline = *offline,
        .scope_basis = *scope_basis,
        .completeness = *completeness,
        .policy = std::move(*policy),
        .extensions = extract_extensions(*coverage_it, kCoverageFields),
    };
    if (const auto valid = validate_coverage(coverage); !valid) {
        return std::unexpected(valid.error());
    }
    return coverage;
}

[[nodiscard]] std::expected<nlohmann::json, ContractError>
required_result_value(const nlohmann::json& result, std::string_view name) {
    const auto it = result.find(name);
    const auto path = "/result/" + std::string{name};
    if (it == result.end()) {
        return std::unexpected(
            error(ContractErrorCode::MissingField, path, std::string{name} + " is required"));
    }
    if (it->is_null()) {
        return std::unexpected(
            error(ContractErrorCode::NullField, path, std::string{name} + " must not be null"));
    }
    return *it;
}

[[nodiscard]] std::expected<B2UseCaseResultPayload, ContractError>
decode_result_payload(const nlohmann::json& root) {
    const auto result_it = root.find("result");
    if (result_it == root.end()) {
        return std::unexpected(
            error(ContractErrorCode::MissingField, "/result", "result is required"));
    }
    if (result_it->is_null()) {
        return std::unexpected(
            error(ContractErrorCode::NullField, "/result", "result must not be null"));
    }
    if (!result_it->is_object()) {
        return std::unexpected(
            error(ContractErrorCode::WrongType, "/result", "result must be an object"));
    }

    auto facts = required_result_value(*result_it, "facts");
    if (!facts)
        return std::unexpected(facts.error());
    auto provenance = required_result_value(*result_it, "provenance");
    if (!provenance)
        return std::unexpected(provenance.error());
    auto decisions = required_result_value(*result_it, "decisions");
    if (!decisions)
        return std::unexpected(decisions.error());
    auto coverage = decode_coverage(*result_it);
    if (!coverage)
        return std::unexpected(coverage.error());

    std::optional<nlohmann::json> plan_reference;
    if (const auto plan_it = result_it->find("proposed_plan_reference");
        plan_it != result_it->end()) {
        if (plan_it->is_null()) {
            return std::unexpected(error(ContractErrorCode::NullField,
                                         "/result/proposed_plan_reference",
                                         "proposed_plan_reference must not be null"));
        }
        plan_reference = *plan_it;
    }

    B2UseCaseResultPayload payload{
        .facts = std::move(*facts),
        .coverage = std::move(*coverage),
        .provenance = std::move(*provenance),
        .decisions = std::move(*decisions),
        .proposed_plan_reference = std::move(plan_reference),
        .extensions = extract_extensions(*result_it, kResultFields),
    };
    if (const auto valid = validate_result_payload(payload); !valid) {
        return std::unexpected(valid.error());
    }
    return payload;
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
    if (const auto authority = reject_request_control_authority(*root); !authority) {
        return std::unexpected(authority.error());
    }

    auto request_id = detail::required_string(*root, "request_id");
    if (!request_id) return std::unexpected(request_id.error());
    auto run_id = detail::required_string(*root, "use_case_run_id");
    if (!run_id) return std::unexpected(run_id.error());
    if (const auto valid_run_id = detail::validate_opaque_run_id(*run_id, "/use_case_run_id");
        !valid_run_id) {
        return std::unexpected(valid_run_id.error());
    }
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

    B2UseCaseRequest request{
        .request_id = std::move(*request_id),
        .use_case_run_id = std::move(*run_id),
        .use_case = std::move(*use_case),
        .module = std::move(*module),
        .normalised_inputs = *inputs_it,
    };
    if (const auto valid = validate_request(request); !valid) {
        return std::unexpected(valid.error());
    }
    return request;
}

std::expected<std::string, ContractError>
canonical_b2_input_bytes(const B2UseCaseRequest& request) {
    if (!request.normalised_inputs.is_object()) {
        return std::unexpected(error(ContractErrorCode::WrongType, "/normalised_inputs",
                                     "normalised_inputs must be an object"));
    }
    if (const auto authority = detail::reject_forbidden_transport_authority_fields_recursive(
            request.normalised_inputs, "/normalised_inputs");
        !authority) {
        return std::unexpected(authority.error());
    }
    return detail::encode_contract_json(request.normalised_inputs);
}

std::expected<std::string, ContractError> canonical_b2_input_hash(const B2UseCaseRequest& request) {
    auto canonical = canonical_b2_input_bytes(request);
    if (!canonical)
        return std::unexpected(canonical.error());
    return sha256_hash(*canonical, "/normalised_inputs",
                       "canonical input hash could not be computed");
}

std::expected<std::string, ContractError> encode_b2_use_case_result(const B2UseCaseResult& result) {
    if (const auto valid = validate_result(result); !valid) {
        return std::unexpected(valid.error());
    }

    const nlohmann::json root{
        {"contract",
         {{"id", kB2UseCaseResult.identifier},
          {"version",
           {{"major", kB2UseCaseResult.current.major},
            {"minor", kB2UseCaseResult.current.minor}}}}},
        {"request_id", result.request_id},
        {"use_case_run_id", result.use_case_run_id},
        {"result_schema_version", result.result_schema_version},
        {"result", result_payload_json(result.result)},
        {"finalisation_receipt", result.finalisation_receipt},
    };
    return detail::encode_contract_json(root);
}

std::expected<B2UseCaseResult, ContractError>
decode_b2_use_case_result(std::string_view wire_json) {
    auto root = detail::parse_contract_json(wire_json);
    if (!root)
        return std::unexpected(root.error());
    if (!root->is_object()) {
        return std::unexpected(
            error(ContractErrorCode::RootNotObject, "", "contract body must be an object"));
    }
    if (const auto authority_fields = detail::reject_forbidden_authority_fields(*root);
        !authority_fields) {
        return std::unexpected(authority_fields.error());
    }
    if (const auto header = detail::decode_contract_header(*root, kB2UseCaseResult); !header) {
        return std::unexpected(header.error());
    }

    auto request_id = detail::required_string(*root, "request_id");
    if (!request_id)
        return std::unexpected(request_id.error());
    auto run_id = detail::required_string(*root, "use_case_run_id");
    if (!run_id)
        return std::unexpected(run_id.error());
    if (const auto valid_run_id = detail::validate_opaque_run_id(*run_id, "/use_case_run_id");
        !valid_run_id) {
        return std::unexpected(valid_run_id.error());
    }
    auto schema_version = detail::required_string(*root, "result_schema_version");
    if (!schema_version)
        return std::unexpected(schema_version.error());
    auto receipt = detail::required_string(*root, "finalisation_receipt");
    if (!receipt)
        return std::unexpected(receipt.error());
    auto payload = decode_result_payload(*root);
    if (!payload)
        return std::unexpected(payload.error());

    B2UseCaseResult result{
        .request_id = std::move(*request_id),
        .use_case_run_id = std::move(*run_id),
        .result_schema_version = std::move(*schema_version),
        .result = std::move(*payload),
        .finalisation_receipt = std::move(*receipt),
    };
    if (const auto valid = validate_result(result); !valid) {
        return std::unexpected(valid.error());
    }
    return result;
}

std::expected<std::string, ContractError> canonical_b2_result_bytes(const B2UseCaseResult& result) {
    if (const auto valid = validate_result(result); !valid) {
        return std::unexpected(valid.error());
    }
    return canonical_b2_result_bytes(result.result_schema_version, result.result);
}

std::expected<std::string, ContractError>
canonical_b2_result_bytes(std::string_view result_schema_version,
                          const B2UseCaseResultPayload& result) {
    if (result_schema_version.empty()) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "/result_schema_version",
                                     "result_schema_version must not be empty"));
    }
    if (const auto valid = validate_result_payload(result); !valid) {
        return std::unexpected(valid.error());
    }
    const nlohmann::json hash_domain{
        {"result_schema_version", result_schema_version},
        {"result", result_payload_json(result)},
    };
    return detail::encode_contract_json(hash_domain);
}

std::expected<std::string, ContractError> canonical_b2_result_hash(const B2UseCaseResult& result) {
    auto canonical = canonical_b2_result_bytes(result);
    if (!canonical)
        return std::unexpected(canonical.error());
    return sha256_hash(*canonical, "/result", "canonical result hash could not be computed");
}

std::expected<std::string, ContractError>
canonical_b2_result_hash(std::string_view result_schema_version,
                         const B2UseCaseResultPayload& result) {
    auto canonical = canonical_b2_result_bytes(result_schema_version, result);
    if (!canonical)
        return std::unexpected(canonical.error());
    return sha256_hash(*canonical, "/result", "canonical result hash could not be computed");
}

} // namespace yuzu::contracts::adr31
