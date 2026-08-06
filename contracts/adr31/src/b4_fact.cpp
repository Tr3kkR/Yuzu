#include <yuzu/contracts/adr31/b4_fact.hpp>

#include <yuzu/contracts/adr31/contract_version.hpp>

#include "json_support.hpp"
#include "rest_a4_support.hpp"

#include <nlohmann/json.hpp>

#include <array>
#include <cstdint>
#include <expected>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace yuzu::contracts::adr31 {
namespace {

ContractError error(ContractErrorCode code, std::string path, std::string message) {
    return ContractError{code, std::move(path), std::move(message)};
}

constexpr std::array<std::string_view, 9> kCoverageFields{
    "intended", "contacted",   "responded",    "failed", "timed_out",
    "offline",  "scope_basis", "completeness", "policy",
};
constexpr std::array<std::string_view, 2> kPolicyFields{
    "minimum_response_percent",
    "blocks_next_step_when_incomplete",
};
constexpr std::array<std::string_view, 12> kFactResultFields{
    "contract",   "correlation_id", "use_case_run_id", "module",      "module_manifest_hash",
    "capability", "facts",          "fact_refs",       "scope_basis", "coverage",
    "provenance", "error",
};

template <std::size_t Size>
bool is_known_field(std::string_view name, const std::array<std::string_view, Size>& known_fields) {
    for (const auto known : known_fields) {
        if (name == known)
            return true;
    }
    return false;
}

template <std::size_t Size>
nlohmann::json extract_extensions(const nlohmann::json& object,
                                  const std::array<std::string_view, Size>& known_fields) {
    auto extensions = nlohmann::json::object();
    for (auto it = object.begin(); it != object.end(); ++it) {
        if (!is_known_field(it.key(), known_fields))
            extensions[it.key()] = *it;
    }
    return extensions;
}

template <std::size_t Size>
std::expected<void, ContractError>
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

std::string normalise_control_name(std::string_view name) {
    std::string result;
    result.reserve(name.size());
    for (const unsigned char byte : name) {
        if (byte >= 'A' && byte <= 'Z') {
            result.push_back(static_cast<char>(byte - 'A' + 'a'));
        } else if ((byte >= 'a' && byte <= 'z') || (byte >= '0' && byte <= '9')) {
            result.push_back(static_cast<char>(byte));
        }
    }
    return result;
}

std::string escape_json_pointer(std::string_view token) {
    std::string escaped;
    escaped.reserve(token.size());
    for (const char byte : token) {
        if (byte == '~') {
            escaped += "~0";
        } else if (byte == '/') {
            escaped += "~1";
        } else {
            escaped.push_back(byte);
        }
    }
    return escaped;
}

std::expected<void, ContractError>
reject_confinement_oracle_fields(const nlohmann::json& value, std::string_view parent_path = {}) {
    constexpr auto forbidden = std::to_array<std::string_view>({
        "fleetsize",       "fleettotal",     "globalcount",     "globaltotal",
        "haswithheld",     "matched",        "matchedcount",    "outofscope",
        "outofscopecount", "removed",        "removedcount",    "requestedbeforeconfinement",
        "truncated",       "truncatedcount", "unfilteredcount", "wastruncated",
        "withheld",        "withheldcount",  "withheldexists",
    });
    struct Pending {
        const nlohmann::json* value;
        std::string path;
    };
    std::vector<Pending> pending{{&value, std::string{parent_path}}};
    while (!pending.empty()) {
        auto current = std::move(pending.back());
        pending.pop_back();
        if (current.value->is_object()) {
            for (auto it = current.value->begin(); it != current.value->end(); ++it) {
                const auto path = current.path + "/" + escape_json_pointer(it.key());
                const auto normalised = normalise_control_name(it.key());
                for (const auto name : forbidden) {
                    if (normalised == name) {
                        return std::unexpected(error(ContractErrorCode::InvalidValue, path,
                                                     "confinement oracle fields are forbidden"));
                    }
                }
                pending.push_back(Pending{&*it, path});
            }
        } else if (current.value->is_array()) {
            for (std::size_t index = 0; index < current.value->size(); ++index) {
                pending.push_back(
                    Pending{&(*current.value)[index], current.path + "/" + std::to_string(index)});
            }
        }
    }
    return {};
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

constexpr std::string_view scope_basis_text(ScopeBasis value) noexcept {
    switch (value) {
    case ScopeBasis::Global:
        return "global";
    case ScopeBasis::AuthorityScoped:
        return "authority_scoped";
    }
    return {};
}

constexpr std::string_view completeness_text(Completeness value) noexcept {
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

std::expected<void, ContractError> validate_coverage(const CoverageEnvelope& coverage,
                                                     std::string_view path) {
    if (coverage.contacted > coverage.intended) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, std::string{path},
                                     "contacted cannot exceed intended"));
    }

    std::uint64_t classified = 0;
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
    if (scope_basis_text(coverage.scope_basis).empty()) {
        return std::unexpected(error(ContractErrorCode::InvalidValue,
                                     std::string{path} + "/scope_basis",
                                     "scope_basis is not a supported value"));
    }
    if (completeness_text(coverage.completeness).empty()) {
        return std::unexpected(error(ContractErrorCode::InvalidValue,
                                     std::string{path} + "/completeness",
                                     "completeness is not a supported value"));
    }
    if (coverage.policy.minimum_response_percent == 0 ||
        coverage.policy.minimum_response_percent > 100) {
        return std::unexpected(error(ContractErrorCode::InvalidValue,
                                     std::string{path} + "/policy/minimum_response_percent",
                                     "minimum_response_percent must be between 1 and 100"));
    }
    const auto policy_path = std::string{path} + "/policy";
    if (const auto extensions =
            validate_extensions(coverage.policy.extensions, kPolicyFields, policy_path);
        !extensions) {
        return std::unexpected(extensions.error());
    }
    if (const auto authority = reject_control_authority(coverage.policy.extensions, policy_path);
        !authority) {
        return std::unexpected(authority.error());
    }
    if (const auto oracle =
            reject_confinement_oracle_fields(coverage.policy.extensions, policy_path);
        !oracle) {
        return std::unexpected(oracle.error());
    }
    if (const auto extensions = validate_extensions(coverage.extensions, kCoverageFields, path);
        !extensions) {
        return std::unexpected(extensions.error());
    }
    if (const auto authority = reject_control_authority(coverage.extensions, path); !authority) {
        return std::unexpected(authority.error());
    }
    if (const auto oracle = reject_confinement_oracle_fields(coverage.extensions, path); !oracle) {
        return std::unexpected(oracle.error());
    }
    if (coverage.completeness == Completeness::Complete &&
        (coverage.contacted != coverage.intended || coverage.responded != coverage.intended ||
         coverage.failed != 0 || coverage.timed_out != 0 || coverage.offline != 0)) {
        return std::unexpected(
            error(ContractErrorCode::InvalidValue, std::string{path} + "/completeness",
                  "complete coverage requires every intended endpoint to respond"));
    }
    return {};
}

nlohmann::json coverage_json(const CoverageEnvelope& coverage) {
    auto policy = coverage.policy.extensions;
    policy["minimum_response_percent"] = coverage.policy.minimum_response_percent;
    policy["blocks_next_step_when_incomplete"] = coverage.policy.blocks_next_step_when_incomplete;

    auto document = coverage.extensions;
    document["intended"] = coverage.intended;
    document["contacted"] = coverage.contacted;
    document["responded"] = coverage.responded;
    document["failed"] = coverage.failed;
    document["timed_out"] = coverage.timed_out;
    document["offline"] = coverage.offline;
    document["scope_basis"] = scope_basis_text(coverage.scope_basis);
    document["completeness"] = completeness_text(coverage.completeness);
    document["policy"] = std::move(policy);
    return document;
}

std::expected<std::uint64_t, ContractError> required_unsigned(const nlohmann::json& object,
                                                              std::string_view name,
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

std::expected<bool, ContractError>
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

std::expected<CompletenessPolicy, ContractError> decode_policy(const nlohmann::json& coverage,
                                                               std::string_view coverage_path) {
    const auto path = std::string{coverage_path} + "/policy";
    const auto policy_it = coverage.find("policy");
    if (policy_it == coverage.end()) {
        return std::unexpected(error(ContractErrorCode::MissingField, path, "policy is required"));
    }
    if (policy_it->is_null()) {
        return std::unexpected(
            error(ContractErrorCode::NullField, path, "policy must not be null"));
    }
    if (!policy_it->is_object()) {
        return std::unexpected(
            error(ContractErrorCode::WrongType, path, "policy must be an object"));
    }

    auto minimum = required_unsigned(*policy_it, "minimum_response_percent", path);
    if (!minimum)
        return std::unexpected(minimum.error());
    if (*minimum > 100) {
        return std::unexpected(error(ContractErrorCode::InvalidValue,
                                     path + "/minimum_response_percent",
                                     "minimum_response_percent must be between 1 and 100"));
    }
    auto blocks = required_bool(*policy_it, "blocks_next_step_when_incomplete", path);
    if (!blocks)
        return std::unexpected(blocks.error());

    return CompletenessPolicy{
        .minimum_response_percent = static_cast<std::uint8_t>(*minimum),
        .blocks_next_step_when_incomplete = *blocks,
        .extensions = extract_extensions(*policy_it, kPolicyFields),
    };
}

std::expected<std::optional<CoverageEnvelope>, ContractError>
decode_optional_coverage(const nlohmann::json& root) {
    constexpr std::string_view path = "/coverage";
    const auto coverage_it = root.find("coverage");
    if (coverage_it == root.end())
        return std::optional<CoverageEnvelope>{};
    if (coverage_it->is_null()) {
        return std::unexpected(
            error(ContractErrorCode::NullField, std::string{path}, "coverage must not be null"));
    }
    if (!coverage_it->is_object()) {
        return std::unexpected(
            error(ContractErrorCode::WrongType, std::string{path}, "coverage must be an object"));
    }

    auto intended = required_unsigned(*coverage_it, "intended", path);
    if (!intended)
        return std::unexpected(intended.error());
    auto contacted = required_unsigned(*coverage_it, "contacted", path);
    if (!contacted)
        return std::unexpected(contacted.error());
    auto responded = required_unsigned(*coverage_it, "responded", path);
    if (!responded)
        return std::unexpected(responded.error());
    auto failed = required_unsigned(*coverage_it, "failed", path);
    if (!failed)
        return std::unexpected(failed.error());
    auto timed_out = required_unsigned(*coverage_it, "timed_out", path);
    if (!timed_out)
        return std::unexpected(timed_out.error());
    auto offline = required_unsigned(*coverage_it, "offline", path);
    if (!offline)
        return std::unexpected(offline.error());

    auto scope_text = detail::required_string(*coverage_it, "scope_basis", path);
    if (!scope_text)
        return std::unexpected(scope_text.error());
    std::optional<ScopeBasis> scope_basis;
    if (*scope_text == "global")
        scope_basis = ScopeBasis::Global;
    if (*scope_text == "authority_scoped")
        scope_basis = ScopeBasis::AuthorityScoped;
    if (!scope_basis) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "/coverage/scope_basis",
                                     "scope_basis is not a supported value"));
    }

    auto completeness_value = detail::required_string(*coverage_it, "completeness", path);
    if (!completeness_value)
        return std::unexpected(completeness_value.error());
    std::optional<Completeness> completeness;
    if (*completeness_value == "complete")
        completeness = Completeness::Complete;
    if (*completeness_value == "partial")
        completeness = Completeness::Partial;
    if (*completeness_value == "insufficient")
        completeness = Completeness::Insufficient;
    if (*completeness_value == "unknown")
        completeness = Completeness::Unknown;
    if (!completeness) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "/coverage/completeness",
                                     "completeness is not a supported value"));
    }

    auto policy = decode_policy(*coverage_it, path);
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
    if (const auto valid = validate_coverage(coverage, path); !valid) {
        return std::unexpected(valid.error());
    }
    return std::optional<CoverageEnvelope>{std::move(coverage)};
}

std::expected<ScopeBasis, ContractError> decode_scope_basis(const nlohmann::json& root) {
    auto value = detail::required_string(root, "scope_basis");
    if (!value)
        return std::unexpected(value.error());
    if (*value == "global")
        return ScopeBasis::Global;
    if (*value == "authority_scoped")
        return ScopeBasis::AuthorityScoped;
    return std::unexpected(error(ContractErrorCode::InvalidValue, "/scope_basis",
                                 "scope_basis is not a supported value"));
}

std::expected<nlohmann::json, ContractError> decode_required_value(const nlohmann::json& root,
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
    return *it;
}

std::expected<std::vector<std::string>, ContractError>
decode_fact_refs(const nlohmann::json& root) {
    const auto refs_it = root.find("fact_refs");
    if (refs_it == root.end()) {
        return std::unexpected(
            error(ContractErrorCode::MissingField, "/fact_refs", "fact_refs is required"));
    }
    if (refs_it->is_null()) {
        return std::unexpected(
            error(ContractErrorCode::NullField, "/fact_refs", "fact_refs must not be null"));
    }
    if (!refs_it->is_array()) {
        return std::unexpected(
            error(ContractErrorCode::WrongType, "/fact_refs", "fact_refs must be an array"));
    }
    std::vector<std::string> refs;
    refs.reserve(refs_it->size());
    for (std::size_t index = 0; index < refs_it->size(); ++index) {
        const auto& value = (*refs_it)[index];
        const auto path = "/fact_refs/" + std::to_string(index);
        if (value.is_null()) {
            return std::unexpected(
                error(ContractErrorCode::NullField, path, "fact reference must not be null"));
        }
        if (!value.is_string()) {
            return std::unexpected(
                error(ContractErrorCode::WrongType, path, "fact reference must be a string"));
        }
        refs.push_back(value.get<std::string>());
    }
    return refs;
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

std::expected<void, ContractError> validate_result(const B4FactResult& result) {
    if (const auto correlation = detail::validate_correlation_id(result.correlation_id);
        !correlation) {
        return std::unexpected(correlation.error());
    }
    if (const auto run_id =
            detail::validate_opaque_run_id(result.use_case_run_id, "/use_case_run_id");
        !run_id) {
        return std::unexpected(run_id.error());
    }
    if (const auto module = validate_reference(result.module, "/module"); !module) {
        return std::unexpected(module.error());
    }
    if (result.module_manifest_hash.empty()) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "/module_manifest_hash",
                                     "module_manifest_hash must not be empty"));
    }
    if (const auto capability = validate_reference(result.capability, "/capability"); !capability) {
        return std::unexpected(capability.error());
    }
    if (!result.facts.is_object() && !result.facts.is_array()) {
        return std::unexpected(
            error(ContractErrorCode::WrongType, "/facts", "facts must be an object or array"));
    }
    if (const auto authority =
            detail::reject_forbidden_transport_authority_fields_recursive(result.facts, "/facts");
        !authority) {
        return std::unexpected(authority.error());
    }
    if (result.fact_refs.empty()) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "/fact_refs",
                                     "fact_refs must contain at least one Core reference"));
    }
    std::set<std::string, std::less<>> unique_refs;
    for (std::size_t index = 0; index < result.fact_refs.size(); ++index) {
        const auto& reference = result.fact_refs[index];
        const auto path = "/fact_refs/" + std::to_string(index);
        if (reference.empty()) {
            return std::unexpected(
                error(ContractErrorCode::InvalidValue, path, "fact reference must not be empty"));
        }
        if (!unique_refs.emplace(reference).second) {
            return std::unexpected(
                error(ContractErrorCode::InvalidValue, path, "fact references must be unique"));
        }
    }
    if (scope_basis_text(result.scope_basis).empty()) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "/scope_basis",
                                     "scope_basis is not a supported value"));
    }
    if (result.coverage) {
        if (const auto valid = validate_coverage(*result.coverage, "/coverage"); !valid) {
            return std::unexpected(valid.error());
        }
        if (result.coverage->scope_basis != result.scope_basis) {
            return std::unexpected(
                error(ContractErrorCode::InvalidValue, "/coverage/scope_basis",
                      "coverage scope_basis must match the fact result scope_basis"));
        }
    }
    if (!result.provenance.is_object()) {
        return std::unexpected(
            error(ContractErrorCode::WrongType, "/provenance", "provenance must be an object"));
    }
    if (const auto authority = reject_control_authority(result.provenance, "/provenance");
        !authority) {
        return std::unexpected(authority.error());
    }
    if (const auto oracle = reject_confinement_oracle_fields(result.provenance, "/provenance");
        !oracle) {
        return std::unexpected(oracle.error());
    }
    if (const auto extensions = validate_extensions(result.extensions, kFactResultFields, "");
        !extensions) {
        return std::unexpected(extensions.error());
    }
    if (const auto authority = reject_control_authority(result.extensions); !authority) {
        return std::unexpected(authority.error());
    }
    if (const auto oracle = reject_confinement_oracle_fields(result.extensions); !oracle) {
        return std::unexpected(oracle.error());
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

std::expected<void, ContractError> reject_result_control_fields(const nlohmann::json& root) {
    auto control = root;
    control.erase("facts");
    if (const auto authority = reject_control_authority(control); !authority) {
        return std::unexpected(authority.error());
    }
    return reject_confinement_oracle_fields(control);
}

std::expected<void, ContractError> validate_fact_a4_error(const A4ErrorEnvelope& envelope) {
    if (const auto valid = detail::validate_rest_a4_error(envelope); !valid) {
        return std::unexpected(valid.error());
    }
    if (envelope.code == 202) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "/error/code",
                                     "B4 fact reads cannot enter an approval flow"));
    }
    return {};
}

std::string_view response_correlation_id(const B4FactResponse& response) {
    if (const auto* result = std::get_if<B4FactResult>(&response))
        return result->correlation_id;
    return std::get<A4ErrorEnvelope>(response).correlation_id;
}

std::expected<std::string, ContractError> encode_fact_result(const B4FactResult& result) {
    if (const auto valid = validate_result(result); !valid) {
        return std::unexpected(valid.error());
    }

    auto root = result.extensions;
    root["contract"] = {
        {"id", kB4Fact.identifier},
        {"version", {{"major", kB4Fact.current.major}, {"minor", kB4Fact.current.minor}}},
    };
    root["correlation_id"] = result.correlation_id;
    root["use_case_run_id"] = result.use_case_run_id;
    root["module"] = reference_json(result.module);
    root["module_manifest_hash"] = result.module_manifest_hash;
    root["capability"] = reference_json(result.capability);
    root["facts"] = result.facts;
    root["fact_refs"] = result.fact_refs;
    root["scope_basis"] = scope_basis_text(result.scope_basis);
    if (result.coverage)
        root["coverage"] = coverage_json(*result.coverage);
    root["provenance"] = result.provenance;
    return detail::encode_contract_json(root);
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

std::expected<std::string, ContractError> encode_b4_fact_response(const B4FactResponse& response) {
    if (const auto* result = std::get_if<B4FactResult>(&response))
        return encode_fact_result(*result);

    const auto& envelope = std::get<A4ErrorEnvelope>(response);
    if (const auto valid = validate_fact_a4_error(envelope); !valid) {
        return std::unexpected(valid.error());
    }
    auto document = detail::encode_rest_a4_error_document(envelope);
    if (!document)
        return std::unexpected(document.error());
    return detail::encode_contract_json(*document);
}

std::expected<B4FactResponse, ContractError> decode_b4_fact_response(std::string_view wire_json) {
    auto root = detail::parse_contract_json(wire_json);
    if (!root)
        return std::unexpected(root.error());
    if (!root->is_object()) {
        return std::unexpected(
            error(ContractErrorCode::RootNotObject, "", "contract body must be an object"));
    }

    const bool has_facts = root->contains("facts");
    const bool has_error = root->contains("error");
    if (!has_facts && !has_error) {
        return std::unexpected(
            error(ContractErrorCode::MissingField, "", "response must contain facts or error"));
    }
    if (has_facts && has_error) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "",
                                     "response must contain exactly one of facts or error"));
    }

    if (has_error) {
        if (root->contains("contract")) {
            return std::unexpected(error(ContractErrorCode::InvalidValue, "/contract",
                                         "A4 errors do not carry a B4 contract header"));
        }
        if (const auto authority = reject_control_authority(*root); !authority) {
            return std::unexpected(authority.error());
        }
        if (const auto oracle = reject_confinement_oracle_fields(*root); !oracle) {
            return std::unexpected(oracle.error());
        }
        auto envelope = detail::decode_rest_a4_error_document(*root);
        if (!envelope)
            return std::unexpected(envelope.error());
        if (const auto valid = validate_fact_a4_error(*envelope); !valid) {
            return std::unexpected(valid.error());
        }
        return B4FactResponse{std::in_place_type<A4ErrorEnvelope>, std::move(*envelope)};
    }

    if (const auto header = detail::decode_contract_header(*root, kB4Fact); !header) {
        return std::unexpected(header.error());
    }
    if (const auto authority = detail::reject_forbidden_authority_fields(*root); !authority) {
        return std::unexpected(authority.error());
    }
    if (const auto control = reject_result_control_fields(*root); !control) {
        return std::unexpected(control.error());
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
    auto facts = decode_required_value(*root, "facts");
    if (!facts)
        return std::unexpected(facts.error());
    auto fact_refs = decode_fact_refs(*root);
    if (!fact_refs)
        return std::unexpected(fact_refs.error());
    auto scope_basis = decode_scope_basis(*root);
    if (!scope_basis)
        return std::unexpected(scope_basis.error());
    auto coverage = decode_optional_coverage(*root);
    if (!coverage)
        return std::unexpected(coverage.error());
    auto provenance = decode_required_object(*root, "provenance");
    if (!provenance)
        return std::unexpected(provenance.error());

    B4FactResult result{
        .correlation_id = std::move(*correlation),
        .use_case_run_id = std::move(*run_id),
        .module = std::move(*module),
        .module_manifest_hash = std::move(*manifest_hash),
        .capability = std::move(*capability),
        .facts = std::move(*facts),
        .fact_refs = std::move(*fact_refs),
        .scope_basis = *scope_basis,
        .coverage = std::move(*coverage),
        .provenance = std::move(*provenance),
        .extensions = extract_extensions(*root, kFactResultFields),
    };
    if (const auto valid = validate_result(result); !valid) {
        return std::unexpected(valid.error());
    }
    return B4FactResponse{std::in_place_type<B4FactResult>, std::move(result)};
}

std::expected<void, ContractError> validate_b4_fact_exchange(const B4FactRequest& request,
                                                             const B4FactResponse& response) {
    if (const auto valid = validate_request(request); !valid) {
        return std::unexpected(valid.error());
    }
    if (const auto* result = std::get_if<B4FactResult>(&response)) {
        if (const auto valid = validate_result(*result); !valid) {
            return std::unexpected(valid.error());
        }
    } else if (const auto valid = validate_fact_a4_error(std::get<A4ErrorEnvelope>(response));
               !valid) {
        return std::unexpected(valid.error());
    }

    if (request.correlation_id != response_correlation_id(response)) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "/correlation_id",
                                     "response correlation does not match the request"));
    }
    const auto* result = std::get_if<B4FactResult>(&response);
    if (!result)
        return {};
    if (request.use_case_run_id != result->use_case_run_id) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "/use_case_run_id",
                                     "response use_case_run_id does not match the request"));
    }
    if (request.module.id != result->module.id) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "/module/id",
                                     "response module id does not match the request"));
    }
    if (request.module.version != result->module.version) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "/module/version",
                                     "response module version does not match the request"));
    }
    if (request.module_manifest_hash != result->module_manifest_hash) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "/module_manifest_hash",
                                     "response module manifest hash does not match the request"));
    }
    if (request.capability.id != result->capability.id) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "/capability/id",
                                     "response capability id does not match the request"));
    }
    if (request.capability.version != result->capability.version) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "/capability/version",
                                     "response capability version does not match the request"));
    }
    return {};
}

} // namespace yuzu::contracts::adr31
