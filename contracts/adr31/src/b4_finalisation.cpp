#include <yuzu/contracts/adr31/b4_finalisation.hpp>

#include <yuzu/contracts/adr31/contract_version.hpp>

#include "json_support.hpp"
#include "rest_a4_support.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
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

constexpr std::array<std::string_view, 9> kCoverageFields{
    "intended", "contacted",   "responded",    "failed", "timed_out",
    "offline",  "scope_basis", "completeness", "policy",
};
constexpr std::array<std::string_view, 2> kPolicyFields{
    "minimum_response_percent",
    "blocks_next_step_when_incomplete",
};
constexpr std::array<std::string_view, 1> kDisclosureFields{"fact_refs"};
constexpr std::array<std::string_view, 12> kRequestFields{
    "contract",
    "correlation_id",
    "use_case_run_id",
    "use_case",
    "module",
    "module_manifest_hash",
    "result_schema_version",
    "result_hash",
    "disclosure_summary",
    "coverage",
    "provenance",
    "error",
};
constexpr std::array<std::string_view, 12> kResultFields{
    "contract", "correlation_id",       "use_case_run_id",       "use_case",
    "module",   "module_manifest_hash", "result_schema_version", "result_hash",
    "coverage", "provenance",           "finalisation_receipt",  "error",
};

[[nodiscard]] ContractError error(ContractErrorCode code, std::string path, std::string message) {
    return ContractError{code, std::move(path), std::move(message)};
}

template <std::size_t Size>
[[nodiscard]] bool is_known_field(std::string_view name,
                                  const std::array<std::string_view, Size>& fields) {
    return std::ranges::find(fields, name) != fields.end();
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

[[nodiscard]] std::string normalise_control_name(std::string_view name) {
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

[[nodiscard]] std::string escape_json_pointer(std::string_view token) {
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

[[nodiscard]] std::expected<void, ContractError>
reject_confinement_oracle_fields(const nlohmann::json& value, std::string_view parent_path = {}) {
    constexpr auto forbidden = std::to_array<std::string_view>({
        "fleetsize",
        "fleettotal",
        "globalcount",
        "globaltotal",
        "haswithheld",
        "matched",
        "matchedcount",
        "outofscope",
        "outofscopecount",
        "releasedinputdigest",
        "removed",
        "removedcount",
        "requestedbeforeconfinement",
        "truncated",
        "truncatedcount",
        "unfilteredcount",
        "wastruncated",
        "withheld",
        "withheldcount",
        "withheldexists",
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
                if (std::ranges::find(forbidden, normalised) != forbidden.end()) {
                    return std::unexpected(error(ContractErrorCode::InvalidValue, path,
                                                 "confinement oracle fields are forbidden"));
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

[[nodiscard]] std::expected<void, ContractError>
reject_control_authority(const nlohmann::json& value, std::string_view path = {}) {
    if (const auto authority = detail::reject_forbidden_authority_fields_recursive(value, path);
        !authority) {
        return std::unexpected(authority.error());
    }
    return detail::reject_forbidden_transport_authority_fields_recursive(value, path);
}

[[nodiscard]] constexpr std::string_view scope_basis_text(ScopeBasis value) noexcept {
    switch (value) {
    case ScopeBasis::Global:
        return "global";
    case ScopeBasis::AuthorityScoped:
        return "authority_scoped";
    }
    return {};
}

[[nodiscard]] constexpr std::string_view completeness_text(Completeness value) noexcept {
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

[[nodiscard]] std::expected<void, ContractError> validate_coverage(const CoverageEnvelope& coverage,
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

[[nodiscard]] nlohmann::json coverage_json(const CoverageEnvelope& coverage) {
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
decode_policy(const nlohmann::json& coverage, std::string_view coverage_path) {
    const auto path = std::string{coverage_path} + "/policy";
    const auto it = coverage.find("policy");
    if (it == coverage.end()) {
        return std::unexpected(error(ContractErrorCode::MissingField, path, "policy is required"));
    }
    if (it->is_null()) {
        return std::unexpected(
            error(ContractErrorCode::NullField, path, "policy must not be null"));
    }
    if (!it->is_object()) {
        return std::unexpected(
            error(ContractErrorCode::WrongType, path, "policy must be an object"));
    }
    auto minimum = required_unsigned(*it, "minimum_response_percent", path);
    if (!minimum)
        return std::unexpected(minimum.error());
    if (*minimum == 0 || *minimum > 100) {
        return std::unexpected(error(ContractErrorCode::InvalidValue,
                                     path + "/minimum_response_percent",
                                     "minimum_response_percent must be between 1 and 100"));
    }
    auto blocks = required_bool(*it, "blocks_next_step_when_incomplete", path);
    if (!blocks)
        return std::unexpected(blocks.error());
    return CompletenessPolicy{
        .minimum_response_percent = static_cast<std::uint8_t>(*minimum),
        .blocks_next_step_when_incomplete = *blocks,
        .extensions = extract_extensions(*it, kPolicyFields),
    };
}

[[nodiscard]] std::expected<CoverageEnvelope, ContractError>
decode_coverage(const nlohmann::json& root) {
    constexpr std::string_view path = "/coverage";
    const auto it = root.find("coverage");
    if (it == root.end()) {
        return std::unexpected(
            error(ContractErrorCode::MissingField, std::string{path}, "coverage is required"));
    }
    if (it->is_null()) {
        return std::unexpected(
            error(ContractErrorCode::NullField, std::string{path}, "coverage must not be null"));
    }
    if (!it->is_object()) {
        return std::unexpected(
            error(ContractErrorCode::WrongType, std::string{path}, "coverage must be an object"));
    }

    auto intended = required_unsigned(*it, "intended", path);
    if (!intended)
        return std::unexpected(intended.error());
    auto contacted = required_unsigned(*it, "contacted", path);
    if (!contacted)
        return std::unexpected(contacted.error());
    auto responded = required_unsigned(*it, "responded", path);
    if (!responded)
        return std::unexpected(responded.error());
    auto failed = required_unsigned(*it, "failed", path);
    if (!failed)
        return std::unexpected(failed.error());
    auto timed_out = required_unsigned(*it, "timed_out", path);
    if (!timed_out)
        return std::unexpected(timed_out.error());
    auto offline = required_unsigned(*it, "offline", path);
    if (!offline)
        return std::unexpected(offline.error());

    auto scope = detail::required_string(*it, "scope_basis", path);
    if (!scope)
        return std::unexpected(scope.error());
    std::optional<ScopeBasis> scope_basis;
    if (*scope == "global")
        scope_basis = ScopeBasis::Global;
    if (*scope == "authority_scoped")
        scope_basis = ScopeBasis::AuthorityScoped;
    if (!scope_basis) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "/coverage/scope_basis",
                                     "scope_basis is not a supported value"));
    }

    auto completeness_value = detail::required_string(*it, "completeness", path);
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

    auto policy = decode_policy(*it, path);
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
        .extensions = extract_extensions(*it, kCoverageFields),
    };
    if (const auto valid = validate_coverage(coverage, path); !valid)
        return std::unexpected(valid.error());
    return coverage;
}

[[nodiscard]] std::expected<void, ContractError>
validate_reference(const VersionedIdentity& reference, std::string_view path) {
    if (reference.id.empty() || reference.version.empty()) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, std::string{path},
                                     "id and version must not be empty"));
    }
    return {};
}

[[nodiscard]] nlohmann::json reference_json(const VersionedIdentity& reference) {
    return nlohmann::json{{"id", reference.id}, {"version", reference.version}};
}

[[nodiscard]] std::expected<VersionedIdentity, ContractError>
decode_reference(const nlohmann::json& root, std::string_view name) {
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
    if (!id)
        return std::unexpected(id.error());
    auto version = detail::required_string(*it, "version", path);
    if (!version)
        return std::unexpected(version.error());
    return VersionedIdentity{.id = std::move(*id), .version = std::move(*version)};
}

[[nodiscard]] std::expected<void, ContractError>
validate_result_hash(std::string_view hash, std::string_view path = "/result_hash") {
    if (hash.size() != 71 || !hash.starts_with("sha256:")) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, std::string{path},
                                     "result_hash must be sha256 plus 64 lowercase hex digits"));
    }
    for (const char byte : hash.substr(7)) {
        if (!((byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f'))) {
            return std::unexpected(
                error(ContractErrorCode::InvalidValue, std::string{path},
                      "result_hash must be sha256 plus 64 lowercase hex digits"));
        }
    }
    return {};
}

[[nodiscard]] std::expected<std::string, ContractError>
journal_id_from_provenance(const nlohmann::json& provenance,
                           std::string_view path = "/provenance") {
    if (!provenance.is_object()) {
        return std::unexpected(
            error(ContractErrorCode::WrongType, std::string{path}, "provenance must be an object"));
    }
    auto journal_id = detail::required_string(provenance, "journal_id", path);
    if (!journal_id)
        return std::unexpected(journal_id.error());
    if (journal_id->empty()) {
        return std::unexpected(error(ContractErrorCode::InvalidValue,
                                     std::string{path} + "/journal_id",
                                     "journal_id must not be empty"));
    }
    return journal_id;
}

[[nodiscard]] std::expected<void, ContractError>
validate_disclosure(B4DisclosureSummary& disclosure) {
    if (const auto extensions =
            validate_extensions(disclosure.extensions, kDisclosureFields, "/disclosure_summary");
        !extensions) {
        return std::unexpected(extensions.error());
    }
    if (const auto authority =
            reject_control_authority(disclosure.extensions, "/disclosure_summary");
        !authority) {
        return std::unexpected(authority.error());
    }
    if (const auto oracle =
            reject_confinement_oracle_fields(disclosure.extensions, "/disclosure_summary");
        !oracle) {
        return std::unexpected(oracle.error());
    }

    std::set<std::string, std::less<>> unique;
    for (std::size_t index = 0; index < disclosure.fact_refs.size(); ++index) {
        const auto& reference = disclosure.fact_refs[index];
        const auto path = "/disclosure_summary/fact_refs/" + std::to_string(index);
        if (reference.empty()) {
            return std::unexpected(
                error(ContractErrorCode::InvalidValue, path, "fact reference must not be empty"));
        }
        if (!unique.emplace(reference).second) {
            return std::unexpected(
                error(ContractErrorCode::InvalidValue, path, "fact references must be unique"));
        }
    }
    std::ranges::sort(disclosure.fact_refs);
    return {};
}

[[nodiscard]] std::expected<B4DisclosureSummary, ContractError>
decode_disclosure(const nlohmann::json& root) {
    constexpr std::string_view path = "/disclosure_summary";
    const auto it = root.find("disclosure_summary");
    if (it == root.end()) {
        return std::unexpected(error(ContractErrorCode::MissingField, std::string{path},
                                     "disclosure_summary is required"));
    }
    if (it->is_null()) {
        return std::unexpected(error(ContractErrorCode::NullField, std::string{path},
                                     "disclosure_summary must not be null"));
    }
    if (!it->is_object()) {
        return std::unexpected(error(ContractErrorCode::WrongType, std::string{path},
                                     "disclosure_summary must be an object"));
    }
    const auto refs = it->find("fact_refs");
    if (refs == it->end()) {
        return std::unexpected(error(ContractErrorCode::MissingField,
                                     "/disclosure_summary/fact_refs", "fact_refs is required"));
    }
    if (refs->is_null()) {
        return std::unexpected(error(ContractErrorCode::NullField, "/disclosure_summary/fact_refs",
                                     "fact_refs must not be null"));
    }
    if (!refs->is_array()) {
        return std::unexpected(error(ContractErrorCode::WrongType, "/disclosure_summary/fact_refs",
                                     "fact_refs must be an array"));
    }
    B4DisclosureSummary disclosure{
        .extensions = extract_extensions(*it, kDisclosureFields),
    };
    disclosure.fact_refs.reserve(refs->size());
    for (std::size_t index = 0; index < refs->size(); ++index) {
        const auto& value = (*refs)[index];
        const auto ref_path = "/disclosure_summary/fact_refs/" + std::to_string(index);
        if (value.is_null()) {
            return std::unexpected(
                error(ContractErrorCode::NullField, ref_path, "fact reference must not be null"));
        }
        if (!value.is_string()) {
            return std::unexpected(
                error(ContractErrorCode::WrongType, ref_path, "fact reference must be a string"));
        }
        disclosure.fact_refs.push_back(value.get<std::string>());
    }
    if (const auto valid = validate_disclosure(disclosure); !valid)
        return std::unexpected(valid.error());
    return disclosure;
}

[[nodiscard]] std::expected<void, ContractError> validate_request(B4FinalisationRequest& request) {
    if (const auto correlation = detail::validate_correlation_id(request.correlation_id);
        !correlation) {
        return std::unexpected(correlation.error());
    }
    if (const auto run =
            detail::validate_opaque_run_id(request.use_case_run_id, "/use_case_run_id");
        !run) {
        return std::unexpected(run.error());
    }
    if (const auto valid = validate_reference(request.use_case, "/use_case"); !valid)
        return std::unexpected(valid.error());
    if (const auto valid = validate_reference(request.module, "/module"); !valid)
        return std::unexpected(valid.error());
    if (request.module_manifest_hash.empty()) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "/module_manifest_hash",
                                     "module_manifest_hash must not be empty"));
    }
    if (request.result_schema_version.empty()) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "/result_schema_version",
                                     "result_schema_version must not be empty"));
    }
    if (const auto valid = validate_result_hash(request.result_hash); !valid)
        return std::unexpected(valid.error());
    if (const auto valid = validate_disclosure(request.disclosure_summary); !valid)
        return std::unexpected(valid.error());
    if (const auto valid = validate_coverage(request.coverage, "/coverage"); !valid)
        return std::unexpected(valid.error());
    if (const auto journal = journal_id_from_provenance(request.provenance); !journal)
        return std::unexpected(journal.error());
    if (const auto authority = reject_control_authority(request.provenance, "/provenance");
        !authority) {
        return std::unexpected(authority.error());
    }
    if (const auto oracle = reject_confinement_oracle_fields(request.provenance, "/provenance");
        !oracle) {
        return std::unexpected(oracle.error());
    }
    if (const auto extensions = validate_extensions(request.extensions, kRequestFields, "");
        !extensions) {
        return std::unexpected(extensions.error());
    }
    if (const auto authority = reject_control_authority(request.extensions); !authority)
        return std::unexpected(authority.error());
    return reject_confinement_oracle_fields(request.extensions);
}

[[nodiscard]] std::expected<void, ContractError>
validate_result(const B4FinalisationResult& result) {
    if (const auto correlation = detail::validate_correlation_id(result.correlation_id);
        !correlation) {
        return std::unexpected(correlation.error());
    }
    if (const auto run = detail::validate_opaque_run_id(result.use_case_run_id, "/use_case_run_id");
        !run) {
        return std::unexpected(run.error());
    }
    if (const auto valid = validate_reference(result.use_case, "/use_case"); !valid)
        return std::unexpected(valid.error());
    if (const auto valid = validate_reference(result.module, "/module"); !valid)
        return std::unexpected(valid.error());
    if (result.module_manifest_hash.empty()) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "/module_manifest_hash",
                                     "module_manifest_hash must not be empty"));
    }
    if (result.result_schema_version.empty()) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "/result_schema_version",
                                     "result_schema_version must not be empty"));
    }
    if (const auto valid = validate_result_hash(result.result_hash); !valid)
        return std::unexpected(valid.error());
    if (const auto valid = validate_coverage(result.coverage, "/coverage"); !valid)
        return std::unexpected(valid.error());
    if (result.journal_id.empty()) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "/provenance/journal_id",
                                     "journal_id must not be empty"));
    }
    if (result.finalisation_receipt.empty()) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "/finalisation_receipt",
                                     "finalisation_receipt must not be empty"));
    }
    if (const auto extensions = validate_extensions(result.extensions, kResultFields, "");
        !extensions) {
        return std::unexpected(extensions.error());
    }
    if (const auto authority = reject_control_authority(result.extensions); !authority)
        return std::unexpected(authority.error());
    return reject_confinement_oracle_fields(result.extensions);
}

[[nodiscard]] std::expected<void, ContractError>
validate_finalisation_a4(const A4ErrorEnvelope& envelope) {
    if (const auto valid = detail::validate_rest_a4_error(envelope); !valid)
        return std::unexpected(valid.error());
    if (envelope.code == 202) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "/error/code",
                                     "B4 finalisation cannot enter an approval flow"));
    }
    return {};
}

[[nodiscard]] std::string_view response_correlation_id(const B4FinalisationResponse& response) {
    if (const auto* result = std::get_if<B4FinalisationResult>(&response))
        return result->correlation_id;
    return std::get<A4ErrorEnvelope>(response).correlation_id;
}

[[nodiscard]] std::expected<std::string, ContractError>
encode_finalisation_request(B4FinalisationRequest request) {
    if (const auto valid = validate_request(request); !valid)
        return std::unexpected(valid.error());

    auto disclosure = request.disclosure_summary.extensions;
    disclosure["fact_refs"] = request.disclosure_summary.fact_refs;

    auto root = request.extensions;
    root["contract"] = {
        {"id", kB4Finalisation.identifier},
        {"version",
         {{"major", kB4Finalisation.current.major}, {"minor", kB4Finalisation.current.minor}}},
    };
    root["correlation_id"] = request.correlation_id;
    root["use_case_run_id"] = request.use_case_run_id;
    root["use_case"] = reference_json(request.use_case);
    root["module"] = reference_json(request.module);
    root["module_manifest_hash"] = request.module_manifest_hash;
    root["result_schema_version"] = request.result_schema_version;
    root["result_hash"] = request.result_hash;
    root["disclosure_summary"] = std::move(disclosure);
    root["coverage"] = coverage_json(request.coverage);
    root["provenance"] = request.provenance;
    return detail::encode_contract_json(root);
}

[[nodiscard]] std::expected<std::string, ContractError>
encode_finalisation_result(const B4FinalisationResult& result) {
    if (const auto valid = validate_result(result); !valid)
        return std::unexpected(valid.error());

    auto root = result.extensions;
    root["contract"] = {
        {"id", kB4Finalisation.identifier},
        {"version",
         {{"major", kB4Finalisation.current.major}, {"minor", kB4Finalisation.current.minor}}},
    };
    root["correlation_id"] = result.correlation_id;
    root["use_case_run_id"] = result.use_case_run_id;
    root["use_case"] = reference_json(result.use_case);
    root["module"] = reference_json(result.module);
    root["module_manifest_hash"] = result.module_manifest_hash;
    root["result_schema_version"] = result.result_schema_version;
    root["result_hash"] = result.result_hash;
    root["coverage"] = coverage_json(result.coverage);
    root["provenance"] = {{"journal_id", result.journal_id}};
    root["finalisation_receipt"] = result.finalisation_receipt;
    return detail::encode_contract_json(root);
}

[[nodiscard]] std::expected<void, ContractError>
validate_retained_result(const B4FinalisationRequest& request,
                         const B2UseCaseRequest& received_b2_request,
                         const B2UseCaseResultPayload& result) {
    if (received_b2_request.request_id.empty()) {
        return std::unexpected(
            error(ContractErrorCode::InvalidValue, "/request_id", "request_id must not be empty"));
    }
    if (received_b2_request.use_case_run_id != request.use_case_run_id) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "/use_case_run_id",
                                     "retained B2 run does not match finalisation"));
    }
    if (received_b2_request.use_case != request.use_case) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "/use_case",
                                     "retained B2 use case does not match finalisation"));
    }
    if (received_b2_request.module != request.module) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "/module",
                                     "retained B2 module does not match finalisation"));
    }
    if (result.coverage != request.coverage) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "/coverage",
                                     "retained B2 coverage does not match finalisation"));
    }
    if (result.provenance != request.provenance) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "/provenance",
                                     "retained B2 provenance does not match finalisation"));
    }
    auto hash = canonical_b2_result_hash(request.result_schema_version, result);
    if (!hash)
        return std::unexpected(hash.error());
    if (*hash != request.result_hash) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "/result_hash",
                                     "retained B2 result does not match finalisation hash"));
    }
    return {};
}

} // namespace

B4FinalisationCall::B4FinalisationCall(std::string body,
                                       TransportAuthSlot engine_credential) noexcept
    : body_(std::move(body)), engine_credential_(std::move(engine_credential)) {}

B4FinalisationReply::B4FinalisationReply(
    std::string body, std::optional<TransportAuthSlot> release_authorization) noexcept
    : body_(std::move(body)), release_authorization_(std::move(release_authorization)) {}

B4PendingRelease::B4PendingRelease(std::string request_id, B2UseCaseResultPayload result,
                                   B4FinalisationResult receipt,
                                   TransportAuthSlot release_authorization) noexcept
    : request_id_(std::move(request_id)), result_(std::move(result)), receipt_(std::move(receipt)),
      release_authorization_(std::move(release_authorization)) {}

std::expected<B4FinalisationCall, B4FinalisationCallError>
make_b4_finalisation_call(B4FinalisationDraft draft, const B2UseCaseRequest& received_b2_request,
                          const B2UseCaseResultPayload& result,
                          TransportAuthSlot engine_credential) {
    if (!engine_credential.valid()) {
        return std::unexpected(
            B4FinalisationCallError{B4FinalisationBindingError::MissingEngineCredential});
    }
    if (engine_credential.kind() != TransportAuthKind::EngineCredential) {
        return std::unexpected(
            B4FinalisationCallError{B4FinalisationBindingError::WrongEngineCredentialKind});
    }
    if (received_b2_request.request_id.empty()) {
        return std::unexpected(
            B4FinalisationCallError{std::in_place_type<ContractError>,
                                    ContractError{ContractErrorCode::InvalidValue, "/request_id",
                                                  "request_id must not be empty"}});
    }

    auto hash = canonical_b2_result_hash(draft.result_schema_version, result);
    if (!hash) {
        return std::unexpected(
            B4FinalisationCallError{std::in_place_type<ContractError>, std::move(hash.error())});
    }
    B4FinalisationRequest request{
        .correlation_id = std::move(draft.correlation_id),
        .use_case_run_id = received_b2_request.use_case_run_id,
        .use_case = received_b2_request.use_case,
        .module = received_b2_request.module,
        .module_manifest_hash = std::move(draft.module_manifest_hash),
        .result_schema_version = std::move(draft.result_schema_version),
        .result_hash = std::move(*hash),
        .disclosure_summary = std::move(draft.disclosure_summary),
        .coverage = result.coverage,
        .provenance = result.provenance,
        .extensions = std::move(draft.extensions),
    };
    auto body = encode_finalisation_request(std::move(request));
    if (!body) {
        return std::unexpected(
            B4FinalisationCallError{std::in_place_type<ContractError>, std::move(body.error())});
    }
    return B4FinalisationCall{std::move(*body), std::move(engine_credential)};
}

std::expected<B4FinalisationRequest, ContractError>
decode_b4_finalisation_request(std::string_view wire_json) {
    auto root = detail::parse_contract_json(wire_json);
    if (!root)
        return std::unexpected(root.error());
    if (!root->is_object()) {
        return std::unexpected(
            error(ContractErrorCode::RootNotObject, "", "contract body must be an object"));
    }
    if (root->contains("error")) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "/error",
                                     "a finalisation request cannot contain an A4 error arm"));
    }
    if (const auto header = detail::decode_contract_header(*root, kB4Finalisation); !header)
        return std::unexpected(header.error());
    if (const auto authority = reject_control_authority(*root); !authority)
        return std::unexpected(authority.error());
    if (const auto oracle = reject_confinement_oracle_fields(*root); !oracle)
        return std::unexpected(oracle.error());

    auto correlation = detail::required_string(*root, "correlation_id");
    if (!correlation)
        return std::unexpected(correlation.error());
    auto run_id = detail::required_string(*root, "use_case_run_id");
    if (!run_id)
        return std::unexpected(run_id.error());
    auto use_case = decode_reference(*root, "use_case");
    if (!use_case)
        return std::unexpected(use_case.error());
    auto module = decode_reference(*root, "module");
    if (!module)
        return std::unexpected(module.error());
    auto manifest_hash = detail::required_string(*root, "module_manifest_hash");
    if (!manifest_hash)
        return std::unexpected(manifest_hash.error());
    auto schema = detail::required_string(*root, "result_schema_version");
    if (!schema)
        return std::unexpected(schema.error());
    auto result_hash = detail::required_string(*root, "result_hash");
    if (!result_hash)
        return std::unexpected(result_hash.error());
    auto disclosure = decode_disclosure(*root);
    if (!disclosure)
        return std::unexpected(disclosure.error());
    auto coverage = decode_coverage(*root);
    if (!coverage)
        return std::unexpected(coverage.error());
    const auto provenance_it = root->find("provenance");
    if (provenance_it == root->end()) {
        return std::unexpected(
            error(ContractErrorCode::MissingField, "/provenance", "provenance is required"));
    }
    if (provenance_it->is_null()) {
        return std::unexpected(
            error(ContractErrorCode::NullField, "/provenance", "provenance must not be null"));
    }
    if (!provenance_it->is_object()) {
        return std::unexpected(
            error(ContractErrorCode::WrongType, "/provenance", "provenance must be an object"));
    }

    B4FinalisationRequest request{
        .correlation_id = std::move(*correlation),
        .use_case_run_id = std::move(*run_id),
        .use_case = std::move(*use_case),
        .module = std::move(*module),
        .module_manifest_hash = std::move(*manifest_hash),
        .result_schema_version = std::move(*schema),
        .result_hash = std::move(*result_hash),
        .disclosure_summary = std::move(*disclosure),
        .coverage = std::move(*coverage),
        .provenance = *provenance_it,
        .extensions = extract_extensions(*root, kRequestFields),
    };
    if (const auto valid = validate_request(request); !valid)
        return std::unexpected(valid.error());
    return request;
}

std::expected<std::string, ContractError>
encode_b4_finalisation_response(const B4FinalisationResponse& response) {
    if (const auto* result = std::get_if<B4FinalisationResult>(&response))
        return encode_finalisation_result(*result);

    const auto& envelope = std::get<A4ErrorEnvelope>(response);
    if (const auto valid = validate_finalisation_a4(envelope); !valid)
        return std::unexpected(valid.error());
    auto document = detail::encode_rest_a4_error_document(envelope);
    if (!document)
        return std::unexpected(document.error());
    return detail::encode_contract_json(*document);
}

std::expected<B4FinalisationResponse, ContractError>
decode_b4_finalisation_response(std::string_view wire_json) {
    auto root = detail::parse_contract_json(wire_json);
    if (!root)
        return std::unexpected(root.error());
    if (!root->is_object()) {
        return std::unexpected(
            error(ContractErrorCode::RootNotObject, "", "contract body must be an object"));
    }

    const bool has_receipt = root->contains("finalisation_receipt");
    const bool has_error = root->contains("error");
    if (!has_receipt && !has_error) {
        return std::unexpected(error(ContractErrorCode::MissingField, "",
                                     "response must contain finalisation_receipt or error"));
    }
    if (has_receipt && has_error) {
        return std::unexpected(
            error(ContractErrorCode::InvalidValue, "",
                  "response must contain exactly one of finalisation_receipt or error"));
    }

    if (has_error) {
        if (root->contains("contract")) {
            return std::unexpected(error(ContractErrorCode::InvalidValue, "/contract",
                                         "A4 errors do not carry a B4 contract header"));
        }
        if (const auto authority = reject_control_authority(*root); !authority)
            return std::unexpected(authority.error());
        if (const auto oracle = reject_confinement_oracle_fields(*root); !oracle)
            return std::unexpected(oracle.error());
        auto envelope = detail::decode_rest_a4_error_document(*root);
        if (!envelope)
            return std::unexpected(envelope.error());
        if (const auto valid = validate_finalisation_a4(*envelope); !valid)
            return std::unexpected(valid.error());
        return B4FinalisationResponse{std::in_place_type<A4ErrorEnvelope>, std::move(*envelope)};
    }

    if (const auto header = detail::decode_contract_header(*root, kB4Finalisation); !header)
        return std::unexpected(header.error());
    if (const auto authority = reject_control_authority(*root); !authority)
        return std::unexpected(authority.error());
    if (const auto oracle = reject_confinement_oracle_fields(*root); !oracle)
        return std::unexpected(oracle.error());

    auto correlation = detail::required_string(*root, "correlation_id");
    if (!correlation)
        return std::unexpected(correlation.error());
    auto run_id = detail::required_string(*root, "use_case_run_id");
    if (!run_id)
        return std::unexpected(run_id.error());
    auto use_case = decode_reference(*root, "use_case");
    if (!use_case)
        return std::unexpected(use_case.error());
    auto module = decode_reference(*root, "module");
    if (!module)
        return std::unexpected(module.error());
    auto manifest_hash = detail::required_string(*root, "module_manifest_hash");
    if (!manifest_hash)
        return std::unexpected(manifest_hash.error());
    auto schema = detail::required_string(*root, "result_schema_version");
    if (!schema)
        return std::unexpected(schema.error());
    auto result_hash = detail::required_string(*root, "result_hash");
    if (!result_hash)
        return std::unexpected(result_hash.error());
    auto coverage = decode_coverage(*root);
    if (!coverage)
        return std::unexpected(coverage.error());
    const auto provenance_it = root->find("provenance");
    if (provenance_it == root->end()) {
        return std::unexpected(
            error(ContractErrorCode::MissingField, "/provenance", "provenance is required"));
    }
    if (provenance_it->is_null()) {
        return std::unexpected(
            error(ContractErrorCode::NullField, "/provenance", "provenance must not be null"));
    }
    auto journal_id = journal_id_from_provenance(*provenance_it);
    if (!journal_id)
        return std::unexpected(journal_id.error());
    auto receipt = detail::required_string(*root, "finalisation_receipt");
    if (!receipt)
        return std::unexpected(receipt.error());

    B4FinalisationResult result{
        .correlation_id = std::move(*correlation),
        .use_case_run_id = std::move(*run_id),
        .use_case = std::move(*use_case),
        .module = std::move(*module),
        .module_manifest_hash = std::move(*manifest_hash),
        .result_schema_version = std::move(*schema),
        .result_hash = std::move(*result_hash),
        .coverage = std::move(*coverage),
        .journal_id = std::move(*journal_id),
        .finalisation_receipt = std::move(*receipt),
        .extensions = extract_extensions(*root, kResultFields),
    };
    if (const auto valid = validate_result(result); !valid)
        return std::unexpected(valid.error());
    return B4FinalisationResponse{std::in_place_type<B4FinalisationResult>, std::move(result)};
}

std::expected<B4FinalisationReply, B4FinalisationReplyError>
make_b4_finalisation_reply(B4FinalisationResponse response,
                           std::optional<TransportAuthSlot> release_authorization) {
    auto body = encode_b4_finalisation_response(response);
    if (!body) {
        return std::unexpected(
            B4FinalisationReplyError{std::in_place_type<ContractError>, std::move(body.error())});
    }

    const bool success = std::holds_alternative<B4FinalisationResult>(response);
    if (success && !release_authorization) {
        return std::unexpected(
            B4FinalisationReplyError{B4FinalisationBindingError::MissingReleaseAuthorization});
    }
    if (!success && release_authorization) {
        return std::unexpected(
            B4FinalisationReplyError{B4FinalisationBindingError::UnexpectedReleaseAuthorization});
    }
    if (release_authorization && !release_authorization->valid()) {
        return std::unexpected(
            B4FinalisationReplyError{B4FinalisationBindingError::InvalidReleaseAuthorization});
    }
    if (release_authorization &&
        release_authorization->kind() != TransportAuthKind::ReleaseAuthorization) {
        return std::unexpected(
            B4FinalisationReplyError{B4FinalisationBindingError::WrongReleaseAuthorizationKind});
    }
    return B4FinalisationReply{std::move(*body), std::move(release_authorization)};
}

std::expected<void, ContractError>
validate_b4_finalisation_exchange(const B4FinalisationRequest& unvalidated_request,
                                  const B4FinalisationResponse& response) {
    auto request = unvalidated_request;
    if (const auto valid = validate_request(request); !valid)
        return std::unexpected(valid.error());
    if (const auto* result = std::get_if<B4FinalisationResult>(&response)) {
        if (const auto valid = validate_result(*result); !valid)
            return std::unexpected(valid.error());
    } else if (const auto valid = validate_finalisation_a4(std::get<A4ErrorEnvelope>(response));
               !valid) {
        return std::unexpected(valid.error());
    }

    if (request.correlation_id != response_correlation_id(response)) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "/correlation_id",
                                     "response correlation does not match the request"));
    }
    const auto* result = std::get_if<B4FinalisationResult>(&response);
    if (!result)
        return {};
    if (request.use_case_run_id != result->use_case_run_id) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "/use_case_run_id",
                                     "response run does not match the request"));
    }
    if (request.use_case.id != result->use_case.id) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "/use_case/id",
                                     "response use-case id does not match the request"));
    }
    if (request.use_case.version != result->use_case.version) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "/use_case/version",
                                     "response use-case version does not match the request"));
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
                                     "response manifest hash does not match the request"));
    }
    if (request.result_schema_version != result->result_schema_version) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "/result_schema_version",
                                     "response schema does not match the request"));
    }
    if (request.result_hash != result->result_hash) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "/result_hash",
                                     "response result hash does not match the request"));
    }
    if (request.coverage != result->coverage) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "/coverage",
                                     "response coverage does not match the request"));
    }
    auto journal_id = journal_id_from_provenance(request.provenance);
    if (!journal_id)
        return std::unexpected(journal_id.error());
    if (*journal_id != result->journal_id) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "/provenance/journal_id",
                                     "response journal does not match the request"));
    }
    return {};
}

std::expected<B4BoundFinalisation, B4FinalisationExchangeError>
bind_b4_finalisation_exchange(const B4FinalisationRequest& request,
                              const B2UseCaseRequest& received_b2_request,
                              const B2UseCaseResultPayload& result, B4FinalisationResponse response,
                              std::optional<TransportAuthSlot> release_authorization) {
    if (const auto valid = validate_b4_finalisation_exchange(request, response); !valid) {
        return std::unexpected(B4FinalisationExchangeError{std::in_place_type<ContractError>,
                                                           std::move(valid.error())});
    }
    if (std::holds_alternative<A4ErrorEnvelope>(response)) {
        if (release_authorization) {
            return std::unexpected(B4FinalisationExchangeError{
                B4FinalisationBindingError::UnexpectedReleaseAuthorization});
        }
        return B4BoundFinalisation{std::in_place_type<A4ErrorEnvelope>,
                                   std::get<A4ErrorEnvelope>(std::move(response))};
    }

    if (const auto retained = validate_retained_result(request, received_b2_request, result);
        !retained) {
        return std::unexpected(B4FinalisationExchangeError{std::in_place_type<ContractError>,
                                                           std::move(retained.error())});
    }
    if (!release_authorization) {
        return std::unexpected(
            B4FinalisationExchangeError{B4FinalisationBindingError::MissingReleaseAuthorization});
    }
    if (!release_authorization->valid()) {
        return std::unexpected(
            B4FinalisationExchangeError{B4FinalisationBindingError::InvalidReleaseAuthorization});
    }
    if (release_authorization->kind() != TransportAuthKind::ReleaseAuthorization) {
        return std::unexpected(
            B4FinalisationExchangeError{B4FinalisationBindingError::WrongReleaseAuthorizationKind});
    }

    auto receipt = std::get<B4FinalisationResult>(std::move(response));
    B4PendingRelease pending{received_b2_request.request_id, result, std::move(receipt),
                             std::move(*release_authorization)};
    return B4BoundFinalisation{std::in_place_type<B4PendingRelease>, std::move(pending)};
}

} // namespace yuzu::contracts::adr31
