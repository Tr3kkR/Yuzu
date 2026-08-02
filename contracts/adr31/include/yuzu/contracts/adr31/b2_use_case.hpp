#pragma once

#include "contract_error.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>

namespace yuzu::contracts::adr31 {

struct VersionedIdentity {
    std::string id;
    std::string version;

    friend bool operator==(const VersionedIdentity&, const VersionedIdentity&) = default;
};

struct B2UseCaseRequest {
    std::string request_id;
    std::string use_case_run_id;
    VersionedIdentity use_case;
    VersionedIdentity module;
    nlohmann::json normalised_inputs;
};

enum class ScopeBasis : std::uint8_t {
    Global,
    AuthorityScoped,
};

enum class Completeness : std::uint8_t {
    Complete,
    Partial,
    Insufficient,
    Unknown,
};

struct CompletenessPolicy {
    std::uint8_t minimum_response_percent;
    bool blocks_next_step_when_incomplete;
    nlohmann::json extensions = nlohmann::json::object();

    friend bool operator==(const CompletenessPolicy&, const CompletenessPolicy&) = default;
};

struct CoverageEnvelope {
    std::uint64_t intended;
    std::uint64_t contacted;
    std::uint64_t responded;
    std::uint64_t failed;
    std::uint64_t timed_out;
    std::uint64_t offline;
    ScopeBasis scope_basis;
    Completeness completeness;
    CompletenessPolicy policy;
    nlohmann::json extensions = nlohmann::json::object();

    friend bool operator==(const CoverageEnvelope&, const CoverageEnvelope&) = default;
};

struct B2UseCaseResultPayload {
    nlohmann::json facts;
    CoverageEnvelope coverage;
    nlohmann::json provenance;
    nlohmann::json decisions;
    std::optional<nlohmann::json> proposed_plan_reference;
    nlohmann::json extensions = nlohmann::json::object();

    friend bool operator==(const B2UseCaseResultPayload&, const B2UseCaseResultPayload&) = default;
};

struct B2UseCaseResult {
    std::string request_id;
    std::string use_case_run_id;
    std::string result_schema_version;
    B2UseCaseResultPayload result;
    std::string finalisation_receipt;

    friend bool operator==(const B2UseCaseResult&, const B2UseCaseResult&) = default;
};

[[nodiscard]] std::expected<std::string, ContractError>
encode_b2_use_case_request(const B2UseCaseRequest& request);

[[nodiscard]] std::expected<B2UseCaseRequest, ContractError>
decode_b2_use_case_request(std::string_view wire_json);

/// Canonical bytes Core hashes at admission and the engine hashes again before
/// starting the run. This is Yuzu's compact, sorted nlohmann JSON projection;
/// it is not advertised as RFC 8785/JCS.
[[nodiscard]] std::expected<std::string, ContractError>
canonical_b2_input_bytes(const B2UseCaseRequest& request);

[[nodiscard]] std::expected<std::string, ContractError>
encode_b2_use_case_result(const B2UseCaseResult& result);

[[nodiscard]] std::expected<B2UseCaseResult, ContractError>
decode_b2_use_case_result(std::string_view wire_json);

/// Canonical result hash domain. It includes the schema version and result
/// payload, but deliberately excludes the Core-issued finalisation receipt.
[[nodiscard]] std::expected<std::string, ContractError>
canonical_b2_result_bytes(const B2UseCaseResult& result);

[[nodiscard]] std::expected<std::string, ContractError>
canonical_b2_result_bytes(std::string_view result_schema_version,
                          const B2UseCaseResultPayload& result);

} // namespace yuzu::contracts::adr31
