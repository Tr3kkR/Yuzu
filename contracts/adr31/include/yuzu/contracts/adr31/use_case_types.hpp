#pragma once

#include <nlohmann/json.hpp>

#include <cstdint>
#include <string>

namespace yuzu::contracts::adr31 {

/// Exact versioned artifact reference; never an authenticated principal or an
/// authority claim.
struct VersionedIdentity {
    std::string id;
    std::string version;

    friend bool operator==(const VersionedIdentity&, const VersionedIdentity&) = default;
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

} // namespace yuzu::contracts::adr31
