#pragma once

#include "contract_error.hpp"

#include <nlohmann/json.hpp>

#include <expected>
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

[[nodiscard]] std::expected<std::string, ContractError>
encode_b2_use_case_request(const B2UseCaseRequest& request);

[[nodiscard]] std::expected<B2UseCaseRequest, ContractError>
decode_b2_use_case_request(std::string_view wire_json);

} // namespace yuzu::contracts::adr31
