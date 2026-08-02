#include "json_support.hpp"

#include <nlohmann/json.hpp>

#include <array>
#include <string>
#include <string_view>

namespace yuzu::contracts::adr31::detail {
namespace {

constexpr std::array<std::string_view, 39> kForbiddenAuthorityNames{
    "accesstoken",
    "apitoken",
    "actor",
    "actorid",
    "actingprincipal",
    "actingprincipalid",
    "audience",
    "auth",
    "authenticatedactor",
    "authenticatedprincipal",
    "authorization",
    "bearertoken",
    "caller",
    "callerid",
    "credential",
    "credentialid",
    "credentials",
    "engineprincipal",
    "engineprincipalid",
    "grant",
    "invocationgrant",
    "onbehalfof",
    "operator",
    "operatorid",
    "principal",
    "principalcredential",
    "principalid",
    "recipient",
    "releaseauthorization",
    "representedoperator",
    "representedoperatorid",
    "resultscopedgrant",
    "scopeceiling",
    "sessiontoken",
    "subject",
    "subjectid",
    "token",
    "user",
    "userid",
};

[[nodiscard]] std::string normalise_name(std::string_view name) {
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

} // namespace

std::expected<void, ContractError>
reject_forbidden_authority_fields(const nlohmann::json& root) {
    for (auto it = root.begin(); it != root.end(); ++it) {
        const auto normalised = normalise_name(it.key());
        for (const auto forbidden : kForbiddenAuthorityNames) {
            if (normalised == forbidden) {
                return std::unexpected(ContractError{
                    ContractErrorCode::ForbiddenAuthorityField,
                    "/" + std::string{forbidden},
                    "caller-authored identity or authentication context is forbidden",
                });
            }
        }
    }
    return {};
}

} // namespace yuzu::contracts::adr31::detail
