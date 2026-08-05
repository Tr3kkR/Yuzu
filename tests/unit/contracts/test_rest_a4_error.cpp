#include <yuzu/contracts/adr31/rest_a4_error.hpp>

#include <catch2/catch_test_macros.hpp>

#include <optional>
#include <type_traits>

namespace contracts = yuzu::contracts::adr31;

static_assert(std::is_aggregate_v<contracts::A4ErrorEnvelope>);

TEST_CASE("ADR-0031 REST A4 error value is independent of a seam DTO", "[adr31][contract][a4]") {
    const contracts::A4ErrorEnvelope error{
        .code = 503,
        .message = "service unavailable",
        .correlation_id = "req-contract-0001",
        .retry_after_ms = 5000,
        .remediation = std::nullopt,
        .permission = std::nullopt,
        .approval_id = std::nullopt,
        .status_url = std::nullopt,
    };
    auto same_error = error;
    CHECK(same_error == error);
}
