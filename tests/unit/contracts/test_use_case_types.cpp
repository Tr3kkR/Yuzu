#include <yuzu/contracts/adr31/use_case_types.hpp>

#include <catch2/catch_test_macros.hpp>

#include <type_traits>

namespace contracts = yuzu::contracts::adr31;

static_assert(std::is_aggregate_v<contracts::VersionedIdentity>);
static_assert(std::is_aggregate_v<contracts::CompletenessPolicy>);
static_assert(std::is_aggregate_v<contracts::CoverageEnvelope>);

TEST_CASE("ADR-0031 shared use-case values are independent of B2", "[adr31][contract][types]") {
    const contracts::VersionedIdentity identity{
        .id = "vulnerability-management",
        .version = "3.1.4",
    };
    CHECK(identity == contracts::VersionedIdentity{
                          .id = "vulnerability-management",
                          .version = "3.1.4",
                      });

    const contracts::CoverageEnvelope coverage{
        .intended = 2,
        .contacted = 2,
        .responded = 1,
        .failed = 0,
        .timed_out = 1,
        .offline = 0,
        .scope_basis = contracts::ScopeBasis::AuthorityScoped,
        .completeness = contracts::Completeness::Partial,
        .policy =
            {
                .minimum_response_percent = 100,
                .blocks_next_step_when_incomplete = true,
            },
    };
    auto same_coverage = coverage;
    CHECK(same_coverage == coverage);
}
