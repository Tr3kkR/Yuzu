#include <yuzu/contracts/adr31/contract_version.hpp>

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <string_view>

namespace contracts = yuzu::contracts::adr31;

TEST_CASE("ADR-0031 contracts publish stable identifiers and versions", "[adr31][contract]") {
    constexpr std::array expected{
        std::string_view{"yuzu.b2.use_case.request"},
        std::string_view{"yuzu.b2.use_case.result"},
        std::string_view{"yuzu.b3.platform.request"},
        std::string_view{"yuzu.b3.platform.result"},
        std::string_view{"yuzu.b4.fact"},
        std::string_view{"yuzu.b4.finalisation"},
        std::string_view{"yuzu.b4.redemption"},
    };

    const auto published = contracts::contract_descriptors();
    REQUIRE(published.size() == expected.size());

    for (std::size_t i = 0; i < published.size(); ++i) {
        CHECK(published[i].identifier == expected[i]);
        CHECK(published[i].current == contracts::ContractVersion{1, 0});
        REQUIRE(published[i].supported_versions.size() == 1);
        CHECK(published[i].supported_versions.front() == contracts::ContractVersion{1, 0});
        CHECK(contracts::supports(published[i], published[i].current));
        CHECK_FALSE(contracts::supports(published[i], contracts::ContractVersion{1, 1}));
        CHECK_FALSE(contracts::supports(published[i], contracts::ContractVersion{2, 0}));
    }
}
