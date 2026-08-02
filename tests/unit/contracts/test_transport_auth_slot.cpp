#include <yuzu/contracts/adr31/b3_platform.hpp>
#include <yuzu/contracts/adr31/transport_auth_slot.hpp>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <sstream>
#include <string>
#include <type_traits>
#include <utility>

namespace contracts = yuzu::contracts::adr31;

static_assert(!std::is_default_constructible_v<contracts::TransportAuthSlot>);
static_assert(!std::is_copy_constructible_v<contracts::TransportAuthSlot>);
static_assert(!std::is_copy_assignable_v<contracts::TransportAuthSlot>);
static_assert(std::is_nothrow_move_constructible_v<contracts::TransportAuthSlot>);
static_assert(std::is_nothrow_move_assignable_v<contracts::TransportAuthSlot>);

TEST_CASE("ADR-0031 transport authentication is a move-only redacted lease",
          "[adr31][contract][auth]") {
    constexpr std::string_view secret = "contract-fixture-secret";
    auto created = contracts::make_transport_auth_slot(
        contracts::TransportAuthKind::CallerCredential, std::string{secret});
    REQUIRE(created.has_value());
    CHECK(created->valid());
    CHECK(created->kind() == contracts::TransportAuthKind::CallerCredential);

    bool visited = false;
    REQUIRE(created->visit_secret([&](std::string_view value) {
        visited = true;
        CHECK(value == secret);
    }));
    CHECK(visited);

    std::ostringstream rendered;
    rendered << *created;
    CHECK(rendered.str() == "<redacted:caller-credential>");
    CHECK(rendered.str().find(secret) == std::string::npos);

    auto moved = std::move(*created);
    CHECK_FALSE(created->valid());
    CHECK(moved.valid());
    CHECK_FALSE(created->visit_secret([](std::string_view) {}));

    const contracts::B3PlatformRequest request{
        .correlation_id = "req-contract-0001",
        .securable = "GuaranteedState",
        .operation = contracts::CoreOperation::Read,
        .scope = nlohmann::json{{"kind", "fleet"}},
    };
    const auto encoded = contracts::encode_b3_platform_request(request);
    REQUIRE(encoded.has_value());
    CHECK(encoded->find(secret) == std::string::npos);
}

TEST_CASE("ADR-0031 transport authentication rejects empty and oversized material",
          "[adr31][contract][auth][negative]") {
    const auto empty = contracts::make_transport_auth_slot(
        contracts::TransportAuthKind::CallerCredential, std::string{});
    REQUIRE_FALSE(empty.has_value());
    CHECK(empty.error() == contracts::TransportAuthError::Empty);

    const auto oversized = contracts::make_transport_auth_slot(
        contracts::TransportAuthKind::InvocationGrant,
        std::string(contracts::kMaxTransportAuthBytes + 1, 'x'));
    REQUIRE_FALSE(oversized.has_value());
    CHECK(oversized.error() == contracts::TransportAuthError::TooLarge);

    for (const char invalid : {'\0', '\r', '\n'}) {
        const auto unsafe =
            contracts::make_transport_auth_slot(contracts::TransportAuthKind::EngineCredential,
                                                std::string{"credential"} + invalid + "suffix");
        REQUIRE_FALSE(unsafe.has_value());
        CHECK(unsafe.error() == contracts::TransportAuthError::InvalidCharacter);
    }
}
