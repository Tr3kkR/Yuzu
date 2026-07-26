/**
 * test_rotation_confirm_state.cpp — locks the pure confirm-state classifier
 * (rotation_confirm_state.hpp) that decides, from the active-credential set a
 * confirm reads under the advisory lock, whether the state is a terminal
 * conflict, a permanent client error, or the one deliberately-retryable
 * empty/ambiguous case (#2404). No DB — the classifier is a pure function over
 * an already-read vector; the store test (test_api_token_store.cpp) exercises
 * the wired behaviour end-to-end.
 */

#include "rotation_confirm_state.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

using yuzu::server::ApiToken;
using yuzu::server::detail::classify_confirm_state;
using yuzu::server::detail::RotationConfirmState;

namespace {

// A plain standalone (never-/no-longer-rotating) engine credential.
ApiToken clear_token(const std::string& id, int64_t confirmed_at = 0) {
    ApiToken t;
    t.token_id = id;
    t.principal_kind = "engine";
    t.confirmed_at = confirmed_at;
    // rotation_group / supersedes_token_id / overlap_expires_at stay empty/0.
    return t;
}

} // namespace

TEST_CASE("classify_confirm_state: count-based states", "[rotation_confirm]") {
    const std::string pin = "aaaa";

    // 0 active -> ambiguous with a swallowed read failure -> retryable.
    CHECK(classify_confirm_state({}, pin) == RotationConfirmState::kNoneActive);

    // >2 active -> a credential minted outside the rotation path.
    std::vector<ApiToken> three{clear_token("a"), clear_token("b"), clear_token("c")};
    CHECK(classify_confirm_state(three, pin) == RotationConfirmState::kOverfull);

    // exactly 2 -> the caller's normal pair-processing path (pin/linkage checked
    // downstream by confirm_rotation itself, not here).
    std::vector<ApiToken> two{clear_token("a"), clear_token("b")};
    CHECK(classify_confirm_state(two, pin) == RotationConfirmState::kPair);
}

TEST_CASE("classify_confirm_state: sole-credential discrimination", "[rotation_confirm]") {
    const std::string pin = "successor-1";

    SECTION("linkage NOT clear (rotation_group set) -> unresolved, do not rotate") {
        ApiToken t = clear_token(pin);
        t.rotation_group = "grp-1";
        CHECK(classify_confirm_state({t}, pin) == RotationConfirmState::kUnresolvedSole);
    }
    SECTION("linkage NOT clear (supersedes set) -> unresolved") {
        ApiToken t = clear_token(pin);
        t.supersedes_token_id = "predecessor-0";
        CHECK(classify_confirm_state({t}, pin) == RotationConfirmState::kUnresolvedSole);
    }
    SECTION("clear + pin matches + confirmed_at != 0 -> already confirmed") {
        ApiToken t = clear_token(pin, /*confirmed_at=*/12345);
        CHECK(classify_confirm_state({t}, pin) == RotationConfirmState::kSoleConfirmed);
    }
    SECTION("clear + pin matches + confirmed_at == 0 -> resolved without confirm") {
        ApiToken t = clear_token(pin, /*confirmed_at=*/0);
        CHECK(classify_confirm_state({t}, pin) == RotationConfirmState::kSoleResolved);
    }
    SECTION("clear + pin does NOT match -> the rotation moved on") {
        ApiToken t = clear_token("some-other-token", /*confirmed_at=*/999);
        CHECK(classify_confirm_state({t}, pin) == RotationConfirmState::kSoleOtherToken);
    }
}
