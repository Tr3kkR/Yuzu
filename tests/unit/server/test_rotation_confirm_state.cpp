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
using yuzu::server::detail::pair_matches_pin;
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

namespace {

// A linked (predecessor, successor) pair - same rotation_group, successor's
// supersedes_token_id pointing at the predecessor.
std::pair<ApiToken, ApiToken> linked_pair(const std::string& predecessor_id,
                                          const std::string& successor_id,
                                          const std::string& group = "grp-1") {
    ApiToken predecessor = clear_token(predecessor_id);
    predecessor.rotation_group = group;
    ApiToken successor = clear_token(successor_id);
    successor.rotation_group = group;
    successor.supersedes_token_id = predecessor_id;
    return {predecessor, successor};
}

} // namespace

// #2443: `classify_confirm_state` alone only counts rows - `pair_matches_pin`
// is the additional check that closes the burn where a NEWER rotation (a
// different successor token_id than the ticket was minted for) also reads as
// `kPair`.
TEST_CASE("pair_matches_pin", "[rotation_confirm][2443]") {
    SECTION("not exactly 2 active -> false regardless of content") {
        CHECK_FALSE(pair_matches_pin({}, "x"));
        CHECK_FALSE(pair_matches_pin({clear_token("a")}, "a"));
        auto [p, s] = linked_pair("p", "s");
        CHECK_FALSE(pair_matches_pin({p, s, clear_token("c")}, "s"));
    }
    SECTION("linked pair, pin matches the successor -> true") {
        auto [p, s] = linked_pair("p", "s");
        CHECK(pair_matches_pin({p, s}, "s"));
        CHECK(pair_matches_pin({s, p}, "s")); // order-independent
    }
    SECTION("linked pair, pin does NOT match the successor (a NEWER rotation) -> false") {
        // The exact #2443 burn shape: the ticket was pinned to an OLDER
        // successor ("old-s") that has since resolved; a NEW rotation
        // produced a different successor ("new-s"). Both are still
        // structurally a valid pair - just not the pair this ticket names.
        auto [p, s] = linked_pair("p", "new-s");
        CHECK_FALSE(pair_matches_pin({p, s}, "old-s"));
    }
    SECTION("two active rows but NOT linked to each other -> false even if the pin matches "
            "one of them") {
        // Two independently-minted standalone credentials (no rotation in
        // progress between them) must never read as a confirmable pair.
        ApiToken a = clear_token("a");
        ApiToken b = clear_token("b");
        CHECK_FALSE(pair_matches_pin({a, b}, "b"));
    }
    SECTION("mismatched rotation_group -> false") {
        auto [p, s] = linked_pair("p", "s", "grp-1");
        s.rotation_group = "grp-2"; // linkage broken
        CHECK_FALSE(pair_matches_pin({p, s}, "s"));
    }
    SECTION("supersedes_token_id points at the wrong predecessor -> false") {
        auto [p, s] = linked_pair("p", "s");
        s.supersedes_token_id = "not-p";
        CHECK_FALSE(pair_matches_pin({p, s}, "s"));
    }
    SECTION("both rows look like successors (malformed) -> no predecessor found -> false") {
        ApiToken a = clear_token("a");
        a.supersedes_token_id = "x";
        ApiToken b = clear_token("b");
        b.supersedes_token_id = "y";
        CHECK_FALSE(pair_matches_pin({a, b}, "a"));
    }
}
