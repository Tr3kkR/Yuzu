// test_gateway_route_reap_rules.cpp — HA WS-4 slice 4.2a, PR #4299 round-3.
//
// PURE decision-layer tests for gateway_route_reap_rules.hpp's `decide_reap`
// and the two parsers (`parse_reap_i64`, `parse_declined_marker`). NO [pg], NO
// Postgres — this is the whole point of the decide/apply split: every reap
// outcome (what to do to the sweeps, the anchor, and the decline marker) is a
// value computed from raw text, checkable without a database.
//
// The integration layer — that the apply tail in gateway_route_store.cpp wires
// these decisions onto real SQL correctly — stays in test_gateway_route_store's
// [pg] suite (raw_get_reap_declined_anchor / raw_get_reap_anchor), unchanged.

#include "gateway_route_reap_rules.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <optional>
#include <string_view>

using namespace yuzu::server;

namespace {

// This store's own implausible-skew bound (kMaxPlausibleSkewMs = 1 day). The
// pure layer takes it as a parameter; these tests pin the production value so
// the forward-skew threshold matches what reap_stale_routes passes.
constexpr std::int64_t kSkew = 24LL * 3600 * 1000;

// A plausible "now" well clear of the skew bound from the anchors below.
constexpr std::int64_t kNow = 1'000'000'000'000; // ~2001 in epoch-ms, arbitrary but positive

std::optional<std::string_view> sv(std::string_view s) { return std::optional<std::string_view>(s); }

} // namespace

// --- decide_reap: the five-decision set -------------------------------------

TEST_CASE("decide_reap: bad now (unparseable) -> clear marker, no sweep, anomaly",
          "[gateway_route][reap_rules]") {
    const ReapDecision d = decide_reap("not-a-number", sv("900000000000"),
                                       sv("900000000000:forward"), kSkew);
    CHECK(d.marker.kind() == MarkerAction::Kind::Clear);
    CHECK_FALSE(d.new_anchor.has_value()); // anchor untouched
    CHECK_FALSE(d.run_sweeps);
    CHECK(d.clock_anomaly);
    CHECK_FALSE(d.recovered);
}

TEST_CASE("decide_reap: bad now (negative) -> clear marker, no sweep, anomaly",
          "[gateway_route][reap_rules]") {
    const ReapDecision d = decide_reap("-5", sv("900000000000"), std::nullopt, kSkew);
    CHECK(d.marker.kind() == MarkerAction::Kind::Clear);
    CHECK_FALSE(d.new_anchor.has_value());
    CHECK_FALSE(d.run_sweeps);
    CHECK(d.clock_anomaly);
    CHECK_FALSE(d.recovered);
}

TEST_CASE("decide_reap: corrupt persisted anchor -> clear + re-anchor to now, no sweep, anomaly",
          "[gateway_route][reap_rules]") {
    SECTION("unparseable anchor") {
        const ReapDecision d =
            decide_reap(std::to_string(kNow), sv("garbage"), sv("123:backward"), kSkew);
        CHECK(d.marker.kind() == MarkerAction::Kind::Clear);
        REQUIRE(d.new_anchor.has_value());
        CHECK(*d.new_anchor == kNow); // re-anchored to THIS pass's now
        CHECK_FALSE(d.run_sweeps);
        CHECK(d.clock_anomaly);
        CHECK_FALSE(d.recovered);
    }
    SECTION("negative anchor") {
        const ReapDecision d = decide_reap(std::to_string(kNow), sv("-1"), std::nullopt, kSkew);
        CHECK(d.marker.kind() == MarkerAction::Kind::Clear);
        REQUIRE(d.new_anchor.has_value());
        CHECK(*d.new_anchor == kNow);
        CHECK_FALSE(d.run_sweeps);
        CHECK(d.clock_anomaly);
    }
}

TEST_CASE("decide_reap: no anchor (first pass) -> clear + anchor to now + run sweeps",
          "[gateway_route][reap_rules]") {
    const ReapDecision d = decide_reap(std::to_string(kNow), std::nullopt, std::nullopt, kSkew);
    CHECK(d.marker.kind() == MarkerAction::Kind::Clear);
    REQUIRE(d.new_anchor.has_value());
    CHECK(*d.new_anchor == kNow);
    CHECK(d.run_sweeps);
    CHECK_FALSE(d.clock_anomaly);
    CHECK_FALSE(d.recovered);
}

TEST_CASE("decide_reap: clean pass (valid anchor, no skew) -> clear + advance to max + run sweeps",
          "[gateway_route][reap_rules]") {
    SECTION("anchor behind now -> advance to now") {
        const std::int64_t anchor = kNow - 5000;
        const ReapDecision d =
            decide_reap(std::to_string(kNow), sv(std::to_string(anchor)), std::nullopt, kSkew);
        CHECK(d.marker.kind() == MarkerAction::Kind::Clear);
        REQUIRE(d.new_anchor.has_value());
        CHECK(*d.new_anchor == kNow); // max(anchor, now) == now
        CHECK(d.run_sweeps);
        CHECK_FALSE(d.clock_anomaly);
        CHECK_FALSE(d.recovered);
    }
    SECTION("anchor equal to now -> stays") {
        const ReapDecision d =
            decide_reap(std::to_string(kNow), sv(std::to_string(kNow)), std::nullopt, kSkew);
        REQUIRE(d.new_anchor.has_value());
        CHECK(*d.new_anchor == kNow);
        CHECK(d.run_sweeps);
    }
    SECTION("anchor a little ahead but within skew -> NOT a backward anomaly is false; "
            "now<anchor IS backward") {
        // now just below anchor is a backward skew, NOT a clean pass — covered
        // by the backward-skew case below. Here: anchor slightly behind within
        // plausible range stays a clean advance.
        const std::int64_t anchor = kNow - 1; // now ahead by 1ms, well under skew
        const ReapDecision d =
            decide_reap(std::to_string(kNow), sv(std::to_string(anchor)), std::nullopt, kSkew);
        REQUIRE(d.new_anchor.has_value());
        CHECK(*d.new_anchor == kNow);
        CHECK(d.run_sweeps);
        CHECK_FALSE(d.clock_anomaly);
    }
}

TEST_CASE("decide_reap: fresh forward skew, no marker -> ARM(forward), no sweep, anomaly",
          "[gateway_route][reap_rules]") {
    const std::int64_t anchor = kNow - 2 * kSkew; // now - anchor > 1 day
    const ReapDecision d =
        decide_reap(std::to_string(kNow), sv(std::to_string(anchor)), std::nullopt, kSkew);
    REQUIRE(d.marker.kind() == MarkerAction::Kind::Arm);
    CHECK(d.marker.anchor() == anchor);
    CHECK(d.marker.direction() == "forward");
    CHECK_FALSE(d.new_anchor.has_value()); // decline never advances the anchor
    CHECK_FALSE(d.run_sweeps);
    CHECK(d.clock_anomaly);
    CHECK_FALSE(d.recovered);
}

TEST_CASE("decide_reap: fresh backward skew, no marker -> ARM(backward), no sweep, anomaly",
          "[gateway_route][reap_rules]") {
    const std::int64_t anchor = kNow + 3600LL * 1000; // anchor ahead of now -> backward
    const ReapDecision d =
        decide_reap(std::to_string(kNow), sv(std::to_string(anchor)), std::nullopt, kSkew);
    REQUIRE(d.marker.kind() == MarkerAction::Kind::Arm);
    CHECK(d.marker.anchor() == anchor);
    CHECK(d.marker.direction() == "backward");
    CHECK_FALSE(d.new_anchor.has_value());
    CHECK_FALSE(d.run_sweeps);
    CHECK(d.clock_anomaly);
}

TEST_CASE("decide_reap: matched (same anchor AND direction) repeat -> RECOVER, unconditional "
          "re-anchor to now, run sweeps",
          "[gateway_route][reap_rules]") {
    const std::int64_t anchor = kNow - 2 * kSkew; // forward skew
    const ReapDecision d = decide_reap(std::to_string(kNow), sv(std::to_string(anchor)),
                                       sv(std::to_string(anchor) + ":forward"), kSkew);
    CHECK(d.marker.kind() == MarkerAction::Kind::Clear);
    REQUIRE(d.new_anchor.has_value());
    CHECK(*d.new_anchor == kNow); // UNCONDITIONAL now, never max(anchor, now)
    CHECK(d.run_sweeps);
    CHECK_FALSE(d.clock_anomaly);
    CHECK(d.recovered);
}

TEST_CASE("decide_reap: different-DIRECTION marker at same anchor (r2) -> ARM, not RECOVER",
          "[gateway_route][reap_rules]") {
    // The anomaly THIS pass sees is forward-skew; the marker frozen at the same
    // anchor claims "backward". Anchor matches, direction does not -> re-decline
    // (never recover) — the round-2 external-review defect this guards.
    const std::int64_t anchor = kNow - 2 * kSkew; // forward skew this pass
    const ReapDecision d = decide_reap(std::to_string(kNow), sv(std::to_string(anchor)),
                                       sv(std::to_string(anchor) + ":backward"), kSkew);
    REQUIRE(d.marker.kind() == MarkerAction::Kind::Arm);
    CHECK(d.marker.direction() == "forward"); // re-armed with THIS pass's direction
    CHECK_FALSE(d.new_anchor.has_value());
    CHECK_FALSE(d.run_sweeps);
    CHECK(d.clock_anomaly);
    CHECK_FALSE(d.recovered);
}

TEST_CASE("decide_reap: different-ANCHOR marker -> ARM, not RECOVER", "[gateway_route][reap_rules]") {
    const std::int64_t anchor = kNow - 2 * kSkew; // forward skew
    const std::int64_t other_anchor = anchor - 777;
    const ReapDecision d = decide_reap(std::to_string(kNow), sv(std::to_string(anchor)),
                                       sv(std::to_string(other_anchor) + ":forward"), kSkew);
    REQUIRE(d.marker.kind() == MarkerAction::Kind::Arm);
    CHECK(d.marker.anchor() == anchor);
    CHECK(d.marker.direction() == "forward");
    CHECK_FALSE(d.run_sweeps);
    CHECK(d.clock_anomaly);
    CHECK_FALSE(d.recovered);
}

TEST_CASE("decide_reap: unparseable/legacy marker under a skew -> ARM (treated as absent)",
          "[gateway_route][reap_rules]") {
    const std::int64_t anchor = kNow - 2 * kSkew; // forward skew
    SECTION("legacy bare-integer marker (no :direction)") {
        const ReapDecision d = decide_reap(std::to_string(kNow), sv(std::to_string(anchor)),
                                           sv(std::to_string(anchor)), kSkew);
        REQUIRE(d.marker.kind() == MarkerAction::Kind::Arm);
        CHECK(d.marker.direction() == "forward");
        CHECK_FALSE(d.recovered);
    }
    SECTION("garbage marker") {
        const ReapDecision d =
            decide_reap(std::to_string(kNow), sv(std::to_string(anchor)), sv("total-garbage"), kSkew);
        REQUIRE(d.marker.kind() == MarkerAction::Kind::Arm);
        CHECK_FALSE(d.recovered);
    }
}

// The r3 scenario: a valid marker "A:forward" exists, but now_raw is
// negative/junk — the bad-now guard runs FIRST and CLEARs the marker, so a
// FOLLOWING forward skew at A re-arms fresh rather than free-riding the stale
// recovery identity. (The pre-fix bad-now branch LEFT the marker.)
TEST_CASE("decide_reap: bad now with a matching-looking marker present still CLEARs it (r3 fix)",
          "[gateway_route][reap_rules]") {
    const std::int64_t anchor = kNow - 2 * kSkew;
    SECTION("junk now") {
        const ReapDecision d = decide_reap("junk", sv(std::to_string(anchor)),
                                           sv(std::to_string(anchor) + ":forward"), kSkew);
        CHECK(d.marker.kind() == MarkerAction::Kind::Clear); // NOT left, NOT recovered
        CHECK_FALSE(d.new_anchor.has_value());
        CHECK_FALSE(d.run_sweeps);
        CHECK(d.clock_anomaly);
        CHECK_FALSE(d.recovered);
    }
    SECTION("negative now") {
        const ReapDecision d = decide_reap("-1", sv(std::to_string(anchor)),
                                           sv(std::to_string(anchor) + ":forward"), kSkew);
        CHECK(d.marker.kind() == MarkerAction::Kind::Clear);
        CHECK_FALSE(d.recovered);
    }
}

// --- parse_reap_i64: the from_chars malformed-input matrix -------------------

TEST_CASE("parse_reap_i64: canonical integers accepted", "[gateway_route][reap_rules]") {
    CHECK(parse_reap_i64("0") == std::optional<std::int64_t>(0));
    CHECK(parse_reap_i64("5") == std::optional<std::int64_t>(5));
    CHECK(parse_reap_i64("-5") == std::optional<std::int64_t>(-5));
    CHECK(parse_reap_i64("1000000000000") == std::optional<std::int64_t>(1000000000000));
}

TEST_CASE("parse_reap_i64: non-canonical / malformed rejected", "[gateway_route][reap_rules]") {
    CHECK_FALSE(parse_reap_i64("").has_value());         // empty
    CHECK_FALSE(parse_reap_i64(" 5").has_value());       // leading ws
    CHECK_FALSE(parse_reap_i64("5 ").has_value());       // trailing ws
    CHECK_FALSE(parse_reap_i64("+5").has_value());       // leading +
    CHECK_FALSE(parse_reap_i64("007").has_value());      // zero-padded (non-canonical)
    CHECK_FALSE(parse_reap_i64("-0").has_value());       // negative zero (non-canonical)
    CHECK_FALSE(parse_reap_i64("123abc").has_value());   // trailing garbage
    CHECK_FALSE(parse_reap_i64("1.5").has_value());      // not an integer
    CHECK_FALSE(parse_reap_i64("abc").has_value());      // not a number
    CHECK_FALSE(parse_reap_i64("5:forward").has_value()); // the whole marker, not a bare int
}

// --- parse_declined_marker: the marker-format matrix ------------------------

TEST_CASE("parse_declined_marker: well-formed markers accepted", "[gateway_route][reap_rules]") {
    auto f = parse_declined_marker("42:forward");
    REQUIRE(f.has_value());
    CHECK(f->first == 42);
    CHECK(f->second == "forward");

    auto b = parse_declined_marker("1000000000000:backward");
    REQUIRE(b.has_value());
    CHECK(b->first == 1000000000000);
    CHECK(b->second == "backward");

    auto zero = parse_declined_marker("0:forward");
    REQUIRE(zero.has_value());
    CHECK(zero->first == 0);
}

TEST_CASE("parse_declined_marker: malformed markers treated as absent",
          "[gateway_route][reap_rules]") {
    CHECK_FALSE(parse_declined_marker("").has_value());            // empty
    CHECK_FALSE(parse_declined_marker("42").has_value());          // legacy bare integer, no colon
    CHECK_FALSE(parse_declined_marker("42:sideways").has_value()); // bad direction token
    CHECK_FALSE(parse_declined_marker("42:FORWARD").has_value());  // case-sensitive
    CHECK_FALSE(parse_declined_marker("42:").has_value());         // empty direction
    CHECK_FALSE(parse_declined_marker(":forward").has_value());    // empty anchor
    CHECK_FALSE(parse_declined_marker("-5:forward").has_value());  // negative anchor rejected
    CHECK_FALSE(parse_declined_marker("007:forward").has_value()); // non-canonical anchor rejected
    CHECK_FALSE(parse_declined_marker(" 5:forward").has_value());  // leading ws on anchor
    CHECK_FALSE(parse_declined_marker("42:forward:extra").has_value()); // multi-colon: "forward:extra" not a direction
    CHECK_FALSE(parse_declined_marker("abc:forward").has_value());  // non-numeric anchor
}

TEST_CASE("decide_reap: a negative skew bound is clamped to 0 (cannot invert the clean path)",
          "[gateway_route][reap_rules]") {
    // Defensive clamp: an unclamped negative max_plausible_skew_ms would make
    // now==anchor read as forward-skew (0 > -1) — a spurious decline on an
    // otherwise-clean pass. The entry clamp (<0 -> 0) keeps now==anchor clean.
    // Discriminating: without the clamp these CHECK_FALSEs flip (arm + anomaly).
    const ReapDecision d =
        decide_reap(std::to_string(kNow), sv(std::to_string(kNow)), std::nullopt, -1);
    CHECK(d.marker.kind() == MarkerAction::Kind::Clear);
    REQUIRE(d.new_anchor.has_value());
    CHECK(*d.new_anchor == kNow);
    CHECK(d.run_sweeps);
    CHECK_FALSE(d.clock_anomaly); // clamp present: clean pass, not a forward-skew decline
    CHECK_FALSE(d.recovered);
}
