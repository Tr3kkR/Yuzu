#pragma once

/// @file gateway_route_reap_rules.hpp
/// HA WS-4 slice 4.2a — the PURE decision half of
/// `GatewayRouteStore::reap_stale_routes()` (PR #4299 round-3 review).
///
/// WHY THIS FILE EXISTS (the marker-obligation class). `reap_stale_routes()`
/// had THREE rounds of the SAME defect: one terminal/decline path forgetting
/// to decide what happens to the persisted `reap_declined_anchor_ms` marker
/// (LEAVE it, CLEAR it, or ARM it). Each round hand-patched the one path that
/// was wrong and left the class open for a fourth. This header closes the
/// class structurally by SPLITTING decide-from-apply: every reap outcome is a
/// `ReapDecision` whose `marker` field is a `MarkerAction` with NO default
/// constructor, so a future branch that forgets the marker decision is a
/// COMPILE error (the same discipline `command_capability.hpp`'s `ExecuteGate`
/// uses to make an omitted gate a build failure).
///
/// PURE (server-local, NOT common/include/ — this is server-trust-boundary
/// reap policy, not shared decision code). No DB, no `now()`, no I/O: the
/// caller performs the three reads (DB `now()`, the persisted `reap_anchor_ms`
/// anchor, the `reap_declined_anchor_ms` marker) and hands `decide_reap` the
/// raw SELECTed text; `decide_reap` returns what to do, and the caller's ONE
/// apply tail executes it. This makes every decision unit-testable with no
/// Postgres at all (see tests/unit/server/test_gateway_route_reap_rules.cpp).
///
/// The semantics here are BYTE-IDENTICAL to the pre-split behaviour for every
/// path EXCEPT the bad-`now()` branch: that path used to LEAVE the marker
/// (round-3 defect), and now CLEARs it — a distinct anomaly must not leave a
/// stale recovery identity behind, so a later same-direction skew is judged
/// fresh. See docs/clock-guarded-retention.md's GatewayRouteStore entry.

#include <algorithm> // std::max — anchor advance (parenthesised for the MSVC <windows.h> macro)
#include <charconv>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace yuzu::server {

/// Checked parse of a Postgres bigint text value, hardened past a bare
/// `strtoll` (PR #4299 round-3 review): `std::from_chars` + FULL consumption
/// (`ptr == end`) + a canonical round-trip (`std::to_string(v) == input`),
/// following `leader_elector.cpp`'s `parse_i64`. The round-trip rejects the
/// non-canonical forms `strtoll` silently accepted — leading/trailing space,
/// a leading `+`, zero-padding (`007`), and `-0` — so a value is parseable
/// here ONLY if this store could itself have written it. A garbled-but-
/// otherwise-numeric stored value therefore reads as absent (→ re-decline),
/// never as a spurious match. Empty, unparseable, or trailing-garbage → nullopt.
inline std::optional<std::int64_t> parse_reap_i64(std::string_view val) {
    std::int64_t v = 0;
    const char* begin = val.data();
    const char* end = begin + val.size();
    auto [ptr, ec] = std::from_chars(begin, end, v);
    if (ec != std::errc{} || ptr != end)
        return std::nullopt;
    // Canonical round-trip: from_chars already rejects a leading '+' and
    // leading whitespace, but accepts '007' and '-0'; the round-trip closes
    // those so "written by this store" is checkable.
    if (std::to_string(v) != val)
        return std::nullopt;
    return v;
}

/// Parses the `reap_declined_anchor_ms` marker, format
/// `"<anchor>:<direction>"` (direction ∈ {"forward","backward"}). The
/// decline/recovery pair is judged on the FULL fact set (frozen anchor AND
/// anomaly direction), never the anchor alone (docs/clock-guarded-retention.md
/// part 4; PR #4299 round-2 external review). Direction is NEVER sign-encoded
/// — a negative anchor is the tamper signal `parse_reap_i64` already rejects,
/// so it stays a suffix, not an arithmetic trick.
///
/// Absent on any of: no `:` (a LEGACY bare-integer marker from before this
/// fix, or a garbled value), an unrecognised direction token, or an
/// unparseable/negative anchor half. Absent is always safe — every call site
/// treats it as "no prior decline", which re-arms in the new format and
/// declines once more rather than granting an unearned recovery. This is what
/// makes a MIXED-VERSION rollout safe in both directions: an OLDER binary
/// reading this store's new `"<int>:<dir>"` value hands the whole string to
/// its own bare `parse_reap_i64`, which stops at the `:` and rejects the
/// trailing text — so it too treats the marker as absent and declines.
inline std::optional<std::pair<std::int64_t, std::string>>
parse_declined_marker(std::string_view val) {
    const auto colon = val.find(':');
    if (colon == std::string_view::npos)
        return std::nullopt;
    const std::string_view direction = val.substr(colon + 1);
    if (direction != "forward" && direction != "backward")
        return std::nullopt;
    auto anchor = parse_reap_i64(val.substr(0, colon));
    if (!anchor || *anchor < 0)
        return std::nullopt;
    return std::make_pair(*anchor, std::string(direction));
}

/// What a reap pass must do to the persisted `reap_declined_anchor_ms` marker.
/// Deliberately has NO public default constructor, so every `ReapDecision`
/// MUST name one of `clear()` / `arm(...)`: a future reap branch that forgets
/// the marker decision is a COMPILE error, not a silently-wrong runtime path
/// (the ExecuteGate discipline — this is the whole point of the decide/apply
/// split, PR #4299 round-3 review). `LEAVE` is deliberately NOT expressible:
/// every lock-holding pass that COMMITS writes the marker exactly once (ARM or
/// CLEAR); LEAVE only ever applied to passes that never read `now()` (the
/// lock-skip early return) or that roll back — neither reaches `decide_reap`.
class MarkerAction {
public:
    enum class Kind {
        Clear, ///< DELETE reap_declined_anchor_ms
        Arm,   ///< upsert reap_declined_anchor_ms = "<anchor>:<direction>"
    };

    /// Clear the marker (accepted pass, recovery, self-heal, bad-now decline).
    static MarkerAction clear() { return MarkerAction(Kind::Clear, 0, ""); }

    /// Arm/re-arm the marker against this pass's (anchor, direction) anomaly.
    static MarkerAction arm(std::int64_t anchor, std::string_view direction) {
        return MarkerAction(Kind::Arm, anchor, std::string(direction));
    }

    [[nodiscard]] Kind kind() const { return kind_; }
    [[nodiscard]] std::int64_t anchor() const { return anchor_; }
    [[nodiscard]] const std::string& direction() const { return direction_; }

private:
    MarkerAction(Kind k, std::int64_t a, std::string d)
        : kind_(k), anchor_(a), direction_(std::move(d)) {}

    Kind kind_;
    std::int64_t anchor_;
    std::string direction_;
};

/// The outcome of `decide_reap`. `marker` is MANDATORY (no default) — see
/// `MarkerAction`. `new_anchor` is `nullopt` to LEAVE `reap_anchor_ms`
/// untouched (a skew decline/arm never advances it), or the value to upsert.
struct ReapDecision {
    MarkerAction marker;                    ///< mandatory — every branch names one
    std::optional<std::int64_t> new_anchor; ///< nullopt = leave reap_anchor_ms untouched
    bool run_sweeps;                        ///< run both capped sweeps this pass
    bool clock_anomaly;                     ///< this pass was DECLINED on a clock-guard anomaly
    bool recovered;                         ///< ran via the decline-once/drain-on-repeat recovery
};

/// PURE reap decision. `now_raw` is the DB `now()` epoch-ms text; `anchor_raw`
/// the persisted `reap_anchor_ms` (nullopt if no row); `marker_raw` the
/// persisted `reap_declined_anchor_ms` (nullopt if no row). Returns the exact,
/// exhaustive five-decision set (each constructs a MarkerAction):
///
///  - **bad now_raw** (unparseable OR negative): CLEAR, leave anchor, no
///    sweeps, clock_anomaly. A distinct anomaly CLEARs the stale recovery
///    identity so a later same-direction skew is judged fresh (the round-3
///    fix — this path used to LEAVE the marker).
///  - **anchor_raw present but unparseable/negative** (corrupt-anchor
///    self-heal): CLEAR, re-anchor to now_ms, no sweeps, clock_anomaly. This
///    method is the anchor's sole writer, so a bad stored value is
///    corruption/tampering — re-anchor rather than wedge every future pass.
///  - **anchor_raw absent** (first/no-anchor pass): CLEAR, anchor = now_ms,
///    run sweeps.
///  - **valid anchor, skew present** (forward: now_ms-anchor>max_skew;
///    backward: now_ms<anchor):
///      - **marker matches** (declined anchor == anchor AND declined
///        direction == this pass's direction): CLEAR, anchor = now_ms
///        UNCONDITIONALLY, run sweeps, recovered — a persisted gap treated as
///        genuine elapsed downtime.
///      - **else** (no marker / different anchor / different direction /
///        unparseable marker): ARM(anchor, direction), leave anchor, no
///        sweeps, clock_anomaly.
///  - **valid anchor, NO skew** (clean): CLEAR, anchor = max(anchor, now_ms),
///    run sweeps.
inline ReapDecision decide_reap(std::string_view now_raw,
                                std::optional<std::string_view> anchor_raw,
                                std::optional<std::string_view> marker_raw,
                                std::int64_t max_plausible_skew_ms) {
    // SANITISE now() (clock-guarded-retention part 3): unparseable or negative
    // is an ANOMALY, never a quiet fallback. NOT a wedge risk — nothing here
    // is persisted beyond clearing a stale marker; the next pass issues its
    // own fresh SELECT now() and is judged on that fresh reading. CLEARing the
    // marker (the round-3 fix) ensures a distinct anomaly cannot leave a stale
    // recovery identity a later same-direction skew would free-ride on.
    const std::optional<std::int64_t> parsed_now = parse_reap_i64(now_raw);
    if (!parsed_now || *parsed_now < 0) {
        return ReapDecision{.marker = MarkerAction::clear(),
                            .new_anchor = std::nullopt,
                            .run_sweeps = false,
                            .clock_anomaly = true,
                            .recovered = false};
    }
    const std::int64_t now_ms = *parsed_now;

    if (anchor_raw.has_value()) {
        const std::optional<std::int64_t> parsed_anchor = parse_reap_i64(*anchor_raw);
        if (!parsed_anchor || *parsed_anchor < 0) {
            // SELF-HEAL a corrupt/tampered PERSISTED anchor: re-anchor to this
            // pass's own sanitised now_ms and clear any stale skew marker
            // (recorded against the now-discarded anchor), declining only this
            // one pass. Do NOT drain-on-repeat — a garbage anchor is not
            // evidence of genuine elapsed downtime the way a persisting skew
            // is, and auto-draining on tampering risks a mass-reap.
            return ReapDecision{.marker = MarkerAction::clear(),
                                .new_anchor = now_ms,
                                .run_sweeps = false,
                                .clock_anomaly = true,
                                .recovered = false};
        }
        const std::int64_t anchor = *parsed_anchor;

        // Overflow-safe forward-skew comparison (subtracting two already-
        // sanitised non-negative int64_t values cannot overflow). forward and
        // backward are mutually exclusive, so "direction" is a lossless raw
        // fact, not a classified enum.
        const bool forward_skew = now_ms >= anchor && now_ms - anchor > max_plausible_skew_ms;
        const bool backward_skew = now_ms < anchor;

        if (forward_skew || backward_skew) {
            const std::string_view current_direction = forward_skew ? "forward" : "backward";
            std::optional<std::pair<std::int64_t, std::string>> declined;
            if (marker_raw.has_value())
                declined = parse_declined_marker(*marker_raw);
            // RECOVER only on the FULL (anchor, direction) match — a value-only
            // match let a DIFFERENT-direction anomaly at the same frozen anchor
            // recover and run the sweeps against a corrupted now_ms (round-2
            // external review defect).
            if (declined.has_value() && declined->first == anchor &&
                declined->second == current_direction) {
                return ReapDecision{.marker = MarkerAction::clear(),
                                    .new_anchor = now_ms, // UNCONDITIONAL — move off the stale anchor
                                    .run_sweeps = true,
                                    .clock_anomaly = false,
                                    .recovered = true};
            }
            // ARM / re-arm against this pass's (anchor, direction); overwrites
            // any stale marker. Anchor unchanged (a decline never advances it,
            // so the identical repeat presents the same frozen pair).
            return ReapDecision{.marker = MarkerAction::arm(anchor, current_direction),
                                .new_anchor = std::nullopt,
                                .run_sweeps = false,
                                .clock_anomaly = true,
                                .recovered = false};
        }

        // Clean accepted pass with a valid anchor: advance to max(anchor,
        // now_ms) (parenthesised to dodge the <windows.h> `max` macro, MSVC).
        return ReapDecision{.marker = MarkerAction::clear(),
                            .new_anchor = (std::max)(anchor, now_ms),
                            .run_sweeps = true,
                            .clock_anomaly = false,
                            .recovered = false};
    }

    // First/no-anchor pass (part 6 PROCEED): anchor to now_ms and sweep.
    return ReapDecision{.marker = MarkerAction::clear(),
                        .new_anchor = now_ms,
                        .run_sweeps = true,
                        .clock_anomaly = false,
                        .recovered = false};
}

} // namespace yuzu::server
