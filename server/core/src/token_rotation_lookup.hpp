#pragma once

#include "api_token_store.hpp"

#include <cstdint>
#include <string>

/// @file token_rotation_lookup.hpp
/// Single source of truth for locating a human token-keyed rotation's
/// successor row after `ApiTokenStore::rotate_token`/`confirm_token_rotation`
/// (P2 #11, SOC 2 CC6.3) — shared by every transport surface that needs to
/// correlate a rotate response with the successor it just minted/re-served
/// (REST today; the MCP twin is landing separately and must call THIS, never
/// re-derive its own copy).
///
/// WHY THIS IS A SEPARATE HEADER, NOT INLINE IN THE ROUTE: a round-3 review
/// found the original REST-only inline loop had been copied verbatim from
/// the engine-principal rotate route (`rest_api_v1.cpp`'s
/// `/engine-principals/{id}/credentials/rotate`), where "the row whose
/// `supersedes_token_id` is non-empty" is a sound match because that route's
/// own store arm (`rotate_engine_credential`) enforces a <=2-ACTIVE-
/// CREDENTIALS-PER-PRINCIPAL ceiling — at most one linked row can ever exist
/// for that principal. `ApiTokenStore::rotate_token`'s own doc comment
/// (api_token_store.hpp, "Human arm") declares that invariant explicitly
/// FALSE for a human principal: "one user routinely holds N concurrent
/// unrelated named tokens" — the ceiling here is <=2 PER ROTATION GROUP,
/// never per principal. So a human principal can have SEVERAL independent
/// in-flight rotations at once, and the copied loop matched the FIRST linked
/// row it found — not necessarily the one belonging to the predecessor
/// actually rotated. Reproduced end-to-end against live Postgres: rotating
/// token A then token B (both owned by the same user) inside A's overlap
/// window returned B's raw secret paired with A's successor `token_id`;
/// confirming that id revoked A while B — the token whose secret the caller
/// actually held — stayed live and unconfirmed. EXTEND this header, never
/// fork it — a second inline copy (on the REST side, the MCP side, or a
/// future third transport) is exactly the drift that produced the bug.

namespace yuzu::server::detail {

/// Result of `derive_rotation_successor` below.
struct RotationSuccessorInfo {
    /// false iff the scan came back with no row whose `supersedes_token_id`
    /// matches `predecessor_token_id` — see the function doc for why a
    /// caller that just observed a successful rotate/confirm MUST treat this
    /// as an ambiguous failure, never a legitimate "no successor" answer.
    bool found = false;
    std::string successor_token_id;
    int64_t successor_expires_at = 0;
    /// The PREDECESSOR row's own `overlap_expires_at` — never the
    /// successor's. `ApiTokenStore::rotate_token`'s successor `INSERT` never
    /// sets this column (only the predecessor's row is stamped with it), so
    /// a caller reading it off the successor row observes a structural `0`.
    /// Echoed here, from the predecessor, purely for the response's
    /// convenience — there is no separate successor-side value to report.
    int64_t predecessor_overlap_expires_at = 0;
};

/// Scans `store.list_active_for_principal(principal_id)` ONCE and returns
/// both halves a rotate response needs: the successor row scoped EXACTLY to
/// `predecessor_token_id` (matched via `supersedes_token_id ==
/// predecessor_token_id`, never merely "any linked row of this principal"),
/// and that same predecessor's own `overlap_expires_at`.
///
/// `found == false` on the returned struct means the scan came back without
/// a match for this exact predecessor. `list_active_for_principal` is a
/// best-effort maintenance-style read that swallows a lease/query failure
/// into an empty vector rather than propagating a typed error
/// (`api_token_store.hpp`) — so, immediately after a caller has observed
/// `rotate_token`/`confirm_token_rotation` succeed for this very
/// predecessor, a genuinely empty match here is structurally impossible
/// EXCEPT as a swallowed read failure. Callers MUST treat `found == false`
/// as an ambiguous, retryable failure and fail CLOSED — never place the raw
/// secret already in hand into a response with no `token_id` to ever confirm
/// it against.
[[nodiscard]] inline RotationSuccessorInfo
derive_rotation_successor(ApiTokenStore& store, const std::string& principal_id,
                          const std::string& predecessor_token_id) {
    RotationSuccessorInfo info;
    for (const auto& t : store.list_active_for_principal(principal_id)) {
        if (t.supersedes_token_id == predecessor_token_id) {
            info.found = true;
            info.successor_token_id = t.token_id;
            info.successor_expires_at = t.expires_at;
        } else if (t.token_id == predecessor_token_id) {
            info.predecessor_overlap_expires_at = t.overlap_expires_at;
        }
    }
    return info;
}

} // namespace yuzu::server::detail
