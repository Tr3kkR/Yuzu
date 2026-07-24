#pragma once

/// @file rotation_confirm_state.hpp
/// Pure classifier for the state a `confirm_rotation` call finds when it reads
/// the active-credential set for an engine principal (design doc §7 overlap-pair
/// rotation). NO database access: it operates on the already-read `ApiToken`
/// vector while the caller still holds the per-principal advisory lock, so the
/// caller's in-transaction recheck stays authoritative. Factored out so a future
/// pre-consume recheck seam (#2443) can reuse the exact same taxonomy through an
/// inspection seam, without duplicating the state machine or the
/// terminal-vs-transient split.
///
/// POSITIVE-READ CONTRACT (the reason most one-active states are terminal, not
/// retryable): `read_active_for_principal_on_conn` returns an EMPTY vector on a
/// swallowed SELECT failure and NEVER a partial result — libpq's
/// `PGRES_TUPLES_OK` is all-or-nothing, and a `std::bad_alloc` while building
/// the vector unwinds rather than returning a short read. So any NON-empty
/// vector here is positive evidence of the real active-set size. Only
/// `kNoneActive` is ambiguous with a masked read failure; every other state is
/// a fact the caller can classify terminally (#2404).

#include <string>
#include <vector>

#include "api_token_store.hpp" // for yuzu::server::ApiToken

namespace yuzu::server::detail {

/// The disjoint states `confirm_rotation` can observe once it has read (under
/// the advisory lock) the active credentials for a principal and knows the
/// caller's pinned successor `token_id`. Mapped 1:1 to a store error string by
/// the caller; the strings then classify to an HTTP/JSON-RPC status class via
/// `engine_store_error_class.hpp` (`kNoneActive` -> Transient; every terminal
/// state below -> Conflict or ClientValidation).
enum class RotationConfirmState {
    kNoneActive,     //!< 0 active. Ambiguous with a swallowed read failure -> stays retryable/Transient.
    kOverfull,       //!< >2 active. A credential was minted outside the rotation path -> manual resolution.
    kUnresolvedSole, //!< 1 active whose rotation linkage is NOT fully cleared (a best-effort
                     //!< pair-resolve failed, or the partner expired before cleanup). Rotating from
                     //!< here would strand a malformed pair (#2404 F1) -> terminal, do NOT advise rotate.
    kSoleConfirmed,  //!< 1 active, linkage clear, pin matches, confirmed_at != 0. The rotation in which
                     //!< THIS row was the successor was confirmed (confirmed_at is written only by
                     //!< confirm, only on a successor row, and a row is a successor exactly once).
    kSoleResolved,   //!< 1 active, linkage clear, pin matches, confirmed_at == 0. Resolved without an
                     //!< explicit confirm (never rotated, or cut over by the sweep / a revoke).
    kSoleOtherToken, //!< 1 active, linkage clear, pin does NOT match. The pinned rotation has moved on;
                     //!< the surviving credential is a different token (cause not row-attributable).
    kPair,           //!< Exactly 2 active. The caller's normal pair-processing path (pin + initiator).
};

/// Classify `active` (the rows `read_active_for_principal_on_conn` returned)
/// against the caller's pinned successor `pin_token_id`. Pure; total; no I/O.
[[nodiscard]] inline RotationConfirmState
classify_confirm_state(const std::vector<ApiToken>& active, const std::string& pin_token_id) {
    if (active.empty())
        return RotationConfirmState::kNoneActive;
    if (active.size() > 2)
        return RotationConfirmState::kOverfull;
    if (active.size() == 2)
        return RotationConfirmState::kPair;

    // size == 1: a positive read, so this is a real sole-credential state, not a
    // masked empty read. Linkage must be fully cleared for the row to be a plain
    // standalone credential; a non-empty rotation_group or supersedes_token_id
    // means a rotation never finished resolving on this row.
    const ApiToken& sole = active.front();
    const bool linkage_clear = sole.rotation_group.empty() && sole.supersedes_token_id.empty();
    if (!linkage_clear)
        return RotationConfirmState::kUnresolvedSole;
    if (sole.token_id != pin_token_id)
        return RotationConfirmState::kSoleOtherToken;
    return sole.confirmed_at != 0 ? RotationConfirmState::kSoleConfirmed
                                  : RotationConfirmState::kSoleResolved;
}

} // namespace yuzu::server::detail
