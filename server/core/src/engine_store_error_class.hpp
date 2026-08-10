#pragma once

/// @file engine_store_error_class.hpp
/// Single source of truth for classifying an EnginePrincipalStore /
/// ApiTokenStore `std::expected<..., std::string>` error string into an HTTP /
/// JSON-RPC status class. The REST surface (`engine_store_error_status` in
/// rest_api_v1.cpp) and the MCP surface (`mcp_error_for_store_msg` in
/// mcp_server.cpp) BOTH route through this so the two transports can never
/// disagree on whether a given store error is a client error, a conflict, or a
/// retryable transient failure (PR #2284 review Major 5 — "keep the two
/// classifiers in sync"; the hand-duplicated versions had already diverged).
///
/// LOAD-BEARING ORDERING: several conflict strings contain a broad transient
/// substring (e.g. "rotation confirmation unavailable" contains "unavailable"),
/// so the specific conflict matches MUST be tested before the broad transient
/// ones. None of the client-validation substrings contain a transient
/// substring, so they are safely tested last, before the retryable default.
///
/// POSITIVE-READ EXEMPTION (#2404, detailed at step 3): the confirm-replay
/// conflict strings are emitted only after a non-empty active-credential read,
/// so — unlike the deliberately-transient "no in-flight rotation to confirm"
/// (0-active, ambiguous with a swallowed read failure) — they are terminal.

#include <string>
#include <string_view>

namespace yuzu::server::detail {

enum class EngineStoreErrorClass {
    ClientValidation, //!< Bad input / bad state — REST 400, MCP kInvalidParams.
    Conflict,         //!< Rotation-state conflict, don't blindly retry — REST 409, MCP kInvalidParams.
    Transient,        //!< Store/infra failure, retryable — REST 503, MCP kInternalError.
};

[[nodiscard]] inline EngineStoreErrorClass classify_engine_store_error(const std::string& msg) {
    const auto has = [&](std::string_view s) { return msg.find(s) != std::string_view::npos; };

    // 1. CSPRNG failure — transient (a fresh secret couldn't be generated).
    if (has("CSPRNG"))
        return EngineStoreErrorClass::Transient;

    // 1b. ApiTokenStore::confirm_token_rotation (human token-keyed arm,
    //     P2 #11, round 4) — "no rotation currently pending ... nothing to
    //     confirm". EXPLICIT, deliberate entry, not relying on fall-through
    //     (step 7's default happens to be Transient too, but an explicit
    //     check is the fix for the class of bug this file exists to prevent
    //     — see the next paragraph). Genuinely retryable-in-spirit: nothing
    //     about this token_id's state changes on a bare retry of the SAME
    //     confirm call, but the message's own guidance is "call rotate
    //     again", not "this is a dead end" — so unlike step 3's #2404
    //     confirm-replay strings (below), a client is told to take a
    //     DIFFERENT follow-up action, which the Transient wire contract
    //     (retry-shaped, REST 503 / MCP kInternalError) fits better than a
    //     hard 409 telling it never to retry.
    //
    //     LOAD-BEARING WHY THIS MUST BE ITS OWN CHECK, NOT REUSED WORDING:
    //     the human arm's two emission sites (`pinned.rotation_group.empty()`
    //     and `GroupRotationConfirmState::kGroupEmpty`, api_token_store.cpp)
    //     originally reused the ENGINE arm's kSoleOtherToken string
    //     byte-for-byte (a DIFFERENT fact pattern — a pin mismatch against a
    //     DIFFERENT surviving credential, not "nothing pending") and so
    //     silently inherited THAT string's Conflict classification via the
    //     "the rotation was resolved" substring below (step 3) — a client
    //     polling confirm on a never-rotated or already-resolved token got a
    //     409 "don't retry" answer whose own text said to retry. Two
    //     byte-identical strings can never carry two different
    //     classifications through this substring matcher, so closing the gap
    //     required BOTH a new, deliberately-distinct string at the emission
    //     sites AND this explicit check — reusing the engine wording here
    //     would have reintroduced the exact collision this entry exists to
    //     avoid.
    if (has("no rotation currently pending for the supplied token_id"))
        return EngineStoreErrorClass::Transient;

    // 2. Conflict strings that ALSO contain a broad transient substring —
    //    must win before the broad "unavailable" check below.
    if (has("rotation confirmation unavailable")) // grace binding gone (restart / already-resolved)
        return EngineStoreErrorClass::Conflict;

    // 3. Other rotation-state conflicts (no broad substring, order-independent).
    //    "does not match the pending rotation": the confirm token_id pin
    //    (#2384) — a stale/wrong successor id, i.e. the rotation state has
    //    moved on. 409, don't blindly retry with the same id.
    //    The #2404 confirm-replay strings are terminal conflicts too: they are
    //    emitted ONLY after a POSITIVE row read (a non-empty active set — see
    //    rotation_confirm_state.hpp), so unlike the transient "no in-flight
    //    rotation to confirm" (0-active, ambiguous with a swallowed read
    //    failure) they carry no read-failure ambiguity and must not be retried:
    //      "sole active credential"       -> already confirmed / already resolved (pin match);
    //      "the rotation was resolved"    -> a different credential survives (pin mismatch, 1 active);
    //      "unresolved rotation metadata" -> a best-effort pair-resolve left stale linkage (#2404 F1).
    //    None contains a broad transient substring ("not open"/"unavailable"/
    //    "rotation lock"), so their placement here (before step 5) is safe.
    if (has("grace window elapsed") || has("different operator") ||
        has("does not match the pending rotation") || has("sole active credential") ||
        has("the rotation was resolved") || has("unresolved rotation metadata"))
        return EngineStoreErrorClass::Conflict;

    // 4. Advisory-lock contention — transient/retryable.
    if (has("rotation lock"))
        return EngineStoreErrorClass::Transient;

    // 5. Broad transient: "database not open", "... unavailable — try again",
    //    "engine referent check unavailable". No client-validation string below
    //    contains these substrings, so this broad match is safe here.
    if (has("not open") || has("unavailable"))
        return EngineStoreErrorClass::Transient;

    // 6. Genuine client-validation strings — pure input/state checks the store
    //    performs (or, for the two "recognized shape" rotate messages, only
    //    reachable AFTER a read already returned real rows, so they can't be a
    //    masked read failure). These stay client-class; everything else falls
    //    through to the retryable default.
    static constexpr std::string_view kClientValidationSubstrings[] = {
        // EnginePrincipalStore::create
        "classification must be",
        "principal_id must be in the reserved",
        "principal_id slug may only contain",
        "owner_username cannot be empty",
        "justification cannot be empty",
        // ApiTokenStore::create_token (general + engine §6/§7/§8 validation)
        "token name cannot be empty",
        "service-scoped tokens must have an expiration time",
        "invalid MCP tier",
        "MCP tokens must have an expiration time",
        "invalid principal_kind",
        "engine:-namespaced principal_id requires principal_kind=engine",
        "engine principal tokens cannot be service-scoped",
        "engine principal tokens must use mcp_tier=readonly",
        "engine principal tokens cannot be perpetual",
        "exceed 90 days",
        "engine principal not found or revoked",
        // MCP transfer_owner folds not-found/not-active into the store error
        // string (the REST twin pre-checks and 404s before reaching here), so
        // this permanent client condition must classify as ClientValidation,
        // not the retryable Transient default (PR #2284 round-2 review).
        "not found or not active",
        // Terminal data-shape condition (create_token engine path): a principal
        // whose existing credential is non-engine is a permanent client error,
        // not a transient store failure. Low reachability (the G2 namespace
        // guard normally prevents it) but classified explicitly per step 6.
        "non-engine active credential",
        "principal_id required",
        "token_id required",
        "requesting_user required",
        "overlap window below 24h floor",
        "overlap window exceeds the maximum",
        "overlap window would exceed the predecessor credential's expiry",
        "overlap window would exceed the successor credential's expiry",
        "not in a recognized rotation pair",
        "more than two active credentials",
        // ApiTokenStore::rotate_token / confirm_token_rotation (human
        // token-keyed arm, P2 #11) — new, permanent client-validation
        // conditions the group-scoped state machine can name precisely
        // (unlike the principal-wide engine arm's ambiguous 0-active case,
        // these are reached only after a POSITIVE, definitive row lookup —
        // see api_token_store.cpp's TokenLookup / rotation_confirm_state.hpp's
        // classify_confirm_state_in_group for why each is safe to classify
        // terminally rather than falling to the retryable default).
        "no such token to rotate",
        "no such token to confirm",
        "token is not a human-owned credential",
        "credential is not currently active — nothing to rotate",
        "principal has a non-human active credential",
    };
    for (const std::string_view needle : kClientValidationSubstrings)
        if (has(needle))
            return EngineStoreErrorClass::ClientValidation;

    // 7. Default: an UNRECOGNIZED store-layer error (a bare "rotation
    //    failed"/"confirm failed" fallback, a DB-error-suffixed message, a
    //    swallowed read failure surfaced as "no active credential to rotate")
    //    is far more likely a transient infrastructure failure than a client
    //    error — fail SAFE (retryable), never a misleading 400/kInvalidParams.
    return EngineStoreErrorClass::Transient;
}

/// Metric `result`-label for a store error class, shared by the REST and MCP
/// confirm handlers so `yuzu_engine_principal_confirm_total{result=...}` reads
/// identically on both surfaces (#2404). `success` is stamped by the caller on
/// the ok path; this maps only the failure classes. The four labels
/// (success|conflict|client_error|transient) are the closed set pre-seeded in
/// server.cpp — keep the two in sync.
[[nodiscard]] inline const char* confirm_result_label(EngineStoreErrorClass cls) {
    switch (cls) {
    case EngineStoreErrorClass::ClientValidation:
        return "client_error";
    case EngineStoreErrorClass::Conflict:
        return "conflict";
    case EngineStoreErrorClass::Transient:
        return "transient";
    }
    return "transient"; // unreachable — all enum cases return above
}

} // namespace yuzu::server::detail
