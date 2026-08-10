/**
 * test_engine_store_error_class.cpp — locks the shared REST/MCP store-error
 * classifier (engine_store_error_class.hpp). This is the single source of truth
 * both transports dispatch through; a missed string here mis-classifies a
 * permanent client condition as a retryable transient error (or vice versa),
 * the exact defect PR #2284 review caught twice. No DB needed — pure function.
 */

#include "engine_store_error_class.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <string_view>
#include <vector>

using yuzu::server::detail::classify_engine_store_error;
using yuzu::server::detail::confirm_result_label;
using yuzu::server::detail::EngineStoreErrorClass;

TEST_CASE("classify_engine_store_error: transient / conflict / client classes",
          "[engine_store_error]") {
    using E = EngineStoreErrorClass;

    // Transient (retryable — REST 503 / MCP kInternalError).
    CHECK(classify_engine_store_error("database not open") == E::Transient);
    CHECK(classify_engine_store_error("engine principal store unavailable — try again") ==
          E::Transient);
    CHECK(classify_engine_store_error("CSPRNG failure") == E::Transient);
    CHECK(classify_engine_store_error("rotation lock could not be acquired") == E::Transient);

    // Unrecognized store error -> Transient (fail-safe default, never a
    // misleading client error).
    CHECK(classify_engine_store_error("rotation failed") == E::Transient);
    CHECK(classify_engine_store_error("failed to mint successor credential: connection reset") ==
          E::Transient);
    CHECK(classify_engine_store_error("no active credential to rotate — mint one first") ==
          E::Transient);

    // Conflict (don't blindly retry). "rotation confirmation unavailable"
    // contains the broad "unavailable" substring — the ordering must classify
    // it as Conflict, NOT Transient (load-bearing).
    CHECK(classify_engine_store_error("rotation confirmation unavailable — retry via rotate") ==
          E::Conflict);
    CHECK(classify_engine_store_error("grace window elapsed") == E::Conflict);
    CHECK(classify_engine_store_error("rotation in progress by a different operator") ==
          E::Conflict);
    // #2384 confirm token_id pin: a stale/wrong successor id means the
    // rotation state has moved on — 409, don't blindly retry with the same id.
    CHECK(classify_engine_store_error("token_id does not match the pending rotation successor; "
                                      "pass the token_id returned by rotate") == E::Conflict);

    // Client-validation (permanent bad input/state — REST 400 / MCP kInvalidParams).
    CHECK(classify_engine_store_error("classification must be internal or external") ==
          E::ClientValidation);
    CHECK(classify_engine_store_error("more than two active credentials") == E::ClientValidation);
    CHECK(classify_engine_store_error("engine principal not found or revoked") ==
          E::ClientValidation);
    CHECK(classify_engine_store_error("overlap window below 24h floor") == E::ClientValidation);

    // Regression guards for the two strings the round-2 review found missing:
    // both are permanent client conditions that were defaulting to Transient.
    CHECK(classify_engine_store_error("engine principal not found or not active") ==
          E::ClientValidation);
    CHECK(classify_engine_store_error("principal has a non-engine active credential") ==
          E::ClientValidation);

    // #2384: the confirm token_id input guard is a permanent client error.
    CHECK(classify_engine_store_error("token_id required") == E::ClientValidation);
}

TEST_CASE("classify_engine_store_error: #2404 confirm-replay terminal strings",
          "[engine_store_error]") {
    using E = EngineStoreErrorClass;

    // The confirm-replay conflicts (emitted only after a POSITIVE row read, so
    // terminal — a client must not blindly retry them). All four MUST classify
    // as Conflict, and none may collide with the transient/client arms.
    CHECK(classify_engine_store_error(
              "rotation already confirmed - the supplied token_id is the sole active "
              "credential; nothing to confirm") == E::Conflict);
    CHECK(classify_engine_store_error(
              "no rotation in flight - the supplied token_id is already the sole active "
              "credential; nothing to confirm") == E::Conflict);
    CHECK(classify_engine_store_error(
              "no rotation in flight for the supplied token_id - the rotation was resolved "
              "(confirmed, revoked, or cut over); rotate again if a new rotation is needed") ==
          E::Conflict);
    CHECK(classify_engine_store_error(
              "one active credential with unresolved rotation metadata - inspect the "
              "credential state and do not rotate; revoke only if it is confirmed stale") ==
          E::Conflict);

    // The >2-active confirm string is a permanent client condition (mirrors
    // rotate's), not a conflict.
    CHECK(classify_engine_store_error(
              "more than two active credentials for this principal - resolve manually "
              "before confirming") == E::ClientValidation);

    // REGRESSION (load-bearing): the deliberately-ambiguous 0-active/malformed-pair
    // string MUST stay Transient — the #2404 conflict needles must not have
    // widened to swallow it (that would turn a retryable read hiccup into a
    // terminal 409, the opposite failure).
    CHECK(classify_engine_store_error("no in-flight rotation to confirm") == E::Transient);
}

TEST_CASE("classify_engine_store_error: human token-keyed arm (P2 #11) new strings",
          "[engine_store_error]") {
    using E = EngineStoreErrorClass;

    // rotate_token/confirm_token_rotation reach these only after a POSITIVE,
    // definitive row lookup (TokenLookup::ok, api_token_store.cpp) — unlike
    // the engine arm's ambiguous 0-active case, so they classify terminally
    // (permanent client error), never the retryable default.
    CHECK(classify_engine_store_error("no such token to rotate") == E::ClientValidation);
    CHECK(classify_engine_store_error("no such token to confirm") == E::ClientValidation);
    CHECK(classify_engine_store_error("token is not a human-owned credential") ==
          E::ClientValidation);
    CHECK(classify_engine_store_error("credential is not currently active — nothing to "
                                      "rotate") == E::ClientValidation);
    CHECK(classify_engine_store_error("principal has a non-human active credential") ==
          E::ClientValidation);

    // The deliberately-ambiguous query-failure wording the mint arm reuses
    // verbatim from the engine arm must stay Transient even when reached via
    // the human path (same 0-active/read-failure ambiguity).
    CHECK(classify_engine_store_error("no active credential to rotate — mint one first") ==
          E::Transient);

    // Round 4 regression: this state MUST be Transient via its OWN explicit
    // entry, and must NOT collide with the engine arm's Conflict-classified
    // "the rotation was resolved" substring — see engine_store_error_class.hpp's
    // dedicated check for the full story (two byte-identical strings could
    // never carry two different classes through this matcher; the human arm's
    // occurrences needed their own wording once that was discovered).
    const std::string no_pending_msg =
        "no rotation currently pending for the supplied token_id — nothing "
        "to confirm; call rotate again if a new rotation is needed";
    CHECK(classify_engine_store_error(no_pending_msg) == E::Transient);
    CHECK(no_pending_msg.find("the rotation was resolved") == std::string::npos);
}

TEST_CASE("classify_engine_store_error: round-trip over every error string "
          "rotate_token/confirm_token_rotation can emit (round 4 coverage)",
          "[engine_store_error]") {
    // Every literal error_msg/std::unexpected string reachable from
    // ApiTokenStore::rotate_token and ApiTokenStore::confirm_token_rotation
    // (api_token_store.cpp), transcribed verbatim, paired with its expected
    // class. This is the gap three separate reviewers — including two who
    // walked the error strings specifically looking for collisions — missed:
    // a new string that ACQUIRES an existing keyed substring by accident
    // (the round-4 "no rotation currently pending" defect) is invisible to a
    // test that only checks the individual new strings in isolation, because
    // the isolated check doesn't re-verify every OTHER string the same
    // classifier call must still get right. A future string addition that
    // silently changes ANY of these results — in either direction — fails
    // here first.
    using E = EngineStoreErrorClass;
    struct Case {
        std::string message;
        E expected;
    };
    const std::vector<Case> cases = {
        // ── rotate_token ────────────────────────────────────────────────
        {"database not open", E::Transient},
        {"token_id required", E::ClientValidation},
        {"requesting_user required", E::ClientValidation},
        {"overlap window below 24h floor", E::ClientValidation},
        {"overlap window exceeds the maximum (10 years)", E::ClientValidation},
        {"database unavailable — try again", E::Transient},
        {"no such token to rotate", E::ClientValidation},
        {"token is not a human-owned credential", E::ClientValidation},
        {"credential is not currently active — nothing to rotate", E::ClientValidation},
        {"failed to acquire rotation lock", E::Transient},
        {"no active credential to rotate — mint one first", E::Transient},
        {"overlap window would exceed the predecessor credential's expiry", E::ClientValidation},
        {"overlap window would exceed the successor credential's expiry", E::ClientValidation},
        {"failed to mint successor credential", E::Transient},
        {"failed to stamp predecessor overlap window", E::Transient},
        {"principal has a non-human active credential", E::ClientValidation},
        {"more than two active credentials for this principal — resolve manually before "
         "rotating",
         E::ClientValidation},
        {"two active credentials not in a recognized rotation pair — resolve via revoke, "
         "not rotate",
         E::ClientValidation},
        {"rotation grace window elapsed; confirm or revoke", E::Conflict},
        {"rotation in progress by a different operator", E::Conflict},
        {"rotation failed", E::Transient}, // generic with_txn_for-failed fallback
        // validate_human_mint's own strings, surfaced verbatim as
        // rotate_token's candidate_error on the mint arm:
        {"token name cannot be empty", E::ClientValidation},
        {"service-scoped tokens must have an expiration time", E::ClientValidation},
        {"invalid MCP tier — must be 'readonly', 'operator', or 'supervised'",
         E::ClientValidation},
        {"MCP tokens must have an expiration time (max 90 days)", E::ClientValidation},
        {"MCP token TTL cannot exceed 90 days", E::ClientValidation},
        // generate_raw_token's CSPRNG failure, also surfaced as candidate_error:
        {"CSPRNG unavailable (entropy exhausted)", E::Transient},

        // ── confirm_token_rotation ──────────────────────────────────────
        {"no such token to confirm", E::ClientValidation},
        {"no in-flight rotation to confirm", E::Transient},
        {"no rotation currently pending for the supplied token_id — nothing to confirm; "
         "call rotate again if a new rotation is needed",
         E::Transient},
        {"more than two active credentials for this principal - resolve manually before "
         "confirming",
         E::ClientValidation},
        {"one active credential with unresolved rotation metadata - inspect the credential "
         "state and do not rotate; revoke only if it is confirmed stale",
         E::Conflict},
        {"token_id does not match the pending rotation successor; pass the token_id "
         "returned by rotate",
         E::Conflict},
        {"rotation confirmation unavailable — retry via rotate or fall back to revoke",
         E::Conflict},
        {"failed to confirm rotation", E::Transient},
        {"failed to revoke predecessor on confirm", E::Transient},
        {"failed to clear successor rotation state on confirm", E::Transient},
        {"confirm failed", E::Transient}, // generic with_txn_for-failed fallback
    };

    for (const auto& c : cases) {
        CAPTURE(c.message);
        CHECK(classify_engine_store_error(c.message) == c.expected);
    }
}

TEST_CASE("confirm_result_label maps every class to a pre-seeded metric label",
          "[engine_store_error]") {
    using E = EngineStoreErrorClass;
    // The three failure labels must exactly match the closed set pre-seeded in
    // server.cpp (surface x {success,conflict,client_error,transient}); `success`
    // is stamped by the caller, not this function.
    CHECK(std::string_view(confirm_result_label(E::ClientValidation)) == "client_error");
    CHECK(std::string_view(confirm_result_label(E::Conflict)) == "conflict");
    CHECK(std::string_view(confirm_result_label(E::Transient)) == "transient");
}
