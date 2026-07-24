/**
 * test_engine_store_error_class.cpp — locks the shared REST/MCP store-error
 * classifier (engine_store_error_class.hpp). This is the single source of truth
 * both transports dispatch through; a missed string here mis-classifies a
 * permanent client condition as a retryable transient error (or vice versa),
 * the exact defect PR #2284 review caught twice. No DB needed — pure function.
 */

#include "engine_store_error_class.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string_view>

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
              "one active credential with unresolved rotation metadata - do not rotate; "
              "revoke or inspect the credential state") == E::Conflict);

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
