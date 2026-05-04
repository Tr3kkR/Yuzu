// test_store_errors.cpp — Unit tests for the kConflictPrefix shared
// contract (#396, #399, #402; governance Gate 3 arch-B1).
//
// The store↔route layer uses a magic-string prefix to signal duplicate
// conflicts. A typo in either layer would silently degrade 409 → 400 with
// no test failure. Centralizing the constant + helpers in store_errors.hpp
// makes a typo a compile error; testing the helpers themselves locks in
// the contract semantics so a refactor of one helper can't drift the
// invariant.

#include "store_errors.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

using namespace yuzu::server;

TEST_CASE("kConflictPrefix is the canonical 'conflict:' string", "[store_errors]") {
    // Wire-contract assertion. If anyone ever shortens this to 'conf:' or
    // capitalizes it, the route handlers and this test all fail together
    // — exactly the failure mode the centralization is designed to enforce.
    CHECK(std::string(kConflictPrefix) == "conflict:");
}

TEST_CASE("is_conflict_error matches only the canonical prefix",
          "[store_errors]") {
    CHECK(is_conflict_error("conflict: anything"));
    CHECK(is_conflict_error("conflict:nospace"));
    CHECK(is_conflict_error("conflict:"));

    // Negative cases — the route layer must default to 400 for these.
    CHECK_FALSE(is_conflict_error(""));
    CHECK_FALSE(is_conflict_error("Conflict: capitalized"));
    CHECK_FALSE(is_conflict_error(" conflict: leading space"));
    CHECK_FALSE(is_conflict_error("not a conflict"));
    CHECK_FALSE(is_conflict_error("internal: prepare failed"));
    CHECK_FALSE(is_conflict_error("insert failed: UNIQUE constraint"));
}

TEST_CASE("strip_conflict_prefix returns the operator-facing message",
          "[store_errors]") {
    // Canonical form: "conflict: <message>" → "<message>".
    CHECK(strip_conflict_prefix("conflict: instruction definition 'foo' already exists") ==
          "instruction definition 'foo' already exists");
    CHECK(strip_conflict_prefix("conflict: policy fragment named 'bar' already exists") ==
          "policy fragment named 'bar' already exists");

    // Multiple spaces after the prefix collapse — defensive against future
    // contributors writing "conflict:  foo" by accident.
    CHECK(strip_conflict_prefix("conflict:   spaced") == "spaced");

    // No-space form is also stripped (helper does not require the space).
    CHECK(strip_conflict_prefix("conflict:nospace") == "nospace");

    // Non-conflict messages are returned unchanged.
    CHECK(strip_conflict_prefix("internal: prepare failed") == "internal: prepare failed");
    CHECK(strip_conflict_prefix("") == "");
    CHECK(strip_conflict_prefix("insert failed") == "insert failed");
}

// iter-L1: lock in boundary behavior on degenerate inputs flagged by Gate 7
// re-review (sec-LOW1 deferred — verify these don't crash or underflow).
TEST_CASE("strip_conflict_prefix handles boundary inputs without underflow",
          "[store_errors][boundary]") {
    // Bare prefix with no body — must return an empty view, not underflow
    // when the rest is empty after the leading-space loop.
    CHECK(strip_conflict_prefix("conflict:") == "");
    CHECK(strip_conflict_prefix("conflict: ") == "");
    CHECK(strip_conflict_prefix("conflict:    ") == "");

    // Embedded NUL after the prefix — string_view preserves the NUL; the
    // helper must still strip the prefix correctly. Audit/log layers may
    // truncate at NUL but that's their concern, not the helper's.
    std::string nul_after_prefix("conflict:\0bar", 13);
    auto stripped = strip_conflict_prefix(nul_after_prefix);
    CHECK(stripped.size() == 4);  // "\0bar" is 4 bytes
    CHECK(stripped[0] == '\0');
    CHECK(stripped[1] == 'b');

    // is_conflict_error matches the prefix even if the body contains NULs.
    CHECK(is_conflict_error(nul_after_prefix));
}
