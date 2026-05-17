/**
 * test_product_pack_store.cpp — coverage for ProductPackStore signature
 * enforcement and the #802 / W7.4 security-by-default flip.
 *
 * Pre-W7.4 state: `require_signed_packs_` defaulted to false AND the setter
 * was never called from anywhere in production. The "flag exists but is
 * unreachable" pattern was the actual vulnerability — even an operator who
 * wanted pack signing had no way to enable it, so every install path took
 * the unsigned-pass branch.
 *
 * Pins:
 *   1. Default ctor sets require_signed_packs() == true.
 *   2. Install of an unsigned pack is REJECTED by default with the
 *      documented error string ("' is unsigned and require_signed_packs is
 *      enabled").
 *   3. After set_require_signed_packs(false) — the escape hatch — the same
 *      unsigned pack INSTALLS, preserving the pre-flip behaviour as
 *      explicit opt-in.
 *   4. A pack with a signature field always goes through the verify path
 *      regardless of the flag — wrong signature still rejects.
 *
 * No tests here exercise audit emission — that happens at the server.cpp
 * construction site, covered (when added) by a server-startup-audit
 * integration test rather than the store-unit suite.
 */

#include "product_pack_store.hpp"

#include "../test_helpers.hpp"
#include <catch2/catch_test_macros.hpp>

#include <string>

using yuzu::server::ProductPackStore;

namespace {

/// Minimal valid YAML bundle with no signature — exercises the unsigned-pack
/// branch at product_pack_store.cpp:435.
constexpr const char* kUnsignedPackYaml = R"(apiVersion: yuzu.io/v1alpha1
kind: ProductPack
name: test-unsigned
version: 1.0.0
description: Bundle without signature for #802 test
---
apiVersion: yuzu.io/v1alpha1
kind: InstructionDefinition
name: test-instruction
)";

/// install_fn stub — accepts every item, returns a synthetic id. We don't
/// care which items installed downstream because #802 is a pre-item-install
/// reject check; the install_fn here is just to satisfy the signature.
yuzu::server::ItemInstallFn make_accept_all_install_fn() {
    return [](const std::string&, const std::string&) -> std::expected<std::string, std::string> {
        return std::string{"item-id"};
    };
}

} // namespace

TEST_CASE("ProductPackStore: default ctor requires signed packs (#802)",
          "[product_pack_store][issue802][security]") {
    // Pre-W7.4 default was false; the flip is the security-by-default fix.
    // Pin both the default value and the rejection semantics with the
    // documented error string so a future "convenience" reversion is loud.
    yuzu::test::TempDbFile db{std::string_view{"pack-store-default-"}};
    ProductPackStore store{db.path};
    REQUIRE(store.is_open());
    CHECK(store.require_signed_packs());

    auto result = store.install(kUnsignedPackYaml, make_accept_all_install_fn());
    REQUIRE_FALSE(result.has_value());
    // The error string is the operator-facing signal that the flag is doing
    // its job. Pin a substring rather than the exact string so harmless
    // rephrasing of the prefix doesn't trip the test — but the
    // "require_signed_packs" token is load-bearing for operator log
    // diagnosis and must survive any rephrase.
    CHECK(result.error().find("require_signed_packs") != std::string::npos);
}

TEST_CASE("ProductPackStore: opt-out flag accepts unsigned packs (#802 escape hatch)",
          "[product_pack_store][issue802][security]") {
    // The escape hatch — operators with legacy unsigned packs call
    // set_require_signed_packs(false) (via the --allow-unsigned-packs
    // server flag). The same payload that the default rejects must now
    // install successfully, otherwise the migration path is broken.
    yuzu::test::TempDbFile db{std::string_view{"pack-store-optout-"}};
    ProductPackStore store{db.path};
    REQUIRE(store.is_open());
    store.set_require_signed_packs(false);
    CHECK_FALSE(store.require_signed_packs());

    auto result = store.install(kUnsignedPackYaml, make_accept_all_install_fn());
    REQUIRE(result.has_value());
    CHECK_FALSE(result->empty());
}

TEST_CASE("ProductPackStore: set_require_signed_packs is idempotent and round-trips",
          "[product_pack_store][issue802]") {
    // Sanity pin on the setter — protects against a future refactor that
    // accidentally inverts the bool or makes the setter one-shot.
    yuzu::test::TempDbFile db{std::string_view{"pack-store-setter-"}};
    ProductPackStore store{db.path};
    REQUIRE(store.require_signed_packs()); // post-W7.4 default

    store.set_require_signed_packs(false);
    CHECK_FALSE(store.require_signed_packs());

    store.set_require_signed_packs(true);
    CHECK(store.require_signed_packs());

    store.set_require_signed_packs(true); // idempotent
    CHECK(store.require_signed_packs());
}

TEST_CASE("ProductPackStore: pack with signature + wrong public key rejects "
          "regardless of require_signed_packs",
          "[product_pack_store][issue802][security]") {
    // Sibling-handler check: the require_signed_packs flag is for UNSIGNED
    // packs only. A pack that DOES include a signature must always go
    // through verify_signature regardless of the flag — a wrong/forged
    // signature rejects unconditionally. Pin this so a future "simplify"
    // refactor that collapses the two paths can't accidentally weaken the
    // signed-pack path.
    constexpr const char* signed_pack_bad_sig = R"(apiVersion: yuzu.io/v1alpha1
kind: ProductPack
name: test-bad-sig
version: 1.0.0
description: Bundle with invalid signature
signature: 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
publicKey: 0000000000000000000000000000000000000000000000000000000000000000
---
apiVersion: yuzu.io/v1alpha1
kind: InstructionDefinition
name: signed-test-instruction
)";

    yuzu::test::TempDbFile db{std::string_view{"pack-store-badsig-"}};
    ProductPackStore store{db.path};
    REQUIRE(store.is_open());

    // Default (require_signed_packs == true) — rejects.
    auto result_default = store.install(signed_pack_bad_sig, make_accept_all_install_fn());
    REQUIRE_FALSE(result_default.has_value());
    CHECK(result_default.error().find("signature verification failed") != std::string::npos);

    // Even with the escape hatch on, a signature-present-but-invalid pack
    // still rejects — the flag is unsigned-only, not "skip all crypto".
    store.set_require_signed_packs(false);
    auto result_optout = store.install(signed_pack_bad_sig, make_accept_all_install_fn());
    REQUIRE_FALSE(result_optout.has_value());
    CHECK(result_optout.error().find("signature verification failed") != std::string::npos);
}
