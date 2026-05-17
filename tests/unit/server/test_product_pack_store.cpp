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
#include <openssl/evp.h>

#include <memory>
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
    // gov W7.4 R1 QE-S1: tighter than substring — pin the full operator-facing
    // suffix via `ends_with`. The token chain "is unsigned and signature
    // enforcement is enabled" plus the actionable hint pointing at the
    // CLI flag must survive any rephrase; a regression that drops either
    // piece (or accidentally re-exposes the internal field name
    // "require_signed_packs") fails this test immediately.
    CHECK(result.error().ends_with(
        "is unsigned and signature enforcement is enabled "
        "(set --allow-unsigned-packs / YUZU_ALLOW_UNSIGNED_PACKS=1 to bypass)"));
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

TEST_CASE("ProductPackStore: pack with malformed/zero public key + signature "
          "rejects regardless of require_signed_packs",
          "[product_pack_store][issue802][security]") {
    // gov W7.4 R1 QE-S2: renamed for accuracy — the fixture uses 64 zero
    // bytes for both signature and public key, exercising the
    // hex_decode-OK + EVP_DigestVerify-fail path. A test that says "wrong
    // public key" implies a syntactically valid but mismatched keypair,
    // which is a different (related) scenario covered indirectly by the
    // positive-pair test below (mutating one byte of a valid signature).
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

TEST_CASE("ProductPackStore: pack with signature but no publicKey rejects",
          "[product_pack_store][issue802][security]") {
    // gov W7.4 R1 QE-B1: the third rejection branch (signature present, no
    // publicKey) at product_pack_store.cpp:432-437 had no test coverage. A
    // future refactor that drops or inverts this check would slip past every
    // existing test in this file. Pins both the rejection AND the
    // operator-facing error string.
    constexpr const char* pack_sig_no_pubkey = R"(apiVersion: yuzu.io/v1alpha1
kind: ProductPack
name: test-orphan-sig
version: 1.0.0
description: Bundle with signature but missing publicKey
signature: 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
---
apiVersion: yuzu.io/v1alpha1
kind: InstructionDefinition
name: orphan-sig-instruction
)";

    yuzu::test::TempDbFile db{std::string_view{"pack-store-nopubkey-"}};
    ProductPackStore store{db.path};
    REQUIRE(store.is_open());

    auto result = store.install(pack_sig_no_pubkey, make_accept_all_install_fn());
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().find("has signature but no publicKey") != std::string::npos);
}

namespace {

/// Generate an Ed25519 keypair via OpenSSL EVP and return raw 32-byte
/// public key + private-key signer suitable for `EVP_DigestSign` over
/// arbitrary content. Used by the positive signed-pack test to prove the
/// crypto happy path — without it, a regression that breaks
/// `verify_signature` (e.g. always returns false) would leave every
/// existing rejection-only test green.
struct Ed25519Pair {
    std::unique_ptr<EVP_PKEY, void (*)(EVP_PKEY*)> pkey{nullptr, &EVP_PKEY_free};
    std::string public_key_hex; // 64 hex chars
};

Ed25519Pair generate_ed25519() {
    std::unique_ptr<EVP_PKEY_CTX, void (*)(EVP_PKEY_CTX*)> kctx(
        EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr), &EVP_PKEY_CTX_free);
    REQUIRE(kctx);
    REQUIRE(EVP_PKEY_keygen_init(kctx.get()) == 1);

    EVP_PKEY* raw = nullptr;
    REQUIRE(EVP_PKEY_keygen(kctx.get(), &raw) == 1);
    Ed25519Pair p{std::unique_ptr<EVP_PKEY, void (*)(EVP_PKEY*)>(raw, &EVP_PKEY_free), {}};

    unsigned char pub[32];
    std::size_t pub_len = sizeof(pub);
    REQUIRE(EVP_PKEY_get_raw_public_key(p.pkey.get(), pub, &pub_len) == 1);
    REQUIRE(pub_len == 32);
    static constexpr char hex[] = "0123456789abcdef";
    p.public_key_hex.reserve(64);
    for (std::size_t i = 0; i < 32; ++i) {
        p.public_key_hex.push_back(hex[pub[i] >> 4]);
        p.public_key_hex.push_back(hex[pub[i] & 0x0F]);
    }
    return p;
}

std::string sign_hex(EVP_PKEY* pkey, std::string_view content) {
    std::unique_ptr<EVP_MD_CTX, void (*)(EVP_MD_CTX*)> ctx(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
    REQUIRE(ctx);
    REQUIRE(EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, pkey) == 1);
    std::size_t sig_len = 64; // Ed25519 signature size
    unsigned char sig[64];
    REQUIRE(EVP_DigestSign(ctx.get(), sig, &sig_len,
                           reinterpret_cast<const unsigned char*>(content.data()),
                           content.size()) == 1);
    REQUIRE(sig_len == 64);
    static constexpr char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(128);
    for (std::size_t i = 0; i < 64; ++i) {
        out.push_back(hex[sig[i] >> 4]);
        out.push_back(hex[sig[i] & 0x0F]);
    }
    return out;
}

} // namespace

TEST_CASE("ProductPackStore: correctly signed pack installs (positive crypto path)",
          "[product_pack_store][issue802][security]") {
    // gov W7.4 R1 QE-B2: the entire happy-path of verify_signature was
    // unobservable — every prior [issue802] test asserts rejection. A
    // regression that makes verify_signature always return false (e.g. early
    // return in a refactor, OpenSSL/BCrypt API misuse, hex decode bug) would
    // leave the entire suite green. This test signs a real pack with an
    // in-test-generated Ed25519 keypair, builds the bundle in the exact
    // format `install()` expects (non-ProductPack docs joined with "\n---\n"
    // per product_pack_store.cpp:411), and asserts both (a) the signed pack
    // installs (verify_signature returns true) AND (b) a one-byte mutation
    // of the signature flips it to reject (proves the verify was real, not
    // a "skip on flag" pass-through).

    auto pair = generate_ed25519();

    // The content that gets signed is the non-ProductPack documents joined
    // with "\n---\n", per product_pack_store.cpp lines 408-415. Construct
    // the inner doc separately so we know its exact bytes.
    const std::string inner_doc = "apiVersion: yuzu.io/v1alpha1\n"
                                  "kind: InstructionDefinition\n"
                                  "name: signed-positive-test\n";
    const std::string signature_hex = sign_hex(pair.pkey.get(), inner_doc);

    // Build the full bundle.
    const std::string bundle = "apiVersion: yuzu.io/v1alpha1\n"
                               "kind: ProductPack\n"
                               "name: test-signed-positive\n"
                               "version: 1.0.0\n"
                               "description: Bundle with valid signature\n"
                               "signature: " +
                               signature_hex +
                               "\n"
                               "publicKey: " +
                               pair.public_key_hex +
                               "\n"
                               "---\n" +
                               inner_doc;

    yuzu::test::TempDbFile db{std::string_view{"pack-store-signed-pos-"}};
    ProductPackStore store{db.path};
    REQUIRE(store.is_open());

    auto result = store.install(bundle, make_accept_all_install_fn());
    REQUIRE(result.has_value());
    CHECK_FALSE(result->empty());

    // Mutate one byte of the signature (flip the last hex char). Verify
    // must now reject — proves the crypto path is real, not a stub.
    std::string mutated_sig = signature_hex;
    mutated_sig.back() = (mutated_sig.back() == '0' ? '1' : '0');
    const std::string mutated_bundle = "apiVersion: yuzu.io/v1alpha1\n"
                                       "kind: ProductPack\n"
                                       "name: test-signed-mutated\n"
                                       "version: 1.0.0\n"
                                       "description: Bundle with one-byte-mutated signature\n"
                                       "signature: " +
                                       mutated_sig +
                                       "\n"
                                       "publicKey: " +
                                       pair.public_key_hex +
                                       "\n"
                                       "---\n" +
                                       inner_doc;

    yuzu::test::TempDbFile db2{std::string_view{"pack-store-signed-mut-"}};
    ProductPackStore store2{db2.path};
    REQUIRE(store2.is_open());

    auto result_mut = store2.install(mutated_bundle, make_accept_all_install_fn());
    REQUIRE_FALSE(result_mut.has_value());
    CHECK(result_mut.error().find("signature verification failed") != std::string::npos);
}
