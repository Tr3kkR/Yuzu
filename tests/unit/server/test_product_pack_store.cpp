/**
 * test_product_pack_store.cpp — `ProductPackStore` (operator-installed product packs,
 * ADR-0006/0009/0054).
 *
 * Migrated-to-Postgres store (ADR-0012 §1, authoritative/fail-hard). PG-gated: skips when
 * YUZU_TEST_POSTGRES_DSN is unset, fails when set but broken (test_helpers.hpp skip-vs-fail
 * contract). Store-behaviour cases use the pre-migrated PgTestTemplate variant
 * (docs/postgres-store-playbook.md step 7); the two fail-closed construction cases use
 * YUZU_REQUIRE_PG_DB / no gate at all, per the plain-migration-test carve-out.
 *
 * Covers:
 *  - fail-closed construction: a live-but-unmigratable database, and an unreachable pool (every
 *    method fails closed with `kProductPackDbErrorPrefix`).
 *  - the pre-migration #802/W7.4 signed-pack coverage, unchanged in intent: default ctor
 *    requires signed packs; the escape hatch (`set_require_signed_packs(false)`) accepts
 *    unsigned packs; a present-but-invalid signature always rejects regardless of the flag; a
 *    signature with no publicKey rejects; the positive Ed25519 crypto path (a real signed pack
 *    installs, a one-byte-mutated signature rejects).
 *  - list/get/uninstall round-trip through the new `std::expected` reads (ADR-0036): `get`'s
 *    nullopt-inside-expected distinguishes "not found" from a genuine DB error; `uninstall`'s
 *    `"not_found: "` prefix.
 *  - migrate_from_sqlite backfill contract (ADR-0009/0054): sourceless-then-holder shape,
 *    fingerprint-dedup idempotency, half-schema legacy file fail-closed, pre-7.13
 *    missing-`verified`-column legacy read (defaults to unverified), identical-content conflict
 *    is a benign no-op, differently-valued conflict fails closed, mid-scan corruption.
 */

#include "product_pack_store.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "sqlite_raii.hpp"
#include "test_route_sink.hpp"
#include "workflow_routes.hpp"

#include <yuzu/metrics.hpp>

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <openssl/evp.h>

#include <libpq-fe.h>
#include <sqlite3.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <format>
#include <thread>
#include <memory>
#include <string>
#include <tuple>
#include <vector>

using yuzu::server::ItemInstallFn;
using yuzu::server::ProductPack;
using yuzu::server::ProductPackQuery;
using yuzu::server::ProductPackStore;
using yuzu::server::SqliteDb;
using yuzu::server::SqliteStmt;
using yuzu::server::WorkflowRoutes;
namespace pg = yuzu::server::pg;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;

namespace {

yuzu::test::PgTestTemplate product_pack_store_tpl{
    "productpackstore", [](const std::string& dsn) {
        PgPool pool{{.conninfo = dsn, .size = 1}};
        ProductPackStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("product_pack_store template: store failed to migrate");
    }};

/// Minimal valid YAML bundle with no signature — exercises the unsigned-pack branch.
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

/// Two InstructionDefinition documents — paired with make_accept_all_install_fn() (which
/// returns the same fixed id for every document), this bundle deterministically produces a
/// duplicate item_id.
constexpr const char* kUnsignedPackYamlDuplicateItems = R"(apiVersion: yuzu.io/v1alpha1
kind: ProductPack
name: test-duplicate-items
version: 1.0.0
description: Bundle with two documents assigned the same item id
---
apiVersion: yuzu.io/v1alpha1
kind: InstructionDefinition
name: test-instruction-a
---
apiVersion: yuzu.io/v1alpha1
kind: InstructionDefinition
name: test-instruction-b
)";

/// A second, content-distinct bundle — used only to prove idempotency-key reuse with a
/// DIFFERENT body is rejected (F033/#3481). Deliberately unrelated to kUnsignedPackYaml beyond
/// both being minimal valid unsigned bundles.
constexpr const char* kUnsignedPackYamlAlt = R"(apiVersion: yuzu.io/v1alpha1
kind: ProductPack
name: test-unsigned-alt
version: 1.0.0
description: A different bundle for the idempotency-key-reuse-with-different-body test
---
apiVersion: yuzu.io/v1alpha1
kind: InstructionDefinition
name: test-instruction-alt
)";

/// install_fn stub — accepts every item, returns a synthetic id. We don't
/// care which items installed downstream because #802 is a pre-item-install
/// reject check; the install_fn here is just to satisfy the signature.
ItemInstallFn make_accept_all_install_fn() {
    return [](const std::string&, const std::string&) -> std::expected<std::string, std::string> {
        return std::string{"item-id"};
    };
}

ItemInstallFn make_counting_install_fn(int* counter) {
    return [counter](const std::string&,
                     const std::string&) -> std::expected<std::string, std::string> {
        ++*counter;
        return std::string{"item-id-"} + std::to_string(*counter);
    };
}

} // namespace

// ── Construction fail-closed ────────────────────────────────────────────────

TEST_CASE("ProductPackStore reports !is_open on a migration failure", "[product_pack_store][pg]") {
    YUZU_REQUIRE_PG_DB(db);
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult s{PQexec(conn.get(), "CREATE SCHEMA product_pack_store")};
        REQUIRE(s.ok());
        PgResult t{PQexec(conn.get(), "CREATE TABLE product_pack_store.product_packs (bogus int)")};
        REQUIRE(t.ok());
    }
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    ProductPackStore store{pool};
    CHECK_FALSE(store.is_open());
}

TEST_CASE("ProductPackStore reports !is_open on an unreachable pool, and every method fails "
          "closed",
          "[product_pack_store]") {
    PgPool pool{{.conninfo = "=quohth4eeQu5 garbage =", .size = 2}};
    REQUIRE_FALSE(pool.valid());
    ProductPackStore store{pool};
    CHECK_FALSE(store.is_open());

    auto install_res = store.install(kUnsignedPackYaml, make_accept_all_install_fn());
    CHECK_FALSE(install_res.has_value());
    CHECK(install_res.error().starts_with(yuzu::server::kProductPackDbErrorPrefix));

    auto list_res = store.list();
    CHECK_FALSE(list_res.has_value());
    CHECK(list_res.error().starts_with(yuzu::server::kProductPackDbErrorPrefix));

    auto get_res = store.get("x");
    CHECK_FALSE(get_res.has_value());
    CHECK(get_res.error().starts_with(yuzu::server::kProductPackDbErrorPrefix));

    auto uninstall_res = store.uninstall(
        "x", [](const std::string&, const std::string&) { return true; });
    CHECK_FALSE(uninstall_res.has_value());
    CHECK(uninstall_res.error().starts_with(yuzu::server::kProductPackDbErrorPrefix));

    CHECK_FALSE(store.migrate_from_sqlite("/nonexistent/does/not/matter"));
}

// ── #802 / W7.4 signature enforcement ───────────────────────────────────────

TEST_CASE("ProductPackStore: default ctor requires signed packs (#802)",
          "[product_pack_store][issue802][security][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, product_pack_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ProductPackStore store{pool};
    REQUIRE(store.is_open());
    CHECK(store.require_signed_packs());

    auto result = store.install(kUnsignedPackYaml, make_accept_all_install_fn());
    REQUIRE_FALSE(result.has_value());
    // gov W7.4 R1 QE-S1: tighter than substring — pin the full operator-facing
    // suffix via `ends_with`. A regression that drops either piece (or
    // accidentally re-exposes the internal field name "require_signed_packs")
    // fails this test immediately.
    CHECK(result.error().ends_with(
        "is unsigned and signature enforcement is enabled "
        "(set --allow-unsigned-packs / YUZU_ALLOW_UNSIGNED_PACKS=1 to bypass)"));
}

TEST_CASE("ProductPackStore: opt-out flag accepts unsigned packs (#802 escape hatch)",
          "[product_pack_store][issue802][security][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, product_pack_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ProductPackStore store{pool};
    REQUIRE(store.is_open());
    store.set_require_signed_packs(false);
    CHECK_FALSE(store.require_signed_packs());

    auto result = store.install(kUnsignedPackYaml, make_accept_all_install_fn());
    REQUIRE(result.has_value());
    CHECK_FALSE(result->empty());
}

TEST_CASE("ProductPackStore: set_require_signed_packs is idempotent and round-trips",
          "[product_pack_store][issue802][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, product_pack_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ProductPackStore store{pool};
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
          "[product_pack_store][issue802][security][pg]") {
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

    YUZU_REQUIRE_PG_DB_TPL(db, product_pack_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ProductPackStore store{pool};
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
          "[product_pack_store][issue802][security][pg]") {
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

    YUZU_REQUIRE_PG_DB_TPL(db, product_pack_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ProductPackStore store{pool};
    REQUIRE(store.is_open());

    auto result = store.install(pack_sig_no_pubkey, make_accept_all_install_fn());
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().find("has signature but no publicKey") != std::string::npos);
}

namespace {

/// Generate an Ed25519 keypair via OpenSSL EVP and return raw 32-byte
/// public key + private-key signer suitable for `EVP_DigestSign` over
/// arbitrary content.
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
          "[product_pack_store][issue802][security][pg]") {
    auto pair = generate_ed25519();

    // The content that gets signed is the non-ProductPack documents joined
    // with "\n---\n" (product_pack_store.cpp `install()`). Construct the
    // inner doc separately so we know its exact bytes.
    const std::string inner_doc = "apiVersion: yuzu.io/v1alpha1\n"
                                  "kind: InstructionDefinition\n"
                                  "name: signed-positive-test\n";
    const std::string signature_hex = sign_hex(pair.pkey.get(), inner_doc);

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

    YUZU_REQUIRE_PG_DB_TPL(db, product_pack_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ProductPackStore store{pool};
    REQUIRE(store.is_open());

    auto result = store.install(bundle, make_accept_all_install_fn());
    REQUIRE(result.has_value());
    CHECK_FALSE(result->empty());

    // The installed pack round-trips through get() with verified=true.
    auto got = store.get(*result);
    REQUIRE(got.has_value());
    REQUIRE(got->has_value());
    CHECK((*got)->verified);
    CHECK((*got)->name == "test-signed-positive");

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

    auto result_mut = store.install(mutated_bundle, make_accept_all_install_fn());
    REQUIRE_FALSE(result_mut.has_value());
    CHECK(result_mut.error().find("signature verification failed") != std::string::npos);
}

// ── list / get / uninstall round-trip ───────────────────────────────────────

TEST_CASE("ProductPackStore: list/get/uninstall round-trip", "[product_pack_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, product_pack_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ProductPackStore store{pool};
    REQUIRE(store.is_open());
    store.set_require_signed_packs(false);

    int install_calls = 0;
    auto result = store.install(kUnsignedPackYaml, make_counting_install_fn(&install_calls));
    REQUIRE(result.has_value());
    const std::string pack_id = *result;
    CHECK(install_calls == 1);

    SECTION("get finds the installed pack with its item") {
        auto got = store.get(pack_id);
        REQUIRE(got.has_value());
        REQUIRE(got->has_value());
        CHECK((*got)->id == pack_id);
        CHECK((*got)->name == "test-unsigned");
        CHECK_FALSE((*got)->verified);
        REQUIRE((*got)->items.size() == 1);
        CHECK((*got)->items[0].kind == "InstructionDefinition");
        CHECK((*got)->items[0].item_id == "item-id-1");
    }

    SECTION("get on an unknown id returns nullopt, not an error") {
        auto got = store.get("does-not-exist");
        REQUIRE(got.has_value());
        CHECK_FALSE(got->has_value());
    }

    SECTION("list finds the installed pack") {
        auto listed = store.list();
        REQUIRE(listed.has_value());
        bool found = false;
        for (const auto& p : *listed)
            found = found || p.id == pack_id;
        CHECK(found);
    }

    SECTION("list name_filter narrows the result") {
        ProductPackQuery q;
        q.name_filter = "nonexistent-name-xyz";
        auto listed = store.list(q);
        REQUIRE(listed.has_value());
        CHECK(listed->empty());
    }

    SECTION("uninstall on an unknown id returns not_found") {
        auto r = store.uninstall("does-not-exist",
                                 [](const std::string&, const std::string&) { return true; });
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().starts_with("not_found:"));
    }

    SECTION("uninstall removes the pack and invokes uninstall_fn per item") {
        int uninstall_calls = 0;
        auto r = store.uninstall(pack_id, [&uninstall_calls](const std::string&,
                                                              const std::string&) {
            ++uninstall_calls;
            return true;
        });
        REQUIRE(r.has_value());
        CHECK(uninstall_calls == 1);

        auto got = store.get(pack_id);
        REQUIRE(got.has_value());
        CHECK_FALSE(got->has_value());
    }
}

// Gate 8 review (Fable, external): a bundle whose documents assign the same item id twice
// must fail as a plain validation error (never kProductPackDbErrorPrefix) — retryable-503
// misclassification would turn a deterministic duplicate-id bundle into a repeated orphan
// generator against the sibling stores, since install_fn runs with no pool_ lease held and
// a client retry would re-invoke it on every attempt.
TEST_CASE("ProductPackStore::install: a duplicate item id in one bundle fails as a plain "
          "validation error, never a retryable db_error",
          "[product_pack_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, product_pack_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ProductPackStore store{pool};
    REQUIRE(store.is_open());
    store.set_require_signed_packs(false);

    auto result = store.install(kUnsignedPackYamlDuplicateItems, make_accept_all_install_fn());
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().find("duplicate item id") != std::string::npos);
    CHECK(result.error().find(yuzu::server::kProductPackDbErrorPrefix) == std::string::npos);

    // Nothing was persisted — the pack never reaches Postgres.
    auto listed = store.list();
    REQUIRE(listed.has_value());
    for (const auto& p : *listed)
        CHECK(p.name != "test-duplicate-items");
}

// Gov Gate 2 finding (security-guardian, this PR's own review): the duplicate-item-id check
// above returns BEFORE the persist transaction, but install_fn has ALREADY committed both
// documents into sibling stores by that point — the exact orphan shape F031 exists to close.
// The original fix only wired compensate_fn into the later with_txn_for failure path; this
// proves it now ALSO fires here.
TEST_CASE("ProductPackStore::install: a duplicate item id also triggers compensation "
          "(not just the final persist path)",
          "[product_pack_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, product_pack_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ProductPackStore store{pool};
    REQUIRE(store.is_open());
    store.set_require_signed_packs(false);

    std::vector<std::pair<std::string, std::string>> compensated;
    auto compensate_fn = [&compensated](const std::string& kind,
                                        const std::string& item_id) -> bool {
        compensated.emplace_back(kind, item_id);
        return true;
    };

    auto result = store.install(kUnsignedPackYamlDuplicateItems, make_accept_all_install_fn(),
                                compensate_fn);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().find("duplicate item id") != std::string::npos);
    CHECK(result.error().find(yuzu::server::kProductPackDbErrorPrefix) == std::string::npos);
    REQUIRE(compensated.size() == 2);
    CHECK(compensated[0].first == "InstructionDefinition");
    CHECK(compensated[1].first == "InstructionDefinition");
}

// ── Compensating cleanup (F031/#3481) ───────────────────────────────────────
//
// Pool-contention fault injection technique (proven precedent:
// test_api_token_store.cpp's "failed_pairs counts a POOL-CONTENTION ACQUIRE failure" test) — a
// size-1 pool, pinned by an unrelated held lease AFTER construction/migration has already
// released its own lease, leaves nothing for install()'s own with_txn_for to acquire. This is a
// REAL Postgres-level failure (a genuine bounded acquire timeout), not a mock.

TEST_CASE("ProductPackStore::install: a late persist failure (pool-contention) triggers "
          "best-effort compensation for every already-installed item",
          "[product_pack_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, product_pack_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 1}};
    ProductPackStore store{pool};
    REQUIRE(store.is_open());
    store.set_require_signed_packs(false);

    auto unrelated_lease = pool.acquire();
    REQUIRE(unrelated_lease);

    int install_calls = 0;
    std::vector<std::pair<std::string, std::string>> compensated;
    auto compensate_fn = [&compensated](const std::string& kind,
                                        const std::string& item_id) -> bool {
        compensated.emplace_back(kind, item_id);
        return true;
    };

    auto result = store.install(kUnsignedPackYaml, make_counting_install_fn(&install_calls),
                                compensate_fn);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().starts_with(yuzu::server::kProductPackDbErrorPrefix));
    CHECK(install_calls == 1);
    REQUIRE(compensated.size() == 1);
    CHECK(compensated[0].first == "InstructionDefinition");
    CHECK(compensated[0].second == "item-id-1");

    unrelated_lease.reset();
    auto listed = store.list();
    REQUIRE(listed.has_value());
    for (const auto& p : *listed)
        CHECK(p.name != "test-unsigned");
}

TEST_CASE("ProductPackStore::install: compensation runs in reverse install order",
          "[product_pack_store][pg]") {
    // Reverse order matters when a bundle's documents have an install-order dependency — e.g. a
    // PolicyFragment installed before a Policy that references it (bundle order is dependency
    // order: PolicyStore::create_policy validates the fragment exists at creation time), and
    // PolicyStore::delete_fragment refuses while any Policy still references it. Compensating
    // forward would spuriously fail to clean up the fragment. This store's own unit tests don't
    // wire a live PolicyStore, so this proves the ordering mechanism generically with two stub
    // items, asserting compensation visits them in the reverse of install_fn's call order.
    YUZU_REQUIRE_PG_DB_TPL(db, product_pack_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 1}};
    ProductPackStore store{pool};
    REQUIRE(store.is_open());
    store.set_require_signed_packs(false);

    auto unrelated_lease = pool.acquire();
    REQUIRE(unrelated_lease);

    int install_calls = 0;
    std::vector<std::string> compensated_ids;
    auto compensate_fn = [&compensated_ids](const std::string&,
                                            const std::string& item_id) -> bool {
        compensated_ids.push_back(item_id);
        return true;
    };

    auto result = store.install(kUnsignedPackYamlDuplicateItems,
                                make_counting_install_fn(&install_calls), compensate_fn);
    REQUIRE_FALSE(result.has_value());
    REQUIRE(compensated_ids.size() == 2);
    CHECK(compensated_ids[0] == "item-id-2");
    CHECK(compensated_ids[1] == "item-id-1");
}

// ── Idempotency (F033/#3481) ─────────────────────────────────────────────────

TEST_CASE("ProductPackStore::install: the idempotency pre-check fails closed under pool "
          "contention",
          "[product_pack_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, product_pack_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 1}};
    ProductPackStore store{pool};
    REQUIRE(store.is_open());
    store.set_require_signed_packs(false);

    auto unrelated_lease = pool.acquire();
    REQUIRE(unrelated_lease);

    int install_calls = 0;
    auto result = store.install(kUnsignedPackYaml, make_counting_install_fn(&install_calls), {},
                                "some-key");
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().starts_with(yuzu::server::kProductPackDbErrorPrefix));
    CHECK(install_calls == 0); // install_fn never reached — the pre-check failed first
}

TEST_CASE("ProductPackStore::install: a repeated Idempotency-Key with an identical bundle "
          "returns the original pack id and does not re-invoke install_fn",
          "[product_pack_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, product_pack_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ProductPackStore store{pool};
    REQUIRE(store.is_open());
    store.set_require_signed_packs(false);

    int install_calls = 0;
    auto first = store.install(kUnsignedPackYaml, make_counting_install_fn(&install_calls), {},
                               "replay-key-1");
    REQUIRE(first.has_value());
    CHECK(install_calls == 1);

    auto second = store.install(kUnsignedPackYaml, make_counting_install_fn(&install_calls), {},
                                "replay-key-1");
    REQUIRE(second.has_value());
    CHECK(*second == *first);
    CHECK(install_calls == 1);

    auto listed = store.list();
    REQUIRE(listed.has_value());
    int matching = 0;
    for (const auto& p : *listed)
        if (p.name == "test-unsigned")
            ++matching;
    CHECK(matching == 1);
}

TEST_CASE("ProductPackStore::install: a repeated Idempotency-Key with a different bundle is "
          "rejected as a plain validation error",
          "[product_pack_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, product_pack_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ProductPackStore store{pool};
    REQUIRE(store.is_open());
    store.set_require_signed_packs(false);

    int install_calls = 0;
    auto first = store.install(kUnsignedPackYaml, make_counting_install_fn(&install_calls), {},
                               "reuse-key-1");
    REQUIRE(first.has_value());
    CHECK(install_calls == 1);

    auto second = store.install(kUnsignedPackYamlAlt, make_counting_install_fn(&install_calls),
                                {}, "reuse-key-1");
    REQUIRE_FALSE(second.has_value());
    CHECK(second.error().find("idempotency key") != std::string::npos);
    CHECK(second.error().find(yuzu::server::kProductPackDbErrorPrefix) == std::string::npos);
    CHECK(install_calls == 1); // install_fn never invoked for the rejected second attempt
}

TEST_CASE("ProductPackStore::install: an empty idempotency_key preserves today's behavior (no "
          "dedup)",
          "[product_pack_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, product_pack_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ProductPackStore store{pool};
    REQUIRE(store.is_open());
    store.set_require_signed_packs(false);

    auto first = store.install(kUnsignedPackYaml, make_accept_all_install_fn());
    REQUIRE(first.has_value());
    auto second = store.install(kUnsignedPackYaml, make_accept_all_install_fn());
    REQUIRE(second.has_value());
    CHECK(*first != *second);
}

// ── Accepted-risk residual (F032/#3481) ──────────────────────────────────────

TEST_CASE("ProductPackStore::uninstall: a retried DELETE after a late metadata-delete failure "
          "eventually converges",
          "[product_pack_store][pg]") {
    // F032 is specifically the metadata-delete TRANSACTION failing AFTER uninstall_fn already
    // ran against sibling content — NOT get() failing before anything happens. A single pinned
    // connection (the technique used for F031 above) starves get() too, since uninstall() calls
    // get() first to fetch pack.items — that would prove the wrong thing. Instead, reuse the
    // erasure-coordination-lock test's technique below: hold kErasureCoordLockSql open on a
    // second connection from the SAME pool, and give the pool a short lock_timeout_ms so
    // uninstall()'s own attempt to take that lock (the first statement inside its with_txn_for,
    // AFTER uninstall_fn has already run) genuinely fails with a real Postgres lock-timeout
    // error — a deterministic, real failure at exactly the point F032 describes.
    YUZU_REQUIRE_PG_DB_TPL(db, product_pack_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2, .lock_timeout_ms = 500}};
    ProductPackStore store{pool};
    REQUIRE(store.is_open());
    store.set_require_signed_packs(false);

    auto installed = store.install(kUnsignedPackYaml, make_accept_all_install_fn());
    REQUIRE(installed.has_value());
    const std::string pack_id = *installed;

    // Hold the SAME advisory lock uninstall() takes, uncommitted, on a separate connection —
    // must match kErasureCoordLockSql in product_pack_store.cpp exactly (private to that
    // translation unit, so hard-coded here, same as the erasure-coordination-lock test above).
    auto lease_a = pool.acquire();
    REQUIRE(lease_a);
    REQUIRE(pg::exec_params(lease_a.get(), "BEGIN", std::vector<std::string>{}).ok());
    REQUIRE(pg::exec_params(lease_a.get(),
                            "SELECT pg_advisory_xact_lock(2037545589, "
                            "hashtext('product_pack_store:erasure_coordination'))",
                            std::vector<std::string>{})
                .ok());

    int first_uninstall_calls = 0;
    auto first =
        store.uninstall(pack_id, [&first_uninstall_calls](const std::string&,
                                                           const std::string&) {
            ++first_uninstall_calls;
            return true;
        });
    REQUIRE_FALSE(first.has_value());
    CHECK(first.error().starts_with(yuzu::server::kProductPackDbErrorPrefix));
    CHECK(first_uninstall_calls == 1);

    // The pack must still be listed as installed — the metadata delete never committed, even
    // though uninstall_fn already ran against (fake) sibling content above.
    auto still_there = store.get(pack_id);
    REQUIRE(still_there.has_value());
    REQUIRE(still_there->has_value());

    // Releasing an open-transaction lease rolls it back defensively (PgPool contract), freeing
    // the advisory lock.
    lease_a.reset();

    int second_uninstall_calls = 0;
    auto second =
        store.uninstall(pack_id, [&second_uninstall_calls](const std::string&,
                                                            const std::string&) {
            ++second_uninstall_calls;
            return true;
        });
    REQUIRE(second.has_value());
    CHECK(second_uninstall_calls == 1);

    auto gone = store.get(pack_id);
    REQUIRE(gone.has_value());
    CHECK_FALSE(gone->has_value());
}

// ── Backfill (ADR-0009/0054) ─────────────────────────────────────────────────

namespace {

void legacy_exec(sqlite3* db, const char* sql) {
    char* err = nullptr;
    int rc = sqlite3_exec(db, sql, nullptr, nullptr, &err);
    INFO((err ? err : "no error"));
    REQUIRE(rc == SQLITE_OK);
    if (err)
        sqlite3_free(err);
}

} // namespace

TEST_CASE("ProductPackStore::migrate_from_sqlite: no legacy file is a sourceless no-op",
          "[product_pack_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, product_pack_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ProductPackStore store{pool};
    REQUIRE(store.is_open());

    CHECK(store.migrate_from_sqlite("/nonexistent/product-packs.db"));
    // Idempotent — a second call against the same (sourceless) fingerprint is a no-op too.
    CHECK(store.migrate_from_sqlite("/nonexistent/product-packs.db"));

    auto listed = store.list();
    REQUIRE(listed.has_value());
    CHECK(listed->empty());
}

TEST_CASE("ProductPackStore::migrate_from_sqlite: backfills a v1-schema legacy file "
          "(with verified column) and is idempotent",
          "[product_pack_store][pg]") {
    yuzu::test::TempDbFile legacy_db{std::string_view{"pack-legacy-v1-"}};
    {
        SqliteDb db;
        REQUIRE(sqlite3_open_v2(legacy_db.path.string().c_str(), db.addr(),
                                SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) == SQLITE_OK);
        legacy_exec(db.get(),
                    "CREATE TABLE product_packs (id TEXT PRIMARY KEY, name TEXT NOT NULL, "
                    "version TEXT NOT NULL DEFAULT '1.0.0', description TEXT NOT NULL DEFAULT "
                    "'', yaml_source TEXT NOT NULL, installed_at INTEGER NOT NULL DEFAULT 0, "
                    "verified INTEGER NOT NULL DEFAULT 0);");
        legacy_exec(db.get(),
                    "CREATE TABLE product_pack_items (pack_id TEXT NOT NULL, kind TEXT NOT "
                    "NULL, item_id TEXT NOT NULL, name TEXT NOT NULL DEFAULT '', yaml_source "
                    "TEXT NOT NULL DEFAULT '', PRIMARY KEY (pack_id, item_id));");
        legacy_exec(db.get(),
                    "INSERT INTO product_packs VALUES ('legacy-pack-1', 'Legacy Pack', "
                    "'2.0.0', 'a legacy pack', 'kind: ProductPack', 1700000000, 1);");
        legacy_exec(db.get(),
                    "INSERT INTO product_pack_items VALUES ('legacy-pack-1', "
                    "'InstructionDefinition', 'legacy-item-1', 'Legacy Item', "
                    "'kind: InstructionDefinition');");
    }

    YUZU_REQUIRE_PG_DB_TPL(db, product_pack_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ProductPackStore store{pool};
    REQUIRE(store.is_open());

    REQUIRE(store.migrate_from_sqlite(legacy_db.path));

    auto got = store.get("legacy-pack-1");
    REQUIRE(got.has_value());
    REQUIRE(got->has_value());
    CHECK((*got)->name == "Legacy Pack");
    CHECK((*got)->version == "2.0.0");
    CHECK((*got)->verified);
    REQUIRE((*got)->items.size() == 1);
    CHECK((*got)->items[0].item_id == "legacy-item-1");

    // Idempotent: a second call against the same file/fingerprint does not duplicate or error.
    REQUIRE(store.migrate_from_sqlite(legacy_db.path));
    auto got2 = store.get("legacy-pack-1");
    REQUIRE(got2.has_value());
    REQUIRE(got2->has_value());
}

TEST_CASE("ProductPackStore::migrate_from_sqlite: pre-7.13 legacy file with no `verified` "
          "column backfills with verified=false",
          "[product_pack_store][pg]") {
    yuzu::test::TempDbFile legacy_db{std::string_view{"pack-legacy-pre713-"}};
    {
        SqliteDb db;
        REQUIRE(sqlite3_open_v2(legacy_db.path.string().c_str(), db.addr(),
                                SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) == SQLITE_OK);
        // Pre-7.13 shape: product_packs has NO `verified` column at all.
        legacy_exec(db.get(),
                    "CREATE TABLE product_packs (id TEXT PRIMARY KEY, name TEXT NOT NULL, "
                    "version TEXT NOT NULL DEFAULT '1.0.0', description TEXT NOT NULL DEFAULT "
                    "'', yaml_source TEXT NOT NULL, installed_at INTEGER NOT NULL DEFAULT 0);");
        legacy_exec(db.get(),
                    "CREATE TABLE product_pack_items (pack_id TEXT NOT NULL, kind TEXT NOT "
                    "NULL, item_id TEXT NOT NULL, name TEXT NOT NULL DEFAULT '', yaml_source "
                    "TEXT NOT NULL DEFAULT '', PRIMARY KEY (pack_id, item_id));");
        legacy_exec(db.get(),
                    "INSERT INTO product_packs VALUES ('pre713-pack', 'Pre-7.13 Pack', "
                    "'1.0.0', 'predates verified', 'kind: ProductPack', 1600000000);");
    }

    YUZU_REQUIRE_PG_DB_TPL(db, product_pack_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ProductPackStore store{pool};
    REQUIRE(store.is_open());

    REQUIRE(store.migrate_from_sqlite(legacy_db.path));

    auto got = store.get("pre713-pack");
    REQUIRE(got.has_value());
    REQUIRE(got->has_value());
    CHECK((*got)->name == "Pre-7.13 Pack");
    CHECK_FALSE((*got)->verified); // defaults to unverified, matching the pre-migration ALTER
                                   // TABLE ... DEFAULT 0 shim
}

TEST_CASE("ProductPackStore::migrate_from_sqlite: half-schema legacy file fails closed",
          "[product_pack_store][pg]") {
    yuzu::test::TempDbFile legacy_db{std::string_view{"pack-legacy-halfschema-"}};
    {
        SqliteDb db;
        REQUIRE(sqlite3_open_v2(legacy_db.path.string().c_str(), db.addr(),
                                SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) == SQLITE_OK);
        // Only product_packs exists — the shipped binary never produces this shape.
        legacy_exec(db.get(),
                    "CREATE TABLE product_packs (id TEXT PRIMARY KEY, name TEXT NOT NULL, "
                    "version TEXT NOT NULL DEFAULT '1.0.0', description TEXT NOT NULL DEFAULT "
                    "'', yaml_source TEXT NOT NULL, installed_at INTEGER NOT NULL DEFAULT 0, "
                    "verified INTEGER NOT NULL DEFAULT 0);");
    }

    YUZU_REQUIRE_PG_DB_TPL(db, product_pack_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ProductPackStore store{pool};
    REQUIRE(store.is_open());

    CHECK_FALSE(store.migrate_from_sqlite(legacy_db.path));
}

// Regression net for the item-conflict read-back bind bug (found in W7.4/ADR-0054 governance):
// the read-back that decides whether a conflicting `product_pack_items` row is a benign replay
// bound the RAW `item_id`, while every write path (including the very INSERT that lost the
// race) binds `sanitize_pg_text(item_id)`. For an item_id that sanitizes to something
// DIFFERENT from its raw bytes (invalid UTF-8, here — an embedded NUL hits the identical class
// but is awkward to author through `legacy_exec`'s C-string API), the read-back's WHERE clause
// never matched the row that is actually there, and a byte-identical replay was misreported as
// "could not be read back for comparison" — failing the ENTIRE backfill transaction closed,
// including the unrelated pack this same legacy file also carried. Exercises both the
// pack-level AND item-level "identical content is a benign no-op" contract the file header
// claims (undocumented before this test — see governance finding).
TEST_CASE("ProductPackStore::migrate_from_sqlite: identical-content conflict (incl. a "
          "non-UTF8 item_id) is a benign no-op, not a fail-closed error",
          "[product_pack_store][pg]") {
    yuzu::test::TempDbFile legacy_a{std::string_view{"pack-legacy-conflict-a-"}};
    {
        SqliteDb db;
        REQUIRE(sqlite3_open_v2(legacy_a.path.string().c_str(), db.addr(),
                                SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) == SQLITE_OK);
        legacy_exec(db.get(),
                    "CREATE TABLE product_packs (id TEXT PRIMARY KEY, name TEXT NOT NULL, "
                    "version TEXT NOT NULL DEFAULT '1.0.0', description TEXT NOT NULL DEFAULT "
                    "'', yaml_source TEXT NOT NULL, installed_at INTEGER NOT NULL DEFAULT 0, "
                    "verified INTEGER NOT NULL DEFAULT 0);");
        legacy_exec(db.get(),
                    "CREATE TABLE product_pack_items (pack_id TEXT NOT NULL, kind TEXT NOT "
                    "NULL, item_id TEXT NOT NULL, name TEXT NOT NULL DEFAULT '', yaml_source "
                    "TEXT NOT NULL DEFAULT '', PRIMARY KEY (pack_id, item_id));");
        legacy_exec(db.get(),
                    "INSERT INTO product_packs VALUES ('conflict-pack-shared', 'Shared Pack', "
                    "'1.0.0', 'replayed across two legacy files', 'kind: ProductPack', "
                    "1700000000, 0);");
        // Raw byte 0xFF is not valid UTF-8 on its own — sanitize_pg_text() replaces it with
        // U+FFFD on write, so the STORED item_id differs from this raw one.
        legacy_exec(db.get(),
                    "INSERT INTO product_pack_items VALUES ('conflict-pack-shared', "
                    "'InstructionDefinition', 'item-\xFF-bad', 'Shared Item', "
                    "'kind: InstructionDefinition');");
    }
    yuzu::test::TempDbFile legacy_b{std::string_view{"pack-legacy-conflict-b-"}};
    {
        SqliteDb db;
        REQUIRE(sqlite3_open_v2(legacy_b.path.string().c_str(), db.addr(),
                                SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) == SQLITE_OK);
        legacy_exec(db.get(),
                    "CREATE TABLE product_packs (id TEXT PRIMARY KEY, name TEXT NOT NULL, "
                    "version TEXT NOT NULL DEFAULT '1.0.0', description TEXT NOT NULL DEFAULT "
                    "'', yaml_source TEXT NOT NULL, installed_at INTEGER NOT NULL DEFAULT 0, "
                    "verified INTEGER NOT NULL DEFAULT 0);");
        legacy_exec(db.get(),
                    "CREATE TABLE product_pack_items (pack_id TEXT NOT NULL, kind TEXT NOT "
                    "NULL, item_id TEXT NOT NULL, name TEXT NOT NULL DEFAULT '', yaml_source "
                    "TEXT NOT NULL DEFAULT '', PRIMARY KEY (pack_id, item_id));");
        // Byte-identical shared pack + item (forces the conflict path on replay)...
        legacy_exec(db.get(),
                    "INSERT INTO product_packs VALUES ('conflict-pack-shared', 'Shared Pack', "
                    "'1.0.0', 'replayed across two legacy files', 'kind: ProductPack', "
                    "1700000000, 0);");
        legacy_exec(db.get(),
                    "INSERT INTO product_pack_items VALUES ('conflict-pack-shared', "
                    "'InstructionDefinition', 'item-\xFF-bad', 'Shared Item', "
                    "'kind: InstructionDefinition');");
        // ...plus an unrelated pack so this file's overall fingerprint differs from legacy_a's
        // (otherwise fingerprint dedup would skip the whole file before ever reaching the
        // per-row conflict-resolution code this test targets).
        legacy_exec(db.get(),
                    "INSERT INTO product_packs VALUES ('conflict-pack-b-only', 'B-Only Pack', "
                    "'1.0.0', 'only in legacy file B', 'kind: ProductPack', 1700000001, 0);");
    }

    YUZU_REQUIRE_PG_DB_TPL(db, product_pack_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ProductPackStore store{pool};
    REQUIRE(store.is_open());

    REQUIRE(store.migrate_from_sqlite(legacy_a.path));
    // legacy_b replays the identical shared pack+item (conflict, but content-identical) and
    // introduces one new pack. Pre-fix, the item read-back's raw-vs-sanitized bind mismatch
    // made this return false and roll back the ENTIRE transaction, including the new pack.
    REQUIRE(store.migrate_from_sqlite(legacy_b.path));

    auto shared = store.get("conflict-pack-shared");
    REQUIRE(shared.has_value());
    REQUIRE(shared->has_value());
    REQUIRE((*shared)->items.size() == 1);
    CHECK((*shared)->items[0].name == "Shared Item");

    auto b_only = store.get("conflict-pack-b-only");
    REQUIRE(b_only.has_value());
    REQUIRE(b_only->has_value());
    CHECK((*b_only)->name == "B-Only Pack");
}

// Companion to the identical-content case above: a conflicting row whose content genuinely
// DIFFERS must fail the backfill closed (every product_packs/product_pack_items column is
// write-once — see product_pack_store.hpp file header) rather than silently keep whichever
// value happened to insert first, and must not partially apply the rest of that legacy file's
// content (one transaction).
TEST_CASE("ProductPackStore::migrate_from_sqlite: differently-valued conflict fails closed "
          "and does not partially apply the rest of the file",
          "[product_pack_store][pg]") {
    yuzu::test::TempDbFile legacy_a{std::string_view{"pack-legacy-diffconflict-a-"}};
    {
        SqliteDb db;
        REQUIRE(sqlite3_open_v2(legacy_a.path.string().c_str(), db.addr(),
                                SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) == SQLITE_OK);
        legacy_exec(db.get(),
                    "CREATE TABLE product_packs (id TEXT PRIMARY KEY, name TEXT NOT NULL, "
                    "version TEXT NOT NULL DEFAULT '1.0.0', description TEXT NOT NULL DEFAULT "
                    "'', yaml_source TEXT NOT NULL, installed_at INTEGER NOT NULL DEFAULT 0, "
                    "verified INTEGER NOT NULL DEFAULT 0);");
        legacy_exec(db.get(),
                    "CREATE TABLE product_pack_items (pack_id TEXT NOT NULL, kind TEXT NOT "
                    "NULL, item_id TEXT NOT NULL, name TEXT NOT NULL DEFAULT '', yaml_source "
                    "TEXT NOT NULL DEFAULT '', PRIMARY KEY (pack_id, item_id));");
        legacy_exec(db.get(),
                    "INSERT INTO product_packs VALUES ('diffconflict-pack', 'Original Pack', "
                    "'1.0.0', 'original description', 'kind: ProductPack', 1700000000, 0);");
    }
    yuzu::test::TempDbFile legacy_c{std::string_view{"pack-legacy-diffconflict-c-"}};
    {
        SqliteDb db;
        REQUIRE(sqlite3_open_v2(legacy_c.path.string().c_str(), db.addr(),
                                SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) == SQLITE_OK);
        legacy_exec(db.get(),
                    "CREATE TABLE product_packs (id TEXT PRIMARY KEY, name TEXT NOT NULL, "
                    "version TEXT NOT NULL DEFAULT '1.0.0', description TEXT NOT NULL DEFAULT "
                    "'', yaml_source TEXT NOT NULL, installed_at INTEGER NOT NULL DEFAULT 0, "
                    "verified INTEGER NOT NULL DEFAULT 0);");
        legacy_exec(db.get(),
                    "CREATE TABLE product_pack_items (pack_id TEXT NOT NULL, kind TEXT NOT "
                    "NULL, item_id TEXT NOT NULL, name TEXT NOT NULL DEFAULT '', yaml_source "
                    "TEXT NOT NULL DEFAULT '', PRIMARY KEY (pack_id, item_id));");
        // Same id, DIFFERENT version — the write-once-column violation this test targets.
        legacy_exec(db.get(),
                    "INSERT INTO product_packs VALUES ('diffconflict-pack', 'Original Pack', "
                    "'2.0.0', 'original description', 'kind: ProductPack', 1700000000, 0);");
        legacy_exec(db.get(),
                    "INSERT INTO product_packs VALUES ('diffconflict-pack-c-only', "
                    "'C-Only Pack', '1.0.0', 'only in legacy file C', 'kind: ProductPack', "
                    "1700000002, 0);");
    }

    YUZU_REQUIRE_PG_DB_TPL(db, product_pack_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ProductPackStore store{pool};
    REQUIRE(store.is_open());

    REQUIRE(store.migrate_from_sqlite(legacy_a.path));
    CHECK_FALSE(store.migrate_from_sqlite(legacy_c.path));

    // Write-once: the original row is untouched by the failed/rolled-back replay.
    auto pack = store.get("diffconflict-pack");
    REQUIRE(pack.has_value());
    REQUIRE(pack->has_value());
    CHECK((*pack)->version == "1.0.0");

    // The unrelated new pack in the same (failed) transaction was NOT partially applied.
    auto c_only = store.get("diffconflict-pack-c-only");
    REQUIRE(c_only.has_value());
    CHECK_FALSE(c_only->has_value());
}

// ADR-0009 erasure consistency (F035/CH-E — the "ghost pack" hazard): a pack legitimately
// uninstalled via uninstall() must never be resurrected by a LATER migrate_from_sqlite call
// against a legacy file that still shows it installed — the concrete scenario is a redeployed
// or newly-joined replica whose own local legacy file predates the uninstall performed
// elsewhere/earlier. The uninstalled pack's id has no existing product_packs row to conflict
// against, so without a tombstone this hits the plain "no conflict, insert it" path.
TEST_CASE("ProductPackStore::migrate_from_sqlite: an uninstalled pack is never resurrected by a "
          "later backfill against a legacy file that still shows it installed",
          "[product_pack_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, product_pack_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ProductPackStore store{pool};
    REQUIRE(store.is_open());
    store.set_require_signed_packs(false);

    // Install, then uninstall — this is the real, server-assigned pack id (a random surrogate,
    // see product_pack_store.hpp), not a hand-chosen one.
    auto installed = store.install(kUnsignedPackYaml, make_accept_all_install_fn());
    REQUIRE(installed.has_value());
    const std::string ghost_id = *installed;

    auto uninstalled = store.uninstall(
        ghost_id, [](const std::string&, const std::string&) { return true; });
    REQUIRE(uninstalled.has_value());
    REQUIRE_FALSE(store.get(ghost_id)->has_value());

    // A legacy file — as if baked into a replica's image before the uninstall above happened —
    // still shows the now-deleted pack installed, plus one genuinely-new, unrelated pack.
    yuzu::test::TempDbFile legacy_ghost{std::string_view{"pack-legacy-ghost-"}};
    {
        SqliteDb legacy_db;
        REQUIRE(sqlite3_open_v2(legacy_ghost.path.string().c_str(), legacy_db.addr(),
                                SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) == SQLITE_OK);
        legacy_exec(legacy_db.get(),
                    "CREATE TABLE product_packs (id TEXT PRIMARY KEY, name TEXT NOT NULL, "
                    "version TEXT NOT NULL DEFAULT '1.0.0', description TEXT NOT NULL DEFAULT "
                    "'', yaml_source TEXT NOT NULL, installed_at INTEGER NOT NULL DEFAULT 0, "
                    "verified INTEGER NOT NULL DEFAULT 0);");
        legacy_exec(legacy_db.get(),
                    "CREATE TABLE product_pack_items (pack_id TEXT NOT NULL, kind TEXT NOT "
                    "NULL, item_id TEXT NOT NULL, name TEXT NOT NULL DEFAULT '', yaml_source "
                    "TEXT NOT NULL DEFAULT '', PRIMARY KEY (pack_id, item_id));");
        legacy_exec(legacy_db.get(),
                    std::format("INSERT INTO product_packs VALUES ('{}', 'test-unsigned', "
                                "'1.0.0', 'stale snapshot of an uninstalled pack', "
                                "'kind: ProductPack', 1700000000, 0);",
                                ghost_id)
                        .c_str());
        legacy_exec(legacy_db.get(),
                    std::format("INSERT INTO product_pack_items VALUES ('{}', "
                                "'InstructionDefinition', 'ghost-item', 'Ghost Item', "
                                "'kind: InstructionDefinition');",
                                ghost_id)
                        .c_str());
        legacy_exec(legacy_db.get(),
                    "INSERT INTO product_packs VALUES ('legit-new-pack', 'Legit New Pack', "
                    "'1.0.0', 'a genuinely new pack in the same legacy file', "
                    "'kind: ProductPack', 1700000001, 0);");
    }

    REQUIRE(store.migrate_from_sqlite(legacy_ghost.path));

    // The uninstalled pack stays gone — not resurrected, and none of its items either.
    auto ghost = store.get(ghost_id);
    REQUIRE(ghost.has_value());
    CHECK_FALSE(ghost->has_value());

    // An unrelated pack in the SAME legacy file, SAME backfill pass, still backfills normally —
    // the tombstone skip is scoped to the one id, not a whole-file failure.
    auto legit = store.get("legit-new-pack");
    REQUIRE(legit.has_value());
    REQUIRE(legit->has_value());
    CHECK((*legit)->name == "Legit New Pack");

    // Idempotent: a second backfill pass against a legacy file with this exact same content is
    // a no-op fingerprint-skip, but re-running against a DIFFERENT (not-yet-seen) legacy file
    // naming the same ghost id must still refuse to resurrect it.
    yuzu::test::TempDbFile legacy_ghost_2{std::string_view{"pack-legacy-ghost-2-"}};
    {
        SqliteDb legacy_db;
        REQUIRE(sqlite3_open_v2(legacy_ghost_2.path.string().c_str(), legacy_db.addr(),
                                SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) == SQLITE_OK);
        legacy_exec(legacy_db.get(),
                    "CREATE TABLE product_packs (id TEXT PRIMARY KEY, name TEXT NOT NULL, "
                    "version TEXT NOT NULL DEFAULT '1.0.0', description TEXT NOT NULL DEFAULT "
                    "'', yaml_source TEXT NOT NULL, installed_at INTEGER NOT NULL DEFAULT 0, "
                    "verified INTEGER NOT NULL DEFAULT 0);");
        legacy_exec(legacy_db.get(),
                    "CREATE TABLE product_pack_items (pack_id TEXT NOT NULL, kind TEXT NOT "
                    "NULL, item_id TEXT NOT NULL, name TEXT NOT NULL DEFAULT '', yaml_source "
                    "TEXT NOT NULL DEFAULT '', PRIMARY KEY (pack_id, item_id));");
        // A second, independently-stale replica snapshot — different unrelated pack alongside
        // the same ghost id, so this file's fingerprint differs from legacy_ghost's.
        legacy_exec(legacy_db.get(),
                    std::format("INSERT INTO product_packs VALUES ('{}', 'test-unsigned', "
                                "'1.0.0', 'a second, independently-stale snapshot', "
                                "'kind: ProductPack', 1700000000, 0);",
                                ghost_id)
                        .c_str());
        legacy_exec(legacy_db.get(),
                    "INSERT INTO product_packs VALUES ('legit-new-pack-2', 'Legit New Pack 2', "
                    "'1.0.0', 'another genuinely new pack', 'kind: ProductPack', 1700000002, "
                    "0);");
    }
    REQUIRE(store.migrate_from_sqlite(legacy_ghost_2.path));
    CHECK_FALSE(store.get(ghost_id)->has_value());
    auto legit2 = store.get("legit-new-pack-2");
    REQUIRE(legit2.has_value());
    REQUIRE(legit2->has_value());
}

// Gate 8 review of F035 (security-guardian/architect, both BLOCKING — same race RbacStore hit
// and fixed as HIGH, CHAOS-1; see test_rbac_store.cpp's identical-shaped test and
// kErasureCoordLockSql's comment in product_pack_store.cpp for the full mechanism): without the
// coordination lock, migrate_from_sqlite's tombstone check and its pack INSERT are two separate
// READ COMMITTED statement snapshots — a concurrent uninstall() that commits its delete +
// tombstone in the window between them would be invisible to the already-taken SELECT snapshot,
// resurrecting the pack despite the tombstone existing right next to it.
TEST_CASE("ProductPackStore::migrate_from_sqlite cannot resurrect a pack mid-uninstall "
          "(erasure-coordination lock)",
          "[product_pack_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, product_pack_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ProductPackStore store{pool};
    REQUIRE(store.is_open());
    store.set_require_signed_packs(false);

    auto installed = store.install(kUnsignedPackYaml, make_accept_all_install_fn());
    REQUIRE(installed.has_value());
    const std::string ghost_id = *installed;

    // A legacy file naming this still-installed pack, as migrate_from_sqlite will see it if it
    // races a concurrent, not-yet-committed uninstall() of the same id.
    yuzu::test::TempDbFile legacy_race{std::string_view{"pack-legacy-race-"}};
    {
        SqliteDb legacy_db;
        REQUIRE(sqlite3_open_v2(legacy_race.path.string().c_str(), legacy_db.addr(),
                                SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) == SQLITE_OK);
        legacy_exec(legacy_db.get(),
                    "CREATE TABLE product_packs (id TEXT PRIMARY KEY, name TEXT NOT NULL, "
                    "version TEXT NOT NULL DEFAULT '1.0.0', description TEXT NOT NULL DEFAULT "
                    "'', yaml_source TEXT NOT NULL, installed_at INTEGER NOT NULL DEFAULT 0, "
                    "verified INTEGER NOT NULL DEFAULT 0);");
        legacy_exec(legacy_db.get(),
                    "CREATE TABLE product_pack_items (pack_id TEXT NOT NULL, kind TEXT NOT "
                    "NULL, item_id TEXT NOT NULL, name TEXT NOT NULL DEFAULT '', yaml_source "
                    "TEXT NOT NULL DEFAULT '', PRIMARY KEY (pack_id, item_id));");
        legacy_exec(legacy_db.get(),
                    std::format("INSERT INTO product_packs VALUES ('{}', 'test-unsigned', "
                                "'1.0.0', 'racing uninstall', 'kind: ProductPack', 1700000000, "
                                "0);",
                                ghost_id)
                        .c_str());
    }

    // Connection A: hand-built SQL replicating uninstall()'s exact write sequence (lock, delete
    // items, delete pack, insert tombstone) — held UNCOMMITTED, simulating uninstall()'s
    // in-flight transaction racing a concurrent migrate_from_sqlite boot on another connection.
    auto lease_a = pool.acquire();
    REQUIRE(lease_a);
    REQUIRE(pg::exec_params(lease_a.get(), "BEGIN", std::vector<std::string>{}).ok());
    REQUIRE(pg::exec_params(lease_a.get(),
                            "SELECT pg_advisory_xact_lock(2037545589, "
                            "hashtext('product_pack_store:erasure_coordination'))",
                            std::vector<std::string>{})
                .ok());
    REQUIRE(pg::exec_params(lease_a.get(),
                            "DELETE FROM product_pack_store.product_pack_items WHERE pack_id = $1",
                            std::vector<std::string>{ghost_id})
                .ok());
    REQUIRE(pg::exec_params(lease_a.get(),
                            "DELETE FROM product_pack_store.product_packs WHERE id = $1",
                            std::vector<std::string>{ghost_id})
                .ok());
    REQUIRE(pg::exec_params(lease_a.get(),
                            "INSERT INTO product_pack_store.deleted_pack_ids (pack_id, "
                            "deleted_at) VALUES ($1, $2::bigint) ON CONFLICT (pack_id) DO "
                            "NOTHING",
                            std::vector<std::string>{ghost_id, "1700000099"})
                .ok());

    // Connection B, on a separate thread: the REAL migrate_from_sqlite, exercising the actual
    // production code, not a hand-copy. Must BLOCK on connection A's held lock, and once
    // unblocked, must see the tombstone A already committed and skip — not resurrect.
    std::atomic<bool> b_started{false};
    std::atomic<bool> b_done{false};
    std::atomic<bool> b_ok{false};
    std::thread migrate_thread([&] {
        b_started = true;
        b_ok = store.migrate_from_sqlite(legacy_race.path);
        b_done = true;
    });
    // cpp-safety (Gate 8): join-on-unwind guard — a REQUIRE between thread construction and the
    // explicit join() below throws on failure, and a joinable std::thread destroyed mid-unwind
    // calls std::terminate(). Not safe to detach: the lambda captures store/b_started/b_done/
    // b_ok BY REFERENCE (stack locals of this TEST_CASE) — a detached thread outliving them
    // would be a use-after-free. The thread's only blocking wait is the advisory lock, server-
    // side bounded by the pool's lock/statement timeouts, so join() here cannot hang forever.
    struct ThreadJoiner {
        std::thread& t;
        ~ThreadJoiner() {
            if (t.joinable())
                t.join();
        }
    } joiner{migrate_thread};

    // Give the migrate thread time to start and genuinely block on connection A's held lock —
    // proves this is a real blocked-then-unblocked interleaving, not a lucky race.
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    CHECK(b_started.load());
    CHECK_FALSE(b_done.load());

    const bool commit_ok = pg::exec_params(lease_a.get(), "COMMIT", std::vector<std::string>{}).ok();
    lease_a.reset();
    migrate_thread.join();
    CHECK(commit_ok);
    CHECK(b_done.load());
    CHECK(b_ok.load());

    // THE FIX: the pack must stay uninstalled — not resurrected by the racing backfill.
    auto ghost = store.get(ghost_id);
    REQUIRE(ghost.has_value());
    CHECK_FALSE(ghost->has_value());
}

// H2 net (governance-pattern regression, matches ResultSetStore/LicenseStore's own mid-scan
// tests): a legacy SQLite file that dies MID-SCAN (a corrupt page / short read, not simply "file
// absent" or "well-formed and empty") must abort the backfill without stamping the marker.
// Truncating a multi-page legacy file to roughly half its size deterministically yields
// SQLITE_CORRUPT on the very first sqlite3_step of the product_packs scan — SQLite's pager
// cross-checks the file's actual byte length against the page count recorded in the header at
// open/first-read time, so this reliably corrupts a multi-page file from the very first read; a
// single-page fixture would not reliably reproduce this.
TEST_CASE("ProductPackStore::migrate_from_sqlite: mid-scan corruption fails closed, never "
          "stamps a partial backfill",
          "[product_pack_store][pg]") {
    yuzu::test::TempDbFile legacy_db{std::string_view{"pack-legacy-corrupt-"}};
    {
        SqliteDb db;
        REQUIRE(sqlite3_open_v2(legacy_db.path.string().c_str(), db.addr(),
                                SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) == SQLITE_OK);
        legacy_exec(db.get(),
                    "CREATE TABLE product_packs (id TEXT PRIMARY KEY, name TEXT NOT NULL, "
                    "version TEXT NOT NULL DEFAULT '1.0.0', description TEXT NOT NULL DEFAULT "
                    "'', yaml_source TEXT NOT NULL, installed_at INTEGER NOT NULL DEFAULT 0, "
                    "verified INTEGER NOT NULL DEFAULT 0);");
        legacy_exec(db.get(),
                    "CREATE TABLE product_pack_items (pack_id TEXT NOT NULL, kind TEXT NOT "
                    "NULL, item_id TEXT NOT NULL, name TEXT NOT NULL DEFAULT '', yaml_source "
                    "TEXT NOT NULL DEFAULT '', PRIMARY KEY (pack_id, item_id));");
        // Bulk-insert enough long-`yaml_source` rows to span several SQLite pages (default
        // 4096-byte page size) — a fixture big enough that "truncate the tail" lands inside the
        // table's b-tree rather than merely shortening an otherwise-intact single-page file.
        SqliteStmt s;
        REQUIRE(sqlite3_prepare_v2(db.get(),
                                   "INSERT INTO product_packs VALUES (?, ?, '1.0.0', '', ?, "
                                   "1700000000, 0)",
                                   -1, s.addr(), nullptr) == SQLITE_OK);
        const std::string padding(512, 'x');
        for (int i = 0; i < 200; ++i) {
            std::string id = "bulk-pack-" + std::to_string(i);
            sqlite3_reset(s.get());
            sqlite3_bind_text(s.get(), 1, id.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(s.get(), 2, id.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(s.get(), 3, padding.c_str(), -1, SQLITE_TRANSIENT);
            REQUIRE(sqlite3_step(s.get()) == SQLITE_DONE);
        }
    }
    auto full_size = std::filesystem::file_size(legacy_db.path);
    REQUIRE(full_size > 8192); // sanity: really did span more than one page
    std::filesystem::resize_file(legacy_db.path, full_size / 2);

    YUZU_REQUIRE_PG_DB_TPL(db, product_pack_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ProductPackStore store{pool};
    REQUIRE(store.is_open());

    CHECK_FALSE(store.migrate_from_sqlite(legacy_db.path));

    // A subsequent migrate_from_sqlite against a freshly-written, INTACT file succeeds against
    // the SAME Postgres database — proving the aborted pass never stamped the marker.
    yuzu::test::TempDbFile intact_db{std::string_view{"pack-legacy-intact-"}};
    {
        SqliteDb db2;
        REQUIRE(sqlite3_open_v2(intact_db.path.string().c_str(), db2.addr(),
                                SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) == SQLITE_OK);
        legacy_exec(db2.get(),
                    "CREATE TABLE product_packs (id TEXT PRIMARY KEY, name TEXT NOT NULL, "
                    "version TEXT NOT NULL DEFAULT '1.0.0', description TEXT NOT NULL DEFAULT "
                    "'', yaml_source TEXT NOT NULL, installed_at INTEGER NOT NULL DEFAULT 0, "
                    "verified INTEGER NOT NULL DEFAULT 0);");
        legacy_exec(db2.get(),
                    "CREATE TABLE product_pack_items (pack_id TEXT NOT NULL, kind TEXT NOT "
                    "NULL, item_id TEXT NOT NULL, name TEXT NOT NULL DEFAULT '', yaml_source "
                    "TEXT NOT NULL DEFAULT '', PRIMARY KEY (pack_id, item_id));");
        legacy_exec(db2.get(),
                    "INSERT INTO product_packs VALUES ('intact-pack', 'Intact Pack', '1.0.0', "
                    "'', 'kind: ProductPack', 1700000000, 0);");
    }
    CHECK(store.migrate_from_sqlite(intact_db.path));
    auto got = store.get("intact-pack");
    REQUIRE(got.has_value());
    CHECK(got->has_value());
}

// ── REST-level regression net (Gate 8 round-2: quality-engineer + unhappy-path, twice-flagged)
// ──
//
// The store-level tests above prove the backend contract; nothing before this point drives an
// actual HTTP request through WorkflowRoutes' four product-pack handlers, so the genericization
// split (workflow_routes.cpp's product_pack_client_message — response body only, never the
// audit trail) and the DELETE-denied audit_fn addition (56fbd3580) were previously verified only
// by direct code reading. These two cases close that gap. No new test FILE — same
// [product_pack_store] tag family, inherits the existing shard placement, no meson.build change.

namespace {

/// Minimal WorkflowRoutes harness scoped to the product-pack routes only. Every other Deps
/// field stays default (nullptr/empty std::function) — safe, because auth_fn/scope_fn/
/// command_dispatch_fn/caller_fn are never invoked by the GET/POST/DELETE product-pack handlers
/// (only by this file's other registered routes, none of which this harness dispatches to).
struct ProductPackRestHarness {
    // Declaration order matters (gov Gate 8 round-3, cpp-safety): `sink` stores the
    // registered handlers, one of which captures `this` to append into `audit_rows` — so
    // `audit_rows` must outlive `sink` and therefore be declared BEFORE it (destroyed
    // after it, per reverse-declaration-order teardown). `metrics` is unreferenced by any
    // product-pack handler but is declared first regardless, matching
    // test_route_sink.hpp's own "declare the sink after the route owner" invariant.
    yuzu::MetricsRegistry metrics;
    std::vector<std::tuple<std::string, std::string, std::string, std::string, std::string>>
        audit_rows; // (action, result, target_type, target_id, detail)
    yuzu::server::test::TestRouteSink sink;

    explicit ProductPackRestHarness(ProductPackStore* store) {
        WorkflowRoutes routes;
        WorkflowRoutes::Deps deps;
        deps.perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                          const std::string&) { return true; };
        deps.audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string& target_type,
                               const std::string& target_id, const std::string& detail) {
            audit_rows.emplace_back(action, result, target_type, target_id, detail);
        };
        deps.emit_fn = [](const std::string&, const httplib::Request&) {};
        deps.product_pack_store = store;
        deps.metrics = &metrics;
        routes.register_routes(sink, std::move(deps));
    }
};

} // namespace

TEST_CASE("REST: a genuine DB error never reaches the response body or the audit trail as raw "
          "driver text",
          "[product_pack_store]") {
    // Unreachable pool (same fixture as the store-level "!is_open" test above) — every
    // ProductPackStore method deterministically returns a kProductPackDbErrorPrefix error, with
    // no live Postgres required. This is the classifier's PREFIX check, not its content, so it
    // exercises the same genericization path a real PQerrorMessage() leak would hit.
    PgPool pool{{.conninfo = "=quohth4eeQu5 garbage =", .size = 2}};
    REQUIRE_FALSE(pool.valid());
    ProductPackStore store{pool};
    REQUIRE_FALSE(store.is_open());

    ProductPackRestHarness h{&store};

    // GET /api/product-packs has its OWN pre-existing `!is_open()` early guard (unrelated to
    // this fix round — it short-circuits before list() is ever called, so it never reaches
    // product_pack_client_message()'s genericization path at all) with its own hardcoded,
    // already-generic message. Different string than the genericizer's, same "no internals
    // leaked" property — assert that property, not byte-identical wording across routes.
    auto list_res = h.sink.dispatch("GET", "/api/product-packs");
    REQUIRE(list_res);
    CHECK(list_res->status == 503);
    CHECK(list_res->body.find("db_error") == std::string::npos);
    CHECK(list_res->body.find("not open") == std::string::npos);

    auto del_res = h.sink.dispatch("DELETE", "/api/product-packs/some-id");
    REQUIRE(del_res);
    CHECK(del_res->status == 503);
    CHECK(del_res->body.find("service unavailable") != std::string::npos);
    CHECK(del_res->body.find("db_error") == std::string::npos);
    CHECK(del_res->body.find("not open") == std::string::npos);

    // Regression net for 56fbd3580: the audit `detail` must be genericized identically to the
    // response body, not the raw "db_error: database not open" the store returned.
    REQUIRE(h.audit_rows.size() == 1);
    const auto& [action, result, target_type, target_id, detail] = h.audit_rows[0];
    CHECK(action == "product_pack.uninstall");
    CHECK(result == "denied");
    CHECK(target_type == "ProductPack");
    CHECK(target_id == "some-id");
    CHECK(detail == "service unavailable");
    CHECK(detail.find("db_error") == std::string::npos);
    CHECK(detail.find("not open") == std::string::npos);
}

TEST_CASE("REST: a not-found rejection is echoed verbatim in both the response and the audit "
          "trail",
          "[product_pack_store][pg]") {
    // Live store: not_found never carries kProductPackDbErrorPrefix, so it must pass through
    // product_pack_client_message() unchanged in both the response body and the audit detail —
    // the positive-path counterpart to the genericization test above.
    YUZU_REQUIRE_PG_DB_TPL(db, product_pack_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ProductPackStore store{pool};
    REQUIRE(store.is_open());

    ProductPackRestHarness h{&store};

    auto del_res = h.sink.dispatch("DELETE", "/api/product-packs/does-not-exist");
    REQUIRE(del_res);
    CHECK(del_res->status == 404);
    CHECK((del_res->body.find("not_found") != std::string::npos ||
          del_res->body.find("does-not-exist") != std::string::npos));

    REQUIRE(h.audit_rows.size() == 1);
    const auto& [action, result, target_type, target_id, detail] = h.audit_rows[0];
    CHECK(action == "product_pack.uninstall");
    CHECK(result == "denied");
    CHECK(target_type == "ProductPack");
    CHECK(target_id == "does-not-exist");
    CHECK(detail.starts_with("not_found:"));
    CHECK(detail.find("does-not-exist") != std::string::npos);
}
