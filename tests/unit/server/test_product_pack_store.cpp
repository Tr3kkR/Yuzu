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
 *
 * No legacy-SQLite backfill test coverage: the dedicated migrate_from_sqlite TEST_CASE suite
 * was removed as part of a fresh-start-by-default policy change (ADR-0009 amendment) -- no
 * production fleet has ever run a pre-Postgres build. ProductPackStore::migrate_from_sqlite()
 * itself is UNCHANGED and still present in production code; only this file's test coverage of
 * it was removed.
 */

#include "product_pack_store.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "test_route_sink.hpp"
#include "workflow_routes.hpp"

#include <yuzu/metrics.hpp>

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <openssl/evp.h>

#include <libpq-fe.h>

#include <atomic>
#include <chrono>
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
