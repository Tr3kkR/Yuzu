/**
 * test_ca_store.cpp — `CaStore` (Yuzu internal CA inventory + lifecycle, ADR-0053).
 *
 * Covers:
 *  - fail-closed construction (a live but unmigratable database).
 *  - root: try_insert_root's first-boot race-safety (winner/loser semantics), set_root's
 *    unconditional-replace contract (subordinate import / test seeding), get_root's
 *    type-distinguishable read.
 *  - issued-cert record/get/list/list_issued_by_key_id, provenance columns, duplicate-serial
 *    classification (#1276), revoke (idempotent, expected<bool,...> semantics), is_revoked
 *    (fail-closed bool), list_revoked, a real-leaf revocation round-trip through pki::.
 *  - serial normalisation (pure function).
 *  - CRL numbering + record/latest roundtrip, publish_next_crl atomic allocation,
 *    record_crl's duplicate-version refusal.
 *
 * No legacy-SQLite backfill test coverage: the dedicated backfill TEST_CASE suite
 * (ADR-0009/0053) was removed as part of a fresh-start-by-default policy change
 * (ADR-0009 amendment, 2026-08-25) -- no production fleet has ever run a
 * pre-Postgres build. CaStore::migrate_from_sqlite() itself is UNCHANGED and
 * still present (its removal is a separate, later step).
 *
 * Migrated-to-Postgres store (ADR-0012 §1, authoritative/fail-hard). PG-gated: skips when
 * YUZU_TEST_POSTGRES_DSN is unset, fails when set but broken (test_helpers.hpp skip-vs-fail
 * contract). Store-behaviour cases use the pre-migrated PgTestTemplate variant
 * (docs/postgres-store-playbook.md step 7); the fail-closed construction case uses
 * YUZU_REQUIRE_PG_DB / no gate at all, per the plain-migration-test carve-out documented on that
 * macro.
 */

#include "ca_store.hpp"
#include "x509_ca.hpp"

#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>

#include <chrono>
#include <cstdint>
#include <set>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

using namespace yuzu::server;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;

// CaStore borrows a PgPool&; it must be non-copyable (and non-movable) so the borrow can never be
// duplicated.
static_assert(!std::is_copy_constructible_v<CaStore>);
static_assert(!std::is_copy_assignable_v<CaStore>);

namespace {

yuzu::test::PgTestTemplate ca_store_tpl{"castore", [](const std::string& dsn) {
                                            PgPool pool{{.conninfo = dsn, .size = 1}};
                                            CaStore store{pool};
                                            if (!store.is_open())
                                                throw std::runtime_error(
                                                    "ca_store template: store failed to migrate");
                                        }};

int64_t now_s() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

IssuedCertRecord sample_issued(const std::string& serial, const std::string& purpose = "agent") {
    IssuedCertRecord r;
    r.serial_hex = serial;
    r.subject = "CN=agent-" + serial;
    r.san = "URI:yuzu://inst/agent/" + serial;
    r.purpose = purpose;
    r.not_after = now_s() + 86400;
    r.issued_at = now_s();
    return r;
}

CaRoot sample_root(const std::string& fingerprint = "AB:CD:EF") {
    CaRoot root;
    root.cert_pem = "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n";
    root.key_ref = "/etc/yuzu/certs/ca.key";
    root.algo = "EcP384";
    root.not_before = now_s();
    root.not_after = now_s() + 10L * 31557600L;
    root.fingerprint_sha256 = fingerprint;
    root.mode = CaMode::Builtin;
    return root;
}

} // namespace

// ── Construction fail-closed ────────────────────────────────────────────────

TEST_CASE("CaStore reports !is_open on a migration failure", "[ca_store][pg]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult s{PQexec(conn.get(), "CREATE SCHEMA ca_store")};
        REQUIRE(s.ok());
        PgResult t{PQexec(conn.get(), "CREATE TABLE ca_store.ca_root (bogus int)")};
        REQUIRE(t.ok());
    }
    PgPool pool{{.conninfo = db.dsn(), .size = 1}};
    CaStore store{pool};
    REQUIRE_FALSE(store.is_open());
}

// ── Root ──────────────────────────────────────────────────────────────────

TEST_CASE("CaStore: opens with no root", "[ca_store][pg][root]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    REQUIRE(store.is_open());
    REQUIRE_FALSE(store.has_root());
    auto got = store.get_root();
    REQUIRE(got.has_value());
    REQUIRE_FALSE(got->has_value());
}

TEST_CASE("CaStore: set_root unconditionally replaces (subordinate import / test seeding)",
          "[ca_store][pg][root]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    REQUIRE(store.is_open());

    auto root = sample_root();
    REQUIRE(store.set_root(root).has_value());
    REQUIRE(store.has_root());

    auto got = store.get_root();
    REQUIRE(got.has_value());
    REQUIRE(got->has_value());
    CHECK((*got)->cert_pem == root.cert_pem);
    CHECK((*got)->key_ref == root.key_ref);
    CHECK((*got)->algo == "EcP384");
    CHECK((*got)->fingerprint_sha256 == "AB:CD:EF");
    CHECK((*got)->mode == CaMode::Builtin);
    CHECK((*got)->chain_pem.empty()); // builtin → no parent chain (PR6)

    // Replace with a subordinate-CA import: single row, latest wins, and the parent chain
    // (enterprise root above our issuing intermediate) round-trips.
    CaRoot root2 = root;
    root2.fingerprint_sha256 = "99:88:77";
    root2.mode = CaMode::Subordinate;
    root2.chain_pem = "-----BEGIN CERTIFICATE-----\nENTERPRISE-ROOT\n-----END CERTIFICATE-----\n";
    REQUIRE(store.set_root(root2).has_value());
    auto got2 = store.get_root();
    REQUIRE(got2.has_value());
    REQUIRE(got2->has_value());
    CHECK((*got2)->fingerprint_sha256 == "99:88:77");
    CHECK((*got2)->mode == CaMode::Subordinate);
    CHECK((*got2)->chain_pem == root2.chain_pem);
}

TEST_CASE("CaStore: set_root rejects empty cert/key_ref", "[ca_store][pg][root][negative]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    CaRoot bad;
    bad.algo = "EcP384";
    REQUIRE_FALSE(store.set_root(bad).has_value());
    REQUIRE_FALSE(store.has_root());
}

// ADR-0053 "Root-singleton first-boot race": the one genuinely new problem a shared Postgres
// substrate introduces over per-instance SQLite.
TEST_CASE("CaStore: try_insert_root — first caller wins, echoes its own root",
          "[ca_store][pg][root]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    REQUIRE(store.is_open());

    auto root = sample_root("WINNER:FP");
    auto result = store.try_insert_root(root);
    REQUIRE(result.has_value());
    CHECK(result->fingerprint_sha256 == "WINNER:FP");

    auto got = store.get_root();
    REQUIRE(got.has_value());
    REQUIRE(got->has_value());
    CHECK((*got)->fingerprint_sha256 == "WINNER:FP");
}

TEST_CASE("CaStore: try_insert_root — a losing caller reads back the winner, never clobbers it",
          "[ca_store][pg][root][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    REQUIRE(store.is_open());

    auto winner_root = sample_root("WINNER:FP");
    auto winner_result = store.try_insert_root(winner_root);
    REQUIRE(winner_result.has_value());
    CHECK(winner_result->fingerprint_sha256 == "WINNER:FP");

    // A second instance independently generated DIFFERENT root material and races the same
    // call — it must NOT win, must NOT clobber, and must read back the ALREADY-established root.
    auto loser_root = sample_root("LOSER:FP");
    loser_root.cert_pem = "-----BEGIN CERTIFICATE-----\nLOSER\n-----END CERTIFICATE-----\n";
    auto loser_result = store.try_insert_root(loser_root);
    REQUIRE(loser_result.has_value());
    CHECK(loser_result->fingerprint_sha256 == "WINNER:FP"); // NOT its own — the winner's
    CHECK(loser_result->cert_pem == winner_root.cert_pem);

    // The stored row is still exactly the winner's — never clobbered.
    auto got = store.get_root();
    REQUIRE(got.has_value());
    REQUIRE(got->has_value());
    CHECK((*got)->fingerprint_sha256 == "WINNER:FP");
}

TEST_CASE("CaStore: try_insert_root rejects empty cert/key_ref", "[ca_store][pg][root][negative]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    CaRoot bad;
    bad.algo = "EcP384";
    REQUIRE_FALSE(store.try_insert_root(bad).has_value());
    REQUIRE_FALSE(store.has_root());
}

TEST_CASE("CaStore: get_root() reports a genuine store failure as unexpected, while has_root() "
          "collapses the SAME failure to false (governance Gate 3 quality-engineer, 2026-08-21)",
          "[ca_store][pg][root][security]") {
    // The distinction this test pins is exactly what the a14138449 adversarial-review fix
    // depends on: server.cpp's boot-time PKI wiring block must call get_root() (typed,
    // distinguishes "genuine DB error" from "no root") rather than has_root() (collapses
    // BOTH cases to false) — a lossy has_root() at that ONE call site was the HIGH. This
    // test does not exercise server.cpp's full boot sequence (not unit-constructible, see
    // test_default_certs.cpp's existing note on that class of code) — it instead proves the
    // store-level CONTRACT the fix relies on: given the identical underlying failure, the two
    // methods must disagree in exactly this way, in isolation, cheaply, without booting a
    // real ServerImpl.
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    REQUIRE(store.is_open());

    // Establish a real root first — the pre-migration bug specifically mattered when a root
    // ALREADY EXISTS and a later read of it degrades; a permanently-empty store never reaches
    // the boot-wiring block's true branch in the first place.
    auto root = sample_root("EXISTING:FP");
    REQUIRE(store.try_insert_root(root).has_value());
    REQUIRE(store.has_root());

    // Sabotage the store out from under the open CaStore instance — same technique as
    // test_deployment_store.cpp's "list_jobs/get_job report a genuine store failure as
    // unexpected" and test_api_token_store.cpp's equivalent (both cited as this codebase's
    // established pattern for this exact class of test).
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult d{PQexec(conn.get(), "DROP TABLE ca_store.ca_root CASCADE")};
        REQUIRE(d.status() == PGRES_COMMAND_OK);
    }

    // get_root(): typed, distinguishable — a genuine DB error, never folded into "no root".
    auto got = store.get_root();
    CHECK_FALSE(got.has_value());
    CHECK(got.error().starts_with(kCaDbErrorPrefix));

    // has_root(): the SAME underlying failure collapses to false — indistinguishable, by
    // design, from a genuinely-empty store. This is exactly why ADR-0053 restricts has_root()
    // to the two callers that are provably safe with that collapse (the CRL-freshness sweep
    // tick, /readyz) and why the boot-time PKI wiring block must NOT be a third.
    CHECK_FALSE(store.has_root());
}

// ── Issued inventory ─────────────────────────────────────────────────────

TEST_CASE("CaStore: issued record/get/list", "[ca_store][pg][issued]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};

    REQUIRE(store.record_issued(sample_issued("AA11")).has_value());
    REQUIRE(store.record_issued(sample_issued("BB22", "https")).has_value());

    auto got = store.get_issued("AA11");
    REQUIRE(got.has_value());
    REQUIRE(got->has_value());
    CHECK((*got)->purpose == "agent");
    CHECK((*got)->status == CertStatus::Active);

    auto nope = store.get_issued("NOPE");
    REQUIRE(nope.has_value());
    REQUIRE_FALSE(nope->has_value());

    auto all = store.list_issued();
    REQUIRE(all.has_value());
    CHECK(all->size() == 2);
}

// #1276 (record_issued's flake lead): a serial collision is classified distinctly, prefixed
// kCaDuplicateSerialPrefix, not the generic kCaDbErrorPrefix — a caller can retry with a fresh
// serial rather than treating it as an outage.
TEST_CASE("CaStore: record_issued classifies a duplicate serial distinctly (#1276)",
          "[ca_store][pg][issued][negative]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};

    REQUIRE(store.record_issued(sample_issued("AA11")).has_value());
    auto dup = store.record_issued(sample_issued("AA11"));
    REQUIRE_FALSE(dup.has_value());
    CHECK(dup.error().starts_with(kCaDuplicateSerialPrefix));
    CHECK_FALSE(dup.error().starts_with(kCaDbErrorPrefix));
}

TEST_CASE("CaStore: record_issued rejects empty serial", "[ca_store][pg][issued][negative]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    REQUIRE_FALSE(store.record_issued(sample_issued("")).has_value());
}

TEST_CASE("CaStore: issued provenance columns round-trip", "[ca_store][pg][issued]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    auto rec = sample_issued("CAFE");
    rec.issued_by = "operator:alice";
    rec.enrollment_request_id = "enr-123";
    rec.cert_pem = "-----BEGIN CERTIFICATE-----\nXYZ\n-----END CERTIFICATE-----\n";
    REQUIRE(store.record_issued(rec).has_value());
    auto got = store.get_issued("CAFE");
    REQUIRE(got.has_value());
    REQUIRE(got->has_value());
    CHECK((*got)->issued_by == "operator:alice");
    CHECK((*got)->enrollment_request_id == "enr-123");
    CHECK((*got)->cert_pem == rec.cert_pem);
}

TEST_CASE("CaStore: revoke is idempotent and reflected", "[ca_store][pg][revoke]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    REQUIRE(store.record_issued(sample_issued("DEAD")).has_value());

    REQUIRE_FALSE(store.is_revoked("DEAD"));

    auto r1 = store.revoke("DEAD", "key compromise");
    REQUIRE(r1.has_value());
    CHECK(*r1); // first revoke changes a row

    auto r2 = store.revoke("DEAD", "again");
    REQUIRE(r2.has_value());
    CHECK_FALSE(*r2); // idempotent: no change

    auto r3 = store.revoke("UNKNOWN", "n/a");
    REQUIRE(r3.has_value());
    CHECK_FALSE(*r3); // unknown serial: no change

    REQUIRE(store.is_revoked("DEAD"));
    auto got = store.get_issued("DEAD");
    REQUIRE(got.has_value());
    REQUIRE(got->has_value());
    CHECK((*got)->status == CertStatus::Revoked);
    CHECK((*got)->revocation_reason == "key compromise");
    CHECK((*got)->revoked_at > 0);

    auto revoked = store.list_revoked();
    REQUIRE(revoked.has_value());
    REQUIRE(revoked->size() == 1);
    CHECK((*revoked)[0].serial_hex == "DEAD");
}

// PR3 governance regression net: exercise the EXACT chain the server's is_peer_cert_revoked()
// uses against a REAL issued leaf — issue → parse_certificate to recover the serial →
// record_issued → revoke → is_revoked(parsed serial). Also pins the serial-format round-trip
// (sign side and parse side both BN_bn2hex → identical).
TEST_CASE("CaStore: revocation round-trip against a real issued leaf",
          "[ca_store][pg][pki][security]") {
    using namespace yuzu::server::pki;

    auto ca_key = generate_private_key(KeyAlgo::EcP384);
    REQUIRE(ca_key);
    CaParams cp;
    cp.subject = {"Yuzu Test CA", "Yuzu"};
    cp.validity = validity_years_from_now(10);
    auto ca_cert = self_sign_ca(*ca_key, cp);
    REQUIRE(ca_cert);

    auto leaf_key = generate_private_key(KeyAlgo::EcP256);
    REQUIRE(leaf_key);
    CsrParams csrp;
    csrp.subject = {"agent-rt", "Yuzu"};
    auto csr = make_csr(*leaf_key, csrp);
    REQUIRE(csr);
    LeafParams lp;
    lp.subject = {"agent-rt", "Yuzu"};
    lp.validity = validity_days_from_now(365);
    lp.usage.client_auth = true;
    auto issued = sign_csr(*csr, *ca_cert, *ca_key, lp);
    REQUIRE(issued);

    auto parsed = parse_certificate(issued->cert_pem);
    REQUIRE(parsed);
    REQUIRE(parsed->serial_hex == issued->serial_hex);

    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    REQUIRE(store.is_open());

    IssuedCertRecord rec;
    rec.serial_hex = issued->serial_hex;
    rec.subject = "agent-rt";
    rec.purpose = "agent";
    rec.not_after = now_s() + 365 * 86400;
    rec.cert_pem = issued->cert_pem;
    REQUIRE(store.record_issued(rec).has_value());

    REQUIRE_FALSE(store.is_revoked(parsed->serial_hex));
    REQUIRE(store.revoke(issued->serial_hex, "compromised").value_or(false));
    REQUIRE(store.is_revoked(parsed->serial_hex));
    CHECK_FALSE(store.revoke(issued->serial_hex, "again").value_or(true));
}

// ── Serial normalisation (pure function, unchanged by the migration) ────────

TEST_CASE("CaStore: normalize_serial_hex canonicalises + fails closed", "[ca_store][serial]") {
    REQUIRE(normalize_serial_hex("ab:cd:ef") == "ABCDEF");
    REQUIRE(normalize_serial_hex("ABCDEF") == "ABCDEF");
    REQUIRE(normalize_serial_hex(" aa bb\t") == "AABB");
    REQUIRE(normalize_serial_hex("00ab") == "AB");
    REQUIRE(normalize_serial_hex("0A") == "A");
    REQUIRE(normalize_serial_hex("0000") == "0");
    REQUIRE(normalize_serial_hex("0") == "0");
    REQUIRE_FALSE(normalize_serial_hex(""));
    REQUIRE_FALSE(normalize_serial_hex(":::"));
    REQUIRE_FALSE(normalize_serial_hex("12xy"));
    REQUIRE_FALSE(normalize_serial_hex("-1"));
    REQUIRE_FALSE(normalize_serial_hex(std::string(300, 'a')));
}

TEST_CASE("CaStore: revoke/is_revoked match across case + colon variance",
          "[ca_store][pg][serial][revoke][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    REQUIRE(store.record_issued(sample_issued("ABCD12")).has_value());
    REQUIRE(store.revoke("ab:cd:12", "operator typed colons + lowercase").value_or(false));
    REQUIRE(store.is_revoked("ABCD12"));
    REQUIRE(store.is_revoked("abcd12"));
    REQUIRE(store.is_revoked("AB:CD:12"));
    REQUIRE(store.is_revoked("00ABCD12"));
    CHECK_FALSE(store.revoke("ABCD12", "again").value_or(true));
}

TEST_CASE("CaStore: record_issued normalises + is_revoked fails closed on non-hex",
          "[ca_store][pg][serial][negative][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    REQUIRE(store.record_issued(sample_issued("aa:bb")).has_value());
    REQUIRE(store.get_issued("AABB")->has_value());
    REQUIRE(store.get_issued("aa:bb")->has_value());
    REQUIRE_FALSE(store.record_issued(sample_issued("zz-not-hex")).has_value());
    // is_revoked treats an un-normalisable serial as revoked (reject), not "clean".
    REQUIRE(store.is_revoked("not-a-serial"));
}

TEST_CASE("CaStore: issuer_fingerprint provenance round-trips (issued + CRL)",
          "[ca_store][pg][provenance]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    auto rec = sample_issued("FACE01");
    rec.issuer_fingerprint = "AA:BB:CC:DD";
    REQUIRE(store.record_issued(rec).has_value());
    auto got = store.get_issued("FACE01");
    REQUIRE(got.has_value());
    REQUIRE(got->has_value());
    CHECK((*got)->issuer_fingerprint == "AA:BB:CC:DD");

    CrlVersionRecord crl;
    crl.version = 1;
    crl.der = {0x30, 0x00};
    crl.this_update = now_s();
    crl.next_update = now_s() + 86400;
    crl.issuer_fingerprint = "AA:BB:CC:DD";
    REQUIRE(store.record_crl(crl));
    auto latest = store.latest_crl();
    REQUIRE(latest);
    CHECK(latest->issuer_fingerprint == "AA:BB:CC:DD");
}

TEST_CASE("CaStore: issuer_key_id round-trips and list_issued_by_key_id filters (#1296)",
          "[ca_store][pg][provenance][pki]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    const std::string kid_a = "AA:AA:AA:AA";
    const std::string kid_b = "BB:BB:BB:BB";

    auto mk = [&](const std::string& serial, const std::string& kid) {
        auto r = sample_issued(serial);
        r.issuer_key_id = kid;
        return r;
    };
    REQUIRE(store.record_issued(mk("A1", kid_a)).has_value());
    REQUIRE(store.record_issued(mk("A2", kid_a)).has_value());
    REQUIRE(store.record_issued(mk("B1", kid_b)).has_value());
    REQUIRE(store.record_issued(sample_issued("C1")).has_value()); // empty issuer_key_id

    auto got = store.get_issued("A1");
    REQUIRE(got.has_value());
    REQUIRE(got->has_value());
    CHECK((*got)->issuer_key_id == kid_a);

    auto a = store.list_issued_by_key_id(kid_a);
    REQUIRE(a.has_value());
    REQUIRE(a->size() == 2);
    for (const auto& r : *a)
        CHECK(r.issuer_key_id == kid_a);
    auto b = store.list_issued_by_key_id(kid_b);
    REQUIRE(b.has_value());
    CHECK(b->size() == 1);

    // The empty key id is the unpopulated-row sentinel, NOT a CA identity.
    auto blank = store.list_issued_by_key_id("");
    REQUIRE(blank.has_value());
    CHECK(blank->empty());

    CrlVersionRecord crl;
    crl.version = 1;
    crl.der = {0x30, 0x00};
    crl.this_update = now_s();
    crl.next_update = now_s() + 86400;
    crl.issuer_key_id = kid_a;
    REQUIRE(store.record_crl(crl));
    auto latest = store.latest_crl();
    REQUIRE(latest);
    CHECK(latest->issuer_key_id == kid_a);
}

TEST_CASE("CaStore: list_revoked surfaces a revoked agent cert by BARE agent_id (re-issue guard)",
          "[ca_store][pg][revoke][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    const std::string agent_id = "agent-7f3c";
    const std::string other_id = "agent-other";

    auto mk = [&](const std::string& serial, const std::string& subject) {
        IssuedCertRecord r;
        r.serial_hex = serial;
        r.subject = subject;
        r.purpose = "agent";
        r.not_after = now_s() + 365 * 86400;
        r.issued_at = now_s();
        return r;
    };
    REQUIRE(store.record_issued(mk("A1", agent_id)).has_value());
    REQUIRE(store.record_issued(mk("B2", other_id)).has_value());
    REQUIRE(store.revoke("A1", "compromised").value_or(false));

    auto revoked = store.list_revoked();
    REQUIRE(revoked.has_value());
    REQUIRE(revoked->size() == 1);
    CHECK(revoked->front().subject == agent_id);
    CHECK(revoked->front().not_after > now_s());
    CHECK(revoked->front().subject != other_id);
}

TEST_CASE("CaStore: list_revoked_serials matches list_revoked's serial set exactly "
          "(Gate 8 fix, 2026-08-21)",
          "[ca_store][pg][revoke][security]") {
    // Gate 8 (unhappy-path): the revocation-sweep tick now reads this cheaper,
    // serials-only variant instead of the full list_revoked() (cert_pem blobs +
    // ORDER BY) — same WHERE clause, same partial index, must return the SAME
    // set of serials or the sweep silently diverges from CRL construction.
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};

    auto mk = [&](const std::string& serial) {
        IssuedCertRecord r;
        r.serial_hex = serial;
        r.subject = "agent-" + serial;
        r.purpose = "agent";
        r.not_after = now_s() + 365 * 86400;
        r.issued_at = now_s();
        return r;
    };
    REQUIRE(store.record_issued(mk("A1")).has_value());
    REQUIRE(store.record_issued(mk("B2")).has_value());
    REQUIRE(store.record_issued(mk("C3")).has_value());
    REQUIRE(store.revoke("A1", "compromised").value_or(false));
    REQUIRE(store.revoke("C3", "key_loss").value_or(false));

    auto serials = store.list_revoked_serials();
    REQUIRE(serials.has_value());
    std::set<std::string> got(serials->begin(), serials->end());
    CHECK(got == std::set<std::string>{"A1", "C3"});

    auto full = store.list_revoked();
    REQUIRE(full.has_value());
    std::set<std::string> from_full;
    for (const auto& rec : *full)
        from_full.insert(rec.serial_hex);
    CHECK(got == from_full);
}

TEST_CASE("CaStore: list_revoked_serials reports a genuine store failure as unexpected, "
          "never as an empty (nobody-revoked) set (Gate 8 fix, 2026-08-21)",
          "[ca_store][pg][revoke][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    IssuedCertRecord r;
    r.serial_hex = "DEAD";
    r.subject = "agent-x";
    r.purpose = "agent";
    r.not_after = now_s() + 365 * 86400;
    REQUIRE(store.record_issued(r).has_value());
    REQUIRE(store.revoke("DEAD", "compromised").value_or(false));

    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult d{PQexec(conn.get(), "DROP TABLE ca_store.ca_issued CASCADE")};
        REQUIRE(d.status() == PGRES_COMMAND_OK);
    }

    auto serials = store.list_revoked_serials();
    CHECK_FALSE(serials.has_value());
    CHECK(serials.error().starts_with(kCaDbErrorPrefix));
}

// ── CRL versions ─────────────────────────────────────────────────────────

TEST_CASE("CaStore: CRL numbering and roundtrip", "[ca_store][pg][crl]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};

    auto n1 = store.next_crl_number();
    REQUIRE(n1.has_value());
    CHECK(*n1 == 1);
    REQUIRE_FALSE(store.latest_crl());

    CrlVersionRecord v1;
    v1.version = 1;
    v1.der = {0x30, 0x82, 0x01, 0x02};
    v1.this_update = now_s();
    v1.next_update = now_s() + 7 * 86400;
    REQUIRE(store.record_crl(v1));

    auto n2 = store.next_crl_number();
    REQUIRE(n2.has_value());
    CHECK(*n2 == 2);
    auto latest = store.latest_crl();
    REQUIRE(latest);
    CHECK(latest->version == 1);
    CHECK(latest->der == v1.der);

    CrlVersionRecord v2 = v1;
    v2.version = 2;
    v2.der = {0x30, 0x82, 0x02, 0x05};
    REQUIRE(store.record_crl(v2));
    auto latest2 = store.latest_crl();
    REQUIRE(latest2);
    CHECK(latest2->version == 2);
    CHECK(latest2->der == v2.der);
}

TEST_CASE("CaStore: publish_next_crl allocates monotonic numbers atomically", "[ca_store][pg][crl]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    REQUIRE(store.record_issued(sample_issued("DEAD")).has_value());
    REQUIRE(store.revoke("DEAD", "x").value_or(false));

    uint64_t seen_number = 0;
    std::size_t seen_revoked = 0;
    auto build = [&](uint64_t n, const std::vector<IssuedCertRecord>& revoked) {
        seen_number = n;
        seen_revoked = revoked.size();
        const std::string s = "CRL#" + std::to_string(n);
        return std::vector<uint8_t>(s.begin(), s.end());
    };

    auto v1 = store.publish_next_crl(build, now_s(), now_s() + 7 * 86400, "FP1");
    REQUIRE(v1);
    CHECK(v1->version == 1);
    CHECK(seen_number == 1);
    CHECK(seen_revoked == 1); // build saw the revoked DEAD cert
    CHECK(v1->issuer_fingerprint == "FP1");

    auto v2 = store.publish_next_crl(build, now_s(), now_s() + 7 * 86400, "FP1");
    REQUIRE(v2);
    CHECK(v2->version == 2);
    CHECK(seen_number == 2);
    CHECK(store.next_crl_number().value() == 3);

    auto latest = store.latest_crl();
    REQUIRE(latest);
    CHECK(latest->version == 2);

    // A build that aborts (empty DER) inserts nothing and does NOT consume a number.
    auto none = store.publish_next_crl(
        [](uint64_t, const std::vector<IssuedCertRecord>&) { return std::vector<uint8_t>{}; },
        now_s(), now_s() + 7 * 86400);
    REQUIRE_FALSE(none);
    CHECK(store.next_crl_number().value() == 3);
}

TEST_CASE("CaStore: record_crl rejects version < 1 and silent-clobber duplicates",
          "[ca_store][pg][crl][negative]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    CrlVersionRecord r;
    r.version = 0;
    r.der = {0x30, 0x00};
    r.this_update = now_s();
    r.next_update = now_s() + 86400;
    REQUIRE_FALSE(store.record_crl(r));
    r.version = 1;
    REQUIRE(store.record_crl(r));
    r.der = {0x30, 0x01}; // a different CRL claiming the same number
    REQUIRE_FALSE(store.record_crl(r));
    auto latest = store.latest_crl();
    REQUIRE(latest);
    CHECK(latest->der == std::vector<uint8_t>{0x30, 0x00}); // original preserved
}
