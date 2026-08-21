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
 *  - migrate_from_sqlite backfill contract (ADR-0009/0053): sourceless, half-schema fail-closed,
 *    ca_root IDENTITY-mismatch fail-closed, ca_issued IDENTITY-mismatch fail-closed, ca_issued
 *    LIFECYCLE (legacy-ahead fails closed / never un-revoke; Postgres-ahead is a benign no-op),
 *    unrecognised status fail-closed before ever reaching Postgres, ca_crl_versions fork
 *    fail-closed, ca_crl_versions identical-DER benign no-op, a full happy-path backfill,
 *    fingerprint-marker idempotent re-run.
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
#include "sqlite_raii.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>
#include <sqlite3.h>

#include <chrono>
#include <cstdint>
#include <filesystem>
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

// ── Legacy SQLite fixture writer (v5 schema — matches the pre-migration CaStore exactly) ────

struct LegacyRootFixture {
    std::string cert_pem{"-----BEGIN CERTIFICATE-----\nLEGACY-ROOT\n-----END CERTIFICATE-----\n"};
    std::string key_ref{"/etc/yuzu/certs/ca.key"};
    std::string algo{"EcP384"};
    int64_t not_before{0};
    int64_t not_after{0};
    std::string fingerprint_sha256{"LEGACY:FP"};
    std::string mode{"builtin"};
    int64_t created_at{0};
    std::string chain_pem;
};

struct LegacyIssuedFixture {
    std::string serial_hex;
    std::string subject{"agent-legacy"};
    std::string san;
    std::string purpose{"agent"};
    int64_t not_after{0};
    std::string status{"active"};
    std::string revocation_reason;
    int64_t revoked_at{0};
    int64_t issued_at{0};
    std::string issued_by;
    std::string enrollment_request_id;
    std::string cert_pem;
    std::string issuer_fingerprint;
    std::string issuer_key_id;
};

struct LegacyCrlFixture {
    int64_t version{1};
    std::vector<uint8_t> der{0x30, 0x00};
    int64_t this_update{0};
    int64_t next_update{0};
    int64_t published_at{0};
    std::string issuer_fingerprint;
    std::string issuer_key_id;
};

void write_legacy_sqlite_db(const std::filesystem::path& path,
                            const std::optional<LegacyRootFixture>& root,
                            const std::vector<LegacyIssuedFixture>& issued,
                            const std::vector<LegacyCrlFixture>& crls,
                            bool with_root_table = true, bool with_issued_table = true,
                            bool with_crl_table = true) {
    SqliteDb db;
    REQUIRE(sqlite3_open(path.string().c_str(), db.addr()) == SQLITE_OK);

    if (with_root_table) {
        const char* ddl =
            "CREATE TABLE ca_root (id INTEGER PRIMARY KEY CHECK (id=1), cert_pem TEXT NOT NULL, "
            "key_ref TEXT NOT NULL, algo TEXT NOT NULL, not_before INTEGER NOT NULL, "
            "not_after INTEGER NOT NULL, fingerprint_sha256 TEXT NOT NULL, "
            "mode TEXT NOT NULL DEFAULT 'builtin', created_at INTEGER NOT NULL, "
            "chain_pem TEXT NOT NULL DEFAULT '');";
        REQUIRE(sqlite3_exec(db.get(), ddl, nullptr, nullptr, nullptr) == SQLITE_OK);
        if (root) {
            SqliteStmt s;
            const char* isql =
                "INSERT INTO ca_root (id, cert_pem, key_ref, algo, not_before, not_after, "
                "fingerprint_sha256, mode, created_at, chain_pem) VALUES (1,?,?,?,?,?,?,?,?,?);";
            REQUIRE(sqlite3_prepare_v2(db.get(), isql, -1, s.addr(), nullptr) == SQLITE_OK);
            sqlite3_bind_text(s.get(), 1, root->cert_pem.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(s.get(), 2, root->key_ref.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(s.get(), 3, root->algo.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(s.get(), 4, root->not_before);
            sqlite3_bind_int64(s.get(), 5, root->not_after);
            sqlite3_bind_text(s.get(), 6, root->fingerprint_sha256.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(s.get(), 7, root->mode.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(s.get(), 8, root->created_at ? root->created_at : now_s());
            sqlite3_bind_text(s.get(), 9, root->chain_pem.c_str(), -1, SQLITE_TRANSIENT);
            REQUIRE(sqlite3_step(s.get()) == SQLITE_DONE);
        }
    }

    if (with_issued_table) {
        const char* ddl =
            "CREATE TABLE ca_issued (serial_hex TEXT PRIMARY KEY, subject TEXT NOT NULL, "
            "san TEXT NOT NULL DEFAULT '', purpose TEXT NOT NULL DEFAULT '', "
            "not_after INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'active', "
            "revocation_reason TEXT NOT NULL DEFAULT '', revoked_at INTEGER NOT NULL DEFAULT 0, "
            "issued_at INTEGER NOT NULL, issued_by TEXT NOT NULL DEFAULT '', "
            "enrollment_request_id TEXT NOT NULL DEFAULT '', cert_pem TEXT NOT NULL DEFAULT '', "
            "issuer_fingerprint TEXT NOT NULL DEFAULT '', issuer_key_id TEXT NOT NULL DEFAULT '');";
        REQUIRE(sqlite3_exec(db.get(), ddl, nullptr, nullptr, nullptr) == SQLITE_OK);
        for (const auto& i : issued) {
            SqliteStmt s;
            const char* isql =
                "INSERT INTO ca_issued (serial_hex, subject, san, purpose, not_after, status, "
                "revocation_reason, revoked_at, issued_at, issued_by, enrollment_request_id, "
                "cert_pem, issuer_fingerprint, issuer_key_id) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?);";
            REQUIRE(sqlite3_prepare_v2(db.get(), isql, -1, s.addr(), nullptr) == SQLITE_OK);
            sqlite3_bind_text(s.get(), 1, i.serial_hex.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(s.get(), 2, i.subject.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(s.get(), 3, i.san.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(s.get(), 4, i.purpose.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(s.get(), 5, i.not_after);
            sqlite3_bind_text(s.get(), 6, i.status.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(s.get(), 7, i.revocation_reason.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(s.get(), 8, i.revoked_at);
            sqlite3_bind_int64(s.get(), 9, i.issued_at ? i.issued_at : now_s());
            sqlite3_bind_text(s.get(), 10, i.issued_by.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(s.get(), 11, i.enrollment_request_id.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(s.get(), 12, i.cert_pem.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(s.get(), 13, i.issuer_fingerprint.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(s.get(), 14, i.issuer_key_id.c_str(), -1, SQLITE_TRANSIENT);
            REQUIRE(sqlite3_step(s.get()) == SQLITE_DONE);
        }
    }

    if (with_crl_table) {
        const char* ddl =
            "CREATE TABLE ca_crl_versions (version INTEGER PRIMARY KEY, der BLOB NOT NULL, "
            "this_update INTEGER NOT NULL, next_update INTEGER NOT NULL, "
            "published_at INTEGER NOT NULL, issuer_fingerprint TEXT NOT NULL DEFAULT '', "
            "issuer_key_id TEXT NOT NULL DEFAULT '');";
        REQUIRE(sqlite3_exec(db.get(), ddl, nullptr, nullptr, nullptr) == SQLITE_OK);
        for (const auto& c : crls) {
            SqliteStmt s;
            const char* isql =
                "INSERT INTO ca_crl_versions (version, der, this_update, next_update, "
                "published_at, issuer_fingerprint, issuer_key_id) VALUES (?,?,?,?,?,?,?);";
            REQUIRE(sqlite3_prepare_v2(db.get(), isql, -1, s.addr(), nullptr) == SQLITE_OK);
            sqlite3_bind_int64(s.get(), 1, c.version);
            sqlite3_bind_blob(s.get(), 2, c.der.data(), static_cast<int>(c.der.size()),
                              SQLITE_TRANSIENT);
            sqlite3_bind_int64(s.get(), 3, c.this_update);
            sqlite3_bind_int64(s.get(), 4, c.next_update);
            sqlite3_bind_int64(s.get(), 5, c.published_at ? c.published_at : now_s());
            sqlite3_bind_text(s.get(), 6, c.issuer_fingerprint.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(s.get(), 7, c.issuer_key_id.c_str(), -1, SQLITE_TRANSIENT);
            REQUIRE(sqlite3_step(s.get()) == SQLITE_DONE);
        }
    }
}

} // namespace

// ── Construction fail-closed ────────────────────────────────────────────────

TEST_CASE("CaStore reports !is_open on a migration failure", "[ca_store][pg]") {
    YUZU_REQUIRE_PG_DB(db);
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

// ── Backfill (ADR-0009/0053) ────────────────────────────────────────────────

TEST_CASE("CaStore::migrate_from_sqlite — no legacy file is a no-op success",
          "[ca_store][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    REQUIRE(store.is_open());
    auto legacy = yuzu::test::unique_temp_path("yuzu_test_ca_store_missing_");
    REQUIRE(store.migrate_from_sqlite(legacy));
    REQUIRE_FALSE(store.has_root());
}

TEST_CASE("CaStore::migrate_from_sqlite — half-schema legacy file fails closed",
          "[ca_store][pg][backfill][negative]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    REQUIRE(store.is_open());

    yuzu::test::TempDbFile legacy{"yuzu_test_ca_store_half_"};
    // Only ca_issued present — the shipped pre-migration binary always creates all three
    // together, so this shape is never a real fresh-install/upgrade artifact.
    write_legacy_sqlite_db(legacy.path, std::nullopt, {LegacyIssuedFixture{.serial_hex = "AA"}},
                           {}, /*with_root_table=*/false, /*with_issued_table=*/true,
                           /*with_crl_table=*/false);
    REQUIRE_FALSE(store.migrate_from_sqlite(legacy.path));
}

TEST_CASE("CaStore::migrate_from_sqlite — full happy-path backfill + idempotent re-run",
          "[ca_store][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    REQUIRE(store.is_open());

    yuzu::test::TempDbFile legacy{"yuzu_test_ca_store_happy_"};
    LegacyRootFixture root;
    root.fingerprint_sha256 = "LEGACY:ROOT:FP";
    LegacyIssuedFixture active;
    active.serial_hex = "ACE001";
    active.status = "active";
    LegacyIssuedFixture revoked;
    revoked.serial_hex = "DEAD01";
    revoked.status = "revoked";
    revoked.revocation_reason = "compromised";
    revoked.revoked_at = now_s();
    LegacyCrlFixture crl;
    crl.version = 1;
    crl.der = {0x30, 0x01, 0x02};
    write_legacy_sqlite_db(legacy.path, root, {active, revoked}, {crl});

    REQUIRE(store.migrate_from_sqlite(legacy.path));

    auto got_root = store.get_root();
    REQUIRE(got_root.has_value());
    REQUIRE(got_root->has_value());
    CHECK((*got_root)->fingerprint_sha256 == "LEGACY:ROOT:FP");

    auto got_active = store.get_issued("ACE001");
    REQUIRE(got_active.has_value());
    REQUIRE(got_active->has_value());
    CHECK((*got_active)->status == CertStatus::Active);

    auto got_revoked = store.get_issued("DEAD01");
    REQUIRE(got_revoked.has_value());
    REQUIRE(got_revoked->has_value());
    CHECK((*got_revoked)->status == CertStatus::Revoked);
    CHECK((*got_revoked)->revocation_reason == "compromised");

    auto latest = store.latest_crl();
    REQUIRE(latest);
    CHECK(latest->version == 1);
    CHECK(latest->der == crl.der);

    // Idempotent re-run: same fingerprint already processed → success no-op, no error, state
    // unchanged.
    REQUIRE(store.migrate_from_sqlite(legacy.path));
    auto still_active = store.get_issued("ACE001");
    REQUIRE(still_active.has_value());
    REQUIRE(still_active->has_value());

    // next_crl_number resumes ABOVE the backfilled max — never regresses to 1 (ADR-0053 "CRL
    // version continuity").
    CHECK(store.next_crl_number().value() == 2);
}

TEST_CASE("CaStore::migrate_from_sqlite — ca_root IDENTITY mismatch fails closed",
          "[ca_store][pg][backfill][negative][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    REQUIRE(store.is_open());

    // A DIFFERENT root is already established in Postgres (e.g. this-boot's first-boot
    // generation already won the try_insert_root race).
    REQUIRE(store.set_root(sample_root("ALREADY:HERE")).has_value());

    yuzu::test::TempDbFile legacy{"yuzu_test_ca_store_rootmismatch_"};
    LegacyRootFixture legacy_root;
    legacy_root.fingerprint_sha256 = "DIFFERENT:ROOT";
    write_legacy_sqlite_db(legacy.path, legacy_root, {}, {});

    REQUIRE_FALSE(store.migrate_from_sqlite(legacy.path));
    // The already-established root is untouched — never silently discarded/overwritten.
    auto got = store.get_root();
    REQUIRE(got.has_value());
    REQUIRE(got->has_value());
    CHECK((*got)->fingerprint_sha256 == "ALREADY:HERE");
}

TEST_CASE("CaStore::migrate_from_sqlite — legacy-revoked/Postgres-active fails closed "
          "(never un-revoke)",
          "[ca_store][pg][backfill][negative][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    REQUIRE(store.is_open());

    // Postgres already has this serial as active (e.g. re-issued after a fresh boot, or the
    // legacy snapshot predates a real revocation the pre-migration binary later performed).
    REQUIRE(store.record_issued(sample_issued("5AED01")).has_value());

    yuzu::test::TempDbFile legacy{"yuzu_test_ca_store_unrevoke_"};
    LegacyIssuedFixture rev;
    rev.serial_hex = "5AED01";
    rev.subject = "CN=agent-5AED01"; // must match the IDENTITY columns sample_issued() wrote
    rev.san = "URI:yuzu://inst/agent/5AED01";
    rev.not_after = now_s() + 86400;
    rev.issued_at = now_s();
    rev.status = "revoked";
    rev.revocation_reason = "compromised";
    rev.revoked_at = now_s();
    write_legacy_sqlite_db(legacy.path, std::nullopt, {rev}, {});

    REQUIRE_FALSE(store.migrate_from_sqlite(legacy.path));
    // Kept as-is (this is the STALE/CONTRADICTED side, per the fail-closed contract) — but
    // CRUCIALLY it was never silently flipped, and the backfill was refused loudly instead.
    auto got = store.get_issued("5AED01");
    REQUIRE(got.has_value());
    REQUIRE(got->has_value());
}

TEST_CASE("CaStore::migrate_from_sqlite — Postgres-revoked/legacy-active is a benign no-op",
          "[ca_store][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    REQUIRE(store.is_open());

    // Postgres already progressed past this legacy snapshot: the cert was revoked AFTER the
    // legacy file was captured (or by a concurrent live operator action).
    REQUIRE(store.record_issued(sample_issued("5AED02")).has_value());
    REQUIRE(store.revoke("5AED02", "live revoke").value_or(false));

    yuzu::test::TempDbFile legacy{"yuzu_test_ca_store_stale_legacy_"};
    LegacyIssuedFixture still_active;
    still_active.serial_hex = "5AED02";
    still_active.subject = "CN=agent-5AED02";
    still_active.san = "URI:yuzu://inst/agent/5AED02";
    still_active.not_after = now_s() + 86400;
    still_active.issued_at = now_s();
    still_active.status = "active"; // predates the live revoke
    write_legacy_sqlite_db(legacy.path, std::nullopt, {still_active}, {});

    REQUIRE(store.migrate_from_sqlite(legacy.path)); // benign no-op, NOT a failure
    // Postgres's revoked state is KEPT — never un-revoked by a stale legacy snapshot.
    auto got = store.get_issued("5AED02");
    REQUIRE(got.has_value());
    REQUIRE(got->has_value());
    CHECK((*got)->status == CertStatus::Revoked);
}

TEST_CASE("CaStore::migrate_from_sqlite — unrecognised status fails closed before reaching "
          "Postgres",
          "[ca_store][pg][backfill][negative]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    REQUIRE(store.is_open());

    yuzu::test::TempDbFile legacy{"yuzu_test_ca_store_badstatus_"};
    LegacyIssuedFixture bad;
    bad.serial_hex = "BAD1";
    bad.status = "pending-hand-edited-nonsense";
    write_legacy_sqlite_db(legacy.path, std::nullopt, {bad}, {});

    REQUIRE_FALSE(store.migrate_from_sqlite(legacy.path));
    auto got = store.get_issued("BAD1");
    REQUIRE(got.has_value());
    REQUIRE_FALSE(got->has_value()); // never reached Postgres
}

TEST_CASE("CaStore::migrate_from_sqlite — a CRL version fork (same version, different DER) "
          "fails closed",
          "[ca_store][pg][backfill][negative][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    REQUIRE(store.is_open());

    CrlVersionRecord existing;
    existing.version = 1;
    existing.der = {0x30, 0x00};
    existing.this_update = now_s();
    existing.next_update = now_s() + 86400;
    REQUIRE(store.record_crl(existing));

    yuzu::test::TempDbFile legacy{"yuzu_test_ca_store_crlfork_"};
    LegacyCrlFixture forked;
    forked.version = 1;
    forked.der = {0x30, 0xFF}; // DIFFERENT DER, same crlNumber — a fork
    write_legacy_sqlite_db(legacy.path, std::nullopt, {}, {forked});

    REQUIRE_FALSE(store.migrate_from_sqlite(legacy.path));
    // The original, already-recorded CRL is untouched — never silently picked/clobbered.
    auto latest = store.latest_crl();
    REQUIRE(latest);
    CHECK(latest->der == existing.der);
}

TEST_CASE("CaStore::migrate_from_sqlite — identical CRL DER at the same version is a benign "
          "no-op",
          "[ca_store][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    REQUIRE(store.is_open());

    CrlVersionRecord existing;
    existing.version = 1;
    existing.der = {0x30, 0x00};
    existing.this_update = now_s();
    existing.next_update = now_s() + 86400;
    REQUIRE(store.record_crl(existing));

    yuzu::test::TempDbFile legacy{"yuzu_test_ca_store_crlsame_"};
    LegacyCrlFixture same;
    same.version = 1;
    same.der = {0x30, 0x00}; // byte-identical
    write_legacy_sqlite_db(legacy.path, std::nullopt, {}, {same});

    REQUIRE(store.migrate_from_sqlite(legacy.path));
    auto latest = store.latest_crl();
    REQUIRE(latest);
    CHECK(latest->der == existing.der);
}
