/**
 * test_ca_store.cpp — Unit tests for CaStore (ca.db), PR1.
 *
 * Covers: open + migration, single-row root set/get/replace, issued-cert
 * record/get/list, revoke (idempotent, RETURNING-based change detection),
 * is_revoked, list_revoked, CRL numbering + record/latest roundtrip.
 */

#include "ca_store.hpp"

#include <catch2/catch_test_macros.hpp>

#include "../test_helpers.hpp"

#include <chrono>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

using namespace yuzu::server;

// CaStore owns a sqlite handle; it must be non-copyable (and non-movable) so the
// handle can never be double-closed.
static_assert(!std::is_copy_constructible_v<CaStore>);
static_assert(!std::is_copy_assignable_v<CaStore>);

namespace {

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

} // namespace

TEST_CASE("CaStore: opens and migrates", "[ca_store][db]") {
    yuzu::test::TempDbFile db{std::string_view{"ca-store-"}};
    CaStore store(db.path);
    REQUIRE(store.is_open());
    REQUIRE_FALSE(store.has_root());
}

TEST_CASE("CaStore: root set/get/replace", "[ca_store][root]") {
    yuzu::test::TempDbFile db{std::string_view{"ca-store-"}};
    CaStore store(db.path);
    REQUIRE(store.is_open());

    CaRoot root;
    root.cert_pem = "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n";
    root.key_ref = "/etc/yuzu/certs/ca.key";
    root.algo = "EcP384";
    root.not_before = now_s();
    root.not_after = now_s() + 10L * 31557600L;
    root.fingerprint_sha256 = "AB:CD:EF";
    root.mode = CaMode::Builtin;
    REQUIRE(store.set_root(root));
    REQUIRE(store.has_root());

    auto got = store.get_root();
    REQUIRE(got);
    REQUIRE(got->cert_pem == root.cert_pem);
    REQUIRE(got->key_ref == root.key_ref);
    REQUIRE(got->algo == "EcP384");
    REQUIRE(got->fingerprint_sha256 == "AB:CD:EF");
    REQUIRE(got->mode == CaMode::Builtin);

    // Replace (e.g. subordinate-CA import later): single row, latest wins.
    CaRoot root2 = root;
    root2.fingerprint_sha256 = "99:88:77";
    root2.mode = CaMode::Subordinate;
    REQUIRE(store.set_root(root2));
    auto got2 = store.get_root();
    REQUIRE(got2);
    REQUIRE(got2->fingerprint_sha256 == "99:88:77");
    REQUIRE(got2->mode == CaMode::Subordinate);
}

TEST_CASE("CaStore: set_root rejects empty cert/key_ref", "[ca_store][root][negative]") {
    yuzu::test::TempDbFile db{std::string_view{"ca-store-"}};
    CaStore store(db.path);
    CaRoot bad;
    bad.algo = "EcP384";
    REQUIRE_FALSE(store.set_root(bad));
    REQUIRE_FALSE(store.has_root());
}

TEST_CASE("CaStore: issued record/get/list", "[ca_store][issued]") {
    yuzu::test::TempDbFile db{std::string_view{"ca-store-"}};
    CaStore store(db.path);

    REQUIRE(store.record_issued(sample_issued("AA11")));
    REQUIRE(store.record_issued(sample_issued("BB22", "https")));

    auto got = store.get_issued("AA11");
    REQUIRE(got);
    REQUIRE(got->purpose == "agent");
    REQUIRE(got->status == CertStatus::Active);

    REQUIRE_FALSE(store.get_issued("NOPE"));

    auto all = store.list_issued();
    REQUIRE(all.size() == 2);

    // Duplicate serial is rejected (PRIMARY KEY).
    REQUIRE_FALSE(store.record_issued(sample_issued("AA11")));
}

TEST_CASE("CaStore: revoke is idempotent and reflected", "[ca_store][revoke]") {
    yuzu::test::TempDbFile db{std::string_view{"ca-store-"}};
    CaStore store(db.path);
    REQUIRE(store.record_issued(sample_issued("DEAD")));

    REQUIRE_FALSE(store.is_revoked("DEAD"));
    REQUIRE(store.revoke("DEAD", "key compromise")); // first revoke changes a row
    REQUIRE_FALSE(store.revoke("DEAD", "again"));     // idempotent: no change
    REQUIRE_FALSE(store.revoke("UNKNOWN", "n/a"));    // unknown serial: no change

    REQUIRE(store.is_revoked("DEAD"));
    auto got = store.get_issued("DEAD");
    REQUIRE(got);
    REQUIRE(got->status == CertStatus::Revoked);
    REQUIRE(got->revocation_reason == "key compromise");
    REQUIRE(got->revoked_at > 0);

    auto revoked = store.list_revoked();
    REQUIRE(revoked.size() == 1);
    REQUIRE(revoked[0].serial_hex == "DEAD");
}

TEST_CASE("CaStore: CRL numbering and roundtrip", "[ca_store][crl]") {
    yuzu::test::TempDbFile db{std::string_view{"ca-store-"}};
    CaStore store(db.path);

    REQUIRE(store.next_crl_number() == 1);
    REQUIRE_FALSE(store.latest_crl());

    CrlVersionRecord v1;
    v1.version = 1;
    v1.der = {0x30, 0x82, 0x01, 0x02}; // arbitrary DER-ish bytes
    v1.this_update = now_s();
    v1.next_update = now_s() + 7 * 86400;
    REQUIRE(store.record_crl(v1));

    REQUIRE(store.next_crl_number() == 2);
    auto latest = store.latest_crl();
    REQUIRE(latest);
    REQUIRE(latest->version == 1);
    REQUIRE(latest->der == v1.der);

    CrlVersionRecord v2 = v1;
    v2.version = 2;
    v2.der = {0x30, 0x82, 0x02, 0x05};
    REQUIRE(store.record_crl(v2));
    auto latest2 = store.latest_crl();
    REQUIRE(latest2);
    REQUIRE(latest2->version == 2);
    REQUIRE(latest2->der == v2.der);
}

TEST_CASE("CaStore: record_issued rejects empty serial", "[ca_store][issued][negative]") {
    yuzu::test::TempDbFile db{std::string_view{"ca-store-"}};
    CaStore store(db.path);
    REQUIRE_FALSE(store.record_issued(sample_issued("")));
}

TEST_CASE("CaStore: issued provenance columns round-trip", "[ca_store][issued]") {
    yuzu::test::TempDbFile db{std::string_view{"ca-store-"}};
    CaStore store(db.path);
    auto rec = sample_issued("CAFE");
    rec.issued_by = "operator:alice";
    rec.enrollment_request_id = "enr-123";
    rec.cert_pem = "-----BEGIN CERTIFICATE-----\nXYZ\n-----END CERTIFICATE-----\n";
    REQUIRE(store.record_issued(rec));
    auto got = store.get_issued("CAFE");
    REQUIRE(got);
    REQUIRE(got->issued_by == "operator:alice");
    REQUIRE(got->enrollment_request_id == "enr-123");
    REQUIRE(got->cert_pem == rec.cert_pem);
}

TEST_CASE("CaStore: an unopenable path yields !is_open", "[ca_store][db][negative]") {
    // A directory is not a valid SQLite file — open must fail and is_open() false.
    auto dir = yuzu::test::unique_temp_path("ca-store-dir-");
    std::filesystem::create_directories(dir);
    {
        CaStore store(dir);
        REQUIRE_FALSE(store.is_open());
        REQUIRE_FALSE(store.has_root());
    }
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}
