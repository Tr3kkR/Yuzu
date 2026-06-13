/**
 * test_ca_store.cpp — Unit tests for CaStore (ca.db), PR1.
 *
 * Covers: open + migration, single-row root set/get/replace, issued-cert
 * record/get/list, revoke (idempotent, RETURNING-based change detection),
 * is_revoked, list_revoked, CRL numbering + record/latest roundtrip.
 */

#include "ca_store.hpp"
#include "x509_ca.hpp"

#include <catch2/catch_test_macros.hpp>

#include "../test_helpers.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
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
    REQUIRE(got->chain_pem.empty()); // builtin → no parent chain (PR6)

    // Replace with a subordinate-CA import: single row, latest wins, and the
    // parent chain (enterprise root above our issuing intermediate) round-trips.
    CaRoot root2 = root;
    root2.fingerprint_sha256 = "99:88:77";
    root2.mode = CaMode::Subordinate;
    root2.chain_pem = "-----BEGIN CERTIFICATE-----\nENTERPRISE-ROOT\n-----END CERTIFICATE-----\n";
    REQUIRE(store.set_root(root2));
    auto got2 = store.get_root();
    REQUIRE(got2);
    REQUIRE(got2->fingerprint_sha256 == "99:88:77");
    REQUIRE(got2->mode == CaMode::Subordinate);
    REQUIRE(got2->chain_pem == root2.chain_pem); // PR6 parent chain persisted
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

// PR3 governance (quality-engineer BLOCKING): exercise the EXACT chain the server's
// is_peer_cert_revoked() uses against a REAL issued leaf — issue → parse_certificate
// to recover the serial → record_issued → revoke → is_revoked(parsed serial). This
// is the regression net for revocation enforcement at the Subscribe/Heartbeat gates
// (the private ServerImpl method is thin glue over these primitives). It also pins
// the serial-format round-trip (sign side and parse side both BN_bn2hex → identical).
TEST_CASE("CaStore: revocation round-trip against a real issued leaf", "[ca_store][pki][security]") {
    using namespace yuzu::server::pki;

    // Build a CA + a per-agent client leaf the way sign_agent_csr does.
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

    // The serial recovered from the issued PEM must equal the one returned at
    // issuance (both canonical BN_bn2hex) — otherwise the revocation lookup misses.
    auto parsed = parse_certificate(issued->cert_pem);
    REQUIRE(parsed);
    REQUIRE(parsed->serial_hex == issued->serial_hex);

    yuzu::test::TempDbFile db{std::string_view{"ca-store-rt-"}};
    CaStore store(db.path);
    REQUIRE(store.is_open());

    IssuedCertRecord rec;
    rec.serial_hex = issued->serial_hex;
    rec.subject = "agent-rt";
    rec.purpose = "agent";
    rec.not_after = now_s() + 365 * 86400;
    rec.cert_pem = issued->cert_pem;
    REQUIRE(store.record_issued(rec));

    // Before revocation: the parsed-serial lookup says not-revoked.
    REQUIRE_FALSE(store.is_revoked(parsed->serial_hex));
    // Revoke, then the SAME parsed-serial lookup the server gate performs is true.
    REQUIRE(store.revoke(issued->serial_hex, "compromised"));
    REQUIRE(store.is_revoked(parsed->serial_hex));
    // Idempotent: a second revoke of an already-revoked serial returns false.
    REQUIRE_FALSE(store.revoke(issued->serial_hex, "again"));
}

// ── Serial normalisation (Tr3kkR #1237 review) ──────────────────────────────

TEST_CASE("CaStore: normalize_serial_hex canonicalises + fails closed", "[ca_store][serial]") {
    REQUIRE(normalize_serial_hex("ab:cd:ef") == "ABCDEF"); // lowercase + colons
    REQUIRE(normalize_serial_hex("ABCDEF") == "ABCDEF");    // already canonical
    REQUIRE(normalize_serial_hex(" aa bb\t") == "AABB");    // whitespace stripped
    // Leading zeros stripped → matches BN_bn2hex's value form (so a zero-padded
    // operator serial still resolves to the stored one).
    REQUIRE(normalize_serial_hex("00ab") == "AB");
    REQUIRE(normalize_serial_hex("0A") == "A");
    REQUIRE(normalize_serial_hex("0000") == "0"); // all-zero value → single "0"
    REQUIRE(normalize_serial_hex("0") == "0");
    REQUIRE_FALSE(normalize_serial_hex(""));                  // empty
    REQUIRE_FALSE(normalize_serial_hex(":::"));               // separators only → empty
    REQUIRE_FALSE(normalize_serial_hex("12xy"));              // non-hex
    REQUIRE_FALSE(normalize_serial_hex("-1"));                // sign char is non-hex
    REQUIRE_FALSE(normalize_serial_hex(std::string(300, 'a'))); // length cap
}

TEST_CASE("CaStore: revoke/is_revoked match across case + colon variance",
          "[ca_store][serial][revoke][security]") {
    // The engine stores uppercase, colon-free serials; a PR4 operator/REST serial
    // may arrive lowercase or colon-decorated. Without boundary normalisation that
    // would silently miss the row — a revoked cert that keeps validating.
    yuzu::test::TempDbFile db{std::string_view{"ca-store-"}};
    CaStore store(db.path);
    REQUIRE(store.record_issued(sample_issued("ABCD12"))); // stored canonical
    REQUIRE(store.revoke("ab:cd:12", "operator typed colons + lowercase"));
    REQUIRE(store.is_revoked("ABCD12"));
    REQUIRE(store.is_revoked("abcd12"));
    REQUIRE(store.is_revoked("AB:CD:12"));
    REQUIRE(store.is_revoked("00ABCD12")); // zero-padded form still matches
    REQUIRE_FALSE(store.revoke("ABCD12", "again")); // idempotent across forms
}

TEST_CASE("CaStore: record_issued normalises + is_revoked fails closed on non-hex",
          "[ca_store][serial][negative][security]") {
    yuzu::test::TempDbFile db{std::string_view{"ca-store-"}};
    CaStore store(db.path);
    REQUIRE(store.record_issued(sample_issued("aa:bb"))); // stored as AABB
    REQUIRE(store.get_issued("AABB"));
    REQUIRE(store.get_issued("aa:bb")); // queried in any form
    REQUIRE_FALSE(store.record_issued(sample_issued("zz-not-hex"))); // refused
    // is_revoked treats an un-normalisable serial as revoked (reject), not "clean".
    REQUIRE(store.is_revoked("not-a-serial"));
}

TEST_CASE("CaStore: issuer_fingerprint provenance round-trips (issued + CRL)",
          "[ca_store][provenance]") {
    yuzu::test::TempDbFile db{std::string_view{"ca-store-"}};
    CaStore store(db.path);
    auto rec = sample_issued("FACE01");
    rec.issuer_fingerprint = "AA:BB:CC:DD";
    REQUIRE(store.record_issued(rec));
    auto got = store.get_issued("FACE01");
    REQUIRE(got);
    REQUIRE(got->issuer_fingerprint == "AA:BB:CC:DD");

    CrlVersionRecord crl;
    crl.version = 1;
    crl.der = {0x30, 0x00};
    crl.this_update = now_s();
    crl.next_update = now_s() + 86400;
    crl.issuer_fingerprint = "AA:BB:CC:DD";
    REQUIRE(store.record_crl(crl));
    auto latest = store.latest_crl();
    REQUIRE(latest);
    REQUIRE(latest->issuer_fingerprint == "AA:BB:CC:DD");
}

TEST_CASE("CaStore: issuer_key_id round-trips and list_issued_by_key_id filters (#1296)",
          "[ca_store][provenance][pki]") {
    // The stable key-based CA identity (issuer_key_id) is what an "issued by THIS
    // CA" query keys on — invariant across a subordinate re-key (same key, new
    // issuer cert). Here we model TWO issuer identities (kid_a, kid_b) and assert
    // the filtered query returns exactly the rows minted under each, and that the
    // empty-sentinel returns nothing (an unpopulated row is not a CA identity).
    yuzu::test::TempDbFile db{std::string_view{"ca-store-"}};
    CaStore store(db.path);
    const std::string kid_a = "AA:AA:AA:AA";
    const std::string kid_b = "BB:BB:BB:BB";

    auto mk = [&](const std::string& serial, const std::string& kid) {
        auto r = sample_issued(serial);
        r.issuer_key_id = kid;
        return r;
    };
    REQUIRE(store.record_issued(mk("A1", kid_a)));
    REQUIRE(store.record_issued(mk("A2", kid_a)));
    REQUIRE(store.record_issued(mk("B1", kid_b)));
    REQUIRE(store.record_issued(sample_issued("C1"))); // empty issuer_key_id

    // Field round-trips on the single-row getter.
    auto got = store.get_issued("A1");
    REQUIRE(got);
    REQUIRE(got->issuer_key_id == kid_a);

    // The filter returns exactly the two kid_a rows, not kid_b or the blank one.
    auto a = store.list_issued_by_key_id(kid_a);
    REQUIRE(a.size() == 2);
    for (const auto& r : a)
        REQUIRE(r.issuer_key_id == kid_a);
    REQUIRE(store.list_issued_by_key_id(kid_b).size() == 1);

    // The empty key id is the unpopulated-row sentinel, NOT a CA identity — it must
    // never surface the (single) blank row, or "issued by this CA" would conflate
    // with "we don't know".
    REQUIRE(store.list_issued_by_key_id("").empty());

    // CRL row carries the stable id too.
    CrlVersionRecord crl;
    crl.version = 1;
    crl.der = {0x30, 0x00};
    crl.this_update = now_s();
    crl.next_update = now_s() + 86400;
    crl.issuer_key_id = kid_a;
    REQUIRE(store.record_crl(crl));
    auto latest = store.latest_crl();
    REQUIRE(latest);
    REQUIRE(latest->issuer_key_id == kid_a);
}

TEST_CASE("CaStore: list_revoked surfaces a revoked agent cert by BARE agent_id (re-issue guard)",
          "[ca_store][revoke][security]") {
    // Pins the PR3 HIGH-2 guard contract (#1239): sign_agent_csr refuses to
    // re-issue to an agent_id that has a revoked, non-expired cert by scanning
    // list_revoked() for `rev.subject == agent_id`. CRUCIAL: sign_agent_csr stores
    // the BARE agent_id in ca_issued.subject (server.cpp `rec.subject = agent_id;`),
    // NOT a "CN=..." DN — so the guard's bare-vs-bare comparison matches. This test
    // mirrors that exact storage form (the generic sample_issued helper uses a
    // "CN=agent-..." subject, which would NOT reflect how agent certs are stored).
    yuzu::test::TempDbFile db{std::string_view{"ca-store-"}};
    CaStore store(db.path);
    const std::string agent_id = "agent-7f3c";       // bare, as sign_agent_csr stores
    const std::string other_id = "agent-other";

    auto mk = [&](const std::string& serial, const std::string& subject) {
        IssuedCertRecord r;
        r.serial_hex = serial;
        r.subject = subject; // BARE agent_id for agent certs
        r.purpose = "agent";
        r.not_after = now_s() + 365 * 86400; // non-expired
        r.issued_at = now_s();
        return r;
    };
    REQUIRE(store.record_issued(mk("A1", agent_id)));
    REQUIRE(store.record_issued(mk("B2", other_id))); // different agent, left active
    REQUIRE(store.revoke("A1", "compromised"));

    const auto revoked = store.list_revoked();
    REQUIRE(revoked.size() == 1);
    // The exact predicate the guard evaluates (rev.subject == agent_id) is TRUE
    // for the bare id, and the cert is non-expired → re-issue is blocked.
    REQUIRE(revoked.front().subject == agent_id);
    REQUIRE(revoked.front().not_after > now_s());
    // A different, non-revoked agent_id does NOT match → its re-provision proceeds.
    REQUIRE(revoked.front().subject != other_id);
}

// ── Atomic CRL-number allocation (Tr3kkR #1237 review) ──────────────────────

TEST_CASE("CaStore: publish_next_crl allocates monotonic numbers atomically",
          "[ca_store][crl]") {
    yuzu::test::TempDbFile db{std::string_view{"ca-store-"}};
    CaStore store(db.path);
    REQUIRE(store.record_issued(sample_issued("DEAD")));
    REQUIRE(store.revoke("DEAD", "x"));

    uint64_t seen_number = 0;
    std::size_t seen_revoked = 0;
    auto build = [&](uint64_t n, const std::vector<IssuedCertRecord>& revoked) {
        seen_number = n;
        seen_revoked = revoked.size();
        const std::string s = "CRL#" + std::to_string(n); // pretend-DER carrying n
        return std::vector<uint8_t>(s.begin(), s.end());
    };

    auto v1 = store.publish_next_crl(build, now_s(), now_s() + 7 * 86400, "FP1");
    REQUIRE(v1);
    REQUIRE(v1->version == 1);
    REQUIRE(seen_number == 1);          // built for the allocated number
    REQUIRE(seen_revoked == 1);         // build saw the revoked DEAD cert (lock-safe)
    REQUIRE(v1->issuer_fingerprint == "FP1");

    auto v2 = store.publish_next_crl(build, now_s(), now_s() + 7 * 86400, "FP1");
    REQUIRE(v2);
    REQUIRE(v2->version == 2);          // monotonic
    REQUIRE(seen_number == 2);
    REQUIRE(store.next_crl_number() == 3);

    auto latest = store.latest_crl();
    REQUIRE(latest);
    REQUIRE(latest->version == 2);

    // A build that aborts (empty DER) inserts nothing and does NOT consume a
    // number — the next allocation is still 3.
    auto none = store.publish_next_crl(
        [](uint64_t, const std::vector<IssuedCertRecord>&) { return std::vector<uint8_t>{}; },
        now_s(), now_s() + 7 * 86400);
    REQUIRE_FALSE(none);
    REQUIRE(store.next_crl_number() == 3);
}

TEST_CASE("CaStore: record_crl rejects version < 1 and silent-clobber duplicates",
          "[ca_store][crl][negative]") {
    yuzu::test::TempDbFile db{std::string_view{"ca-store-"}};
    CaStore store(db.path);
    CrlVersionRecord r;
    r.version = 0;
    r.der = {0x30, 0x00};
    r.this_update = now_s();
    r.next_update = now_s() + 86400;
    REQUIRE_FALSE(store.record_crl(r)); // version < 1 rejected
    r.version = 1;
    REQUIRE(store.record_crl(r));
    r.der = {0x30, 0x01};               // a different CRL claiming the same number
    REQUIRE_FALSE(store.record_crl(r)); // duplicate version rejected, not clobbered
    auto latest = store.latest_crl();
    REQUIRE(latest);
    REQUIRE(latest->der == std::vector<uint8_t>{0x30, 0x00}); // original preserved
}
