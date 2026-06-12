// SecretCodec tests (#1320 PR 4, ADR-0010): blob v1 format, canonical AAD
// anti-swap + boundary-shift, fail-closed boot verification
// (kek_unresolvable / kek_corrupt), fresh-DEK-per-encrypt, and the fjarvis
// #1333 rotation reproduction — encrypt → rotate (re-wrap only) → payload
// still decrypts; tampered blob kek_version → wrap tag fails.

#include <catch2/catch_test_macros.hpp>

#include "key_provider.hpp"
#include "pg/pg_raii.hpp"
#include "pg/secret_codec.hpp"

#include "../test_helpers.hpp"

#include <libpq-fe.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

using yuzu::server::FileKeyProvider;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgResult;
using yuzu::server::pg::SecretCodec;

namespace {

struct TempDir {
    std::filesystem::path path;
    TempDir() : path(yuzu::test::unique_temp_path("sc-keys-")) {}
    ~TempDir() {
        std::error_code ec;
        std::filesystem::remove_all(path, ec);
    }
    TempDir(const TempDir&) = delete;
    TempDir& operator=(const TempDir&) = delete;
};

PgConn connect(const std::string& dsn) {
    PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    return conn;
}

std::vector<std::uint8_t> bytes_of(std::string_view s) {
    return {reinterpret_cast<const std::uint8_t*>(s.data()),
            reinterpret_cast<const std::uint8_t*>(s.data()) + s.size()};
}

SecretCodec::SecretId test_id(std::int64_t pk = 42) {
    return {"tstore", "things", "secret", SecretCodec::encode_bigint_pk(pk)};
}

/// The registered test table the rotation scan walks.
void create_test_table(PGconn* conn) {
    PgResult schema{PQexec(conn, "CREATE SCHEMA IF NOT EXISTS tstore")};
    REQUIRE(schema.ok());
    PgResult table{PQexec(conn, "CREATE TABLE IF NOT EXISTS tstore.things ("
                                "  id     BIGINT PRIMARY KEY,"
                                "  secret BYTEA"
                                ")")};
    REQUIRE(table.ok());
}

void upsert_secret(PGconn* conn, std::int64_t pk, std::span<const std::uint8_t> blob) {
    const std::string pk_str = std::to_string(pk);
    const char* values[] = {pk_str.c_str(), reinterpret_cast<const char*>(blob.data())};
    const int lengths[] = {0, static_cast<int>(blob.size())};
    const int formats[] = {0, 1};
    PgResult res{PQexecParams(conn,
                              "INSERT INTO tstore.things (id, secret)"
                              " VALUES ($1::bigint, $2)"
                              " ON CONFLICT (id) DO UPDATE SET secret = EXCLUDED.secret",
                              2, nullptr, values, lengths, formats, 0)};
    REQUIRE(res.ok());
}

std::vector<std::uint8_t> fetch_secret(PGconn* conn, std::int64_t pk) {
    const std::string pk_str = std::to_string(pk);
    const char* values[] = {pk_str.c_str()};
    PgResult res{PQexecParams(conn, "SELECT secret FROM tstore.things WHERE id = $1::bigint", 1,
                              nullptr, values, nullptr, nullptr, /*resultFormat=*/1)};
    REQUIRE(res.status() == PGRES_TUPLES_OK);
    REQUIRE(PQntuples(res.get()) == 1);
    const auto* p = reinterpret_cast<const std::uint8_t*>(PQgetvalue(res.get(), 0, 0));
    return {p, p + PQgetlength(res.get(), 0, 0)};
}

std::uint32_t blob_kek_version(std::span<const std::uint8_t> blob) {
    REQUIRE(blob.size() >= SecretCodec::kMinBlobSize);
    const auto* p = blob.data() + SecretCodec::kKekVersionOffset;
    return (static_cast<std::uint32_t>(p[0]) << 24) | (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) | static_cast<std::uint32_t>(p[3]);
}

void set_blob_kek_version(std::vector<std::uint8_t>& blob, std::uint32_t v) {
    blob[SecretCodec::kKekVersionOffset + 0] = static_cast<std::uint8_t>(v >> 24);
    blob[SecretCodec::kKekVersionOffset + 1] = static_cast<std::uint8_t>(v >> 16);
    blob[SecretCodec::kKekVersionOffset + 2] = static_cast<std::uint8_t>(v >> 8);
    blob[SecretCodec::kKekVersionOffset + 3] = static_cast<std::uint8_t>(v);
}

} // namespace

#ifdef YUZU_TEST_ENABLE_PG

TEST_CASE("SecretCodec: encode_bigint_pk is fixed 8-byte BE", "[secrets]") {
    const std::string be = SecretCodec::encode_bigint_pk(0x0102030405060708);
    REQUIRE(be.size() == 8);
    for (std::size_t i = 0; i < 8; ++i)
        REQUIRE(static_cast<std::uint8_t>(be[i]) == i + 1);
    // Negative pks stay canonical (two's complement BE), distinct from positive.
    REQUIRE(SecretCodec::encode_bigint_pk(-1) != SecretCodec::encode_bigint_pk(1));
}

TEST_CASE("SecretCodec: register_secret_column validates identifiers", "[secrets]") {
    TempDir keys;
    FileKeyProvider provider(keys.path);
    SecretCodec codec(provider);
    REQUIRE(codec.register_secret_column(
        {"tstore", "things", "secret", "id", SecretCodec::PkKind::bigint}));
    REQUIRE_FALSE(codec.register_secret_column(
        {"Bad-Schema", "things", "secret", "id", SecretCodec::PkKind::bigint}));
    REQUIRE_FALSE(codec.register_secret_column(
        {"tstore", "things; DROP TABLE x", "secret", "id", SecretCodec::PkKind::bigint}));
    REQUIRE_FALSE(codec.register_secret_column(
        {"public", "things", "secret", "id", SecretCodec::PkKind::bigint}));
}

TEST_CASE("SecretCodec init: first boot generates v1; re-init verifies", "[pg][secrets]") {
    YUZU_REQUIRE_PG_DB(db);
    TempDir keys;
    FileKeyProvider provider(keys.path);
    PgConn conn = connect(db.dsn());

    std::vector<std::string> audit_verbs;
    SecretCodec codec(provider);
    codec.set_audit_hook(
        [&](std::string_view verb, const std::string&) { audit_verbs.emplace_back(verb); });

    REQUIRE(codec.active_kek_version() == 0);
    auto r = codec.init(conn.get());
    INFO((r ? std::string{} : r.error()));
    REQUIRE(r.has_value());
    REQUIRE(codec.active_kek_version() == 1);
    REQUIRE(provider.resolve_kek("secrets-kek-v1"));
    REQUIRE(std::count(audit_verbs.begin(), audit_verbs.end(), "kek.generated") == 1);

    // One fingerprint row registered.
    PgResult res{PQexec(conn.get(), "SELECT count(*) FROM secrets.kek_meta")};
    REQUIRE(res.status() == PGRES_TUPLES_OK);
    REQUIRE(std::string{PQgetvalue(res.get(), 0, 0)} == "1");

    // Second boot (fresh codec, same keys dir + db): verification passes,
    // no second generation.
    SecretCodec codec2(provider);
    auto r2 = codec2.init(conn.get());
    INFO((r2 ? std::string{} : r2.error()));
    REQUIRE(r2.has_value());
    REQUIRE(codec2.active_kek_version() == 1);
}

TEST_CASE("SecretCodec init: fail-closed boot verification", "[pg][secrets]") {
    YUZU_REQUIRE_PG_DB(db);
    TempDir keys;
    PgConn conn = connect(db.dsn());
    {
        FileKeyProvider provider(keys.path);
        SecretCodec codec(provider);
        REQUIRE(codec.init(conn.get()).has_value());
    }

    SECTION("missing KEK file (backup skew / dual server) -> kek_unresolvable") {
        TempDir other_keys; // empty keys dir, same database
        FileKeyProvider provider(other_keys.path);
        SecretCodec codec(provider);
        auto r = codec.init(conn.get());
        REQUIRE_FALSE(r.has_value());
        REQUIRE(r.error().find("kek_unresolvable") != std::string::npos);
    }
    SECTION("corrupt KEK file -> kek_corrupt") {
        // Overwrite the key file with different 32 bytes; fresh provider so
        // no resident cached copy masks the corruption.
        const auto key_path = keys.path / "secrets-kek-v1.key";
        {
            std::ofstream out(key_path, std::ios::binary | std::ios::trunc);
            const std::vector<std::uint8_t> junk(32, 0xAB);
            out.write(reinterpret_cast<const char*>(junk.data()),
                      static_cast<std::streamsize>(junk.size()));
        }
        FileKeyProvider provider(keys.path);
        SecretCodec codec(provider);
        auto r = codec.init(conn.get());
        REQUIRE_FALSE(r.has_value());
        REQUIRE(r.error().find("kek_corrupt") != std::string::npos);
    }
}

TEST_CASE("SecretCodec: round-trip, blob format, fresh DEK per encrypt", "[pg][secrets]") {
    YUZU_REQUIRE_PG_DB(db);
    TempDir keys;
    FileKeyProvider provider(keys.path);
    SecretCodec codec(provider);
    PgConn conn = connect(db.dsn());
    REQUIRE(codec.init(conn.get()).has_value());

    const auto plaintext = bytes_of("hunter2-totp-seed");
    const auto id = test_id();

    auto blob = codec.encrypt(id, plaintext);
    REQUIRE(blob.has_value());
    REQUIRE(blob->size() == SecretCodec::kMinBlobSize + plaintext.size());
    REQUIRE((*blob)[0] == SecretCodec::kBlobVersion);
    REQUIRE(blob_kek_version(*blob) == 1);

    auto back = codec.decrypt(id, *blob);
    REQUIRE(back.has_value());
    REQUIRE(back->size() == plaintext.size());
    REQUIRE(std::equal(plaintext.begin(), plaintext.end(), back->data()));

    // Fresh DEK + nonces per encryption: same value, different blob —
    // including the ciphertext (different DEK), not just the nonces.
    auto blob2 = codec.encrypt(id, plaintext);
    REQUIRE(blob2.has_value());
    REQUIRE(*blob != *blob2);
    REQUIRE_FALSE(std::equal(blob->begin() + SecretCodec::kCiphertextOffset, blob->end(),
                             blob2->begin() + SecretCodec::kCiphertextOffset));

    // Empty plaintext is a valid value (blob == fixed minimum).
    auto empty = codec.encrypt(id, {});
    REQUIRE(empty.has_value());
    REQUIRE(empty->size() == SecretCodec::kMinBlobSize);
    REQUIRE(codec.decrypt(id, *empty).has_value());
}

TEST_CASE("SecretCodec: AAD anti-swap and boundary-shift", "[pg][secrets]") {
    YUZU_REQUIRE_PG_DB(db);
    TempDir keys;
    FileKeyProvider provider(keys.path);
    SecretCodec codec(provider);
    PgConn conn = connect(db.dsn());
    REQUIRE(codec.init(conn.get()).has_value());

    const auto plaintext = bytes_of("webhook-signing-secret");

    SECTION("any identity coordinate change fails the tag") {
        const auto id = test_id(42);
        auto blob = codec.encrypt(id, plaintext);
        REQUIRE(blob.has_value());

        auto wrong_pk = codec.decrypt(test_id(43), *blob);
        REQUIRE_FALSE(wrong_pk.has_value());
        REQUIRE(wrong_pk.error().cls == SecretCodec::FailureClass::tag_mismatch);

        SecretCodec::SecretId wrong_col = id;
        wrong_col.column = "other";
        auto r2 = codec.decrypt(wrong_col, *blob);
        REQUIRE_FALSE(r2.has_value());
        REQUIRE(r2.error().cls == SecretCodec::FailureClass::tag_mismatch);

        SecretCodec::SecretId wrong_table = id;
        wrong_table.table = "webhooks";
        REQUIRE_FALSE(codec.decrypt(wrong_table, *blob).has_value());

        SecretCodec::SecretId wrong_store = id;
        wrong_store.store = "offload";
        REQUIRE_FALSE(codec.decrypt(wrong_store, *blob).has_value());
    }

    SECTION("boundary shift: (a,bc) vs (ab,c) must not collide") {
        // Naive concatenation would serialize both identities to the same
        // AAD bytes; the u32-BE length prefixes must keep them distinct.
        SecretCodec::SecretId id1{"s", "a", "bc", "pk"};
        SecretCodec::SecretId id2{"s", "ab", "c", "pk"};
        auto blob = codec.encrypt(id1, plaintext);
        REQUIRE(blob.has_value());
        auto shifted = codec.decrypt(id2, *blob);
        REQUIRE_FALSE(shifted.has_value());
        REQUIRE(shifted.error().cls == SecretCodec::FailureClass::tag_mismatch);
        REQUIRE(codec.decrypt(id1, *blob).has_value());
    }
}

TEST_CASE("SecretCodec: malformed blobs and payload tamper", "[pg][secrets]") {
    YUZU_REQUIRE_PG_DB(db);
    TempDir keys;
    FileKeyProvider provider(keys.path);
    SecretCodec codec(provider);
    PgConn conn = connect(db.dsn());
    REQUIRE(codec.init(conn.get()).has_value());

    const auto id = test_id();
    auto blob = codec.encrypt(id, bytes_of("oidc-client-secret"));
    REQUIRE(blob.has_value());

    SECTION("below fixed minimum") {
        std::vector<std::uint8_t> shorted(blob->begin(),
                                          blob->begin() + SecretCodec::kMinBlobSize - 1);
        auto r = codec.decrypt(id, shorted);
        REQUIRE_FALSE(r.has_value());
        REQUIRE(r.error().cls == SecretCodec::FailureClass::malformed_blob);
    }
    SECTION("unknown version byte") {
        auto t = *blob;
        t[0] = 0x7F;
        auto r = codec.decrypt(id, t);
        REQUIRE_FALSE(r.has_value());
        REQUIRE(r.error().cls == SecretCodec::FailureClass::malformed_blob);
    }
    SECTION("flipped ciphertext byte") {
        auto t = *blob;
        t[SecretCodec::kCiphertextOffset] ^= 0x01;
        auto r = codec.decrypt(id, t);
        REQUIRE_FALSE(r.has_value());
        REQUIRE(r.error().cls == SecretCodec::FailureClass::tag_mismatch);
    }
    SECTION("flipped data tag byte") {
        auto t = *blob;
        t[SecretCodec::kDataTagOffset] ^= 0x01;
        auto r = codec.decrypt(id, t);
        REQUIRE_FALSE(r.has_value());
        REQUIRE(r.error().cls == SecretCodec::FailureClass::tag_mismatch);
    }
    SECTION("failure counters accumulate by store and class") {
        auto t = *blob;
        t[SecretCodec::kDataTagOffset] ^= 0x01;
        (void)codec.decrypt(id, t);
        const auto counts = codec.decrypt_failure_counts();
        bool found = false;
        for (const auto& [key, n] : counts)
            if (key.first == "tstore" && key.second == SecretCodec::FailureClass::tag_mismatch &&
                n >= 1)
                found = true;
        REQUIRE(found);
    }
}

TEST_CASE("SecretCodec: KEK rotation — the fjarvis #1333 reproduction", "[pg][secrets]") {
    YUZU_REQUIRE_PG_DB(db);
    TempDir keys;
    FileKeyProvider provider(keys.path);
    SecretCodec codec(provider);
    PgConn conn = connect(db.dsn());
    REQUIRE(codec.init(conn.get()).has_value());
    create_test_table(conn.get());
    REQUIRE(codec.register_secret_column(
        {"tstore", "things", "secret", "id", SecretCodec::PkKind::bigint}));

    std::vector<std::string> audit_verbs;
    codec.set_audit_hook(
        [&](std::string_view verb, const std::string&) { audit_verbs.emplace_back(verb); });

    const auto plaintext = bytes_of("offload-credential");
    const auto id = test_id(42);
    auto v1_blob = codec.encrypt(id, plaintext);
    REQUIRE(v1_blob.has_value());
    REQUIRE(blob_kek_version(*v1_blob) == 1);
    upsert_secret(conn.get(), 42, *v1_blob);

    // Rotate: mint v2, re-wrap ONLY (payload untouched).
    auto rotated = codec.rotate_kek(conn.get());
    INFO((rotated ? std::string{} : rotated.error()));
    REQUIRE(rotated.has_value());
    REQUIRE(*rotated == 2);
    REQUIRE(codec.active_kek_version() == 2);
    REQUIRE(std::count(audit_verbs.begin(), audit_verbs.end(), "kek.rotated") == 1);

    const auto v2_blob = fetch_secret(conn.get(), 42);
    REQUIRE(blob_kek_version(v2_blob) == 2);
    // Payload section (data_nonce || data_tag || ciphertext) byte-identical:
    // rotation never touches it — including kek_version in the payload AAD
    // would have bricked this row (the #1333 HIGH-1 bug, reproduced live).
    REQUIRE(std::equal(v1_blob->begin() + SecretCodec::kDataNonceOffset, v1_blob->end(),
                       v2_blob.begin() + SecretCodec::kDataNonceOffset, v2_blob.end()));
    // Wrap section re-keyed.
    REQUIRE_FALSE(std::equal(v1_blob->begin() + SecretCodec::kWrapNonceOffset,
                             v1_blob->begin() + SecretCodec::kDataNonceOffset,
                             v2_blob.begin() + SecretCodec::kWrapNonceOffset));

    // The payload still decrypts after re-wrap-only rotation.
    auto back = codec.decrypt(id, v2_blob);
    INFO((back ? std::string{} : back.error().message));
    REQUIRE(back.has_value());
    REQUIRE(std::equal(plaintext.begin(), plaintext.end(), back->data()));

    // Completion signal: nothing references v1 anymore.
    auto oldest = codec.oldest_kek_version_in_use(conn.get());
    REQUIRE(oldest.has_value());
    REQUIRE(*oldest == 2);

    SECTION("tampered blob kek_version fails the wrap tag (version integrity)") {
        // Patch the v2 blob's version field back to 1 — v1 is still live, so
        // this resolves a KEK; the wrap AAD binds the field, so the wrap tag
        // must fail as tag_mismatch (NOT kek_unresolvable, NOT success).
        auto tampered = v2_blob;
        set_blob_kek_version(tampered, 1);
        auto r = codec.decrypt(id, tampered);
        REQUIRE_FALSE(r.has_value());
        REQUIRE(r.error().cls == SecretCodec::FailureClass::tag_mismatch);
    }
    SECTION("unknown kek_version is unresolvable") {
        auto tampered = v2_blob;
        set_blob_kek_version(tampered, 99);
        auto r = codec.decrypt(id, tampered);
        REQUIRE_FALSE(r.has_value());
        REQUIRE(r.error().cls == SecretCodec::FailureClass::kek_unresolvable);
    }
    SECTION("interrupted rotation resumes via rewrap_all (header-version detection)") {
        // Put the original v1 blob back (as if the CAS write never landed),
        // then resume: rewrap_all must rewrap exactly that one row.
        upsert_secret(conn.get(), 42, *v1_blob);
        auto resumed = codec.rewrap_all(conn.get());
        REQUIRE(resumed.has_value());
        REQUIRE(*resumed == 1);
        REQUIRE(blob_kek_version(fetch_secret(conn.get(), 42)) == 2);
        // Idempotent re-run: nothing left to do.
        auto again = codec.rewrap_all(conn.get());
        REQUIRE(again.has_value());
        REQUIRE(*again == 0);
    }
    SECTION("retirement lifecycle") {
        // Refuse while a blob still references v1.
        upsert_secret(conn.get(), 42, *v1_blob);
        REQUIRE_FALSE(codec.retire_kek(conn.get(), 1).has_value());
        // Refuse the active version outright.
        REQUIRE_FALSE(codec.retire_kek(conn.get(), 2).has_value());

        // After a full rewrap, v1 retires: meta row keeps destruction evidence,
        // the key file is gone, and a v1 blob now reads as unresolvable.
        REQUIRE(codec.rewrap_all(conn.get()).has_value());
        auto retired = codec.retire_kek(conn.get(), 1);
        INFO((retired ? std::string{} : retired.error()));
        REQUIRE(retired.has_value());
        REQUIRE(std::count(audit_verbs.begin(), audit_verbs.end(), "kek.retired") == 1);
        REQUIRE_FALSE(provider.resolve_kek("secrets-kek-v1"));

        PgResult meta{PQexec(conn.get(), "SELECT count(*) FROM secrets.kek_meta"
                                         " WHERE kek_version = 1 AND retired_at IS NOT NULL")};
        REQUIRE(meta.status() == PGRES_TUPLES_OK);
        REQUIRE(std::string{PQgetvalue(meta.get(), 0, 0)} == "1");

        auto r = codec.decrypt(id, *v1_blob);
        REQUIRE_FALSE(r.has_value());
        REQUIRE(r.error().cls == SecretCodec::FailureClass::kek_unresolvable);

        // Boot verification skips retired versions: a fresh codec still
        // boots cleanly with the v1 key file destroyed.
        SecretCodec codec2(provider);
        auto r2 = codec2.init(conn.get());
        INFO((r2 ? std::string{} : r2.error()));
        REQUIRE(r2.has_value());
        REQUIRE(codec2.active_kek_version() == 2);
    }
}

#endif // YUZU_TEST_ENABLE_PG
