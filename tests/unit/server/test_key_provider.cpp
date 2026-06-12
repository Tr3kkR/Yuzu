/**
 * test_key_provider.cpp — Unit tests for FileKeyProvider (PR1).
 *
 * Covers: store/load roundtrip, 0600 file mode (POSIX), the path-traversal
 * guard on key_id, the within-base guard on opaque refs (load/has/delete must
 * refuse a ref pointing outside the provider's base dir), and delete.
 */

#include "key_provider.hpp"

#include <catch2/catch_test_macros.hpp>

#include "../test_helpers.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

using namespace yuzu::server;

namespace {

struct TempDir {
    std::filesystem::path path;
    TempDir() : path(yuzu::test::unique_temp_path("kp-")) {}
    ~TempDir() {
        std::error_code ec;
        std::filesystem::remove_all(path, ec);
    }
    TempDir(const TempDir&) = delete;
    TempDir& operator=(const TempDir&) = delete;
};

constexpr const char* kSampleKey =
    "-----BEGIN PRIVATE KEY-----\nMIGHAgEA...test...\n-----END PRIVATE KEY-----\n";

} // namespace

TEST_CASE("FileKeyProvider: store/load roundtrip", "[key_provider]") {
    TempDir dir;
    FileKeyProvider provider(dir.path);

    auto ref = provider.store_key("ca-root", kSampleKey);
    REQUIRE(ref);
    REQUIRE(provider.has_key(*ref));

    auto loaded = provider.load_key(*ref);
    REQUIRE(loaded);
    REQUIRE(*loaded == kSampleKey);

    // ref resolves to <base>/ca-root.key
    REQUIRE(*ref == provider.path_for("ca-root").string());
}

#ifndef _WIN32
TEST_CASE("FileKeyProvider: stored key is 0600", "[key_provider][posix]") {
    namespace fs = std::filesystem;
    TempDir dir;
    FileKeyProvider provider(dir.path);
    auto ref = provider.store_key("k", kSampleKey);
    REQUIRE(ref);

    const auto p = fs::status(*ref).permissions();
    REQUIRE((p & fs::perms::owner_read) != fs::perms::none);
    REQUIRE((p & fs::perms::owner_write) != fs::perms::none);
    REQUIRE((p & fs::perms::group_all) == fs::perms::none);
    REQUIRE((p & fs::perms::others_all) == fs::perms::none);
}
#endif

TEST_CASE("FileKeyProvider: rejects unsafe key_id (traversal)", "[key_provider][security]") {
    TempDir dir;
    FileKeyProvider provider(dir.path);
    REQUIRE_FALSE(provider.store_key("../evil", kSampleKey));
    REQUIRE_FALSE(provider.store_key("a/b", kSampleKey));
    REQUIRE_FALSE(provider.store_key("..", kSampleKey));
    REQUIRE_FALSE(provider.store_key("", kSampleKey));
    REQUIRE_FALSE(provider.store_key("has space", kSampleKey));
    REQUIRE_FALSE(provider.store_key("semi;colon", kSampleKey));
    // A valid id still works.
    REQUIRE(provider.store_key("valid-id_1.key", kSampleKey));
}

TEST_CASE("FileKeyProvider: refuses refs outside base dir", "[key_provider][security]") {
    TempDir dir;
    FileKeyProvider provider(dir.path);
    REQUIRE(provider.store_key("k", kSampleKey));

    // An opaque ref pointing outside the base must not be readable/deletable.
    REQUIRE_FALSE(provider.load_key("/etc/hostname"));
    REQUIRE_FALSE(provider.has_key("/etc/hostname"));
    REQUIRE_FALSE(provider.delete_key("/etc/passwd"));
    const std::string escape = (dir.path / ".." / "outside.key").string();
    REQUIRE_FALSE(provider.load_key(escape));
}

TEST_CASE("FileKeyProvider: rejects empty and oversized keys", "[key_provider][negative]") {
    TempDir dir;
    FileKeyProvider provider(dir.path);
    REQUIRE_FALSE(provider.store_key("k", ""));
    const std::string huge(1024 * 1024 + 1, 'x'); // > kMaxKeyPemSize
    REQUIRE_FALSE(provider.store_key("k", huge));
    // A normal key still stores after the rejections.
    REQUIRE(provider.store_key("k", kSampleKey));
}

TEST_CASE("FileKeyProvider: delete removes the key", "[key_provider]") {
    TempDir dir;
    FileKeyProvider provider(dir.path);
    auto ref = provider.store_key("temp", kSampleKey);
    REQUIRE(ref);
    REQUIRE(provider.has_key(*ref));
    REQUIRE(provider.delete_key(*ref));
    REQUIRE_FALSE(provider.has_key(*ref));
    // Deleting an already-absent key is success (idempotent).
    REQUIRE(provider.delete_key(*ref));
}

// ── KEK wrap/unwrap seam (ADR-0010 §2, #1320 PR 4) ───────────────────────────

namespace {

std::vector<std::uint8_t> bytes_of(std::string_view s) {
    return {reinterpret_cast<const std::uint8_t*>(s.data()),
            reinterpret_cast<const std::uint8_t*>(s.data()) + s.size()};
}

} // namespace

TEST_CASE("FileKeyProvider: generate_kek mints a 32-byte key, resolve finds it",
          "[key_provider][kek]") {
    namespace fs = std::filesystem;
    TempDir dir;
    FileKeyProvider provider(dir.path);

    REQUIRE_FALSE(provider.resolve_kek("secrets-kek-v1"));
    auto ref = provider.generate_kek("secrets-kek-v1");
    REQUIRE(ref);
    REQUIRE(fs::file_size(fs::path{*ref}) == 32);

    auto resolved = provider.resolve_kek("secrets-kek-v1");
    REQUIRE(resolved);
    REQUIRE(*resolved == *ref);

#ifndef _WIN32
    const auto perms = fs::status(fs::path{*ref}).permissions();
    REQUIRE((perms & (fs::perms::group_all | fs::perms::others_all)) == fs::perms::none);
#endif

    // Re-minting the same id must refuse — overwriting a KEK would orphan
    // every blob wrapped under it.
    REQUIRE_FALSE(provider.generate_kek("secrets-kek-v1"));
    // Unsafe ids are rejected before touching the filesystem.
    REQUIRE_FALSE(provider.generate_kek("../escape"));
}

TEST_CASE("FileKeyProvider: wrap/unwrap round-trip binds the wrap AAD", "[key_provider][kek]") {
    TempDir dir;
    FileKeyProvider provider(dir.path);
    auto ref = provider.generate_kek("secrets-kek-v1");
    REQUIRE(ref);

    std::array<std::uint8_t, 32> dek{};
    for (std::size_t i = 0; i < dek.size(); ++i)
        dek[i] = static_cast<std::uint8_t>(i * 7 + 1);
    const auto aad = bytes_of("store|table|column|pk|v1");

    auto wrapped = provider.wrap_dek(*ref, dek, aad);
    REQUIRE(wrapped);

    auto unwrapped = provider.unwrap_dek(*ref, *wrapped, aad);
    REQUIRE(unwrapped);
    REQUIRE(unwrapped->size() == 32);
    REQUIRE(std::equal(dek.begin(), dek.end(), unwrapped->data()));

    SECTION("different wrap AAD fails the tag") {
        const auto other = bytes_of("store|table|column|pk|v2");
        auto bad = provider.unwrap_dek(*ref, *wrapped, other);
        REQUIRE_FALSE(bad);
        REQUIRE(bad.error() == yuzu::server::KekError::tag_mismatch);
    }
    SECTION("tampered tag fails") {
        auto t = *wrapped;
        t.tag[0] ^= 0x01;
        auto bad = provider.unwrap_dek(*ref, t, aad);
        REQUIRE_FALSE(bad);
        REQUIRE(bad.error() == yuzu::server::KekError::tag_mismatch);
    }
    SECTION("tampered wrapped DEK fails") {
        auto t = *wrapped;
        t.wrapped[5] ^= 0x80;
        auto bad = provider.unwrap_dek(*ref, t, aad);
        REQUIRE_FALSE(bad);
        REQUIRE(bad.error() == yuzu::server::KekError::tag_mismatch);
    }
    SECTION("fresh nonce per wrap — same DEK+AAD wraps differently") {
        auto again = provider.wrap_dek(*ref, dek, aad);
        REQUIRE(again);
        REQUIRE(again->nonce != wrapped->nonce);
        REQUIRE(again->wrapped != wrapped->wrapped);
    }
}

TEST_CASE("FileKeyProvider: unknown / wrong-size / deleted KEK is unresolvable",
          "[key_provider][kek][negative]") {
    TempDir dir;
    FileKeyProvider provider(dir.path);
    std::array<std::uint8_t, 32> dek{};
    const auto aad = bytes_of("aad");

    SECTION("unknown ref") {
        auto r = provider.wrap_dek((dir.path / "nope.key").string(), dek, aad);
        REQUIRE_FALSE(r);
        REQUIRE(r.error() == yuzu::server::KekError::unresolvable);
    }
    SECTION("a PEM-sized file is not a 32-byte KEK") {
        auto pem_ref = provider.store_key("not-a-kek", kSampleKey);
        REQUIRE(pem_ref);
        auto r = provider.wrap_dek(*pem_ref, dek, aad);
        REQUIRE_FALSE(r);
        REQUIRE(r.error() == yuzu::server::KekError::unresolvable);
    }
    SECTION("delete_key evicts the resident KEK") {
        auto ref = provider.generate_kek("secrets-kek-v1");
        REQUIRE(ref);
        REQUIRE(provider.wrap_dek(*ref, dek, aad));
        REQUIRE(provider.delete_key(*ref));
        auto r = provider.wrap_dek(*ref, dek, aad);
        REQUIRE_FALSE(r);
        REQUIRE(r.error() == yuzu::server::KekError::unresolvable);
    }
}

TEST_CASE("FileKeyProvider: kek_check_value is deterministic and key-distinct",
          "[key_provider][kek]") {
    TempDir dir;
    FileKeyProvider provider(dir.path);
    auto r1 = provider.generate_kek("secrets-kek-v1");
    auto r2 = provider.generate_kek("secrets-kek-v2");
    REQUIRE(r1);
    REQUIRE(r2);

    auto k1a = provider.kek_check_value(*r1);
    auto k2 = provider.kek_check_value(*r2);
    REQUIRE(k1a);
    REQUIRE(k2);
    REQUIRE(*k1a != *k2);

    // Survives a provider restart (fresh cache, re-read from disk).
    FileKeyProvider reopened(dir.path);
    auto k1b = reopened.kek_check_value(*r1);
    REQUIRE(k1b);
    REQUIRE(*k1a == *k1b);

    REQUIRE_FALSE(provider.kek_check_value((dir.path / "nope.key").string()));
}
