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

#include <filesystem>
#include <string>
#include <system_error>

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
