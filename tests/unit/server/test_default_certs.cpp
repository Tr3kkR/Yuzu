/**
 * test_default_certs.cpp — Unit tests for the first-boot default-cert bootstrap (PR2).
 *
 * Covers: first-boot generation of the full set, idempotent re-run,
 * regenerate-on-corruption, leaf chains-to-CA + SAN, 0600 key mode (POSIX),
 * leaf-not-after == CA-not-after (the leaf<=CA invariant), and ca_store
 * recording of the root + issued leaves.
 */

#include "default_certs.hpp"

#include "ca_store.hpp"
#include "x509_ca.hpp"

#include <catch2/catch_test_macros.hpp>

#include "../test_helpers.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

using namespace yuzu::server;

namespace {

struct TempDir {
    std::filesystem::path path;
    TempDir() : path(yuzu::test::unique_temp_path("defcerts-")) {}
    ~TempDir() {
        std::error_code ec;
        std::filesystem::remove_all(path, ec);
    }
    TempDir(const TempDir&) = delete;
    TempDir& operator=(const TempDir&) = delete;
};

std::string read_file(const std::filesystem::path& p) {
    std::ifstream in(p, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

bool contains(const std::vector<std::string>& v, const std::string& s) {
    return std::find(v.begin(), v.end(), s) != v.end();
}

} // namespace

TEST_CASE("default_certs: first boot generates a full, chained set", "[default_certs]") {
    TempDir dir;
    DefaultCertSet set;
    REQUIRE(ensure_default_certs(dir.path, "test-host", nullptr, set));
    REQUIRE(set.freshly_generated);
    REQUIRE_FALSE(set.ca_fingerprint_sha256.empty());

    for (const auto& p : {set.ca_cert, set.https_cert, set.https_key, set.server_cert,
                          set.server_key, set.gateway_cert, set.gateway_key}) {
        REQUIRE(std::filesystem::exists(p));
    }

    const std::string ca_pem = read_file(set.ca_cert);
    auto ca_info = pki::parse_certificate(ca_pem);
    REQUIRE(ca_info);
    REQUIRE(ca_info->is_ca);

    // Every server-side leaf chains to the CA.
    for (const auto& leaf : {set.https_cert, set.server_cert, set.gateway_cert}) {
        REQUIRE(pki::verify_chain(read_file(leaf), ca_pem));
    }

    // HTTPS leaf SAN carries localhost / 127.0.0.1 / the hostname.
    auto https = pki::parse_certificate(read_file(set.https_cert));
    REQUIRE(https);
    REQUIRE(contains(https->san.dns, "localhost"));
    REQUIRE(contains(https->san.dns, "test-host"));
    REQUIRE(contains(https->san.ips, "127.0.0.1"));
    REQUIRE_FALSE(https->is_ca);

    // Leaf notAfter must equal the CA notAfter (sized to the issuer).
    REQUIRE(https->not_after == ca_info->not_after);
}

#ifndef _WIN32
TEST_CASE("default_certs: key files are 0600", "[default_certs][posix]") {
    namespace fs = std::filesystem;
    TempDir dir;
    DefaultCertSet set;
    REQUIRE(ensure_default_certs(dir.path, "h", nullptr, set));
    for (const auto& key : {set.https_key, set.server_key, set.gateway_key}) {
        const auto p = fs::status(key).permissions();
        REQUIRE((p & fs::perms::group_all) == fs::perms::none);
        REQUIRE((p & fs::perms::others_all) == fs::perms::none);
    }
}
#endif

TEST_CASE("default_certs: second run is idempotent", "[default_certs]") {
    TempDir dir;
    DefaultCertSet first;
    REQUIRE(ensure_default_certs(dir.path, "host", nullptr, first));
    REQUIRE(first.freshly_generated);

    DefaultCertSet second;
    REQUIRE(ensure_default_certs(dir.path, "host", nullptr, second));
    REQUIRE_FALSE(second.freshly_generated);
    REQUIRE(second.ca_fingerprint_sha256 == first.ca_fingerprint_sha256);
}

TEST_CASE("default_certs: regenerates the whole set when a key is missing",
          "[default_certs]") {
    TempDir dir;
    DefaultCertSet first;
    REQUIRE(ensure_default_certs(dir.path, "host", nullptr, first));

    std::error_code ec;
    std::filesystem::remove(first.server_key, ec); // corrupt the set
    REQUIRE_FALSE(ec);

    DefaultCertSet second;
    REQUIRE(ensure_default_certs(dir.path, "host", nullptr, second));
    REQUIRE(second.freshly_generated);                                  // regenerated
    REQUIRE(second.ca_fingerprint_sha256 != first.ca_fingerprint_sha256); // brand-new CA
    REQUIRE(std::filesystem::exists(second.server_key));
}

TEST_CASE("default_certs: records root + leaves in ca_store", "[default_certs][ca_store]") {
    TempDir dir;
    yuzu::test::TempDbFile db{std::string_view{"defcerts-ca-"}};
    CaStore store(db.path);
    REQUIRE(store.is_open());

    DefaultCertSet set;
    REQUIRE(ensure_default_certs(dir.path, "host", &store, set));

    REQUIRE(store.has_root());
    auto root = store.get_root();
    REQUIRE(root);
    REQUIRE(root->algo == "EcP384");
    REQUIRE(root->mode == CaMode::Builtin);
    REQUIRE(root->fingerprint_sha256 == set.ca_fingerprint_sha256);

    auto issued = store.list_issued();
    REQUIRE(issued.size() == 3); // https + server + gateway
    for (const auto& rec : issued) {
        REQUIRE_FALSE(rec.cert_pem.empty());
        REQUIRE(rec.issued_by == "system:default-certs");
    }
}

TEST_CASE("default_certs: refuses to re-root a populated ca.db (B-2)",
          "[default_certs][ca_store][security]") {
    // B-2 (#1238): a wiped/corrupt on-disk cert dir on a PERSISTENT ca.db must NOT
    // silently regenerate a fresh CA — that would re-root the fleet and orphan
    // every agent enrolled under the old root. ensure_default_certs must refuse;
    // the bootstrap caller turns that into a refuse-to-start with a restore hint.
    TempDir dir;
    yuzu::test::TempDbFile db{std::string_view{"defcerts-ca-"}};
    CaStore store(db.path);
    DefaultCertSet a;
    REQUIRE(ensure_default_certs(dir.path, "host", &store, a));
    REQUIRE(store.has_root());
    REQUIRE(store.list_issued().size() == 3);

    // Corrupt the on-disk set while ca.db stays populated.
    std::error_code ec;
    std::filesystem::remove(a.server_key, ec);
    DefaultCertSet b;
    REQUIRE_FALSE(ensure_default_certs(dir.path, "host", &store, b)); // refuse, don't re-root
    REQUIRE_FALSE(b.freshly_generated);
    // ca.db root + inventory left intact (not REPLACEd, not purged).
    auto root_after = store.get_root();
    REQUIRE(root_after);
    REQUIRE(root_after->fingerprint_sha256 == a.ca_fingerprint_sha256);
    REQUIRE(store.list_issued().size() == 3);
}

TEST_CASE("default_certs: returns false (refuse) when the cert dir cannot be created",
          "[default_certs][negative]") {
    // The "ensure_default_certs-fails" refuse-to-start branch (#1238 B-6): a dir
    // that can't be created (here, a path that is an existing FILE) must make
    // ensure_default_certs return false — not crash, not half-generate — so the
    // bootstrap caller turns it into a clean refuse-to-start. (The startup_failed()
    // wiring itself is exercised by the live boot-test; ServerImpl::run starts a
    // real server, so it is not unit-constructible.)
    const auto file_path = yuzu::test::unique_temp_path("defcerts-not-a-dir-");
    {
        std::ofstream f(file_path);
        f << "this is a file, not a directory";
    }
    DefaultCertSet set;
    REQUIRE_FALSE(ensure_default_certs(file_path, "h", nullptr, set));
    REQUIRE_FALSE(set.freshly_generated);
    std::error_code ec;
    std::filesystem::remove(file_path, ec);
}
