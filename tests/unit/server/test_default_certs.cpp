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
#include <cstddef>
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

std::size_t count_of(const std::vector<std::string>& v, const std::string& s) {
    return static_cast<std::size_t>(std::count(v.begin(), v.end(), s));
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

TEST_CASE("default_certs: --cert-san extra SANs land on every default leaf", "[default_certs]") {
    TempDir dir;
    DefaultCertSet set;
    // Exercise every form: dns:-prefixed, ip:-prefixed, a bare DNS value, a bare
    // IP value (auto-classified), a comma-joined value (single-env-var case), a
    // duplicate of the hostname (dedupe), and a bogus ip: (dropped with a warn).
    const std::vector<std::string> extra = {
        "dns:gateway", "ip:10.1.2.3",          "edge.example.com", "192.0.2.7",
        "dns:a.example,ip:198.51.100.9",       "dns:test-host",    "ip:not-an-ip",
    };
    REQUIRE(ensure_default_certs(dir.path, "test-host", nullptr, set, extra));

    for (const auto& leaf : {set.https_cert, set.server_cert, set.gateway_cert}) {
        auto c = pki::parse_certificate(read_file(leaf));
        REQUIRE(c);
        // Base SANs still present.
        REQUIRE(contains(c->san.dns, "localhost"));
        REQUIRE(contains(c->san.ips, "127.0.0.1"));
        // Extra DNS names (prefixed, bare, and comma-split).
        REQUIRE(contains(c->san.dns, "gateway"));
        REQUIRE(contains(c->san.dns, "edge.example.com"));
        REQUIRE(contains(c->san.dns, "a.example"));
        // Extra IPs (prefixed, bare, and comma-split) — never in the DNS set.
        REQUIRE(contains(c->san.ips, "10.1.2.3"));
        REQUIRE(contains(c->san.ips, "192.0.2.7"));
        REQUIRE(contains(c->san.ips, "198.51.100.9"));
        REQUIRE_FALSE(contains(c->san.dns, "10.1.2.3"));
        // The bogus "ip:not-an-ip" was dropped (neither set).
        REQUIRE_FALSE(contains(c->san.ips, "not-an-ip"));
        REQUIRE_FALSE(contains(c->san.dns, "not-an-ip"));
        // Hostname duplicate collapsed — appears exactly once.
        REQUIRE(count_of(c->san.dns, "test-host") == 1);
    }
}

TEST_CASE("default_certs: --cert-san input validation is robust (no boot-fail on bad input)",
          "[default_certs]") {
    TempDir dir;
    DefaultCertSet set;
    const std::string overlong_label(300, 'a'); // > 63-byte label → rejected
    const std::vector<std::string> extra = {
        "dns:10.0.0.1",        // explicit dns: of an IP literal → kept as DNS, NOT ip
        "1.2.3.4.5",           // bare, IPv4-shaped but invalid → must NOT boot-fail
        "9.9.9.9",             // bare, valid IPv4 → ip
        "with space",          // bad charset (space) → dropped, no crash
        "foo/bar.example",     // bad charset (slash, a templating mistake) → dropped
        std::string("ctl\twith\ttabs"), // control chars → dropped
        overlong_label,        // over-length DNS → dropped
        "*.corp.example",      // wildcard → accepted (with warning)
        "",                    // empty → skipped
        "   ",                 // whitespace-only → skipped
    };
    // The whole point: a typo-laden extra set must still produce a valid cert set.
    REQUIRE(ensure_default_certs(dir.path, "h", nullptr, set, extra));
    REQUIRE(set.freshly_generated);

    auto c = pki::parse_certificate(read_file(set.gateway_cert));
    REQUIRE(c);
    // dns:<ip> stays a DNS-type SAN (Finding 8) — present in dns, absent from ips.
    REQUIRE(contains(c->san.dns, "10.0.0.1"));
    REQUIRE_FALSE(contains(c->san.ips, "10.0.0.1"));
    // Invalid IPv4 literal was NOT shunted to ips (would have hard-failed issue_leaf).
    REQUIRE_FALSE(contains(c->san.ips, "1.2.3.4.5"));
    // Valid bare IPv4 landed in ips.
    REQUIRE(contains(c->san.ips, "9.9.9.9"));
    // Wildcard accepted.
    REQUIRE(contains(c->san.dns, "*.corp.example"));
    // Over-length label and bad-charset values dropped from both sets.
    REQUIRE_FALSE(contains(c->san.dns, overlong_label));
    REQUIRE_FALSE(contains(c->san.dns, "with space"));
    REQUIRE_FALSE(contains(c->san.dns, "foo/bar.example"));
    // Control-char entry dropped (the mid-string tabs make it invalid input).
    for (const auto& d : c->san.dns)
        REQUIRE(d.find('\t') == std::string::npos);
}

TEST_CASE("default_certs: a malformed gethostname() is omitted from the SAN, not baked in",
          "[default_certs]") {
    TempDir dir;
    DefaultCertSet set;
    // Container orchestration can set a hostname containing non-DNS bytes.
    REQUIRE(ensure_default_certs(dir.path, "bad/host name", nullptr, set));
    REQUIRE(set.freshly_generated);
    auto c = pki::parse_certificate(read_file(set.https_cert));
    REQUIRE(c);
    REQUIRE(contains(c->san.dns, "localhost"));        // base coverage intact
    REQUIRE(contains(c->san.ips, "127.0.0.1"));
    REQUIRE_FALSE(contains(c->san.dns, "bad/host name")); // malformed host name not baked in
}

TEST_CASE("default_certs: --cert-san total count is capped", "[default_certs]") {
    TempDir dir;
    DefaultCertSet set;
    std::vector<std::string> extra;
    for (int i = 0; i < 200; ++i)
        extra.push_back("dns:host" + std::to_string(i) + ".example");
    REQUIRE(ensure_default_certs(dir.path, "h", nullptr, set, extra));
    auto c = pki::parse_certificate(read_file(set.gateway_cert));
    REQUIRE(c);
    // base (localhost + h) + at most 64 extras; nowhere near 200.
    REQUIRE(c->san.dns.size() <= 2 + 64);
    REQUIRE(c->san.dns.size() > 2); // but some extras did land
}

TEST_CASE("default_certs: no --cert-san leaves the base SAN set unchanged", "[default_certs]") {
    TempDir dir;
    DefaultCertSet set;
    REQUIRE(ensure_default_certs(dir.path, "plain-host", nullptr, set)); // 4-arg / default {}
    auto c = pki::parse_certificate(read_file(set.gateway_cert));
    REQUIRE(c);
    REQUIRE(contains(c->san.dns, "localhost"));
    REQUIRE(contains(c->san.dns, "plain-host"));
    REQUIRE(contains(c->san.ips, "127.0.0.1"));
    REQUIRE(c->san.ips.size() == 2); // 127.0.0.1 + ::1 (parsed uncompressed), nothing extra
    REQUIRE(c->san.dns.size() == 2); // localhost + hostname, nothing extra
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

TEST_CASE("default_certs: regeneration purges stale inventory rows", "[default_certs][ca_store]") {
    TempDir dir;
    yuzu::test::TempDbFile db{std::string_view{"defcerts-ca-"}};
    CaStore store(db.path);
    DefaultCertSet a;
    REQUIRE(ensure_default_certs(dir.path, "host", &store, a));
    REQUIRE(store.list_issued().size() == 3);

    // Corrupt the set, then regenerate against the SAME store.
    std::error_code ec;
    std::filesystem::remove(a.server_key, ec);
    DefaultCertSet b;
    REQUIRE(ensure_default_certs(dir.path, "host", &store, b));
    REQUIRE(b.freshly_generated);
    REQUIRE(b.ca_fingerprint_sha256 != a.ca_fingerprint_sha256);
    // Old rows purged — 3, not 6.
    REQUIRE(store.list_issued().size() == 3);
}
