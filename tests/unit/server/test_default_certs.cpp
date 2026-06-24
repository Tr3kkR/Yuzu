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

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#ifndef _WIN32
#include <sys/stat.h> // stat (--cert-group perm assertions)
#include <unistd.h>   // getgid
#include <utility>    // pair
#endif

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

// Returns the X509 extended-key-usage flag word (XKU_SSL_SERVER / XKU_SSL_CLIENT
// bits) for a PEM leaf. UINT32_MAX means "no EKU extension" (all purposes).
uint32_t leaf_eku_flags(const std::filesystem::path& pem_path) {
    std::string pem = read_file(pem_path);
    BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    REQUIRE(bio != nullptr);
    X509* x = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    REQUIRE(x != nullptr);
    uint32_t flags = X509_get_extended_key_usage(x); // forces the lazy EKU parse
    X509_free(x);
    return flags;
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

TEST_CASE("default_certs: leaf EKUs match each role (server is also a client — #1314)",
          "[default_certs]") {
    TempDir dir;
    DefaultCertSet set;
    REQUIRE(ensure_default_certs(dir.path, "test-host", nullptr, set));

    // The server forwards commands to the gateway's mgmt plane over MUTUAL TLS
    // (#1314), so it acts as a TLS *client* and its leaf MUST carry clientAuth in
    // addition to serverAuth — otherwise a strict verifier rejects it as a client
    // cert and the command-forwarding dial fails.
    const uint32_t server_eku = leaf_eku_flags(set.server_cert);
    REQUIRE((server_eku & XKU_SSL_SERVER) != 0);
    REQUIRE((server_eku & XKU_SSL_CLIENT) != 0);

    // The gateway is a server to agents AND a client to the server upstream.
    const uint32_t gateway_eku = leaf_eku_flags(set.gateway_cert);
    REQUIRE((gateway_eku & XKU_SSL_SERVER) != 0);
    REQUIRE((gateway_eku & XKU_SSL_CLIENT) != 0);

    // The HTTPS dashboard leaf is server-only — no need for clientAuth.
    const uint32_t https_eku = leaf_eku_flags(set.https_cert);
    REQUIRE((https_eku & XKU_SSL_SERVER) != 0);
    REQUIRE((https_eku & XKU_SSL_CLIENT) == 0);
}

TEST_CASE("default_certs: server leaves backdate notBefore by the clock-skew allowance (#1302)",
          "[default_certs]") {
    // An agent whose clock lags the server at first connect must not reject a
    // freshly-minted server leaf as not-yet-valid. The CA root + per-agent client
    // leaf already backdate notBefore by kClockSkewBackdate; this pins the same for
    // the server-facing default leaves (HTTPS / agent-gRPC / gateway), which the
    // PR3 H-2 fix had missed.
    TempDir dir;
    DefaultCertSet set;
    const auto now = std::chrono::system_clock::now();
    REQUIRE(ensure_default_certs(dir.path, "test-host", nullptr, set));
    // now is captured BEFORE generation, so notBefore <= now - backdate (minus a
    // little slack for test execution time). Use 280s against the 300s backdate.
    const auto floor = now - pki::kClockSkewBackdate + std::chrono::seconds(20);
    for (const auto& leaf : {set.https_cert, set.server_cert, set.gateway_cert}) {
        auto c = pki::parse_certificate(read_file(leaf));
        REQUIRE(c);
        REQUIRE(c->not_before <= floor); // genuinely backdated, not now()
    }
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
        "*.corp.example",      // wildcard → REJECTED (#1271 UP-10/11; fleet-trusted CA)
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
    // Wildcard REJECTED (#1271 UP-10/11): the install CA is distributed fleet-wide,
    // so a wildcard default leaf is not allowed — bring your own cert for that.
    REQUIRE_FALSE(contains(c->san.dns, "*.corp.example"));
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

TEST_CASE("default_certs: a --cert-san invalid-piece flood is bounded, not boot-fatal (#1271 UP-9)",
          "[default_certs]") {
    // The accepted-name cap counts only valid names; a flood of INVALID
    // comma-separated pieces (each dropped-with-warning) must still be bounded so
    // boot can't be CPU/log-flooded. One raw entry packed with thousands of bad
    // pieces must complete and still yield a valid cert set.
    TempDir dir;
    DefaultCertSet set;
    std::string flood = "with space"; // invalid (never accepted)
    for (int i = 0; i < 5000; ++i)
        flood += ",with space"; // 5001 invalid pieces in one raw entry
    REQUIRE(ensure_default_certs(dir.path, "h", nullptr, set, {flood}));
    REQUIRE(set.freshly_generated); // bounded + non-fatal
    auto c = pki::parse_certificate(read_file(set.gateway_cert));
    REQUIRE(c);
    REQUIRE_FALSE(contains(c->san.dns, "with space")); // none of the junk landed
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
    // ::1 parses back UNCOMPRESSED — warn_on_san_drift's deliberate IPv6 skip
    // depends on this form, so pin it (a future OpenSSL change would fail here).
    REQUIRE(contains(c->san.ips, "0:0:0:0:0:0:0:1"));
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

// ── --cert-group (multi-container shared-cert TLS, PKI #1289) ─────────────────
#ifndef _WIN32

namespace {
// {permission bits, owning gid} of a path; {0, -1} on stat failure.
std::pair<unsigned, gid_t> mode_and_gid(const std::filesystem::path& p) {
    struct stat st{};
    if (::stat(p.c_str(), &st) != 0)
        return {0u, static_cast<gid_t>(-1)};
    return {static_cast<unsigned>(st.st_mode) & 07777u, st.st_gid};
}
} // namespace

TEST_CASE("default_certs: --cert-group shares the dir + gateway key, keeps the rest tight",
          "[default_certs][security]") {
    TempDir dir;
    DefaultCertSet set;
    // Use the test process's OWN gid: chgrp to a group you belong to always
    // succeeds, so this drives the real apply_cert_group_share path deterministically.
    const std::string own_gid = std::to_string(static_cast<unsigned long>(::getgid()));
    REQUIRE(ensure_default_certs(dir.path, "h", nullptr, set, {}, own_gid));

    // Cert dir: 0750 + chgrp'd to the shared group (so a different-uid sibling
    // container can traverse it).
    auto [dmode, dgid] = mode_and_gid(dir.path);
    REQUIRE(dmode == 0750u);
    REQUIRE(dgid == ::getgid());

    // Gateway leaf key: group-readable (0640) for the gateway uid.
    auto [gkmode, gkgid] = mode_and_gid(set.gateway_key);
    REQUIRE(gkmode == 0640u);
    REQUIRE(gkgid == ::getgid());

    // The server + HTTPS private keys are NEVER group-shared — owner-only 0600.
    REQUIRE(mode_and_gid(set.server_key).first == 0600u);
    REQUIRE(mode_and_gid(set.https_key).first == 0600u);

    // Public certs stay world-readable (group + other read bits set).
    REQUIRE((mode_and_gid(set.ca_cert).first & 044u) == 044u);
}

TEST_CASE("default_certs: no --cert-group keeps the tight single-host posture (0700/0600)",
          "[default_certs][security]") {
    TempDir dir;
    DefaultCertSet set;
    REQUIRE(ensure_default_certs(dir.path, "h", nullptr, set)); // empty cert_group
    REQUIRE(mode_and_gid(dir.path).first == 0700u);             // owner-only dir
    REQUIRE(mode_and_gid(set.gateway_key).first == 0600u);      // key owner-only
}

TEST_CASE("default_certs: a bogus --cert-group falls back to tight perms (no boot-fail)",
          "[default_certs][security]") {
    TempDir dir;
    DefaultCertSet set;
    REQUIRE(ensure_default_certs(dir.path, "h", nullptr, set, {},
                                 "no-such-group-xyzzy-1289"));
    REQUIRE(mode_and_gid(dir.path).first == 0700u); // resolves nothing → tight
}

#endif // !_WIN32
