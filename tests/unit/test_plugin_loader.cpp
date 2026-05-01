#include <yuzu/agent/plugin_loader.hpp>

#include <catch2/catch_test_macros.hpp>

#include <openssl/bio.h>
// pem.h must come before cms.h so the PEM_*_CMS macros are declared
// (cms.h gates them on OPENSSL_PEM_H).
#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <memory>
#include <random>
#include <string>
#include <system_error>

namespace fs = std::filesystem;

namespace {

#ifdef _WIN32
constexpr const char* kPluginExt = ".dll";
#elif defined(__APPLE__)
constexpr const char* kPluginExt = ".dylib";
#else
constexpr const char* kPluginExt = ".so";
#endif

// Locate the reserved-name fixture plugin built by tests/meson.build
// (`reserved_name_fixture_plugin`). Returns empty path if not found —
// tests that require the fixture should SKIP rather than FAIL to keep
// cross-compile / restricted-CI scenarios quiet.
fs::path find_reserved_fixture_plugin() {
    const std::string lib_name = std::string{"reserved_name_fixture_plugin"} + kPluginExt;

    std::vector<fs::path> candidates;
    if (auto* build_root = std::getenv("MESON_BUILD_ROOT")) {
        candidates.emplace_back(fs::path{build_root} / "tests" / lib_name);
    }
    // Meson launches tests with CWD=build root; tests/ sits alongside the exe.
    candidates.emplace_back(fs::path{"tests"} / lib_name);
    candidates.emplace_back(fs::path{"."} / lib_name);

    for (const auto& p : candidates) {
        std::error_code ec;
        if (fs::exists(p, ec) && !ec) return fs::absolute(p, ec);
    }
    return {};
}

// ── Code-signing test fixtures ───────────────────────────────────────────────
//
// Generate an in-memory CA + signing leaf at test time (no on-disk fixtures
// to expire / drift) and use OpenSSL CMS_sign to produce the detached PEM
// signature the verifier expects. Returns the temp-dir path holding:
//   * trust-bundle.pem    — the CA cert (verifier trust anchor)
//   * other-trust.pem     — a *different* CA cert (used to test "untrusted")
//   * plugin.bin          — a plugin-shaped file (does not need to be a
//                           valid .so for verifier-only tests)
//   * plugin.bin.sig      — PEM CMS detached sig over plugin.bin
//
// All OpenSSL handles are unique_ptr-owned; an OpenSSL failure inside
// build_signing_fixtures() trips a REQUIRE so the test fails loudly rather
// than producing partial state.

struct SslFreer {
    void operator()(BIO* p) const noexcept { BIO_free_all(p); }
    void operator()(EVP_PKEY* p) const noexcept { EVP_PKEY_free(p); }
    void operator()(EVP_PKEY_CTX* p) const noexcept { EVP_PKEY_CTX_free(p); }
    void operator()(X509* p) const noexcept { X509_free(p); }
    void operator()(X509_NAME* p) const noexcept { X509_NAME_free(p); }
    void operator()(CMS_ContentInfo* p) const noexcept { CMS_ContentInfo_free(p); }
};
template <typename T>
using ssl_ptr = std::unique_ptr<T, SslFreer>;

ssl_ptr<EVP_PKEY> generate_ec_key() {
    ssl_ptr<EVP_PKEY_CTX> ctx{EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr)};
    REQUIRE(ctx);
    REQUIRE(EVP_PKEY_keygen_init(ctx.get()) == 1);
    REQUIRE(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(), NID_X9_62_prime256v1) == 1);
    EVP_PKEY* raw = nullptr;
    REQUIRE(EVP_PKEY_keygen(ctx.get(), &raw) == 1);
    return ssl_ptr<EVP_PKEY>{raw};
}

ssl_ptr<X509> mint_cert(EVP_PKEY* subject_key, EVP_PKEY* issuer_key,
                        X509* issuer_cert, const std::string& cn,
                        bool is_ca) {
    ssl_ptr<X509> cert{X509_new()};
    REQUIRE(cert);
    REQUIRE(X509_set_version(cert.get(), 2) == 1);
    ASN1_INTEGER_set(X509_get_serialNumber(cert.get()),
                     static_cast<long>(std::random_device{}()));
    X509_gmtime_adj(X509_getm_notBefore(cert.get()), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert.get()), 60 * 60 * 24);

    X509_NAME* name = X509_get_subject_name(cert.get());
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>(cn.c_str()), -1,
                               -1, 0);
    if (issuer_cert) {
        REQUIRE(X509_set_issuer_name(cert.get(), X509_get_subject_name(issuer_cert)) == 1);
    } else {
        REQUIRE(X509_set_issuer_name(cert.get(), name) == 1); // self-signed CA
    }
    REQUIRE(X509_set_pubkey(cert.get(), subject_key) == 1);

    // Basic constraints — distinguishes CA cert from leaf so the verifier's
    // chain check is meaningful.
    X509V3_CTX v3ctx;
    X509V3_set_ctx_nodb(&v3ctx);
    X509V3_set_ctx(&v3ctx, issuer_cert ? issuer_cert : cert.get(), cert.get(), nullptr,
                   nullptr, 0);
    const char* bc = is_ca ? "critical,CA:TRUE" : "critical,CA:FALSE";
    if (auto* ext = X509V3_EXT_conf_nid(nullptr, &v3ctx, NID_basic_constraints,
                                        const_cast<char*>(bc))) {
        X509_add_ext(cert.get(), ext, -1);
        X509_EXTENSION_free(ext);
    }
    if (!is_ca) {
        if (auto* ext = X509V3_EXT_conf_nid(nullptr, &v3ctx, NID_ext_key_usage,
                                            const_cast<char*>("codeSigning"))) {
            X509_add_ext(cert.get(), ext, -1);
            X509_EXTENSION_free(ext);
        }
    }

    REQUIRE(X509_sign(cert.get(), issuer_key, EVP_sha256()) > 0);
    return cert;
}

void write_pem_cert(const fs::path& path, X509* cert) {
    ssl_ptr<BIO> bio{BIO_new_file(path.string().c_str(), "wb")};
    REQUIRE(bio);
    REQUIRE(PEM_write_bio_X509(bio.get(), cert) == 1);
}

void write_cms_signature(const fs::path& sig_path, const fs::path& payload_path,
                         X509* leaf_cert, EVP_PKEY* leaf_key) {
    ssl_ptr<BIO> in{BIO_new_file(payload_path.string().c_str(), "rb")};
    REQUIRE(in);
    ssl_ptr<CMS_ContentInfo> cms{CMS_sign(leaf_cert, leaf_key, nullptr, in.get(),
                                          CMS_BINARY | CMS_DETACHED | CMS_PARTIAL)};
    REQUIRE(cms);
    REQUIRE(CMS_final(cms.get(), in.get(), nullptr, CMS_BINARY | CMS_DETACHED) == 1);
    ssl_ptr<BIO> out{BIO_new_file(sig_path.string().c_str(), "wb")};
    REQUIRE(out);
    REQUIRE(PEM_write_bio_CMS(out.get(), cms.get()) == 1);
}

struct SigningFixtures {
    fs::path dir;
    fs::path trust_bundle;       // matching CA
    fs::path other_trust_bundle; // different CA (for untrusted tests)
    fs::path plugin_file;
    fs::path sig_file;

    ~SigningFixtures() {
        std::error_code ec;
        fs::remove_all(dir, ec);
    }
};

SigningFixtures build_signing_fixtures() {
    SigningFixtures f;
    std::random_device rd;
    std::mt19937_64 gen(rd());
    f.dir = fs::temp_directory_path() / ("yuzu_test_plugin_sign_" + std::to_string(gen()));
    fs::create_directories(f.dir);

    // Trusted CA + leaf
    auto ca_key = generate_ec_key();
    auto ca_cert = mint_cert(ca_key.get(), ca_key.get(), nullptr, "Yuzu Test CA", true);
    auto leaf_key = generate_ec_key();
    auto leaf_cert = mint_cert(leaf_key.get(), ca_key.get(), ca_cert.get(),
                               "Yuzu Test Plugin Signer", false);

    // A *different* CA used as the "wrong trust bundle" anchor
    auto other_key = generate_ec_key();
    auto other_cert =
        mint_cert(other_key.get(), other_key.get(), nullptr, "Other CA", true);

    f.trust_bundle = f.dir / "trust-bundle.pem";
    f.other_trust_bundle = f.dir / "other-trust.pem";
    write_pem_cert(f.trust_bundle, ca_cert.get());
    write_pem_cert(f.other_trust_bundle, other_cert.get());

    // Plugin payload — opaque bytes; verifier doesn't dlopen, just hashes
    f.plugin_file = f.dir / "plugin.bin";
    {
        std::ofstream pf(f.plugin_file, std::ios::binary);
        pf << "Yuzu plugin test payload\n0123456789abcdef\n";
    }

    f.sig_file = f.dir / "plugin.bin.sig";
    write_cms_signature(f.sig_file, f.plugin_file, leaf_cert.get(), leaf_key.get());

    return f;
}

} // namespace

TEST_CASE("PluginLoader returns empty result for nonexistent directory", "[plugin_loader]") {
    auto result = yuzu::agent::PluginLoader::scan("/nonexistent/path");
    REQUIRE(result.loaded.empty());
    REQUIRE(result.errors.empty());
}

TEST_CASE("PluginLoader returns empty result for empty directory", "[plugin_loader]") {
    auto tmp = fs::temp_directory_path() / "yuzu_test_empty_plugins";
    fs::create_directories(tmp);

    auto result = yuzu::agent::PluginLoader::scan(tmp);
    REQUIRE(result.loaded.empty());
    REQUIRE(result.errors.empty());

    fs::remove(tmp);
}

// ── #453 reserved-name namespace ─────────────────────────────────────────────

TEST_CASE("is_reserved_plugin_name matches the reserved set", "[plugin_loader][reserved_name]") {
    using yuzu::agent::is_reserved_plugin_name;

    REQUIRE(is_reserved_plugin_name("__guard__"));
    REQUIRE(is_reserved_plugin_name("__system__"));
    REQUIRE(is_reserved_plugin_name("__update__"));

    // Match must be exact (case-sensitive, no substring / prefix relaxation).
    REQUIRE_FALSE(is_reserved_plugin_name(""));
    REQUIRE_FALSE(is_reserved_plugin_name("example"));
    REQUIRE_FALSE(is_reserved_plugin_name("__GUARD__"));
    REQUIRE_FALSE(is_reserved_plugin_name("__guard"));
    REQUIRE_FALSE(is_reserved_plugin_name("_guard_"));
    REQUIRE_FALSE(is_reserved_plugin_name("x__guard__"));
    REQUIRE_FALSE(is_reserved_plugin_name("__guard__ "));
}

TEST_CASE("kReservedPluginNames covers guardian, system, update",
          "[plugin_loader][reserved_name]") {
    // Sanity-check the exact namespace. If a new reserved name is added,
    // this test is the deliberate trip-wire reminding authors to update
    // docs/cpp-conventions.md and the plugin ABI reference.
    REQUIRE(yuzu::agent::kReservedPluginNames.size() == 3);
    REQUIRE(yuzu::agent::kReservedPluginNames[0] == "__guard__");
    REQUIRE(yuzu::agent::kReservedPluginNames[1] == "__system__");
    REQUIRE(yuzu::agent::kReservedPluginNames[2] == "__update__");
}

// ── Code-signing tests (#80) ─────────────────────────────────────────────────

TEST_CASE("verify_plugin_signature accepts a valid CMS signature",
          "[plugin_loader][signing]") {
    auto fx = build_signing_fixtures();
    auto err = yuzu::agent::verify_plugin_signature(fx.plugin_file, fx.trust_bundle);
    INFO(err.value_or(""));
    REQUIRE_FALSE(err.has_value());
}

TEST_CASE("verify_plugin_signature reports kSignatureMissingReason when sig absent",
          "[plugin_loader][signing]") {
    auto fx = build_signing_fixtures();
    fs::remove(fx.sig_file);
    auto err = yuzu::agent::verify_plugin_signature(fx.plugin_file, fx.trust_bundle);
    REQUIRE(err.has_value());
    REQUIRE(err->starts_with(yuzu::agent::kSignatureMissingReason));
}

TEST_CASE("verify_plugin_signature rejects a tampered plugin file",
          "[plugin_loader][signing]") {
    auto fx = build_signing_fixtures();
    // Append a byte after signing — invalidates the digest.
    {
        std::ofstream pf(fx.plugin_file,
                         std::ios::binary | std::ios::app);
        pf << 'X';
    }
    auto err = yuzu::agent::verify_plugin_signature(fx.plugin_file, fx.trust_bundle);
    REQUIRE(err.has_value());
    // Tampered content fails the digest check, which OpenSSL surfaces as a
    // CMS-level error — kSignatureInvalidReason is the right bucket.
    REQUIRE(err->starts_with(yuzu::agent::kSignatureInvalidReason));
}

TEST_CASE("verify_plugin_signature rejects when chain does not anchor in bundle",
          "[plugin_loader][signing]") {
    auto fx = build_signing_fixtures();
    auto err = yuzu::agent::verify_plugin_signature(fx.plugin_file, fx.other_trust_bundle);
    REQUIRE(err.has_value());
    REQUIRE(err->starts_with(yuzu::agent::kSignatureUntrustedReason));
}

TEST_CASE("verify_plugin_signature rejects when trust bundle is unreadable",
          "[plugin_loader][signing]") {
    auto fx = build_signing_fixtures();
    auto err = yuzu::agent::verify_plugin_signature(fx.plugin_file,
                                                     fx.dir / "does-not-exist.pem");
    REQUIRE(err.has_value());
    REQUIRE(err->starts_with(yuzu::agent::kSignatureUntrustedReason));
}

TEST_CASE("verify_plugin_signature rejects malformed PEM in sig file",
          "[plugin_loader][signing]") {
    auto fx = build_signing_fixtures();
    {
        std::ofstream sigf(fx.sig_file, std::ios::binary | std::ios::trunc);
        sigf << "not a pem\n";
    }
    auto err = yuzu::agent::verify_plugin_signature(fx.plugin_file, fx.trust_bundle);
    REQUIRE(err.has_value());
    REQUIRE(err->starts_with(yuzu::agent::kSignatureInvalidReason));
}

TEST_CASE("PluginSigningPolicy::enabled flips with bundle path",
          "[plugin_loader][signing]") {
    yuzu::agent::PluginSigningPolicy off{};
    REQUIRE_FALSE(off.enabled());
    yuzu::agent::PluginSigningPolicy on{"/some/path.pem", false};
    REQUIRE(on.enabled());
}

TEST_CASE("PluginLoader::scan with require_signature on rejects unsigned plugin files",
          "[plugin_loader][signing]") {
    auto fx = build_signing_fixtures();
    auto plugin_dir = fx.dir / "plugins";
    fs::create_directories(plugin_dir);

    // Place an extension-correct file with no .sig sibling. require=true
    // means scan() must reject it before dlopen.
    auto plugin_path = plugin_dir / (std::string{"unsigned"} + kPluginExt);
    {
        std::ofstream pf(plugin_path, std::ios::binary);
        pf << "fake plugin bytes";
    }

    yuzu::agent::PluginSigningPolicy policy{fx.trust_bundle, /*require_signature=*/true};
    auto result = yuzu::agent::PluginLoader::scan(plugin_dir, {}, policy);
    REQUIRE(result.loaded.empty());
    REQUIRE(result.errors.size() == 1);
    REQUIRE(result.errors.front().reason.starts_with(
        yuzu::agent::kSignatureMissingReason));
}

TEST_CASE("PluginLoader rejects a plugin declaring a reserved name",
          "[plugin_loader][reserved_name]") {
    auto fixture = find_reserved_fixture_plugin();
    if (fixture.empty()) {
        WARN("reserved_name_fixture_plugin not found — skipping behavioral scan test");
        SUCCEED();
        return;
    }

    // Copy the fixture into an isolated directory so we scan only it —
    // avoids false positives from stray built plugins that may live in a
    // shared tree when run from the build root. Unique per-invocation name
    // is generated from mt19937_64 rather than ::getpid() so the code
    // compiles on MSVC (`_getpid` in <process.h>) and Apple Clang
    // (`<unistd.h>` not transitively available) without per-platform
    // guards. Same pattern sibling store tests use.
    std::random_device rd;
    std::mt19937_64 gen(rd());
    auto tmp = fs::temp_directory_path() /
               ("yuzu_test_reserved_plugin_" + std::to_string(gen()));
    fs::create_directories(tmp);
    auto staged = tmp / fixture.filename();
    std::error_code ec;
    fs::copy_file(fixture, staged, fs::copy_options::overwrite_existing, ec);
    REQUIRE_FALSE(ec);

    auto result = yuzu::agent::PluginLoader::scan(tmp);

    // Must not appear in loaded — nothing under __guard__ may be handed
    // to the dispatcher.
    REQUIRE(result.loaded.empty());

    // Must appear in errors with the stable reason prefix so the agent
    // metric can categorise it.
    REQUIRE(result.errors.size() == 1);
    const auto& err = result.errors.front();
    REQUIRE(err.path == staged.string());
    REQUIRE(err.reason.starts_with(yuzu::agent::kReservedNameReason));
    REQUIRE(err.reason.find("__guard__") != std::string::npos);

    fs::remove_all(tmp);
}
