/**
 * test_x509_ca.cpp — Unit tests for the pure-OpenSSL PKI engine (PR1).
 *
 * Covers: EC keygen (P-256/P-384), self-signed CA shape + validity, CSR build,
 * CSR signing with proof-of-possession, the SECURITY invariant that sign_csr
 * ignores attacker-controlled CSR subject/SAN, one-shot leaf issuance, chain
 * verification (positive + negative), random serials, fingerprint format, and
 * CRL generation.
 *
 * The server test binary always compiles with CPPHTTPLIB_OPENSSL_SUPPORT
 * (tests/meson.build https_cpp_args), so the real implementation is under test.
 */

#include "x509_ca.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdlib>
#include <string>
#include <vector>

using namespace yuzu::server::pki;

namespace {

// Flip one base64 char in the SIGNATURE TAIL of a CSR PEM. The signature is the
// final DER element, so corrupting a tail content byte keeps the ASN.1 structure
// parseable (no length byte is touched) but breaks the self-signature — so it
// exercises sign_csr's proof-of-possession verify (X509_REQ_verify), a distinct
// code path from the PEM-parse rejection the garbage-blob test covers.
std::string tamper_csr_sig(std::string pem) {
    const auto body_begin = pem.find('\n', pem.find("BEGIN"));
    const auto body_end = pem.rfind("-----END");
    REQUIRE(body_begin != std::string::npos);
    REQUIRE(body_end != std::string::npos);
    auto is_b64 = [](char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
               c == '+' || c == '/';
    };
    std::vector<std::size_t> body_b64;
    for (std::size_t i = body_begin; i < body_end; ++i)
        if (is_b64(pem[i]))
            body_b64.push_back(i);
    REQUIRE(body_b64.size() > 16);
    // ~6 base64 chars (~4-5 bytes) before the end → inside the signature value.
    const std::size_t pos = body_b64[body_b64.size() - 6];
    pem[pos] = (pem[pos] == 'A') ? 'B' : 'A';
    return pem;
}

struct TestCa {
    std::string key;
    std::string cert;
};

// A fresh P-384 self-signed CA for tests that need an issuer.
TestCa make_test_ca(const std::string& cn = "Yuzu Test CA") {
    auto key = generate_private_key(KeyAlgo::EcP384);
    REQUIRE(key);
    CaParams p;
    p.subject = {cn, "Yuzu"};
    p.validity = validity_years_from_now(10);
    p.path_len = 0;
    auto cert = self_sign_ca(*key, p);
    REQUIRE(cert);
    return {*key, *cert};
}

bool contains(const std::vector<std::string>& v, const std::string& s) {
    return std::find(v.begin(), v.end(), s) != v.end();
}

} // namespace

TEST_CASE("x509_ca: generate EC keys", "[pki][keygen]") {
    auto p256 = generate_private_key(KeyAlgo::EcP256);
    auto p384 = generate_private_key(KeyAlgo::EcP384);
    REQUIRE(p256);
    REQUIRE(p384);
    REQUIRE(p256->find("PRIVATE KEY") != std::string::npos);
    REQUIRE(p384->find("PRIVATE KEY") != std::string::npos);
    // Two generations differ.
    auto p256b = generate_private_key(KeyAlgo::EcP256);
    REQUIRE(p256b);
    REQUIRE(*p256 != *p256b);
}

TEST_CASE("x509_ca: self-signed CA shape and validity", "[pki][ca]") {
    auto ca = make_test_ca("Yuzu Install CA");
    auto d = parse_certificate(ca.cert);
    REQUIRE(d);
    REQUIRE(d->is_ca);
    REQUIRE(d->subject.common_name == "Yuzu Install CA");
    REQUIRE(d->issuer.common_name == "Yuzu Install CA"); // self-signed

    const auto span = std::chrono::duration_cast<std::chrono::seconds>(d->not_after - d->not_before)
                          .count();
    const long ten_years = 10L * 31557600L;
    REQUIRE(std::abs(span - ten_years) < 86400); // within a day
}

TEST_CASE("x509_ca: sign CSR produces a verifiable leaf", "[pki][leaf]") {
    auto ca = make_test_ca();
    auto leaf_key = generate_private_key(KeyAlgo::EcP256);
    REQUIRE(leaf_key);

    CsrParams csr_p;
    csr_p.subject = {"agent-123", "Yuzu"};
    auto csr = make_csr(*leaf_key, csr_p);
    REQUIRE(csr);

    LeafParams lp;
    lp.subject = {"agent-123", "Yuzu"};
    lp.san.uris = {"yuzu://install-abc/agent/agent-123"};
    lp.validity = validity_days_from_now(365);
    lp.usage.client_auth = true;
    auto issued = sign_csr(*csr, ca.cert, ca.key, lp);
    REQUIRE(issued);
    REQUIRE_FALSE(issued->serial_hex.empty());
    REQUIRE(verify_chain(issued->cert_pem, ca.cert));

    auto d = parse_certificate(issued->cert_pem);
    REQUIRE(d);
    REQUIRE(d->subject.common_name == "agent-123");
    REQUIRE(d->issuer.common_name == "Yuzu Test CA");
    REQUIRE(contains(d->san.uris, "yuzu://install-abc/agent/agent-123"));
    REQUIRE_FALSE(d->is_ca);
}

// The core security property: sign_csr must take subject + SAN ONLY from the
// server-supplied params, never from the (attacker-controlled) CSR.
TEST_CASE("x509_ca: sign_csr ignores CSR-supplied subject and SAN", "[pki][leaf][security]") {
    auto ca = make_test_ca();
    auto leaf_key = generate_private_key(KeyAlgo::EcP256);
    REQUIRE(leaf_key);

    CsrParams evil;
    evil.subject = {"admin", "Megacorp"};
    evil.san.dns = {"evil.example.com"};
    evil.san.uris = {"yuzu://install-abc/agent/some-other-agent"};
    auto csr = make_csr(*leaf_key, evil);
    REQUIRE(csr);

    LeafParams good;
    good.subject = {"agent-7", "Yuzu"};
    good.san.uris = {"yuzu://install-abc/agent/agent-7"};
    good.validity = validity_days_from_now(365);
    good.usage.client_auth = true;
    auto issued = sign_csr(*csr, ca.cert, ca.key, good);
    REQUIRE(issued);

    auto d = parse_certificate(issued->cert_pem);
    REQUIRE(d);
    REQUIRE(d->subject.common_name == "agent-7");
    REQUIRE(contains(d->san.uris, "yuzu://install-abc/agent/agent-7"));
    // None of the attacker's requested identity survives.
    REQUIRE_FALSE(contains(d->san.dns, "evil.example.com"));
    REQUIRE_FALSE(contains(d->san.uris, "yuzu://install-abc/agent/some-other-agent"));
    REQUIRE(d->subject.common_name != "admin");
}

// Typed GENERAL_NAMES construction must treat a SAN value containing config
// metacharacters as a single literal entry — never split it into extra SANs.
TEST_CASE("x509_ca: SAN values cannot inject extra entries", "[pki][leaf][security]") {
    auto ca = make_test_ca();
    LeafParams lp;
    lp.subject = {"svc", "Yuzu"};
    // Under a config-string SAN builder this would have smuggled a second name.
    lp.san.dns = {"good.example,DNS:evil.example"};
    lp.validity = validity_days_from_now(365);
    lp.usage.server_auth = true;
    auto kc = issue_leaf(ca.cert, ca.key, KeyAlgo::EcP256, lp);
    REQUIRE(kc);
    auto d = parse_certificate(kc->cert_pem);
    REQUIRE(d);
    REQUIRE(d->san.dns.size() == 1);
    REQUIRE(d->san.dns[0] == "good.example,DNS:evil.example");
    REQUIRE_FALSE(contains(d->san.dns, "evil.example"));
}

TEST_CASE("x509_ca: leaf may not outlive the issuing CA", "[pki][leaf][security]") {
    // CA valid ~30 days; a leaf requesting 365 days must be rejected.
    auto ca_key = generate_private_key(KeyAlgo::EcP384);
    REQUIRE(ca_key);
    CaParams cp;
    cp.subject = {"Short CA", "Yuzu"};
    cp.validity = validity_days_from_now(30);
    auto ca_cert = self_sign_ca(*ca_key, cp);
    REQUIRE(ca_cert);
    LeafParams lp;
    lp.subject = {"leaf", "Yuzu"};
    lp.validity = validity_days_from_now(365); // outlives the 30-day CA
    lp.usage.server_auth = true;
    REQUIRE_FALSE(issue_leaf(*ca_cert, *ca_key, KeyAlgo::EcP256, lp));
}

TEST_CASE("x509_ca: sign_csr rejects a non-CSR blob", "[pki][leaf][negative]") {
    auto ca = make_test_ca();
    LeafParams lp;
    lp.subject = {"x", "Yuzu"};
    lp.validity = validity_days_from_now(30);
    lp.usage.client_auth = true;
    REQUIRE_FALSE(sign_csr("-----BEGIN CERTIFICATE REQUEST-----\nnotbase64\n", ca.cert, ca.key, lp));
    REQUIRE_FALSE(sign_csr("garbage", ca.cert, ca.key, lp));
}

TEST_CASE("x509_ca: issue_leaf returns key + chained cert", "[pki][leaf]") {
    auto ca = make_test_ca();
    LeafParams lp;
    lp.subject = {"https", "Yuzu"};
    lp.san.dns = {"localhost"};
    lp.san.ips = {"127.0.0.1"};
    lp.validity = validity_days_from_now(365);
    lp.usage.server_auth = true;
    auto kc = issue_leaf(ca.cert, ca.key, KeyAlgo::EcP256, lp);
    REQUIRE(kc);
    REQUIRE(kc->private_key_pem.find("PRIVATE KEY") != std::string::npos);
    REQUIRE(verify_chain(kc->cert_pem, ca.cert));

    auto d = parse_certificate(kc->cert_pem);
    REQUIRE(d);
    REQUIRE(d->subject.common_name == "https");
    REQUIRE(contains(d->san.dns, "localhost"));
    REQUIRE(contains(d->san.ips, "127.0.0.1"));
}

TEST_CASE("x509_ca: serials are unique per issuance", "[pki][serial]") {
    auto ca = make_test_ca();
    LeafParams lp;
    lp.subject = {"n", "Yuzu"};
    lp.validity = validity_days_from_now(30);
    lp.usage.server_auth = true;
    auto a = issue_leaf(ca.cert, ca.key, KeyAlgo::EcP256, lp);
    auto b = issue_leaf(ca.cert, ca.key, KeyAlgo::EcP256, lp);
    REQUIRE(a);
    REQUIRE(b);
    REQUIRE(a->serial_hex != b->serial_hex);
}

TEST_CASE("x509_ca: verify_chain rejects a foreign issuer", "[pki][verify][negative]") {
    auto ca1 = make_test_ca("CA One");
    auto ca2 = make_test_ca("CA Two");
    LeafParams lp;
    lp.subject = {"leaf", "Yuzu"};
    lp.validity = validity_days_from_now(30);
    lp.usage.server_auth = true;
    auto leaf = issue_leaf(ca1.cert, ca1.key, KeyAlgo::EcP256, lp);
    REQUIRE(leaf);
    REQUIRE(verify_chain(leaf->cert_pem, ca1.cert));
    REQUIRE_FALSE(verify_chain(leaf->cert_pem, ca2.cert));
}

TEST_CASE("x509_ca: fingerprint format is stable colon-hex", "[pki][fingerprint]") {
    auto ca = make_test_ca();
    auto fp = fingerprint_sha256(ca.cert);
    REQUIRE(fp);
    REQUIRE(fp->size() == 95); // 32 bytes -> 64 hex + 31 colons
    REQUIRE((*fp)[2] == ':');
    auto fp2 = fingerprint_sha256(ca.cert);
    REQUIRE(fp2);
    REQUIRE(*fp == *fp2); // deterministic

    auto other = make_test_ca("Different");
    auto fp_other = fingerprint_sha256(other.cert);
    REQUIRE(fp_other);
    REQUIRE(*fp != *fp_other);
}

TEST_CASE("x509_ca: build CRL over revoked serials", "[pki][crl]") {
    auto ca = make_test_ca();
    LeafParams lp;
    lp.subject = {"leaf", "Yuzu"};
    lp.validity = validity_days_from_now(30);
    lp.usage.client_auth = true;
    auto leaf = issue_leaf(ca.cert, ca.key, KeyAlgo::EcP256, lp);
    REQUIRE(leaf);

    std::vector<CrlRevocation> revoked = {
        {leaf->serial_hex, std::chrono::system_clock::now()},
    };
    auto der = build_crl(ca.cert, ca.key, revoked, validity_days_from_now(7), 1);
    REQUIRE(der);
    REQUIRE_FALSE(der->empty());

    // An empty CRL (nothing revoked yet) is still valid + signable.
    auto empty = build_crl(ca.cert, ca.key, {}, validity_days_from_now(7), 2);
    REQUIRE(empty);
    REQUIRE_FALSE(empty->empty());
}

TEST_CASE("x509_ca: build_crl fails closed on a bad serial", "[pki][crl][security]") {
    auto ca = make_test_ca();
    // A non-hex serial must abort CRL generation, never be silently dropped
    // (a dropped revocation = a cert that still validates).
    std::vector<CrlRevocation> bad = {{"not-hex-!!", std::chrono::system_clock::now()}};
    REQUIRE_FALSE(build_crl(ca.cert, ca.key, bad, validity_days_from_now(7), 3));
    std::vector<CrlRevocation> empty_serial = {{"", std::chrono::system_clock::now()}};
    REQUIRE_FALSE(build_crl(ca.cert, ca.key, empty_serial, validity_days_from_now(7), 4));
}

TEST_CASE("x509_ca: verify_chain rejects an expired leaf", "[pki][verify][negative][security]") {
    // verify_chain must enforce the validity window (it backs the mTLS-accept
    // gate). Issue a leaf entirely in the past and confirm it does NOT verify,
    // even though it chains to and was signed by the CA.
    auto ca = make_test_ca();
    LeafParams lp;
    lp.subject = {"agent-expired", "Yuzu"};
    lp.usage.client_auth = true;
    const auto now = std::chrono::system_clock::now();
    lp.validity = Validity{now - std::chrono::hours(24 * 800), now - std::chrono::hours(24 * 400)};
    auto kc = issue_leaf(ca.cert, ca.key, KeyAlgo::EcP256, lp);
    REQUIRE(kc); // a past-dated leaf still issues (notAfter < CA notAfter)...
    REQUIRE_FALSE(verify_chain(kc->cert_pem, ca.cert)); // ...but must not verify (expired)
}

TEST_CASE("x509_ca: sign_csr rejects a tampered CSR signature",
          "[pki][leaf][negative][security]") {
    // Proof-of-possession: a CSR whose self-signature does not match its key must
    // be refused. This hits X509_REQ_verify — distinct from the garbage-blob test
    // (which fails at PEM parse). The pristine CSR signs fine; flipping one byte
    // of its signature tail (still parseable) must flip the result to rejected.
    auto ca = make_test_ca();
    auto key = generate_private_key(KeyAlgo::EcP256);
    REQUIRE(key);
    CsrParams cp;
    cp.subject = {"agent-pop", "Yuzu"};
    auto csr = make_csr(*key, cp);
    REQUIRE(csr);

    LeafParams lp;
    lp.subject = {"agent-pop", "Yuzu"};
    lp.validity = validity_days_from_now(30);
    REQUIRE(sign_csr(*csr, ca.cert, ca.key, lp)); // pristine: POP holds

    const std::string tampered = tamper_csr_sig(*csr);
    REQUIRE(tampered != *csr);
    REQUIRE_FALSE(sign_csr(tampered, ca.cert, ca.key, lp)); // tampered: POP fails
}

TEST_CASE("x509_ca: fingerprint/parse reject non-cert input", "[pki][negative]") {
    REQUIRE_FALSE(fingerprint_sha256("not a certificate"));
    REQUIRE_FALSE(parse_certificate("garbage"));
    REQUIRE_FALSE(fingerprint_sha256("")); // empty rejected by the size guard
}
