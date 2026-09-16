/**
 * test_cert_scan_rules.cpp -- unit tests for cert_scan_rules.hpp, the pure
 * classification layer of the cert_scan plugin (private-key/certificate/
 * CSR/container detection and severity assignment). Every test runs
 * against in-memory strings only -- no filesystem, no real key material --
 * mirroring test_certificates_x509.cpp's own "pure header, pure test"
 * split.
 */

#include <catch2/catch_test_macros.hpp>

#include <cert_scan_rules.hpp>

#include <cstdint>
#include <openssl/evp.h>
#include <string>
#include <vector>

using namespace yuzu::cert_scan;
using yuzu::certificates_x509::CertFields;

namespace {

// ── Real self-signed capture, reused verbatim from
// tests/unit/test_certificates_x509.cpp's kRealSystemDefaultCertPem
// (see that file for full provenance) -- a genuine macOS system-identity
// certificate where subject == issuer, notBefore=2022-10-08,
// notAfter=2042-10-03 (valid for the lifetime of this test suite).
constexpr const char* kSelfSignedValidCertPem = R"(-----BEGIN CERTIFICATE-----
MIIDPzCCAiegAwIBAgIEWrRdxjANBgkqhkiG9w0BAQsFADA8MSAwHgYDVQQDDBdj
b20uYXBwbGUuc3lzdGVtZGVmYXVsdDEYMBYGA1UECgwPU3lzdGVtIElkZW50aXR5
MB4XDTIyMTAwODIxMjgzOVoXDTQyMTAwMzIxMjgzOVowPDEgMB4GA1UEAwwXY29t
LmFwcGxlLnN5c3RlbWRlZmF1bHQxGDAWBgNVBAoMD1N5c3RlbSBJZGVudGl0eTCC
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKgl58SsQSJ+XhqHn/XgwSHK
YM3M5nhVkSl/xKiz1jvKYBtvWjvlSDTQy5mQ7hRk7Qj/2EJSDiIl9AhD0qPU2M8c
IdL6pn7mfJVUVEK/unhKvr5nJEfdXKIhc8DontIPLDEW1xUbxVGkA4zeozIAjo8l
DirhbhmZ1LLtuNzfZub295UQp7iOizPYol8hwWqtVRZeG2ouqN/8vlk+TUQlRI21
UR8eUufjH3uDEFSJkf55eIxQz4HD6eKzKBazilKiUE/kzUUaVqDNd/W0Z0ERDLic
6cK+TEQsdmv0zunklKKM8dMu3TADoj8orQdgjWkcNLlKiREsCWsOI8xAqPJL9lkC
AwEAAaNJMEcwCwYDVR0PBAQDAgSwMCIGA1UdEQQbMBmCF2NvbS5hcHBsZS5zeXN0
ZW1kZWZhdWx0MBQGA1UdJQQNMAsGCSqGSIb3Y2QEBDANBgkqhkiG9w0BAQsFAAOC
AQEAVGS+UbSwKPq38g/VSlBEK45MpSuB8zRF36u3jAMLWhd5iAENEygNsHMFnqyy
gk+6lM0x8K2hA2hZvPFycP5ZUQyUqiXR1234mJ7brQgIrl2wJxX6Sz7FtkYpGg2Z
jQxT6pxDxqw2RJbIz4Kox+TTFvV/Sx/4AmdJN9OVZfkDYlYTiVkC9g3kUBUrzSeO
qgTqw72AadP8OqSJykLIF9xs29w5FVr36Jh370i58w+qy3KU7o6gwWWhfVVBjjBV
lLRWW0KknzZSXMWXM78/qPe8IDBQElKg+qAceQD2zB91por6QerRkdXmtl0CtsuP
vp7XnhPLblSLFY/trPrbGXu7Cw==
-----END CERTIFICATE-----
)";

// ── Synthetic: expired cert (notAfter 2021-01-01), reused verbatim from
// test_certificates_x509.cpp's kExpiredCertPem. Self-signed too (`openssl
// req -x509` always produces a self-signed cert), which is fine -- the
// expired-detection test below only cares about is_expired(), not
// certificate_severity()'s combined ladder.
constexpr const char* kExpiredCertPem = R"(-----BEGIN CERTIFICATE-----
MIIDDzCCAfegAwIBAgIUX8xgpbv8KmYlEwrbELUGcKyR9/UwDQYJKoZIhvcNAQEL
BQAwFzEVMBMGA1UEAwwMZXhwaXJlZC1jZXJ0MB4XDTIwMDEwMTAwMDAwMFoXDTIx
MDEwMTAwMDAwMFowFzEVMBMGA1UEAwwMZXhwaXJlZC1jZXJ0MIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy1v4DkKI0Z9BtOLs2+4ji7IH0MT7U8LXzcdz
80j7drbdmflwf2zKyhqDFfCE52FdU/ANPl3lHuWCuc/UVD6DVqOwkwO4ekvvtUVQ
SH6mbLA4BSCbp3gmyqDgaEVfNsAM7DHMTsqLfbDejTilnjzzHeHcuNbsxMH7T6Qy
aIIaMUOHygElarat5eMx19CVDBhy0JrAVMaBku4ceSWP5ipVOqzlhcLgBBfT8p+/
KdzcKGyjYgvipgudfJXZpqk6axBh6xssQsIkuqcXmDkQz77giQUXKlFIB0KlaCoX
A6juPS9XpyWqKQ2iRG5nnqL9VMoilnIskQdnNbL2UVe+lbZdSwIDAQABo1MwUTAd
BgNVHQ4EFgQU4t2+TPyG/2UIM9FZyNJN+IvCWTQwHwYDVR0jBBgwFoAU4t2+TPyG
/2UIM9FZyNJN+IvCWTQwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOC
AQEAXU1ZWlOCFz+ELy52lpYHQPwSMh71WlCecB+jstMZ+o09QflAVRKdwNVa0hKd
nihJSegSoUmC/7RjW/zfwvsO8EMlEeTW06pHkSmOtsbLGlCRVDHJYrsXOlY3nswi
ZypRgumWMByvdI17Ut5out0FitkOL/oprTYygH+An2tiwY5SDW2pkwFNkjGaUm97
fx+rQf0UN4NIjHL0BGNaj6EhyrtmHlPDKy3GaVOwS1bfuXDY8RJJY5D3k/B1eWI7
0m2/xMhhdltL3KzXWsGs5uExMvkNPEH2RC5Y41h4Q2A/gK2LD2j01X7htmZ6fHAH
o1O+mvv2u0O0bWUxE6ID/fdNuQ==
-----END CERTIFICATE-----
)";

/// Builds a synthetic OpenSSH private-key-shaped base64 body: the real
/// "openssh-key-v1\0" magic + a length-prefixed ciphername, base64-encoded
/// -- exactly the prefix openssh_key_encryption() reads, padded with
/// trailing zero bytes so the decode has enough length to work with. The
/// rest of a real OpenSSH key body (kdfname/kdfoptions/pubkeys/private
/// section) is irrelevant to this function, which only ever reads the
/// ciphername field.
std::string make_openssh_body(const std::string& cipher_name) {
    std::vector<unsigned char> raw;
    static constexpr char kMagic[] = "openssh-key-v1"; // 14 chars + implicit NUL below
    raw.insert(raw.end(), kMagic, kMagic + 14);
    raw.push_back('\0');
    std::uint32_t len = static_cast<std::uint32_t>(cipher_name.size());
    raw.push_back(static_cast<unsigned char>((len >> 24) & 0xFF));
    raw.push_back(static_cast<unsigned char>((len >> 16) & 0xFF));
    raw.push_back(static_cast<unsigned char>((len >> 8) & 0xFF));
    raw.push_back(static_cast<unsigned char>(len & 0xFF));
    raw.insert(raw.end(), cipher_name.begin(), cipher_name.end());
    // Padding so the decoded buffer comfortably exceeds the 20-byte floor
    // openssh_key_encryption() requires before it even looks at the magic.
    raw.resize(raw.size() + 32, 0);

    std::vector<unsigned char> encoded(raw.size() * 2 + 16);
    int n = EVP_EncodeBlock(encoded.data(), raw.data(), static_cast<int>(raw.size()));
    return std::string(reinterpret_cast<const char*>(encoded.data()), static_cast<std::size_t>(n));
}

} // namespace

// ── Self-signed / expired detection (pure CertFields input, no parsing) ──

TEST_CASE("is_self_signed: subject == issuer", "[cert_scan]") {
    CertFields f;
    f.subject = "CN=example";
    f.issuer = "CN=example";
    CHECK(is_self_signed(f));
}

TEST_CASE("is_self_signed: subject != issuer", "[cert_scan]") {
    CertFields f;
    f.subject = "CN=leaf";
    f.issuer = "CN=some-ca";
    CHECK_FALSE(is_self_signed(f));
}

TEST_CASE("is_self_signed: unknown subject never matches", "[cert_scan]") {
    CertFields f; // defaults: subject == issuer == "(unknown)"
    CHECK_FALSE(is_self_signed(f));
}

TEST_CASE("is_expired: past notAfter is expired", "[cert_scan]") {
    CertFields f;
    f.not_after = "2021-01-01";
    auto result = is_expired(f, "2026-09-16");
    REQUIRE(result.has_value());
    CHECK(*result);
}

TEST_CASE("is_expired: future notAfter is not expired", "[cert_scan]") {
    CertFields f;
    f.not_after = "2042-10-03";
    auto result = is_expired(f, "2026-09-16");
    REQUIRE(result.has_value());
    CHECK_FALSE(*result);
}

TEST_CASE("is_expired: unknown date is undeterminable", "[cert_scan]") {
    CertFields f; // not_after defaults to "(unknown)"
    CHECK_FALSE(is_expired(f, "2026-09-16").has_value());
}

TEST_CASE("certificate_severity: self-signed and valid-dated is Medium", "[cert_scan]") {
    CertFields f;
    f.subject = "CN=x";
    f.issuer = "CN=x";
    f.not_after = "2099-01-01";
    CHECK(certificate_severity(f, "2026-09-16") == Severity::Medium);
}

TEST_CASE("certificate_severity: expired but not self-signed is Medium", "[cert_scan]") {
    CertFields f;
    f.subject = "CN=leaf";
    f.issuer = "CN=ca";
    f.not_after = "2021-01-01";
    CHECK(certificate_severity(f, "2026-09-16") == Severity::Medium);
}

TEST_CASE("certificate_severity: valid and not self-signed is Low", "[cert_scan]") {
    CertFields f;
    f.subject = "CN=leaf";
    f.issuer = "CN=ca";
    f.not_after = "2099-01-01";
    CHECK(certificate_severity(f, "2026-09-16") == Severity::Low);
}

// ── PEM marker detection ─────────────────────────────────────────────────

TEST_CASE("contains_private_key_marker: detects every recognized header", "[cert_scan]") {
    CHECK(contains_private_key_marker("-----BEGIN PRIVATE KEY-----\nx\n"));
    CHECK(contains_private_key_marker("-----BEGIN ENCRYPTED PRIVATE KEY-----\nx\n"));
    CHECK(contains_private_key_marker("-----BEGIN RSA PRIVATE KEY-----\nx\n"));
    CHECK(contains_private_key_marker("-----BEGIN EC PRIVATE KEY-----\nx\n"));
    CHECK(contains_private_key_marker("-----BEGIN DSA PRIVATE KEY-----\nx\n"));
    CHECK(contains_private_key_marker("-----BEGIN OPENSSH PRIVATE KEY-----\nx\n"));
}

TEST_CASE("contains_private_key_marker: public key is not a private-key marker", "[cert_scan]") {
    CHECK_FALSE(contains_private_key_marker("-----BEGIN PUBLIC KEY-----\nx\n"));
}

TEST_CASE("contains_csr_marker: both CSR header variants", "[cert_scan]") {
    CHECK(contains_csr_marker("-----BEGIN CERTIFICATE REQUEST-----\nx\n"));
    CHECK(contains_csr_marker("-----BEGIN NEW CERTIFICATE REQUEST-----\nx\n"));
}

// ── classify_content: private keys ───────────────────────────────────────

TEST_CASE("classify_content: unencrypted PKCS8 private key is Critical", "[cert_scan]") {
    auto findings = classify_content(
        "-----BEGIN PRIVATE KEY-----\nMIIFake==\n-----END PRIVATE KEY-----\n", "2026-09-16");
    REQUIRE(findings.size() == 1);
    CHECK(findings[0].kind == FindingKind::PrivateKeyUnencrypted);
    CHECK(findings[0].severity == Severity::Critical);
}

TEST_CASE("classify_content: encrypted PKCS8 private key is High", "[cert_scan]") {
    auto findings = classify_content(
        "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIFake==\n-----END ENCRYPTED PRIVATE KEY-----\n",
        "2026-09-16");
    REQUIRE(findings.size() == 1);
    CHECK(findings[0].kind == FindingKind::PrivateKeyEncrypted);
    CHECK(findings[0].severity == Severity::High);
}

TEST_CASE("classify_content: traditional RSA key without Proc-Type is Critical", "[cert_scan]") {
    auto findings = classify_content(
        "-----BEGIN RSA PRIVATE KEY-----\nMIIFake==\n-----END RSA PRIVATE KEY-----\n", "2026-09-16");
    REQUIRE(findings.size() == 1);
    CHECK(findings[0].kind == FindingKind::PrivateKeyUnencrypted);
    CHECK(findings[0].severity == Severity::Critical);
}

TEST_CASE("classify_content: traditional RSA key with Proc-Type header is High", "[cert_scan]") {
    auto findings = classify_content(
        "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,ABCD\n\n"
        "MIIFake==\n-----END RSA PRIVATE KEY-----\n",
        "2026-09-16");
    REQUIRE(findings.size() == 1);
    CHECK(findings[0].kind == FindingKind::PrivateKeyEncrypted);
    CHECK(findings[0].severity == Severity::High);
}

TEST_CASE("classify_content: EC and DSA traditional keys are detected independently",
         "[cert_scan]") {
    auto ec = classify_content("-----BEGIN EC PRIVATE KEY-----\nMIIFake==\n-----END EC PRIVATE KEY-----\n",
                               "2026-09-16");
    REQUIRE(ec.size() == 1);
    CHECK(ec[0].kind == FindingKind::PrivateKeyUnencrypted);

    auto dsa = classify_content(
        "-----BEGIN DSA PRIVATE KEY-----\nMIIFake==\n-----END DSA PRIVATE KEY-----\n", "2026-09-16");
    REQUIRE(dsa.size() == 1);
    CHECK(dsa[0].kind == FindingKind::PrivateKeyUnencrypted);
}

TEST_CASE("classify_content: OpenSSH key with cipher \"none\" is Critical", "[cert_scan]") {
    std::string body = make_openssh_body("none");
    std::string content =
        "-----BEGIN OPENSSH PRIVATE KEY-----\n" + body + "\n-----END OPENSSH PRIVATE KEY-----\n";
    auto findings = classify_content(content, "2026-09-16");
    REQUIRE(findings.size() == 1);
    CHECK(findings[0].kind == FindingKind::PrivateKeyUnencrypted);
    CHECK(findings[0].severity == Severity::Critical);
}

TEST_CASE("classify_content: OpenSSH key with a real cipher name is High", "[cert_scan]") {
    std::string body = make_openssh_body("aes256-ctr");
    std::string content =
        "-----BEGIN OPENSSH PRIVATE KEY-----\n" + body + "\n-----END OPENSSH PRIVATE KEY-----\n";
    auto findings = classify_content(content, "2026-09-16");
    REQUIRE(findings.size() == 1);
    CHECK(findings[0].kind == FindingKind::PrivateKeyEncrypted);
    CHECK(findings[0].severity == Severity::High);
}

TEST_CASE("classify_content: OpenSSH key with undecodable body is Unknown -> High",
         "[cert_scan]") {
    std::string content =
        "-----BEGIN OPENSSH PRIVATE KEY-----\nnotvalidbase64!!!\n-----END OPENSSH PRIVATE KEY-----\n";
    auto findings = classify_content(content, "2026-09-16");
    REQUIRE(findings.size() == 1);
    CHECK(findings[0].kind == FindingKind::PrivateKeyEncrypted);
    CHECK(findings[0].severity == Severity::High);
}

TEST_CASE("classify_content: public key alone yields no findings", "[cert_scan]") {
    auto findings = classify_content(
        "-----BEGIN PUBLIC KEY-----\nMIIFake==\n-----END PUBLIC KEY-----\n", "2026-09-16");
    CHECK(findings.empty());
}

// ── classify_content: certificates and CSRs ──────────────────────────────

TEST_CASE("classify_content: self-signed valid certificate yields Medium finding", "[cert_scan]") {
    auto findings = classify_content(kSelfSignedValidCertPem, "2026-09-16");
    REQUIRE(findings.size() == 1);
    CHECK(findings[0].kind == FindingKind::Certificate);
    CHECK(findings[0].severity == Severity::Medium);
    CHECK(findings[0].cert_fields.subject == findings[0].cert_fields.issuer);
}

TEST_CASE("classify_content: expired certificate yields Medium finding", "[cert_scan]") {
    auto findings = classify_content(kExpiredCertPem, "2026-09-16");
    REQUIRE(findings.size() == 1);
    CHECK(findings[0].kind == FindingKind::Certificate);
    CHECK(findings[0].severity == Severity::Medium);
}

TEST_CASE("classify_content: CSR marker yields Informational finding", "[cert_scan]") {
    auto findings =
        classify_content("-----BEGIN CERTIFICATE REQUEST-----\nMIIFake==\n"
                         "-----END CERTIFICATE REQUEST-----\n",
                         "2026-09-16");
    REQUIRE(findings.size() == 1);
    CHECK(findings[0].kind == FindingKind::CertificateSigningRequest);
    CHECK(findings[0].severity == Severity::Informational);
}

TEST_CASE("classify_content: combined cert + key file yields two findings", "[cert_scan]") {
    // Certificate FIRST, key second -- the conventional ordering for a
    // combined PEM bundle (e.g. HAProxy's cert+key .pem), and also the
    // only ordering parse_pem_certs can see past: certificates_x509.hpp's
    // PEM_read_bio_X509 loop reads whatever PEM block comes first and
    // fails immediately if its name isn't "CERTIFICATE" -- it does not
    // skip a leading non-certificate block to find a later one. A
    // key-before-cert bundle is a real, disclosed limitation of reusing
    // that header here -- see classify_content()'s doc comment.
    std::string combined = std::string(kSelfSignedValidCertPem) +
                           "-----BEGIN PRIVATE KEY-----\nMIIFake==\n"
                           "-----END PRIVATE KEY-----\n";
    auto findings = classify_content(combined, "2026-09-16");
    REQUIRE(findings.size() == 2);
    CHECK(findings[0].kind == FindingKind::PrivateKeyUnencrypted);
    CHECK(findings[1].kind == FindingKind::Certificate);
}

// ── Binary container detection ───────────────────────────────────────────

TEST_CASE("looks_like_jks: matches the 0xFEEDFEED magic", "[cert_scan]") {
    std::string jks{"\xFE\xED\xFE\xEDrestofthefile", 18};
    CHECK(looks_like_jks(jks));
}

TEST_CASE("looks_like_jks: rejects unrelated binary content", "[cert_scan]") {
    std::string other{"\x00\x01\x02\x03", 4};
    CHECK_FALSE(looks_like_jks(other));
}

TEST_CASE("looks_like_der_sequence: matches leading 0x30", "[cert_scan]") {
    std::string der{"\x30\x82\x01\x00", 4};
    CHECK(looks_like_der_sequence(der));
}

TEST_CASE("classify_binary_content: JKS magic wins regardless of extension", "[cert_scan]") {
    std::string jks{"\xFE\xED\xFE\xEDrest", 8};
    auto findings = classify_binary_content(jks, ".keystore", "2026-09-16");
    REQUIRE(findings.size() == 1);
    CHECK(findings[0].kind == FindingKind::JksKeystore);
    CHECK(findings[0].severity == Severity::High);
}

TEST_CASE("classify_binary_content: .p12 content that looks like DER yields Pkcs12Container",
         "[cert_scan]") {
    std::string der{"\x30\x82\x05\x00garbagebytes", 15};
    auto findings = classify_binary_content(der, ".p12", "2026-09-16");
    REQUIRE(findings.size() == 1);
    CHECK(findings[0].kind == FindingKind::Pkcs12Container);
    CHECK(findings[0].severity == Severity::High);
}

TEST_CASE("classify_binary_content: unrecognized binary yields nothing", "[cert_scan]") {
    std::string other{"\x01\x02\x03\x04random", 9};
    auto findings = classify_binary_content(other, ".dat", "2026-09-16");
    CHECK(findings.empty());
}

TEST_CASE("classify_binary_content: garbage .der content parses to nothing, never guessed",
         "[cert_scan]") {
    std::string garbage{"not a real certificate at all", 30};
    auto findings = classify_binary_content(garbage, ".der", "2026-09-16");
    CHECK(findings.empty());
}

// ── has_any_pem_marker dispatch ───────────────────────────────────────────

TEST_CASE("has_any_pem_marker: true for key/cert/CSR content", "[cert_scan]") {
    CHECK(has_any_pem_marker("-----BEGIN PRIVATE KEY-----\n"));
    CHECK(has_any_pem_marker("-----BEGIN CERTIFICATE-----\n"));
    CHECK(has_any_pem_marker("-----BEGIN CERTIFICATE REQUEST-----\n"));
}

TEST_CASE("has_any_pem_marker: false for binary/unrelated content", "[cert_scan]") {
    CHECK_FALSE(has_any_pem_marker(std::string("\xFE\xED\xFE\xED", 4)));
    CHECK_FALSE(has_any_pem_marker("just some ordinary text file\n"));
}
