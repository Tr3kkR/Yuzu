#pragma once

// cert_scan_rules.hpp -- pure classification logic for the cert_scan plugin.
//
// Every function here operates only on already-in-memory bytes (file
// content, or a parsed certificates_x509::CertFields) handed in by the
// caller -- no filesystem access, no I/O -- so the whole decision layer is
// directly unit-testable (tests/unit/test_cert_scan_rules.cpp) without a
// real file on disk. cert_scan_collect.hpp owns all the I/O (home-directory
// discovery, the recursive walk, reading file bytes) and hands this header
// the raw content.
//
// Severity ladder (the plugin's operator-facing risk ranking):
//   Critical      -- an unencrypted private key. Anyone who can read the
//                     file can immediately use the key -- no further
//                     secret is required.
//   High          -- an encrypted private key, or an opaque PKCS#12/JKS
//                     container that likely holds a key (not deep-parsed
//                     in v1 -- see looks_like_pkcs12/looks_like_jks).
//   Medium        -- an expired or self-signed certificate: still a
//                     misconfiguration/hygiene signal, never key material.
//   Low           -- a valid (non-expired, non-self-signed) certificate.
//   Informational -- a certificate signing request (no key material, no
//                     trust decision attached to it yet).

#include <array>
#include <cctype>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <openssl/evp.h>

#include "certificates_x509.hpp"

namespace yuzu::cert_scan {

enum class Severity { Critical, High, Medium, Low, Informational };

[[nodiscard]] constexpr std::string_view severity_name(Severity s) {
    switch (s) {
    case Severity::Critical:
        return "CRITICAL";
    case Severity::High:
        return "HIGH";
    case Severity::Medium:
        return "MEDIUM";
    case Severity::Low:
        return "LOW";
    case Severity::Informational:
        return "INFO";
    }
    return "INFO"; // unreachable -- cases are exhaustive so -Wswitch flags enum drift
}

enum class FindingKind {
    PrivateKeyUnencrypted,
    PrivateKeyEncrypted,
    Pkcs12Container,
    JksKeystore,
    Certificate,
    CertificateSigningRequest,
};

[[nodiscard]] constexpr std::string_view finding_kind_name(FindingKind k) {
    switch (k) {
    case FindingKind::PrivateKeyUnencrypted:
        return "private_key_unencrypted";
    case FindingKind::PrivateKeyEncrypted:
        return "private_key_encrypted";
    case FindingKind::Pkcs12Container:
        return "pkcs12_container";
    case FindingKind::JksKeystore:
        return "jks_keystore";
    case FindingKind::Certificate:
        return "certificate";
    case FindingKind::CertificateSigningRequest:
        return "certificate_signing_request";
    }
    return "certificate"; // unreachable
}

struct CertFinding {
    FindingKind kind{FindingKind::Certificate};
    Severity severity{Severity::Informational};
    /// Populated only for FindingKind::Certificate (subject/issuer/dates/
    /// serial/thumbprint) -- empty CertFields (all "(unknown)"/"(none)")
    /// for every other kind, since key/container/CSR findings carry no
    /// certificates_x509 fields.
    yuzu::certificates_x509::CertFields cert_fields;
};

/// Self-signed iff the subject and issuer render identically via
/// certificates_x509::extract_name -- a string compare, not a
/// X509_check_issued() cryptographic-signature check. This is a real,
/// disclosed limitation: a certificate whose issuer DN happens to equal its
/// subject DN but was NOT actually self-signed (a contrived or malformed
/// chain) would be misclassified. X509_check_issued() would close that gap
/// but needs the issuer's own X509* (this header only ever sees one
/// certificate's already-extracted CertFields at a time) -- true chain
/// validation is out of scope for a discovery scan (it doesn't have the
/// rest of the chain to validate against) and is left as documented future
/// work rather than a partial, easy-to-misread implementation.
[[nodiscard]] inline bool is_self_signed(const yuzu::certificates_x509::CertFields& f) {
    return !f.subject.empty() && f.subject != "(unknown)" && f.subject == f.issuer;
}

/// Expired iff not_after < today, both in the "YYYY-MM-DD" shape
/// certificates_x509::extract_date emits -- lexical comparison is correct
/// for same-length ISO-8601 dates. `today` is a caller-supplied parameter
/// (never read from the system clock in this header) so the pure decision
/// stays deterministic and unit-testable; the plugin's OS-facing side
/// supplies the real current date. std::nullopt when not_after is the
/// "(unknown)" sentinel -- an unparseable date is an honest "cannot
/// determine", never a silent "not expired".
[[nodiscard]] inline std::optional<bool> is_expired(const yuzu::certificates_x509::CertFields& f,
                                                     std::string_view today_iso) {
    if (f.not_after.empty() || f.not_after == "(unknown)" || f.not_after.size() != 10)
        return std::nullopt;
    return f.not_after < today_iso;
}

/// Severity for one already-parsed certificate: Medium if expired,
/// self-signed, or the expiry cannot be determined at all -- Low is
/// reserved for a certificate CONFIRMED both non-self-signed and
/// non-expired. An unresolvable expiry used to fall through to Low (the
/// same label an actually-verified-fresh certificate gets), which reads
/// as "confirmed valid" when the honest answer is "could not confirm
/// either way" -- this codebase's own established convention for exactly
/// this shape of ambiguity is to report the LESS reassuring outcome
/// (see openssh_key_encryption()'s Unknown -> the higher of its two key
/// severities), not the more reassuring one.
[[nodiscard]] inline Severity certificate_severity(const yuzu::certificates_x509::CertFields& f,
                                                    std::string_view today_iso) {
    if (is_self_signed(f))
        return Severity::Medium;
    auto expired = is_expired(f, today_iso);
    if (!expired.has_value() || *expired)
        return Severity::Medium;
    return Severity::Low;
}

// ── PEM marker detection ─────────────────────────────────────────────────

[[nodiscard]] inline bool contains(std::string_view haystack, std::string_view needle) {
    return haystack.find(needle) != std::string_view::npos;
}

/// True for any of the PEM private-key header lines OpenSSL/OpenSSH emit,
/// regardless of encryption. Deliberately excludes "-----BEGIN PUBLIC
/// KEY-----" (a public key is not sensitive) and
/// "-----BEGIN CERTIFICATE-----"/"-----BEGIN CERTIFICATE REQUEST-----"
/// (handled separately by their own detectors).
[[nodiscard]] inline bool contains_private_key_marker(std::string_view content) {
    static constexpr std::array<std::string_view, 6> kMarkers{
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN ENCRYPTED PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN DSA PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
    };
    for (auto marker : kMarkers) {
        if (contains(content, marker))
            return true;
    }
    return false;
}

[[nodiscard]] inline bool contains_certificate_marker(std::string_view content) {
    return contains(content, "-----BEGIN CERTIFICATE-----");
}

[[nodiscard]] inline bool contains_csr_marker(std::string_view content) {
    return contains(content, "-----BEGIN CERTIFICATE REQUEST-----") ||
           contains(content, "-----BEGIN NEW CERTIFICATE REQUEST-----");
}

/// Traditional SSLeay/OpenSSL PEM encryption ("-----BEGIN RSA PRIVATE
/// KEY-----" etc, PKCS#1-style) marks itself with a "Proc-Type: 4,ENCRYPTED"
/// header line immediately inside the block -- PKCS#8's
/// "-----BEGIN ENCRYPTED PRIVATE KEY-----" is unambiguous on its own (the
/// marker text itself says ENCRYPTED, no header to check). This function
/// only needs to disambiguate the traditional-format case; callers check
/// the PKCS#8 marker text directly.
[[nodiscard]] inline bool has_proc_type_encrypted_header(std::string_view content) {
    return contains(content, "Proc-Type: 4,ENCRYPTED");
}

// ── OpenSSH private-key encryption detection ─────────────────────────────
//
// OpenSSH's own key format wraps EVERY key (encrypted or not) in the same
// "-----BEGIN OPENSSH PRIVATE KEY-----" marker text -- unlike PKCS#8/
// traditional PEM, there is no distinguishing marker string. The only way
// to tell is to base64-decode the body and read the "ciphername" field from
// the binary openssh-key-v1 structure: magic "openssh-key-v1\0" (15 bytes),
// then a 4-byte big-endian length + that many bytes of ciphername.
// ciphername == "none" means unencrypted; anything else names a real
// cipher.

enum class KeyEncryption { Unencrypted, Encrypted, Unknown };

/// Decodes just enough of the OpenSSH private-key body (the base64 text
/// between the BEGIN/END markers, exactly as it appears in the file -- may
/// still contain embedded newlines) to read the ciphername field, and
/// returns Unencrypted/Encrypted accordingly. Unknown for anything that
/// doesn't decode to the expected magic + length-prefixed string shape
/// (truncated body, corrupt file, non-OpenSSH content) -- never guessed.
[[nodiscard]] inline KeyEncryption openssh_key_encryption(std::string_view base64_body) {
    // Strip whitespace/newlines so the concatenated stream is pure base64.
    std::string clean;
    clean.reserve(base64_body.size());
    for (char c : base64_body) {
        if (!std::isspace(static_cast<unsigned char>(c)))
            clean += c;
    }

    // Magic (15) + 4-byte length + up to a 64-byte cipher name is ample;
    // 128 base64 chars (a multiple of 4) decodes to 96 bytes, comfortably
    // more than needed and short enough to always be available in a
    // genuine key (the shortest real OpenSSH key body is far longer than
    // this). Truncating to a mid-stream prefix (no trailing '=') means
    // EVP_DecodeBlock's output length is exactly (n/4)*3 bytes, no padding
    // adjustment required.
    constexpr std::size_t kPrefixChars = 128;
    std::size_t take = clean.size() < kPrefixChars ? clean.size() : kPrefixChars;
    take -= take % 4;
    if (take < 20) // not enough base64 to hold the 15-byte magic + a length
        return KeyEncryption::Unknown;

    std::vector<unsigned char> decoded(take / 4 * 3 + 1);
    int decoded_len = EVP_DecodeBlock(decoded.data(),
                                       reinterpret_cast<const unsigned char*>(clean.data()),
                                       static_cast<int>(take));
    if (decoded_len < 0)
        return KeyEncryption::Unknown;

    static constexpr std::string_view kMagic{"openssh-key-v1", 15}; // includes the NUL
    if (static_cast<std::size_t>(decoded_len) < kMagic.size() + 4)
        return KeyEncryption::Unknown;
    if (std::string_view(reinterpret_cast<const char*>(decoded.data()), kMagic.size()) != kMagic)
        return KeyEncryption::Unknown;

    std::size_t off = kMagic.size();
    std::uint32_t cipher_len = (static_cast<std::uint32_t>(decoded[off]) << 24) |
                               (static_cast<std::uint32_t>(decoded[off + 1]) << 16) |
                               (static_cast<std::uint32_t>(decoded[off + 2]) << 8) |
                               static_cast<std::uint32_t>(decoded[off + 3]);
    off += 4;
    if (cipher_len == 0 || off + cipher_len > static_cast<std::size_t>(decoded_len))
        return KeyEncryption::Unknown;

    std::string_view cipher_name(reinterpret_cast<const char*>(decoded.data() + off), cipher_len);
    return cipher_name == "none" ? KeyEncryption::Unencrypted : KeyEncryption::Encrypted;
}

/// Extracts the base64 body of the FIRST "-----BEGIN OPENSSH PRIVATE
/// KEY-----" ... "-----END OPENSSH PRIVATE KEY-----" block in `content`.
/// std::nullopt if the begin marker is present but no matching end marker
/// follows (truncated/corrupt file).
[[nodiscard]] inline std::optional<std::string_view> extract_openssh_key_body(
    std::string_view content) {
    static constexpr std::string_view kBegin = "-----BEGIN OPENSSH PRIVATE KEY-----";
    static constexpr std::string_view kEnd = "-----END OPENSSH PRIVATE KEY-----";
    auto begin_pos = content.find(kBegin);
    if (begin_pos == std::string_view::npos)
        return std::nullopt;
    begin_pos += kBegin.size();
    auto end_pos = content.find(kEnd, begin_pos);
    if (end_pos == std::string_view::npos)
        return std::nullopt;
    return content.substr(begin_pos, end_pos - begin_pos);
}

// ── Binary container detection ───────────────────────────────────────────

/// JKS (Java KeyStore) files begin with the 4-byte big-endian magic
/// 0xFEEDFEED -- documented Java keystore format, stable since JDK 1.2.
[[nodiscard]] inline bool looks_like_jks(std::string_view content) {
    if (content.size() < 4)
        return false;
    return static_cast<unsigned char>(content[0]) == 0xFE &&
           static_cast<unsigned char>(content[1]) == 0xED &&
           static_cast<unsigned char>(content[2]) == 0xFE &&
           static_cast<unsigned char>(content[3]) == 0xED;
}

/// PKCS#12/PFX is a DER-encoded ASN.1 SEQUENCE -- its first byte is always
/// 0x30 (universal, constructed, tag 16). This is a weak signal (plenty of
/// non-PKCS12 DER also starts with 0x30) deliberately combined with the
/// caller's .p12/.pfx extension check rather than used alone -- v1 does not
/// deep-parse the PKCS#12 ASN.1 structure to confirm it is genuinely a
/// keystore (a real, disclosed limitation: a same-extensioned non-PKCS12
/// DER file would still be flagged).
[[nodiscard]] inline bool looks_like_der_sequence(std::string_view content) {
    return !content.empty() && static_cast<unsigned char>(content[0]) == 0x30;
}

// ── Orchestration ─────────────────────────────────────────────────────────

/// Substring of `content` between the first `begin_marker` and the next
/// `end_marker` that follows it (markers excluded), or std::nullopt if
/// `begin_marker` is absent or has no matching `end_marker` after it.
/// Scopes a check (e.g. the Proc-Type header search below) to ONE PEM
/// block rather than the whole file, so a file with more than one PEM
/// block does not let one block's header answer another block's question.
[[nodiscard]] inline std::optional<std::string_view> pem_block(std::string_view content,
                                                                std::string_view begin_marker,
                                                                std::string_view end_marker) {
    auto begin_pos = content.find(begin_marker);
    if (begin_pos == std::string_view::npos)
        return std::nullopt;
    begin_pos += begin_marker.size();
    auto end_pos = content.find(end_marker, begin_pos);
    if (end_pos == std::string_view::npos)
        return std::nullopt;
    return content.substr(begin_pos, end_pos - begin_pos);
}

/// Classifies every recognizable PEM construct in `content`: private keys
/// (all formats), certificates (every block, via
/// certificates_x509::parse_pem_certs), and certificate signing requests.
/// A single file can legitimately yield more than one finding (e.g. a
/// combined "fullchain + key" file, or a certificate chain with more than
/// one CERTIFICATE block) -- every match is reported, never just the
/// first. `today_iso` is threaded through to certificate_severity exactly
/// as in that function's own doc comment (never read from the system
/// clock here).
///
/// Disclosed limitations:
///   - When a file concatenates MORE THAN ONE PEM private key of the
///     SAME traditional format (e.g. two "-----BEGIN RSA PRIVATE
///     KEY-----" blocks) with different encryption states, only the
///     first block's encryption status is reported -- this header does
///     not walk multiple same-type key blocks the way parse_pem_certs
///     walks multiple certificates. A rare shape in practice
///     (concatenated keys of the same type are unusual).
///   - certificates_x509::parse_pem_certs reads whatever PEM block comes
///     FIRST in `content` and stops immediately if its name isn't
///     "CERTIFICATE" -- it does not skip a leading non-certificate block
///     to find a later certificate. A combined bundle with a PRIVATE KEY
///     block BEFORE its CERTIFICATE block(s) therefore yields the key
///     finding but MISSES the certificate finding entirely. The
///     conventional ordering for combined PEM bundles (cert(s) first,
///     key last -- e.g. HAProxy's cert+key .pem) is unaffected; only the
///     less common reverse ordering hits this gap. Both are documented
///     rather than silently guessed.
[[nodiscard]] inline std::vector<CertFinding> classify_content(std::string_view content,
                                                                std::string_view today_iso) {
    std::vector<CertFinding> out;

    // Independent `if`s, not if/else-if: a file concatenating one
    // encrypted PKCS#8 key and one unencrypted PKCS#8 key (a real, if
    // uncommon, shape) used to report only the encrypted one -- the
    // else-if silently dropped the unencrypted CRITICAL finding entirely.
    // The two marker strings never overlap as substrings of each other
    // ("-----BEGIN ENCRYPTED PRIVATE KEY-----" does not contain
    // "-----BEGIN PRIVATE KEY-----" anywhere in it), so checking both
    // independently cannot double-count a single encrypted key as
    // unencrypted too.
    if (contains(content, "-----BEGIN ENCRYPTED PRIVATE KEY-----")) {
        out.push_back(CertFinding{FindingKind::PrivateKeyEncrypted, Severity::High, {}});
    }
    if (contains(content, "-----BEGIN PRIVATE KEY-----")) {
        out.push_back(CertFinding{FindingKind::PrivateKeyUnencrypted, Severity::Critical, {}});
    }

    static constexpr std::array<std::pair<std::string_view, std::string_view>, 3> kTraditional{{
        {"-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----"},
        {"-----BEGIN EC PRIVATE KEY-----", "-----END EC PRIVATE KEY-----"},
        {"-----BEGIN DSA PRIVATE KEY-----", "-----END DSA PRIVATE KEY-----"},
    }};
    for (const auto& [begin, end] : kTraditional) {
        if (!contains(content, begin))
            continue;
        // A truncated file (BEGIN present, END absent -- the realistic
        // disk-full/crash/sync-interrupt shape) used to be silently
        // dropped entirely here (pem_block() returning nullopt skipped
        // the whole iteration) -- a live, readable private key going
        // unreported is far worse than a Proc-Type search whose scope is
        // wider than strictly necessary, so a missing END falls back to
        // "BEGIN to end-of-content" as the search scope instead of
        // skipping the key.
        std::string_view block;
        if (auto scoped = pem_block(content, begin, end)) {
            block = *scoped;
        } else {
            block = content.substr(content.find(begin) + begin.size());
        }
        bool encrypted = has_proc_type_encrypted_header(block);
        out.push_back(CertFinding{
            encrypted ? FindingKind::PrivateKeyEncrypted : FindingKind::PrivateKeyUnencrypted,
            encrypted ? Severity::High : Severity::Critical, {}});
    }

    {
        static constexpr std::string_view kOpenSshBegin = "-----BEGIN OPENSSH PRIVATE KEY-----";
        if (contains(content, kOpenSshBegin)) {
            // Same truncation fallback as the traditional-format loop
            // above -- and unlike that case, the ciphername field this
            // needs to decode sits near the START of the base64 body, so
            // a missing END marker practically never actually prevents
            // decoding it; falling back to "BEGIN to end-of-content"
            // costs nothing extra in the common truncation case while
            // still never silently dropping the key.
            std::string_view body;
            if (auto scoped = extract_openssh_key_body(content)) {
                body = *scoped;
            } else {
                body = content.substr(content.find(kOpenSshBegin) + kOpenSshBegin.size());
            }
            KeyEncryption enc = openssh_key_encryption(body);
            // Unknown (undecodable body) is treated as the lower of the
            // two key severities, not the higher -- an unconfirmed
            // encryption claim should not read as a confirmed Critical
            // finding.
            bool unencrypted = (enc == KeyEncryption::Unencrypted);
            out.push_back(CertFinding{
                unencrypted ? FindingKind::PrivateKeyUnencrypted : FindingKind::PrivateKeyEncrypted,
                unencrypted ? Severity::Critical : Severity::High, {}});
        }
    }

    if (contains_csr_marker(content))
        out.push_back(CertFinding{FindingKind::CertificateSigningRequest, Severity::Informational, {}});

    if (contains_certificate_marker(content)) {
        for (const auto& fields : yuzu::certificates_x509::parse_pem_certs(content)) {
            out.push_back(
                CertFinding{FindingKind::Certificate, certificate_severity(fields, today_iso), fields});
        }
    }

    return out;
}

/// Classifies a non-PEM (binary) candidate file by content + its
/// (already-lower-cased) extension:
///   - JKS magic bytes (0xFEEDFEED) anywhere at the start -- strong signal
///     on its own, checked regardless of extension.
///   - .der/.cer content run through certificates_x509::parse_der_cert --
///     succeeds ONLY for a genuine single X.509 certificate (a PKCS#12
///     bundle is a different ASN.1 structure d2i_X509 rejects), so this is
///     a precise signal, not a guess.
///   - .p12/.pfx content that looks like a DER SEQUENCE -- the weak signal
///     documented on looks_like_der_sequence(), deliberately gated on the
///     extension since a bare DER certificate also starts with 0x30.
/// Anything else yields no findings -- an unrecognized binary file is
/// skipped, never guessed at.
[[nodiscard]] inline std::vector<CertFinding> classify_binary_content(std::string_view content,
                                                                       std::string_view extension,
                                                                       std::string_view today_iso) {
    std::vector<CertFinding> out;

    if (looks_like_jks(content)) {
        out.push_back(CertFinding{FindingKind::JksKeystore, Severity::High, {}});
        return out;
    }

    if (extension == ".der" || extension == ".cer") {
        std::span<const unsigned char> bytes(reinterpret_cast<const unsigned char*>(content.data()),
                                             content.size());
        if (auto fields = yuzu::certificates_x509::parse_der_cert(bytes)) {
            out.push_back(
                CertFinding{FindingKind::Certificate, certificate_severity(*fields, today_iso), *fields});
        }
        return out;
    }

    if (extension == ".p12" || extension == ".pfx") {
        if (looks_like_der_sequence(content))
            out.push_back(CertFinding{FindingKind::Pkcs12Container, Severity::High, {}});
        return out;
    }

    return out;
}

/// True when `content` contains any marker classify_content() recognizes --
/// the plugin's own dispatch between the PEM-text path (classify_content)
/// and the binary path (classify_binary_content) for one candidate file.
[[nodiscard]] inline bool has_any_pem_marker(std::string_view content) {
    return contains_private_key_marker(content) || contains_certificate_marker(content) ||
           contains_csr_marker(content);
}

} // namespace yuzu::cert_scan
