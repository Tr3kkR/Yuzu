/**
 * certificates_plugin.cpp — Certificate inventory plugin for Yuzu
 *
 * Enumerates and manages certificates in system stores.
 *
 * Actions:
 *   "list"    — List certificates in system stores (pipe-delimited).
 *   "details" — Get details for a specific certificate by thumbprint.
 *   "delete"  — Delete a certificate by thumbprint from a given store.
 *
 * Output is pipe-delimited via write_output().
 *
 * Platform implementations:
 *   Windows — CryptoAPI (CertOpenStore, CertEnumCertificatesInStore, etc.)
 *   Linux   — PEM files in /etc/ssl/certs/ parsed in-process via libcrypto
 *             (certificates_x509.hpp) -- no subprocess.
 *   macOS   — System.keychain / SystemRootCertificates.keychain read
 *             in-process via SecItemCopyMatching (certificates_x509.hpp's
 *             DER parse backs the result); the login keychain still reads
 *             via a `security find-certificate` subprocess routed through
 *             the per-user launchd/Aqua session (Decision-7 governed-shell
 *             exception -- see build_login_keychain_read_command()).
 */

#include <yuzu/plugin.hpp>
#include <yuzu/string_utils.hpp> // yuzu::util::safe_output_field (BR-07)

#include "certificates_macos_parsers.hpp" // pure parse/validate/classify/verdict helpers (shared with the unit test)

#include <spdlog/spdlog.h> // degraded-subprocess WARN (SRE S1 observability)

#include <array>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <format>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <wincrypt.h>
#else
#include <filesystem>
#include <fstream>
#endif

#ifdef __APPLE__
// geteuid() -- privilege detection for the store-read sudo hop (mirrors
// quarantine_plugin.cpp's sudo_prefix()). macos_console_user.hpp declares
// `namespace yuzu::macos`, and subprocess_runner.hpp declares
// `namespace yuzu::agent` -- ALL THREE headers below MUST be included
// here, at global scope, before the anonymous namespace below opens:
// including them inside `namespace { ... }` would nest `yuzu::macos`/
// `yuzu::agent` under `(anonymous namespace)::yuzu`, shadowing the global
// `::yuzu` namespace (from <yuzu/plugin.hpp> above) for every unqualified
// `yuzu::` lookup in this file -- e.g. `yuzu::TempFile` below would then
// fail to resolve, since the nested `(anonymous namespace)::yuzu` has no
// TempFile member.
#include <unistd.h>
#include <macos_console_user.hpp>          // shared console-user + store/keychain mapping (#2277)
#include <yuzu/agent/subprocess_runner.hpp> // yuzu::agent::run_bounded_subprocess (BR-03)
#if defined(YUZU_HAVE_SECURITY_FRAMEWORK)
#include <Security/Security.h>          // SecKeychainOpen/SecItemCopyMatching (WP-B rung-1 System/root read)
#include <yuzu/agent/scoped_cfref.hpp>  // yuzu::agent::ScopedCFRef<T> (RAII for the CF objects above)
#endif
#endif

// NOTE: the Linux leg deliberately includes NO subprocess header. WP-B removed
// the `openssl x509` shell-out that used to need one, so the Linux
// list/details/delete paths below spawn nothing at all -- the previous
// `#ifdef __linux__ #include <yuzu/agent/subprocess_runner.hpp>` block is gone
// with the mechanism it served. Every remaining spawn site in this file is
// inside the __APPLE__ region.

#if defined(__linux__) || defined(__APPLE__)
// yuzu::certificates_x509 -- in-process libcrypto PEM/DER parsing (WP-B).
// Backs the Linux PEM-file read entirely and the macOS System.keychain/
// SystemRootCertificates.keychain SecItem read's DER decode; the macOS
// login-keychain path stays on the PEM-block parse in
// certificates_macos_parsers.hpp / parse_pem_block_macos below, untouched.
#include "certificates_x509.hpp"
#endif

// The pure parse/validate/classify/verdict helpers this file shares with
// tests/unit/test_certificates_macos.cpp live in yuzu::certificates_macos
// (certificates_macos_parsers.hpp). Pulled into scope here -- including for
// the CertificatesPlugin::execute() methods further down, which are outside
// the anonymous namespace below -- so the many call sites read exactly as they
// did when these functions were file-local, with no per-call qualification.
using namespace yuzu::certificates_macos;

namespace {

// ── Input validation ────────────────────────────────────────────────────────
// is_valid_thumbprint / expires_within_days moved to certificates_macos_parsers.hpp.
//
// is_safe_path() (a shell-metacharacter allowlist guarding the filename this
// file used to interpolate into an `openssl x509 -in "<path>"` command
// line) and run_command() (the popen-or-bounded-subprocess wrapper that ran
// that command) are DELETED as of WP-B: certificates_x509.hpp's in-process
// libcrypto parse and native std::ifstream file I/O (see
// read_linux_cert_record() below) never build a shell command line from a
// filesystem path, so there is nothing left for either to guard.

// ── Certificate record ───────────────────────────────────────────────────────

struct CertRecord {
    std::string subject;
    std::string issuer;
    std::string thumbprint;
    std::string not_before;
    std::string not_after;
    std::string serial;
    std::string store;
    std::string key_usage;

    std::string to_row() const {
        // subject/issuer/serial/key_usage come from parsed certificate data
        // (subject/issuer are attacker-influenced DN text on any store
        // that can hold a self-signed or otherwise untrusted leaf cert;
        // serial/key_usage are wrapped too for defense-in-depth even
        // though they are openssl-derived hex/enum text) -- escaped via
        // safe_output_field so a hostile '|' or embedded CR/LF can never
        // inject an extra column or row into this pipe-delimited output
        // (BR-07). thumbprint/not_before/not_after/store are excluded:
        // thumbprint is hex-validated (is_valid_thumbprint) or one of this
        // file's own literal sentinels ("(unknown)"/"(skipped)" -- both
        // parenthesised ASCII, no '|' or CR/LF), the dates are produced
        // entirely by this
        // file's own date formatting, and store is always one of this
        // plugin's own fixed literal labels -- none of the four can carry
        // attacker-controlled bytes.
        return std::format("{}|{}|{}|{}|{}|{}|{}|{}", yuzu::util::safe_output_field(subject),
                           yuzu::util::safe_output_field(issuer), thumbprint, not_before,
                           not_after, yuzu::util::safe_output_field(serial), store,
                           yuzu::util::safe_output_field(key_usage));
    }
};

#if defined(__linux__) || defined(__APPLE__)
// Adopt a certificates_x509::CertFields (the pure libcrypto parse result)
// into this file's own CertRecord shape, setting `store` from the caller --
// certificates_x509.hpp never knows which keychain/directory a certificate
// came from, only the plugin's platform-specific read sites do. Shared by
// the Linux PEM-file path (read_linux_cert_record) and the macOS SecItem
// System/root path (list/details_cert_macos) so both adopt CertFields into
// CertRecord identically.
CertRecord to_cert_record(const yuzu::certificates_x509::CertFields& fields, std::string store) {
    CertRecord rec;
    rec.store = std::move(store);
    rec.subject = fields.subject;
    rec.issuer = fields.issuer;
    rec.not_before = fields.not_before;
    rec.not_after = fields.not_after;
    rec.serial = fields.serial;
    rec.thumbprint = fields.thumbprint;
    rec.key_usage = fields.key_usage;
    return rec;
}

/// Report a partial certificate read through the ABI4 typed result seam
/// (`yuzu_ctx_set_result_status`, sdk/include/yuzu/plugin.hpp) in addition to
/// the operator-visible `not_available|<reason>` row the caller writes.
///
/// The sentinel row alone is only OPERATOR-visible: a consumer reading the
/// command's RESULT METADATA rather than scraping rows would otherwise see an
/// inventory that is missing a whole keychain (or a whole certificate file)
/// presented with the default UNDECLARED status, from which the agent derives
/// a coarse success. Every degraded read here is therefore CONSTRAINED +
/// PARTIAL, with `provenance` naming the half that failed so the two halves
/// of a hybrid macOS read stay distinguishable ("login-keychain" is the
/// spec-named value for the governed-shell half).
///
/// Idempotent by construction: the seam records the last call for the
/// currently-executing command, and every call here reports the same
/// CONSTRAINED/PARTIAL pair, so a read that degrades in two places reports
/// degraded once with the last-named provenance rather than escalating.
void mark_result_partial(yuzu::CommandContext& ctx, std::string_view provenance) {
    ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                          provenance);
}

/**
 * Canonicalize a thumbprint to uppercase hex so every downstream comparison
 * against a parsed value (certificates_x509::extract_thumbprint always emits
 * uppercase) is a plain `==`. The `thumbprint` request parameter is
 * documented as case-insensitive (content/definitions/certificates.yaml) but
 * was compared as-is on both the macOS and Linux paths, so a lowercase
 * caller-supplied value silently failed to match. `s` is assumed already
 * hex-validated by is_valid_thumbprint(); this only changes case, never
 * rejects input. Shared (not macOS-only) because details_cert_linux and
 * delete_cert_linux need the identical fold.
 */
std::string canonical_thumbprint(std::string_view s) {
    std::string out{s};
    for (auto& c : out)
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    return out;
}
#endif

// ── Expiry filtering helper ──────────────────────────────────────────────────
// expires_within_days moved to certificates_macos_parsers.hpp (shared with the
// unit test and used by the Windows/Linux paths below too).

// ── Windows implementation ───────────────────────────────────────────────────

#ifdef _WIN32

std::string filetime_to_string(const FILETIME& ft) {
    SYSTEMTIME st{};
    FileTimeToSystemTime(&ft, &st);
    return std::format("{:04d}-{:02d}-{:02d}", st.wYear, st.wMonth, st.wDay);
}

std::string bytes_to_hex(const BYTE* data, DWORD len) {
    std::string hex;
    hex.reserve(len * 2);
    for (DWORD i = 0; i < len; ++i) {
        hex += std::format("{:02X}", data[i]);
    }
    return hex;
}

std::string get_cert_name(PCCERT_CONTEXT cert, DWORD type) {
    char buf[512]{};
    DWORD len =
        CertGetNameStringA(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, type, nullptr, buf, sizeof(buf));
    if (len <= 1)
        return "(unknown)";
    return std::string(buf);
}

std::string get_cert_thumbprint(PCCERT_CONTEXT cert) {
    BYTE hash[20]{};
    DWORD hash_len = sizeof(hash);
    if (CryptHashCertificate(0, CALG_SHA1, 0, cert->pbCertEncoded, cert->cbCertEncoded, hash,
                             &hash_len)) {
        return bytes_to_hex(hash, hash_len);
    }
    return "(unknown)";
}

std::string get_cert_serial(PCCERT_CONTEXT cert) {
    const auto& sn = cert->pCertInfo->SerialNumber;
    // Serial number is stored in little-endian order in Windows
    std::string serial;
    serial.reserve(sn.cbData * 2);
    for (DWORD i = sn.cbData; i > 0; --i) {
        serial += std::format("{:02X}", sn.pbData[i - 1]);
    }
    return serial;
}

std::string get_key_usage(PCCERT_CONTEXT cert) {
    BYTE usage_bits[2]{};
    DWORD usage_size = sizeof(usage_bits);
    if (!CertGetIntendedKeyUsage(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, cert->pCertInfo,
                                 usage_bits, usage_size)) {
        return "(none)";
    }

    std::vector<std::string> usages;
    if (usage_bits[0] & CERT_DIGITAL_SIGNATURE_KEY_USAGE)
        usages.emplace_back("Digital Signature");
    if (usage_bits[0] & CERT_KEY_ENCIPHERMENT_KEY_USAGE)
        usages.emplace_back("Key Encipherment");
    if (usage_bits[0] & CERT_DATA_ENCIPHERMENT_KEY_USAGE)
        usages.emplace_back("Data Encipherment");
    if (usage_bits[0] & CERT_KEY_AGREEMENT_KEY_USAGE)
        usages.emplace_back("Key Agreement");
    if (usage_bits[0] & CERT_KEY_CERT_SIGN_KEY_USAGE)
        usages.emplace_back("Certificate Signing");
    if (usage_bits[0] & CERT_CRL_SIGN_KEY_USAGE)
        usages.emplace_back("CRL Signing");
    if (usage_bits[0] & CERT_NON_REPUDIATION_KEY_USAGE)
        usages.emplace_back("Non-Repudiation");

    if (usages.empty())
        return "(none)";

    std::string result;
    for (size_t i = 0; i < usages.size(); ++i) {
        if (i > 0)
            result += ", ";
        result += usages[i];
    }
    return result;
}

std::vector<CertRecord> enumerate_store(const char* store_name) {
    std::vector<CertRecord> records;

    HCERTSTORE hStore = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, 0,
                                      CERT_SYSTEM_STORE_LOCAL_MACHINE |
                                          CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG,
                                      store_name);

    if (!hStore) {
        // Fall back to current user store
        hStore = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, 0,
                               CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_OPEN_EXISTING_FLAG |
                                   CERT_STORE_READONLY_FLAG,
                               store_name);
    }
    if (!hStore)
        return records;

    PCCERT_CONTEXT cert = nullptr;
    while ((cert = CertEnumCertificatesInStore(hStore, cert)) != nullptr) {
        CertRecord rec;
        rec.subject = get_cert_name(cert, 0);
        rec.issuer = get_cert_name(cert, CERT_NAME_ISSUER_FLAG);
        rec.thumbprint = get_cert_thumbprint(cert);
        rec.not_before = filetime_to_string(cert->pCertInfo->NotBefore);
        rec.not_after = filetime_to_string(cert->pCertInfo->NotAfter);
        rec.serial = get_cert_serial(cert);
        rec.store = store_name;
        rec.key_usage = get_key_usage(cert);
        records.push_back(std::move(rec));
    }

    CertCloseStore(hStore, 0);
    return records;
}

void list_certs_win(yuzu::CommandContext& ctx, std::string_view store_filter, int expiring_days) {
    static const char* kStores[] = {"MY", "ROOT", "CA", "Trust"};

    ctx.write_output("subject|issuer|thumbprint|not_before|not_after|serial|store|key_usage");

    for (const auto* store_name : kStores) {
        if (store_filter != "all" && store_filter != store_name)
            continue;

        auto records = enumerate_store(store_name);
        for (const auto& rec : records) {
            if (expires_within_days(rec.not_after, expiring_days)) {
                ctx.write_output(rec.to_row());
            }
        }
    }
}

void details_cert_win(yuzu::CommandContext& ctx, std::string_view thumbprint) {
    static const char* kStores[] = {"MY", "ROOT", "CA", "Trust"};

    ctx.write_output("subject|issuer|thumbprint|not_before|not_after|serial|store|key_usage");

    for (const auto* store_name : kStores) {
        auto records = enumerate_store(store_name);
        for (const auto& rec : records) {
            if (rec.thumbprint == thumbprint) {
                ctx.write_output(rec.to_row());
                return;
            }
        }
    }
    ctx.write_output("status|not_found");
}

void delete_cert_win(yuzu::CommandContext& ctx, std::string_view thumbprint,
                     std::string_view store_name) {
    HCERTSTORE hStore =
        CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, 0, CERT_SYSTEM_STORE_LOCAL_MACHINE,
                      std::string{store_name}.c_str());

    if (!hStore) {
        hStore = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER,
                               std::string{store_name}.c_str());
    }
    if (!hStore) {
        ctx.write_output("status|not_found");
        return;
    }

    PCCERT_CONTEXT cert = nullptr;
    bool found = false;
    while ((cert = CertEnumCertificatesInStore(hStore, cert)) != nullptr) {
        auto fp = get_cert_thumbprint(cert);
        if (fp == thumbprint) {
            // Duplicate the context because CertDeleteCertificateFromStore
            // frees the context and invalidates the enumeration
            PCCERT_CONTEXT dup = CertDuplicateCertificateContext(cert);
            if (CertDeleteCertificateFromStore(dup)) {
                ctx.write_output("status|deleted");
            } else {
                ctx.write_output("status|delete_failed");
            }
            found = true;
            break;
        }
    }

    if (!found) {
        ctx.write_output("status|not_found");
    }

    CertCloseStore(hStore, 0);
}

#endif // _WIN32

// ── Linux implementation ─────────────────────────────────────────────────────

#ifdef __linux__

// parity: `openssl x509 -in <file>` -- the subprocess call this file used to
// shell out to for every field, replaced below by
// yuzu::certificates_x509::parse_pem_certs -- reads ONLY the first PEM block
// in a file. parse_pem_certs can return every certificate a multi-cert
// bundle contains, so BOTH callers that need "the certificate this file
// represents" (read_linux_cert_record below and delete_cert_linux further
// down) go through this ONE helper and consume only certs.front() -- never
// anything past index 0. Widening either caller to consider a 2nd-or-later
// certificate would make MANY MORE thumbprints match a bundle file, and since
// `delete` removes the whole FILE (`std::filesystem::remove`, the only
// mechanism available for a PEM-directory store), every extra match is
// another way to reach a bulk trust-anchor removal. Note carefully what this
// guard does and does NOT buy: matching only certs.front() is a strict
// REDUCTION in the number of requests that can trigger a bundle-wide delete,
// and it is byte-parity with the replaced subprocess -- but it does not make
// the delete granular. A request naming a bundle's FIRST certificate still
// removes the entire bundle, exactly as the pre-migration code did. That
// pre-existing coarseness is out of WP-B's scope (a granular delete means
// rewriting the file, a different and mutating design); do not read this
// comment as a claim that bundle files are safe from bulk removal.
// Returns std::nullopt for a file that cannot be
// opened OR that yields zero parseable certificates (empty, garbage, a
// truncated PEM block) -- both are "no certificate available from this
// path" as far as every caller here is concerned.
std::optional<yuzu::certificates_x509::CertFields> first_cert_of_file(
    const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in)
        return std::nullopt;
    std::ostringstream contents;
    contents << in.rdbuf();
    auto certs = yuzu::certificates_x509::parse_pem_certs(contents.str());
    if (certs.empty())
        return std::nullopt;
    return std::move(certs.front());
}

CertRecord read_linux_cert_record(yuzu::CommandContext& ctx,
                                  const std::filesystem::path& pem_path,
                                  const std::string& store_name) {
    auto cert = first_cert_of_file(pem_path);
    if (!cert) {
        // The deleted is_safe_path() rejected a path containing shell
        // metacharacters before this file ever shelled out to
        // `openssl x509 -in <path>` -- native std::ifstream I/O never
        // interpolates the path into a shell command, so that specific risk
        // is gone, and with it the only condition "(unsafe path)" ever
        // described. What reaches this branch now is a DIFFERENT condition:
        // a file this code genuinely cannot turn into a certificate record
        // (missing, permission denied, empty, garbage, or a truncated PEM
        // block). Reporting that as "(unsafe path)" would name a cause that
        // cannot occur, so the sentinel says what actually happened.
        //
        // This is a deliberate, narrow divergence from the pre-migration
        // output, and NOT the one the deleted code's own comment claimed:
        // pre-migration an unreadable/unparseable file did NOT take the
        // unsafe-path branch at all -- every `openssl x509` call simply
        // failed, leaving subject/issuer/thumbprint at "(unknown)" and
        // key_usage at "(none)". So "(unsafe path)" was never this case's
        // output either way; "(unreadable)" is strictly more honest than
        // both the old "(unknown)" (which is also what a per-field parse
        // failure on a VALID certificate produces, and so cannot be
        // distinguished from it) and "(unsafe path)".
        //
        // The row is still emitted, not dropped: expires_within_days()
        // returns true for a not_after shorter than 10 characters, so this
        // record survives the expiry filter in list_certs_linux and the
        // unreadable file stays operator-visible. mark_result_partial makes
        // it machine-visible too -- an inventory missing a certificate file
        // is a partial inventory, not a clean one.
        mark_result_partial(ctx, "libcrypto:unreadable-file");
        CertRecord rec;
        rec.store = store_name;
        rec.subject = "(unreadable)";
        rec.thumbprint = "(skipped)";
        return rec;
    }
    return to_cert_record(*cert, store_name);
}

void list_certs_linux(yuzu::CommandContext& ctx, std::string_view /*store_filter*/,
                      int expiring_days) {
    const std::filesystem::path cert_dir{"/etc/ssl/certs"};

    ctx.write_output("subject|issuer|thumbprint|not_before|not_after|serial|store|key_usage");

    std::error_code ec;
    if (!std::filesystem::exists(cert_dir, ec)) {
        return;
    }

    for (const auto& entry : std::filesystem::directory_iterator(cert_dir, ec)) {
        if (!entry.is_regular_file(ec))
            continue;
        auto ext = entry.path().extension().string();
        if (ext != ".pem" && ext != ".crt")
            continue;

        auto rec = read_linux_cert_record(ctx, entry.path(), "/etc/ssl/certs");
        if (expires_within_days(rec.not_after, expiring_days)) {
            ctx.write_output(rec.to_row());
        }
    }
}

void details_cert_linux(yuzu::CommandContext& ctx, std::string_view thumbprint) {
    const std::filesystem::path cert_dir{"/etc/ssl/certs"};

    ctx.write_output("subject|issuer|thumbprint|not_before|not_after|serial|store|key_usage");

    std::error_code ec;
    if (!std::filesystem::exists(cert_dir, ec)) {
        ctx.write_output("status|not_found");
        return;
    }

    // Case-insensitive per content/definitions/certificates.yaml -- see
    // canonical_thumbprint's own comment (consistency-auditor Gate-4 finding:
    // this compared as-is, unlike the macOS path fixed for the same gap
    // earlier in this same PR).
    auto needle = canonical_thumbprint(thumbprint);
    // Tracks whether every candidate file in this directory was actually
    // readable. A file read_linux_cert_record couldn't parse reports its
    // degradation via mark_result_partial (the ABI4 result-status channel)
    // but still leaves this LOCAL loop free to keep scanning -- so without
    // this flag, an unreadable file that happened to be the real target
    // would fall all the way through to "status|not_found" below, an
    // incomplete scan silently presenting as a definitive negative
    // (consistency-auditor Gate-4 BLOCKING finding).
    bool scan_complete = true;
    for (const auto& entry : std::filesystem::directory_iterator(cert_dir, ec)) {
        if (!entry.is_regular_file(ec))
            continue;
        auto ext = entry.path().extension().string();
        if (ext != ".pem" && ext != ".crt")
            continue;

        auto rec = read_linux_cert_record(ctx, entry.path(), "/etc/ssl/certs");
        if (rec.thumbprint == "(skipped)") {
            scan_complete = false;
            continue;
        }
        if (canonical_thumbprint(rec.thumbprint) == needle) {
            ctx.write_output(rec.to_row());
            return;
        }
    }
    if (scan_complete) {
        ctx.write_output("status|not_found");
    } else {
        // Mirrors details_cert_macos's "not_available|<store> scan
        // incomplete" convention for the identical situation: a definitive
        // negative was never established, so this must not say "not_found".
        ctx.write_output("not_available|/etc/ssl/certs scan incomplete");
    }
}

void delete_cert_linux(yuzu::CommandContext& ctx, std::string_view thumbprint,
                       std::string_view /*store*/) {
    const std::filesystem::path cert_dir{"/etc/ssl/certs"};

    std::error_code ec;
    if (!std::filesystem::exists(cert_dir, ec)) {
        ctx.write_output("status|not_found");
        return;
    }

    auto needle = canonical_thumbprint(thumbprint);
    // See details_cert_linux's identical flag -- a delete request must never
    // report "not_found" (which idempotent "ensure-absent" remediation
    // depends on being a definitive negative) when a candidate file couldn't
    // actually be inspected.
    bool scan_complete = true;
    for (const auto& entry : std::filesystem::directory_iterator(cert_dir, ec)) {
        if (!entry.is_regular_file(ec))
            continue;
        auto ext = entry.path().extension().string();
        if (ext != ".pem" && ext != ".crt")
            continue;

        // parity: only the file's FIRST certificate is a delete target --
        // see first_cert_of_file's own comment.
        auto cert = first_cert_of_file(entry.path());
        if (!cert) {
            // Same degraded-read signal read_linux_cert_record gives list/
            // details -- an unreadable file here means this scan cannot
            // prove the target is absent (consistency-auditor Gate-4
            // BLOCKING finding).
            mark_result_partial(ctx, "libcrypto:unreadable-file");
            scan_complete = false;
            continue;
        }
        if (canonical_thumbprint(cert->thumbprint) == needle) {
            if (std::filesystem::remove(entry.path(), ec)) {
                ctx.write_output("status|deleted");
            } else {
                ctx.write_output("status|delete_failed");
            }
            return;
        }
    }
    if (scan_complete) {
        ctx.write_output("status|not_found");
    } else {
        ctx.write_output(
            "error|unreadable file(s) in /etc/ssl/certs prevented a complete scan; "
            "cannot confirm the certificate is absent");
    }
}

#endif // __linux__

// ── macOS implementation ─────────────────────────────────────────────────────

#ifdef __APPLE__

/**
 * Parse individual PEM certificates from the output of
 * `security find-certificate -a -p <keychain>`.
 * Returns the PEM blocks as separate strings.
 */
std::vector<std::string> split_pem_blocks(const std::string& pem_stream) {
    std::vector<std::string> blocks;
    const std::string begin_marker = "-----BEGIN CERTIFICATE-----";
    const std::string end_marker = "-----END CERTIFICATE-----";

    size_t pos = 0;
    while (pos < pem_stream.size()) {
        auto start = pem_stream.find(begin_marker, pos);
        if (start == std::string::npos)
            break;
        auto end = pem_stream.find(end_marker, start);
        if (end == std::string::npos)
            break;
        end += end_marker.size();
        blocks.push_back(pem_stream.substr(start, end - start));
        pos = end;
    }
    return blocks;
}

// ── Bounded-execution bounds (BR-03) ────────────────────────────────────────
//
// Mirrors installed_apps_plugin.cpp's kEnrichmentBudget/kMaxEnrichedApps
// pattern: a per-call deadline alone does not bound a WHOLE action against
// a pathological keychain with many thousands of entries, so every
// action-level entry point (list/details/the delete verify step) also
// computes a wall-clock budget shared across everything IT does, and caps
// how many certificates it will parse out of any single keychain.
constexpr std::chrono::milliseconds kCertParseDeadline{5000};     // one openssl parse of one PEM block (local temp file -- no network)
constexpr std::chrono::milliseconds kKeychainReadDeadline{15000}; // one `security find-certificate` keychain read (incl. the login-keychain launchctl/sudo hop)
constexpr std::chrono::seconds kCertActionBudget{60};             // whole list/details/delete-verify action, across every keychain it reads
constexpr std::size_t kMaxCertsPerKeychain = 2000;                // per-keychain parsed-certificate cap

/**
 * Run `argv` through the bounded subprocess runner and reduce it to the
 * {output, ok, exit_code} shape the macOS cert-reading call sites below
 * were already written against (pre-#2273 they called a popen-backed
 * run_command_checked() with this exact shape) -- so replacing the
 * transport only touches the two lines that build the call, never the
 * surrounding read/verify logic. `ok` requires a CLEAN, COMPLETE capture:
 * the process actually ran, was not killed at its deadline, was not cut
 * off by the runner's internal capture cap, and exited 0 -- the same bar
 * the old ferror()-based `capture_complete` check enforced, now expressed
 * via SubprocessResult's own timed_out/output_truncated fields (BR-03's
 * "honest sentinel on truncation/timeout").
 */
struct CheckedCommandResult {
    std::string output;
    bool ok = false;
    // Populated whenever the child was spawned, independent of `ok` --
    // delete_cert_macos() reads this directly (not `ok`) to decide whether
    // its post-delete re-enumeration is warranted; see its own comment.
    // -1 when the child could not be spawned or did not exit normally
    // (signaled, killed at the deadline/cancel).
    int exit_code = -1;
};

CheckedCommandResult run_bounded_checked(const std::vector<std::string>& argv,
                                         const yuzu::agent::SubprocessOptions& opts,
                                         std::string_view operation) {
    auto result = yuzu::agent::run_bounded_subprocess(argv, opts);
    // SRE S1 observability: a deadline kill or capture-cap truncation still
    // produces an honest sentinel row + rc downstream, but that is only
    // visible by parsing the emitted output -- a degraded keychain read/parse
    // would otherwise be silent in the agent log. Surface it, matching
    // event_logs_plugin.cpp's `log show` WARN pattern.
    if (result.timed_out || result.output_truncated) {
        spdlog::warn("certificates: {} {} (timed_out={}, output_truncated={})", operation,
                     result.timed_out ? "timed out" : "output truncated", result.timed_out,
                     result.output_truncated);
    }
    CheckedCommandResult out;
    out.output = std::move(result.output);
    if (result.tool_ran)
        out.exit_code = result.exit_code;
    out.ok = is_usable_capture(result.tool_ran, result.timed_out, result.output_truncated,
                               result.exit_code);
    return out;
}

// ── System/root keychain read: rung-1 SecItem (WP-B) ────────────────────────
//
// System.keychain and SystemRootCertificates.keychain ONLY -- the login
// keychain stays on the `security find-certificate` subprocess path via
// build_login_keychain_read_command() below (Decision-7 governed-shell
// exception, registered as sink `certificates/list_certs_macos#1` +
// `certificates/details_cert_macos#1` in docs/agent-spawn-sink-manifest.md).
// Gated on YUZU_HAVE_SECURITY_FRAMEWORK
// (meson.build, required:false + -D flag -- same shape as
// agents/plugins/users/meson.build's YUZU_HAVE_SYSTEMCONFIGURATION gate) so
// a box without the Security framework still builds; the #else fallback
// below compiles to an honest "could not read" result rather than reviving
// a subprocess call, so zero-raw-spawn holds either way.
#if defined(YUZU_HAVE_SECURITY_FRAMEWORK)

struct SecItemKeychainResult {
    std::vector<yuzu::certificates_x509::CertFields> certs;
    bool ok = false;       // false: the keychain itself could not be opened/queried.
    bool complete = false; // false: kMaxCertsPerKeychain capped the result --
                            // there were MORE certificates than were parsed.
};

/**
 * Enumerate every certificate in the ONE keychain at `keychain_path` via
 * SecItemCopyMatching (kSecMatchSearchList restricted to just that keychain
 * via SecKeychainOpen, kSecMatchLimitAll, kSecReturnRef) and hand each
 * result's DER encoding (SecCertificateCopyData) to
 * yuzu::certificates_x509::parse_der_cert. test_certificates_x509.cpp is a
 * fixture-only unit suite and cannot exercise this function directly (it
 * needs a real keychain), so the mechanism's equivalence to the
 * `security find-certificate -a -p` subprocess it replaces was established
 * empirically instead, and the check is REPRODUCIBLE rather than anecdotal:
 * enumerate each keychain through this function's query and compare the
 * resulting uppercase SHA-1 thumbprint SET to the set obtained by piping
 * `security find-certificate -a -p <keychain>` through
 * `openssl x509 -noout -fingerprint -sha1` per PEM block. Measured
 * 2026-08-17 on macOS 26.5.2 arm64: System.keychain 3/3 and
 * SystemRootCertificates.keychain 158/158 thumbprints, both sets IDENTICAL
 * (zero diff either way). Re-run that comparison, not a re-read of this
 * comment, when changing the query below.
 *
 * Every CoreFoundation object here is ScopedCFRef-owned (scoped_cfref.hpp)
 * -- read that header's reset()/same-identity contract before touching this
 * function. Every value handed to a ScopedCFRef below is a fresh
 * Create/Copy-rule +1 reference; `CFArrayGetValueAtIndex` results are
 * borrowed (Get-rule) references owned by the array and are never
 * ScopedCFRef-wrapped themselves, only passed to SecCertificateCopyData
 * (which DOES return an owned +1 CFDataRef, and IS wrapped).
 *
 * SecKeychainOpen/SecItemCopyMatching are synchronous CoreFoundation/
 * Security calls with no deadline or cancellation primitive of their own --
 * unlike the bounded subprocess runner they replace, there is no child
 * process here to SIGKILL against a wall clock. `action_deadline` is
 * therefore only ever consulted by the CALLER before invoking this function
 * (skip the call entirely once the action budget is already exhausted),
 * never during the call itself. kMaxCertsPerKeychain still caps how many
 * results are parsed from a single keychain (SecItemKeychainResult::complete
 * reports whether the cap was hit), same discipline as the PEM-block loop
 * (emit_keychain_rows_macos) this replaces for System/root.
 *
 * SecKeychainOpen is deprecated (macOS 10.10+) but remains the API this
 * package's spec calls for and is fully functional on every supported
 * host; the pragma below silences just that one, already-triaged warning.
 */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
SecItemKeychainResult read_keychain_secitem(const char* keychain_path) {
    SecItemKeychainResult out;

    SecKeychainRef raw_keychain = nullptr;
    if (SecKeychainOpen(keychain_path, &raw_keychain) != errSecSuccess || !raw_keychain)
        return out;
    yuzu::agent::ScopedCFRef<SecKeychainRef> keychain(raw_keychain);

    // SecKeychainOpen DOES NOT VALIDATE THE PATH -- it returns errSecSuccess
    // and a live SecKeychainRef for a path that does not exist, and for a
    // file that is not a keychain at all. SecItemCopyMatching over such a
    // reference then returns errSecItemNotFound, which is indistinguishable
    // from a genuinely empty keychain -- so without this check a missing,
    // deleted or corrupt System.keychain would be reported as "read fine,
    // zero certificates" rather than as a read failure, silently dropping
    // the entire trust store from a certificate inventory. That is exactly
    // the class of silent failure the subprocess path's PLAN-12 checked-read
    // discipline exists to prevent, and `security find-certificate -a -p`
    // (the call this replaces) DID fail non-zero on both inputs.
    //
    // SecKeychainGetStatus is the cheap discriminator (measured on macOS
    // 26.5.2, arm64): errSecSuccess for a real keychain,
    // errSecNoSuchKeychain (-25294) for a non-existent path,
    // errSecInvalidKeychain (-25295) for an existing non-keychain file.
    SecKeychainStatus keychain_status = 0;
    if (SecKeychainGetStatus(keychain.get(), &keychain_status) != errSecSuccess)
        return out; // ok stays false -> the caller emits its read-failed sentinel

    const void* keychain_values[] = {keychain.get()};
    yuzu::agent::ScopedCFRef<CFArrayRef> search_list(
        CFArrayCreate(nullptr, keychain_values, 1, &kCFTypeArrayCallBacks));
    if (!search_list)
        return out;

    yuzu::agent::ScopedCFRef<CFMutableDictionaryRef> query(CFDictionaryCreateMutable(
        nullptr, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks));
    if (!query)
        return out;
    CFDictionarySetValue(query.get(), kSecClass, kSecClassCertificate);
    CFDictionarySetValue(query.get(), kSecMatchSearchList, search_list.get());
    CFDictionarySetValue(query.get(), kSecMatchLimit, kSecMatchLimitAll);
    CFDictionarySetValue(query.get(), kSecReturnRef, kCFBooleanTrue);

    CFTypeRef raw_result = nullptr;
    OSStatus status = SecItemCopyMatching(query.get(), &raw_result);
    if (status == errSecItemNotFound) {
        // An empty keychain is a legitimate, successful result: zero
        // certificates, not a failure.
        out.ok = true;
        out.complete = true;
        return out;
    }
    if (status != errSecSuccess || !raw_result)
        return out;
    yuzu::agent::ScopedCFRef<CFTypeRef> result(raw_result);

    // kSecMatchLimitAll documents a CFArrayRef result; defensively also
    // accept a bare (non-array) single-item result, in case a future SDK's
    // behaviour for a one-item match ever differs from what this header was
    // verified against.
    std::vector<CFTypeRef> items;
    if (CFGetTypeID(result.get()) == CFArrayGetTypeID()) {
        auto array = static_cast<CFArrayRef>(const_cast<void*>(result.get()));
        CFIndex count = CFArrayGetCount(array);
        for (CFIndex i = 0; i < count; ++i)
            items.push_back(CFArrayGetValueAtIndex(array, i));
    } else {
        items.push_back(result.get());
    }

    out.ok = true;
    out.complete = items.size() <= kMaxCertsPerKeychain;
    std::size_t attempted = 0;
    for (CFTypeRef item : items) {
        if (attempted >= kMaxCertsPerKeychain)
            break;
        ++attempted;
        auto cert_ref = static_cast<SecCertificateRef>(const_cast<void*>(item));
        yuzu::agent::ScopedCFRef<CFDataRef> der(SecCertificateCopyData(cert_ref));
        if (!der) {
            out.complete = false; // conversion failure -- result is no longer exhaustive
            continue;
        }
        const auto* bytes = CFDataGetBytePtr(der.get());
        auto len = CFDataGetLength(der.get());
        if (!bytes || len <= 0) {
            out.complete = false;
            continue;
        }
        auto parsed = yuzu::certificates_x509::parse_der_cert(
            std::span<const unsigned char>(bytes, static_cast<std::size_t>(len)));
        if (parsed) {
            out.certs.push_back(std::move(*parsed));
        } else {
            out.complete = false; // libcrypto rejected a cert Security.framework accepted
        }
    }
    return out;
}
#pragma clang diagnostic pop

#else // !YUZU_HAVE_SECURITY_FRAMEWORK

struct SecItemKeychainResult {
    std::vector<yuzu::certificates_x509::CertFields> certs;
    bool ok = false;
    bool complete = false;
};

// Honest no-op fallback for a box built without the Security framework --
// same "genuinely-absent primitive" shape as macos_console_user.hpp's own
// console_user() fallback. Never falls back to a subprocess call: the
// caller reports SecItemKeychainResult::ok == false as the same
// "not_available|<keychain> read failed" sentinel a real SecItem failure
// would produce.
SecItemKeychainResult read_keychain_secitem(const char* /*keychain_path*/) {
    return {};
}

#endif // YUZU_HAVE_SECURITY_FRAMEWORK

// clamp_to_action_budget, parse_openssl_native_date and strip_leading_blank
// moved to certificates_macos_parsers.hpp (shared with the unit test).

// `deadline` is the CALLER's already-clamped budget for this one openssl
// call (see clamp_to_action_budget) -- never the raw kCertParseDeadline
// constant directly, so a whole-action budget nearing exhaustion (BR-03/
// FP-CERTS-03) is honoured even for a single PEM block's parse.
CertRecord parse_pem_block_macos(const std::string& pem_block, const std::string& store_name,
                                 std::chrono::milliseconds deadline) {
    CertRecord rec;
    rec.store = store_name;
    rec.subject = "(unknown)";
    rec.issuer = "(unknown)";
    rec.not_before = "(unknown)";
    rec.not_after = "(unknown)";
    rec.serial = "(unknown)";
    rec.thumbprint = "(unknown)";
    rec.key_usage = "(none)";

    // Write PEM to a temp file to avoid shell injection via echo (PEM
    // content from the keychain could contain single quotes that break an
    // echo '...' pattern). yuzu::TempFile (mkstemps/O_EXCL, mode 0600) gives
    // each call its own unique, exclusively-created path -- a fixed shared
    // name would collide when two calls run concurrently.
    auto tmp_file_result = yuzu::TempFile::create("yuzu-cert-", ".pem");
    if (!tmp_file_result) {
        rec.subject = "(temp file error)";
        return rec;
    }
    auto tmp_file = std::move(*tmp_file_result);
    {
        std::ofstream tmp(tmp_file.path(), std::ios::trunc);
        if (!tmp) {
            rec.subject = "(temp file error)";
            return rec;
        }
        tmp << pem_block;
    }

    // ONE bounded subprocess call for every field (was up to 7 separate
    // popen-based calls). LibreSSL happily accepts multiple print options on a
    // single invocation and emits them in the EXACT order given, so
    // -subject/-issuer/-startdate/-enddate/-serial/-fingerprint each
    // contribute one fixed-position, never-indented "label=value" line,
    // followed by the full -text dump (used only for Key Usage below --
    // -text replaces the removed `-ext keyUsage`, which LibreSSL also
    // rejects). Absolute path, matching the /usr/bin/security convention
    // used by every other privileged subprocess call in this file (PATH is
    // not trusted for a process that can run as root).
    // sink: certificates/parse_pem_block_macos#1 — rung-2 runner argv (LibreSSL
    // rejects -ext keyUsage, so this login-keychain block parse stays on the CLI),
    // see manifest
    auto result = yuzu::agent::run_bounded_subprocess(
        {"/usr/bin/openssl", "x509", "-noout", "-in", tmp_file.path(), "-subject", "-issuer",
         "-startdate", "-enddate", "-serial", "-fingerprint", "-sha1", "-text"},
        yuzu::agent::SubprocessOptions{.deadline = deadline});

    // SRE S1 observability: this is the one certificate-reading call site that
    // goes through run_bounded_subprocess directly (not run_bounded_checked),
    // so surface a degraded openssl parse here too, matching that wrapper's WARN.
    if (result.timed_out || result.output_truncated) {
        spdlog::warn("certificates: openssl x509 parse {} (timed_out={}, output_truncated={})",
                     result.timed_out ? "timed out" : "output truncated", result.timed_out,
                     result.output_truncated);
    }

    // A killed or capture-capped run's output is only a PARTIAL prefix of
    // the real dump -- it may have captured subject/issuer but been cut
    // off before serial/fingerprint/Key Usage, which would silently shift
    // every subsequent positional field read below onto the wrong line.
    // Treated as wholly unusable rather than parsed piecemeal, the same
    // discipline filesystem_plugin.cpp applies to a timed-out codesign run
    // (PLAN-02: never report a partial capture as if it were a complete,
    // trustworthy read) -- BR-03's "honest sentinel on truncation/timeout".
    // A nonzero exit is rejected too (fix-round finding FP-CERTS-05): a
    // fully-captured, non-timed-out run can still have failed partway
    // through -- e.g. openssl prints a plausible preamble then exits
    // nonzero -- so trusting the captured text without checking the exit
    // status would risk misreporting a failure as valid certificate data.
    if (!is_usable_capture(result.tool_ran, result.timed_out, result.output_truncated,
                           result.exit_code))
        return rec;

    // Positional field parsing lives in the shared, unit-tested
    // parse_openssl_combined_output (certificates_macos_parsers.hpp); rec keeps
    // the store this keychain read set and adopts the parsed identity fields.
    auto parsed = parse_openssl_combined_output(result.output);
    rec.subject = std::move(parsed.subject);
    rec.issuer = std::move(parsed.issuer);
    rec.not_before = std::move(parsed.not_before);
    rec.not_after = std::move(parsed.not_after);
    rec.serial = std::move(parsed.serial);
    rec.thumbprint = std::move(parsed.thumbprint);
    rec.key_usage = std::move(parsed.key_usage);

    return rec;
}

// Whether THIS process (the agent daemon) is already root. Mirrors
// quarantine_plugin.cpp's sudo_prefix(): the shipped macOS LaunchDaemon has
// no `UserName` key today, so it runs as root (docs/agent-privilege-model.md's
// TL;DR) and `launchctl asuser` -- which itself requires root privileges,
// per `man launchctl` -- already succeeds with no escalation. The target
// least-privilege `_yuzu` account (future hardening, #1455) is NOT root, so
// build_login_keychain_read_command() uses this to decide whether it needs
// to add its own outer `sudo -n` hop first. Cached: EUID can't change during
// the agent's lifetime.
bool caller_is_root() {
    static const bool is_root = (geteuid() == 0);
    return is_root;
}

/**
 * Resolve the current console (GUI) user via subprocess. SystemConfiguration
 * IS linkable from this LaunchDaemon (see agents/shared/macos_console_user.hpp's
 * SCDynamicStoreCopyConsoleUser, already used by the users plugin) -- this
 * shells out to `stat`/`id` by deliberate choice, not because the framework is
 * unavailable: `stat -f%Su /dev/console` reports the console DEVICE owner,
 * while SCDynamicStoreCopyConsoleUser reports the Aqua SESSION owner, and the
 * two diverge under fast user switching / screen sharing -- WHICH user's login
 * keychain this plugin reads is an operator-visible behavioural contract that
 * a rung-1 promotion would need to verify separately (tracked in #2380). See
 * docs/agent-spawn-sink-manifest.md's `resolve_console_user#1` row. Returns
 * std::nullopt when there is no interactive console session (login window /
 * headless -- stat reports the "root" sentinel, see
 * yuzu::macos::is_no_console_user) OR when the resolved username/uid fails
 * the shared allowlist/numeric validation: an unsafe value is never
 * interpolated into a command, so it is treated exactly like "no console
 * user" rather than risking a later step trusting it.
 *
 * `action_deadline` is the CALLER's whole-action budget (BR-03/
 * FP-CERTS-03): this is the FIRST subprocess work any action performs, so
 * both calls below clamp to it via clamp_to_action_budget rather than the
 * raw kCertParseDeadline constant, and bail out to std::nullopt (same as
 * "no console session") if the budget is already exhausted before either
 * can even be attempted.
 */
std::optional<yuzu::macos::ConsoleUser> resolve_console_user(
        std::chrono::steady_clock::time_point action_deadline) {
    auto stat_deadline = clamp_to_action_budget(action_deadline, kCertParseDeadline);
    if (stat_deadline <= std::chrono::milliseconds::zero())
        return std::nullopt;
    // sink: certificates/resolve_console_user#1 — rung-2 runner argv;
    // SystemConfiguration IS linkable here, deliberately not used (device-
    // vs session-owner semantics), see manifest
    auto stat_result = run_bounded_checked({"/usr/bin/stat", "-f%Su", "/dev/console"},
                                           yuzu::agent::SubprocessOptions{
                                               .deadline = stat_deadline},
                                           "console-user stat /dev/console");
    auto username =
        yuzu::macos::parse_console_user_output(stat_result.ok ? stat_result.output : std::string{});
    if (yuzu::macos::is_no_console_user(username))
        return std::nullopt;
    if (!yuzu::macos::is_valid_username(username))
        return std::nullopt;

    // `username` is already allowlist-validated above -- run_bounded_subprocess
    // execs argv directly (no shell), so this was never a shell-injection
    // vector even before, but the validate-before-use order is unchanged.
    auto id_deadline = clamp_to_action_budget(action_deadline, kCertParseDeadline);
    if (id_deadline <= std::chrono::milliseconds::zero())
        return std::nullopt;
    // sink: certificates/resolve_console_user#2 — rung-2 runner argv, same
    // constraint as #1, see manifest
    auto id_result = run_bounded_checked({"/usr/bin/id", "-u", username},
                                         yuzu::agent::SubprocessOptions{
                                             .deadline = id_deadline},
                                         "console-user id -u");
    // parse_console_user_output is a plain leading/trailing-whitespace trim
    // (see its own doc comment) -- reused here for `id -u`'s output too
    // (fix-round finding FP-CERTS-01): run_bounded_subprocess's `.output`
    // is the raw captured stream, trailing '\n' included, and
    // is_valid_uid() rejects any non-digit character outright, so an
    // untrimmed "501\n" always failed validation and this branch always
    // returned std::nullopt -- silently disabling login-keychain reads
    // entirely for every real console user.
    auto uid = yuzu::macos::parse_console_user_output(id_result.ok ? id_result.output
                                                                   : std::string{});
    if (!yuzu::macos::is_valid_uid(uid))
        return std::nullopt;

    return yuzu::macos::ConsoleUser{std::move(username), std::move(uid)};
}

// canonical_thumbprint() moved to the shared __linux__/__APPLE__ block above
// -- details_cert_linux/delete_cert_linux need the identical fold.

// BlockIdentityOutcome / classify_block_identity moved to
// certificates_macos_parsers.hpp (shared with the unit test).

/**
 * Enumerate one keychain's PEM blocks and emit rows for it, filtered by
 * expiry. `action_deadline` is the CALLER's whole-action budget (shared
 * across every keychain that single list_certs_macos() call reads);
 * kMaxCertsPerKeychain additionally caps how many blocks THIS keychain
 * alone contributes, so one pathological keychain can't spend the entire
 * action budget by itself. Once either bound is spent, remaining blocks in
 * this keychain are simply not parsed/emitted -- never a fabricated row --
 * and this returns false so the caller can emit an honest "scan
 * incomplete" sentinel instead of silently presenting a truncated keychain
 * as a complete result (fix-round finding FP-CERTS-02). Returns true only
 * when every block in `pem` was scanned within budget.
 */
bool emit_keychain_rows_macos(yuzu::CommandContext& ctx, const std::string& pem,
                              const std::string& store_label, int expiring_days,
                              std::chrono::steady_clock::time_point action_deadline) {
    std::size_t parsed = 0;
    for (const auto& block : split_pem_blocks(pem)) {
        auto parse_deadline = clamp_to_action_budget(action_deadline, kCertParseDeadline);
        if (parsed >= kMaxCertsPerKeychain || parse_deadline <= std::chrono::milliseconds::zero())
            return false;
        ++parsed;
        auto rec = parse_pem_block_macos(block, store_label, parse_deadline);
        if (expires_within_days(rec.not_after, expiring_days)) {
            ctx.write_output(rec.to_row());
        }
    }
    return true;
}

void list_certs_macos(yuzu::CommandContext& ctx, std::string_view store_filter,
                      int expiring_days) {
    ctx.write_output("subject|issuer|thumbprint|not_before|not_after|serial|store|key_usage");

    // Whole-action budget across EVERYTHING this call does, including
    // console-user resolution (BR-03, mirrors installed_apps_plugin.cpp's
    // kEnrichmentBudget) -- started here, before the first subprocess this
    // action may run, so the 60s bound covers the call's entire wall-clock
    // cost rather than just the per-certificate parsing loops (fix-round
    // finding FP-CERTS-03: previously this was created only AFTER
    // console-user resolution, and every keychain-level `security` read
    // still received its own full, unclamped kKeychainReadDeadline
    // regardless of how much budget was already spent -- letting one call
    // run to roughly 100s in the worst case). See emit_keychain_rows_macos's
    // own comment for how the per-keychain cap and this budget interact.
    const auto action_deadline = std::chrono::steady_clock::now() + kCertActionBudget;

    auto console_user = resolve_console_user(action_deadline);
    auto plan = yuzu::macos::resolve_store_plan(store_filter, console_user.has_value());

    if (plan.sentinel_required) {
        // store=login was explicitly requested and there is no console
        // session to read it from -- never a silent empty (the header row
        // above with zero rows following would read as "ran fine, no
        // certs") and never a fabricated result.
        ctx.write_output("not_available|no console session");
        mark_result_partial(ctx, "login-keychain");
        return;
    }

    // System.keychain / SystemRootCertificates.keychain: rung-1 SecItem read
    // (WP-B) via read_keychain_secitem -- no bounded-subprocess deadline
    // applies to the call itself (see that function's own comment); the
    // action_deadline check below only decides whether to even ATTEMPT it.
    // A checked failure emits an honest sentinel row instead of silently
    // contributing zero rows, same discipline PLAN-12 established for the
    // subprocess path this replaces.
    if (plan.want_system) {
        if (clamp_to_action_budget(action_deadline, kKeychainReadDeadline) <=
            std::chrono::milliseconds::zero()) {
            ctx.write_output("not_available|System.keychain action deadline exceeded");
            mark_result_partial(ctx, "secitem:System.keychain");
        } else {
            auto sys_result = read_keychain_secitem(yuzu::macos::system_keychain_path().c_str());
            if (sys_result.ok) {
                for (const auto& cert : sys_result.certs) {
                    auto rec = to_cert_record(cert, "System.keychain");
                    if (expires_within_days(rec.not_after, expiring_days)) {
                        ctx.write_output(rec.to_row());
                    }
                }
                if (!sys_result.complete) {
                    ctx.write_output("not_available|System.keychain scan incomplete");
                    mark_result_partial(ctx, "secitem:System.keychain");
                }
            } else {
                ctx.write_output("not_available|System.keychain read failed");
                mark_result_partial(ctx, "secitem:System.keychain");
            }
        }
    }

    if (plan.want_root) {
        if (clamp_to_action_budget(action_deadline, kKeychainReadDeadline) <=
            std::chrono::milliseconds::zero()) {
            ctx.write_output(
                "not_available|SystemRootCertificates.keychain action deadline exceeded");
            mark_result_partial(ctx, "secitem:SystemRootCertificates.keychain");
        } else {
            auto root_result = read_keychain_secitem(yuzu::macos::root_keychain_path().c_str());
            if (root_result.ok) {
                for (const auto& cert : root_result.certs) {
                    auto rec = to_cert_record(cert, "SystemRootCertificates.keychain");
                    if (expires_within_days(rec.not_after, expiring_days)) {
                        ctx.write_output(rec.to_row());
                    }
                }
                if (!root_result.complete) {
                    ctx.write_output(
                        "not_available|SystemRootCertificates.keychain scan incomplete");
                    mark_result_partial(ctx, "secitem:SystemRootCertificates.keychain");
                }
            } else {
                ctx.write_output("not_available|SystemRootCertificates.keychain read failed");
                mark_result_partial(ctx, "secitem:SystemRootCertificates.keychain");
            }
        }
    }

    if (plan.want_login) {
        // console_user is guaranteed engaged here: resolve_store_plan only
        // sets want_login when has_console_user was true.
        auto cmd = yuzu::macos::build_login_keychain_read_command(
            console_user->uid, console_user->username, caller_is_root());
        if (cmd.empty()) {
            // Defensive only -- resolve_console_user() already validated
            // uid/username before console_user was populated, so
            // build_login_keychain_read_command()'s own re-validation
            // should never fail here. Still an honest sentinel rather than
            // a silent no-op if it somehow does.
            ctx.write_output("not_available|login keychain command construction failed");
            mark_result_partial(ctx, "login-keychain");
        } else {
            auto read_deadline = clamp_to_action_budget(action_deadline, kKeychainReadDeadline);
            if (read_deadline <= std::chrono::milliseconds::zero()) {
                ctx.write_output("not_available|login keychain action deadline exceeded");
                mark_result_partial(ctx, "login-keychain");
            } else {
                // The launchctl/sudo wrapper relies on the outer shell's
                // `~username` expansion (build_login_keychain_read_command's
                // own comment) -- run_bounded_subprocess execs argv directly
                // with no shell, so it can't expand that itself. `cmd` is a
                // single, already-validated (uid/username allowlist-checked
                // inside build_login_keychain_read_command) string with no
                // caller-controlled shell metacharacters, so handing it to
                // "/bin/sh -c" as ONE argv element keeps the outer exec
                // shell-argument-free while still routing the whole call
                // through the bounded runner for its deadline/cap/cancel
                // support -- the same "trusted script as a single argv
                // element" shape script_exec_plugin.cpp's bash action uses.
                // sink: certificates/list_certs_macos#1 — Decision-7 governed-shell exception, see manifest
                auto login_result = run_bounded_checked(
                    {"/bin/sh", "-c", cmd},
                    yuzu::agent::SubprocessOptions{.deadline = read_deadline},
                    "login keychain read");
                if (login_result.ok) {
                    if (!emit_keychain_rows_macos(ctx, login_result.output, "login.keychain-db",
                                                  expiring_days, action_deadline)) {
                        ctx.write_output("not_available|login keychain scan incomplete");
                        mark_result_partial(ctx, "login-keychain");
                    }
                } else {
                    // A missing sudoers grant, a launchctl/sudo failure, or an
                    // inaccessible keychain path all land here. Report it
                    // honestly instead of emitting zero rows, which would be
                    // indistinguishable from "this keychain is genuinely
                    // empty".
                    ctx.write_output("not_available|login keychain read failed");
                    mark_result_partial(ctx, "login-keychain");
                }
            }
        }
    }
}

void details_cert_macos(yuzu::CommandContext& ctx, std::string_view thumbprint,
                        std::string_view store_filter) {
    ctx.write_output("subject|issuer|thumbprint|not_before|not_after|serial|store|key_usage");

    // Whole-action budget across EVERYTHING this call does, including
    // console-user resolution -- see list_certs_macos's matching comment
    // (BR-03/fix-round finding FP-CERTS-03).
    const auto action_deadline = std::chrono::steady_clock::now() + kCertActionBudget;

    auto console_user = resolve_console_user(action_deadline);
    auto plan = yuzu::macos::resolve_store_plan(store_filter, console_user.has_value());

    if (plan.sentinel_required) {
        ctx.write_output("not_available|no console session");
        mark_result_partial(ctx, "login-keychain");
        return;
    }

    // Canonicalized once so the loop below is a plain `==` against
    // parse_pem_block_macos's always-uppercase output -- the thumbprint
    // parameter is documented case-insensitive (certificates.yaml) but was
    // previously compared as-is, so a lowercase caller-supplied thumbprint
    // silently never matched (CERT-READ-01).
    auto needle = canonical_thumbprint(thumbprint);

    // Tri-state per-keychain scan outcome (fix-round finding FP-CERTS-02):
    // a search that hits the cap/deadline before reaching a conclusive
    // answer, or that encounters a block classify_block_identity can't
    // establish the identity of (a failed/timed-out per-cert openssl
    // parse leaves the honest "(unknown)" sentinel, never a fabricated
    // thumbprint), can never positively prove the needle is ABSENT from
    // that keychain -- both must report kIncomplete, never silently fold
    // into a clean kNotFound that ultimately surfaces as the definitive
    // "status|not_found" below.
    enum class ScanOutcome { kFound, kNotFound, kIncomplete };

    auto check = [&](const std::string& pem, const std::string& store) -> ScanOutcome {
        std::size_t parsed = 0;
        for (const auto& block : split_pem_blocks(pem)) {
            auto parse_deadline = clamp_to_action_budget(action_deadline, kCertParseDeadline);
            if (parsed >= kMaxCertsPerKeychain ||
                parse_deadline <= std::chrono::milliseconds::zero())
                return ScanOutcome::kIncomplete;
            ++parsed;
            auto rec = parse_pem_block_macos(block, store, parse_deadline);
            switch (classify_block_identity(rec.thumbprint, needle)) {
            case BlockIdentityOutcome::kMatch:
                ctx.write_output(rec.to_row());
                return ScanOutcome::kFound;
            case BlockIdentityOutcome::kInconclusive:
                return ScanOutcome::kIncomplete;
            case BlockIdentityOutcome::kNoMatch:
                break;
            }
        }
        return ScanOutcome::kNotFound;
    };

    // Same tri-state scan, but over a SecItem-derived CertFields vector
    // (System/root, WP-B rung-1) instead of raw PEM blocks -- reuses the
    // SAME classify_block_identity decision `check` above uses, so the two
    // scans can never drift on what counts as a match/no-match/inconclusive
    // identity. `result.complete == false` (kMaxCertsPerKeychain capped the
    // read) folds into kIncomplete exactly like `check`'s own cap/deadline
    // check does.
    auto check_secitem = [&](const SecItemKeychainResult& result,
                             const std::string& store) -> ScanOutcome {
        for (const auto& cert : result.certs) {
            switch (classify_block_identity(cert.thumbprint, needle)) {
            case BlockIdentityOutcome::kMatch:
                ctx.write_output(to_cert_record(cert, store).to_row());
                return ScanOutcome::kFound;
            case BlockIdentityOutcome::kInconclusive:
                return ScanOutcome::kIncomplete;
            case BlockIdentityOutcome::kNoMatch:
                break;
            }
        }
        return result.complete ? ScanOutcome::kNotFound : ScanOutcome::kIncomplete;
    };

    // A checked read failure, an exhausted action budget, or an incomplete
    // scan on a selected store all mean the search below is incomplete for
    // that store -- remembered (first failure wins) so the final result
    // can honestly report "not_available" instead of a false "not_found"
    // if no match turns up. A match found in a store that DID read/scan
    // successfully is still reported normally, even if an earlier store
    // had already failed.
    bool read_failed = false;
    std::string_view failure_reason;
    // Which half of the hybrid read failed, for the ABI4 result seam below --
    // set together with failure_reason at every site (first failure wins), so
    // the machine-visible provenance can never name a different keychain from
    // the operator-visible reason.
    std::string_view failure_provenance;

    if (plan.want_system) {
        if (clamp_to_action_budget(action_deadline, kKeychainReadDeadline) <=
            std::chrono::milliseconds::zero()) {
            read_failed = true;
            failure_reason = "System.keychain action deadline exceeded";
            failure_provenance = "secitem:System.keychain";
        } else {
            auto sys_result = read_keychain_secitem(yuzu::macos::system_keychain_path().c_str());
            if (!sys_result.ok) {
                read_failed = true;
                failure_reason = "System.keychain read failed";
                failure_provenance = "secitem:System.keychain";
            } else {
                switch (check_secitem(sys_result, "System.keychain")) {
                case ScanOutcome::kFound:
                    return;
                case ScanOutcome::kIncomplete:
                    read_failed = true;
                    failure_reason = "System.keychain scan incomplete";
                    failure_provenance = "secitem:System.keychain";
                    break;
                case ScanOutcome::kNotFound:
                    break;
                }
            }
        }
    }

    if (plan.want_root) {
        if (clamp_to_action_budget(action_deadline, kKeychainReadDeadline) <=
            std::chrono::milliseconds::zero()) {
            if (!read_failed) {
                read_failed = true;
                failure_reason = "SystemRootCertificates.keychain action deadline exceeded";
                failure_provenance = "secitem:SystemRootCertificates.keychain";
            }
        } else {
            auto root_result = read_keychain_secitem(yuzu::macos::root_keychain_path().c_str());
            if (!root_result.ok) {
                if (!read_failed) {
                    read_failed = true;
                    failure_reason = "SystemRootCertificates.keychain read failed";
                    failure_provenance = "secitem:SystemRootCertificates.keychain";
                }
            } else {
                switch (check_secitem(root_result, "SystemRootCertificates.keychain")) {
                case ScanOutcome::kFound:
                    return;
                case ScanOutcome::kIncomplete:
                    if (!read_failed) {
                        read_failed = true;
                        failure_reason = "SystemRootCertificates.keychain scan incomplete";
                        failure_provenance = "secitem:SystemRootCertificates.keychain";
                    }
                    break;
                case ScanOutcome::kNotFound:
                    break;
                }
            }
        }
    }

    if (plan.want_login) {
        auto cmd = yuzu::macos::build_login_keychain_read_command(
            console_user->uid, console_user->username, caller_is_root());
        if (cmd.empty()) {
            if (!read_failed) {
                read_failed = true;
                failure_reason = "login keychain command construction failed";
                failure_provenance = "login-keychain";
            }
        } else {
            auto read_deadline = clamp_to_action_budget(action_deadline, kKeychainReadDeadline);
            if (read_deadline <= std::chrono::milliseconds::zero()) {
                if (!read_failed) {
                    read_failed = true;
                    failure_reason = "login keychain action deadline exceeded";
                    failure_provenance = "login-keychain";
                }
            } else {
                // See list_certs_macos's matching comment: `cmd` needs the
                // outer shell's `~username` expansion, so it is run as a
                // single trusted argv element via "/bin/sh -c" rather than a
                // clean multi-element argv.
                // sink: certificates/details_cert_macos#1 — Decision-7 governed-shell exception, see manifest
                auto login_result = run_bounded_checked(
                    {"/bin/sh", "-c", cmd},
                    yuzu::agent::SubprocessOptions{.deadline = read_deadline},
                    "login keychain read");
                if (!login_result.ok) {
                    if (!read_failed) {
                        read_failed = true;
                        failure_reason = "login keychain read failed";
                        failure_provenance = "login-keychain";
                    }
                } else {
                    switch (check(login_result.output, "login.keychain-db")) {
                    case ScanOutcome::kFound:
                        return;
                    case ScanOutcome::kIncomplete:
                        if (!read_failed) {
                            read_failed = true;
                            failure_reason = "login keychain scan incomplete";
                            failure_provenance = "login-keychain";
                        }
                        break;
                    case ScanOutcome::kNotFound:
                        break;
                    }
                }
            }
        }
    }

    if (read_failed) {
        // Don't fall through to "status|not_found" below -- that would
        // claim a completed, negative search when a selected keychain was
        // never actually readable OR its scan never reached a conclusive
        // answer (missing sudoers grant, launchctl/sudo failure, an
        // inaccessible keychain path, the cap/deadline hit mid-scan, an
        // unparseable block, ...). See list_certs_macos's matching comment.
        ctx.write_output(std::format("not_available|{}", failure_reason));
        mark_result_partial(ctx, failure_provenance);
        return;
    }

    ctx.write_output("status|not_found");
}

/**
 * Re-enumerate `keychain_path` and report whether `canonical_needle` (an
 * already-uppercased thumbprint -- see canonical_thumbprint) is present.
 * Used by delete_cert_macos() to VERIFY a delete actually took effect
 * rather than trusting a zero exit status alone -- `security
 * delete-certificate` can exit 0 without the item actually being gone
 * (ACL/SIP quirks, an unexpected keychain state), and reporting "deleted"
 * in that case would be exactly the false-success this package exists to
 * prevent. Returns std::nullopt when the keychain itself could not be read
 * (locked, missing, permission denied, a `security` failure, ...) --
 * delete_cert_macos() treats that as the unreadable-keychain verdict,
 * never "absent": a verification read that could not run proves nothing
 * about the outcome. An UNRELATED unparseable block (parse_pem_block_macos
 * falls back to the literal "(unknown)" on a per-record openssl/temp-file
 * failure -- classify_block_identity reports kInconclusive) does NOT abort
 * the proof (UP-5): openssl could not turn it into a cert, so it can never be
 * a positive match for the needle, and aborting on it made a genuinely
 * successful delete report failure (kVerifyUnreadable) whenever the keychain
 * also held any unrelated malformed cert. Such blocks are skipped and the
 * scan continues; only a definitive match returns `true`, and a keychain that
 * was fully read AND fully scanned within budget with no match returns
 * `false` (provably absent). The fail-safe is preserved for the cases that
 * genuinely prove nothing -- a `security` read failure, or a cap/deadline-
 * truncated scan -- which still return std::nullopt (see fold_presence_scan),
 * so an unread/partly-read keychain is never reported as a clean "deleted".
 * Reuses run_bounded_checked + the same PEM-enumeration path as list/details
 * rather than adding a second certificate-reading mechanism.
 *
 * `action_deadline` is the CALLER's whole-action budget (fix-round finding
 * FP-CERTS-R3: this used to start its own fresh kCertActionBudget window
 * regardless of how much of delete_cert_macos()'s own budget the preceding
 * `security delete-certificate` call had already spent, letting the pair
 * run to roughly 75s worst case). The keychain read AND every per-block
 * parse below now clamp to this same shared deadline via
 * clamp_to_action_budget, same as list/details_cert_macos. If the budget is
 * already exhausted before the read can even be attempted, this returns
 * std::nullopt without issuing a doomed call -- classify_delete_verdict
 * already treats std::nullopt as kVerifyUnreadable (an honest "action
 * deadline exceeded" outcome), never kDeleted.
 */
std::optional<bool> keychain_contains_thumbprint(
    const std::string& keychain_path, const std::string& canonical_needle,
    std::chrono::steady_clock::time_point action_deadline) {
    auto read_deadline = clamp_to_action_budget(action_deadline, kKeychainReadDeadline);
    if (read_deadline <= std::chrono::milliseconds::zero()) {
        return std::nullopt;
    }
    // sink: certificates/keychain_contains_thumbprint#1 — rung-2 runner argv,
    // fixed literal keychain path, see manifest
    auto result = run_bounded_checked(
        {"/usr/bin/security", "find-certificate", "-a", "-p", keychain_path},
        yuzu::agent::SubprocessOptions{.deadline = read_deadline}, "keychain verify read");
    if (!result.ok)
        return std::nullopt;

    // Accumulate each block's identity outcome and hand the final verdict to
    // the shared, unit-tested fold_presence_scan. A definitive match
    // short-circuits (no need to parse the rest); an unrelated unparseable
    // block (kInconclusive) is collected and skipped rather than aborting the
    // proof (UP-5, see the function comment). A cap/deadline-truncated scan
    // is passed as scan_complete=false so fold_presence_scan yields the honest
    // std::nullopt -- an incomplete scan can never positively prove absence.
    std::vector<BlockIdentityOutcome> outcomes;
    std::size_t parsed = 0;
    for (const auto& block : split_pem_blocks(result.output)) {
        auto parse_deadline = clamp_to_action_budget(action_deadline, kCertParseDeadline);
        if (parsed >= kMaxCertsPerKeychain || parse_deadline <= std::chrono::milliseconds::zero()) {
            return fold_presence_scan(outcomes, /*scan_complete=*/false);
        }
        ++parsed;
        auto rec = parse_pem_block_macos(block, "", parse_deadline);
        auto outcome = classify_block_identity(rec.thumbprint, canonical_needle);
        if (outcome == BlockIdentityOutcome::kMatch)
            return true;
        outcomes.push_back(outcome);
    }
    return fold_presence_scan(outcomes, /*scan_complete=*/true);
}

// is_provably_absent_macos moved to certificates_macos_parsers.hpp (shared
// with the unit test).

bool delete_cert_macos(yuzu::CommandContext& ctx, std::string_view thumbprint,
                       std::string_view store) {
    // Validate thumbprint is hex-only to prevent command injection.
    if (!is_valid_thumbprint(thumbprint)) {
        ctx.write_output("error|invalid thumbprint format (expected 40 hex characters)");
        return false;
    }

    // SystemRootCertificates.keychain is SEALED on modern (SIP-protected)
    // macOS -- /System/Library/Keychains/... sits under the sealed system
    // volume and cannot be modified by `security delete-certificate` (or
    // anything else short of disabling SIP). Advertising deletion from it
    // as achievable would report a root-trust change that can never
    // actually take effect: reject outright, before ever shelling out, with
    // the same fail-closed posture as the unsupported-store branch below --
    // never silently redirect to a writable keychain either. This check
    // MUST come before resolve_delete_keychain_path(): that resolver maps
    // "root" to a real path (it is a legitimate read target for list/
    // details), so the delete-specific sealed-root rejection has to happen
    // here, not there.
    if (store == "root") {
        // error| prefix for convention consistency (SHOULD-3): every other
        // delete rejection in this function emits `error|<msg>`, so the
        // sealed-root case does too rather than a bespoke
        // `certificates|unsupported|` grammar a downstream consumer would have
        // to special-case.
        ctx.write_output(
            "error|SystemRootCertificates.keychain is sealed on this macOS "
            "version (System Integrity Protection) and cannot be modified");
        return false;
    }

    // Delete acts on exactly one keychain; store otherwise preserves
    // today's unconditional System.keychain target for the unset/"MY"
    // default and "System" (see yuzu::macos::resolve_delete_keychain_path).
    // store=login is deliberately NOT supported for delete here -- unlike
    // list/details it would need the same asuser/sudo dance (and its own
    // honest-sentinel handling) for a destructive action that has no test
    // coverage in this change; left for a follow-up if a real need shows
    // up. "login", "all", and any other unrecognized value (root is
    // already handled above) are REJECTED rather than silently redirected
    // to System.keychain -- a destructive action must never target a
    // keychain the caller didn't ask for.
    auto target = yuzu::macos::resolve_delete_keychain_path(store);
    if (!target) {
        // store is caller-supplied free text (the cross-platform dispatcher
        // passes the raw `store` param straight through) -- safe_output_field
        // it (K-7) so a hostile value containing '|' or embedded CR/LF can
        // never inject an extra column/row into this pipe/newline-delimited
        // output, same as CertRecord::to_row() above.
        ctx.write_output(std::format("error|store '{}' is not supported for delete",
                                     yuzu::util::safe_output_field(store)));
        return false;
    }

    auto needle = canonical_thumbprint(thumbprint);

    // Whole-action budget (BR-03) covering the pre-delete presence check
    // (K-4, below), the delete command, AND its post-delete verify read,
    // same pattern as list/details_cert_macos (fix-round finding
    // FP-CERTS-R3: before this, the verify read computed its own fresh
    // kCertActionBudget window independent of what the delete call above it
    // had already spent, letting the pair run to roughly 75s worst case).
    // Every subprocess this action runs clamps to it via
    // clamp_to_action_budget rather than receiving its own full, unclamped
    // deadline.
    const auto action_deadline = std::chrono::steady_clock::now() + kCertActionBudget;

    // K-4: prove the thumbprint is present (or absent) BEFORE ever running
    // the destructive delete. Without this, deleting an ABSENT thumbprint
    // hits `security delete-certificate`'s own exit-1 "not found" path,
    // which the code below reports as a generic kCommandFailed
    // `error|delete failed ...` -- inconsistent with Windows/Linux (and
    // this macOS action's own pre-change behaviour), which report
    // `status|not_found` rc 0 for an absent cert. Idempotent "ensure-absent"
    // remediation depends on that contract. Reuses the SAME
    // keychain_contains_thumbprint helper the post-delete verify below
    // already trusts, clamped to the same action_deadline budget, so this
    // pre-check can never itself blow the whole-action budget unaccounted
    // for. See is_provably_absent_macos for why only a definitive `false`
    // (never std::nullopt) takes the not_found branch.
    auto pre_delete_presence = keychain_contains_thumbprint(*target, needle, action_deadline);
    if (is_provably_absent_macos(pre_delete_presence)) {
        ctx.write_output("status|not_found");
        return true;
    }

    auto delete_deadline = clamp_to_action_budget(action_deadline, kKeychainReadDeadline);
    if (delete_deadline <= std::chrono::milliseconds::zero()) {
        // Defensive only -- action_deadline is set immediately above, so a
        // freshly-clamped kKeychainReadDeadline cannot itself be zero. Kept
        // for parity with clamp_to_action_budget's other call sites, which
        // must all treat zero as "do not even attempt this subprocess"
        // (see its own comment).
        ctx.write_output("error|action deadline exceeded before delete could run");
        return false;
    }

    // Inspect the ACTUAL exit status of `security delete-certificate`
    // rather than grepping its combined stdout+stderr for words like
    // "error": text-only classification would report "deleted" for any
    // output that doesn't happen to contain those words, including
    // genuine operational failures (permission denied, a locked keychain,
    // ...). merge_stderr=true (was the shell string's `2>&1`) so a failure
    // diagnostic -- `security` writes those to stderr -- is captured into
    // `.output` for the error message below.
    // sink: certificates/delete_cert_macos#1 — rung-2 runner argv, MUTATING,
    // hex-validated thumbprint + fixed literal keychain path, see manifest
    auto delete_result = run_bounded_checked(
        {"/usr/bin/security", "delete-certificate", "-Z", needle, *target},
        yuzu::agent::SubprocessOptions{.deadline = delete_deadline, .merge_stderr = true},
        "delete-certificate");

    // Only re-enumerate to verify when the delete command itself exited 0
    // -- a nonzero/abnormal exit is already a terminal failure, and
    // re-checking presence after a command that didn't run to completion
    // would tell us nothing its own exit status didn't already tell us.
    // Checked via exit_code rather than .ok deliberately: .ok also
    // requires a fully-captured, non-timed-out, non-capped read of THIS
    // command's own diagnostic text (see run_bounded_checked), which is
    // irrelevant here -- only whether `security delete-certificate` itself
    // exited cleanly decides whether a re-enumeration is warranted.
    std::optional<bool> still_present;
    if (delete_result.exit_code == 0) {
        // keychain_contains_thumbprint clamps to the SAME action_deadline
        // (see its own comment) -- if the delete call above consumed most
        // of the budget, the verify read either gets whatever remains or,
        // if nothing remains, an honest std::nullopt (never a doomed call).
        // classify_delete_verdict below maps that to kVerifyUnreadable,
        // never kDeleted.
        still_present = keychain_contains_thumbprint(*target, needle, action_deadline);
    }

    switch (yuzu::macos::classify_delete_verdict(delete_result.exit_code, still_present)) {
    case yuzu::macos::DeleteVerdict::kCommandFailed:
        // delete_result.output is `security`'s captured stderr (merge_stderr
        // = true above) -- raw, attacker-influenceable diagnostic text that
        // typically ends with its own trailing newline and can span multiple
        // lines. safe_output_field it (K-7) so it can never inject an extra
        // pipe-delimited column or newline-delimited row into this output,
        // same as the store field above and CertRecord::to_row().
        ctx.write_output(std::format("error|delete failed (exit {}): {}", delete_result.exit_code,
                                     yuzu::util::safe_output_field(delete_result.output)));
        return false;
    case yuzu::macos::DeleteVerdict::kVerifyUnreadable:
        // rc==0 alone is never sufficient: the keychain could not be
        // re-read to confirm the certificate is actually gone, so this is
        // reported as an unverified failure, NEVER as "deleted" -- an
        // unreadable keychain must not be treated as "absent".
        ctx.write_output(
            "error|delete reported success but the keychain could not be re-read to verify");
        return false;
    case yuzu::macos::DeleteVerdict::kStillPresent:
        ctx.write_output(
            "error|delete reported success but certificate is still present in the keychain");
        return false;
    case yuzu::macos::DeleteVerdict::kDeleted:
        ctx.write_output("status|deleted");
        return true;
    }
    return false; // unreachable -- silences -Wreturn-type
}

#endif // __APPLE__

// ── ABI4 capability declarations (#2204) ────────────────────────────────────
//
// Windows enumerates/deletes via CryptoAPI natively (rung 1). Linux (WP-B)
// enumerates PEM files from /etc/ssl/certs via native filesystem I/O and
// parses every field (subject/issuer/dates/serial/thumbprint/key usage)
// in-process via libcrypto (certificates_x509.hpp) — no subprocess of any
// kind, rung 1 for list/details/delete alike; the openssl-subprocess
// mechanism this replaced, and the /bin/sh -c governed-shell rung it used
// to run under, are gone. macOS list/details are a genuine HYBRID: reading
// System.keychain/SystemRootCertificates.keychain promotes to rung 1
// (SecItemCopyMatching, a direct Security-framework API call — no
// subprocess at all), but the SAME call also still reads the login
// keychain by default, which requires the launchctl/sudo `~user` hop via
// "/bin/sh -c" (Decision-7 governed-shell exception — see
// build_login_keychain_read_command()) — so list/details stay rung 3
// overall, the rung reflecting the DEEPEST interpreter either call path
// intentionally invokes, not the shallowest. macOS delete (System/MY only,
// login unsupported — see below) is unchanged: a direct
// `/usr/bin/security delete-certificate` argv call through the bounded
// subprocess runner, rung 2, and also rejects SystemRootCertificates.keychain
// outright (sealed under System Integrity Protection) — a genuine, permanent
// capability limitation, not merely an error path.
const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "list",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "libcrypto X509 (in-process PEM parse)", nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 3, "SecItem (System/root, in-process) + security find-certificate "
                                    "via governed shell (login)",
         "System.keychain and SystemRootCertificates.keychain are read natively via "
         "SecItemCopyMatching (rung 1); the login keychain still requires the launchctl/sudo "
         "~user hop (Decision-7 governed-shell exception)"},
        /* .windows_leg = */ {YUZU_SUPPORT_SUPPORTED, 1, "CryptoAPI (CertEnumCertificatesInStore)",
                              nullptr},
    },
    {
        /* .action      = */ "details",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "libcrypto X509 (in-process PEM parse)", nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 3, "SecItem (System/root, in-process) + security find-certificate "
                                    "via governed shell (login)",
         "System.keychain and SystemRootCertificates.keychain are read natively via "
         "SecItemCopyMatching (rung 1); the login keychain still requires the launchctl/sudo "
         "~user hop (Decision-7 governed-shell exception)"},
        /* .windows_leg = */ {YUZU_SUPPORT_SUPPORTED, 1, "CryptoAPI (CertEnumCertificatesInStore)",
                              nullptr},
    },
    {
        /* .action      = */ "delete",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "libcrypto X509 lookup + filesystem remove", nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 2, "security delete-certificate via subprocess runner",
         "SystemRootCertificates.keychain is sealed under SIP and rejected outright; only "
         "System/MY store deletes are supported"},
        /* .windows_leg = */ {YUZU_SUPPORT_SUPPORTED, 1, "CryptoAPI (CertDeleteCertificateFromStore)",
                              nullptr},
    },
};

} // namespace

// ── Plugin class ─────────────────────────────────────────────────────────────

class CertificatesPlugin final : public yuzu::Plugin {
public:
    static constexpr const char* kName = "certificates";
    static constexpr const char* kVersion = "1.0.0";

    std::string_view name() const noexcept override { return kName; }
    std::string_view version() const noexcept override { return kVersion; }
    std::string_view description() const noexcept override {
        return "Certificate inventory and management for system stores";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"list", "details", "delete", nullptr};
        return acts;
    }

    const YuzuActionDescriptor* action_descriptors() const noexcept override {
        return kActionDescriptors;
    }
    size_t action_descriptor_count() const noexcept override {
        return sizeof(kActionDescriptors) / sizeof(kActionDescriptors[0]);
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override { return {}; }
    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action, yuzu::Params params) override {

        if (action == "list") {
            auto store = params.get("store", "all");
            auto days_str = params.get("expiring_within_days", "0");
            int expiring_days = 0;
            if (!days_str.empty()) {
                expiring_days = std::atoi(std::string{days_str}.c_str());
            }

#ifdef _WIN32
            list_certs_win(ctx, store, expiring_days);
#elif defined(__linux__)
            list_certs_linux(ctx, store, expiring_days);
#elif defined(__APPLE__)
            list_certs_macos(ctx, store, expiring_days);
#endif
            return 0;
        }

        if (action == "details") {
            auto thumbprint = params.get("thumbprint");
            if (thumbprint.empty()) {
                ctx.write_output("error|thumbprint parameter required");
                return 1;
            }
            if (!is_valid_thumbprint(thumbprint)) {
                ctx.write_output("error|invalid thumbprint format (expected 40 hex characters)");
                return 1;
            }

#ifdef _WIN32
            details_cert_win(ctx, thumbprint);
#elif defined(__linux__)
            details_cert_linux(ctx, thumbprint);
#elif defined(__APPLE__)
            // store defaults to "all" here (unset -> legacy unfiltered
            // behaviour, extended to include the login keychain when a
            // console user is available) -- Windows/Linux details_cert_*
            // don't take a store filter, so the param is only read on this
            // branch to avoid an unused-variable warning on those platforms.
            details_cert_macos(ctx, thumbprint, params.get("store", "all"));
#endif
            return 0;
        }

        if (action == "delete") {
            auto thumbprint = params.get("thumbprint");
            auto store = params.get("store", "MY");
            if (thumbprint.empty()) {
                ctx.write_output("error|thumbprint parameter required");
                return 1;
            }
            if (!is_valid_thumbprint(thumbprint)) {
                ctx.write_output("error|invalid thumbprint format (expected 40 hex characters)");
                return 1;
            }

#ifdef _WIN32
            delete_cert_win(ctx, thumbprint, store);
#elif defined(__linux__)
            delete_cert_linux(ctx, thumbprint, store);
#elif defined(__APPLE__)
            // delete_cert_macos() returns false only for a request REJECTED
            // outright (sealed root / unsupported store) or a delete that
            // was never verified as actually taking effect -- propagate
            // that as a non-zero rc so orchestration can't mistake "nothing
            // was deleted" for a successful no-op.
            if (!delete_cert_macos(ctx, thumbprint, store))
                return 1;
#endif
            return 0;
        }

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }
};

YUZU_PLUGIN_EXPORT(CertificatesPlugin)
