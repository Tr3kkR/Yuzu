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
 *   Linux   — PEM files in /etc/ssl/certs/ parsed via openssl x509 subprocess
 *   macOS   — security find-certificate subprocess
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
#endif

#ifdef __linux__
// The Linux openssl x509 shell-out routes through the bounded, fork-lock-covered
// runner too (review blocker); macOS already includes this above.
#include <yuzu/agent/subprocess_runner.hpp>
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

bool is_safe_path(std::string_view s) {
    for (char c : s) {
        // Reject shell metacharacters in filesystem paths, including
        // redirection (`<` `>`) and the word-splitting space.
        if (c == '`' || c == '$' || c == '(' || c == ')' || c == ';' || c == '|' || c == '&' ||
            c == '\'' || c == '"' || c == '\n' || c == '\r' || c == '\0' || c == '<' || c == '>' ||
            c == ' ')
            return false;
    }
    return true;
}

// ── Subprocess helper ────────────────────────────────────────────────────────

std::string run_command(const char* cmd) {
    std::string result;
#ifdef _WIN32
    std::array<char, 4096> buf{};
    FILE* pipe = _popen(cmd, "r");
    if (pipe) {
        while (fgets(buf.data(), static_cast<int>(buf.size()), pipe))
            result += buf.data();
        _pclose(pipe);
    }
#else
    // Bounded, fork-lock-covered runner (review blocker) instead of a raw,
    // deadline-less popen that bypassed both the fork lock and any timeout.
    // `/bin/sh -c` preserves the shell semantics the Linux `openssl x509`
    // callers rely on; the runner drains and caps stdout.
    auto res = yuzu::agent::run_bounded_subprocess(
        {"/bin/sh", "-c", cmd},
        yuzu::agent::SubprocessOptions{.deadline = std::chrono::seconds{20}});
    result = std::move(res.output);
#endif
    while (!result.empty() && (result.back() == '\n' || result.back() == '\r'))
        result.pop_back();
    return result;
}

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
        // thumbprint is hex-validated (is_valid_thumbprint) or a literal
        // "(unknown)" sentinel, the dates are produced entirely by this
        // file's own date formatting, and store is always one of this
        // plugin's own fixed literal labels -- none of the four can carry
        // attacker-controlled bytes.
        return std::format("{}|{}|{}|{}|{}|{}|{}|{}", yuzu::util::safe_output_field(subject),
                           yuzu::util::safe_output_field(issuer), thumbprint, not_before,
                           not_after, yuzu::util::safe_output_field(serial), store,
                           yuzu::util::safe_output_field(key_usage));
    }
};

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

CertRecord parse_openssl_output(const std::string& pem_path, const std::string& store_name) {
    CertRecord rec;
    rec.store = store_name;

    // Validate path against shell metacharacters to prevent command injection.
    // The path comes from directory_iterator but crafted filenames could inject.
    if (!is_safe_path(pem_path)) {
        rec.subject = "(unsafe path)";
        rec.thumbprint = "(skipped)";
        return rec;
    }

    // Get subject
    auto subj = run_command(
        std::format("openssl x509 -noout -subject -in \"{}\" 2>/dev/null", pem_path).c_str());
    if (subj.starts_with("subject=")) {
        rec.subject = subj.substr(8);
        // Trim leading space
        while (!rec.subject.empty() && rec.subject.front() == ' ')
            rec.subject.erase(rec.subject.begin());
    } else {
        rec.subject = "(unknown)";
    }

    // Get issuer
    auto iss = run_command(
        std::format("openssl x509 -noout -issuer -in \"{}\" 2>/dev/null", pem_path).c_str());
    if (iss.starts_with("issuer=")) {
        rec.issuer = iss.substr(7);
        while (!rec.issuer.empty() && rec.issuer.front() == ' ')
            rec.issuer.erase(rec.issuer.begin());
    } else {
        rec.issuer = "(unknown)";
    }

    // Get dates
    auto dates = run_command(
        std::format("openssl x509 -noout -startdate -enddate -in \"{}\" 2>/dev/null", pem_path)
            .c_str());
    std::istringstream dss(dates);
    std::string line;
    while (std::getline(dss, line)) {
        if (line.starts_with("notBefore=")) {
            // Parse date: "notBefore=Jan  1 00:00:00 2025 GMT" -> YYYY-MM-DD
            auto date_cmd =
                run_command(std::format("openssl x509 -noout -startdate -dateopt iso_8601 "
                                        "-in \"{}\" 2>/dev/null",
                                        pem_path)
                                .c_str());
            if (date_cmd.starts_with("notBefore=") && date_cmd.size() >= 20) {
                rec.not_before = date_cmd.substr(10, 10);
            } else {
                rec.not_before = line.substr(10);
            }
        } else if (line.starts_with("notAfter=")) {
            auto date_cmd =
                run_command(std::format("openssl x509 -noout -enddate -dateopt iso_8601 "
                                        "-in \"{}\" 2>/dev/null",
                                        pem_path)
                                .c_str());
            if (date_cmd.starts_with("notAfter=") && date_cmd.size() >= 19) {
                rec.not_after = date_cmd.substr(9, 10);
            } else {
                rec.not_after = line.substr(9);
            }
        }
    }

    // Get serial number
    auto serial = run_command(
        std::format("openssl x509 -noout -serial -in \"{}\" 2>/dev/null", pem_path).c_str());
    if (serial.starts_with("serial=")) {
        rec.serial = serial.substr(7);
    } else {
        rec.serial = "(unknown)";
    }

    // Get fingerprint (SHA1 thumbprint)
    auto fp = run_command(
        std::format("openssl x509 -noout -fingerprint -sha1 -in \"{}\" 2>/dev/null", pem_path)
            .c_str());
    // Format: "SHA1 Fingerprint=AA:BB:CC:..." or "sha1 Fingerprint=..."
    auto eq = fp.find('=');
    if (eq != std::string::npos) {
        auto hex = fp.substr(eq + 1);
        // Remove colons
        std::string clean;
        clean.reserve(hex.size());
        for (char c : hex) {
            if (c != ':')
                clean += c;
        }
        rec.thumbprint = clean;
    } else {
        rec.thumbprint = "(unknown)";
    }

    // Get key usage
    auto usage = run_command(
        std::format("openssl x509 -noout -ext keyUsage -in \"{}\" 2>/dev/null", pem_path).c_str());
    if (!usage.empty()) {
        // Extract the actual usage line (skip the header)
        std::istringstream uss(usage);
        std::string uline;
        std::string last_line;
        while (std::getline(uss, uline)) {
            while (!uline.empty() && (uline.front() == ' ' || uline.front() == '\t'))
                uline.erase(uline.begin());
            if (!uline.empty() && uline.find("X509v3") == std::string::npos &&
                uline.find("critical") == std::string::npos) {
                last_line = uline;
            }
        }
        rec.key_usage = last_line.empty() ? "(none)" : last_line;
    } else {
        rec.key_usage = "(none)";
    }

    return rec;
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

        auto rec = parse_openssl_output(entry.path().string(), "/etc/ssl/certs");
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

    for (const auto& entry : std::filesystem::directory_iterator(cert_dir, ec)) {
        if (!entry.is_regular_file(ec))
            continue;
        auto ext = entry.path().extension().string();
        if (ext != ".pem" && ext != ".crt")
            continue;

        auto rec = parse_openssl_output(entry.path().string(), "/etc/ssl/certs");
        if (rec.thumbprint == thumbprint) {
            ctx.write_output(rec.to_row());
            return;
        }
    }
    ctx.write_output("status|not_found");
}

void delete_cert_linux(yuzu::CommandContext& ctx, std::string_view thumbprint,
                       std::string_view /*store*/) {
    const std::filesystem::path cert_dir{"/etc/ssl/certs"};

    std::error_code ec;
    if (!std::filesystem::exists(cert_dir, ec)) {
        ctx.write_output("status|not_found");
        return;
    }

    for (const auto& entry : std::filesystem::directory_iterator(cert_dir, ec)) {
        if (!entry.is_regular_file(ec))
            continue;
        auto ext = entry.path().extension().string();
        if (ext != ".pem" && ext != ".crt")
            continue;

        auto rec = parse_openssl_output(entry.path().string(), "/etc/ssl/certs");
        if (rec.thumbprint == thumbprint) {
            if (std::filesystem::remove(entry.path(), ec)) {
                ctx.write_output("status|deleted");
            } else {
                ctx.write_output("status|delete_failed");
            }
            return;
        }
    }
    ctx.write_output("status|not_found");
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
 * were already written against (pre-#2273 they called a popen()-backed
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
    // popen() calls). LibreSSL happily accepts multiple print options on a
    // single invocation and emits them in the EXACT order given, so
    // -subject/-issuer/-startdate/-enddate/-serial/-fingerprint each
    // contribute one fixed-position, never-indented "label=value" line,
    // followed by the full -text dump (used only for Key Usage below --
    // -text replaces the removed `-ext keyUsage`, which LibreSSL also
    // rejects). Absolute path, matching the /usr/bin/security convention
    // used by every other privileged subprocess call in this file (PATH is
    // not trusted for a process that can run as root).
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
 * Resolve the current console (GUI) user via subprocess -- the LaunchDaemon
 * has no framework access (SystemConfiguration) available, so this shells
 * out to `stat`/`id` rather than SCDynamicStoreCopyConsoleUser. Returns
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

/**
 * Canonicalize a thumbprint to uppercase hex so every downstream comparison
 * against a PEM-parsed value (parse_pem_block_macos always emits uppercase,
 * from openssl's `-fingerprint -sha1` output) is a plain `==`. The
 * `thumbprint` request parameter is documented as case-insensitive
 * (content/definitions/certificates.yaml) but was compared as-is, so a
 * lowercase caller-supplied value silently failed to match. `s` is assumed
 * already hex-validated by is_valid_thumbprint(); this only changes case,
 * never rejects input.
 */
std::string canonical_thumbprint(std::string_view s) {
    std::string out{s};
    for (auto& c : out)
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    return out;
}

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
        return;
    }

    // PLAN-12: every selected keychain goes through run_bounded_checked, not
    // just login -- at BASE, System/root used unchecked run_command, so a
    // `security` failure was indistinguishable from a genuinely empty
    // keychain. A checked failure emits an honest sentinel row instead of
    // silently contributing zero rows.
    if (plan.want_system) {
        auto read_deadline = clamp_to_action_budget(action_deadline, kKeychainReadDeadline);
        if (read_deadline <= std::chrono::milliseconds::zero()) {
            ctx.write_output("not_available|System.keychain action deadline exceeded");
        } else {
            auto sys_result = run_bounded_checked(
                {"/usr/bin/security", "find-certificate", "-a", "-p",
                 yuzu::macos::system_keychain_path()},
                yuzu::agent::SubprocessOptions{.deadline = read_deadline},
                "System.keychain read");
            if (sys_result.ok) {
                if (!emit_keychain_rows_macos(ctx, sys_result.output, "System.keychain",
                                              expiring_days, action_deadline)) {
                    ctx.write_output("not_available|System.keychain scan incomplete");
                }
            } else {
                ctx.write_output("not_available|System.keychain read failed");
            }
        }
    }

    if (plan.want_root) {
        auto read_deadline = clamp_to_action_budget(action_deadline, kKeychainReadDeadline);
        if (read_deadline <= std::chrono::milliseconds::zero()) {
            ctx.write_output(
                "not_available|SystemRootCertificates.keychain action deadline exceeded");
        } else {
            auto root_result = run_bounded_checked(
                {"/usr/bin/security", "find-certificate", "-a", "-p",
                 yuzu::macos::root_keychain_path()},
                yuzu::agent::SubprocessOptions{.deadline = read_deadline},
                "SystemRootCertificates.keychain read");
            if (root_result.ok) {
                if (!emit_keychain_rows_macos(ctx, root_result.output,
                                              "SystemRootCertificates.keychain", expiring_days,
                                              action_deadline)) {
                    ctx.write_output(
                        "not_available|SystemRootCertificates.keychain scan incomplete");
                }
            } else {
                ctx.write_output("not_available|SystemRootCertificates.keychain read failed");
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
        } else {
            auto read_deadline = clamp_to_action_budget(action_deadline, kKeychainReadDeadline);
            if (read_deadline <= std::chrono::milliseconds::zero()) {
                ctx.write_output("not_available|login keychain action deadline exceeded");
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
                auto login_result = run_bounded_checked(
                    {"/bin/sh", "-c", cmd},
                    yuzu::agent::SubprocessOptions{.deadline = read_deadline},
                    "login keychain read");
                if (login_result.ok) {
                    if (!emit_keychain_rows_macos(ctx, login_result.output, "login.keychain-db",
                                                  expiring_days, action_deadline)) {
                        ctx.write_output("not_available|login keychain scan incomplete");
                    }
                } else {
                    // A missing sudoers grant, a launchctl/sudo failure, or an
                    // inaccessible keychain path all land here. Report it
                    // honestly instead of emitting zero rows, which would be
                    // indistinguishable from "this keychain is genuinely
                    // empty".
                    ctx.write_output("not_available|login keychain read failed");
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

    // A checked read failure, an exhausted action budget, or an incomplete
    // scan on a selected store all mean the search below is incomplete for
    // that store -- remembered (first failure wins) so the final result
    // can honestly report "not_available" instead of a false "not_found"
    // if no match turns up. A match found in a store that DID read/scan
    // successfully is still reported normally, even if an earlier store
    // had already failed.
    bool read_failed = false;
    std::string_view failure_reason;

    if (plan.want_system) {
        auto read_deadline = clamp_to_action_budget(action_deadline, kKeychainReadDeadline);
        if (read_deadline <= std::chrono::milliseconds::zero()) {
            read_failed = true;
            failure_reason = "System.keychain action deadline exceeded";
        } else {
            auto sys_result = run_bounded_checked(
                {"/usr/bin/security", "find-certificate", "-a", "-p",
                 yuzu::macos::system_keychain_path()},
                yuzu::agent::SubprocessOptions{.deadline = read_deadline},
                "System.keychain read");
            if (!sys_result.ok) {
                read_failed = true;
                failure_reason = "System.keychain read failed";
            } else {
                switch (check(sys_result.output, "System.keychain")) {
                case ScanOutcome::kFound:
                    return;
                case ScanOutcome::kIncomplete:
                    read_failed = true;
                    failure_reason = "System.keychain scan incomplete";
                    break;
                case ScanOutcome::kNotFound:
                    break;
                }
            }
        }
    }

    if (plan.want_root) {
        auto read_deadline = clamp_to_action_budget(action_deadline, kKeychainReadDeadline);
        if (read_deadline <= std::chrono::milliseconds::zero()) {
            if (!read_failed) {
                read_failed = true;
                failure_reason = "SystemRootCertificates.keychain action deadline exceeded";
            }
        } else {
            auto root_result = run_bounded_checked(
                {"/usr/bin/security", "find-certificate", "-a", "-p",
                 yuzu::macos::root_keychain_path()},
                yuzu::agent::SubprocessOptions{.deadline = read_deadline},
                "SystemRootCertificates.keychain read");
            if (!root_result.ok) {
                if (!read_failed) {
                    read_failed = true;
                    failure_reason = "SystemRootCertificates.keychain read failed";
                }
            } else {
                switch (check(root_result.output, "SystemRootCertificates.keychain")) {
                case ScanOutcome::kFound:
                    return;
                case ScanOutcome::kIncomplete:
                    if (!read_failed) {
                        read_failed = true;
                        failure_reason = "SystemRootCertificates.keychain scan incomplete";
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
            }
        } else {
            auto read_deadline = clamp_to_action_budget(action_deadline, kKeychainReadDeadline);
            if (read_deadline <= std::chrono::milliseconds::zero()) {
                if (!read_failed) {
                    read_failed = true;
                    failure_reason = "login keychain action deadline exceeded";
                }
            } else {
                // See list_certs_macos's matching comment: `cmd` needs the
                // outer shell's `~username` expansion, so it is run as a
                // single trusted argv element via "/bin/sh -c" rather than a
                // clean multi-element argv.
                auto login_result = run_bounded_checked(
                    {"/bin/sh", "-c", cmd},
                    yuzu::agent::SubprocessOptions{.deadline = read_deadline},
                    "login keychain read");
                if (!login_result.ok) {
                    if (!read_failed) {
                        read_failed = true;
                        failure_reason = "login keychain read failed";
                    }
                } else {
                    switch (check(login_result.output, "login.keychain-db")) {
                    case ScanOutcome::kFound:
                        return;
                    case ScanOutcome::kIncomplete:
                        if (!read_failed) {
                            read_failed = true;
                            failure_reason = "login keychain scan incomplete";
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
