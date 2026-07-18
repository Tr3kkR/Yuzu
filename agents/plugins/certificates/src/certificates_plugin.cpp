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

#ifdef __APPLE__
// geteuid() -- privilege detection for the login-keychain read's sudo hop
// (mirrors quarantine_plugin.cpp's sudo_prefix()). macos_console_user.hpp
// declares `namespace yuzu::macos` -- both MUST be included here, at global
// scope, before the anonymous namespace below opens: including them inside
// `namespace { ... }` would nest `yuzu::macos` under
// `(anonymous namespace)::yuzu`, shadowing the global `::yuzu` namespace
// (from <yuzu/plugin.hpp> above) for every unqualified `yuzu::` lookup in
// this file -- e.g. `yuzu::TempFile` below would then fail to resolve,
// since the nested `(anonymous namespace)::yuzu` has no TempFile member.
#include <sys/wait.h> // WIFEXITED / WEXITSTATUS -- interpret the login-keychain read's pclose() status
#include <unistd.h>
#include <macos_console_user.hpp> // shared console-user + store/keychain mapping (A-1.11)
#endif

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

namespace {

// ── Input validation ────────────────────────────────────────────────────────

bool is_valid_thumbprint(std::string_view s) {
    if (s.size() != 40)
        return false;
    for (char c : s) {
        if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')))
            return false;
    }
    return true;
}

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
    std::array<char, 4096> buf{};
#ifdef _WIN32
    FILE* pipe = _popen(cmd, "r");
#else
    FILE* pipe = popen(cmd, "r");
#endif
    if (!pipe)
        return result;
    while (fgets(buf.data(), static_cast<int>(buf.size()), pipe)) {
        result += buf.data();
    }
#ifdef _WIN32
    _pclose(pipe);
#else
    pclose(pipe);
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
        return std::format("{}|{}|{}|{}|{}|{}|{}|{}", subject, issuer, thumbprint, not_before,
                           not_after, serial, store, key_usage);
    }
};

// ── Expiry filtering helper ──────────────────────────────────────────────────

/**
 * Returns true if the certificate expires within the given number of days.
 * If days <= 0, all certificates pass the filter.
 * The not_after string is expected to be in YYYY-MM-DD format.
 */
bool expires_within_days(const std::string& not_after, int days) {
    if (days <= 0)
        return true;
    if (not_after.size() < 10)
        return true; // can't parse, include it

    std::tm tm{};
    tm.tm_year = std::atoi(not_after.substr(0, 4).c_str()) - 1900;
    tm.tm_mon = std::atoi(not_after.substr(5, 2).c_str()) - 1;
    tm.tm_mday = std::atoi(not_after.substr(8, 2).c_str());
    tm.tm_isdst = -1;

    std::time_t expiry = std::mktime(&tm);
    if (expiry == static_cast<std::time_t>(-1))
        return true;

    auto now = std::time(nullptr);
    auto diff_seconds = std::difftime(expiry, now);
    auto diff_days = diff_seconds / 86400.0;

    return diff_days <= static_cast<double>(days);
}

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

CertRecord parse_pem_block_macos(const std::string& pem_block, const std::string& store_name) {
    CertRecord rec;
    rec.store = store_name;

    // Write PEM to a temp file to avoid shell injection via echo (PEM
    // content from the keychain could contain single quotes that break an
    // echo '...' pattern). yuzu::TempFile (mkstemps/O_EXCL, mode 0600)
    // gives each call its own unique, exclusively-created path -- the
    // previous fixed "yuzu_cert_tmp.pem" name collided when two `details`
    // calls ran concurrently (P6). RAII also replaces the old manual
    // cleanup() lambda: the file is removed when tmp_file goes out of scope.
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
    auto base_cmd = std::format("openssl x509 -noout -in \"{}\"", tmp_file.path());

    // Subject
    auto subj = run_command(std::format("{} -subject 2>/dev/null", base_cmd).c_str());
    if (subj.starts_with("subject=")) {
        rec.subject = subj.substr(8);
        while (!rec.subject.empty() && rec.subject.front() == ' ')
            rec.subject.erase(rec.subject.begin());
    } else {
        rec.subject = "(unknown)";
    }

    // Issuer
    auto iss = run_command(std::format("{} -issuer 2>/dev/null", base_cmd).c_str());
    if (iss.starts_with("issuer=")) {
        rec.issuer = iss.substr(7);
        while (!rec.issuer.empty() && rec.issuer.front() == ' ')
            rec.issuer.erase(rec.issuer.begin());
    } else {
        rec.issuer = "(unknown)";
    }

    // Dates (ISO 8601)
    auto start_date =
        run_command(std::format("{} -startdate -dateopt iso_8601 2>/dev/null", base_cmd).c_str());
    if (start_date.starts_with("notBefore=") && start_date.size() >= 20) {
        rec.not_before = start_date.substr(10, 10);
    } else {
        rec.not_before = "(unknown)";
    }

    auto end_date =
        run_command(std::format("{} -enddate -dateopt iso_8601 2>/dev/null", base_cmd).c_str());
    if (end_date.starts_with("notAfter=") && end_date.size() >= 19) {
        rec.not_after = end_date.substr(9, 10);
    } else {
        rec.not_after = "(unknown)";
    }

    // Serial
    auto serial = run_command(std::format("{} -serial 2>/dev/null", base_cmd).c_str());
    if (serial.starts_with("serial=")) {
        rec.serial = serial.substr(7);
    } else {
        rec.serial = "(unknown)";
    }

    // SHA1 fingerprint (thumbprint)
    auto fp = run_command(std::format("{} -fingerprint -sha1 2>/dev/null", base_cmd).c_str());
    auto eq = fp.find('=');
    if (eq != std::string::npos) {
        auto hex = fp.substr(eq + 1);
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

    // Key usage
    auto usage = run_command(std::format("{} -ext keyUsage 2>/dev/null", base_cmd).c_str());
    if (!usage.empty()) {
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
 */
std::optional<yuzu::macos::ConsoleUser> resolve_console_user() {
    auto stat_out = run_command("/usr/bin/stat -f%Su /dev/console 2>/dev/null");
    auto username = yuzu::macos::parse_console_user_output(stat_out);
    if (yuzu::macos::is_no_console_user(username))
        return std::nullopt;
    if (!yuzu::macos::is_valid_username(username))
        return std::nullopt;

    auto uid =
        run_command(std::format("/usr/bin/id -u {} 2>/dev/null", username).c_str());
    if (!yuzu::macos::is_valid_uid(uid))
        return std::nullopt;

    return yuzu::macos::ConsoleUser{std::move(username), std::move(uid)};
}

/**
 * Like run_command(), but also reports whether the subprocess exited
 * successfully (status 0). The login-keychain read is the one call site in
 * this file where "the command failed" and "the command succeeded with no
 * output" are NOT interchangeable: a missing sudoers grant, a failed
 * `launchctl asuser` hop, or an inaccessible keychain path must surface as
 * an honest `not_available` result, never as a silent empty list that
 * reads identically to "this keychain has zero certificates" -- see the
 * package's "honest sentinel" requirement. A single popen()/pclose() pair
 * captures both output and status from ONE run of the (privileged,
 * multi-hop sudo/launchctl/sudo/security) command, rather than running it
 * twice to get each half separately.
 */
struct CheckedCommandResult {
    std::string output;
    bool ok = false;
};

CheckedCommandResult run_command_checked(const char* cmd) {
    CheckedCommandResult result;
    std::array<char, 4096> buf{};
    FILE* pipe = popen(cmd, "r");
    if (!pipe)
        return result;
    while (fgets(buf.data(), static_cast<int>(buf.size()), pipe)) {
        result.output += buf.data();
    }
    int status = pclose(pipe);
    result.ok = (status != -1) && WIFEXITED(status) && WEXITSTATUS(status) == 0;
    while (!result.output.empty() && (result.output.back() == '\n' || result.output.back() == '\r'))
        result.output.pop_back();
    return result;
}

/** Enumerate one keychain's PEM blocks and emit rows for it, filtered by expiry. */
void emit_keychain_rows_macos(yuzu::CommandContext& ctx, const std::string& pem,
                              const std::string& store_label, int expiring_days) {
    for (const auto& block : split_pem_blocks(pem)) {
        auto rec = parse_pem_block_macos(block, store_label);
        if (expires_within_days(rec.not_after, expiring_days)) {
            ctx.write_output(rec.to_row());
        }
    }
}

void list_certs_macos(yuzu::CommandContext& ctx, std::string_view store_filter,
                      int expiring_days) {
    ctx.write_output("subject|issuer|thumbprint|not_before|not_after|serial|store|key_usage");

    auto console_user = resolve_console_user();
    auto plan = yuzu::macos::resolve_store_plan(store_filter, console_user.has_value());

    if (plan.sentinel_required) {
        // store=login was explicitly requested and there is no console
        // session to read it from -- never a silent empty (the header row
        // above with zero rows following would read as "ran fine, no
        // certs") and never a fabricated result.
        ctx.write_output("not_available|no console session");
        return;
    }

    if (plan.want_system) {
        auto sys_pem = run_command(
            std::format("security find-certificate -a -p {} 2>/dev/null",
                       yuzu::macos::system_keychain_path())
                .c_str());
        emit_keychain_rows_macos(ctx, sys_pem, "System.keychain", expiring_days);
    }

    if (plan.want_root) {
        auto root_pem = run_command(
            std::format("security find-certificate -a -p {} 2>/dev/null",
                       yuzu::macos::root_keychain_path())
                .c_str());
        emit_keychain_rows_macos(ctx, root_pem, "SystemRootCertificates.keychain", expiring_days);
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
            auto login_result = run_command_checked(cmd.c_str());
            if (!login_result.ok) {
                // A missing sudoers grant, a launchctl/sudo failure, or an
                // inaccessible keychain path all land here. Report it
                // honestly instead of emitting zero rows, which would be
                // indistinguishable from "this keychain is genuinely
                // empty" -- the exact failure mode this package's honest-
                // sentinel requirement exists to prevent.
                ctx.write_output("not_available|login keychain read failed");
            } else {
                emit_keychain_rows_macos(ctx, login_result.output, "login.keychain-db",
                                         expiring_days);
            }
        }
    }
}

void details_cert_macos(yuzu::CommandContext& ctx, std::string_view thumbprint,
                        std::string_view store_filter) {
    ctx.write_output("subject|issuer|thumbprint|not_before|not_after|serial|store|key_usage");

    auto console_user = resolve_console_user();
    auto plan = yuzu::macos::resolve_store_plan(store_filter, console_user.has_value());

    if (plan.sentinel_required) {
        ctx.write_output("not_available|no console session");
        return;
    }

    auto check = [&](const std::string& pem, const std::string& store) -> bool {
        for (const auto& block : split_pem_blocks(pem)) {
            auto rec = parse_pem_block_macos(block, store);
            if (rec.thumbprint == thumbprint) {
                ctx.write_output(rec.to_row());
                return true;
            }
        }
        return false;
    };

    if (plan.want_system) {
        auto sys_pem = run_command(
            std::format("security find-certificate -a -p {} 2>/dev/null",
                       yuzu::macos::system_keychain_path())
                .c_str());
        if (check(sys_pem, "System.keychain"))
            return;
    }

    if (plan.want_root) {
        auto root_pem = run_command(
            std::format("security find-certificate -a -p {} 2>/dev/null",
                       yuzu::macos::root_keychain_path())
                .c_str());
        if (check(root_pem, "SystemRootCertificates.keychain"))
            return;
    }

    if (plan.want_login) {
        auto cmd = yuzu::macos::build_login_keychain_read_command(
            console_user->uid, console_user->username, caller_is_root());
        if (cmd.empty()) {
            ctx.write_output("not_available|login keychain command construction failed");
            return;
        }
        auto login_result = run_command_checked(cmd.c_str());
        if (!login_result.ok) {
            // Don't fall through to "status|not_found" below -- that would
            // claim a completed, negative search when the login keychain
            // was never actually readable (missing sudoers grant,
            // launchctl/sudo failure, ...). See list_certs_macos's
            // matching comment.
            ctx.write_output("not_available|login keychain read failed");
            return;
        }
        if (check(login_result.output, "login.keychain-db"))
            return;
    }

    ctx.write_output("status|not_found");
}

/**
 * Re-enumerate `keychain_path` and report whether `thumbprint` is still
 * present. Used by delete_cert_macos() to VERIFY a delete actually took
 * effect rather than trusting a zero exit status alone -- `security
 * delete-certificate` can exit 0 without the item actually being gone
 * (ACL/SIP quirks, an unexpected keychain state), and reporting "deleted"
 * in that case would be exactly the false-success this package's honest-
 * sentinel requirement exists to prevent. Reuses the same PEM-enumeration
 * path as list/details rather than adding a second certificate-reading
 * mechanism.
 */
bool keychain_contains_thumbprint(const std::string& keychain_path, std::string_view thumbprint) {
    auto pem = run_command(
        std::format("security find-certificate -a -p {} 2>/dev/null", keychain_path).c_str());
    for (const auto& block : split_pem_blocks(pem)) {
        auto rec = parse_pem_block_macos(block, "");
        if (rec.thumbprint == thumbprint)
            return true;
    }
    return false;
}

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
    // actually take effect (BR-04): reject outright, before ever shelling
    // out, with the same fail-closed posture as the unsupported-store
    // branch below -- never silently redirect to a writable keychain
    // either.
    if (store == "root") {
        ctx.write_output(
            "certificates|unsupported|SystemRootCertificates.keychain is sealed on this macOS "
            "version (System Integrity Protection) and cannot be modified");
        return false;
    }

    // Delete acts on exactly one keychain; store otherwise preserves
    // today's unconditional System.keychain target for the unset/"MY"
    // default and "System" (see yuzu::macos::resolve_delete_keychain_path).
    // store=login is deliberately NOT supported for delete here -- unlike
    // list/details it is not part of this package's acceptance criteria,
    // and it would require the same asuser/sudo dance (and its own honest-
    // sentinel handling) for a destructive action that has no test
    // coverage in this change; left for a follow-up if a real need shows
    // up. "login", "all", and any other unrecognized value (root is
    // already handled above) are REJECTED rather than silently redirected
    // to System.keychain -- a destructive action must never target a
    // keychain the caller didn't ask for.
    auto target = yuzu::macos::resolve_delete_keychain_path(store);
    if (!target) {
        ctx.write_output(std::format("error|store '{}' is not supported for delete", store));
        return false;
    }

    // Inspect the ACTUAL pclose()/exit status of `security
    // delete-certificate` rather than grepping its combined stdout+stderr
    // for the words "error"/"Error" (BR-04): text-only classification
    // reports "deleted" for any output that doesn't happen to contain
    // those words, including genuine operational failures (permission
    // denied, locked keychain, ...).
    auto result = run_command_checked(
        std::format("security delete-certificate -Z {} {} 2>&1", thumbprint, *target).c_str());

    if (!result.ok) {
        // The command failed. Distinguish a genuine "not present" --
        // idempotent, matching Windows/Linux's uniform rc=0 for a delete
        // request that completed a search and found nothing to remove --
        // from a real operational failure (permission denied, keychain
        // locked, etc). The exit status alone already told us it failed;
        // the output text here only sub-classifies WHY, it is never used
        // to decide "deleted" on its own.
        std::string lower = result.output;
        for (auto& c : lower)
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (lower.find("could not be found") != std::string::npos ||
            lower.find("not found") != std::string::npos) {
            ctx.write_output("status|not_found");
            return true;
        }
        ctx.write_output(std::format("error|delete failed: {}", result.output));
        return false;
    }

    // Exit status 0 alone is not sufficient (BR-04) -- VERIFY the
    // certificate is actually gone from the target keychain before
    // reporting "deleted". A denied/no-op delete that still exits 0 (a
    // read-only or otherwise-protected keychain state) must not be
    // reported as a security-control change that took effect.
    if (keychain_contains_thumbprint(*target, thumbprint)) {
        ctx.write_output("error|delete reported success but certificate is still present in the keychain");
        return false;
    }

    ctx.write_output("status|deleted");
    // A completed, VERIFIED delete (or a verified-absent not_found above)
    // is a successfully EXECUTED delete request, matching Windows/Linux's
    // uniform rc=0 for that outcome -- only a request REJECTED outright
    // (invalid thumbprint, unsupported store, sealed root keychain) or an
    // operational failure fails here.
    return true;
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
            // outright (unsupported store) -- propagate that as a non-zero
            // rc so orchestration can't mistake "nothing was deleted
            // because the request was refused" for a successful no-op.
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
