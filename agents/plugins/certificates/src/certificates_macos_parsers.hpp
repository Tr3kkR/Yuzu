#pragma once

// certificates_macos_parsers.hpp -- pure parse/validate/classify/verdict
// helpers for the certificates plugin.
//
// These free functions were previously duplicated in TWO places: the
// anonymous namespace of certificates_plugin.cpp (production) and, hand-copied
// "kept in sync manually", the anonymous namespace of
// tests/unit/test_certificates_macos.cpp. That manual replication meant a
// production change could silently drift from the vectors meant to protect it.
// This header is the single source both now #include, ending the drift --
// the same "pure header both plugin and test include" pattern already used by
// filesystem_macos_sig.hpp and event_logs_macos.hpp on this branch.
//
// Everything here is pure: string/number/time transforms and decisions over
// already-captured inputs. Nothing execs a process, touches the filesystem,
// or reads the OS -- certificates_plugin.cpp owns all of that (fork/exec via
// the bounded subprocess runner, temp files, keychain reads) and hands these
// helpers the already-captured text/exit-code/outcome. That is exactly what
// makes them fixture-testable on every CI host, macOS box or not.
//
// Named "_macos" for the login-keychain feature that motivated the header,
// but is_valid_thumbprint / expires_within_days are platform-independent and
// used by the Windows and Linux paths too -- the header is included
// unconditionally by certificates_plugin.cpp.

#include <array>
#include <chrono>
#include <cstdlib>
#include <ctime>
#include <format>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::certificates_macos {

// ── Input validation ────────────────────────────────────────────────────────

/// A SHA-1 thumbprint is exactly 40 hexadecimal characters. Used both to
/// validate caller-supplied thumbprints (before they reach a subprocess) and
/// to decide whether a PEM-parsed fingerprint is trustworthy enough to
/// compare against (classify_block_identity).
inline bool is_valid_thumbprint(std::string_view s) {
    if (s.size() != 40)
        return false;
    for (char c : s) {
        if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')))
            return false;
    }
    return true;
}

// ── Expiry filtering helper ──────────────────────────────────────────────────

/**
 * Returns true if the certificate expires within the given number of days.
 * If days <= 0, all certificates pass the filter.
 * The not_after string is expected to be in YYYY-MM-DD format.
 */
inline bool expires_within_days(const std::string& not_after, int days) {
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

// ── openssl date parsing ─────────────────────────────────────────────────────

/**
 * Parses LibreSSL/OpenSSL's NATIVE ASN1_TIME_print date format -- the only
 * format /usr/bin/openssl can produce on macOS: LibreSSL 3.3.6 rejects
 * `-dateopt iso_8601` outright (exit 1, "unknown option -dateopt"). Native
 * format is e.g. "Jul 20 19:06:44 2026 GMT" or "Jan  1 00:00:00 2025 GMT" --
 * a single-digit day is space-padded to width 2, so the run of whitespace
 * between month and day varies by one character; tokenizing on whitespace
 * (rather than fixed-width substring slicing) handles both shapes without a
 * special case. Returns "(unknown)" for anything that doesn't match the
 * expected shape -- never a fabricated date.
 */
inline std::string parse_openssl_native_date(std::string_view value) {
    static constexpr std::array<std::string_view, 12> kMonths = {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

    std::istringstream iss{std::string{value}};
    std::string mon, day, time_of_day, year;
    if (!(iss >> mon >> day >> time_of_day >> year))
        return "(unknown)";

    int month_num = 0;
    for (std::size_t i = 0; i < kMonths.size(); ++i) {
        if (mon == kMonths[i]) {
            month_num = static_cast<int>(i) + 1;
            break;
        }
    }
    if (month_num == 0)
        return "(unknown)";

    if (day.empty() || day.size() > 2)
        return "(unknown)";
    for (char c : day) {
        if (c < '0' || c > '9')
            return "(unknown)";
    }
    if (year.size() != 4)
        return "(unknown)";
    for (char c : year) {
        if (c < '0' || c > '9')
            return "(unknown)";
    }

    int day_num = std::atoi(day.c_str());
    if (day_num < 1 || day_num > 31)
        return "(unknown)";

    return std::format("{}-{:02d}-{:02d}", year, month_num, day_num);
}

/// Strip leading ASCII spaces/tabs. Used both for openssl's oneline
/// "label=<one leading space>value" fields and for the variably-indented
/// lines inside a `-text` dump.
inline std::string strip_leading_blank(std::string s) {
    std::size_t i = 0;
    while (i < s.size() && (s[i] == ' ' || s[i] == '\t'))
        ++i;
    s.erase(0, i);
    return s;
}

// ── openssl combined-output parse ────────────────────────────────────────────

/// The subset of a certificate row parse_openssl_combined_output can derive
/// from openssl's captured stdout: the six fixed-position preamble fields plus
/// Key Usage. `store` is NOT here -- the caller (parse_pem_block_macos) sets it
/// from the keychain it read, never from openssl output. Defaults are the same
/// honest sentinels certificates_plugin.cpp uses for a block whose fields could
/// not be established.
struct ParsedCertFields {
    std::string subject = "(unknown)";
    std::string issuer = "(unknown)";
    std::string not_before = "(unknown)";
    std::string not_after = "(unknown)";
    std::string serial = "(unknown)";
    std::string thumbprint = "(unknown)";
    std::string key_usage = "(none)";
};

/**
 * Parse the captured stdout of a single
 *   openssl x509 -noout -in <pem> -subject -issuer -startdate -enddate
 *                -serial -fingerprint -sha1 -text
 * invocation into ParsedCertFields. The six -subject/-issuer/-startdate/
 * -enddate/-serial/-fingerprint flags each contribute one fixed-position,
 * never-indented "label=value" line in that EXACT order, followed by the full
 * -text dump (used only for the X509v3 Key Usage extension, which replaces the
 * `-ext keyUsage` LibreSSL rejects). Each preamble field is read from the ONE
 * line openssl generated for its own flag -- a hostile subject/issuer
 * containing literal "serial="/"X509v3 Key Usage:" text cannot be picked up as
 * a different field, since openssl's oneline printer hex-escapes any raw
 * control byte and each line is reserved for its own field.
 *
 * The caller must only pass the stdout of a CLEAN, complete, exit-0 run (see
 * is_usable_capture) -- a killed/truncated capture is a partial prefix that
 * would shift every positional field onto the wrong line, so it is rejected
 * upstream rather than parsed here.
 */
inline ParsedCertFields parse_openssl_combined_output(const std::string& openssl_output) {
    ParsedCertFields rec;

    std::istringstream iss(openssl_output);
    auto next_line = [&]() -> std::string {
        std::string line;
        return std::getline(iss, line) ? line : std::string{};
    };

    if (auto line = next_line(); line.starts_with("subject="))
        rec.subject = strip_leading_blank(line.substr(8));
    if (auto line = next_line(); line.starts_with("issuer="))
        rec.issuer = strip_leading_blank(line.substr(7));
    if (auto line = next_line(); line.starts_with("notBefore="))
        rec.not_before = parse_openssl_native_date(line.substr(10));
    if (auto line = next_line(); line.starts_with("notAfter="))
        rec.not_after = parse_openssl_native_date(line.substr(9));
    if (auto line = next_line(); line.starts_with("serial="))
        rec.serial = line.substr(7);
    if (auto line = next_line();
        line.starts_with("SHA1 Fingerprint=") || line.starts_with("sha1 Fingerprint=")) {
        auto hex = line.substr(line.find('=') + 1);
        std::string clean;
        clean.reserve(hex.size());
        for (char c : hex) {
            if (c != ':')
                clean += c;
        }
        if (!clean.empty())
            rec.thumbprint = clean;
    }

    // Remaining lines are the -text dump. The "X509v3 Key Usage:" header is a
    // fixed label openssl itself generates -- never derived from certificate
    // content -- and always precedes its value on the NEXT line, indented one
    // level deeper. Any other line that happens to CONTAIN a hostile
    // subject/issuer's text still starts with openssl's own "Issuer:"/
    // "Subject:" label after trimming, never with "X509v3 Key Usage:" itself,
    // so a forged match is not reachable through DN content.
    std::string line;
    while (std::getline(iss, line)) {
        auto trimmed = strip_leading_blank(line);
        if (!trimmed.starts_with("X509v3 Key Usage:"))
            continue;
        std::string usage_line;
        if (std::getline(iss, usage_line)) {
            usage_line = strip_leading_blank(usage_line);
            while (!usage_line.empty() &&
                   (usage_line.back() == '\r' || usage_line.back() == '\n'))
                usage_line.pop_back();
            if (!usage_line.empty())
                rec.key_usage = usage_line;
        }
        break;
    }

    return rec;
}

// ── Capture-usability gate ───────────────────────────────────────────────────

/**
 * Whether a completed run_bounded_subprocess call is trustworthy enough to
 * parse/trust at all: the process actually ran, was not killed at its
 * deadline, was not cut off by the runner's internal capture cap, and exited
 * 0. Takes the four SubprocessResult fields directly (rather than the struct)
 * so it is reachable from a plugin-side unit test where agent-core's real type
 * is not linkable -- the same boundary certificates_plugin.cpp injects at.
 */
inline bool is_usable_capture(bool tool_ran, bool timed_out, bool output_truncated,
                              int exit_code) {
    return tool_ran && !timed_out && !output_truncated && exit_code == 0;
}

// ── Per-block identity classification ────────────────────────────────────────

// The three possible outcomes of comparing one parsed certificate block's
// thumbprint against a search needle. kInconclusive is the core distinction:
// parse_openssl_combined_output falls back to the literal "(unknown)" sentinel
// whenever the openssl call was killed/capped/failed (never a fabricated
// identity), and a block whose identity could not be established might BE the
// certificate being searched for -- a caller must never fold that into a clean
// "not this one".
enum class BlockIdentityOutcome { kMatch, kNoMatch, kInconclusive };

/**
 * Pure per-block classification: does `parsed_thumbprint` match `needle`,
 * definitively not match, or is the block's identity simply unknown (not a
 * validated 40-hex-char thumbprint)? Shared by details_cert_macos's
 * per-keychain scan and keychain_contains_thumbprint's verify scan so the two
 * searches can never drift on this decision.
 */
inline BlockIdentityOutcome classify_block_identity(std::string_view parsed_thumbprint,
                                                    std::string_view needle) {
    if (!is_valid_thumbprint(parsed_thumbprint))
        return BlockIdentityOutcome::kInconclusive;
    return parsed_thumbprint == needle ? BlockIdentityOutcome::kMatch
                                       : BlockIdentityOutcome::kNoMatch;
}

/**
 * Fold the per-block identity outcomes of an absence-proving keychain scan
 * (keychain_contains_thumbprint) into a tri-state presence result. Returns
 * true (present) as soon as any block matches; otherwise the result depends on
 * whether the scan was COMPLETE -- `scan_complete` is true IFF the `security`
 * read succeeded AND every block was classified within the per-keychain cap
 * and the action deadline.
 *
 * UP-5: an unrelated unparseable block (kInconclusive) does NOT abort the
 * proof. openssl could not turn it into a cert, so it can never be a positive
 * match for the needle; skipping it lets a genuinely successful delete still
 * verify as absent even when the keychain also holds an unrelated malformed
 * cert (the previous code returned std::nullopt on the FIRST such block,
 * reporting kVerifyUnreadable for an otherwise-clean delete). The fail-safe is
 * preserved by `scan_complete`: a genuine read failure or a cap/deadline-
 * truncated scan is passed as scan_complete=false and still yields
 * std::nullopt, so an unread/partly-read keychain is never reported as a clean
 * "deleted". Only a fully-scanned keychain with no match proves ABSENT.
 */
inline std::optional<bool> fold_presence_scan(const std::vector<BlockIdentityOutcome>& outcomes,
                                              bool scan_complete) {
    for (auto outcome : outcomes) {
        if (outcome == BlockIdentityOutcome::kMatch)
            return true; // present
    }
    if (!scan_complete)
        return std::nullopt; // could not prove absence -- inconclusive
    return false;            // complete scan, no match -> provably absent
}

/**
 * Given the tri-state result of a pre-delete presence check
 * (keychain_contains_thumbprint -- true = present, false = POSITIVELY proven
 * absent, std::nullopt = could not be conclusively read/parsed), should
 * delete_cert_macos report `status|not_found` and skip the destructive
 * `security delete-certificate` call entirely?
 *
 * Only a definitive `false` qualifies. `true` must fall through to the delete
 * attempt, and -- just as importantly -- so must std::nullopt: an
 * unreadable/inconclusive presence check proves nothing about whether the
 * certificate is actually there, so it must never be masked as "not found".
 */
inline bool is_provably_absent_macos(std::optional<bool> presence) {
    return presence.has_value() && !*presence;
}

// ── Action-budget deadline clamp ─────────────────────────────────────────────

/**
 * Clamp `per_call_cap` to whatever remains of the whole-action budget
 * (`action_deadline`) so a later subprocess can never receive its own full,
 * independent deadline regardless of how much of the action budget is already
 * spent. Returns std::chrono::milliseconds::zero() once the action budget is
 * already exhausted; callers MUST treat zero as "the budget is spent, do not
 * even attempt this subprocess" rather than issuing a call with a near-zero
 * deadline that spawns a child only to kill it almost immediately.
 */
inline std::chrono::milliseconds clamp_to_action_budget(
    std::chrono::steady_clock::time_point action_deadline,
    std::chrono::milliseconds per_call_cap) {
    auto remaining = action_deadline - std::chrono::steady_clock::now();
    if (remaining <= std::chrono::steady_clock::duration::zero())
        return std::chrono::milliseconds::zero();
    auto remaining_ms = std::chrono::duration_cast<std::chrono::milliseconds>(remaining);
    return remaining_ms < per_call_cap ? remaining_ms : per_call_cap;
}

} // namespace yuzu::certificates_macos
