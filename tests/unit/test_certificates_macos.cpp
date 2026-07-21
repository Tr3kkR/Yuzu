/**
 * test_certificates_macos.cpp -- pure parse/validate/mapping vectors for the
 * certificates plugin's macOS login-keychain support (macos_console_user.hpp,
 * A-1.11) and its LibreSSL native-output parsing / row-escaping (BR-02/
 * BR-03/BR-07).
 *
 * Everything here runs against fixture strings -- no `stat`/`id`/`launchctl`/
 * `sudo`/`security`/`openssl` subprocess, no real console session, no macOS
 * required -- because the helpers are pure by design (same
 * header-for-testability pattern as installed_apps_inventory.hpp /
 * test_installed_apps_inventory.cpp). Runs on EVERY host (incl. MSVC), same
 * as test_dex_macos.cpp.
 *
 * The shell-injection-guard vectors (is_valid_username / is_valid_uid /
 * build_login_keychain_read_command) are the load-bearing ones: every value
 * this header validates ends up interpolated into a bounded-subprocess
 * argv/command line in certificates_plugin.cpp, so "rejects an unsafe value"
 * here is a direct proxy for "never runs an attacker-influenced command."
 *
 * The BR-02/BR-03/BR-07 section further down (parse_openssl_native_date,
 * expires_within_days, parse_openssl_combined_output, CertRecord-equivalent
 * row escaping) replicates the corresponding logic from
 * certificates_plugin.cpp -- that file builds to a `shared_library` plugin
 * with everything in an anonymous namespace, so it cannot be linked directly
 * into this test binary. Same "helpers copied into the test file's own
 * anonymous namespace" pattern as test_filesystem_actions.cpp /
 * test_filesystem_read.cpp; kept in sync manually with the production
 * versions.
 *
 * A fix-round section further down still replicates four small pure
 * decisions added while closing review findings FP-CERTS-01/02/03/05: the
 * capture-usability gate (nonzero-exit rejection), the tri-state per-block
 * identity classifier the details/delete-verify scans now share, and the
 * action-budget deadline clamp -- each proportionate, targeted coverage for
 * a NEW pure decision point rather than an attempt to unit-test the
 * surrounding subprocess/timing-dependent control flow (list/details'
 * cap-and-deadline loop, resolve_console_user's uid trimming), which would
 * need an injectable subprocess seam this package's owned files do not
 * provide.
 *
 * A further section closes two adversarial-review findings on the delete
 * path (K-4/K-7): is_provably_absent_macos -- the pure tri-state-presence
 * -> not_found decision delete_cert_macos now runs BEFORE ever issuing the
 * destructive `security delete-certificate` call -- is replicated the same
 * way as every other pure decision above. The K-7 row-escaping vectors don't
 * replicate anything (there's no new pure function to replicate): they
 * exercise the REAL yuzu::util::safe_output_field against the exact two
 * `std::format` templates delete_cert_macos's error paths use, the same
 * "prove the real SDK function neutralizes a hostile value in situ" pattern
 * as the to_row() vectors further down.
 */

#include <catch2/catch_test_macros.hpp>

#include <macos_console_user.hpp>
#include <yuzu/string_utils.hpp> // yuzu::util::safe_output_field -- the REAL SDK function, not replicated (BR-07)

#include <array>
#include <chrono>
#include <cstdlib>
#include <ctime>
#include <format>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>

using namespace yuzu::macos;

// ── Replicated from certificates_plugin.cpp (see file banner) ──────────────

namespace {

/// Replica of certificates_plugin.cpp's expires_within_days -- UNCHANGED by
/// this package's fix (the bug it closes is upstream, in what not_after
/// gets populated with -- see parse_openssl_native_date below); replicated
/// here so the acceptance criterion "a cert expiring far beyond `days` is
/// EXCLUDED" is exercised against this exact, real logic rather than
/// asserted only by code review.
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

/// Replica of parse_pem_block_macos's date parser (BR-02): LibreSSL 3.3.6's
/// NATIVE ASN1_TIME_print format ("Jul 20 19:06:44 2026 GMT" / "Jan  1
/// 00:00:00 2025 GMT") -> "YYYY-MM-DD", never `-dateopt iso_8601` (this
/// host's /usr/bin/openssl rejects that option outright, exit 1).
std::string parse_openssl_native_date(std::string_view value) {
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

/// Replica of parse_pem_block_macos's strip_leading_blank.
std::string strip_leading_blank(std::string s) {
    std::size_t i = 0;
    while (i < s.size() && (s[i] == ' ' || s[i] == '\t'))
        ++i;
    s.erase(0, i);
    return s;
}

/// Replica of CertRecord -- the 8 pipe-delimited row fields
/// parse_pem_block_macos populates, plus a to_row() that calls the REAL
/// (not replicated) yuzu::util::safe_output_field, matching
/// certificates_plugin.cpp's CertRecord::to_row() field-for-field (BR-07).
struct FakeCertFields {
    std::string subject = "(unknown)";
    std::string issuer = "(unknown)";
    std::string thumbprint = "(unknown)";
    std::string not_before = "(unknown)";
    std::string not_after = "(unknown)";
    std::string serial = "(unknown)";
    std::string store = "System.keychain";
    std::string key_usage = "(none)";

    std::string to_row() const {
        return std::format("{}|{}|{}|{}|{}|{}|{}|{}", yuzu::util::safe_output_field(subject),
                           yuzu::util::safe_output_field(issuer), thumbprint, not_before,
                           not_after, yuzu::util::safe_output_field(serial), store,
                           yuzu::util::safe_output_field(key_usage));
    }
};

/// Replica of parse_pem_block_macos's PARSING logic only (everything from
/// `std::istringstream iss(result.output)` onward) -- the temp-file-write
/// and run_bounded_subprocess() call are deliberately NOT replicated (a
/// unit test must never fork a real openssl); this takes the subprocess's
/// captured stdout directly as a fixture string, exactly the boundary
/// certificates_plugin.cpp itself injects at (`result.output`).
FakeCertFields parse_openssl_combined_output(const std::string& openssl_output) {
    FakeCertFields rec;

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

/// Replica of certificates_plugin.cpp's parse_pem_block_macos capture-
/// usability gate (BR-03; nonzero-exit rejection added for fix-round
/// finding FP-CERTS-05). Takes the four SubprocessResult fields the real
/// gate reads rather than a SubprocessResult itself -- agent-core's real
/// type is not reachable from a plugin-side unit test (same boundary this
/// whole file is written against).
bool is_usable_capture(bool tool_ran, bool timed_out, bool output_truncated, int exit_code) {
    return tool_ran && !timed_out && !output_truncated && exit_code == 0;
}

/// Replica of certificates_plugin.cpp's is_valid_thumbprint (40 hex chars).
bool is_valid_thumbprint(std::string_view s) {
    if (s.size() != 40)
        return false;
    for (char c : s) {
        if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')))
            return false;
    }
    return true;
}

/// Replica of certificates_plugin.cpp's BlockIdentityOutcome /
/// classify_block_identity (fix-round finding FP-CERTS-02): the tri-state
/// decision details_cert_macos's per-keychain scan and delete's
/// keychain_contains_thumbprint both now share, so a thumbprint that
/// couldn't be established (the "(unknown)" sentinel from a failed/
/// timed-out per-cert openssl parse) is never folded into a clean
/// "not this one".
enum class BlockIdentityOutcome { kMatch, kNoMatch, kInconclusive };

BlockIdentityOutcome classify_block_identity(std::string_view parsed_thumbprint,
                                              std::string_view needle) {
    if (!is_valid_thumbprint(parsed_thumbprint))
        return BlockIdentityOutcome::kInconclusive;
    return parsed_thumbprint == needle ? BlockIdentityOutcome::kMatch
                                        : BlockIdentityOutcome::kNoMatch;
}

/// Replica of certificates_plugin.cpp's is_provably_absent_macos
/// (adversarial-review finding K-4): the pure decision that gates whether
/// delete_cert_macos reports `status|not_found` and skips the destructive
/// `security delete-certificate` call entirely, rather than running it
/// against an already-absent thumbprint and reporting a generic
/// kCommandFailed `error|delete failed ...`. Only a definitive `false`
/// (a successful re-enumeration that positively did not find the
/// thumbprint) qualifies -- `true` (present) and std::nullopt (the presence
/// check itself was inconclusive/unreadable) must both fall through to the
/// real delete attempt, exactly like classify_delete_verdict's own
/// std::nullopt handling for the post-delete verify.
bool is_provably_absent_macos(std::optional<bool> presence) {
    return presence.has_value() && !*presence;
}

/// Replica of certificates_plugin.cpp's clamp_to_action_budget (fix-round
/// finding FP-CERTS-03): clamps a per-subprocess deadline cap to whatever
/// remains of a whole-action budget, returning zero (never negative) once
/// the budget is exhausted.
std::chrono::milliseconds clamp_to_action_budget(
    std::chrono::steady_clock::time_point action_deadline,
    std::chrono::milliseconds per_call_cap) {
    auto remaining = action_deadline - std::chrono::steady_clock::now();
    if (remaining <= std::chrono::steady_clock::duration::zero())
        return std::chrono::milliseconds::zero();
    auto remaining_ms = std::chrono::duration_cast<std::chrono::milliseconds>(remaining);
    return remaining_ms < per_call_cap ? remaining_ms : per_call_cap;
}

} // namespace

// ── parse_console_user_output ────────────────────────────────────────────────

TEST_CASE("parse_console_user_output trims whitespace around the stat payload",
         "[certificates][macos]") {
    SECTION("trailing newline, the common `stat -f%Su` case") {
        CHECK(parse_console_user_output("alice\n") == "alice");
    }
    SECTION("trailing CRLF") {
        CHECK(parse_console_user_output("alice\r\n") == "alice");
    }
    SECTION("leading and trailing blanks") {
        CHECK(parse_console_user_output("  alice  \n") == "alice");
    }
    SECTION("already-clean input is left alone") {
        CHECK(parse_console_user_output("alice") == "alice");
    }
    SECTION("empty input stays empty") {
        CHECK(parse_console_user_output("").empty());
    }
    SECTION("whitespace-only input becomes empty") {
        CHECK(parse_console_user_output("  \n\t ").empty());
    }
    SECTION("the no-console-user sentinel round-trips unchanged") {
        CHECK(parse_console_user_output("root\n") == "root");
    }
}

// ── is_no_console_user ───────────────────────────────────────────────────────

TEST_CASE("is_no_console_user identifies the login-window / headless sentinel",
         "[certificates][macos]") {
    CHECK(is_no_console_user("root"));
    CHECK(is_no_console_user(""));
    CHECK_FALSE(is_no_console_user("alice"));
    CHECK_FALSE(is_no_console_user("rootuser")); // exact match only, not a prefix
    CHECK_FALSE(is_no_console_user("toor"));
    // Case-sensitive by design: `stat -f%Su` always emits lowercase "root"
    // for the sentinel, so a literal "Root" is (if unusual) a real username,
    // not the no-session marker.
    CHECK_FALSE(is_no_console_user("Root"));
}

// ── is_valid_username (shell-injection guard) ────────────────────────────────

TEST_CASE("is_valid_username accepts the safe-identifier allowlist",
         "[certificates][macos]") {
    CHECK(is_valid_username("alice"));
    CHECK(is_valid_username("alice.smith"));
    CHECK(is_valid_username("alice_smith-2"));
    CHECK(is_valid_username("ALICE123"));
    // Syntactically valid as an identifier -- is_no_console_user is the
    // separate, semantic "no session" check; the two are orthogonal.
    CHECK(is_valid_username("root"));
}

TEST_CASE("is_valid_username rejects empty and shell-metacharacter input",
         "[certificates][macos]") {
    CHECK_FALSE(is_valid_username(""));
    CHECK_FALSE(is_valid_username("alice; rm -rf /"));
    CHECK_FALSE(is_valid_username("alice`whoami`"));
    CHECK_FALSE(is_valid_username("$(whoami)"));
    CHECK_FALSE(is_valid_username("alice space"));
    CHECK_FALSE(is_valid_username("alice\"quote"));
    CHECK_FALSE(is_valid_username("alice'quote"));
    CHECK_FALSE(is_valid_username("alice|pipe"));
    CHECK_FALSE(is_valid_username("alice&bg"));
    CHECK_FALSE(is_valid_username("../../etc/passwd"));
    CHECK_FALSE(is_valid_username("alice/bob"));
    CHECK_FALSE(is_valid_username("alice\nbob"));
    CHECK_FALSE(is_valid_username("alice\tbob"));
}

TEST_CASE("is_valid_username rejects option-like leading characters",
         "[certificates][macos]") {
    // A leading '-' would let `id -u <username>` misread the value as one
    // of its own flags rather than an account name to look up -- argument
    // injection, distinct from the shell-metacharacter checks above.
    CHECK_FALSE(is_valid_username("-G"));
    CHECK_FALSE(is_valid_username("--help"));
    CHECK_FALSE(is_valid_username("-a"));
    // A leading '.' is syntactically in the per-character allowlist but is
    // never how a real macOS account name starts; excluded defensively too.
    CHECK_FALSE(is_valid_username(".hidden"));
    // A non-leading '-' or '.' is still fine.
    CHECK(is_valid_username("a-b"));
    CHECK(is_valid_username("a.b"));
}

// ── is_valid_uid (shell-injection guard) ─────────────────────────────────────

TEST_CASE("is_valid_uid accepts numeric-only, non-empty input", "[certificates][macos]") {
    CHECK(is_valid_uid("501"));
    CHECK(is_valid_uid("0"));
    CHECK(is_valid_uid("1"));
    CHECK(is_valid_uid("4294967295"));
}

TEST_CASE("is_valid_uid rejects empty, non-numeric, and injection input",
         "[certificates][macos]") {
    CHECK_FALSE(is_valid_uid(""));
    CHECK_FALSE(is_valid_uid("abc"));
    CHECK_FALSE(is_valid_uid("50a"));
    CHECK_FALSE(is_valid_uid("-1"));
    CHECK_FALSE(is_valid_uid(" 501"));
    CHECK_FALSE(is_valid_uid("501 "));
    CHECK_FALSE(is_valid_uid("501; rm -rf /"));
    CHECK_FALSE(is_valid_uid("0x1F5"));
}

// ── Keychain path mapping ─────────────────────────────────────────────────────

TEST_CASE("system_keychain_path and root_keychain_path are the fixed system paths",
         "[certificates][macos]") {
    CHECK(system_keychain_path() == "/Library/Keychains/System.keychain");
    CHECK(root_keychain_path() ==
         "/System/Library/Keychains/SystemRootCertificates.keychain");
}

TEST_CASE("login_keychain_path builds a ~username-relative path from the username",
         "[certificates][macos]") {
    // ~username (not a bare ~) so the OUTER shell resolves it via that
    // specific account's directory-services home, independent of the
    // invoking (daemon) process's own $HOME -- see the function comment.
    CHECK(login_keychain_path("alice") == "~alice/Library/Keychains/login.keychain-db");
    CHECK(login_keychain_path("bob.smith") ==
         "~bob.smith/Library/Keychains/login.keychain-db");
}

// ── resolve_store_plan ───────────────────────────────────────────────────────

TEST_CASE("resolve_store_plan: store=login", "[certificates][macos]") {
    SECTION("console user present -> login only") {
        auto plan = resolve_store_plan("login", true);
        CHECK(plan.want_login);
        CHECK_FALSE(plan.want_system);
        CHECK_FALSE(plan.want_root);
        CHECK_FALSE(plan.sentinel_required);
    }
    SECTION("no console user -> unfulfillable, sentinel required") {
        auto plan = resolve_store_plan("login", false);
        CHECK(plan.sentinel_required);
        CHECK_FALSE(plan.want_login);
        CHECK_FALSE(plan.want_system);
        CHECK_FALSE(plan.want_root);
    }
}

TEST_CASE("resolve_store_plan: store=System is independent of console-user state",
         "[certificates][macos]") {
    for (bool has_console_user : {true, false}) {
        auto plan = resolve_store_plan("System", has_console_user);
        CHECK(plan.want_system);
        CHECK_FALSE(plan.want_root);
        CHECK_FALSE(plan.want_login);
        CHECK_FALSE(plan.sentinel_required);
    }
}

TEST_CASE("resolve_store_plan: store=root is independent of console-user state",
         "[certificates][macos]") {
    for (bool has_console_user : {true, false}) {
        auto plan = resolve_store_plan("root", has_console_user);
        CHECK(plan.want_root);
        CHECK_FALSE(plan.want_system);
        CHECK_FALSE(plan.want_login);
        CHECK_FALSE(plan.sentinel_required);
    }
}

TEST_CASE("resolve_store_plan: store=all", "[certificates][macos]") {
    SECTION("console user present -> system + root + login, never a sentinel") {
        auto plan = resolve_store_plan("all", true);
        CHECK(plan.want_system);
        CHECK(plan.want_root);
        CHECK(plan.want_login);
        CHECK_FALSE(plan.sentinel_required);
    }
    SECTION("no console user -> system + root only, login silently omitted") {
        auto plan = resolve_store_plan("all", false);
        CHECK(plan.want_system);
        CHECK(plan.want_root);
        CHECK_FALSE(plan.want_login);
        CHECK_FALSE(plan.sentinel_required); // System + root are still real results
    }
}

TEST_CASE("resolve_store_plan: unrecognized/default values behave like \"all\"",
         "[certificates][macos]") {
    SECTION("empty string (defensive -- the shared dispatcher always defaults to \"all\")") {
        auto plan = resolve_store_plan("", true);
        CHECK(plan.want_system);
        CHECK(plan.want_root);
        CHECK(plan.want_login);
    }
    SECTION("a Windows-flavoured store name passed out of habit") {
        auto plan = resolve_store_plan("MY", false);
        CHECK(plan.want_system);
        CHECK(plan.want_root);
        CHECK_FALSE(plan.want_login);
        CHECK_FALSE(plan.sentinel_required);
    }
    SECTION("a wholly unrecognized value") {
        auto plan = resolve_store_plan("bogus", true);
        CHECK(plan.want_system);
        CHECK(plan.want_root);
        CHECK(plan.want_login);
    }
}

// ── resolve_delete_keychain_path ─────────────────────────────────────────────

TEST_CASE("resolve_delete_keychain_path: \"root\" targets the root keychain",
         "[certificates][macos]") {
    auto path = resolve_delete_keychain_path("root");
    REQUIRE(path.has_value());
    CHECK(*path == root_keychain_path());
}

TEST_CASE("resolve_delete_keychain_path: \"MY\"/\"System\" preserve the System.keychain default",
         "[certificates][macos]") {
    auto sys = resolve_delete_keychain_path("System");
    REQUIRE(sys.has_value());
    CHECK(*sys == system_keychain_path());

    auto my = resolve_delete_keychain_path("MY"); // cross-platform dispatcher default
    REQUIRE(my.has_value());
    CHECK(*my == system_keychain_path());
}

TEST_CASE("resolve_delete_keychain_path: unsupported stores are rejected, "
         "never silently redirected",
         "[certificates][macos]") {
    // A destructive action must never target a keychain the caller didn't
    // ask for -- "login" (not implemented for delete) and "all" (no
    // single-keychain meaning) and garbage input all reject rather than
    // falling back to System.keychain.
    CHECK_FALSE(resolve_delete_keychain_path("login").has_value());
    CHECK_FALSE(resolve_delete_keychain_path("all").has_value());
    CHECK_FALSE(resolve_delete_keychain_path("").has_value());
    CHECK_FALSE(resolve_delete_keychain_path("bogus").has_value());
}

// ── build_login_keychain_read_command (shell-injection guard) ───────────────

TEST_CASE("build_login_keychain_read_command: caller already root -- no outer sudo hop",
         "[certificates][macos]") {
    // Mirrors quarantine_plugin.cpp's sudo_prefix(): today's shipped
    // LaunchDaemon runs as root, so `launchctl asuser` (which itself
    // requires root) needs no escalation -- only the inner drop to the
    // target console user does.
    auto cmd = build_login_keychain_read_command("501", "alice", /*caller_is_root=*/true);
    CHECK(cmd == "/bin/launchctl asuser 501 /usr/bin/sudo -n -u alice /usr/bin/security "
                "find-certificate -a -p ~alice/Library/Keychains/login.keychain-db "
                "2>/dev/null");
}

TEST_CASE("build_login_keychain_read_command: non-root caller escalates via an outer sudo",
         "[certificates][macos]") {
    // The target `_yuzu` least-privilege account (#1455) is NOT root, so it
    // must sudo to root itself before launchctl asuser will admit it -- this
    // is exactly the command the sudoers handoff grant needs to cover.
    auto cmd = build_login_keychain_read_command("501", "alice", /*caller_is_root=*/false);
    CHECK(cmd == "/usr/bin/sudo -n /bin/launchctl asuser 501 /usr/bin/sudo -n -u alice "
                "/usr/bin/security find-certificate -a -p "
                "~alice/Library/Keychains/login.keychain-db 2>/dev/null");
}

TEST_CASE("build_login_keychain_read_command rejects an invalid uid", "[certificates][macos]") {
    CHECK(build_login_keychain_read_command("abc", "alice", true).empty());
    CHECK(build_login_keychain_read_command("", "alice", true).empty());
    CHECK(build_login_keychain_read_command("501; rm -rf /", "alice", true).empty());
    // Invalid input is rejected the same way regardless of caller_is_root.
    CHECK(build_login_keychain_read_command("abc", "alice", false).empty());
}

TEST_CASE("build_login_keychain_read_command rejects an invalid username",
         "[certificates][macos]") {
    CHECK(build_login_keychain_read_command("501", "alice; rm -rf /", true).empty());
    CHECK(build_login_keychain_read_command("501", "", true).empty());
    CHECK(build_login_keychain_read_command("501", "alice`whoami`", true).empty());
    CHECK(build_login_keychain_read_command("501", "$(whoami)", true).empty());
    CHECK(build_login_keychain_read_command("501", "alice space", true).empty());
    CHECK(build_login_keychain_read_command("501", "-G", true).empty());
}

TEST_CASE("build_login_keychain_read_command rejects when both uid and username are invalid",
         "[certificates][macos]") {
    CHECK(build_login_keychain_read_command("", "", true).empty());
    CHECK(build_login_keychain_read_command("nope", "nope; rm -rf /", true).empty());
}

// ── classify_delete_verdict (PLAN-06: rc + still-present -> verdict) ────────
//
// delete_cert_macos()'s tri-state post-delete verify, factored out as a pure
// decision so it is exercised here with fixture int/optional<bool> inputs
// -- no `security` subprocess, no real keychain, matching every other
// vector in this file. The first argument is the raw exit code
// (run_bounded_checked's `exit_code` field, BR-03), not a pre-collapsed
// bool, so representative nonzero values and the -1 spawn-failure/abnormal-
// termination sentinel are exercised directly.

TEST_CASE("classify_delete_verdict: a failed delete command is always kCommandFailed",
         "[certificates][macos]") {
    // still_present is meaningless when the delete command itself never
    // succeeded -- a real caller never populates it in that case, but the
    // classifier must still be safe (and consistent) if it somehow is.
    CHECK(classify_delete_verdict(-1, std::nullopt) ==
         DeleteVerdict::kCommandFailed); // spawn failure / abnormal termination
    CHECK(classify_delete_verdict(1, std::nullopt) ==
         DeleteVerdict::kCommandFailed); // representative nonzero POSIX exit
    CHECK(classify_delete_verdict(1, true) == DeleteVerdict::kCommandFailed);
    CHECK(classify_delete_verdict(-1, false) == DeleteVerdict::kCommandFailed);
}

TEST_CASE("classify_delete_verdict: rc==0 but the verify re-enumeration couldn't read the "
         "keychain -> kVerifyUnreadable, never kDeleted",
         "[certificates][macos]") {
    // The exact false-success gap this package exists to close: a zero
    // exit status alone must never be reported as "deleted" -- an
    // unreadable keychain proves nothing about whether the certificate is
    // actually gone.
    CHECK(classify_delete_verdict(0, std::nullopt) == DeleteVerdict::kVerifyUnreadable);
}

TEST_CASE("classify_delete_verdict: rc==0 but the certificate is still present -> kStillPresent",
         "[certificates][macos]") {
    CHECK(classify_delete_verdict(0, true) == DeleteVerdict::kStillPresent);
}

TEST_CASE("classify_delete_verdict: rc==0 and the certificate is proven absent -> kDeleted",
         "[certificates][macos]") {
    CHECK(classify_delete_verdict(0, false) == DeleteVerdict::kDeleted);
}

// ── is_provably_absent_macos (adversarial-review finding K-4) ───────────────
//
// delete_cert_macos's pre-delete presence check, factored out as a pure
// decision so it is exercised here with fixture std::optional<bool> inputs --
// no `security` subprocess, no real keychain, matching classify_delete_verdict
// above. Cross-platform consistency requires an absent thumbprint to report
// `status|not_found` (rc 0), the same contract Windows/Linux (and this
// macOS action's own pre-change behaviour) already honour; idempotent
// "ensure-absent" remediation depends on it.

TEST_CASE("is_provably_absent_macos: a definitive absent verdict (false) reports not_found",
         "[certificates][macos]") {
    CHECK(is_provably_absent_macos(false));
}

TEST_CASE("is_provably_absent_macos: a present thumbprint (true) falls through to the real "
         "delete attempt",
         "[certificates][macos]") {
    CHECK_FALSE(is_provably_absent_macos(true));
}

TEST_CASE("is_provably_absent_macos: an inconclusive/unreadable presence check (std::nullopt) "
         "must NEVER be masked as not_found",
         "[certificates][macos]") {
    // The K-4 finding's explicit guardrail: if the pre-delete presence
    // check itself could not conclusively read/parse the keychain (locked,
    // permission denied, an inconclusive block identity, action-budget
    // exhaustion, ...), that proves nothing about whether the certificate
    // is actually there -- it must fall through to the real delete attempt
    // (and whatever honest error that produces), never be silently
    // reported as "not found".
    CHECK_FALSE(is_provably_absent_macos(std::nullopt));
}

// ── is_usable_capture (fix-round finding FP-CERTS-05) ────────────────────────
//
// parse_pem_block_macos's gate for whether a completed run_bounded_subprocess
// call is trustworthy enough to parse at all. Before this fix round, a
// cleanly-captured (not killed, not truncated) run that still exited nonzero
// -- e.g. openssl printing a plausible-looking preamble before failing --
// was parsed as if it were a complete, trustworthy capture.

TEST_CASE("is_usable_capture: only a clean, complete, exit-0 run is usable",
         "[certificates][macos]") {
    CHECK(is_usable_capture(/*tool_ran=*/true, /*timed_out=*/false, /*output_truncated=*/false,
                            /*exit_code=*/0));
}

TEST_CASE("is_usable_capture: rejects exec failure, timeout, truncation, and a nonzero exit",
         "[certificates][macos]") {
    CHECK_FALSE(is_usable_capture(false, false, false, 0)); // exec itself failed
    CHECK_FALSE(is_usable_capture(true, true, false, 0));   // killed at its deadline
    CHECK_FALSE(is_usable_capture(true, false, true, 0));   // capture hit the runner's cap
    // FP-CERTS-05: fully captured, not timed out, not truncated -- but the
    // process still exited nonzero. Before this fix round the gate did not
    // check exit_code at all, so this case was (incorrectly) usable=true.
    CHECK_FALSE(is_usable_capture(true, false, false, 1));
}

// ── classify_block_identity (fix-round finding FP-CERTS-02) ─────────────────
//
// The tri-state per-block decision details_cert_macos's per-keychain scan
// and delete's keychain_contains_thumbprint now share: a block whose
// identity could not be established (parse_pem_block_macos's honest
// "(unknown)" sentinel, from a failed/timed-out/killed per-cert openssl
// call) must never be folded into a clean "not this one" -- it might BE the
// certificate being searched for.

TEST_CASE("classify_block_identity: a validated thumbprint equal to the needle is a match",
         "[certificates][macos]") {
    const std::string needle = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    CHECK(classify_block_identity(needle, needle) == BlockIdentityOutcome::kMatch);
}

TEST_CASE("classify_block_identity: a validated thumbprint different from the needle is a "
         "clean non-match",
         "[certificates][macos]") {
    const std::string needle = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    CHECK(classify_block_identity("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", needle) ==
         BlockIdentityOutcome::kNoMatch);
}

TEST_CASE("classify_block_identity: the honest (unknown) sentinel is inconclusive, never a "
         "silent non-match",
         "[certificates][macos]") {
    const std::string needle = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    // "(unknown)" is exactly what parse_pem_block_macos's CertRecord.thumbprint
    // stays at when its own openssl call was killed/capped/failed -- FP-CERTS-02's
    // regression scenario. Before this fix round, a plain `==` comparison
    // treated this the same as a definitive non-match.
    CHECK(classify_block_identity("(unknown)", needle) == BlockIdentityOutcome::kInconclusive);
}

TEST_CASE("classify_block_identity: an empty thumbprint is inconclusive",
         "[certificates][macos]") {
    CHECK(classify_block_identity("", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") ==
         BlockIdentityOutcome::kInconclusive);
}

// ── clamp_to_action_budget (fix-round finding FP-CERTS-03) ──────────────────
//
// Every macOS cert subprocess now receives min(its own per-call cap, the
// whole action's remaining budget) rather than its own full independent
// deadline -- before this fix round, list/details' 60s action_deadline was
// created only after console-user resolution had already run, and every
// later keychain-level `security` read still got the FULL kKeychainReadDeadline
// regardless of budget already spent, letting a single call run to roughly
// 100s in the worst case.

TEST_CASE("clamp_to_action_budget: plenty of budget remaining returns the per-call cap unchanged",
         "[certificates][macos]") {
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(60);
    CHECK(clamp_to_action_budget(deadline, std::chrono::milliseconds(5000)) ==
         std::chrono::milliseconds(5000));
}

TEST_CASE("clamp_to_action_budget: an already-exhausted budget returns zero, never negative",
         "[certificates][macos]") {
    auto deadline = std::chrono::steady_clock::now() - std::chrono::seconds(1);
    CHECK(clamp_to_action_budget(deadline, std::chrono::milliseconds(5000)) ==
         std::chrono::milliseconds::zero());
}

TEST_CASE("clamp_to_action_budget: less budget remaining than the per-call cap clamps down to "
         "the budget",
         "[certificates][macos]") {
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(200);
    auto clamped = clamp_to_action_budget(deadline, std::chrono::milliseconds(5000));
    CHECK(clamped > std::chrono::milliseconds::zero());
    CHECK(clamped <= std::chrono::milliseconds(200));
}

// ── FP-CERTS-R3 regression: exhausted-budget verify must never read as ─────
// "deleted" ──────────────────────────────────────────────────────────────
//
// delete_cert_macos()'s post-delete keychain_contains_thumbprint() re-read
// now clamps to the SAME whole-action deadline the preceding `security
// delete-certificate` call already spent budget against, instead of opening
// its own fresh window (the ~75s-worst-case gap this finding closed). This
// doesn't add a new pure decision point of its own -- it's these two
// helpers wired together -- so the regression is expressed directly in
// terms of them: once clamp_to_action_budget reports the budget spent, the
// only honest outcome available to the verify read is std::nullopt, and
// classify_delete_verdict must map that to kVerifyUnreadable, never
// kDeleted, exactly like an unreadable keychain.

TEST_CASE("FP-CERTS-R3: an exhausted action budget clamps the verify read's deadline to zero, "
         "which classify_delete_verdict must treat as kVerifyUnreadable, never kDeleted",
         "[certificates][macos]") {
    auto action_deadline = std::chrono::steady_clock::now() - std::chrono::seconds(1);
    // Same clamp keychain_contains_thumbprint applies to its own read
    // before issuing it -- exhausted, so the production code skips the
    // subprocess entirely rather than issuing a doomed call.
    CHECK(clamp_to_action_budget(action_deadline, std::chrono::milliseconds(15000)) ==
         std::chrono::milliseconds::zero());
    // The resulting std::nullopt (never a fabricated `false`/absent) must
    // still be classified as an unverified failure even though the delete
    // command itself reported rc==0.
    CHECK(classify_delete_verdict(0, std::nullopt) == DeleteVerdict::kVerifyUnreadable);
}

// ── parse_console_user_output + is_valid_uid: FP-CERTS-01 regression ────────
//
// resolve_console_user() (certificates_plugin.cpp) validates `id -u
// <username>`'s captured output with is_valid_uid() before trusting it.
// run_bounded_subprocess's SubprocessResult::output is the RAW captured
// stream -- a trailing '\n' included -- and is_valid_uid() rejects any
// non-digit character outright, so before this fix round every ordinary
// `id -u` result ("501\n") failed validation and login-keychain reads were
// silently disabled entirely. The fix reuses parse_console_user_output
// (already proven to trim exactly this shape, see the section above) on the
// uid capture too, before validation.

TEST_CASE("FP-CERTS-01: raw id -u output with its trailing newline fails uid validation "
         "unless trimmed first",
         "[certificates][macos]") {
    const std::string raw_id_output = "501\n"; // ordinary `id -u alice` capture
    CHECK_FALSE(is_valid_uid(raw_id_output)); // the pre-fix bug: always rejected
    CHECK(is_valid_uid(parse_console_user_output(raw_id_output))); // the fix: trim first
    CHECK(parse_console_user_output(raw_id_output) == "501");
}

// ── parse_openssl_native_date (BR-02) ────────────────────────────────────────
//
// LibreSSL 3.3.6 -- this host's /usr/bin/openssl -- rejects `-dateopt
// iso_8601` outright (exit 1, "unknown option -dateopt"), so
// parse_pem_block_macos parses openssl's NATIVE ASN1_TIME_print format
// instead. All fixture strings below are the exact shape captured from a
// real invocation of this host's /usr/bin/openssl.

TEST_CASE("parse_openssl_native_date: standard two-digit day", "[certificates][macos]") {
    CHECK(parse_openssl_native_date("Jul 20 19:06:44 2026 GMT") == "2026-07-20");
}

TEST_CASE("parse_openssl_native_date: single-digit day is space-padded to width 2",
         "[certificates][macos]") {
    // A single-digit day prints as e.g. "Jan  1" -- TWO spaces, since
    // ASN1_TIME_print space-pads the day to width 2 -- so the run of
    // whitespace between month and day varies by one character depending
    // on the day. Tokenizing on whitespace handles both without a special
    // case; a fixed-width substring slice (the pre-fix -dateopt approach)
    // would not.
    CHECK(parse_openssl_native_date("Jan  1 00:00:00 2025 GMT") == "2025-01-01");
}

TEST_CASE("parse_openssl_native_date: every month abbreviation maps to the right number",
         "[certificates][macos]") {
    CHECK(parse_openssl_native_date("Jan  5 00:00:00 2030 GMT") == "2030-01-05");
    CHECK(parse_openssl_native_date("Feb 28 00:00:00 2030 GMT") == "2030-02-28");
    CHECK(parse_openssl_native_date("Mar 15 00:00:00 2030 GMT") == "2030-03-15");
    CHECK(parse_openssl_native_date("Apr 30 00:00:00 2030 GMT") == "2030-04-30");
    CHECK(parse_openssl_native_date("May 10 00:00:00 2030 GMT") == "2030-05-10");
    CHECK(parse_openssl_native_date("Jun 20 00:00:00 2030 GMT") == "2030-06-20");
    CHECK(parse_openssl_native_date("Jul  4 00:00:00 2030 GMT") == "2030-07-04");
    CHECK(parse_openssl_native_date("Aug 31 00:00:00 2030 GMT") == "2030-08-31");
    CHECK(parse_openssl_native_date("Sep  9 00:00:00 2030 GMT") == "2030-09-09");
    CHECK(parse_openssl_native_date("Oct 31 00:00:00 2030 GMT") == "2030-10-31");
    CHECK(parse_openssl_native_date("Nov 11 00:00:00 2030 GMT") == "2030-11-11");
    CHECK(parse_openssl_native_date("Dec 25 00:00:00 2030 GMT") == "2030-12-25");
}

TEST_CASE("parse_openssl_native_date: malformed input yields the honest unknown sentinel, "
         "never a fabricated date",
         "[certificates][macos]") {
    CHECK(parse_openssl_native_date("") == "(unknown)");
    CHECK(parse_openssl_native_date("garbage") == "(unknown)");
    CHECK(parse_openssl_native_date("2026-07-20") == "(unknown)"); // ISO 8601 is NOT native format
    CHECK(parse_openssl_native_date("Xxx 20 19:06:44 2026 GMT") == "(unknown)"); // unrecognized month
    CHECK(parse_openssl_native_date("Jul AB 19:06:44 2026 GMT") == "(unknown)"); // non-numeric day
    CHECK(parse_openssl_native_date("Jul 20 19:06:44 20AB GMT") == "(unknown)"); // non-numeric year
    CHECK(parse_openssl_native_date("Jul 20 19:06:44 26 GMT") == "(unknown)");   // 2-digit year
    CHECK(parse_openssl_native_date("Jul 40 19:06:44 2026 GMT") == "(unknown)"); // day out of range
    CHECK(parse_openssl_native_date("Jul") == "(unknown)"); // too few tokens
}

// ── expires_within_days with REAL dates (BR-02 regression) ──────────────────
//
// Before this fix, not_after was always the 9-char literal "(unknown)"
// placeholder (the -dateopt call failed against LibreSSL), and
// expires_within_days's own `not_after.size() < 10` guard treated that as
// "can't parse, include it" -- so EVERY certificate silently passed the
// expiry filter regardless of `days`. expires_within_days's logic itself is
// unchanged by this package; these vectors prove the regression is closed
// by what now reaches it.

TEST_CASE("expires_within_days: days<=0 includes every certificate", "[certificates][macos]") {
    CHECK(expires_within_days("2099-01-01", 0));
    CHECK(expires_within_days("2099-01-01", -5));
}

TEST_CASE("expires_within_days: an unparseable/short date is honestly included, never dropped",
         "[certificates][macos]") {
    // The pre-fix universal-pass case (the literal 9-char placeholder) --
    // still honoured today for a genuinely unparseable date, just no
    // longer what a SUCCESSFUL parse produces.
    CHECK(expires_within_days("(unknown)", 30));
    CHECK(expires_within_days("", 30));
}

TEST_CASE("expires_within_days: a certificate expiring far beyond `days` is EXCLUDED",
         "[certificates][macos]") {
    // The exact BR-02 regression this package closes: with a REAL
    // not_after date (not the 9-char placeholder), a certificate that
    // expires decades from now must NOT pass a tight 30-day filter.
    CHECK_FALSE(expires_within_days("2099-01-01", 30));
}

TEST_CASE("expires_within_days: an already-expired certificate is included",
         "[certificates][macos]") {
    CHECK(expires_within_days("2020-01-01", 30));
}

// ── parse_openssl_combined_output (BR-02 + BR-03) ────────────────────────────
//
// parse_pem_block_macos now issues ONE bounded openssl call covering
// -subject/-issuer/-startdate/-enddate/-serial/-fingerprint (each a fixed-
// position, never-indented "label=value" line, in that exact order) plus
// -text (used only for the X509v3 Key Usage extension, replacing the
// removed `-ext keyUsage`, which LibreSSL also rejects). Fixture strings
// below are the exact shape captured from a real invocation of this host's
// /usr/bin/openssl.

TEST_CASE("parse_openssl_combined_output: full fixture with a critical Key Usage extension",
         "[certificates][macos]") {
    const std::string fixture =
        "subject= /CN=test.example.com\n"
        "issuer= /CN=Test CA\n"
        "notBefore=Jul 20 19:06:44 2026 GMT\n"
        "notAfter=Jul 20 19:06:44 2027 GMT\n"
        "serial=B7AC9DB9CAF6ADDB\n"
        "SHA1 Fingerprint=5A:1F:42:58:CB:50:26:DC:A9:C6:FB:77:02:ED:A6:93:3A:F3:51:CB\n"
        "Certificate:\n"
        "    Data:\n"
        "        X509v3 extensions:\n"
        "            X509v3 Key Usage: critical\n"
        "                Digital Signature, Key Encipherment\n"
        "    Signature Algorithm: sha256WithRSAEncryption\n";

    auto rec = parse_openssl_combined_output(fixture);
    CHECK(rec.subject == "/CN=test.example.com");
    CHECK(rec.issuer == "/CN=Test CA");
    CHECK(rec.not_before == "2026-07-20");
    CHECK(rec.not_after == "2027-07-20");
    CHECK(rec.serial == "B7AC9DB9CAF6ADDB");
    CHECK(rec.thumbprint == "5A1F4258CB5026DCA9C6FB7702EDA6933AF351CB");
    CHECK(rec.key_usage == "Digital Signature, Key Encipherment");
}

TEST_CASE("parse_openssl_combined_output: non-critical Key Usage (trailing space, no marker)",
         "[certificates][macos]") {
    const std::string fixture = "subject= /CN=test\n"
                                "issuer= /CN=test\n"
                                "notBefore=Jul 20 19:06:44 2026 GMT\n"
                                "notAfter=Jul 20 19:06:44 2027 GMT\n"
                                "serial=AA\n"
                                "SHA1 Fingerprint=11:22:33\n"
                                "Certificate:\n"
                                "        X509v3 extensions:\n"
                                "            X509v3 Key Usage: \n"
                                "                Digital Signature, Key Encipherment, "
                                "Certificate Sign, CRL Sign\n";

    auto rec = parse_openssl_combined_output(fixture);
    CHECK(rec.key_usage == "Digital Signature, Key Encipherment, Certificate Sign, CRL Sign");
}

TEST_CASE("parse_openssl_combined_output: no X509v3 extensions section leaves key_usage "
         "at the honest (none) default",
         "[certificates][macos]") {
    const std::string fixture = "subject= /CN=test\n"
                                "issuer= /CN=test\n"
                                "notBefore=Jul 20 19:06:44 2026 GMT\n"
                                "notAfter=Jul 20 19:06:44 2027 GMT\n"
                                "serial=AA\n"
                                "SHA1 Fingerprint=11:22:33\n"
                                "Certificate:\n"
                                "    Signature Algorithm: sha256WithRSAEncryption\n";

    auto rec = parse_openssl_combined_output(fixture);
    CHECK(rec.key_usage == "(none)");
}

TEST_CASE("parse_openssl_combined_output: empty output leaves every field at its honest default",
         "[certificates][macos]") {
    // Mirrors a killed/failed run (parse_pem_block_macos short-circuits
    // before ever reaching this parser in that case, but the parser itself
    // must still degrade honestly if handed nothing).
    auto rec = parse_openssl_combined_output("");
    CHECK(rec.subject == "(unknown)");
    CHECK(rec.issuer == "(unknown)");
    CHECK(rec.not_before == "(unknown)");
    CHECK(rec.not_after == "(unknown)");
    CHECK(rec.serial == "(unknown)");
    CHECK(rec.thumbprint == "(unknown)");
    CHECK(rec.key_usage == "(none)");
}

TEST_CASE("parse_openssl_combined_output: a hostile Issuer/Subject line containing the literal "
         "\"X509v3 Key Usage:\" text cannot forge a fake match",
         "[certificates][macos]") {
    // A hostile certificate whose Subject/Issuer DN, as rendered by -text's
    // own "Issuer: .../Subject: ..." lines, happens to CONTAIN the literal
    // "X509v3 Key Usage:" string. The real header is only ever recognized
    // when it is the START of its own line (after trimming indentation) --
    // an "Issuer:"/"Subject:" line always carries that literal openssl-
    // generated label first, so a forged occurrence embedded inside the DN
    // text can never reach that position.
    const std::string fixture =
        "subject= /CN=test\n"
        "issuer= /CN=test\n"
        "notBefore=Jul 20 19:06:44 2026 GMT\n"
        "notAfter=Jul 20 19:06:44 2027 GMT\n"
        "serial=AA\n"
        "SHA1 Fingerprint=11:22:33\n"
        "Certificate:\n"
        "        Issuer: CN=X509v3 Key Usage: critical FORGED\n"
        "        Subject: CN=X509v3 Key Usage: critical FORGED\n"
        "        X509v3 extensions:\n"
        "            X509v3 Key Usage: critical\n"
        "                Key Agreement\n";

    auto rec = parse_openssl_combined_output(fixture);
    CHECK(rec.key_usage == "Key Agreement"); // the REAL extension, never the forged text
}

// ── CertRecord::to_row() escaping (BR-07) ────────────────────────────────────
//
// subject/issuer/serial/key_usage are passed through the REAL
// yuzu::util::safe_output_field (imported, not replicated) before
// certificates_plugin.cpp's CertRecord::to_row() builds the pipe-delimited
// row -- a hostile value can no longer inject an extra column ('|') or row
// (CR/LF) into `list`/`details` output.

TEST_CASE("to_row: a well-behaved certificate's fields round-trip unchanged",
         "[certificates][macos]") {
    FakeCertFields rec;
    rec.subject = "/CN=test.example.com";
    rec.issuer = "/CN=Test CA";
    rec.thumbprint = "5A1F4258CB5026DCA9C6FB7702EDA6933AF351CB";
    rec.not_before = "2026-07-20";
    rec.not_after = "2027-07-20";
    rec.serial = "B7AC9DB9CAF6ADDB";
    rec.store = "System.keychain";
    rec.key_usage = "Digital Signature, Key Encipherment";

    CHECK(rec.to_row() == "/CN=test.example.com|/CN=Test CA|"
                          "5A1F4258CB5026DCA9C6FB7702EDA6933AF351CB|2026-07-20|2027-07-20|"
                          "B7AC9DB9CAF6ADDB|System.keychain|Digital Signature, Key Encipherment");
}

TEST_CASE("to_row: a hostile subject/issuer containing '|' is escaped, never a raw "
         "column separator",
         "[certificates][macos]") {
    FakeCertFields rec;
    rec.subject = "CN=evil|injected|columns";
    rec.issuer = "CN=also|hostile";
    rec.thumbprint = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    rec.not_before = "2026-01-01";
    rec.not_after = "2027-01-01";
    rec.serial = "AA";
    rec.store = "System.keychain";
    rec.key_usage = "Digital Signature";

    auto row = rec.to_row();

    // Matches CertRecord::to_row() field-for-field.
    auto expected = std::format(
        "{}|{}|{}|{}|{}|{}|{}|{}", yuzu::util::safe_output_field(rec.subject),
        yuzu::util::safe_output_field(rec.issuer), rec.thumbprint, rec.not_before, rec.not_after,
        yuzu::util::safe_output_field(rec.serial), rec.store,
        yuzu::util::safe_output_field(rec.key_usage));
    CHECK(row == expected);

    // The defining property (the acceptance criterion): splitting the row
    // on a BARE '|' -- one NOT preceded by the '\' escape_pipes emits --
    // recovers exactly the 8 documented columns. A parser that honours the
    // escape can no longer mistake the hostile subject/issuer's '|' for a
    // column boundary.
    std::size_t bare_pipes = 0;
    for (std::size_t i = 0; i < row.size(); ++i) {
        if (row[i] == '|' && (i == 0 || row[i - 1] != '\\'))
            ++bare_pipes;
    }
    CHECK(bare_pipes == 7); // 8 fields => 7 real separators
}

TEST_CASE("to_row: embedded CR/LF in a hostile subject/issuer cannot inject an extra row",
         "[certificates][macos]") {
    FakeCertFields rec;
    rec.subject = "CN=evil\r\nstatus|deleted";
    rec.issuer = "CN=hostile\nrow";
    rec.thumbprint = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    rec.not_before = "2026-01-01";
    rec.not_after = "2027-01-01";
    rec.serial = "BB";
    rec.store = "System.keychain";
    rec.key_usage = "Digital Signature";

    auto row = rec.to_row();
    CHECK(row.find('\r') == std::string::npos);
    CHECK(row.find('\n') == std::string::npos);

    std::size_t bare_pipes = 0;
    for (std::size_t i = 0; i < row.size(); ++i) {
        if (row[i] == '|' && (i == 0 || row[i - 1] != '\\'))
            ++bare_pipes;
    }
    CHECK(bare_pipes == 7);
}

TEST_CASE("to_row: thumbprint/not_before/not_after/store are never escaped",
         "[certificates][macos]") {
    // These four are never attacker-influenced free text (thumbprint is
    // hex-validated or the literal sentinel, the dates are produced
    // entirely by this file's own date formatting, and store is always one
    // of this plugin's own fixed literal labels) -- confirms they pass
    // through byte-identical rather than being silently mangled by an
    // over-broad escape.
    FakeCertFields rec;
    rec.subject = "/CN=plain";
    rec.issuer = "/CN=plain-ca";
    rec.thumbprint = "0123456789ABCDEF0123456789ABCDEF01234567";
    rec.not_before = "2026-01-01";
    rec.not_after = "2027-01-01";
    rec.serial = "CAFE";
    rec.store = "SystemRootCertificates.keychain";
    rec.key_usage = "(none)";

    auto row = rec.to_row();
    CHECK(row.find(rec.thumbprint) != std::string::npos);
    CHECK(row.find(rec.not_before) != std::string::npos);
    CHECK(row.find(rec.not_after) != std::string::npos);
    CHECK(row.find(rec.store) != std::string::npos);
}

// ── delete-path error-row escaping (adversarial-review finding K-7) ─────────
//
// delete_cert_macos's two error-formatting call sites interpolate raw,
// attacker-influenceable text -- the caller-supplied `store` param (an
// unrecognized/unsupported store is rejected via `error|store '{}' is not
// supported for delete`) and `security delete-certificate`'s own captured,
// merged stderr (`error|delete failed (exit {}): {}`) -- directly into
// pipe/newline-delimited output. Neither replicates a NEW pure function (the
// fix is simply wrapping the interpolated value in the REAL
// yuzu::util::safe_output_field, already proven above for CertRecord's
// fields); these vectors instead exercise that real function against the
// EXACT two std::format templates certificates_plugin.cpp now uses, proving
// a hostile value can no longer inject an extra column/row into either.

TEST_CASE("K-7: the unsupported-store error message neutralizes a hostile store value",
         "[certificates][macos]") {
    // Mirrors delete_cert_macos's `error|store '{}' is not supported for
    // delete` format string verbatim, with safe_output_field applied to the
    // interpolated store value exactly as the fixed code now does.
    const std::string hostile_store = "evil|injected\r\nstatus|deleted";
    auto message = std::format("error|store '{}' is not supported for delete",
                               yuzu::util::safe_output_field(hostile_store));

    CHECK(message.find('\r') == std::string::npos);
    CHECK(message.find('\n') == std::string::npos);

    // Exactly one unescaped '|' -- the literal "error|" prefix's own
    // separator. Every '|' the hostile store contributed must have been
    // escaped (preceded by '\'), so it can no longer be mistaken for a
    // column boundary by a caller splitting this line on a bare '|'.
    std::size_t bare_pipes = 0;
    for (std::size_t i = 0; i < message.size(); ++i) {
        if (message[i] == '|' && (i == 0 || message[i - 1] != '\\'))
            ++bare_pipes;
    }
    CHECK(bare_pipes == 1);
}

TEST_CASE("K-7: the delete-failed error message neutralizes hostile multi-line stderr",
         "[certificates][macos]") {
    // Mirrors delete_cert_macos's `error|delete failed (exit {}): {}` format
    // string verbatim. delete_result.output is `security`'s captured,
    // merged stderr (merge_stderr=true) -- it typically ends with its own
    // trailing newline and can span multiple lines, and is never trusted to
    // be free of '|' either.
    const std::string hostile_stderr =
        "security: SecKeychainItemDelete: permission denied\nstatus|deleted\n";
    auto message = std::format("error|delete failed (exit {}): {}", 1,
                               yuzu::util::safe_output_field(hostile_stderr));

    CHECK(message.find('\r') == std::string::npos);
    CHECK(message.find('\n') == std::string::npos);

    std::size_t bare_pipes = 0;
    for (std::size_t i = 0; i < message.size(); ++i) {
        if (message[i] == '|' && (i == 0 || message[i - 1] != '\\'))
            ++bare_pipes;
    }
    CHECK(bare_pipes == 1); // only the literal "error|" prefix's own separator
}
