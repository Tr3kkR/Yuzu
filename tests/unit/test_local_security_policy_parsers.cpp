/**
 * test_local_security_policy_parsers.cpp -- pure core of local_security_policy over REAL
 * CAPTURE fixtures (wave8/local_security_policy/, provenance beside each set; *_assumed_shape
 * files are labelled reconstructions). The collector runs through injected readers: no
 * process, no live OS. Unguarded on every OS; expected values are pinned literals.
 */
#include <catch2/catch_test_macros.hpp>

#include "local_security_policy_legs.hpp" // pwpolicy_plist_to_items (CoreFoundation on macOS)

#include <cerrno>
#include <filesystem>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using namespace yuzu::local_security_policy;
using Rows = std::vector<std::string>;

namespace {

std::string fixture(const std::string& rel) {
    const fs::path p = fs::path{YUZU_TEST_FIXTURE_DIR} / "wave8" / "local_security_policy" / rel;
    REQUIRE(fs::exists(p)); // never skipped on a missing fixture
    std::ifstream f(p, std::ios::binary);
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

/// path -> fixture reader. A `files` value is a fixture name under linux/<set>/, or "@<text>" for
/// literal text; a path in `denied` is EACCES, any other path ENOENT.
struct FakeFs {
    std::string set;
    std::map<std::string, std::string> files;
    std::map<std::string, std::vector<std::string>> dirs;
    std::vector<std::string> denied;
    FileReader reader() const {
        return [this](const std::string& p) -> FileRead {
            if (std::find(denied.begin(), denied.end(), p) != denied.end()) return {EACCES, {}};
            const auto it = files.find(p);
            if (it == files.end()) return {ENOENT, {}};
            return {0, it->second[0] == '@' ? it->second.substr(1) : fixture("linux/" + set + "/" + it->second)};
        };
    }
    DirLister lister() const {
        return [this](const std::string& d) -> DirList {
            const auto it = dirs.find(d);
            return it == dirs.end() ? DirList{ENOENT, {}, false} : DirList{0, it->second, false};
        };
    }
};

FakeFs default_fs() {
    return {"default",
            {{"/etc/login.defs", "login.defs"}, {"/etc/security/pwquality.conf", "pwquality.conf"},
             {"/etc/security/faillock.conf", "faillock.conf"}, {"/etc/pam.d/common-password", "common-password"},
             {"/etc/pam.d/common-auth", "common-auth"}, {"/etc/sudoers", "sudoers"}, {"/etc/audit/audit.rules", "audit.rules"}},
            {{"/etc/sudoers.d", {}}}, {}};
}
FakeFs hardened_fs() {
    return {"hardened",
            {{"/etc/login.defs", "login.defs"}, {"/etc/security/pwquality.conf", "pwquality.conf"},
             {"/etc/security/faillock.conf", "faillock.conf"}, {"/etc/pam.d/password-auth", "password-auth"},
             {"/etc/sudoers", "sudoers"}, {"/etc/sudoers.d/10-ops", "sudoers.d-10-ops"}, {"/etc/audit/audit.rules", "audit.rules"}},
            {{"/etc/sudoers.d", {"10-ops"}}}, {}};
}

Collected run(const FakeFs& fs, LocalPolicyAction a, FileFlavor f = FileFlavor::Linux) {
    return collect_file_policy(f, a, fs.reader(), fs.lister());
}

std::vector<std::string> split_escape_aware(const std::string& row) {
    std::vector<std::string> out;
    std::string cur;
    for (std::size_t i = 0; i < row.size(); ++i) {
        if (row[i] == '\\' && i + 1 < row.size() && row[i + 1] == '|') cur += '|', ++i;
        else if (row[i] == '|') out.push_back(cur), cur.clear();
        else cur += row[i];
    }
    out.push_back(cur);
    return out;
}

std::vector<std::uint8_t> utf16le_bom(const std::u16string& s, bool bom = true) {
    std::vector<std::uint8_t> b;
    if (bom) b = {0xFF, 0xFE};
    for (char16_t c : s) b.push_back(c & 0xFF), b.push_back(c >> 8);
    return b;
}

} // namespace

// Fails under: dropped BOM check, wrong shift/mask, surrogate pairing removed, odd-length accepted.
TEST_CASE("decode_utf16le_bom: UTF-8 out, and every malformed buffer is nullopt", "[local_security_policy][parsers]") {
    CHECK(*decode_utf16le_bom(utf16le_bom(u"[System Access]\r\n")) == "[System Access]\r\n");
    CHECK(*decode_utf16le_bom(utf16le_bom(u"\u00e9\u20ac\U0001F600")) == "\xC3\xA9\xE2\x82\xAC\xF0\x9F\x98\x80");
    CHECK(decode_utf16le_bom(utf16le_bom(u"")) == std::string{}); // BOM only: empty, not failure
    CHECK_FALSE(decode_utf16le_bom(utf16le_bom(u"abc", false)).has_value()); // BOM-less
    auto odd = utf16le_bom(u"abc");
    odd.pop_back();
    CHECK_FALSE(decode_utf16le_bom(odd).has_value()); // odd length
    CHECK_FALSE(decode_utf16le_bom(utf16le_bom(std::u16string{char16_t{0xD83D}})).has_value()); // lone high surrogate
    CHECK_FALSE(decode_utf16le_bom(utf16le_bom(std::u16string{char16_t{0xDE00}})).has_value()); // lone low surrogate
    CHECK_FALSE(decode_utf16le_bom({}).has_value());
}

// Fails under: section handling, '=' split at the LAST '=', comment/blank handling, last-wins removed.
TEST_CASE("parse_inf_sections: sections, comments, first-'=' split, last key wins", "[local_security_policy][parsers]") {
    const auto s = parse_inf_sections("orphan = 1\r\n; comment\r\n[System Access]\r\nMinimumPasswordLength = 14\r\n"
                                      "NewAdministratorName = \"a=b\"\r\nMinimumPasswordLength = 8\r\n\r\n[Event Audit]\r\nAuditLogonEvents = 3\r\n");
    REQUIRE(s.size() == 2);
    CHECK(s.at("System Access").at("MinimumPasswordLength") == "8");
    CHECK(s.at("System Access").at("NewAdministratorName") == "\"a=b\"");
    CHECK(s.at("Event Audit").at("AuditLogonEvents") == "3");
    CHECK(s.at("System Access").count("orphan") == 0);
}

// Fails under: key list changes, absent-vs-value, audit bitmask mapping, missing-section handling.
TEST_CASE("secedit_policy_rows: keys, absent, audit bitmask, unmodelled, missing sections", "[local_security_policy][parsers]") {
    const auto text = decode_utf16le_bom(utf16le_bom(u"[System Access]\r\nMinimumPasswordLength = 14\r\nPasswordComplexity = 1\r\n"
                                                     "LockoutBadCount = 5\r\n[Event Audit]\r\nAuditLogonEvents = 3\r\nAuditPolicyChange = 2\r\n"
                                                     "AuditObjectAccess = 1\r\nAuditSystemEvents = 0\r\nAuditOdd = 7|x\r\n"));
    REQUIRE(text.has_value());
    const auto sections = parse_inf_sections(*text);
    const auto pw = secedit_policy_rows("password_policy", sections);
    CHECK(pw.failure_token.empty());
    CHECK(pw.rows == Rows{"password_policy|MinimumPasswordAge|absent|secedit", "password_policy|MaximumPasswordAge|absent|secedit",
                          "password_policy|MinimumPasswordLength|14|secedit", "password_policy|PasswordComplexity|1|secedit",
                          "password_policy|PasswordHistorySize|absent|secedit", "password_policy|ClearTextPassword|absent|secedit"});
    CHECK(secedit_policy_rows("lockout_policy", sections).rows == Rows{"lockout_policy|LockoutBadCount|5|secedit",
        "lockout_policy|ResetLockoutCount|absent|secedit", "lockout_policy|LockoutDuration|absent|secedit"});
    CHECK(secedit_policy_rows("audit_policy", sections).rows == Rows{"audit_policy|AuditLogonEvents|success_failure|secedit",
        "audit_policy|AuditObjectAccess|success|secedit", "audit_policy|AuditOdd|unmodelled:7\\|x|secedit",
        "audit_policy|AuditPolicyChange|failure|secedit", "audit_policy|AuditSystemEvents|none|secedit"});
    CHECK(secedit_policy_rows("password_policy", {}).failure_token == "secedit:section_missing_system_access");
    CHECK(secedit_policy_rows("audit_policy", {{"System Access", {{"a", "b"}}}}).failure_token == "secedit:section_missing_event_audit");
    CHECK(secedit_policy_rows("sudoers", sections).failure_token == "secedit:unsupported_action");
}

// The real secedit export is P83-2's fixture; it resolves once both packages are integrated.
TEST_CASE("secedit export fixture: UTF-16LE BOM decodes and both read sections parse", "[local_security_policy][parsers][windows_fixture]") {
    const std::string raw = fixture("windows/secedit_export.inf");
    const auto text = decode_utf16le_bom({reinterpret_cast<const std::uint8_t*>(raw.data()), raw.size()});
    REQUIRE(text.has_value());
    const auto s = parse_inf_sections(*text);
    REQUIRE(s.count("System Access") == 1);
    REQUIRE(s.count("Event Audit") == 1);
    CHECK(s.at("System Access").count("MinimumPasswordLength") == 1);
    CHECK(s.at("System Access").count("PasswordComplexity") == 1);
    CHECK_FALSE(s.at("Event Audit").empty());
    const auto rows = secedit_policy_rows("password_policy", s).rows;
    REQUIRE(rows.size() == 6);
    CHECK(rows[2].rfind("password_policy|MinimumPasswordLength|", 0) == 0);
    CHECK(rows[2].find("|absent|") == std::string::npos); // present in a real export
}

// Fails under: pam control/module/args split, allowlist removal, '-type' handling, continuation joining.
TEST_CASE("parse_pam_lines: bracketed controls, -type, @include, continuations", "[local_security_policy][parsers]") {
    const auto p = parse_pam_lines("# c\n@include common-auth\n-session optional pam_systemd.so\n"
                                   "auth [success=1 default=ignore] pam_unix.so nullok \\\n  try_first_pass\nbroken line\n");
    REQUIRE(p.size() == 2);
    CHECK(p[0].type == "session");
    CHECK(p[0].control == "optional");
    CHECK(p[0].args.empty());
    CHECK(p[1].control == "[success=1 default=ignore]");
    CHECK(p[1].module == "pam_unix.so");
    CHECK(p[1].args == "nullok  try_first_pass");
}

TEST_CASE("parse_auditd_rules_count: rule classes, -e, unmodelled", "[local_security_policy][parsers]") {
    const auto c = parse_auditd_rules_count("-D\n-b 8192\n-w /etc/sudoers -p wa\n-a always,exit -S execve\n-A exit,always -S open\n"
                                            "-e 1\n-e 2\n--weird\n# c\n\n");
    CHECK(c.total == 8);
    CHECK(c.watches == 1);
    CHECK(c.syscalls == 2);
    CHECK(c.unmodelled == 1);
    CHECK(*c.enabled == "2"); // last -e wins
    CHECK(audit_enabled_token("0") == "disabled");
    CHECK(audit_enabled_token("1") == "enabled");
    CHECK(audit_enabled_token("2") == "immutable");
    CHECK(audit_enabled_token("9") == "unmodelled:9");
}

// Fails under: NOPASSWD tag lost/sticky, runas split, escaped comma, directive kinds, unmodelled dropped.
TEST_CASE("parse_sudoers: kinds, tags, escaped commas, continuations, unmodelled", "[local_security_policy][parsers]") {
    const auto e = parse_sudoers("Defaults@web !lecture\nDefaults!/bin/su log_output\nUser_Alias ADMINS = a, b\n"
                                 "#include /etc/extra\n@includedir /etc/more.d\n# just a comment\n"
                                 "a, b web1 = (root) NOPASSWD: /bin/a\\, x, /bin/b, (bob) PASSWD: /bin/c # trailing\n"
                                 "#1000 ALL = \\\n  ALL\nFrobnicate the widgets\n");
    REQUIRE(e.size() == 9);
    CHECK(e[0].kind == "defaults");
    CHECK(e[0].subject == "host:web");
    CHECK(e[1].subject == "cmnd:/bin/su");
    CHECK(e[2].subject == "User_Alias:ADMINS");
    CHECK(e[2].commands == "a, b");
    CHECK(e[3].kind == "include");
    CHECK(e[3].commands == "/etc/extra");
    CHECK(e[4].kind == "includedir");
    CHECK(e[5].subject == "a, b@web1");
    CHECK(e[5].runas == "root");
    CHECK(e[5].nopasswd == "true");
    CHECK(e[5].commands == "/bin/a\\, x, /bin/b"); // escaped comma stays inside one command
    CHECK(e[6].runas == "bob");
    CHECK(e[6].nopasswd == "false");
    CHECK(e[6].commands == "/bin/c");
    CHECK(e[7].subject == "#1000@ALL"); // #<digits> is a uid, not a comment
    CHECK(e[8].kind == "unmodelled");
    CHECK(e[8].commands == "Frobnicate the widgets");
}

// Fails under: any change to which errno is absent vs denied vs failed, or to the status table.
TEST_CASE("classify_read_errno and select_status pin the failure contract", "[local_security_policy][parsers]") {
    CHECK(classify_read_errno(ENOENT).cls == ReadClass::Absent);
    CHECK(classify_read_errno(ENOTDIR).cls == ReadClass::Absent);
    CHECK(classify_read_errno(EACCES).cls == ReadClass::Denied);
    CHECK(classify_read_errno(EPERM).token == "permission_denied");
    CHECK(classify_read_errno(EIO).token == "io_error");
    CHECK(classify_read_errno(kReadOversized).token == "oversized");
    CHECK(classify_read_errno(kReadNotRegular).token == "not_regular");
    CHECK(classify_read_errno(EINVAL).token == "errno_" + std::to_string(EINVAL));
    CHECK(classify_read_errno(EINVAL).cls == ReadClass::Failed);
    CHECK(select_status(0, 0, 0) == PolicyStatus::Ok);
    CHECK(select_status(3, 0, 0) == PolicyStatus::Ok);
    CHECK(select_status(0, 2, 0) == PolicyStatus::PermissionDenied);
    CHECK(select_status(1, 1, 0) == PolicyStatus::Constrained);
    CHECK(select_status(0, 1, 1) == PolicyStatus::Constrained);
    CHECK(select_status(2, 0, 1) == PolicyStatus::Constrained);
}

// Real debian:12 default files. Fails under: login.defs allowlist, pam filtering, absent handling.
TEST_CASE("Linux default host (debian:12): exact rows", "[local_security_policy][collector]") {
    const auto fs = default_fs();
    const auto pw = run(fs, LocalPolicyAction::Password);
    CHECK(pw.status == PolicyStatus::Ok);
    CHECK(pw.reason.empty());
    CHECK(pw.rows == Rows{
        "password_policy|PASS_MAX_DAYS|99999|/etc/login.defs",
        "password_policy|PASS_MIN_DAYS|0|/etc/login.defs",
        "password_policy|PASS_WARN_AGE|7|/etc/login.defs",
        "password_policy|ENCRYPT_METHOD|SHA512|/etc/login.defs",
        "password_policy|pam.password.pam_pwquality.so|requisite retry=3|/etc/pam.d/common-password",
        "password_policy|pam.password.pam_unix.so|[success=1 default=ignore] obscure use_authtok try_first_pass yescrypt|/etc/pam.d/common-password"});
    CHECK(run(fs, LocalPolicyAction::Lockout).rows == Rows{
        "lockout_policy|FAILLOG_ENAB|yes|/etc/login.defs", "lockout_policy|LOGIN_RETRIES|5|/etc/login.defs",
        "lockout_policy|LOGIN_TIMEOUT|60|/etc/login.defs"});
    const auto au = run(fs, LocalPolicyAction::Audit).rows;
    CHECK(au.front() == "audit_policy|rules|4|/etc/audit/audit.rules");
    CHECK(au.back() == "audit_policy|enabled|unset|/etc/audit/audit.rules");
    const auto su = run(fs, LocalPolicyAction::Sudoers);
    REQUIRE(su.rows.size() == 7);
    CHECK(su.rows[0] == "sudoers|/etc/sudoers|defaults|-|-|-|env_reset");
    CHECK(su.rows[4] == "sudoers|/etc/sudoers|user_spec|root@ALL|ALL:ALL|false|ALL");
    CHECK(su.rows[5] == "sudoers|/etc/sudoers|user_spec|%sudo@ALL|ALL:ALL|false|ALL");
    CHECK(su.rows[6] == "sudoers|/etc/sudoers|includedir|-|-|-|/etc/sudoers.d");
}

// Real fedora:40 after authselect/pwquality/faillock/audit/sudoers.d changes.
TEST_CASE("Linux hardened host (fedora:40): exact rows", "[local_security_policy][collector]") {
    const auto fs = hardened_fs();
    const auto pw = run(fs, LocalPolicyAction::Password);
    CHECK(pw.status == PolicyStatus::Ok);
    REQUIRE(pw.rows.size() == 11);
    CHECK(pw.rows[0] == "password_policy|PASS_MAX_DAYS|60|/etc/login.defs");
    CHECK(pw.rows[5] == "password_policy|minlen|14|/etc/security/pwquality.conf");
    CHECK(pw.rows[6] == "password_policy|dcredit|-1|/etc/security/pwquality.conf");
    CHECK(pw.rows[9] == "password_policy|pam.password.pam_pwquality.so|requisite|/etc/pam.d/password-auth");
    CHECK(pw.rows[10] == "password_policy|pam.password.pam_unix.so|sufficient yescrypt shadow nullok use_authtok|/etc/pam.d/password-auth");
    const auto lo = run(fs, LocalPolicyAction::Lockout);
    CHECK(lo.rows == Rows{
        "lockout_policy|deny|3|/etc/security/faillock.conf", "lockout_policy|fail_interval|900|/etc/security/faillock.conf",
        "lockout_policy|unlock_time|900|/etc/security/faillock.conf",
        "lockout_policy|pam.auth.pam_faillock.so|required preauth silent|/etc/pam.d/password-auth",
        "lockout_policy|pam.auth.pam_faillock.so|required authfail|/etc/pam.d/password-auth",
        "lockout_policy|pam.account.pam_faillock.so|required|/etc/pam.d/password-auth"});
    const auto au = run(fs, LocalPolicyAction::Audit).rows;
    CHECK(au[0] == "audit_policy|rules|7|/etc/audit/audit.rules");
    CHECK(au[1] == "audit_policy|watch_rules|2|/etc/audit/audit.rules");
    CHECK(au[2] == "audit_policy|syscall_rules|3|/etc/audit/audit.rules");
    CHECK(au[4] == "audit_policy|enabled|immutable|/etc/audit/audit.rules");
    const auto su = run(fs, LocalPolicyAction::Sudoers).rows;
    REQUIRE(su.size() == 20);
    CHECK(su[13] == "sudoers|/etc/sudoers|includedir|-|-|-|/etc/sudoers.d");
    CHECK(su[14] == "sudoers|/etc/sudoers.d/10-ops|alias|User_Alias:OPS|-|-|alice, bob");
    CHECK(su[16] == "sudoers|/etc/sudoers.d/10-ops|defaults|user:OPS|-|-|!requiretty");
    CHECK(su[17] == "sudoers|/etc/sudoers.d/10-ops|user_spec|OPS@ALL|root|true|WEB");
    CHECK(su[18] == "sudoers|/etc/sudoers.d/10-ops|user_spec|OPS@ALL|root|false|/usr/bin/journalctl");
}

TEST_CASE("sudoers.d: names sudo ignores are listed as `ignored`, not read", "[local_security_policy][collector]") {
    auto fs = hardened_fs();
    fs.dirs["/etc/sudoers.d"] = {"10-ops", "10-ops.bak", "old~"}; // the last two are synthetic
    const auto rows = run(fs, LocalPolicyAction::Sudoers).rows;
    CHECK(rows[rows.size() - 2] == "sudoers|/etc/sudoers.d/10-ops.bak|ignored|-|-|-|name_ignored_by_sudo");
    CHECK(rows.back() == "sudoers|/etc/sudoers.d/old~|ignored|-|-|-|name_ignored_by_sudo");
}

// Fails under: absent counted as failure (contract decision), denied folded into absent, status table.
TEST_CASE("failure semantics: absent is a row and no failure; denied/failed never read as absent", "[local_security_policy][collector]") {
    auto fs = default_fs();
    fs.files.erase("/etc/security/pwquality.conf");
    const auto absent = run(fs, LocalPolicyAction::Password);
    CHECK(absent.status == PolicyStatus::Ok);
    CHECK(absent.reason.empty());
    CHECK(absent.rows[4] == "password_policy|source_state|absent|/etc/security/pwquality.conf");

    fs = default_fs();
    fs.denied = {"/etc/sudoers"}; // nothing readable -> PERMISSION_DENIED
    const auto denied = run(fs, LocalPolicyAction::Sudoers);
    CHECK(denied.status == PolicyStatus::PermissionDenied);
    CHECK(denied.reason == "/etc/sudoers:permission_denied");
    CHECK(denied.rows == Rows{"sudoers|/etc/sudoers|unreadable|-|-|-|permission_denied"});

    fs = hardened_fs();
    fs.denied = {"/etc/sudoers.d/10-ops"}; // one refused, another readable -> CONSTRAINED
    const auto mixed = run(fs, LocalPolicyAction::Sudoers);
    CHECK(mixed.status == PolicyStatus::Constrained);
    CHECK(mixed.rows.back() == "sudoers|/etc/sudoers.d/10-ops|unreadable|-|-|-|permission_denied");

    fs = default_fs();
    fs.files["/etc/login.defs"] = "@";
    fs.denied = {"/etc/pam.d/common-password"};
    const auto pw = run(fs, LocalPolicyAction::Password);
    CHECK(pw.status == PolicyStatus::Constrained); // login.defs readable, PAM refused
    CHECK(pw.rows.back() == "password_policy|source_state|unreadable:permission_denied|/etc/pam.d/common-password");

    fs = default_fs();
    fs.files.erase("/etc/pam.d/common-password"); // no PAM stack file exists at all -> one absent row
    CHECK(run(fs, LocalPolicyAction::Password).rows.back() == "password_policy|source_state|absent|/etc/pam.d");
}

TEST_CASE("row cap: a runaway file is capped and reported, never silently truncated", "[local_security_policy][collector]") {
    auto fs = default_fs();
    std::string big;
    for (int i = 0; i < 5000; ++i) big += "Defaults x" + std::to_string(i) + "\n";
    fs.files["/etc/sudoers"] = "@" + big;
    const auto c = run(fs, LocalPolicyAction::Sudoers);
    CHECK(c.rows.size() == kMaxRows);
    CHECK(c.status == PolicyStatus::Constrained);
    CHECK(c.reason == "row_cap");
}

// macOS: the two real defaults on this Mac (audit_control absent, /etc/sudoers root:wheel 0440).
TEST_CASE("macOS file legs: audit_control absent by default, sudoers unreadable for non-root", "[local_security_policy][collector]") {
    FakeFs fs{"default", {}, {{"/etc/sudoers.d", {}}}, {"/etc/sudoers"}};
    const auto au = run(fs, LocalPolicyAction::Audit, FileFlavor::Macos);
    CHECK(au.status == PolicyStatus::Ok);
    CHECK(au.rows == Rows{"audit_policy|source_state|absent|/etc/security/audit_control"});
    const auto su = run(fs, LocalPolicyAction::Sudoers, FileFlavor::Macos);
    CHECK(su.status == PolicyStatus::PermissionDenied);
    CHECK(su.rows == Rows{"sudoers|/etc/sudoers|unreadable|-|-|-|permission_denied"});
}

TEST_CASE("macOS audit_control (ASSUMED SHAPE fixture): colon keys, empty value is `present`", "[local_security_policy][collector]") {
    FakeFs fs{"default", {{"/etc/security/audit_control", "@" + fixture("macos/audit_control_assumed_shape.txt")}}, {}, {}};
    const auto au = run(fs, LocalPolicyAction::Audit, FileFlavor::Macos);
    REQUIRE(au.rows.size() == 8);
    CHECK(au.rows[1] == "audit_policy|flags|lo,aa|/etc/security/audit_control");
    CHECK(au.rows[4] == "audit_policy|policy|cnt,argv|/etc/security/audit_control");
    CHECK(au.rows[7] == "audit_policy|member-set-sflags-mask|present|/etc/security/audit_control");
}

// Wire grammar: a field ending in a backslash or holding '|' must not split the row.
TEST_CASE("row fields go through safe_output_field (trailing backslash, pipe)", "[local_security_policy][rows]") {
    const auto row = format_sudoers_row("/etc/sudoers.d/x", {"user_spec", "a@b", "-", "false", "/bin/echo a|b\\"});
    CHECK(split_escape_aware(row).size() == 7);
    CHECK(row == "sudoers|/etc/sudoers.d/x|user_spec|a@b|-|false|/bin/echo a\\|b/");
    CHECK(format_kv_row("password_policy", "k", "v|w\\", "/p") == "password_policy|k|v\\|w/|/p");
    CHECK(format_kv_row("password_policy", "k", "", "/p") == "password_policy|k|present|/p");
}

// --- macOS pwpolicy -----------------------------------------------------------------

TEST_CASE("pwpolicy: banner is stripped, prefixed and bare forms agree, no XML is nullopt", "[local_security_policy][pwpolicy]") {
    const std::string raw = fixture("macos/pwpolicy_getaccountpolicies.txt");
    REQUIRE(raw.rfind("Getting global account policies\n", 0) == 0); // real capture keeps the banner
    const auto prefixed = strip_to_xml(raw);
    REQUIRE(prefixed.has_value());
    CHECK(prefixed->rfind("<?xml", 0) == 0);
    CHECK(strip_to_xml(*prefixed) == prefixed); // bare form unchanged
    CHECK_FALSE(strip_to_xml("Getting global account policies\n").has_value());
}

TEST_CASE("classify_pwpolicy_run pins each failure token", "[local_security_policy][pwpolicy]") {
    CHECK(classify_pwpolicy_run(true, false, false, 0).empty());
    CHECK(classify_pwpolicy_run(false, false, false, 0) == "pwpolicy:spawn_error");
    CHECK(classify_pwpolicy_run(true, true, false, -1) == "pwpolicy:deadline");
    CHECK(classify_pwpolicy_run(true, false, true, 0) == "pwpolicy:output_truncated");
    CHECK(classify_pwpolicy_run(true, false, false, 3) == "pwpolicy:exit_3");
}

TEST_CASE("pwpolicy_min_length reads only `.{N,}`", "[local_security_policy][pwpolicy]") {
    CHECK(*pwpolicy_min_length("policyAttributePassword matches '.{4,}+'") == 4);
    CHECK(*pwpolicy_min_length("x matches '.{12,}'") == 12);
    CHECK_FALSE(pwpolicy_min_length("x matches '^(?=.*[0-9]).*'").has_value());
    CHECK_FALSE(pwpolicy_min_length("x matches '.{,}'").has_value());
    CHECK_FALSE(pwpolicy_min_length("x matches '.{4}'").has_value());
}

// Real capture shape (hand-built items equal to the fixture's one policy) -- runs on every OS.
TEST_CASE("pwpolicy_rows: real default Mac has one password policy and no lockout policy", "[local_security_policy][pwpolicy]") {
    const std::vector<PwPolicyItem> items{{"policyCategoryPasswordContent", "com.apple.defaultpasswordpolicy.fde",
                                           "policyAttributePassword matches '.{4,}+'", {}}};
    CHECK(pwpolicy_rows(LocalPolicyAction::Password, items) == Rows{
        "password_policy|policy_content|policyAttributePassword matches '.{4,}+'|pwpolicy:com.apple.defaultpasswordpolicy.fde",
        "password_policy|minimum_length|4|pwpolicy:com.apple.defaultpasswordpolicy.fde"});
    CHECK(pwpolicy_rows(LocalPolicyAction::Lockout, items) == Rows{"lockout_policy|policies|none|pwpolicy"});
    CHECK(pwpolicy_rows(LocalPolicyAction::Password, {}) == Rows{"password_policy|policies|none|pwpolicy"});
}

// Fails under: category routing, policyAttribute filter (other keys are named, never valued), unmodelled dropped.
TEST_CASE("pwpolicy_rows: routing, policyAttribute-only values, unmodelled category in both actions", "[local_security_policy][pwpolicy]") {
    const std::vector<PwPolicyItem> items{
        {"policyCategoryAuthentication", "Lockout", "expr", {{"autoEnableInSeconds", "900"}, {"policyAttributeMaximumFailedAuthentications", "5"}}},
        {"policyCategoryPasswordChange", "Change", "", {{"policyAttributeExpiresEveryNDays", "90"}}},
        {"policyCategoryMystery", "", "", {}}};
    CHECK(pwpolicy_rows(LocalPolicyAction::Lockout, items) == Rows{
        "lockout_policy|policy_content|expr|pwpolicy:Lockout",
        "lockout_policy|unmodelled_parameter|autoEnableInSeconds|pwpolicy:Lockout",
        "lockout_policy|policyAttributeMaximumFailedAuthentications|5|pwpolicy:Lockout",
        "lockout_policy|unmodelled_category|policyCategoryMystery|pwpolicy"});
    CHECK(pwpolicy_rows(LocalPolicyAction::Password, items) == Rows{
        "password_policy|policyAttributeExpiresEveryNDays|90|pwpolicy:Change",
        "password_policy|unmodelled_category|policyCategoryMystery|pwpolicy"});
}

// CFPropertyListCreateWithData is the parser; off macOS the bridge is a stub that reports failure.
TEST_CASE("pwpolicy plist bridge: real capture, malformed input and wrong root", "[local_security_policy][pwpolicy]") {
    const std::string raw = fixture("macos/pwpolicy_getaccountpolicies.txt");
    const auto items = pwpolicy_plist_to_items(*strip_to_xml(raw));
    const auto managed = pwpolicy_plist_to_items(fixture("macos/pwpolicy_managed_assumed_shape.plist"));
#if defined(__APPLE__)
    REQUIRE(items.has_value());
    REQUIRE(items->size() == 1);
    CHECK((*items)[0].category == "policyCategoryPasswordContent");
    CHECK((*items)[0].identifier == "com.apple.defaultpasswordpolicy.fde");
    CHECK((*items)[0].content == "policyAttributePassword matches '.{4,}+'");
    CHECK((*items)[0].params.empty());
    REQUIRE(managed.has_value());
    CHECK(pwpolicy_rows(LocalPolicyAction::Lockout, *managed) == Rows{
        "lockout_policy|policy_content|(policyAttributeFailedAuthentications < policyAttributeMaximumFailedAuthentications) OR "
        "(policyAttributeCurrentTime > policyAttributeLastFailedAuthenticationTime + autoEnableInSeconds)|pwpolicy:Authentication Lockout",
        "lockout_policy|unmodelled_parameter|autoEnableInSeconds|pwpolicy:Authentication Lockout",
        "lockout_policy|policyAttributeMaximumFailedAuthentications|5|pwpolicy:Authentication Lockout"});
    CHECK(pwpolicy_rows(LocalPolicyAction::Password, *managed) == Rows{"password_policy|policies|none|pwpolicy"});
#else
    CHECK_FALSE(items.has_value());
    CHECK_FALSE(managed.has_value());
#endif
    CHECK_FALSE(pwpolicy_plist_to_items("<?xml version=\"1.0\"?><plist><dict><key>x</key>").has_value());  // truncated
    CHECK_FALSE(pwpolicy_plist_to_items("<?xml version=\"1.0\"?><plist version=\"1.0\"><array/></plist>").has_value()); // root not a dict
    CHECK_FALSE(pwpolicy_plist_to_items("").has_value());
}
