/**
 * test_local_security_policy_parsers.cpp -- pure tests for the local_security_policy
 * plugin's sudoers lexer, secedit INI decode/mapping, PAM/login.defs/auditd parsers,
 * pwpolicy row mapping and the Windows scratch-sweep decisions. Runs on every OS:
 * nothing here touches the filesystem, the registry or a process.
 *
 * No REAL CAPTURE fixtures here (unlike app_control/autoruns/runtimes): this plugin's
 * inputs are host-specific system files (/etc/sudoers, a live secedit export, a live
 * pwpolicy plist) that vary machine to machine, not a stable binary/text format worth
 * freezing as a committed capture. Every input below is either a small, clearly labelled
 * inline reconstruction of the documented shape (sudoers(5), the INF/secedit export
 * grammar, the pwpolicy plist bridge's PwPolicyItem contract) or a direct call into the
 * injected FileReader/DirLister seam collect_file_policy takes, per this repo's existing
 * fixture-avoidance precedent for host-varying sources.
 */
#include <catch2/catch_test_macros.hpp>

#include "../../agents/plugins/local_security_policy/src/local_security_policy_parsers.hpp"
#include "../../agents/plugins/local_security_policy/src/local_security_policy_scratch_sweep.hpp"

#include <cerrno>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

using namespace yuzu::local_security_policy;

namespace {

FileReader reader_from(std::map<std::string, std::string> files) {
    return [files = std::move(files)](const std::string& path) -> FileRead {
        auto it = files.find(path);
        if (it == files.end()) return {ENOENT, {}};
        return {0, it->second};
    };
}

DirLister empty_dir() {
    return [](const std::string&) -> DirList { return {}; };
}

} // namespace

// ── text helpers ──────────────────────────────────────────────────────────────────

TEST_CASE("local_security_policy text helpers: trim and line splitting",
          "[local_security_policy][parsers]") {
    CHECK(trim_ws(" \t a b \r") == "a b");
    CHECK(trim_ws("") == "");
    CHECK(trim_ws("\t\r") == "");
    CHECK(split_lines("a\nb\n\nc") == std::vector<std::string_view>{"a", "b", "", "c"});
    CHECK(split_lines("").empty());
    CHECK(split_lines("a") == std::vector<std::string_view>{"a"});
}

// ── kv / PAM / auditd (Linux/macOS file sources) ──────────────────────────────────

TEST_CASE("local_security_policy parse_kv_lines: separators, comments, valueless keys",
          "[local_security_policy][parsers]") {
    const auto kv = parse_kv_lines("# comment\nPASS_MAX_DAYS   99999\n\nFLAG\nEMPTY \t\n", " \t");
    REQUIRE(kv.size() == 3);
    CHECK(kv[0] == std::pair<std::string, std::string>{"PASS_MAX_DAYS", "99999"});
    CHECK(kv[1] == std::pair<std::string, std::string>{"FLAG", ""});
    CHECK(kv[2] == std::pair<std::string, std::string>{"EMPTY", ""});
    const auto eq = parse_kv_lines("minlen = 14\ndcredit=-1\n", " \t=");
    CHECK(eq == KvList{{"minlen", "14"}, {"dcredit", "-1"}});
}

TEST_CASE("local_security_policy PAM: logical-line joining and stack parsing",
          "[local_security_policy][parsers]") {
    // A trailing backslash joins the next physical line with one blank; a bare '#'
    // (even mid-continuation) cuts the rest of the physical line and ENDS the logical
    // line -- no further continuation.
    const auto lines = pam_logical_lines("password requisite pam_pwquality.so \\\n"
                                          "    retry=3 # a trailing comment\n"
                                          "password required pam_unix.so\n");
    REQUIRE(lines.size() == 2);
    CHECK(lines[0] == "password requisite pam_pwquality.so retry=3");
    CHECK(lines[1] == "password required pam_unix.so");

    const auto pam = parse_pam_lines(
        "password requisite pam_pwquality.so retry=3\n"
        "password [success=1 default=ignore] pam_unix.so obscure use_authtok\n"
        "@include common-auth\n"
        "malformed line\n" // fewer than 3 tokens: module ends up empty, dropped
        "-account required pam_unix.so\n");
    REQUIRE(pam.size() == 3);
    CHECK(pam[0].type == "password");
    CHECK(pam[0].control == "requisite");
    CHECK(pam[0].module == "pam_pwquality.so");
    CHECK(pam[0].args == "retry=3");
    CHECK(pam[1].control == "[success=1 default=ignore]");
    CHECK(pam[1].module == "pam_unix.so");
    CHECK(pam[1].args == "obscure use_authtok");
    CHECK(pam[2].type == "account"); // leading '-' (silence-on-failure) is dropped
    CHECK(pam[2].module == "pam_unix.so");
}

TEST_CASE("local_security_policy auditd: rule vs control-directive counting",
          "[local_security_policy][parsers]") {
    const auto c = parse_auditd_rules_count(
        "# audit rules\n"
        "-D\n"
        "-b 8192\n"
        "-w /etc/shadow -p wa -k identity\n"
        "-a always,exit -F arch=b64 -S execve\n"
        "-e 1\n"
        "some_unknown_directive foo\n");
    CHECK(c.total == 6);
    CHECK(c.watches == 1);
    CHECK(c.syscalls == 1);
    CHECK(c.control == 3); // -D, -b, -e
    CHECK(c.unmodelled == 1);
    CHECK(c.rules() == 3); // watches + syscalls + unmodelled, never counting -D/-b/-e
    REQUIRE(c.enabled.has_value());
    CHECK(*c.enabled == "1");

    CHECK(audit_enabled_token("0") == "disabled");
    CHECK(audit_enabled_token("1") == "enabled");
    CHECK(audit_enabled_token("2") == "immutable");
    CHECK(audit_enabled_token("9") == "unmodelled:9");

    const auto none = parse_auditd_rules_count("# nothing but comments\n\n");
    CHECK(none.total == 0);
    CHECK_FALSE(none.enabled.has_value());
}

// ── sudoers lexer / grammar ────────────────────────────────────────────────────────

TEST_CASE("local_security_policy sudoers: correctly-spelled aliases are their own kind",
          "[local_security_policy][parsers][sudoers]") {
    for (const auto& [kw, name] :
         {std::pair{std::string{"User_Alias"}, std::string{"ADMINS"}},
          std::pair{std::string{"Host_Alias"}, std::string{"WEBSERVERS"}},
          std::pair{std::string{"Runas_Alias"}, std::string{"OP"}},
          std::pair{std::string{"Cmnd_Alias"}, std::string{"SHELLS"}}}) {
        const auto rows = parse_sudoers(kw + " " + name + " = /bin/sh\n");
        INFO("keyword: " << kw);
        REQUIRE(rows.size() == 1);
        CHECK(rows[0].kind == "alias");
        CHECK(rows[0].subject == kw + ":" + name);
        CHECK(rows[0].commands == "/bin/sh");
    }
}

// Regression for #4997 finding 2: `Cmd_Alias` (sudo-legal alternate spelling of
// `Cmnd_Alias`) was NOT in the alias-keyword set, so this line fell through to
// parse_user_spec and was silently accepted as an ordinary user grant for a
// fictitious principal "Cmd_Alias" on host "SHELLS" -- under a clean OK/FULL result,
// no failure token anywhere.
TEST_CASE("local_security_policy sudoers: Cmd_Alias is recognised, never a fictitious grant",
          "[local_security_policy][parsers][sudoers]") {
    const auto rows = parse_sudoers("Cmd_Alias SHELLS = /bin/sh\n");
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].kind == "alias");
    CHECK(rows[0].subject == "Cmd_Alias:SHELLS");
    CHECK(rows[0].commands == "/bin/sh");
    CHECK_FALSE(rows[0].kind == "user_spec"); // the bug this closes
    CHECK_FALSE(rows[0].subject == "Cmd_Alias@SHELLS");
}

TEST_CASE("local_security_policy sudoers: Defaults, includes, comments",
          "[local_security_policy][parsers][sudoers]") {
    const auto rows = parse_sudoers(
        "Defaults env_reset\n"
        "Defaults:alice !authenticate\n"
        "#include /etc/sudoers.extra\n"
        "@includedir /etc/sudoers.d\n"
        "# a whole-line comment, never a row\n"
        // A trailing `#1000` (a digit follows the '#') is a uid reference, not a
        // comment -- so it is lexed as its own trailing word, which the user_spec
        // grammar has no place for after the command list; the whole line is
        // unmodelled, but with the `#1000` text kept, never swallowed as a comment.
        "alice ALL = /bin/ls #1000\n");
    REQUIRE(rows.size() == 5);
    CHECK(rows[0].kind == "defaults");
    CHECK(rows[0].subject == "-");
    CHECK(rows[0].commands == "env_reset");
    CHECK(rows[1].kind == "defaults");
    CHECK(rows[1].subject == "user:alice");
    CHECK(rows[1].commands == "!authenticate");
    CHECK(rows[2].kind == "include");
    CHECK(rows[2].commands == "/etc/sudoers.extra");
    CHECK(rows[3].kind == "includedir");
    CHECK(rows[3].commands == "/etc/sudoers.d");
    CHECK(rows[4].kind == "unmodelled");
    CHECK(rows[4].commands.find("#1000") != std::string::npos); // kept, not treated as a comment
}

// Regression for #4997 finding 3: command_args's break set wrongly included `=`
// (correct only for command()'s own PATH-name scan just above it), truncating a
// legal `--flag=value` sudoers command argument at the `=`.
TEST_CASE("local_security_policy sudoers: command_args keeps '=' in an argument",
          "[local_security_policy][parsers][sudoers]") {
    const auto rows =
        parse_sudoers("deploy ALL=(root) NOPASSWD: /usr/bin/rsync --rsync-path=x\n");
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].kind == "user_spec");
    CHECK(rows[0].subject == "deploy@ALL");
    CHECK(rows[0].runas == "root");
    CHECK(rows[0].nopasswd == "true");
    CHECK(rows[0].commands == "/usr/bin/rsync --rsync-path=x"); // NOT cut at '='

    // A VAR=value environment-style argument survives the same way.
    const auto env_rows = parse_sudoers("alice ALL = /usr/bin/make VAR=value target\n");
    REQUIRE(env_rows.size() == 1);
    CHECK(env_rows[0].commands == "/usr/bin/make VAR=value target");
}

TEST_CASE("local_security_policy sudoers: NOPASSWD/PASSWD clause splitting, runas carry-over",
          "[local_security_policy][parsers][sudoers]") {
    const auto rows = parse_sudoers("alice ALL = (root) NOPASSWD: /bin/ls, PASSWD: /bin/cat\n");
    REQUIRE(rows.size() == 2);
    CHECK(rows[0].subject == "alice@ALL");
    CHECK(rows[0].runas == "root");
    CHECK(rows[0].nopasswd == "true");
    CHECK(rows[0].commands == "/bin/ls");
    CHECK(rows[1].subject == "alice@ALL");
    CHECK(rows[1].runas == "root"); // carried across the same clause
    CHECK(rows[1].nopasswd == "false");
    CHECK(rows[1].commands == "/bin/cat");

    // Same NOPASSWD state, several commands: one entry, comma-joined.
    const auto same = parse_sudoers("bob ALL = NOPASSWD: /bin/ls, /bin/cat\n");
    REQUIRE(same.size() == 1);
    CHECK(same[0].commands == "/bin/ls, /bin/cat");

    // Two Host_List clauses on one line (colon-separated) are two independent entries.
    const auto multi = parse_sudoers("carol HOST1 = /bin/ls : HOST2 = /bin/cat\n");
    REQUIRE(multi.size() == 2);
    CHECK(multi[0].subject == "carol@HOST1");
    CHECK(multi[1].subject == "carol@HOST2");
}

// Regression for #4997 finding 2 (the fail-safe half): a grammatically malformed
// grant that still carries an undecoded NOPASSWD:/PASSWD: tag is reported `unmodelled`
// with the tag intact in its text -- the caller (sudoers_file) must treat this as a
// failure, never a silent `false`.
TEST_CASE("local_security_policy sudoers: an undecoded NOPASSWD tag is unmodelled, tag intact",
          "[local_security_policy][parsers][sudoers]") {
    // No command follows the tag -- ungrammatical, so parse_user_spec returns nullopt
    // and the NOPASSWD: tag (already lexed into the statement text) survives verbatim.
    const auto rows = parse_sudoers("alice ALL = NOPASSWD:\n");
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].kind == "unmodelled");
    CHECK(rows[0].commands.find("NOPASSWD:") != std::string::npos);
    CHECK(detail::has_passwd_tag(rows[0].commands));
}

TEST_CASE("local_security_policy sudoers: has_passwd_tag word-boundary and spacing",
          "[local_security_policy][parsers][sudoers]") {
    CHECK(detail::has_passwd_tag("NOPASSWD:"));
    CHECK(detail::has_passwd_tag("PASSWD:"));
    CHECK(detail::has_passwd_tag("NOPASSWD  :")); // blanks before the colon still count
    CHECK_FALSE(detail::has_passwd_tag("MYNOPASSWD:")); // part of a longer identifier
    CHECK_FALSE(detail::has_passwd_tag("/bin/ls"));
    CHECK_FALSE(detail::has_passwd_tag(""));
}

TEST_CASE("local_security_policy sudoers: quoted strings, IPv6 hosts, digests, negation",
          "[local_security_policy][parsers][sudoers]") {
    const auto rows = parse_sudoers(
        R"(alice ::1 = CWD="/tmp:x" sha256:abcd1234 !!/bin/ls)"
        "\n");
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].subject == "alice@::1"); // an IPv6 host, colon kept intact
    CHECK(rows[0].commands.find(R"(CWD="/tmp:x")") != std::string::npos); // quoted value untouched
    CHECK(rows[0].commands.find("sha256:abcd1234") != std::string::npos);
    CHECK(rows[0].commands.find("/bin/ls") != std::string::npos); // even '!' count cancels out
}

TEST_CASE("local_security_policy sudoers.d: name filtering", "[local_security_policy][parsers][sudoers]") {
    CHECK_FALSE(sudoers_dir_entry_ignored("readable"));
    CHECK(sudoers_dir_entry_ignored("webadmins.rpmnew"));
    CHECK(sudoers_dir_entry_ignored("backup~"));
    CHECK_FALSE(sudoers_dir_entry_ignored(""));
}

// ── errno classification / status selection ───────────────────────────────────────

TEST_CASE("local_security_policy errno classification: absent vs denied vs failed",
          "[local_security_policy][parsers]") {
    for (const int e : {ENOENT, ENOTDIR}) {
        const auto o = classify_read_errno(e);
        CHECK(o.cls == ReadClass::Absent);
        CHECK(o.token.empty());
    }
    for (const int e : {EACCES, EPERM}) {
        const auto o = classify_read_errno(e);
        CHECK(o.cls == ReadClass::Denied);
        CHECK(o.token == "permission_denied");
    }
    CHECK(classify_read_errno(ELOOP).token == "symlink_loop");
    CHECK(classify_read_errno(EIO).token == "io_error");
    CHECK(classify_read_errno(kReadOversized).token == "oversized");
    CHECK(classify_read_errno(kReadNotRegular).token == "not_regular");
    CHECK(classify_read_errno(kReadEmbeddedNul).token == "embedded_nul");
    const auto other = classify_read_errno(9999);
    CHECK(other.cls == ReadClass::Failed);
    CHECK(other.token == "errno_9999");
}

TEST_CASE("local_security_policy select_status: PERMISSION_DENIED only when nothing else failed",
          "[local_security_policy][parsers]") {
    CHECK(select_status(3, 0, 0) == PolicyStatus::Ok);
    CHECK(select_status(0, 2, 0) == PolicyStatus::PermissionDenied);
    CHECK(select_status(0, 0, 1) == PolicyStatus::Constrained);
    CHECK(select_status(1, 1, 0) == PolicyStatus::Constrained); // some readable, some denied
    CHECK(select_status(1, 1, 1) == PolicyStatus::Constrained);
    CHECK(select_status(0, 0, 0) == PolicyStatus::Ok);
}

// ── row formatters ─────────────────────────────────────────────────────────────────

TEST_CASE("local_security_policy row formatters: escaping and shape",
          "[local_security_policy][parsers]") {
    CHECK(format_kv_row("password_policy", "PASS_MAX_DAYS", "99999", "/etc/login.defs") ==
          "password_policy|PASS_MAX_DAYS|99999|/etc/login.defs");
    CHECK(format_kv_row("password_policy", "FLAG", "", "/etc/login.defs") ==
          "password_policy|FLAG|present|/etc/login.defs"); // empty value -> "present"
    CHECK(format_kv_row("audit_policy", "a|b", "c\r\nd", "/etc/x") ==
          "audit_policy|a\\|b|c  d|/etc/x"); // pipe escaped, newline folded to spaces

    const SudoersEntry e{"user_spec", "alice@ALL", "root", "true", "/bin/ls"};
    CHECK(format_sudoers_row("/etc/sudoers", e) == "sudoers|/etc/sudoers|user_spec|alice@ALL|root|true|/bin/ls");
}

// ── collect_file_policy (injected FileReader/DirLister) ───────────────────────────

TEST_CASE("local_security_policy collect_file_policy: password_policy over injected files",
          "[local_security_policy][parsers]") {
    auto rd = reader_from({{"/etc/login.defs", "PASS_MAX_DAYS 99999\nPASS_MIN_DAYS 0\n"}});
    // pwquality.conf and every PAM alternative are absent (ENOENT via reader_from's default).
    const auto c = collect_file_policy(FileFlavor::Linux, LocalPolicyAction::Password, rd, empty_dir());
    CHECK(c.status == PolicyStatus::Ok); // absence is not a failure
    bool saw_max_days = false, saw_pam_absent = false;
    for (const auto& r : c.rows) {
        if (r == "password_policy|PASS_MAX_DAYS|99999|/etc/login.defs") saw_max_days = true;
        if (r == "password_policy|source_state|absent|/etc/pam.d") saw_pam_absent = true;
    }
    CHECK(saw_max_days);
    CHECK(saw_pam_absent); // every PAM alternative absent collapses to one absent row
}

TEST_CASE("local_security_policy collect_file_policy: sudoers end to end, undecoded tag is CONSTRAINED",
          "[local_security_policy][parsers]") {
    auto rd = reader_from({{"/etc/sudoers", "alice ALL = NOPASSWD:\n"}});
    const auto c = collect_file_policy(FileFlavor::Linux, LocalPolicyAction::Sudoers, rd, empty_dir());
    CHECK(c.status == PolicyStatus::Constrained);
    CHECK(c.reason.find("/etc/sudoers:undecoded_passwd_tag") != std::string::npos);
    bool saw_unmodelled = false;
    for (const auto& r : c.rows)
        if (r.rfind("sudoers|/etc/sudoers|unmodelled|", 0) == 0) saw_unmodelled = true;
    CHECK(saw_unmodelled);
}

TEST_CASE("local_security_policy collect_file_policy: sudoers.d name filtering and per-file reads",
          "[local_security_policy][parsers]") {
    auto rd = reader_from({{"/etc/sudoers", "alice ALL = /bin/ls\n"},
                           {"/etc/sudoers.d/readable", "bob ALL = /bin/cat\n"}});
    const auto dl = [](const std::string& path) -> DirList {
        if (path == "/etc/sudoers.d")
            return {0, {"backup~", "readable", "webadmins.rpmnew"}, false};
        return {};
    };
    const auto c = collect_file_policy(FileFlavor::Linux, LocalPolicyAction::Sudoers, rd, dl);
    CHECK(c.status == PolicyStatus::Ok);
    int ignored = 0, real = 0;
    for (const auto& r : c.rows) {
        if (r.find("|ignored|") != std::string::npos) ++ignored;
        if (r.rfind("sudoers|/etc/sudoers.d/readable|user_spec|", 0) == 0) ++real;
    }
    CHECK(ignored == 2); // backup~ (trailing '~') and webadmins.rpmnew (a '.')
    CHECK(real == 1);
}

TEST_CASE("local_security_policy collect_file_policy: a refused read is PERMISSION_DENIED, never absent",
          "[local_security_policy][parsers]") {
    auto rd = [](const std::string& path) -> FileRead {
        if (path == "/etc/login.defs") return {EACCES, {}};
        return {ENOENT, {}}; // everything else genuinely absent
    };
    const auto c = collect_file_policy(FileFlavor::Linux, LocalPolicyAction::Password, rd, empty_dir());
    CHECK(c.status == PolicyStatus::PermissionDenied);
    bool saw_denied = false;
    for (const auto& r : c.rows)
        if (r == "password_policy|source_state|unreadable:permission_denied|/etc/login.defs")
            saw_denied = true;
    CHECK(saw_denied);
}

TEST_CASE("local_security_policy collect_file_policy: macOS never reads Linux password/lockout paths",
          "[local_security_policy][parsers]") {
    // FAIL CLOSED: this arm is unreachable via the real macOS leg (it routes to pwpolicy
    // first), but collect_file_policy itself must still refuse rather than silently read
    // /etc/login.defs on a Mac.
    bool called = false;
    auto rd = [&](const std::string&) -> FileRead {
        called = true;
        return {ENOENT, {}};
    };
    const auto c = collect_file_policy(FileFlavor::Macos, LocalPolicyAction::Password, rd, empty_dir());
    CHECK(c.status == PolicyStatus::Constrained);
    CHECK(c.reason == "unsupported_action");
    CHECK(c.rows.empty());
    CHECK_FALSE(called);
}

TEST_CASE("local_security_policy Tally: the row cap reserves its own slot for the truncation marker",
          "[local_security_policy][parsers]") {
    detail::Tally t;
    t.marker_prefix = "password_policy";
    t.marker_fields = 4;
    for (std::size_t i = 0; i < kMaxRows; ++i) t.row("password_policy|k" + std::to_string(i) + "|v|src");
    REQUIRE(t.rows.size() == kMaxRows); // never exceeds the cap, even by one
    CHECK(t.rows.back() == "password_policy|source_state|unreadable:row_cap|password_policy");
    CHECK(t.capped);
    CHECK(t.acc.reason() == "row_cap");
    // A further row is dropped outright, not appended past the cap.
    t.row("password_policy|extra|v|src");
    CHECK(t.rows.size() == kMaxRows);

    detail::Tally sudo_t;
    sudo_t.marker_prefix = "sudoers";
    sudo_t.marker_fields = 7;
    for (std::size_t i = 0; i < kMaxRows; ++i) sudo_t.row("sudoers|f|user_spec|s|-|false|c");
    CHECK(sudo_t.rows.back() == "sudoers|-|unreadable|-|-|-|row_cap"); // 7-field shape preserved
}

// ── secedit (Windows) ─────────────────────────────────────────────────────────────

TEST_CASE("local_security_policy secedit: decode_utf16le_bom", "[local_security_policy][parsers][secedit]") {
    // "AB" as UTF-16LE with the mandatory BOM.
    const std::vector<std::uint8_t> good{0xFF, 0xFE, 'A', 0x00, 'B', 0x00};
    const auto decoded = decode_utf16le_bom(good);
    REQUIRE(decoded.has_value());
    CHECK(*decoded == "AB");
    const std::vector<std::uint8_t> no_bom{'A', 0x00};
    CHECK_FALSE(decode_utf16le_bom(no_bom).has_value());
    const std::vector<std::uint8_t> odd_len{0xFF, 0xFE, 'A'};
    CHECK_FALSE(decode_utf16le_bom(odd_len).has_value());
    const std::vector<std::uint8_t> unpaired_low{0xFF, 0xFE, 0x00, 0xDC}; // a lone low surrogate
    CHECK_FALSE(decode_utf16le_bom(unpaired_low).has_value());
    const std::vector<std::uint8_t> unpaired_high{0xFF, 0xFE, 0x00, 0xD8}; // a lone high surrogate, no partner
    CHECK_FALSE(decode_utf16le_bom(unpaired_high).has_value());
}

TEST_CASE("local_security_policy secedit: audit setting bitmask", "[local_security_policy][parsers][secedit]") {
    CHECK(secedit_audit_setting("0") == "none");
    CHECK(secedit_audit_setting("1") == "success");
    CHECK(secedit_audit_setting("2") == "failure");
    CHECK(secedit_audit_setting("3") == "success_failure");
    CHECK(secedit_audit_setting("9") == "unmodelled:9");
}

TEST_CASE("local_security_policy secedit: export completeness requires the signed final [Version]",
          "[local_security_policy][parsers][secedit]") {
    const std::string full =
        "[System Access]\nMinimumPasswordLength = 8\n"
        "[Event Audit]\nAuditSystemEvents = 3\n"
        "[Version]\nsignature=\"$CHICAGO$\"\nRevision=1\n";
    CHECK(secedit_export_complete(full));
    // Case-insensitive section/key names -- the INF rule.
    const std::string lower =
        "[system access]\nminimumpasswordlength = 8\n"
        "[event audit]\n"
        "[version]\nSIGNATURE=\"$CHICAGO$\"\n";
    CHECK(secedit_export_complete(lower));
    CHECK_FALSE(secedit_export_complete("[System Access]\n[Version]\nsignature=\"$CHICAGO$\"\n")); // no Event Audit
    CHECK_FALSE(secedit_export_complete(full + "[Extra]\nx=1\n")); // Version not the FINAL section
    CHECK_FALSE(secedit_export_complete("[System Access]\n[Event Audit]\n[Version]\n")); // unsigned
    CHECK_FALSE(secedit_export_complete(""));
}

TEST_CASE("local_security_policy secedit_policy_rows: audit, password, lockout, unsupported",
          "[local_security_policy][parsers][secedit]") {
    const auto sections = parse_inf_sections(
        "[System Access]\nMinimumPasswordLength = 14\nLockoutBadCount = 0\n"
        "[Event Audit]\nAuditSystemEvents = 3\nAuditLogonEvents = 1\n");
    const auto pw = secedit_policy_rows("password_policy", sections);
    CHECK(pw.failure_token.empty());
    bool saw_len = false, saw_absent_history = false;
    for (const auto& r : pw.rows) {
        if (r == "password_policy|MinimumPasswordLength|14|secedit") saw_len = true;
        if (r == "password_policy|PasswordHistorySize|absent|secedit") saw_absent_history = true;
    }
    CHECK(saw_len);
    CHECK(saw_absent_history); // a key the export doesn't carry reads the modal "absent"

    const auto lock = secedit_policy_rows("lockout_policy", sections);
    bool saw_zero = false;
    for (const auto& r : lock.rows)
        if (r == "lockout_policy|LockoutBadCount|0|secedit") saw_zero = true;
    CHECK(saw_zero);

    const auto audit = secedit_policy_rows("audit_policy", sections);
    CHECK(audit.rows == std::vector<std::string>{"audit_policy|AuditLogonEvents|success|secedit",
                                                  "audit_policy|AuditSystemEvents|success_failure|secedit"});

    const auto unsup = secedit_policy_rows("sudoers", sections);
    CHECK(unsup.failure_token == "secedit:unsupported_action");
    CHECK(unsup.rows.empty());

    const auto missing = secedit_policy_rows("audit_policy", InfSections{});
    CHECK(missing.failure_token == "secedit:section_missing_event_audit");
}

// Regression for #4997 finding 4: the per-key row lookup used a plain
// std::map<std::string,...> ordered/looked-up by exact bytes, so a present but
// differently-cased section or key silently read as the modal "absent" under a
// clean OK/FULL result.
TEST_CASE("local_security_policy secedit: case-insensitive section/key lookup",
          "[local_security_policy][parsers][secedit]") {
    const auto sections = parse_inf_sections("[system access]\nminimumpasswordlength = 14\n");
    const auto pw = secedit_policy_rows("password_policy", sections);
    CHECK(pw.failure_token.empty());
    bool saw_len = false;
    for (const auto& r : pw.rows) {
        CHECK(r != "password_policy|MinimumPasswordLength|absent|secedit"); // the bug this closes
        if (r == "password_policy|MinimumPasswordLength|14|secedit") saw_len = true;
    }
    CHECK(saw_len);
}

TEST_CASE("local_security_policy parse_inf_sections: comments, pre-section lines, repeated key",
          "[local_security_policy][parsers][secedit]") {
    const auto s = parse_inf_sections(
        "; a leading comment, no section yet\n"
        "orphan = ignored\n"
        "[System Access]\n"
        "; a section comment\n"
        "MinimumPasswordLength = 8\n"
        "minimumpasswordlength = 14\n"); // a later, differently-cased repeat wins
    REQUIRE(s.contains("System Access"));
    REQUIRE(s.at("System Access").contains("MinimumPasswordLength"));
    CHECK(s.at("System Access").at("MinimumPasswordLength") == "14");
    CHECK_FALSE(s.contains("orphan")); // a line before any section is dropped, not a phantom section
}

// ── pwpolicy (macOS) ───────────────────────────────────────────────────────────────

TEST_CASE("local_security_policy pwpolicy: strip_to_xml drops the banner line",
          "[local_security_policy][parsers][pwpolicy]") {
    const auto stripped = strip_to_xml("Getting global account policies\n<?xml version=\"1.0\"?><plist/>");
    REQUIRE(stripped.has_value());
    CHECK(stripped->starts_with("<?xml"));
    CHECK_FALSE(strip_to_xml("no xml banner here").has_value());
}

TEST_CASE("local_security_policy pwpolicy: run classification", "[local_security_policy][parsers][pwpolicy]") {
    CHECK(classify_pwpolicy_run(RunEnd::SpawnError, false, 0) == "pwpolicy:spawn_error");
    CHECK(classify_pwpolicy_run(RunEnd::Deadline, false, 0) == "pwpolicy:deadline");
    CHECK(classify_pwpolicy_run(RunEnd::Cancelled, false, 0) == "pwpolicy:cancelled");
    CHECK(classify_pwpolicy_run(RunEnd::Signaled, false, 0) == "pwpolicy:signaled");
    CHECK(classify_pwpolicy_run(RunEnd::Other, false, 0) == "pwpolicy:unexpected_termination");
    CHECK(classify_pwpolicy_run(RunEnd::Exited, true, 0) == "pwpolicy:output_truncated");
    CHECK(classify_pwpolicy_run(RunEnd::Exited, false, 1) == "pwpolicy:exit_1");
    CHECK(classify_pwpolicy_run(RunEnd::Exited, false, 0).empty());
}

TEST_CASE("local_security_policy pwpolicy: minimum-length extraction is exact, never guessed",
          "[local_security_policy][parsers][pwpolicy]") {
    CHECK(pwpolicy_min_length("policyAttributePassword matches '.{14,}'") == std::optional<unsigned>{14});
    CHECK(pwpolicy_min_length("policyAttributePassword matches '.{0,}'") == std::optional<unsigned>{0});
    CHECK_FALSE(pwpolicy_min_length("no length expression here").has_value());
    CHECK_FALSE(pwpolicy_min_length(".{,}").has_value());       // no digits
    CHECK_FALSE(pwpolicy_min_length(".{14}").has_value());      // missing the comma
}

TEST_CASE("local_security_policy pwpolicy_rows: category routing, defects, and the clean-none row",
          "[local_security_policy][parsers][pwpolicy]") {
    const PwPolicyItem lock{"policyCategoryAuthentication", "loginRateLimit",
                            "policyAttributeFailedAuthentications < 5", {}, {}};
    const PwPolicyItem pw{"policyCategoryPasswordContent", "requireAlpha",
                          "policyAttributePassword matches '.{14,}'",
                          {{"policyAttributePassword", "x"}, {"autoEnableInSeconds", "300"}}, {}};
    const PwPolicyItem unmodelled_cat{"policyCategorySomethingElse", "", "", {}, {}};
    const PwPolicyItem defective{"policyCategoryPasswordContent", "broken", "", {}, {"malformed_content"}};

    const auto lockout = pwpolicy_rows(LocalPolicyAction::Lockout, {lock, pw, unmodelled_cat});
    bool saw_content = false, saw_unmodelled = false;
    for (const auto& r : lockout.rows) {
        if (r.find("policy_content|policyAttributeFailedAuthentications < 5") != std::string::npos)
            saw_content = true;
        if (r.rfind("lockout_policy|unmodelled_category|policyCategorySomethingElse|", 0) == 0)
            saw_unmodelled = true;
        CHECK(r.find("requireAlpha") == std::string::npos); // the password item never leaks into lockout
    }
    CHECK(saw_content);
    CHECK(saw_unmodelled);
    CHECK(lockout.status == PolicyStatus::Ok);

    const auto password = pwpolicy_rows(LocalPolicyAction::Password, {pw});
    bool saw_attr = false, saw_min_len = false, saw_unmodelled_param = false;
    for (const auto& r : password.rows) {
        if (r.find("policyAttributePassword|x|") != std::string::npos) saw_attr = true;
        if (r.find("minimum_length|14|") != std::string::npos) saw_min_len = true;
        if (r.find("unmodelled_parameter|autoEnableInSeconds=300|") != std::string::npos)
            saw_unmodelled_param = true;
    }
    CHECK(saw_attr);
    CHECK(saw_min_len);
    CHECK(saw_unmodelled_param);

    const auto with_defect = pwpolicy_rows(LocalPolicyAction::Password, {defective});
    CHECK(with_defect.status == PolicyStatus::Constrained);
    CHECK(with_defect.reason.find("pwpolicy:malformed_content") != std::string::npos);
    bool saw_defect_row = false;
    for (const auto& r : with_defect.rows)
        if (r.find("unreadable:malformed_content") != std::string::npos) saw_defect_row = true;
    CHECK(saw_defect_row);

    // An item carrying nothing this action can report is its own shape defect.
    const PwPolicyItem empty_item{"policyCategoryPasswordContent", "id", "", {}, {}};
    const auto empty_result = pwpolicy_rows(LocalPolicyAction::Password, {empty_item});
    CHECK(empty_result.status == PolicyStatus::Constrained);
    bool saw_missing_content = false;
    for (const auto& r : empty_result.rows)
        if (r.find("unreadable:missing_content") != std::string::npos) saw_missing_content = true;
    CHECK(saw_missing_content);

    // No matching item and no defect: the clean modal "none" row, never an empty vector.
    const auto none = pwpolicy_rows(LocalPolicyAction::Lockout, {});
    CHECK(none.rows == std::vector<std::string>{"lockout_policy|policies|none|pwpolicy"});
    CHECK(none.status == PolicyStatus::Ok);
}

// ── Windows scratch-sweep decisions ────────────────────────────────────────────────

TEST_CASE("local_security_policy sweep: scratch directory name validation",
          "[local_security_policy][parsers][sweep]") {
    CHECK(is_scratch_dir_name("local_security_policy-0123456789abcdef0123456789ABCDEF"));
    CHECK_FALSE(is_scratch_dir_name("local_security_policy-tooshort"));
    CHECK_FALSE(is_scratch_dir_name("local_security_policy-0123456789abcdef0123456789abcdeg")); // 'g' not hex
    CHECK_FALSE(is_scratch_dir_name("other_plugin-0123456789abcdef0123456789abcdef"));
    CHECK_FALSE(is_scratch_dir_name("local_security_policy-"));
    CHECK_FALSE(is_scratch_dir_name(""));
}

TEST_CASE("local_security_policy sweep: staleness is strict, exact equality is fresh",
          "[local_security_policy][parsers][sweep]") {
    CHECK_FALSE(is_stale(1000, 1000 + 3600, 3600));       // exactly the threshold: fresh
    CHECK(is_stale(1000, 1000 + 3601, 3600));             // one second past: stale
    CHECK_FALSE(is_stale(1000, 500, 3600));               // a future-dated mtime (clock skew): fresh
}

TEST_CASE("local_security_policy sweep: candidate classification covers all four states",
          "[local_security_policy][parsers][sweep]") {
    const std::string name = "local_security_policy-0123456789abcdef0123456789abcdef";
    CHECK(classify_sweep_candidate("not_a_match", true, 0, 4000, 3600) == SweepCandidate::NotCandidate);
    CHECK(classify_sweep_candidate(name, false, 0, 4000, 3600) == SweepCandidate::NotCandidate); // not a directory
    CHECK(classify_sweep_candidate(name, true, std::nullopt, 4000, 3600) == SweepCandidate::NoMtime);
    CHECK(classify_sweep_candidate(name, true, 3999, 4000, 3600) == SweepCandidate::Fresh);
    CHECK(classify_sweep_candidate(name, true, 0, 3601, 3600) == SweepCandidate::Stale);
}

TEST_CASE("local_security_policy sweep: ownership gate and log-worthiness",
          "[local_security_policy][parsers][sweep]") {
    CHECK(sweep_may_remove(true));
    CHECK_FALSE(sweep_may_remove(false));

    CHECK_FALSE(sweep_worth_logging({})); // an all-zero steady-state pass says nothing
    ScratchSweepResult removed_one;
    removed_one.removed = 1;
    CHECK(sweep_worth_logging(removed_one));
    ScratchSweepResult failed_one;
    failed_one.failed = 1;
    CHECK(sweep_worth_logging(failed_one));
    ScratchSweepResult foreign;
    foreign.skipped_not_ours = 1;
    CHECK(sweep_worth_logging(foreign));
    ScratchSweepResult deferred;
    deferred.deferred = 1;
    CHECK(sweep_worth_logging(deferred));
    ScratchSweepResult fresh_only;
    fresh_only.skipped_fresh = 3; // fresh candidates alone are not worth a log line
    CHECK_FALSE(sweep_worth_logging(fresh_only));

    ScratchSweepResult r;
    r.removed = 2;
    r.failed = 1;
    r.skipped_fresh = 3;
    r.skipped_not_ours = 1;
    r.deferred = 1;
    CHECK(format_sweep_summary(r) ==
          "scratch_sweep: removed 2 failed 1 fresh 3 not_ours 1 deferred 1");
}

TEST_CASE("local_security_policy sweep: secedit run/read classification",
          "[local_security_policy][parsers][sweep]") {
    CHECK(classify_export_run(RunEnd::SpawnError, 0) == "secedit:spawn_error");
    CHECK(classify_export_run(RunEnd::Deadline, 0) == "secedit:deadline");
    CHECK(classify_export_run(RunEnd::Cancelled, 0) == "secedit:cancelled");
    CHECK(classify_export_run(RunEnd::Signaled, 0) == "secedit:signaled");
    CHECK(classify_export_run(RunEnd::Other, 0) == "secedit:unexpected_termination");
    CHECK(classify_export_run(RunEnd::Exited, 0).empty());
    CHECK(classify_export_run(RunEnd::Exited, 1) == "secedit:exit_1");

    const auto denied = classify_export_read_error(kWin32AccessDenied);
    CHECK(denied.permission_denied);
    CHECK(denied.token == "secedit:access_denied");
    for (const auto err : {kWin32FileNotFound, kWin32PathNotFound}) {
        const auto missing = classify_export_read_error(err);
        CHECK_FALSE(missing.permission_denied);
        CHECK(missing.token == "secedit:output_missing");
    }
    const auto other = classify_export_read_error(1234);
    CHECK_FALSE(other.permission_denied);
    CHECK(other.token == "secedit:read_1234");

    CHECK_FALSE(classify_export_object(false, 100).has_value()); // usable
    REQUIRE(classify_export_object(true, 100).has_value());
    CHECK(classify_export_object(true, 100)->token == "secedit:output_not_regular");
    REQUIRE(classify_export_object(false, kExportMaxBytes + 1).has_value());
    CHECK(classify_export_object(false, kExportMaxBytes + 1)->token == "secedit:output_oversized");

    CHECK(classify_export_read_length(100, 100).empty());
    CHECK(classify_export_read_length(100, 50) == "secedit:output_short_read");

    CHECK(classify_decoded_export(std::nullopt) == "secedit:decode_failed");
    CHECK(classify_decoded_export(std::optional<std::string>{""}) == "secedit:decode_failed");
    CHECK(classify_decoded_export(std::optional<std::string>{std::string("a\0b", 3)}) ==
          "secedit:embedded_nul");
    CHECK(classify_decoded_export(std::optional<std::string>{"clean text"}).empty());
}
