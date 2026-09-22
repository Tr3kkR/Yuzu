/**
 * local_security_policy_parsers.hpp -- pure core of the plugin: no OS call, process
 * or clock. Every decision (errno class, status, row shape, sudoers kind) is a
 * function here; the leg TUs only read bytes and hand them in.
 *
 * Rows (fields through safe_output_field):
 *   password_policy|<key>|<value>|<source>   lockout_policy|...   audit_policy|<category>|<setting>|<source>
 *   sudoers|<file>|<kind>|<subject>|<runas>|<nopasswd>|<commands>
 *     kind: defaults | alias | include | includedir | user_spec | unmodelled | ignored | absent | unreadable
 * A definitively missing source is the row state `absent` (key `source_state`) and no
 * failure token; an unreadable one is `unreadable:<token>` -- failure never reads as absent.
 */
#pragma once

#include <yuzu/string_utils.hpp>

#include <constraint_accumulator.hpp>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <functional>
#include <initializer_list>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::local_security_policy {

// ---- text helpers -----------------------------------------------------------

inline std::string_view trim_ws(std::string_view s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\r'))
        s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r'))
        s.remove_suffix(1);
    return s;
}

inline std::vector<std::string_view> split_lines(std::string_view text) {
    std::vector<std::string_view> out;
    while (!text.empty()) {
        const auto nl = text.find('\n');
        out.push_back(text.substr(0, nl));
        text = nl == std::string_view::npos ? std::string_view{} : text.substr(nl + 1);
    }
    return out;
}

/// Lines with trailing-backslash continuations joined (single space), each trimmed.
inline std::vector<std::string> logical_lines(std::string_view text) {
    std::vector<std::string> out;
    std::string cur;
    for (auto raw : split_lines(text)) {
        raw = trim_ws(raw);
        const bool cont = !raw.empty() && raw.back() == '\\';
        if (cont) raw.remove_suffix(1);
        if (!cur.empty()) cur += ' ';
        cur.append(raw);
        if (!cont) {
            out.push_back(std::move(cur));
            cur.clear();
        }
    }
    if (!cur.empty()) out.push_back(std::move(cur));
    return out;
}

// ---- secedit export (UTF-16LE INI) -------------------------------------------

/// UTF-16LE with a mandatory FF FE BOM -> UTF-8. nullopt (never an empty
/// success) for a BOM-less, odd-length or unpaired-surrogate buffer.
inline std::optional<std::string> decode_utf16le_bom(std::span<const std::uint8_t> b) {
    if (b.size() < 2 || (b.size() % 2) != 0 || b[0] != 0xFF || b[1] != 0xFE) return std::nullopt;
    std::string out;
    const auto unit = [&](std::size_t i) -> std::uint32_t {
        return static_cast<std::uint32_t>(b[i]) | (static_cast<std::uint32_t>(b[i + 1]) << 8);
    };
    for (std::size_t i = 2; i < b.size(); i += 2) {
        std::uint32_t cp = unit(i);
        if (cp >= 0xDC00 && cp <= 0xDFFF) return std::nullopt;
        if (cp >= 0xD800 && cp <= 0xDBFF) {
            if (i + 3 >= b.size()) return std::nullopt;
            const std::uint32_t lo = unit(i + 2);
            if (lo < 0xDC00 || lo > 0xDFFF) return std::nullopt;
            cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
            i += 2;
        }
        if (cp < 0x80) {
            out += static_cast<char>(cp);
        } else if (cp < 0x800) {
            out += static_cast<char>(0xC0 | (cp >> 6));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        } else if (cp < 0x10000) {
            out += static_cast<char>(0xE0 | (cp >> 12));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        } else {
            out += static_cast<char>(0xF0 | (cp >> 18));
            out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        }
    }
    return out;
}

/// `[Section]` / `key = value` INI (secedit .inf). `;` comments and lines
/// before the first section are ignored; a repeated key keeps the last value.
using InfSections = std::map<std::string, std::map<std::string, std::string>>;

inline InfSections parse_inf_sections(std::string_view text) {
    InfSections out;
    std::map<std::string, std::string>* cur = nullptr;
    for (auto raw : split_lines(text)) {
        const auto line = trim_ws(raw);
        if (line.empty() || line.front() == ';') continue;
        if (line.front() == '[' && line.back() == ']') {
            cur = &out[std::string{trim_ws(line.substr(1, line.size() - 2))}];
            continue;
        }
        const auto eq = line.find('=');
        if (cur == nullptr || eq == std::string_view::npos) continue;
        (*cur)[std::string{trim_ws(line.substr(0, eq))}] = std::string{trim_ws(line.substr(eq + 1))};
    }
    return out;
}

// ---- key/value config files (login.defs, pwquality.conf, faillock.conf, audit_control) --

using KvList = std::vector<std::pair<std::string, std::string>>;

/// `key<sep>value` lines; `seps` is the set of separator characters (login.defs
/// " \t", pwquality/faillock " \t=", audit_control ":"). `#` lines are comments.
/// A key with no value is kept with an empty value.
inline KvList parse_kv_lines(std::string_view text, std::string_view seps) {
    KvList out;
    for (auto raw : split_lines(text)) {
        const auto line = trim_ws(raw);
        if (line.empty() || line.front() == '#') continue;
        const auto k_end = line.find_first_of(seps);
        if (k_end == std::string_view::npos) {
            out.emplace_back(std::string{line}, std::string{});
            continue;
        }
        auto rest = line.substr(k_end);
        while (!rest.empty() && (seps.find(rest.front()) != std::string_view::npos ||
                                 rest.front() == ' ' || rest.front() == '\t'))
            rest.remove_prefix(1);
        out.emplace_back(std::string{line.substr(0, k_end)}, std::string{trim_ws(rest)});
    }
    return out;
}

inline constexpr std::string_view kLoginDefsPasswordKeys[] = {
    "PASS_MAX_DAYS", "PASS_MIN_DAYS", "PASS_MIN_LEN", "PASS_WARN_AGE", "ENCRYPT_METHOD",
    "SHA_CRYPT_MIN_ROUNDS", "SHA_CRYPT_MAX_ROUNDS"};
inline constexpr std::string_view kLoginDefsLockoutKeys[] = {"LOGIN_RETRIES", "LOGIN_TIMEOUT",
                                                             "FAILLOG_ENAB", "FAIL_DELAY"};

// ---- PAM stacks -----------------------------------------------------------------

struct PamLine {
    std::string type;   // auth | account | password | session (a leading '-' dropped)
    std::string control; // required | [success=1 default=ignore] | ...
    std::string module;  // pam_unix.so
    std::string args;    // remaining text, verbatim
};

/// Skips comments, blanks and `@include`. A line that is not `type control module`
/// is dropped (PAM itself would reject it) -- pam.d holds no other policy.
inline std::vector<PamLine> parse_pam_lines(std::string_view text) {
    std::vector<PamLine> out;
    for (const auto& line : logical_lines(text)) {
        std::string_view s = line;
        if (s.empty() || s.front() == '#' || s.front() == '@') continue;
        const auto word = [&s]() {
            s = trim_ws(s);
            const auto e = s.find_first_of(" \t");
            const auto w = s.substr(0, e);
            s = e == std::string_view::npos ? std::string_view{} : s.substr(e);
            return w;
        };
        PamLine p;
        auto t = word();
        if (!t.empty() && t.front() == '-') t.remove_prefix(1);
        p.type = std::string{t};
        s = trim_ws(s);
        if (!s.empty() && s.front() == '[') {
            const auto close = s.find(']');
            if (close == std::string_view::npos) continue;
            p.control = std::string{s.substr(0, close + 1)};
            s.remove_prefix(close + 1);
        } else {
            p.control = std::string{word()};
        }
        p.module = std::string{word()};
        p.args = std::string{trim_ws(s)};
        if (p.type.empty() || p.control.empty() || p.module.empty()) continue;
        out.push_back(std::move(p));
    }
    return out;
}

inline constexpr std::string_view kPamPasswordModules[] = {"pam_pwquality.so", "pam_pwhistory.so",
                                                            "pam_cracklib.so", "pam_unix.so"};
inline constexpr std::string_view kPamLockoutModules[] = {"pam_faillock.so", "pam_tally2.so",
                                                           "pam_tally.so"};

// ---- auditd rules -----------------------------------------------------------------

struct AuditRuleCounts {
    std::size_t total = 0;    // every non-comment, non-blank line
    std::size_t watches = 0;  // -w
    std::size_t syscalls = 0; // -a / -A
    std::size_t unmodelled = 0;
    std::optional<std::string> enabled; // -e value, last one wins
};

inline AuditRuleCounts parse_auditd_rules_count(std::string_view text) {
    AuditRuleCounts c;
    for (auto raw : split_lines(text)) {
        const auto line = trim_ws(raw);
        if (line.empty() || line.front() == '#') continue;
        ++c.total;
        const auto sp = line.find_first_of(" \t");
        const auto opt = line.substr(0, sp);
        if (opt == "-w") ++c.watches;
        else if (opt == "-a" || opt == "-A") ++c.syscalls;
        else if (opt == "-e") c.enabled = std::string{sp == std::string_view::npos ? "" : trim_ws(line.substr(sp))};
        else if (opt == "-D" || opt == "-b" || opt == "-f" || opt == "-r" || opt == "-i" ||
                 opt == "-c" || opt == "--backlog_wait_time" || opt == "--loginuid-immutable")
            continue; // control lines: counted in total, not a rule class
        else ++c.unmodelled;
    }
    return c;
}

/// auditctl -e: 0 disabled, 1 enabled, 2 immutable; anything else is the named `unmodelled:`.
inline std::string audit_enabled_token(std::string_view v) {
    if (v == "0") return "disabled";
    if (v == "1") return "enabled";
    if (v == "2") return "immutable";
    return "unmodelled:" + std::string{v}; // escaped once, by the row formatter
}

// ---- sudoers ------------------------------------------------------------------------

struct SudoersEntry {
    std::string kind, subject, runas, nopasswd, commands;
};

namespace detail {

inline std::vector<std::string> split_unescaped_commas(std::string_view s) {
    std::vector<std::string> out;
    std::string cur;
    for (std::size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\\' && i + 1 < s.size()) {
            cur += s[i];
            cur += s[++i];
        } else if (s[i] == ',') {
            out.push_back(std::string{trim_ws(cur)});
            cur.clear();
        } else {
            cur += s[i];
        }
    }
    out.push_back(std::string{trim_ws(cur)});
    return out;
}

/// Cuts a trailing `# comment` (preceded by whitespace, not `#<digits>` which is a uid).
inline std::string_view cut_sudoers_comment(std::string_view s) {
    for (std::size_t i = 1; i < s.size(); ++i)
        if (s[i] == '#' && (s[i - 1] == ' ' || s[i - 1] == '\t') &&
            !(i + 1 < s.size() && s[i + 1] >= '0' && s[i + 1] <= '9'))
            return trim_ws(s.substr(0, i));
    return s;
}

inline bool is_tag_word(std::string_view w) {
    if (w.size() < 2 || w.back() != ':') return false;
    return std::all_of(w.begin(), w.end() - 1, [](char c) { return (c >= 'A' && c <= 'Z') || c == '_'; });
}

/// `user host = (runas) TAG: cmd, cmd ...` -> one entry per contiguous (runas, NOPASSWD) run.
inline bool parse_user_spec(std::string_view line, std::vector<SudoersEntry>& out) {
    const auto eq = line.find('=');
    if (eq == std::string_view::npos) return false;
    const auto left = trim_ws(line.substr(0, eq));
    const auto ws = left.find_last_of(" \t");
    if (ws == std::string_view::npos) return false;
    const std::string subject = std::string{trim_ws(left.substr(0, ws))} + "@" +
                                std::string{trim_ws(left.substr(ws))};
    std::string runas = "-", nopasswd = "false";
    std::vector<std::string> run;
    const auto flush = [&] {
        if (run.empty()) return;
        std::string cmds;
        for (const auto& c : run) cmds += (cmds.empty() ? "" : ", ") + c;
        out.push_back({"user_spec", subject, runas, nopasswd, std::move(cmds)});
        run.clear();
    };
    for (auto item : split_unescaped_commas(line.substr(eq + 1))) {
        std::string_view it = item;
        std::string next_runas = runas, next_nopw = nopasswd;
        if (!it.empty() && it.front() == '(') {
            const auto close = it.find(')');
            if (close == std::string_view::npos) return false;
            next_runas = std::string{trim_ws(it.substr(1, close - 1))};
            it = trim_ws(it.substr(close + 1));
        }
        for (;;) {
            const auto w = it.substr(0, it.find_first_of(" \t"));
            if (!is_tag_word(w)) break;
            // Only NOPASSWD:/PASSWD: are semantically decoded; any other recognized tag
            // (SETENV:, NOEXEC:, a known sudo privilege-escalation vector among them) is
            // left in place rather than silently consumed -- it survives verbatim as part
            // of the stored command text, matching the "never dropped" treatment
            // unmodelled_parameter already gets elsewhere in this file.
            if (w == "NOPASSWD:") next_nopw = "true";
            else if (w == "PASSWD:") next_nopw = "false";
            else break;
            it = trim_ws(it.substr(w.size()));
        }
        if (it.empty()) return false;
        if (next_runas != runas || next_nopw != nopasswd) flush();
        runas = std::move(next_runas);
        nopasswd = std::move(next_nopw);
        run.emplace_back(it);
    }
    flush();
    return true;
}

} // namespace detail

/// Parses one sudoers file. `#include`/`#includedir`/`@include*` are listed
/// (kind include/includedir), never followed; any other line that is not a
/// Defaults / *_Alias / user spec is kind `unmodelled` with the raw line in
/// `commands` -- never dropped.
inline std::vector<SudoersEntry> parse_sudoers(std::string_view text) {
    std::vector<SudoersEntry> out;
    for (const auto& raw : logical_lines(text)) {
        std::string_view line = detail::cut_sudoers_comment(trim_ws(raw));
        if (line.empty()) continue;
        if (line.front() == '#' && !(line.size() > 1 && line[1] >= '0' && line[1] <= '9') &&
            line.substr(0, 8) != "#include") continue;
        const auto word = line.substr(0, line.find_first_of(" \t"));
        const auto rest = trim_ws(line.substr(word.size()));
        if (word == "#include" || word == "@include")
            out.push_back({"include", "-", "-", "-", std::string{rest}});
        else if (word == "#includedir" || word == "@includedir")
            out.push_back({"includedir", "-", "-", "-", std::string{rest}});
        else if (word.substr(0, 8) == "Defaults" &&
                 (word.size() == 8 || std::string_view{":@!>"}.find(word[8]) != std::string_view::npos)) {
            std::string scope = "-"; // Defaults:user / @host / !cmnd / >runas
            if (word.size() > 8) {
                const auto k = std::string_view{":@!>"}.find(word[8]);
                scope = std::string{std::array{"user:", "host:", "cmnd:", "runas:"}[k]} + std::string{word.substr(9)};
            }
            out.push_back({"defaults", scope, "-", "-", std::string{rest}});
        } else if (word == "User_Alias" || word == "Runas_Alias" || word == "Host_Alias" ||
                   word == "Cmnd_Alias") {
            const auto eq = rest.find('=');
            out.push_back({"alias", std::string{word} + ":" + std::string{trim_ws(rest.substr(0, eq))},
                           "-", "-", eq == std::string_view::npos ? "" : std::string{trim_ws(rest.substr(eq + 1))}});
        } else if (!detail::parse_user_spec(line, out)) {
            out.push_back({"unmodelled", "-", "-", "-", std::string{line}});
        }
    }
    return out;
}

/// sudo skips /etc/sudoers.d names containing '.' or ending in '~'.
inline bool sudoers_dir_entry_ignored(std::string_view name) {
    return name.find('.') != std::string_view::npos || (!name.empty() && name.back() == '~');
}

// ---- errno classification and status (one function for every leg) --------------------

inline constexpr int kReadOversized = -1;
inline constexpr int kReadNotRegular = -2;

enum class ReadClass { Absent, Denied, Failed };
struct ReadOutcome {
    ReadClass cls;
    std::string token; // lower_snake failure token; empty for Absent
};

inline ReadOutcome classify_read_errno(int err) {
    switch (err) {
    case ENOENT:
    case ENOTDIR: return {ReadClass::Absent, ""};
    case EACCES:
    case EPERM: return {ReadClass::Denied, "permission_denied"};
    case ELOOP: return {ReadClass::Failed, "symlink_loop"};
    case EIO: return {ReadClass::Failed, "io_error"};
    case kReadOversized: return {ReadClass::Failed, "oversized"};
    case kReadNotRegular: return {ReadClass::Failed, "not_regular"};
    default: return {ReadClass::Failed, "errno_" + std::to_string(err)};
    }
}

enum class PolicyStatus { Ok, Constrained, PermissionDenied };

/// PERMISSION_DENIED only when every existing source was refused (nothing
/// readable, nothing else failed); any other failure is CONSTRAINED; else OK.
inline PolicyStatus select_status(std::size_t readable, std::size_t denied, std::size_t failed) {
    if (denied == 0 && failed == 0) return PolicyStatus::Ok;
    if (readable == 0 && failed == 0) return PolicyStatus::PermissionDenied;
    return PolicyStatus::Constrained;
}

// ---- row formatters ---------------------------------------------------------------------

inline std::string join_row(std::string_view head, std::initializer_list<std::string_view> fields) {
    std::string r{head};
    for (auto f : fields) r += '|', r += yuzu::util::safe_output_field(f);
    return r;
}

/// A key present with no value reads `present`.
inline std::string format_kv_row(std::string_view action, std::string_view key,
                                 std::string_view value, std::string_view source) {
    return join_row(action, {key, value.empty() ? std::string_view{"present"} : value, source});
}

inline std::string format_sudoers_row(std::string_view file, const SudoersEntry& e) {
    return join_row("sudoers", {file, e.kind, e.subject, e.runas, e.nopasswd, e.commands});
}

// ---- file-source collector (Linux and macOS file legs; reader injected) --------------------

struct FileRead {
    int err = 0; // 0 = ok; errno, or kReadOversized / kReadNotRegular
    std::string data;
};
struct DirList {
    int err = 0;
    std::vector<std::string> names; // sorted, no "." / ".."
    bool truncated = false;
};
using FileReader = std::function<FileRead(const std::string&)>;
using DirLister = std::function<DirList(const std::string&)>;

enum class LocalPolicyAction { Password, Lockout, Audit, Sudoers, Unknown };
enum class FileFlavor { Linux, Macos };

inline LocalPolicyAction parse_local_policy_action(std::string_view a) {
    if (a == "password_policy") return LocalPolicyAction::Password;
    if (a == "lockout_policy") return LocalPolicyAction::Lockout;
    if (a == "audit_policy") return LocalPolicyAction::Audit;
    if (a == "sudoers") return LocalPolicyAction::Sudoers;
    return LocalPolicyAction::Unknown;
}
inline std::string_view action_row_prefix(LocalPolicyAction a) {
    switch (a) {
    case LocalPolicyAction::Password: return "password_policy";
    case LocalPolicyAction::Lockout: return "lockout_policy";
    case LocalPolicyAction::Audit: return "audit_policy";
    default: return "sudoers";
    }
}

inline constexpr std::size_t kMaxFileBytes = 256 * 1024;
inline constexpr std::size_t kMaxDirEntries = 256;
inline constexpr std::size_t kMaxRows = 4096;

struct Collected {
    std::vector<std::string> rows;
    PolicyStatus status = PolicyStatus::Ok;
    std::string reason; // comma-joined `<source>:<token>` failure tokens
};

namespace detail {

struct Tally {
    std::size_t readable = 0, denied = 0, failed = 0;
    yuzu::shared::ConstraintAccumulator acc;
    std::vector<std::string> rows;
    bool capped = false;

    void row(std::string r) {
        if (rows.size() >= kMaxRows) {
            if (!capped) acc.add_failure("row_cap");
            capped = true;
            return;
        }
        rows.push_back(std::move(r));
    }
    /// Records a failed (non-absent) read.
    void failure(const ReadOutcome& o, std::string_view src) {
        (o.cls == ReadClass::Denied ? denied : failed)++;
        acc.add_failure(std::string{src} + ":" + o.token);
    }
    /// Records the outcome and returns {state, detail}: {"absent", ""} or {"unreadable", token}.
    std::pair<std::string, std::string> state_of(const ReadOutcome& o, std::string_view src) {
        if (o.cls == ReadClass::Absent) return {"absent", ""};
        failure(o, src);
        return {"unreadable", o.token};
    }
};

inline std::string kv_state_text(const std::pair<std::string, std::string>& st) {
    return st.second.empty() ? st.first : st.first + ":" + st.second;
}

/// Reads `path`; on success returns the text. An absent / failed source hands its
/// {state, detail} to `state_row` and returns nullopt.
template <class StateRow>
std::optional<std::string> read_source(const FileReader& rd, Tally& t, const std::string& path,
                                       StateRow&& state_row) {
    auto r = rd(path);
    if (r.err == 0) {
        ++t.readable;
        return std::move(r.data);
    }
    state_row(t.state_of(classify_read_errno(r.err), path));
    return std::nullopt;
}

inline void kv_source(const FileReader& rd, Tally& t, std::string_view action, const std::string& path,
                      std::string_view seps, std::span<const std::string_view> allow) {
    auto text = read_source(rd, t, path, [&](const auto& st) {
        t.row(format_kv_row(action, "source_state", kv_state_text(st), path));
    });
    if (!text) return;
    for (const auto& [k, v] : parse_kv_lines(*text, seps))
        if (allow.empty() || std::find(allow.begin(), allow.end(), k) != allow.end())
            t.row(format_kv_row(action, k, v, path));
}

inline void pam_sources(const FileReader& rd, Tally& t, std::string_view action,
                        std::span<const std::string_view> files,
                        std::span<const std::string_view> types,
                        std::span<const std::string_view> modules) {
    std::size_t exist = 0; // present, refused or failed -- anything but definitively absent
    for (auto f : files) {
        const std::string path = "/etc/pam.d/" + std::string{f};
        auto r = rd(path);
        if (r.err == 0) {
            ++exist;
            ++t.readable;
            for (const auto& p : parse_pam_lines(r.data))
                if (std::find(types.begin(), types.end(), p.type) != types.end() &&
                    std::find(modules.begin(), modules.end(), p.module) != modules.end())
                    t.row(format_kv_row(action, "pam." + p.type + "." + p.module,
                                        p.control + (p.args.empty() ? "" : " " + p.args), path));
            continue;
        }
        const auto st = t.state_of(classify_read_errno(r.err), path);
        if (st.first != "absent") {
            ++exist;
            t.row(format_kv_row(action, "source_state", kv_state_text(st), path));
        }
        if (f == files.back() && exist == 0)
            t.row(format_kv_row(action, "source_state", "absent", "/etc/pam.d"));
    }
}

inline void sudoers_file(const FileReader& rd, Tally& t, const std::string& path) {
    auto text = read_source(rd, t, path, [&](const auto& st) {
        t.row(format_sudoers_row(path, {st.first, "-", "-", "-", st.second.empty() ? "-" : st.second}));
    });
    if (!text) return;
    for (const auto& e : parse_sudoers(*text)) t.row(format_sudoers_row(path, e));
}

} // namespace detail

/// Collects the rows + status for a file-backed action. `Macos` password/lockout
/// come from pwpolicy, not files, and are not handled here.
inline Collected collect_file_policy(FileFlavor flavor, LocalPolicyAction action,
                                     const FileReader& rd, const DirLister& ls) {
    detail::Tally t;
    const auto prefix = action_row_prefix(action);
    switch (action) {
    case LocalPolicyAction::Password: {
        detail::kv_source(rd, t, prefix, "/etc/login.defs", " \t", kLoginDefsPasswordKeys);
        detail::kv_source(rd, t, prefix, "/etc/security/pwquality.conf", " \t=", {});
        constexpr std::string_view files[] = {"common-password", "system-auth", "password-auth"};
        constexpr std::string_view types[] = {"password"};
        detail::pam_sources(rd, t, prefix, files, types, kPamPasswordModules);
        break;
    }
    case LocalPolicyAction::Lockout: {
        detail::kv_source(rd, t, prefix, "/etc/login.defs", " \t", kLoginDefsLockoutKeys);
        detail::kv_source(rd, t, prefix, "/etc/security/faillock.conf", " \t=", {});
        constexpr std::string_view files[] = {"common-auth", "common-account", "system-auth",
                                              "password-auth"};
        constexpr std::string_view types[] = {"auth", "account"};
        detail::pam_sources(rd, t, prefix, files, types, kPamLockoutModules);
        break;
    }
    case LocalPolicyAction::Audit: {
        const std::string path = flavor == FileFlavor::Macos ? "/etc/security/audit_control"
                                                             : "/etc/audit/audit.rules";
        auto text = detail::read_source(rd, t, path, [&](const auto& st) {
            t.row(format_kv_row(prefix, "source_state", detail::kv_state_text(st), path));
        });
        if (!text) break;
        if (flavor == FileFlavor::Macos) {
            for (const auto& [k, v] : parse_kv_lines(*text, ":")) t.row(format_kv_row(prefix, k, v, path));
            break;
        }
        const auto c = parse_auditd_rules_count(*text);
        t.row(format_kv_row(prefix, "rules", std::to_string(c.total), path));
        t.row(format_kv_row(prefix, "watch_rules", std::to_string(c.watches), path));
        t.row(format_kv_row(prefix, "syscall_rules", std::to_string(c.syscalls), path));
        t.row(format_kv_row(prefix, "unmodelled_lines", std::to_string(c.unmodelled), path));
        t.row(format_kv_row(prefix, "enabled", c.enabled ? audit_enabled_token(*c.enabled) : "unset", path));
        break;
    }
    case LocalPolicyAction::Sudoers: {
        detail::sudoers_file(rd, t, "/etc/sudoers");
        const auto d = ls("/etc/sudoers.d");
        if (d.err != 0) {
            const auto st = t.state_of(classify_read_errno(d.err), "sudoers.d");
            t.row(format_sudoers_row("/etc/sudoers.d", {st.first, "-", "-", "-", st.second.empty() ? "-" : st.second}));
            break;
        }
        if (d.truncated) t.acc.add_failure("sudoers.d:truncated"), ++t.failed;
        for (const auto& n : d.names) {
            const std::string path = "/etc/sudoers.d/" + n;
            if (sudoers_dir_entry_ignored(n))
                t.row(format_sudoers_row(path, {"ignored", "-", "-", "-", "name_ignored_by_sudo"}));
            else
                detail::sudoers_file(rd, t, path);
        }
        break;
    }
    case LocalPolicyAction::Unknown: break;
    }
    return {std::move(t.rows), select_status(t.readable, t.denied, t.failed + (t.capped ? 1 : 0)),
            t.acc.reason()};
}

// ---- Windows secedit export -> rows (the Windows leg only reads and decodes the bytes) --------

struct SeceditRows {
    std::vector<std::string> rows;
    std::string failure_token; // non-empty -> CONSTRAINED; rows must not be trusted
};

inline constexpr std::string_view kSeceditPasswordKeys[] = {
    "MinimumPasswordAge", "MaximumPasswordAge", "MinimumPasswordLength",
    "PasswordComplexity", "PasswordHistorySize", "ClearTextPassword"};
inline constexpr std::string_view kSeceditLockoutKeys[] = {"LockoutBadCount", "ResetLockoutCount",
                                                           "LockoutDuration"};

/// [Event Audit] values are the AUDIT_* bitmask: 0 none, 1 success, 2 failure, 3 both;
/// anything else is the named `unmodelled:` state, never dropped and never "no data".
inline std::string secedit_audit_setting(std::string_view raw) {
    raw = trim_ws(raw);
    if (raw == "0") return "none";
    if (raw == "1") return "success";
    if (raw == "2") return "failure";
    if (raw == "3") return "success_failure";
    return "unmodelled:" + std::string{raw};
}

/// `<action>|<key>|<value>|secedit` rows (audit: every [Event Audit] category). A key the
/// export does not carry is the row value `absent` (a modal state, no token); a missing
/// required section means the export is not the shape we read -- a failure token, never an
/// empty success.
inline SeceditRows secedit_policy_rows(std::string_view action, const InfSections& sections) {
    SeceditRows out;
    const auto which = parse_local_policy_action(action);
    if (which == LocalPolicyAction::Unknown || which == LocalPolicyAction::Sudoers) {
        out.failure_token = "secedit:unsupported_action";
        return out;
    }
    const bool audit = which == LocalPolicyAction::Audit;
    const auto sec = sections.find(audit ? "Event Audit" : "System Access");
    if (sec == sections.end() || sec->second.empty()) {
        out.failure_token = audit ? "secedit:section_missing_event_audit"
                                  : "secedit:section_missing_system_access";
        return out;
    }
    const auto prefix = action_row_prefix(which);
    if (audit) {
        for (const auto& [k, v] : sec->second)
            out.rows.push_back(format_kv_row(prefix, k, secedit_audit_setting(v), "secedit"));
        return out;
    }
    for (const auto key : which == LocalPolicyAction::Lockout ? std::span<const std::string_view>{kSeceditLockoutKeys}
                                                              : std::span<const std::string_view>{kSeceditPasswordKeys}) {
        const auto it = sec->second.find(std::string{key});
        out.rows.push_back(format_kv_row(prefix, key, it == sec->second.end() ? "absent" : it->second, "secedit"));
    }
    return out;
}

// ---- macOS pwpolicy ------------------------------------------------------------------------

struct PwPolicyItem {
    std::string category;   // policyCategoryAuthentication | policyCategoryPasswordContent | ...
    std::string identifier; // policyIdentifier
    std::string content;    // policyContent (Apple policy expression)
    std::vector<std::pair<std::string, std::string>> params; // policyParameters scalars, key-sorted
};

/// `pwpolicy -getaccountpolicies` prints a non-plist banner line before the XML
/// (`Getting global account policies`); everything before `<?xml` is discarded.
inline std::optional<std::string_view> strip_to_xml(std::string_view raw) {
    const auto at = raw.find("<?xml");
    if (at == std::string_view::npos) return std::nullopt;
    return raw.substr(at);
}

/// Failure token for a finished pwpolicy run, or empty when the output is usable.
inline std::string classify_pwpolicy_run(bool tool_ran, bool timed_out, bool truncated, int exit_code) {
    if (!tool_ran) return "pwpolicy:spawn_error";
    if (timed_out) return "pwpolicy:deadline";
    if (truncated) return "pwpolicy:output_truncated";
    if (exit_code != 0) return "pwpolicy:exit_" + std::to_string(exit_code);
    return "";
}

/// `policyAttributePassword matches '.{N,}...'` -> N. Anything else -> nullopt (not guessed).
inline std::optional<unsigned> pwpolicy_min_length(std::string_view content) {
    const auto at = content.find(".{");
    if (at == std::string_view::npos) return std::nullopt;
    std::size_t i = at + 2;
    unsigned n = 0;
    const auto start = i;
    while (i < content.size() && content[i] >= '0' && content[i] <= '9' && i - start < 6)
        n = n * 10 + static_cast<unsigned>(content[i++] - '0');
    if (i == start || i + 1 >= content.size() || content[i] != ',' || content[i + 1] != '}')
        return std::nullopt;
    return n;
}

/// Rows for one action from the parsed policy items. Categories: *Authentication ->
/// lockout, policyCategoryPassword* -> password, anything else is `unmodelled_category`
/// in BOTH actions. Only `policyAttribute*` parameter keys carry a value; other
/// parameter keys are named (`unmodelled_parameter`), never valued. No matching
/// policy is the modal row `policies|none`, not an error.
inline std::vector<std::string> pwpolicy_rows(LocalPolicyAction action,
                                              const std::vector<PwPolicyItem>& items) {
    const auto prefix = action_row_prefix(action);
    std::vector<std::string> rows;
    for (const auto& it : items) {
        const bool lock = it.category.find("Authentication") != std::string::npos;
        const bool pw = it.category.rfind("policyCategoryPassword", 0) == 0;
        const std::string src = "pwpolicy:" + (it.identifier.empty() ? it.category : it.identifier);
        if (!lock && !pw) {
            rows.push_back(format_kv_row(prefix, "unmodelled_category", it.category, "pwpolicy"));
            continue;
        }
        if (lock != (action == LocalPolicyAction::Lockout)) continue;
        if (!it.content.empty()) rows.push_back(format_kv_row(prefix, "policy_content", it.content, src));
        if (const auto n = pwpolicy_min_length(it.content))
            rows.push_back(format_kv_row(prefix, "minimum_length", std::to_string(*n), src));
        for (const auto& [k, v] : it.params) {
            if (k.rfind("policyAttribute", 0) == 0) rows.push_back(format_kv_row(prefix, k, v, src));
            else rows.push_back(format_kv_row(prefix, "unmodelled_parameter", k, src));
        }
    }
    if (rows.empty()) rows.push_back(format_kv_row(prefix, "policies", "none", "pwpolicy"));
    return rows;
}

} // namespace yuzu::local_security_policy
