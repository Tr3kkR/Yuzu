/**
 * local_security_policy_parsers.hpp -- pure core of the plugin: no OS call, process
 * or clock. Every decision (errno class, status, row shape, sudoers kind) is a
 * function here; the leg TUs only read bytes and hand them in.
 *
 * Rows (fields through safe_output_field). All four shapes, since this header is
 * what local_security_policy_plugin.cpp points at for them:
 *   <action>|<key>|<value>|<source>          password_policy, lockout_policy, audit_policy
 *   sudoers|<file>|<kind>|<subject>|<runas>|<nopasswd>|<commands>
 *     kind: defaults | alias | include | includedir | user_spec | unmodelled | ignored | absent | unreadable
 *   <action>|status|<state>|<reason>         the zero-row fallback (local_security_policy_legs.hpp)
 *   constrained|<token>                      the 2-field diagnostic row: every Windows-leg failure,
 *                                            and a contained exception (`internal_error`) on any leg
 * A definitively missing source is the row state `absent` (key `source_state`) and no
 * failure token; an unreadable one is `unreadable:<token>` -- failure never reads as absent.
 * A pwpolicy item that is not in the documented plist shape is the same
 * `source_state|unreadable:<defect>` row plus a `pwpolicy:<defect>` token (pwpolicy_rows).
 */
#pragma once

#include <yuzu/string_utils.hpp>

#include <constraint_accumulator.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <cstdint>
#include <functional>
#include <initializer_list>
#include <iterator>
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
/// `cut_comment` runs on each PHYSICAL line BEFORE the continuation test, as sudo's
/// lexer and libpam's _pam_assemble_line both do: a comment ending in `\` must not
/// swallow the next line (a `# note \` above a NOPASSWD grant hid the grant).
template <class CutComment>
std::vector<std::string> logical_lines(std::string_view text, CutComment cut_comment) {
    std::vector<std::string> out;
    std::string cur;
    for (auto raw : split_lines(text)) {
        raw = trim_ws(cut_comment(trim_ws(raw)));
        const bool cont = !raw.empty() && raw.back() == '\\';
        if (cont) raw = trim_ws(raw.substr(0, raw.size() - 1));
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
/// std::map, not unordered: secedit_policy_rows iterates `[Event Audit]`
/// directly, so the key order IS the audit_policy row order on the wire.
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
/// is dropped (PAM itself would reject it) -- pam.d holds no other policy. A `#`
/// anywhere starts a comment, as in libpam.
inline std::vector<PamLine> parse_pam_lines(std::string_view text) {
    std::vector<PamLine> out;
    const auto cut = [](std::string_view l) { return l.substr(0, l.find('#')); };
    for (const auto& line : logical_lines(text, cut)) {
        std::string_view s = line;
        if (s.empty() || s.front() == '@') continue;
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
    std::size_t control = 0;  // -D/-b/-f/-r/-i/-c/-e/--backlog_wait_time/--loginuid-immutable
    std::size_t unmodelled = 0;
    std::optional<std::string> enabled; // -e value, last one wins

    /// The RULE count. A control directive (-D, -b, -f, -e, ...) configures the
    /// auditd subsystem; it is not a rule, and counting it as one reports
    /// "4 rules" for a stock file that contains no rule at all. An unrecognised
    /// line counts as a rule: this is a rules file, and over-reporting an
    /// unknown line is safer than dropping a real rule.
    [[nodiscard]] std::size_t rules() const { return watches + syscalls + unmodelled; }
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
        else if (opt == "-e") {
            c.enabled = std::string{sp == std::string_view::npos ? "" : trim_ws(line.substr(sp))};
            ++c.control;
        }
        else if (opt == "-D" || opt == "-b" || opt == "-f" || opt == "-r" || opt == "-i" ||
                 opt == "-c" || opt == "--backlog_wait_time" || opt == "--loginuid-immutable")
            ++c.control; // configures auditd; not a rule
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

/// Splits a sudoers list at unescaped commas. A comma inside a Runas_Spec -- a `(`
/// that OPENS an item, up to its `)` -- is part of the spec, not a separator:
/// `(root, %wheel) NOPASSWD: /bin/ls` is one item (sudoers(5) Runas_List). Only an
/// item-leading `(` opens a spec, so parentheses inside a command's arguments never
/// suppress splitting.
inline std::vector<std::string> split_unescaped_commas(std::string_view s) {
    std::vector<std::string> out;
    std::string cur;
    bool in_runas = false;
    for (std::size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\\' && i + 1 < s.size()) {
            cur += s[i];
            cur += s[++i];
        } else if (s[i] == '(' && !in_runas && trim_ws(cur).empty()) {
            in_runas = true;
            cur += s[i];
        } else if (s[i] == ')' && in_runas) {
            in_runas = false;
            cur += s[i];
        } else if (s[i] == ',' && !in_runas) {
            out.push_back(std::string{trim_ws(cur)});
            cur.clear();
        } else {
            cur += s[i];
        }
    }
    out.push_back(std::string{trim_ws(cur)});
    return out;
}

/// Cuts a `# comment` from one physical line: a whole-line comment (not `#<digits>`,
/// a uid, nor `#include`/`#includedir`) or a trailing one preceded by whitespace.
inline std::string_view cut_sudoers_comment(std::string_view s) {
    if (!s.empty() && s.front() == '#' && !(s.size() > 1 && s[1] >= '0' && s[1] <= '9') &&
        !s.starts_with("#include"))
        return {};
    for (std::size_t i = 1; i < s.size(); ++i)
        if (s[i] == '#' && (s[i - 1] == ' ' || s[i - 1] == '\t') &&
            !(i + 1 < s.size() && s[i + 1] >= '0' && s[i + 1] <= '9'))
            return trim_ws(s.substr(0, i));
    return s;
}

/// True for a bare Tag_Spec NAME (no colon): non-empty, `[A-Z_]` only.
inline bool is_tag_name(std::string_view w) {
    return !w.empty() &&
           std::all_of(w.begin(), w.end(), [](char c) { return (c >= 'A' && c <= 'Z') || c == '_'; });
}

/// Length of the leading `TAG:` in `s`, INCLUDING the colon and any blanks
/// around it, or 0 when `s` does not start with one.
///
/// Keyed on the COLON, not on whitespace: sudo's lexer matches
/// `NOPASSWD[[:blank:]]*:` with no requirement of a blank AFTER the colon, so
/// `NOPASSWD:/bin/ls`, `NOPASSWD :/bin/ls` and `NOPASSWD : /bin/ls` are all
/// valid sudoers (verified with visudo) and all mean passwordless. Splitting
/// on whitespace saw the first two as one opaque word and reported
/// `nopasswd|false` for a genuinely passwordless root grant. A command can
/// still carry a colon (`/bin/foo -o a:b`): the text before it is not
/// `[A-Z_]`-only, so this returns 0 and the caller stops scanning.
inline std::size_t tag_prefix_len(std::string_view s) {
    const auto colon = s.find(':');
    if (colon == std::string_view::npos) return 0;
    if (!is_tag_name(trim_ws(s.substr(0, colon)))) return 0;
    std::size_t end = colon + 1;
    while (end < s.size() && (s[end] == ' ' || s[end] == '\t')) ++end;
    return end;
}

/// Length of a leading sudoers(5) Option_Spec word (`CWD=/tmp`, `TIMEOUT=5m`,
/// `ROLE=sysadm_r`, `NOTBEFORE=...`, `APPARMOR_PROFILE=...`): `[A-Z_]+=` plus the
/// non-blank value; 0 when `s` does not start with one.
inline std::size_t option_prefix_len(std::string_view s) {
    const auto eq = s.find('=');
    if (eq == std::string_view::npos || !is_tag_name(s.substr(0, eq))) return 0;
    const auto end = s.find_first_of(" \t", eq);
    return end == std::string_view::npos ? s.size() : end;
}

/// True when `s` still carries an unescaped `NOPASSWD:` / `PASSWD:` tag (blanks
/// allowed before the colon). A decoded tag is removed from the row's text, so
/// one found here was NOT decoded into the `nopasswd` column.
inline bool has_passwd_tag(std::string_view s) {
    for (std::size_t at = 0; (at = s.find("PASSWD", at)) != std::string_view::npos; ++at) {
        const std::size_t b = at >= 2 && s.substr(at - 2, 2) == "NO" ? at - 2 : at;
        if (b > 0 && (std::isalnum(static_cast<unsigned char>(s[b - 1])) || s[b - 1] == '_'))
            continue;
        std::size_t e = at + 6;
        while (e < s.size() && (s[e] == ' ' || s[e] == '\t')) ++e;
        if (e < s.size() && s[e] == ':') return true;
    }
    return false;
}

/// sudoers(5) Tag_Spec names and Digest_Spec types: a `:` after one of these is
/// part of the Cmnd_Spec, never a Host_List clause separator.
inline constexpr std::string_view kColonWords[] = {
    "EXEC", "NOEXEC", "FOLLOW", "NOFOLLOW", "LOG_INPUT", "NOLOG_INPUT", "LOG_OUTPUT",
    "NOLOG_OUTPUT", "MAIL", "NOMAIL", "INTERCEPT", "NOINTERCEPT", "PASSWD", "NOPASSWD",
    "SETENV", "NOSETENV", "sha224", "sha256", "sha384", "sha512"};

/// Splits a user spec's right-hand side into its `Host_List = Cmnd_Spec_List`
/// clauses (sudoers(5): `User_List Host_List = Cmnd_Spec_List (: Host_List =
/// Cmnd_Spec_List)*`). A `:` separates clauses only when it is unescaped, outside a
/// Runas_Spec, not after a tag name or digest type, and followed by a non-empty
/// host list and `=`. Returns {host, cmnd_spec_list} pairs; the first host is `host`.
inline std::vector<std::pair<std::string, std::string>> split_host_clauses(std::string_view host,
                                                                           std::string_view rhs) {
    std::vector<std::pair<std::string, std::string>> out{{std::string{host}, {}}};
    int depth = 0;
    for (std::size_t i = 0; i < rhs.size(); ++i) {
        if (rhs[i] == '\\' && i + 1 < rhs.size()) {
            out.back().second.append(rhs.substr(i++, 2));
            continue;
        }
        if (rhs[i] == '(') ++depth;
        if (rhs[i] == ')' && depth > 0) --depth;
        if (rhs[i] == ':' && depth == 0) {
            std::size_t w_end = i;
            while (w_end > 0 && (rhs[w_end - 1] == ' ' || rhs[w_end - 1] == '\t')) --w_end;
            std::size_t w = w_end;
            while (w > 0 && std::string_view{" \t,()"}.find(rhs[w - 1]) == std::string_view::npos) --w;
            const auto word = rhs.substr(w, w_end - w);
            std::size_t eq = i + 1;
            while (eq < rhs.size() && rhs[eq] != '=' && rhs[eq] != '\\') ++eq;
            const auto next_host = eq < rhs.size() && rhs[eq] == '='
                                       ? trim_ws(rhs.substr(i + 1, eq - i - 1)) : std::string_view{};
            if (std::find(std::begin(kColonWords), std::end(kColonWords), word) == std::end(kColonWords) &&
                !next_host.empty() && next_host.find_first_of(":()") == std::string_view::npos) {
                out.emplace_back(std::string{next_host}, std::string{});
                i = eq;
                continue;
            }
        }
        out.back().second += rhs[i];
    }
    return out;
}

/// `user host = (runas) OPTION=v TAG: cmd, cmd ... [: host2 = ...]` -> one entry per
/// contiguous (runas, NOPASSWD) run of each Host_List clause; nullopt when the line is
/// not decodable as a user spec.
///
/// FAIL SAFE: nopasswd is the one field a reader filters on, so a NOPASSWD:/PASSWD:
/// tag this function did not decode must never leave a `false` row under OK. If one
/// survives into any field (a shape the scan does not model), the whole line is
/// nullopt -- parse_sudoers then reports it `unmodelled`, and the collector adds the
/// `<file>:undecoded_passwd_tag` token (CONSTRAINED).
inline std::optional<std::vector<SudoersEntry>> parse_user_spec(std::string_view line) {
    const auto eq = line.find('=');
    if (eq == std::string_view::npos) return std::nullopt;
    const auto left = trim_ws(line.substr(0, eq));
    const auto ws = left.find_last_of(" \t");
    if (ws == std::string_view::npos) return std::nullopt;
    const std::string users{trim_ws(left.substr(0, ws))};
    std::vector<SudoersEntry> out;
    for (const auto& [host, list] : split_host_clauses(trim_ws(left.substr(ws)), line.substr(eq + 1))) {
        // Runas and tags carry across one Cmnd_Spec_List, never into the next clause.
        const std::string subject = users + "@" + host;
        std::string runas = "-", nopasswd = "false";
        std::vector<std::string> run;
        const auto flush = [&] {
            if (run.empty()) return;
            std::string cmds;
            for (const auto& c : run) cmds += (cmds.empty() ? "" : ", ") + c;
            out.push_back({"user_spec", subject, runas, nopasswd, std::move(cmds)});
            run.clear();
        };
        for (auto item : split_unescaped_commas(list)) {
            std::string_view it = item;
            std::string next_runas = runas, next_nopw = nopasswd;
            if (!it.empty() && it.front() == '(') {
                const auto close = it.find(')');
                if (close == std::string_view::npos) return std::nullopt;
                next_runas = std::string{trim_ws(it.substr(1, close - 1))};
                it = trim_ws(it.substr(close + 1));
            }
            // sudoers(5) lets a Tag_Spec carry its tags in ANY order, so the scan must not
            // stop at the first tag it does not decode: `SETENV: NOPASSWD: /usr/bin/bar`
            // grants passwordless root exactly as `NOPASSWD: SETENV: ...` does. Option_Spec
            // words (`CWD=/tmp`, `TIMEOUT=5m`, ...) precede the tags and are consumed the
            // same way. Only NOPASSWD:/PASSWD: are decoded into the typed column; every
            // OTHER tag (SETENV: and NOEXEC: among them, both sudo privilege-escalation
            // vectors) and every option is carried into the stored command text verbatim
            // -- the same "never dropped" treatment unmodelled_parameter gets elsewhere
            // in this file -- so neither property is ever traded for the other.
            std::string kept_tags;
            for (;;) {
                if (const std::size_t len = tag_prefix_len(it)) {
                    const auto name = trim_ws(it.substr(0, it.find(':')));
                    if (name == "NOPASSWD") next_nopw = "true";
                    else if (name == "PASSWD") next_nopw = "false";
                    else {
                        kept_tags.append(name); // normalised to `TAG: `, whatever spacing it had
                        kept_tags.append(": ");
                    }
                    it = trim_ws(it.substr(len));
                } else if (const std::size_t opt = option_prefix_len(it)) {
                    kept_tags.append(it.substr(0, opt));
                    kept_tags += ' ';
                    it = trim_ws(it.substr(opt));
                } else {
                    break;
                }
            }
            if (it.empty()) return std::nullopt;
            if (next_runas != runas || next_nopw != nopasswd) flush();
            runas = std::move(next_runas);
            nopasswd = std::move(next_nopw);
            run.emplace_back(kept_tags + std::string{it});
        }
        flush();
    }
    for (const auto& e : out)
        if (has_passwd_tag(e.subject) || has_passwd_tag(e.runas) || has_passwd_tag(e.commands))
            return std::nullopt;
    return out;
}

} // namespace detail

/// Parses one sudoers file. `#include`/`#includedir`/`@include*` are listed
/// (kind include/includedir), never followed; any other line that is not a
/// Defaults / *_Alias / user spec is kind `unmodelled` with the raw line in
/// `commands` -- never dropped. An `unmodelled` line that still carries a
/// NOPASSWD:/PASSWD: tag is the collector's `undecoded_passwd_tag` failure.
inline std::vector<SudoersEntry> parse_sudoers(std::string_view text) {
    std::vector<SudoersEntry> out;
    for (const auto& line_str : logical_lines(text, detail::cut_sudoers_comment)) {
        const std::string_view line = line_str;
        if (line.empty()) continue;
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
        } else if (auto spec = detail::parse_user_spec(line)) {
            for (auto& e : *spec) out.push_back(std::move(e));
        } else {
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
/// The file holds a NUL byte. Every C consumer of these files (sudo's lexer, libpam,
/// shadow's getdef) stops or diverges at it, so no value read past it can be reported
/// as the one in force, and a NUL crossing write_output's C string would cut the row.
inline constexpr int kReadEmbeddedNul = -3;

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
    case kReadEmbeddedNul: return {ReadClass::Failed, "embedded_nul"};
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

/// A NUL never reaches write_output, which takes a C string and would silently end the
/// row there. Every source already refuses one upstream (kReadEmbeddedNul, cf_to_utf8,
/// secedit:embedded_nul), so this substitution (U+FFFD, visible) is defence in depth.
inline std::string join_row(std::string_view head, std::initializer_list<std::string_view> fields) {
    std::string r{head};
    for (auto f : fields) {
        r += '|';
        r += yuzu::util::safe_output_field(f);
    }
    for (std::size_t at = 0; (at = r.find('\0', at)) != std::string::npos;)
        r.replace(at, 1, "\xEF\xBF\xBD");
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
    int err = 0; // 0 = ok; errno, or kReadOversized / kReadNotRegular / kReadEmbeddedNul
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
/// Exhaustive rather than defaulted: a `default:` arm here mapped Unknown to
/// "sudoers", silently labelling rows with a prefix whose contract is 7 fields,
/// not 4. Unreachable today (execute() rejects Unknown before any leg runs), but
/// the compiler now enforces that a new action gets a deliberate answer.
inline std::string_view action_row_prefix(LocalPolicyAction a) {
    switch (a) {
    case LocalPolicyAction::Password: return "password_policy";
    case LocalPolicyAction::Lockout: return "lockout_policy";
    case LocalPolicyAction::Audit: return "audit_policy";
    case LocalPolicyAction::Sudoers: return "sudoers";
    case LocalPolicyAction::Unknown: break;
    }
    return "";
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

    /// The LAST slot is reserved for the truncation marker itself. Without that
    /// reservation the cap silently drops the row announcing the cap, so the
    /// output ended on an ordinary row indistinguishable from a complete dump --
    /// the one place a non-OK status was not paired with a row saying why.
    /// `marker_prefix` is the action's row prefix; `marker_fields` makes the
    /// marker match the action's own field count (4 for the kv actions, 7 for
    /// sudoers), so the truncation notice never breaks the wire shape.
    void row(std::string r) {
        if (rows.size() + 1 >= kMaxRows) {
            if (!capped) {
                acc.add_failure("row_cap");
                rows.push_back(truncation_marker());
            }
            capped = true;
            return;
        }
        rows.push_back(std::move(r));
    }

    std::string marker_prefix{"local_security_policy"};
    std::size_t marker_fields{4};
    [[nodiscard]] std::string truncation_marker() const {
        return marker_fields == 7
                   ? format_sudoers_row("-", {"unreadable", "-", "-", "-", "row_cap"})
                   : format_kv_row(marker_prefix, "source_state", "unreadable:row_cap",
                                   marker_prefix);
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

/// The one call site of the injected reader: a read that succeeded but holds a NUL
/// byte is the failure kReadEmbeddedNul (the whole source `unreadable:embedded_nul`
/// plus a token -- the same convention as oversized or not_regular), never a value.
inline FileRead checked_read(const FileReader& rd, const std::string& path) {
    auto r = rd(path);
    if (r.err == 0 && r.data.find('\0') != std::string::npos) return {kReadEmbeddedNul, {}};
    return r;
}

/// Reads `path`; on success returns the text. An absent / failed source hands its
/// {state, detail} to `state_row` and returns nullopt.
template <class StateRow>
std::optional<std::string> read_source(const FileReader& rd, Tally& t, const std::string& path,
                                       StateRow&& state_row) {
    auto r = checked_read(rd, path);
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

/// `files` are distro ALTERNATIVES (Debian common-*, RHEL system-auth/password-auth), so one
/// ABSENT file is deliberately silent while any sibling exists; a refused or failed one is
/// always its own row, and all-absent is one `/etc/pam.d` absent row.
inline void pam_sources(const FileReader& rd, Tally& t, std::string_view action,
                        std::span<const std::string_view> files,
                        std::span<const std::string_view> types,
                        std::span<const std::string_view> modules) {
    std::size_t exist = 0; // present, refused or failed -- anything but definitively absent
    for (auto f : files) {
        const std::string path = "/etc/pam.d/" + std::string{f};
        auto r = checked_read(rd, path);
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
    for (const auto& e : parse_sudoers(*text)) {
        t.row(format_sudoers_row(path, e));
        // The fail-safe half of parse_user_spec: a NOPASSWD:/PASSWD: tag the parser could
        // not decode is an unmodelled row AND a failure, never a quiet `false`.
        if (e.kind == "unmodelled" && has_passwd_tag(e.commands)) {
            ++t.failed;
            t.acc.add_failure(path + ":undecoded_passwd_tag");
        }
    }
}

} // namespace detail

/// Collects the rows + status for a file-backed action. `Macos` password/lockout
/// come from pwpolicy, not files, and are not handled here.
inline Collected collect_file_policy(FileFlavor flavor, LocalPolicyAction action,
                                     const FileReader& rd, const DirLister& ls) {
    detail::Tally t;
    const auto prefix = action_row_prefix(action);
    // Shape the row-cap truncation marker like the action's own rows (sudoers is
    // 7 fields, the rest 4), so the notice can never break the wire contract.
    t.marker_prefix = std::string{prefix};
    t.marker_fields = action == LocalPolicyAction::Sudoers ? 7u : 4u;
    // FAIL CLOSED, not open. Both arms below are unreachable today -- execute()
    // rejects Unknown before any leg runs, and the macOS leg routes Password and
    // Lockout to pwpolicy before calling here -- but returning an empty Collected
    // would be status OK with zero rows, which apply_collected reports as a green
    // empty result. A named CONSTRAINED says what happened instead. (The
    // Password/Lockout arms read Linux paths and never consult `flavor`, so this
    // is also what stops a relaxed macOS early return quietly reading
    // /etc/login.defs on a Mac.)
    if (action == LocalPolicyAction::Unknown ||
        (flavor == FileFlavor::Macos &&
         (action == LocalPolicyAction::Password || action == LocalPolicyAction::Lockout)))
        return {{}, PolicyStatus::Constrained, "unsupported_action"};
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
        // rules == watch_rules + syscall_rules + unmodelled_lines, and
        // control_lines accounts for every remaining non-comment line, so the
        // row set closes arithmetically and `rules` means what it says.
        t.row(format_kv_row(prefix, "rules", std::to_string(c.rules()), path));
        t.row(format_kv_row(prefix, "watch_rules", std::to_string(c.watches), path));
        t.row(format_kv_row(prefix, "syscall_rules", std::to_string(c.syscalls), path));
        t.row(format_kv_row(prefix, "unmodelled_lines", std::to_string(c.unmodelled), path));
        t.row(format_kv_row(prefix, "control_lines", std::to_string(c.control), path));
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
        // Pair the failure with its row, like every other failure site in this
        // function. Counting one WITHOUT a row is what would let collect_file_policy
        // return a non-OK status with zero rows, and apply_collected's fallback would
        // then write its 4-field `<action>|status|...` shape into this action's
        // 7-field contract. It also puts the truncation on the wire instead of only
        // in the status reason. `unreadable` is already a declared sudoers kind.
        if (d.truncated) {
            t.acc.add_failure("sudoers.d:truncated");
            ++t.failed;
            t.row(format_sudoers_row("/etc/sudoers.d", {"unreadable", "-", "-", "-", "truncated"}));
        }
        for (const auto& n : d.names) {
            const std::string path = "/etc/sudoers.d/" + n;
            if (sudoers_dir_entry_ignored(n))
                t.row(format_sudoers_row(path, {"ignored", "-", "-", "-", "name_ignored_by_sudo"}));
            else
                detail::sudoers_file(rd, t, path);
        }
        break;
    }
    case LocalPolicyAction::Unknown: break; // refused above; the switch stays exhaustive
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

/// True only for a WHOLE export. `absent` is a real modal value (LockoutDuration when
/// LockoutBadCount=0), so a truncated file that exits 0 would otherwise report the keys it
/// lost as absent under OK. Measured on the-rig (Windows 11 Pro 10.0.26200, LocalSystem,
/// exit 0, 12828 bytes UTF-16LE, BOM FF FE): the sections run `[System Access]`,
/// `[Event Audit]`, `[Registry Values]`, `[Version]`, with `[Version]` LAST carrying
/// `signature="$CHICAGO$"` and `Revision=1`. Complete = both policy sections present and
/// the final section `[Version]` with that signature; anything else is
/// `secedit:export_incomplete`. Section/key names compare case-insensitively (INF rule).
inline bool secedit_export_complete(std::string_view text) {
    const auto ieq = [](std::string_view a, std::string_view b) {
        return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin(), [](char x, char y) {
                   return std::tolower(static_cast<unsigned char>(x)) == std::tolower(static_cast<unsigned char>(y));
               });
    };
    bool system_access = false, event_audit = false, signed_version = false;
    std::string_view last;
    for (auto raw : split_lines(text)) {
        const auto line = trim_ws(raw);
        if (!line.empty() && line.front() == '[' && line.back() == ']') {
            last = trim_ws(line.substr(1, line.size() - 2));
            system_access = system_access || ieq(last, "System Access");
            event_audit = event_audit || ieq(last, "Event Audit");
            signed_version = false; // only the FINAL section's signature counts
        } else if (const auto eq = line.find('='); ieq(last, "Version") && eq != std::string_view::npos &&
                   ieq(trim_ws(line.substr(0, eq)), "signature")) {
            signed_version = ieq(trim_ws(line.substr(eq + 1)), "\"$CHICAGO$\"");
        }
    }
    return system_access && event_audit && ieq(last, "Version") && signed_version;
}

/// `<action>|<key>|<value>|secedit` rows (audit: every [Event Audit] category). A key the
/// export does not carry is the row value `absent` (a modal state, no token); a missing
/// required section means the export is not the shape we read -- a failure token, never an
/// empty success. A reported key or value holding U+0000 is `secedit:embedded_nul` (the
/// Windows leg is all-or-nothing): the value past it is unknowable, never truncated.
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
    const auto nul = [&out](std::string_view k, std::string_view v) {
        if (k.find('\0') == std::string_view::npos && v.find('\0') == std::string_view::npos) return false;
        out = {{}, "secedit:embedded_nul"};
        return true;
    };
    if (audit) {
        for (const auto& [k, v] : sec->second) {
            if (nul(k, v)) return out;
            out.rows.push_back(format_kv_row(prefix, k, secedit_audit_setting(v), "secedit"));
        }
        return out;
    }
    for (const auto key : which == LocalPolicyAction::Lockout ? std::span<const std::string_view>{kSeceditLockoutKeys}
                                                              : std::span<const std::string_view>{kSeceditPasswordKeys}) {
        const auto it = sec->second.find(std::string{key});
        if (it != sec->second.end() && nul(key, it->second)) return out;
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
    /// What the plist bridge could NOT read in the documented shape, each named once:
    /// `malformed_category` (the category's value is not an array), `malformed_policy`
    /// (an array element is not a dictionary), `malformed_identifier` / `malformed_content` /
    /// `malformed_parameter_value` (a modelled field is not a scalar), `malformed_parameters` (policyParameters
    /// is not a dictionary), `non_string_key` (a dictionary key that is not a string was
    /// skipped; at the plist root the item's category is empty), `unconvertible_key` (a
    /// string key with no UTF-8 rendering was skipped). pwpolicy_rows adds `missing_content`
    /// for an element that carries nothing reportable. A known category that
    /// is malformed would otherwise yield no rows and read as `policies|none`, a clean
    /// "nothing configured" -- so every defect becomes a row and a token, never silence.
    std::vector<std::string> defects;
};

/// `pwpolicy -getaccountpolicies` prints a non-plist banner line before the XML
/// (`Getting global account policies`); everything before `<?xml` is discarded.
inline std::optional<std::string_view> strip_to_xml(std::string_view raw) {
    const auto at = raw.find("<?xml");
    if (at == std::string_view::npos) return std::nullopt;
    return raw.substr(at);
}

/// Failure token for a finished pwpolicy run, or empty when the output is usable.
/// How the runner reported a child ending (yuzu::agent::TerminationReason, mirrored so this
/// header stays free of agent-core types; to_run_end in the legs header maps it). Both rung-2
/// legs classify from this, never from the runner's convenience flags, so a signalled or
/// cancelled run is named for what it was (agents/shared/subprocess_degradation.hpp).
enum class RunEnd { Exited, Deadline, Cancelled, Signaled, SpawnError, Other };

inline std::string classify_pwpolicy_run(RunEnd end, bool truncated, int exit_code) {
    switch (end) {
    case RunEnd::SpawnError:
        return "pwpolicy:spawn_error";
    case RunEnd::Deadline:
        return "pwpolicy:deadline";
    case RunEnd::Cancelled:
        return "pwpolicy:cancelled";
    case RunEnd::Signaled:
        return "pwpolicy:signaled";
    case RunEnd::Other:
        return "pwpolicy:unexpected_termination";
    case RunEnd::Exited:
        break;
    }
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

/// Rows + status for one action from the parsed policy items. Categories:
/// *Authentication -> lockout, policyCategoryPassword* -> password, anything else is
/// `unmodelled_category` in BOTH actions. A `policyAttribute*` parameter is its own key;
/// any other scalar parameter (e.g. `autoEnableInSeconds`, the lockout duration) is key
/// `unmodelled_parameter`, value `<name>=<value>` -- the key set stays closed and the
/// value is never dropped. Each
/// item defect (PwPolicyItem::defects) is a `source_state|unreadable:<defect>` row and a
/// `pwpolicy:<defect>` token (CONSTRAINED) in the action(s) its category routes to. No
/// matching policy and no defect is the modal row `policies|none`, not an error.
inline Collected pwpolicy_rows(LocalPolicyAction action, const std::vector<PwPolicyItem>& items) {
    const auto prefix = action_row_prefix(action);
    std::vector<std::string> rows;
    yuzu::shared::ConstraintAccumulator acc;
    for (const auto& it : items) {
        const bool lock = it.category.find("Authentication") != std::string::npos;
        const bool pw = it.category.rfind("policyCategoryPassword", 0) == 0;
        const std::string& named = it.identifier.empty() ? it.category : it.identifier;
        const std::string src = named.empty() ? std::string{"pwpolicy"} : "pwpolicy:" + named;
        const auto defect_rows = [&] {
            for (const auto& d : it.defects) {
                rows.push_back(format_kv_row(prefix, "source_state", "unreadable:" + d, src));
                acc.add_failure("pwpolicy:" + d);
            }
        };
        if (!lock && !pw) {
            // The root non_string_key placeholder has no category to name; a real
            // category -- even an empty-named one -- always keeps its row.
            if (!(it.category.empty() && !it.defects.empty()))
                rows.push_back(format_kv_row(prefix, "unmodelled_category", it.category, "pwpolicy"));
            defect_rows();
            continue;
        }
        if (lock != (action == LocalPolicyAction::Lockout)) continue;
        if (it.content.empty() && it.params.empty() && it.defects.empty()) {
            // A policy element carrying nothing this action can report is a shape defect,
            // not "no policy": without this row it would vanish, and could leave the clean
            // `policies|none` answer below.
            rows.push_back(format_kv_row(prefix, "source_state", "unreadable:missing_content", src));
            acc.add_failure("pwpolicy:missing_content");
            continue;
        }
        if (!it.content.empty()) rows.push_back(format_kv_row(prefix, "policy_content", it.content, src));
        if (const auto n = pwpolicy_min_length(it.content))
            rows.push_back(format_kv_row(prefix, "minimum_length", std::to_string(*n), src));
        for (const auto& [k, v] : it.params) {
            if (k.rfind("policyAttribute", 0) == 0) rows.push_back(format_kv_row(prefix, k, v, src));
            else rows.push_back(format_kv_row(prefix, "unmodelled_parameter", k + "=" + v, src));
        }
        defect_rows();
    }
    if (rows.empty()) rows.push_back(format_kv_row(prefix, "policies", "none", "pwpolicy"));
    return {std::move(rows), acc.any_failure() ? PolicyStatus::Constrained : PolicyStatus::Ok,
            acc.reason()};
}

} // namespace yuzu::local_security_policy
