/**
 * ssh_hardening_rules.hpp — Pure parsing/evaluation logic for the ssh_hardening plugin.
 *
 * Mozilla OpenSSH "Modern" baseline: https://wiki.mozilla.org/Security/Guidelines/OpenSSH
 *
 * Deliberately has no filesystem access so it can be exercised directly by
 * tests/unit/test_ssh_hardening_rules.cpp on every CI platform, mirroring the
 * cve_rules.hpp / config_checks.hpp split in agents/plugins/vuln_scan/src/.
 * The filesystem/glob walk that builds the flattened directive stream this
 * file evaluates lives in ssh_hardening_collect.hpp (Linux-only).
 */
#pragma once

#include <algorithm>
#include <array>
#include <cctype>
#include <format>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::ssh_hardening {

// A single "Keyword value" line from an sshd_config-format file.
struct Directive {
    std::string keyword; // lower-cased
    std::string value;   // trimmed, original case
};

struct ConfigCheckResult {
    std::string_view severity; // CRITICAL/HIGH/MEDIUM/LOW/INFO
    std::string_view title;    // directive name, e.g. "KexAlgorithms"
    std::string detail;
    bool passed;
};

// ── small string helpers ────────────────────────────────────────────────────

namespace detail {

inline std::string_view trim(std::string_view s) {
    size_t b = s.find_first_not_of(" \t");
    if (b == std::string_view::npos)
        return {};
    size_t e = s.find_last_not_of(" \t\r");
    return s.substr(b, e - b + 1);
}

inline std::string to_lower(std::string_view s) {
    std::string out(s);
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

inline std::vector<std::string> split(std::string_view s, char delim) {
    std::vector<std::string> out;
    size_t start = 0;
    while (start <= s.size()) {
        size_t pos = s.find(delim, start);
        if (pos == std::string_view::npos) {
            out.emplace_back(trim(s.substr(start)));
            break;
        }
        out.emplace_back(trim(s.substr(start, pos - start)));
        start = pos + 1;
    }
    return out;
}

// Whitespace-run split, e.g. for Include's space-separated glob argument list.
inline std::vector<std::string> split_ws(std::string_view s) {
    std::vector<std::string> out;
    size_t i = 0;
    while (i < s.size()) {
        while (i < s.size() && std::isspace(static_cast<unsigned char>(s[i])))
            ++i;
        size_t start = i;
        while (i < s.size() && !std::isspace(static_cast<unsigned char>(s[i])))
            ++i;
        if (i > start)
            out.emplace_back(s.substr(start, i - start));
    }
    return out;
}

inline std::string join(const std::vector<std::string>& parts, std::string_view sep) {
    std::string out;
    for (size_t i = 0; i < parts.size(); ++i) {
        if (i)
            out += sep;
        out += parts[i];
    }
    return out;
}

} // namespace detail

// ── Single-file parsing (pure — no filesystem access) ──────────────────────

// One line's worth of structured content, in file order.
struct Entry {
    enum class Kind { Directive, Include };
    Kind kind;
    Directive directive;                    // valid when kind == Directive
    std::vector<std::string> include_globs; // valid when kind == Include (raw, unexpanded)
};

struct ParsedFile {
    std::vector<Entry> entries; // in file order, up to (not including) a top-level Match line
    bool hit_match = false;     // true if a top-level "Match" line was seen
};

// Parses one sshd_config-format file's content. Stops recording entries at
// the first "Match" line: sshd applies everything after Match conditionally,
// and per real sshd semantics that conditional scope extends across any
// files Included afterward too, so callers must stop the whole walk (not
// just this file) once hit_match comes back true. "Include" lines are
// reported back as raw, unexpanded glob arguments in their original file
// position — expanding them needs filesystem access this function
// deliberately does not perform; see ssh_hardening_collect.hpp.
inline ParsedFile parse_sshd_config_content(std::string_view content) {
    ParsedFile result;
    size_t pos = 0;
    while (pos <= content.size()) {
        size_t nl = content.find('\n', pos);
        std::string_view raw_line =
            (nl == std::string_view::npos) ? content.substr(pos) : content.substr(pos, nl - pos);
        pos = (nl == std::string_view::npos) ? content.size() + 1 : nl + 1;

        auto line = detail::trim(raw_line);
        if (line.empty() || line[0] == '#')
            continue;

        // Keyword ends at the first whitespace or '=' (sshd_config accepts
        // both "Keyword value" and "Keyword=value").
        size_t split_at = line.find_first_of(" \t=");
        std::string_view keyword_raw =
            (split_at == std::string_view::npos) ? line : line.substr(0, split_at);
        std::string_view rest =
            (split_at == std::string_view::npos) ? std::string_view{} : line.substr(split_at);
        rest = detail::trim(rest);
        if (!rest.empty() && rest[0] == '=') {
            rest = detail::trim(rest.substr(1));
        }

        std::string keyword = detail::to_lower(keyword_raw);

        if (keyword == "match") {
            result.hit_match = true;
            break;
        }

        if (keyword == "include") {
            Entry e;
            e.kind = Entry::Kind::Include;
            e.include_globs = detail::split_ws(rest);
            result.entries.push_back(std::move(e));
            continue;
        }

        Entry e;
        e.kind = Entry::Kind::Directive;
        e.directive = Directive{std::move(keyword), std::string(rest)};
        result.entries.push_back(std::move(e));
    }
    return result;
}

// ── Effective-config evaluation (pure) ──────────────────────────────────────
//
// `directives` is the fully flattened, in-order stream across the root file
// and every Include'd file (an Included file's directives are interleaved at
// the exact point its Include line occurred, exactly as OpenSSH would see
// them). Building that flattened stream requires filesystem + glob access
// and lives in the platform-specific collector (ssh_hardening_collect.hpp);
// everything below is pure so it can be unit-tested without touching disk.

// sshd_config uses first-obtained-value-wins semantics for ordinary
// directives (sshd_config(5): "for each keyword, the first obtained value
// will be used").
inline std::optional<std::string> first_value(const std::vector<Directive>& directives,
                                               std::string_view keyword_lower) {
    for (const auto& d : directives) {
        if (d.keyword == keyword_lower)
            return d.value;
    }
    return std::nullopt;
}

// HostKey is a repeatable directive — every occurrence adds a host key, none
// of them "override" each other.
inline std::vector<std::string> all_values(const std::vector<Directive>& directives,
                                            std::string_view keyword_lower) {
    std::vector<std::string> out;
    for (const auto& d : directives) {
        if (d.keyword == keyword_lower)
            out.push_back(d.value);
    }
    return out;
}

// Evaluates a comma-separated algorithm-list directive (KexAlgorithms,
// Ciphers, MACs) against an approved allow-list.
inline ConfigCheckResult evaluate_algorithm_directive(std::string_view display_name,
                                                       const std::optional<std::string>& raw_value,
                                                       std::span<const std::string_view> allowed) {
    if (!raw_value) {
        return {"MEDIUM", display_name,
                std::format("{} is not explicitly set in sshd_config -- the OpenSSH "
                            "compiled-in default list applies, which may include "
                            "algorithms weaker than the approved baseline",
                            display_name),
                false};
    }

    std::string_view val = detail::trim(*raw_value);
    if (val.empty()) {
        return {"MEDIUM", display_name, std::format("{} is set but has no value", display_name),
                false};
    }

    if (val[0] == '+' || val[0] == '-' || val[0] == '^') {
        return {"MEDIUM", display_name,
                std::format("{} uses the '{}' modifier (\"{}\") -- the effective algorithm "
                            "list depends on OpenSSH's compiled-in defaults and cannot be "
                            "resolved from the config file alone; replace with an explicit "
                            "list or verify the effective list manually (`sshd -T`)",
                            display_name, val[0], val),
                false};
    }

    auto configured = detail::split(val, ',');
    std::vector<std::string> disallowed;
    for (const auto& algo : configured) {
        if (algo.empty())
            continue;
        bool ok = std::find(allowed.begin(), allowed.end(), algo) != allowed.end();
        if (!ok)
            disallowed.push_back(algo);
    }

    if (disallowed.empty()) {
        return {"INFO", display_name,
                std::format("{} is restricted to the approved baseline ({})", display_name, val),
                true};
    }

    return {"HIGH", display_name,
            std::format("{} permits algorithm(s) outside the approved baseline: {}", display_name,
                        detail::join(disallowed, ", ")),
            false};
}

// Classifies a HostKey path's key type from its filename.
inline std::string_view classify_host_key_type(std::string_view path) {
    std::string lower = detail::to_lower(path);
    // Checked in this order because "ecdsa" contains "dsa" as a substring.
    if (lower.find("ed25519") != std::string::npos)
        return "ed25519";
    if (lower.find("ecdsa") != std::string::npos)
        return "ecdsa";
    if (lower.find("rsa") != std::string::npos)
        return "rsa";
    if (lower.find("dsa") != std::string::npos)
        return "dsa";
    return "unknown";
}

inline ConfigCheckResult evaluate_host_keys(const std::vector<std::string>& paths) {
    if (paths.empty()) {
        return {"MEDIUM", "HostKey",
                "No HostKey directives explicitly configured -- relying on distro-default "
                "host keys, which may include legacy key types",
                false};
    }

    static constexpr std::array<std::string_view, 3> kApproved = {"ed25519", "rsa", "ecdsa"};
    std::vector<std::string> bad;
    for (const auto& path : paths) {
        auto type = classify_host_key_type(path);
        if (std::find(kApproved.begin(), kApproved.end(), type) == kApproved.end()) {
            bad.push_back(std::format("{} ({})", path, type));
        }
    }

    if (!bad.empty()) {
        return {"HIGH", "HostKey",
                std::format("HostKey directive(s) reference disallowed or legacy key type(s): {}",
                            detail::join(bad, ", ")),
                false};
    }

    return {"INFO", "HostKey",
            std::format("HostKey directives are restricted to approved types ({} configured)",
                        paths.size()),
            true};
}

// ── Mozilla "Modern" OpenSSH baseline ───────────────────────────────────────
// https://wiki.mozilla.org/Security/Guidelines/OpenSSH

inline constexpr std::array<std::string_view, 5> kApprovedKexAlgorithms = {
    "curve25519-sha256@libssh.org",
    "ecdh-sha2-nistp521",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp256",
    "diffie-hellman-group-exchange-sha256",
};

inline constexpr std::array<std::string_view, 6> kApprovedCiphers = {
    "chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes128-gcm@openssh.com",
    "aes256-ctr",                    "aes192-ctr",             "aes128-ctr",
};

inline constexpr std::array<std::string_view, 6> kApprovedMacs = {
    "hmac-sha2-512-etm@openssh.com", "hmac-sha2-256-etm@openssh.com", "umac-128-etm@openssh.com",
    "hmac-sha2-512",                 "hmac-sha2-256",                 "umac-128@openssh.com",
};

// Runs all four checks against an already-flattened effective directive
// stream and returns one ConfigCheckResult per directive.
inline std::vector<ConfigCheckResult>
evaluate_ssh_hardening(const std::vector<Directive>& effective) {
    std::vector<ConfigCheckResult> results;
    results.push_back(evaluate_algorithm_directive(
        "KexAlgorithms", first_value(effective, "kexalgorithms"), kApprovedKexAlgorithms));
    results.push_back(evaluate_algorithm_directive("Ciphers", first_value(effective, "ciphers"),
                                                    kApprovedCiphers));
    results.push_back(
        evaluate_algorithm_directive("MACs", first_value(effective, "macs"), kApprovedMacs));
    results.push_back(evaluate_host_keys(all_values(effective, "hostkey")));
    return results;
}

} // namespace yuzu::ssh_hardening
