/**
 * ssh_hardening_collect.hpp — Filesystem/glob walk that builds the flattened
 * effective sshd_config directive stream evaluated by ssh_hardening_rules.hpp.
 *
 * Linux-only (sshd_config's Include directive and glob(3) expansion are a
 * Linux/glibc concern here; see docs/os-capability-matrix.md). Off Linux this
 * header still declares collect_effective_sshd_config() so the plugin can
 * call it unconditionally, but the function is unavailable — the plugin
 * itself is compiled only on Linux (see meson.build), so this guard exists
 * purely so the header can be included by cross-platform test binaries
 * without pulling in <glob.h>.
 */
#pragma once

#include "ssh_hardening_rules.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <optional>
#include <set>
#include <sstream>
#include <string>

#ifdef __linux__
#include <glob.h>
#endif

namespace yuzu::ssh_hardening {

#ifdef __linux__

namespace detail {

inline std::string read_file(const std::string& path, bool& existed) {
    std::ifstream f(path, std::ios::binary);
    existed = f.is_open();
    if (!existed)
        return {};
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

inline std::string resolve_include_path(const std::string& token, const std::string& base_dir) {
    // sshd_config(5): a non-absolute Include path is relative to /etc/ssh/
    // (here, the directory of the file containing the Include line, which is
    // /etc/ssh for the root file and matches real sshd for drop-ins too).
    if (!token.empty() && token[0] == '/')
        return token;
    return base_dir + "/" + token;
}

inline std::vector<std::string> glob_expand(const std::string& pattern) {
    std::vector<std::string> matches;
    glob_t g{};
    if (glob(pattern.c_str(), 0, nullptr, &g) == 0) {
        for (size_t i = 0; i < g.gl_pathc; ++i) {
            matches.emplace_back(g.gl_pathv[i]);
        }
    }
    globfree(&g);
    // OpenSSH's Include expands entries in sorted order.
    std::sort(matches.begin(), matches.end());
    return matches;
}

// Recursively walks `path` and any files it Includes, appending directives to
// `out` in encounter order (an Included file's directives land at the exact
// point its Include line occurred) and stopping the ENTIRE walk — not just
// the current file — the moment a top-level "Match" line is seen anywhere in
// the tree, matching real sshd where Match's conditional scope is not
// file-bound.
inline void collect_recursive(const std::string& path, std::set<std::string>& visited,
                              bool& match_hit, std::vector<Directive>& out) {
    if (match_hit)
        return;

    std::error_code ec;
    auto canon = std::filesystem::weakly_canonical(path, ec);
    std::string key = ec ? path : canon.string();
    if (visited.contains(key))
        return; // Include cycle guard
    visited.insert(key);

    bool existed = false;
    std::string content = read_file(path, existed);
    if (!existed)
        return;

    auto parsed = parse_sshd_config_content(content);

    std::string base_dir = "/etc/ssh";
    if (auto slash = path.find_last_of('/'); slash != std::string::npos) {
        base_dir = path.substr(0, slash);
    }

    for (const auto& entry : parsed.entries) {
        if (entry.kind == Entry::Kind::Directive) {
            out.push_back(entry.directive);
            continue;
        }
        // Entry::Kind::Include
        for (const auto& tok : entry.include_globs) {
            if (match_hit)
                break;
            auto resolved = resolve_include_path(tok, base_dir);
            for (const auto& match : glob_expand(resolved)) {
                if (match_hit)
                    break;
                collect_recursive(match, visited, match_hit, out);
            }
        }
        if (match_hit)
            break;
    }

    if (parsed.hit_match) {
        match_hit = true;
    }
}

} // namespace detail

// Reads /etc/ssh/sshd_config and every file it Includes, returning the
// flattened, in-order effective directive stream (everything before the
// first top-level Match block). Returns std::nullopt if sshd_config itself
// does not exist (host likely does not run an SSH server).
inline std::optional<std::vector<Directive>>
collect_effective_sshd_config(const std::string& root_path = "/etc/ssh/sshd_config") {
    if (!std::filesystem::exists(root_path))
        return std::nullopt;

    std::vector<Directive> out;
    std::set<std::string> visited;
    bool match_hit = false;
    detail::collect_recursive(root_path, visited, match_hit, out);
    return out;
}

#endif // __linux__

} // namespace yuzu::ssh_hardening
