/**
 * pii_scan_collect.hpp — Filesystem walking for the pii_scan plugin.
 *
 * Unlike ssh_hardening_collect.hpp (Linux-only glob semantics tied to
 * sshd_config's Include directive), directory walking here is genuinely
 * portable — std::filesystem::recursive_directory_iterator behaves the
 * same on all three OSes — so this header has no #ifdef platform guards.
 *
 * Scope, deliberately, for v1:
 *   - Plain-text and structured-text files only (extension allowlist).
 *     Binary document formats (PDF, DOCX, XLSX) need format-specific text
 *     extraction this plugin does not do — a real, disclosed limitation,
 *     not a silent gap. A future iteration could add those via a
 *     dedicated extraction library.
 *   - A per-file size cap (skip huge files rather than loading them whole
 *     into memory) and a per-scan file-count cap (bound the blast radius
 *     of one scan invocation, matching the "opt-in, throttled" precedent
 *     other Yuzu collectors follow, e.g. ADR-0015's capture sources).
 *   - Symlinks are not followed (avoids cycles and scanning outside the
 *     configured root unexpectedly).
 */
#pragma once

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_set>
#include <vector>

namespace yuzu::pii {

struct ScanConfig {
    std::vector<std::string> roots;
    std::unordered_set<std::string> extensions = {
        ".txt", ".csv", ".tsv", ".json", ".xml", ".yaml", ".yml", ".log",
        ".md",  ".sql", ".ini", ".conf", ".config", ".properties", ".env",
        ".html", ".htm", ".js",  ".py",  ".java", ".cs",  ".php",
    };
    bool scan_all_extensions = false; // overrides `extensions` — scan every file found
    uint64_t max_file_size_bytes = 10ull * 1024 * 1024; // 10 MB
    size_t max_files_per_scan = 10000;
};

struct CandidateFile {
    std::string path;
    uint64_t size_bytes = 0;
};

// Enumerates candidate files under all configured roots, applying the
// extension allowlist, size cap, and total-file-count cap. Symlinks are
// not followed. Errors on an individual entry (permission denied, races
// with a deleted file, etc.) are skipped rather than aborting the whole
// walk — a single unreadable file must not stop scanning the rest of a
// large tree.
inline std::vector<CandidateFile> enumerate_files(const ScanConfig& config) {
    std::vector<CandidateFile> out;

    for (const auto& root : config.roots) {
        if (out.size() >= config.max_files_per_scan)
            break;

        std::error_code ec;
        std::filesystem::recursive_directory_iterator it(
            root, std::filesystem::directory_options::skip_permission_denied, ec);
        std::filesystem::recursive_directory_iterator end;
        if (ec)
            continue; // root doesn't exist / not readable — skip, don't abort the whole scan

        for (; it != end && out.size() < config.max_files_per_scan; it.increment(ec)) {
            if (ec) {
                ec.clear();
                continue;
            }
            if (it->is_symlink(ec) || ec) {
                ec.clear();
                continue;
            }
            if (!it->is_regular_file(ec) || ec) {
                ec.clear();
                continue;
            }

            const std::filesystem::path& p = it->path();
            if (!config.scan_all_extensions) {
                std::string ext = p.extension().string();
                for (char& c : ext)
                    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                if (config.extensions.find(ext) == config.extensions.end())
                    continue;
            }

            uint64_t size = it->file_size(ec);
            if (ec) {
                ec.clear();
                continue;
            }
            if (size == 0 || size > config.max_file_size_bytes)
                continue;

            out.push_back(CandidateFile{p.string(), size});
        }
    }

    return out;
}

// Reads a file's full content as text (up to `max_bytes`). Returns
// nullopt on any I/O error rather than a partial/garbage read.
inline std::optional<std::string> read_file_text(const std::string& path, uint64_t max_bytes) {
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open())
        return std::nullopt;

    std::error_code ec;
    auto size = std::filesystem::file_size(path, ec);
    if (ec || size > max_bytes)
        return std::nullopt;

    std::ostringstream ss;
    ss << f.rdbuf();
    if (!f.good() && !f.eof())
        return std::nullopt;
    return ss.str();
}

} // namespace yuzu::pii
