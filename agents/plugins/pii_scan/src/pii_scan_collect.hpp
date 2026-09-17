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
 *   - Directory-exclusion list + a wall-clock walk deadline (below): the
 *     file-count/size caps bound OUTPUT, not walk cost — a tree full of
 *     non-matching entries (a large `node_modules`, a big media library)
 *     was walked in full regardless, with no way to observe or cancel it,
 *     and the SDK has no generic per-plugin execute() deadline to fall
 *     back on. Neither of these makes the walk provably bounded in the
 *     worst case (an operator-supplied root with no excluded directories
 *     and a huge flat file count can still run long) — the deadline is
 *     what actually caps worst-case wall time; the exclusion list is a
 *     cheap, high-value reduction in the common case (dev machines,
 *     servers) on top of it. `truncated_by_deadline` on the return value
 *     tells the caller when the walk stopped early so it can report an
 *     honest partial-completeness result instead of a false "clean".
 */
#pragma once

#include <cctype>
#include <chrono>
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
    // Directory (not path) names never descended into, regardless of
    // where they occur in the tree — checked against the directory
    // entry's own filename() component. Deliberately name-only (not a
    // full-path match): the same noise directories recur at arbitrary
    // depth in a real tree (nested node_modules, vendored .git checkouts).
    std::unordered_set<std::string> excluded_dir_names = {
        ".git", "node_modules", "__pycache__", ".venv", "venv",
        "$RECYCLE.BIN", "System Volume Information",
        ".Spotlight-V100", ".fseventsd", ".Trashes",
    };
    // Hard wall-clock ceiling on one enumerate_files() call, checked
    // periodically (not per-entry, to avoid a clock syscall per file) —
    // see the header comment above for why the file-count/size caps
    // alone don't bound walk cost.
    std::chrono::milliseconds max_walk_duration{5 * 60 * 1000}; // 5 minutes
};

struct CandidateFile {
    std::string path;
    uint64_t size_bytes = 0;
};

struct EnumerateFilesResult {
    std::vector<CandidateFile> files;
    // True iff the walk stopped early because max_walk_duration elapsed
    // (as opposed to running every root to completion or hitting
    // max_files_per_scan, which is a normal, fully-enumerated stop). The
    // caller uses this to report an honest partial-completeness result
    // rather than a scan that looks clean but never finished looking.
    bool truncated_by_deadline = false;
};

// Enumerates candidate files under all configured roots, applying the
// directory-exclusion list, extension allowlist, size cap, total-file-
// count cap, and wall-clock deadline. Symlinks are not followed. Errors on
// an individual entry (permission denied, races with a deleted file, etc.)
// are skipped rather than aborting the whole walk — a single unreadable
// file must not stop scanning the rest of a large tree. A root that is
// itself a regular file (not a directory) is scanned directly as a single
// candidate, bypassing the extension allowlist -- an operator who names an
// exact file path is making an explicit choice the allowlist shouldn't
// silently veto; `recursive_directory_iterator` would otherwise fail
// outright on a non-directory root (ENOTDIR) and this whole root would be
// silently skipped, reporting "0 files, 0 findings" indistinguishable from
// a genuinely clean scan.
inline EnumerateFilesResult enumerate_files(const ScanConfig& config) {
    EnumerateFilesResult result;
    auto& out = result.files;
    const auto deadline = std::chrono::steady_clock::now() + config.max_walk_duration;
    // Checked every kClockCheckInterval entries visited (not every entry)
    // to keep the steady_clock read off the hot per-file path.
    constexpr int kClockCheckInterval = 256;
    int entries_since_clock_check = 0;

    auto deadline_exceeded = [&]() {
        if (++entries_since_clock_check < kClockCheckInterval)
            return false;
        entries_since_clock_check = 0;
        return std::chrono::steady_clock::now() >= deadline;
    };

    for (const auto& root : config.roots) {
        if (out.size() >= config.max_files_per_scan)
            break;
        if (std::chrono::steady_clock::now() >= deadline) {
            result.truncated_by_deadline = true;
            break;
        }

        std::error_code ec;
        if (std::filesystem::is_regular_file(root, ec) && !ec) {
            uint64_t size = std::filesystem::file_size(root, ec);
            if (!ec && size > 0 && size <= config.max_file_size_bytes)
                out.push_back(CandidateFile{root, size});
            continue;
        }
        ec.clear();

        std::filesystem::recursive_directory_iterator it(
            root, std::filesystem::directory_options::skip_permission_denied, ec);
        std::filesystem::recursive_directory_iterator end;
        if (ec)
            continue; // root doesn't exist / not readable — skip, don't abort the whole scan

        for (; it != end && out.size() < config.max_files_per_scan; it.increment(ec)) {
            if (deadline_exceeded()) {
                result.truncated_by_deadline = true;
                break;
            }
            if (ec) {
                ec.clear();
                continue;
            }
            if (it->is_symlink(ec) || ec) {
                ec.clear();
                continue;
            }

            bool is_dir = it->is_directory(ec);
            if (ec) {
                ec.clear();
                continue;
            }
            if (is_dir) {
                if (config.excluded_dir_names.count(it->path().filename().string()) > 0)
                    it.disable_recursion_pending();
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
        if (result.truncated_by_deadline)
            break;
    }

    return result;
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
