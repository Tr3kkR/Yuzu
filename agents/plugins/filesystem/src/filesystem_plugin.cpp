/**
 * filesystem_plugin.cpp — Filesystem operations plugin for Yuzu
 *
 * Actions:
 *   "exists"          — Check if a path exists, report type and size.
 *   "list_dir"        — List directory contents (max 1000 entries).
 *   "file_hash"       — Compute SHA-256 (or SHA-1) hash of a file.
 *   "create_temp"     — Create a secure temporary file (mode 0600 / owner-only DACL).
 *   "create_temp_dir" — Create a secure temporary directory (mode 0700 / owner-only DACL).
 *   "search_dir"      — Find directories/files by name pattern (glob/regex).
 *   "get_version_info" — Extract PE version resource info (Windows only).
 *   "search"          — Search file contents for a pattern.
 *   "replace"         — Find/replace text in a file (atomic write).
 *   "write_content"   — Write or overwrite file contents.
 *   "append"          — Append content to a file.
 *   "delete_lines"    — Delete a range of lines from a file.
 *
 * Security:
 *   - All paths are canonicalized via std::filesystem::canonical() to
 *     resolve symlinks and prevent traversal attacks.
 *   - An optional base_dir parameter restricts access to a subtree.
 *   - Temp files use mkstemps() (POSIX) / CreateFile+CREATE_NEW (Windows)
 *     with restrictive permissions to prevent TOCTOU races.
 *   - Write operations use atomic temp+rename to prevent partial writes.
 *   - This plugin requires admin role on the server side.
 *
 * Output is pipe-delimited via write_output():
 *   exists|true/false, type|file/directory/other, size|N
 *   entry|name|type|size
 *   hash|HEXSTRING, algorithm|sha256, size|N
 *   path|/tmp/yuzu-XXXXXX.tmp, persist|true/false
 */

#include <yuzu/plugin.hpp>

#include <algorithm>
#include <array>
#include <cstdio>
#include <filesystem>
#include <format>
#include <fstream>
#include <regex>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
// clang-format off
#include <windows.h>  // must precede bcrypt.h (defines NTSTATUS)
// clang-format on
#include <aclapi.h>
#include <bcrypt.h>
#include <sddl.h>
#include <softpub.h>
#include <wintrust.h>
#include <winver.h>
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "version.lib")
#else
#include <sys/stat.h>
#include <sys/wait.h>
#include <grp.h>
#include <pwd.h>
#include <unistd.h>
#endif

namespace {

namespace fs = std::filesystem;

// Maximum file size for hashing (10 GB)
constexpr std::uintmax_t kMaxHashFileSize = 10ULL * 1024 * 1024 * 1024;

// ── Path validation ─────────────────────────────────────────────────────

// Canonicalize a path and optionally enforce a base directory restriction.
// Returns empty string on failure (path doesn't exist, escapes base_dir, etc.)
std::string validate_path(std::string_view raw_path, std::string_view base_dir) {
    if (raw_path.empty())
        return {};

    std::error_code ec;
    std::string path_str{raw_path};

    // First check the path exists (canonical requires it to exist)
    if (!fs::exists(path_str, ec))
        return {};

    // Resolve all symlinks and normalize the path
    auto canonical = fs::canonical(path_str, ec);
    if (ec)
        return {};

    // If a base_dir is configured, ensure the canonical path is within it
    if (!base_dir.empty()) {
        auto canonical_base = fs::canonical(std::string{base_dir}, ec);
        if (ec)
            return {};

        auto canon_str = canonical.string();
        auto base_str = canonical_base.string();

        // Ensure the canonical path starts with the base directory
        if (canon_str.size() < base_str.size() ||
            canon_str.compare(0, base_str.size(), base_str) != 0) {
            return {};
        }
        // Ensure it's not just a prefix match on a directory name
        // e.g., /var/log vs /var/logbackup
        if (canon_str.size() > base_str.size() && canon_str[base_str.size()] != '/' &&
            canon_str[base_str.size()] != '\\') {
            return {};
        }
    }

    return canonical.string();
}

// For paths that might not exist yet (exists check), validate the parent
std::string validate_path_or_parent(std::string_view raw_path, std::string_view base_dir) {
    if (raw_path.empty())
        return {};

    std::error_code ec;
    std::string path_str{raw_path};

    // If it exists, do full validation
    if (fs::exists(path_str, ec)) {
        return validate_path(raw_path, base_dir);
    }

    // For non-existent paths, validate the parent directory
    auto parent = fs::path(path_str).parent_path();
    if (parent.empty() || !fs::exists(parent, ec))
        return {};

    auto canonical_parent = fs::canonical(parent, ec);
    if (ec)
        return {};

    if (!base_dir.empty()) {
        auto canonical_base = fs::canonical(std::string{base_dir}, ec);
        if (ec)
            return {};

        auto parent_str = canonical_parent.string();
        auto base_str = canonical_base.string();

        if (parent_str.size() < base_str.size() ||
            parent_str.compare(0, base_str.size(), base_str) != 0) {
            return {};
        }
        if (parent_str.size() > base_str.size() && parent_str[base_str.size()] != '/' &&
            parent_str[base_str.size()] != '\\') {
            return {};
        }
    }

    // Return the original path (parent is validated, file just doesn't exist)
    return path_str;
}

#ifdef _WIN32

std::string compute_hash_win(const std::string& path, std::string_view algorithm) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    LPCWSTR alg_id = BCRYPT_SHA256_ALGORITHM;

    if (algorithm == "sha1") {
        alg_id = BCRYPT_SHA1_ALGORITHM;
    }

    if (BCryptOpenAlgorithmProvider(&alg, alg_id, nullptr, 0) != 0) {
        return {};
    }

    DWORD hash_length = 0;
    DWORD result_size = 0;
    BCryptGetProperty(alg, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hash_length),
                      sizeof(hash_length), &result_size, 0);

    DWORD object_length = 0;
    BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&object_length),
                      sizeof(object_length), &result_size, 0);

    std::vector<UCHAR> hash_object(object_length);
    std::vector<UCHAR> hash_value(hash_length);

    if (BCryptCreateHash(alg, &hash, hash_object.data(), object_length, nullptr, 0, 0) != 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return {};
    }

    // Read file in chunks
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs.is_open()) {
        BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(alg, 0);
        return {};
    }

    std::array<char, 8192> buf{};
    while (ifs.read(buf.data(), static_cast<std::streamsize>(buf.size())) || ifs.gcount() > 0) {
        BCryptHashData(hash, reinterpret_cast<PUCHAR>(buf.data()), static_cast<ULONG>(ifs.gcount()),
                       0);
        if (ifs.eof())
            break;
    }

    BCryptFinishHash(hash, hash_value.data(), hash_length, 0);
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);

    // Convert to hex
    std::string hex;
    hex.reserve(hash_length * 2);
    for (DWORD i = 0; i < hash_length; ++i) {
        hex += std::format("{:02x}", hash_value[i]);
    }
    return hex;
}

#else

std::string compute_hash_unix(const std::string& path, std::string_view algorithm) {
    // Use execvp-based approach to avoid shell injection via path
    int pipe_fd[2];
    if (pipe(pipe_fd) != 0)
        return {};

    pid_t pid = fork();
    if (pid < 0) {
        close(pipe_fd[0]);
        close(pipe_fd[1]);
        return {};
    }

    if (pid == 0) {
        close(pipe_fd[0]);
        dup2(pipe_fd[1], STDOUT_FILENO);
        close(pipe_fd[1]);

#ifdef __APPLE__
        if (algorithm == "sha1") {
            execlp("shasum", "shasum", "-a", "1", path.c_str(), nullptr);
        } else {
            execlp("shasum", "shasum", "-a", "256", path.c_str(), nullptr);
        }
#else
        if (algorithm == "sha1") {
            execlp("sha1sum", "sha1sum", path.c_str(), nullptr);
        } else {
            execlp("sha256sum", "sha256sum", path.c_str(), nullptr);
        }
#endif
        _exit(127);
    }

    close(pipe_fd[1]);

    std::string result;
    std::array<char, 256> buf{};
    ssize_t n;
    while ((n = read(pipe_fd[0], buf.data(), buf.size())) > 0) {
        result.append(buf.data(), static_cast<size_t>(n));
    }
    close(pipe_fd[0]);

    int status = 0;
    waitpid(pid, &status, 0);

    while (!result.empty() && (result.back() == '\n' || result.back() == '\r')) {
        result.pop_back();
    }

    // Output format: "HASH  filename" or "HASH filename"
    auto space = result.find(' ');
    if (space != std::string::npos) {
        return result.substr(0, space);
    }
    return result;
}

#endif

// ── Regex safety check ─────────────────────────────────────────────────
// Reject patterns with nested quantifiers that cause catastrophic backtracking.
bool has_nested_quantifiers(std::string_view pattern) {
    // Detect (X+)+, (X*)+, (X+)*, (X*)* and similar nested quantifier patterns
    int paren_depth = 0;
    bool last_was_quantifier = false;
    for (size_t i = 0; i < pattern.size(); ++i) {
        char c = pattern[i];
        if (c == '\\' && i + 1 < pattern.size()) { ++i; last_was_quantifier = false; continue; }
        if (c == '(') { ++paren_depth; last_was_quantifier = false; continue; }
        if (c == ')') {
            --paren_depth;
            // If closing paren follows a quantifier and is itself followed by a quantifier
            if (i + 1 < pattern.size() && last_was_quantifier) {
                char next = pattern[i + 1];
                if (next == '+' || next == '*' || next == '?' || next == '{')
                    return true;
            }
            last_was_quantifier = false;
            continue;
        }
        last_was_quantifier = (c == '+' || c == '*' || c == '?' ||
                               (c == '}' && pattern.substr(0, i).rfind('{') != std::string_view::npos));
    }
    return false;
}

// ── Glob pattern matching ──────────────────────────────────────────────
// Simple glob matcher: * matches any chars, ? matches one char, [abc] char class.
bool glob_match(std::string_view pattern, std::string_view text) {
    size_t px = 0, tx = 0;
    size_t star_px = std::string_view::npos, star_tx = 0;

    while (tx < text.size()) {
        if (px < pattern.size() && (pattern[px] == '?' ||
            (pattern[px] != '*' && pattern[px] != '[' && (pattern[px] == text[tx])))) {
            ++px; ++tx;
        } else if (px < pattern.size() && pattern[px] == '[') {
            ++px;
            bool negate = (px < pattern.size() && pattern[px] == '!');
            if (negate) ++px;
            bool matched = false;
            while (px < pattern.size() && pattern[px] != ']') {
                if (px + 2 < pattern.size() && pattern[px + 1] == '-') {
                    if (text[tx] >= pattern[px] && text[tx] <= pattern[px + 2])
                        matched = true;
                    px += 3;
                } else {
                    if (text[tx] == pattern[px]) matched = true;
                    ++px;
                }
            }
            if (px < pattern.size()) ++px; // skip ']'
            if (matched == negate) {
                if (star_px != std::string_view::npos) { px = star_px + 1; tx = ++star_tx; }
                else return false;
            } else { ++tx; }
        } else if (px < pattern.size() && pattern[px] == '*') {
            star_px = px; star_tx = tx; ++px;
        } else if (star_px != std::string_view::npos) {
            px = star_px + 1; tx = ++star_tx;
        } else {
            return false;
        }
    }
    while (px < pattern.size() && pattern[px] == '*') ++px;
    return px == pattern.size();
}

// ── Atomic file write helper ───────────────────────────────────────────
// Write content to a temp file in the same directory, then rename.
bool atomic_write_file(const fs::path& target, std::string_view content) {
    auto dir = target.parent_path();
    auto tmp = dir / (target.filename().string() + ".yuzu_tmp");
    {
        std::ofstream ofs(tmp, std::ios::binary | std::ios::trunc);
        if (!ofs) return false;
        ofs.write(content.data(), static_cast<std::streamsize>(content.size()));
        if (!ofs) { std::error_code ec; fs::remove(tmp, ec); return false; }
    }
    std::error_code ec;
#ifdef _WIN32
    // On Windows, fs::rename may fail if target is open; try ReplaceFile first
    std::wstring wold, wnew;
    {
        auto s = tmp.string();
        int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
        wold.resize(static_cast<size_t>(len));
        MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, wold.data(), len);
    }
    {
        auto s = target.string();
        int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
        wnew.resize(static_cast<size_t>(len));
        MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, wnew.data(), len);
    }
    if (fs::exists(target, ec)) {
        if (ReplaceFileW(wnew.c_str(), wold.c_str(), nullptr, 0, nullptr, nullptr))
            return true;
    }
#endif
    fs::rename(tmp, target, ec);
    if (ec) { fs::remove(tmp, ec); return false; }
    return true;
}

} // namespace

class FilesystemPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "filesystem"; }
    std::string_view version() const noexcept override { return "0.4.0"; }
    std::string_view description() const noexcept override {
        return "Filesystem operations — exists, list_dir, file_hash, search_dir, text ops "
               "(admin-only)";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"exists",          "list_dir",        "file_hash",
                                     "create_temp",     "create_temp_dir", "read",
                                     "get_acl",         "get_signature",   "find_by_hash",
                                     "search_dir",      "get_version_info",
                                     "search",          "replace",         "write_content",
                                     "append",          "delete_lines",    nullptr};
        return acts;
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override { return {}; }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action, yuzu::Params params) override {
        if (action == "exists") {
            return do_exists(ctx, params);
        }
        if (action == "list_dir") {
            return do_list_dir(ctx, params);
        }
        if (action == "file_hash") {
            return do_file_hash(ctx, params);
        }
        if (action == "create_temp") {
            return do_create_temp(ctx, params);
        }
        if (action == "create_temp_dir") {
            return do_create_temp_dir(ctx, params);
        }
        if (action == "read") {
            return do_read(ctx, params);
        }
        if (action == "get_acl") {
            return do_get_acl(ctx, params);
        }
        if (action == "get_signature") {
            return do_get_signature(ctx, params);
        }
        if (action == "find_by_hash") {
            return do_find_by_hash(ctx, params);
        }
        if (action == "search_dir") {
            return do_search_dir(ctx, params);
        }
        if (action == "get_version_info") {
            return do_get_version_info(ctx, params);
        }
        if (action == "search") {
            return do_search(ctx, params);
        }
        if (action == "replace") {
            return do_replace(ctx, params);
        }
        if (action == "write_content") {
            return do_write_content(ctx, params);
        }
        if (action == "append") {
            return do_append(ctx, params);
        }
        if (action == "delete_lines") {
            return do_delete_lines(ctx, params);
        }

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }

private:
    int do_exists(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto path = params.get("path");
        if (path.empty()) {
            ctx.write_output("error|missing required parameter: path");
            return 1;
        }

        auto base_dir = params.get("base_dir");

        // For exists check, use validate_path_or_parent (path may not exist)
        auto validated = validate_path_or_parent(path, base_dir);
        if (validated.empty() && !base_dir.empty()) {
            ctx.write_output("error|path is outside allowed base directory");
            return 1;
        }

        std::error_code ec;
        std::string path_str = validated.empty() ? std::string{path} : validated;
        bool exists = fs::exists(path_str, ec);
        ctx.write_output(std::format("exists|{}", exists ? "true" : "false"));

        if (exists) {
            // Re-validate with canonical now that we know it exists
            auto canon = validate_path(path, base_dir);
            if (canon.empty() && !base_dir.empty()) {
                ctx.write_output("error|path resolves outside allowed base directory");
                return 1;
            }
            auto& check_path = canon.empty() ? path_str : canon;

            if (fs::is_regular_file(check_path, ec)) {
                ctx.write_output("type|file");
                auto sz = fs::file_size(check_path, ec);
                ctx.write_output(std::format("size|{}", ec ? 0 : sz));
            } else if (fs::is_directory(check_path, ec)) {
                ctx.write_output("type|directory");
                ctx.write_output("size|0");
            } else {
                ctx.write_output("type|other");
                ctx.write_output("size|0");
            }
        }
        return 0;
    }

    int do_list_dir(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto path = params.get("path");
        if (path.empty()) {
            ctx.write_output("error|missing required parameter: path");
            return 1;
        }

        auto base_dir = params.get("base_dir");
        auto validated = validate_path(path, base_dir);
        if (validated.empty()) {
            ctx.write_output("error|path is not accessible or outside allowed base directory");
            return 1;
        }

        std::error_code ec;
        if (!fs::is_directory(validated, ec)) {
            ctx.write_output("error|path is not a directory or does not exist");
            return 1;
        }

        int count = 0;
        constexpr int max_entries = 1000;

        for (auto it = fs::directory_iterator(validated, ec);
             it != fs::directory_iterator() && count < max_entries; it.increment(ec)) {
            if (ec)
                continue;

            const auto& entry = *it;
            std::string entry_name = entry.path().filename().string();
            std::string entry_type = "other";
            std::uintmax_t entry_size = 0;

            std::error_code entry_ec;
            if (entry.is_regular_file(entry_ec)) {
                entry_type = "file";
                entry_size = entry.file_size(entry_ec);
                if (entry_ec)
                    entry_size = 0;
            } else if (entry.is_directory(entry_ec)) {
                entry_type = "directory";
            } else if (entry.is_symlink(entry_ec)) {
                entry_type = "symlink";
            }

            ctx.write_output(std::format("entry|{}|{}|{}", entry_name, entry_type, entry_size));
            ++count;
        }

        if (count >= max_entries) {
            ctx.write_output("warning|output truncated at 1000 entries");
        }
        return 0;
    }

    int do_file_hash(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto path = params.get("path");
        if (path.empty()) {
            ctx.write_output("error|missing required parameter: path");
            return 1;
        }

        auto base_dir = params.get("base_dir");
        auto validated = validate_path(path, base_dir);
        if (validated.empty()) {
            ctx.write_output("error|path is not accessible or outside allowed base directory");
            return 1;
        }

        auto algorithm = params.get("algorithm", "sha256");
        std::string algo_str{algorithm};

        // Validate algorithm
        if (algo_str != "sha256" && algo_str != "sha1") {
            ctx.write_output(std::format("error|unsupported algorithm: {}", algo_str));
            return 1;
        }

        std::error_code ec;
        if (!fs::is_regular_file(validated, ec)) {
            ctx.write_output("error|path is not a regular file or does not exist");
            return 1;
        }

        auto file_size = fs::file_size(validated, ec);
        if (ec)
            file_size = 0;

        if (file_size > kMaxHashFileSize) {
            ctx.write_output(std::format("error|file too large for hashing ({} bytes, max {})",
                                         file_size, kMaxHashFileSize));
            return 1;
        }

#ifdef _WIN32
        auto hash = compute_hash_win(validated, algo_str);
#else
        auto hash = compute_hash_unix(validated, algo_str);
#endif

        if (hash.empty()) {
            ctx.write_output("error|failed to compute hash");
            return 1;
        }

        ctx.write_output(std::format("hash|{}", hash));
        ctx.write_output(std::format("algorithm|{}", algo_str));
        ctx.write_output(std::format("size|{}", file_size));
        return 0;
    }

    int do_create_temp(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto prefix = params.get("prefix", "yuzu-");
        auto suffix = params.get("suffix", ".tmp");
        auto directory = params.get("directory");
        auto persist = params.get("persist", "true");

        // Validate directory if provided
        if (!directory.empty()) {
            auto validated = validate_path(directory, {});
            if (validated.empty()) {
                ctx.write_output("error|directory does not exist or is not accessible");
                return 1;
            }
            std::error_code ec;
            if (!fs::is_directory(validated, ec)) {
                ctx.write_output("error|specified directory is not a directory");
                return 1;
            }
        }

        char path_buf[512]{};
        int rc = yuzu_create_temp_file(std::string{prefix}.c_str(), std::string{suffix}.c_str(),
                                       directory.empty() ? nullptr : std::string{directory}.c_str(),
                                       path_buf, sizeof(path_buf));

        if (rc != 0) {
            ctx.write_output("error|failed to create temporary file");
            return 1;
        }

        ctx.write_output(std::format("path|{}", path_buf));
        ctx.write_output(std::format("persist|{}", persist));

        // If not persistent, delete the file when this action completes
        if (persist != "true") {
            std::error_code ec;
            fs::remove(path_buf, ec);
            ctx.write_output("cleanup|deleted");
        }

        return 0;
    }

    int do_read(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto path = params.get("path");
        if (path.empty()) {
            ctx.write_output("error|missing required parameter: path");
            return 1;
        }

        auto base_dir = params.get("base_dir");
        auto validated = validate_path(path, base_dir);
        if (validated.empty()) {
            ctx.write_output("error|path is not accessible or outside allowed base directory");
            return 1;
        }

        std::error_code ec;
        if (!fs::is_regular_file(validated, ec)) {
            ctx.write_output("error|path is not a regular file");
            return 1;
        }

        auto file_size = fs::file_size(validated, ec);
        if (ec)
            file_size = 0;

        // Cap at 100 MB
        constexpr std::uintmax_t kMaxReadSize = 100ULL * 1024 * 1024;
        if (file_size > kMaxReadSize) {
            ctx.write_output(
                std::format("error|file too large ({} bytes, max {})", file_size, kMaxReadSize));
            return 1;
        }

        // Parse offset and limit
        int offset = 1; // 1-based line number
        int limit = 100;
        constexpr int kMaxLimit = 10000;

        auto offset_str = params.get("offset");
        if (!offset_str.empty()) {
            try {
                offset = std::stoi(std::string{offset_str});
            } catch (...) {
                offset = 1;
            }
            if (offset < 1)
                offset = 1;
        }

        auto limit_str = params.get("limit");
        if (!limit_str.empty()) {
            try {
                limit = std::stoi(std::string{limit_str});
            } catch (...) {
                limit = 100;
            }
            if (limit < 1)
                limit = 1;
            if (limit > kMaxLimit)
                limit = kMaxLimit;
        }

        // Binary detection: probe first 512 bytes for NUL
        {
            std::ifstream probe(validated, std::ios::binary);
            char buf[512]{};
            probe.read(buf, sizeof(buf));
            auto bytes_read = probe.gcount();
            for (std::streamsize i = 0; i < bytes_read; ++i) {
                if (buf[i] == '\0') {
                    ctx.write_output("error|file appears to be binary");
                    return 1;
                }
            }
        }

        // Read lines with offset and limit
        std::ifstream f(validated);
        if (!f) {
            ctx.write_output("error|failed to open file");
            return 1;
        }

        std::string line;
        int line_num = 0;
        int collected = 0;
        int total_lines = 0;

        while (std::getline(f, line)) {
            ++line_num;
            ++total_lines;

            if (line_num < offset)
                continue;
            if (collected >= limit) {
                // Keep counting total lines
                while (std::getline(f, line))
                    ++total_lines;
                break;
            }

            // Strip trailing \r for CRLF
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }

            ctx.write_output(std::format("line|{}|{}", line_num, line));
            ++collected;
        }

        ctx.write_output(std::format("total_lines|{}", total_lines));
        ctx.write_output(std::format("file_size|{}", file_size));
        return 0;
    }

    int do_create_temp_dir(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto prefix = params.get("prefix", "yuzu-");
        auto directory = params.get("directory");
        auto persist = params.get("persist", "true");

        if (!directory.empty()) {
            auto validated = validate_path(directory, {});
            if (validated.empty()) {
                ctx.write_output("error|directory does not exist or is not accessible");
                return 1;
            }
            std::error_code ec;
            if (!fs::is_directory(validated, ec)) {
                ctx.write_output("error|specified directory is not a directory");
                return 1;
            }
        }

        char path_buf[512]{};
        int rc = yuzu_create_temp_dir(std::string{prefix}.c_str(),
                                      directory.empty() ? nullptr : std::string{directory}.c_str(),
                                      path_buf, sizeof(path_buf));

        if (rc != 0) {
            ctx.write_output("error|failed to create temporary directory");
            return 1;
        }

        ctx.write_output(std::format("path|{}", path_buf));
        ctx.write_output(std::format("persist|{}", persist));

        if (persist != "true") {
            std::error_code ec;
            fs::remove_all(path_buf, ec);
            ctx.write_output("cleanup|deleted");
        }

        return 0;
    }

    // ── get_acl: Return file/directory ACL permissions ────────────────────

    int do_get_acl(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto path = params.get("path");
        if (path.empty()) {
            ctx.write_output("error|missing required parameter: path");
            return 1;
        }

        auto base_dir = params.get("base_dir");
        auto validated = validate_path(path, base_dir);
        if (validated.empty()) {
            ctx.write_output("error|path is not accessible or outside allowed base directory");
            return 1;
        }

#ifdef _WIN32
        // Windows: Use GetNamedSecurityInfo to retrieve the DACL
        PSECURITY_DESCRIPTOR sd = nullptr;
        PACL dacl = nullptr;
        std::wstring wpath;
        {
            std::string p = validated;
            int len = MultiByteToWideChar(CP_UTF8, 0, p.c_str(), -1, nullptr, 0);
            wpath.resize(static_cast<size_t>(len));
            MultiByteToWideChar(CP_UTF8, 0, p.c_str(), -1, wpath.data(), len);
        }

        DWORD result = GetNamedSecurityInfoW(
            wpath.c_str(), SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            nullptr, nullptr, &dacl, nullptr, &sd);

        if (result != ERROR_SUCCESS) {
            ctx.write_output(std::format("error|GetNamedSecurityInfo failed (error {})", result));
            return 1;
        }

        // Convert security descriptor to SDDL string for readable output
        LPSTR sddl_str = nullptr;
        if (ConvertSecurityDescriptorToStringSecurityDescriptorA(
                sd, SDDL_REVISION_1,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &sddl_str, nullptr)) {
            ctx.write_output(std::format("sddl|{}", sddl_str));
            LocalFree(sddl_str);
        }

        // Enumerate individual ACEs
        if (dacl) {
            ACL_SIZE_INFORMATION acl_info{};
            if (GetAclInformation(dacl, &acl_info, sizeof(acl_info), AclSizeInformation)) {
                for (DWORD i = 0; i < acl_info.AceCount; ++i) {
                    LPVOID ace = nullptr;
                    if (!GetAce(dacl, i, &ace)) continue;

                    auto* header = static_cast<ACE_HEADER*>(ace);
                    std::string ace_type =
                        (header->AceType == ACCESS_ALLOWED_ACE_TYPE) ? "allow" :
                        (header->AceType == ACCESS_DENIED_ACE_TYPE)  ? "deny"  : "other";

                    PSID sid = nullptr;
                    ACCESS_MASK mask = 0;
                    if (header->AceType == ACCESS_ALLOWED_ACE_TYPE) {
                        auto* a = static_cast<ACCESS_ALLOWED_ACE*>(ace);
                        sid = &a->SidStart;
                        mask = a->Mask;
                    } else if (header->AceType == ACCESS_DENIED_ACE_TYPE) {
                        auto* a = static_cast<ACCESS_DENIED_ACE*>(ace);
                        sid = &a->SidStart;
                        mask = a->Mask;
                    }

                    if (sid) {
                        char name[256]{}, domain[256]{};
                        DWORD name_len = sizeof(name), domain_len = sizeof(domain);
                        SID_NAME_USE use;
                        std::string account;
                        if (LookupAccountSidA(nullptr, sid, name, &name_len,
                                              domain, &domain_len, &use)) {
                            account = std::format("{}\\{}", domain, name);
                        } else {
                            LPSTR sid_str = nullptr;
                            if (ConvertSidToStringSidA(sid, &sid_str)) {
                                account = sid_str;
                                LocalFree(sid_str);
                            }
                        }
                        ctx.write_output(std::format("ace|{}|{}|0x{:08x}", ace_type, account, mask));
                    }
                }
            }
        }

        LocalFree(sd);
        return 0;

#else
        // Linux/macOS: Use stat() for basic POSIX permissions
        struct stat st{};
        if (stat(validated.c_str(), &st) != 0) {
            ctx.write_output("error|stat failed");
            return 1;
        }

        // Owner info
        struct passwd* pw = getpwuid(st.st_uid);
        struct group* gr = getgrgid(st.st_gid);
        ctx.write_output(std::format("owner|{}", pw ? pw->pw_name : std::to_string(st.st_uid)));
        ctx.write_output(std::format("group|{}", gr ? gr->gr_name : std::to_string(st.st_gid)));

        // Permission string
        auto perm_char = [](mode_t mode, mode_t bit, char c) { return (mode & bit) ? c : '-'; };
        std::string perms;
        perms += perm_char(st.st_mode, S_IRUSR, 'r');
        perms += perm_char(st.st_mode, S_IWUSR, 'w');
        perms += perm_char(st.st_mode, S_IXUSR, 'x');
        perms += perm_char(st.st_mode, S_IRGRP, 'r');
        perms += perm_char(st.st_mode, S_IWGRP, 'w');
        perms += perm_char(st.st_mode, S_IXGRP, 'x');
        perms += perm_char(st.st_mode, S_IROTH, 'r');
        perms += perm_char(st.st_mode, S_IWOTH, 'w');
        perms += perm_char(st.st_mode, S_IXOTH, 'x');

        ctx.write_output(std::format("permissions|{}", perms));
        ctx.write_output(std::format("mode|{:04o}", st.st_mode & 07777));
        return 0;
#endif
    }

    // ── get_signature: Check Authenticode signature (Windows only) ────────

    int do_get_signature(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto path = params.get("path");
        if (path.empty()) {
            ctx.write_output("error|missing required parameter: path");
            return 1;
        }

        auto base_dir = params.get("base_dir");
        auto validated = validate_path(path, base_dir);
        if (validated.empty()) {
            ctx.write_output("error|path is not accessible or outside allowed base directory");
            return 1;
        }

#ifdef _WIN32
        // Convert path to wide string
        std::wstring wpath;
        {
            int len = MultiByteToWideChar(CP_UTF8, 0, validated.c_str(), -1, nullptr, 0);
            wpath.resize(static_cast<size_t>(len));
            MultiByteToWideChar(CP_UTF8, 0, validated.c_str(), -1, wpath.data(), len);
        }

        // Set up WINTRUST_FILE_INFO
        WINTRUST_FILE_INFO file_info{};
        file_info.cbStruct = sizeof(file_info);
        file_info.pcwszFilePath = wpath.c_str();

        // Set up WINTRUST_DATA
        GUID action_id = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        WINTRUST_DATA trust_data{};
        trust_data.cbStruct = sizeof(trust_data);
        trust_data.dwUIChoice = WTD_UI_NONE;
        trust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
        trust_data.dwUnionChoice = WTD_CHOICE_FILE;
        trust_data.pFile = &file_info;
        trust_data.dwStateAction = WTD_STATEACTION_VERIFY;
        trust_data.dwProvFlags = WTD_SAFER_FLAG;

        LONG status = WinVerifyTrust(
            static_cast<HWND>(INVALID_HANDLE_VALUE), &action_id, &trust_data);

        std::string sig_status;
        switch (status) {
        case ERROR_SUCCESS:
            sig_status = "valid";
            break;
        case TRUST_E_NOSIGNATURE:
            sig_status = "unsigned";
            break;
        case TRUST_E_EXPLICIT_DISTRUST:
            sig_status = "distrusted";
            break;
        case TRUST_E_SUBJECT_NOT_TRUSTED:
            sig_status = "untrusted";
            break;
        case CRYPT_E_SECURITY_SETTINGS:
            sig_status = "security_settings_blocked";
            break;
        default:
            sig_status = std::format("error_0x{:08x}", static_cast<unsigned long>(status));
            break;
        }

        ctx.write_output(std::format("signature_status|{}", sig_status));

        // Clean up the trust state
        trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &action_id, &trust_data);

        return 0;
#else
        ctx.write_output("error|Authenticode signature verification is not supported on this platform");
        return 1;
#endif
    }

    // ── search_dir: Find directories/files by name pattern ────────────────

    int do_search_dir(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto root = params.get("root");
        auto pattern = params.get("pattern");
        if (root.empty() || pattern.empty()) {
            ctx.write_output("error|missing required parameters: root, pattern");
            return 1;
        }

        auto base_dir = params.get("base_dir");
        auto validated = validate_path(root, base_dir);
        if (validated.empty()) {
            ctx.write_output("error|root is not accessible or outside allowed base directory");
            return 1;
        }

        std::error_code ec;
        if (!fs::is_directory(validated, ec)) {
            ctx.write_output("error|root is not a directory");
            return 1;
        }

        auto use_regex_str = params.get("regex", "false");
        bool use_regex = (use_regex_str == "true");
        auto match_type = params.get("match_type", "directories");

        int max_depth = 5;
        auto depth_str = params.get("max_depth", "5");
        try { max_depth = std::stoi(std::string{depth_str}); } catch (...) {}
        if (max_depth < 1) max_depth = 1;
        if (max_depth > 20) max_depth = 20;

        int max_results = 100;
        auto results_str = params.get("max_results", "100");
        try { max_results = std::stoi(std::string{results_str}); } catch (...) {}
        if (max_results < 1) max_results = 1;
        if (max_results > 1000) max_results = 1000;

        // Compile regex if requested
        std::regex re;
        if (use_regex) {
            std::string pat_str{pattern};
            if (pat_str.size() > 256) {
                ctx.write_output("error|pattern too long (max 256 chars)");
                return 1;
            }
            if (has_nested_quantifiers(pat_str)) {
                ctx.write_output("error|regex contains nested quantifiers (potential ReDoS)");
                return 1;
            }
            try {
                re = std::regex(pat_str, std::regex::ECMAScript | std::regex::optimize);
            } catch (const std::regex_error& e) {
                ctx.write_output(std::format("error|invalid regex: {}", e.what()));
                return 1;
            }
        }

        int found_count = 0;
        auto base_depth = std::count(validated.begin(), validated.end(), '/') +
                          std::count(validated.begin(), validated.end(), '\\');

        for (auto it = fs::recursive_directory_iterator(validated,
                 fs::directory_options::skip_permission_denied, ec);
             it != fs::recursive_directory_iterator() && found_count < max_results;
             it.increment(ec)) {
            if (ec) continue;

            const auto& entry = *it;
            auto entry_path = entry.path().string();
            auto depth = std::count(entry_path.begin(), entry_path.end(), '/') +
                         std::count(entry_path.begin(), entry_path.end(), '\\') - base_depth;
            if (depth > max_depth) {
                it.disable_recursion_pending();
                continue;
            }

            std::error_code fec;
            bool is_dir = entry.is_directory(fec);
            bool is_file = entry.is_regular_file(fec);

            if (match_type == "directories" && !is_dir) continue;
            if (match_type == "files" && !is_file) continue;
            if (match_type == "both" && !is_dir && !is_file) continue;

            auto name = entry.path().filename().string();
            bool matched = false;
            if (use_regex) {
                matched = std::regex_match(name, re);
            } else {
                matched = glob_match(pattern, name);
            }

            if (matched) {
                auto type_str = is_dir ? "directory" : "file";
                ctx.write_output(std::format("result|{}|{}", entry_path, type_str));
                ++found_count;
            }
        }

        ctx.write_output(std::format("total_matches|{}", found_count));
        return 0;
    }

    // ── get_version_info: Extract PE version resource (Windows) ─────────

    int do_get_version_info(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto path = params.get("path");
        if (path.empty()) {
            ctx.write_output("error|missing required parameter: path");
            return 1;
        }

        auto base_dir = params.get("base_dir");
        auto validated = validate_path(path, base_dir);
        if (validated.empty()) {
            ctx.write_output("error|path is not accessible or outside allowed base directory");
            return 1;
        }

#ifdef _WIN32
        // Convert to wide string
        std::wstring wpath;
        {
            int len = MultiByteToWideChar(CP_UTF8, 0, validated.c_str(), -1, nullptr, 0);
            wpath.resize(static_cast<size_t>(len));
            MultiByteToWideChar(CP_UTF8, 0, validated.c_str(), -1, wpath.data(), len);
        }

        DWORD dummy = 0;
        DWORD size = GetFileVersionInfoSizeW(wpath.c_str(), &dummy);
        if (size == 0) {
            ctx.write_output("error|no version info found in file");
            return 1;
        }

        std::vector<BYTE> buf(size);
        if (!GetFileVersionInfoW(wpath.c_str(), 0, size, buf.data())) {
            ctx.write_output("error|failed to read version info");
            return 1;
        }

        // Extract fixed version info
        VS_FIXEDFILEINFO* ffi = nullptr;
        UINT ffi_len = 0;
        if (VerQueryValueW(buf.data(), L"\\", reinterpret_cast<LPVOID*>(&ffi), &ffi_len) && ffi) {
            ctx.write_output(std::format("file_version|{}.{}.{}.{}",
                HIWORD(ffi->dwFileVersionMS), LOWORD(ffi->dwFileVersionMS),
                HIWORD(ffi->dwFileVersionLS), LOWORD(ffi->dwFileVersionLS)));
            ctx.write_output(std::format("product_version|{}.{}.{}.{}",
                HIWORD(ffi->dwProductVersionMS), LOWORD(ffi->dwProductVersionMS),
                HIWORD(ffi->dwProductVersionLS), LOWORD(ffi->dwProductVersionLS)));
        }

        // Get translation table for string queries
        struct LangCodePage { WORD language; WORD code_page; };
        LangCodePage* trans = nullptr;
        UINT trans_len = 0;
        if (VerQueryValueW(buf.data(), L"\\VarFileInfo\\Translation",
                           reinterpret_cast<LPVOID*>(&trans), &trans_len) && trans) {
            auto lang = trans[0].language;
            auto cp = trans[0].code_page;

            auto query_string = [&](const wchar_t* name) -> std::string {
                auto sub_block = std::format(L"\\StringFileInfo\\{:04x}{:04x}\\{}", lang, cp, name);
                wchar_t* val = nullptr;
                UINT val_len = 0;
                if (VerQueryValueW(buf.data(), sub_block.c_str(),
                                   reinterpret_cast<LPVOID*>(&val), &val_len) && val && val_len > 0) {
                    int mb_len = WideCharToMultiByte(CP_UTF8, 0, val, -1, nullptr, 0, nullptr, nullptr);
                    std::string result(static_cast<size_t>(mb_len), '\0');
                    WideCharToMultiByte(CP_UTF8, 0, val, -1, result.data(), mb_len, nullptr, nullptr);
                    while (!result.empty() && result.back() == '\0') result.pop_back();
                    return result;
                }
                return {};
            };

            auto emit = [&](const char* key, const wchar_t* name) {
                auto val = query_string(name);
                if (!val.empty()) ctx.write_output(std::format("{}|{}", key, val));
            };

            emit("company_name", L"CompanyName");
            emit("file_description", L"FileDescription");
            emit("internal_name", L"InternalName");
            emit("original_filename", L"OriginalFilename");
            emit("product_name", L"ProductName");
            emit("legal_copyright", L"LegalCopyright");
        }

        return 0;
#else
        ctx.write_output("error|PE version info is only available on Windows");
        return 1;
#endif
    }

    // ── search: Search file contents for a pattern ──────────────────────

    int do_search(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto path = params.get("path");
        auto pattern = params.get("pattern");
        if (path.empty() || pattern.empty()) {
            ctx.write_output("error|missing required parameters: path, pattern");
            return 1;
        }

        auto base_dir = params.get("base_dir");
        auto validated = validate_path(path, base_dir);
        if (validated.empty()) {
            ctx.write_output("error|path is not accessible or outside allowed base directory");
            return 1;
        }

        std::error_code ec;
        if (!fs::is_regular_file(validated, ec)) {
            ctx.write_output("error|path is not a regular file");
            return 1;
        }

        auto file_size = fs::file_size(validated, ec);
        constexpr std::uintmax_t kMaxSearchSize = 100ULL * 1024 * 1024;
        if (file_size > kMaxSearchSize) {
            ctx.write_output(std::format("error|file too large ({} bytes, max {})", file_size, kMaxSearchSize));
            return 1;
        }

        bool use_regex = (params.get("regex", "false") == "true");
        bool case_sensitive = (params.get("case_sensitive", "true") == "true");
        int max_matches = 100;
        auto mm_str = params.get("max_matches", "100");
        try { max_matches = std::stoi(std::string{mm_str}); } catch (...) {}
        if (max_matches < 1) max_matches = 1;
        if (max_matches > 10000) max_matches = 10000;

        std::regex re;
        std::string pattern_str{pattern};
        if (pattern_str.size() > 256) {
            ctx.write_output("error|pattern too long (max 256 chars)");
            return 1;
        }

        if (use_regex) {
            if (has_nested_quantifiers(pattern_str)) {
                ctx.write_output("error|regex rejected: nested quantifiers risk catastrophic backtracking");
                return 1;
            }
            auto flags = std::regex::ECMAScript | std::regex::optimize;
            if (!case_sensitive) flags |= std::regex::icase;
            try {
                re = std::regex(pattern_str, flags);
            } catch (const std::regex_error& e) {
                ctx.write_output(std::format("error|invalid regex: {}", e.what()));
                return 1;
            }
        } else if (!case_sensitive) {
            std::transform(pattern_str.begin(), pattern_str.end(), pattern_str.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        }

        std::ifstream f(validated);
        if (!f) {
            ctx.write_output("error|failed to open file");
            return 1;
        }

        std::string line;
        int line_num = 0;
        int match_count = 0;
        while (std::getline(f, line) && match_count < max_matches) {
            ++line_num;
            if (!line.empty() && line.back() == '\r') line.pop_back();

            bool matched = false;
            if (use_regex) {
                matched = std::regex_search(line, re);
            } else {
                if (case_sensitive) {
                    matched = line.find(pattern_str) != std::string::npos;
                } else {
                    std::string lower = line;
                    std::transform(lower.begin(), lower.end(), lower.begin(),
                                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                    matched = lower.find(pattern_str) != std::string::npos;
                }
            }

            if (matched) {
                ctx.write_output(std::format("match|{}|{}", line_num, line));
                ++match_count;
            }
        }

        ctx.write_output(std::format("total_matches|{}", match_count));
        return 0;
    }

    // ── replace: Find/replace text in a file ────────────────────────────

    int do_replace(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto path = params.get("path");
        auto search_str = params.get("search");
        auto replacement = params.get("replacement");
        if (path.empty() || search_str.empty()) {
            ctx.write_output("error|missing required parameters: path, search");
            return 1;
        }

        auto base_dir = params.get("base_dir");
        auto validated = validate_path(path, base_dir);
        if (validated.empty()) {
            ctx.write_output("error|path is not accessible or outside allowed base directory");
            return 1;
        }

        std::error_code ec;
        if (!fs::is_regular_file(validated, ec)) {
            ctx.write_output("error|path is not a regular file");
            return 1;
        }

        auto file_size = fs::file_size(validated, ec);
        constexpr std::uintmax_t kMaxReplaceSize = 100ULL * 1024 * 1024;
        if (file_size > kMaxReplaceSize) {
            ctx.write_output(std::format("error|file too large ({} bytes, max {})", file_size, kMaxReplaceSize));
            return 1;
        }

        bool use_regex = (params.get("regex", "false") == "true");
        bool case_sensitive = (params.get("case_sensitive", "true") == "true");
        bool dry_run = (params.get("dry_run", "false") == "true");
        int max_replacements = 0; // 0 = unlimited
        auto mr_str = params.get("max_replacements", "0");
        try { max_replacements = std::stoi(std::string{mr_str}); } catch (...) {}

        // Read entire file
        std::ifstream f(validated, std::ios::binary);
        if (!f) { ctx.write_output("error|failed to open file"); return 1; }
        std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        f.close();

        auto size_before = content.size();
        int count = 0;
        std::string search_s{search_str};
        std::string replace_s{replacement};

        if (use_regex) {
            if (search_s.size() > 256) {
                ctx.write_output("error|pattern too long (max 256 chars)");
                return 1;
            }
            if (has_nested_quantifiers(search_s)) {
                ctx.write_output("error|regex rejected: nested quantifiers risk catastrophic backtracking");
                return 1;
            }
            auto flags = std::regex::ECMAScript | std::regex::optimize;
            if (!case_sensitive) flags |= std::regex::icase;
            std::regex re;
            try { re = std::regex(search_s, flags); }
            catch (const std::regex_error& e) {
                ctx.write_output(std::format("error|invalid regex: {}", e.what()));
                return 1;
            }

            if (max_replacements <= 0) {
                // Count matches first
                auto it = std::sregex_iterator(content.begin(), content.end(), re);
                auto end = std::sregex_iterator();
                count = static_cast<int>(std::distance(it, end));
                content = std::regex_replace(content, re, replace_s);
            } else {
                std::string result;
                auto it = std::sregex_iterator(content.begin(), content.end(), re);
                auto end = std::sregex_iterator();
                size_t last_pos = 0;
                for (; it != end && count < max_replacements; ++it, ++count) {
                    auto& m = *it;
                    result.append(content, last_pos, static_cast<size_t>(m.position()) - last_pos);
                    result.append(replace_s);
                    last_pos = static_cast<size_t>(m.position() + m.length());
                }
                result.append(content, last_pos, content.size() - last_pos);
                content = std::move(result);
            }
        } else {
            // Literal replace
            std::string haystack;
            std::string needle = search_s;
            if (!case_sensitive) {
                std::transform(needle.begin(), needle.end(), needle.begin(),
                               [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                // Build lowercase copy for case-insensitive searching
                haystack = content;
                std::transform(haystack.begin(), haystack.end(), haystack.begin(),
                               [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            }

            std::string result;
            size_t pos = 0;
            while (pos < content.size()) {
                size_t found = std::string::npos;
                // Search from current position
                if (case_sensitive) {
                    found = content.find(needle, pos);
                } else {
                    found = haystack.find(needle, pos);
                }

                if (found == std::string::npos) {
                    result.append(content, pos, content.size() - pos);
                    break;
                }

                if (max_replacements > 0 && count >= max_replacements) {
                    result.append(content, pos, content.size() - pos);
                    break;
                }

                result.append(content, pos, found - pos);
                result.append(replace_s);
                pos = found + search_s.size();
                ++count;
            }
            content = std::move(result);
        }

        if (!dry_run && count > 0) {
            if (!atomic_write_file(fs::path(validated), content)) {
                ctx.write_output("error|failed to write file");
                return 1;
            }
        }

        ctx.write_output(std::format("replacements_made|{}", count));
        ctx.write_output(std::format("file_size_before|{}", size_before));
        ctx.write_output(std::format("file_size_after|{}", content.size()));
        if (dry_run) ctx.write_output("dry_run|true");
        return 0;
    }

    // ── write_content: Write or overwrite file contents ─────────────────

    int do_write_content(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto path = params.get("path");
        auto content = params.get("content");
        if (path.empty()) {
            ctx.write_output("error|missing required parameter: path");
            return 1;
        }

        auto base_dir = params.get("base_dir");
        bool create = (params.get("create", "false") == "true");
        bool overwrite = (params.get("overwrite", "false") == "true");

        // Validate path FIRST (canonicalize + base_dir check) before
        // checking existence to prevent TOCTOU with symlinks.
        // Try validate_path (for existing files), fall back to
        // validate_path_or_parent (for new files).
        auto validated = validate_path(path, base_dir);
        bool exists = !validated.empty();
        if (!exists) {
            validated = validate_path_or_parent(path, base_dir);
            if (validated.empty()) {
                ctx.write_output("error|path is not accessible or outside allowed base directory");
                return 1;
            }
        }

        if (!exists && !create) {
            ctx.write_output("error|file does not exist and create=false");
            return 1;
        }
        if (exists && !overwrite) {
            ctx.write_output("error|file exists and overwrite=false");
            return 1;
        }

        constexpr size_t kMaxWriteSize = 100ULL * 1024 * 1024;
        if (content.size() > kMaxWriteSize) {
            ctx.write_output(std::format("error|content too large ({} bytes, max {})", content.size(), kMaxWriteSize));
            return 1;
        }

        if (exists) {
            if (!atomic_write_file(fs::path(validated), content)) {
                ctx.write_output("error|failed to write file");
                return 1;
            }
        } else {
            std::ofstream ofs(validated, std::ios::binary | std::ios::trunc);
            if (!ofs) { ctx.write_output("error|failed to create file"); return 1; }
            ofs.write(content.data(), static_cast<std::streamsize>(content.size()));
            if (!ofs) { ctx.write_output("error|write failed"); return 1; }
        }

        ctx.write_output("status|ok");
        ctx.write_output(std::format("bytes_written|{}", content.size()));
        ctx.write_output(std::format("path|{}", validated));
        return 0;
    }

    // ── append: Append content to a file ────────────────────────────────

    int do_append(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto path = params.get("path");
        auto content = params.get("content");
        if (path.empty()) {
            ctx.write_output("error|missing required parameter: path");
            return 1;
        }

        auto base_dir = params.get("base_dir");
        auto validated = validate_path(path, base_dir);
        if (validated.empty()) {
            ctx.write_output("error|path is not accessible or outside allowed base directory");
            return 1;
        }

        std::error_code ec;
        if (!fs::is_regular_file(validated, ec)) {
            ctx.write_output("error|path is not a regular file");
            return 1;
        }

        bool add_newline = (params.get("newline", "true") == "true");

        std::ofstream ofs(validated, std::ios::binary | std::ios::app);
        if (!ofs) {
            ctx.write_output("error|failed to open file for append");
            return 1;
        }

        size_t bytes = 0;

        // Check if file ends with newline
        if (add_newline) {
            auto file_size = fs::file_size(validated, ec);
            if (file_size > 0) {
                std::ifstream check(validated, std::ios::binary | std::ios::ate);
                check.seekg(-1, std::ios::end);
                char last = 0;
                check.get(last);
                if (last != '\n') {
                    ofs.put('\n');
                    ++bytes;
                }
            }
        }

        ofs.write(content.data(), static_cast<std::streamsize>(content.size()));
        bytes += content.size();

        if (!ofs) {
            ctx.write_output("error|append failed");
            return 1;
        }

        auto total_size = fs::file_size(validated, ec);
        ctx.write_output("status|ok");
        ctx.write_output(std::format("bytes_appended|{}", bytes));
        ctx.write_output(std::format("total_size|{}", ec ? 0 : total_size));
        return 0;
    }

    // ── delete_lines: Delete a range of lines from a file ───────────────

    int do_delete_lines(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto path = params.get("path");
        auto start_str = params.get("start_line");
        auto end_str = params.get("end_line");
        if (path.empty() || start_str.empty() || end_str.empty()) {
            ctx.write_output("error|missing required parameters: path, start_line, end_line");
            return 1;
        }

        auto base_dir = params.get("base_dir");
        auto validated = validate_path(path, base_dir);
        if (validated.empty()) {
            ctx.write_output("error|path is not accessible or outside allowed base directory");
            return 1;
        }

        std::error_code ec;
        if (!fs::is_regular_file(validated, ec)) {
            ctx.write_output("error|path is not a regular file");
            return 1;
        }

        auto file_size = fs::file_size(validated, ec);
        constexpr std::uintmax_t kMaxSize = 100ULL * 1024 * 1024;
        if (file_size > kMaxSize) {
            ctx.write_output(std::format("error|file too large ({} bytes, max {})", file_size, kMaxSize));
            return 1;
        }

        int start_line = 0, end_line = 0;
        try { start_line = std::stoi(std::string{start_str}); } catch (...) {}
        try { end_line = std::stoi(std::string{end_str}); } catch (...) {}
        if (start_line < 1 || end_line < start_line) {
            ctx.write_output("error|invalid line range (1-based, start <= end)");
            return 1;
        }

        // Read all lines
        std::ifstream f(validated);
        if (!f) { ctx.write_output("error|failed to open file"); return 1; }
        std::vector<std::string> lines;
        std::string line;
        while (std::getline(f, line)) {
            lines.push_back(std::move(line));
        }
        f.close();

        int total_before = static_cast<int>(lines.size());
        if (start_line > total_before) {
            ctx.write_output("error|start_line beyond end of file");
            return 1;
        }

        // Clamp end_line
        if (end_line > total_before) end_line = total_before;

        int deleted = end_line - start_line + 1;
        lines.erase(lines.begin() + (start_line - 1), lines.begin() + end_line);

        // Rebuild content
        std::string content;
        for (size_t i = 0; i < lines.size(); ++i) {
            content += lines[i];
            if (i + 1 < lines.size()) content += '\n';
        }
        if (!lines.empty()) content += '\n'; // trailing newline

        if (!atomic_write_file(fs::path(validated), content)) {
            ctx.write_output("error|failed to write file");
            return 1;
        }

        ctx.write_output(std::format("lines_deleted|{}", deleted));
        ctx.write_output(std::format("total_lines_before|{}", total_before));
        ctx.write_output(std::format("total_lines_after|{}", static_cast<int>(lines.size())));
        return 0;
    }

    // ── find_by_hash: Search for a file by SHA256 hash ───────────────────

    int do_find_by_hash(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto directory = params.get("directory");
        auto target_hash = params.get("sha256");
        auto max_depth_str = params.get("max_depth", "3");

        if (directory.empty() || target_hash.empty()) {
            ctx.write_output("error|missing required parameters: directory, sha256");
            return 1;
        }

        auto validated = validate_path(directory, {});
        if (validated.empty()) {
            ctx.write_output("error|directory is not accessible");
            return 1;
        }

        std::error_code ec;
        if (!fs::is_directory(validated, ec)) {
            ctx.write_output("error|path is not a directory");
            return 1;
        }

        int max_depth = 3;
        try { max_depth = std::stoi(std::string{max_depth_str}); }
        catch (...) { max_depth = 3; }
        if (max_depth < 1) max_depth = 1;
        if (max_depth > 10) max_depth = 10;

        // Normalize target hash to lowercase
        std::string target(target_hash);
        std::transform(target.begin(), target.end(), target.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

        int found_count = 0;
        constexpr int max_results = 100;

        // Recursive directory walk with depth limit
        auto base_depth = std::count(validated.begin(), validated.end(), '/') +
                          std::count(validated.begin(), validated.end(), '\\');

        for (auto it = fs::recursive_directory_iterator(validated,
                 fs::directory_options::skip_permission_denied, ec);
             it != fs::recursive_directory_iterator() && found_count < max_results;
             it.increment(ec)) {
            if (ec) continue;

            const auto& entry = *it;
            auto entry_path = entry.path().string();
            auto depth = std::count(entry_path.begin(), entry_path.end(), '/') +
                         std::count(entry_path.begin(), entry_path.end(), '\\') - base_depth;
            if (depth > max_depth) {
                it.disable_recursion_pending();
                continue;
            }

            std::error_code fec;
            if (!entry.is_regular_file(fec) || fec) continue;

            auto file_size = entry.file_size(fec);
            if (fec || file_size == 0 || file_size > kMaxHashFileSize) continue;

#ifdef _WIN32
            auto hash = compute_hash_win(entry_path, "sha256");
#else
            auto hash = compute_hash_unix(entry_path, "sha256");
#endif
            if (!hash.empty() && hash == target) {
                ctx.write_output(std::format("match|{}|{}", entry_path, file_size));
                ++found_count;
            }
        }

        ctx.write_output(std::format("matches_found|{}", found_count));
        return 0;
    }
};

YUZU_PLUGIN_EXPORT(FilesystemPlugin)
