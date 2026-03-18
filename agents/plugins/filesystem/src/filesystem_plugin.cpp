/**
 * filesystem_plugin.cpp — Filesystem operations plugin for Yuzu
 *
 * Actions:
 *   "exists"          — Check if a path exists, report type and size.
 *   "list_dir"        — List directory contents (max 1000 entries).
 *   "file_hash"       — Compute SHA-256 (or SHA-1) hash of a file.
 *   "create_temp"     — Create a secure temporary file (mode 0600 / owner-only DACL).
 *   "create_temp_dir" — Create a secure temporary directory (mode 0700 / owner-only DACL).
 *
 * Security:
 *   - All paths are canonicalized via std::filesystem::canonical() to
 *     resolve symlinks and prevent traversal attacks.
 *   - An optional base_dir parameter restricts access to a subtree.
 *   - Temp files use mkstemps() (POSIX) / CreateFile+CREATE_NEW (Windows)
 *     with restrictive permissions to prevent TOCTOU races.
 *   - This plugin requires admin role on the server side.
 *
 * Output is pipe-delimited via write_output():
 *   exists|true/false, type|file/directory/other, size|N
 *   entry|name|type|size
 *   hash|HEXSTRING, algorithm|sha256, size|N
 *   path|/tmp/yuzu-XXXXXX.tmp, persist|true/false
 */

#include <yuzu/plugin.hpp>

#include <array>
#include <cstdio>
#include <filesystem>
#include <format>
#include <fstream>
#include <string>
#include <string_view>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <bcrypt.h>
#include <windows.h>
#pragma comment(lib, "bcrypt.lib")
#else
#include <sys/wait.h>
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

} // namespace

class FilesystemPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "filesystem"; }
    std::string_view version() const noexcept override { return "0.3.0"; }
    std::string_view description() const noexcept override {
        return "Filesystem operations — exists, list_dir, file_hash, create_temp, create_temp_dir "
               "(admin-only)";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"exists",          "list_dir", "file_hash", "create_temp",
                                     "create_temp_dir", "read",     nullptr};
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
};

YUZU_PLUGIN_EXPORT(FilesystemPlugin)
