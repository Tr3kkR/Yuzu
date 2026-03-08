/**
 * filesystem_plugin.cpp — Filesystem query plugin for Yuzu
 *
 * Actions:
 *   "exists"    — Check if a path exists, report type and size.
 *   "list_dir"  — List directory contents (max 1000 entries).
 *   "file_hash" — Compute SHA-256 (or SHA-1) hash of a file.
 *
 * Output is pipe-delimited via write_output():
 *   exists|true/false, type|file/directory/other, size|N
 *   entry|name|type|size
 *   hash|HEXSTRING, algorithm|sha256, size|N
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
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#endif

namespace {

namespace fs = std::filesystem;

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

    if (BCryptCreateHash(alg, &hash, hash_object.data(),
                         object_length, nullptr, 0, 0) != 0) {
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
        BCryptHashData(hash, reinterpret_cast<PUCHAR>(buf.data()),
                       static_cast<ULONG>(ifs.gcount()), 0);
        if (ifs.eof()) break;
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

std::string run_command(const char* cmd) {
    std::string result;
    std::array<char, 256> buf{};
    FILE* pipe = popen(cmd, "r");
    if (!pipe) return result;
    while (fgets(buf.data(), static_cast<int>(buf.size()), pipe)) {
        result += buf.data();
    }
    pclose(pipe);
    while (!result.empty() && (result.back() == '\n' || result.back() == '\r')) {
        result.pop_back();
    }
    return result;
}

std::string compute_hash_unix(const std::string& path, std::string_view algorithm) {
    std::string cmd;

#ifdef __APPLE__
    if (algorithm == "sha1") {
        cmd = std::format("shasum -a 1 '{}'", path);
    } else {
        cmd = std::format("shasum -a 256 '{}'", path);
    }
#else
    if (algorithm == "sha1") {
        cmd = std::format("sha1sum '{}'", path);
    } else {
        cmd = std::format("sha256sum '{}'", path);
    }
#endif

    auto output = run_command(cmd.c_str());
    // Output format: "HASH  filename" or "HASH filename"
    auto space = output.find(' ');
    if (space != std::string::npos) {
        return output.substr(0, space);
    }
    return output;
}

#endif

} // namespace

class FilesystemPlugin final : public yuzu::Plugin {
public:
    std::string_view name()        const noexcept override { return "filesystem"; }
    std::string_view version()     const noexcept override { return "0.1.0"; }
    std::string_view description() const noexcept override {
        return "Filesystem queries — exists, list_dir, file_hash";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = { "exists", "list_dir", "file_hash", nullptr };
        return acts;
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override {
        return {};
    }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx,
                std::string_view action,
                yuzu::Params params) override {
        if (action == "exists") {
            return do_exists(ctx, params);
        }
        if (action == "list_dir") {
            return do_list_dir(ctx, params);
        }
        if (action == "file_hash") {
            return do_file_hash(ctx, params);
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

        std::error_code ec;
        std::string path_str{path};
        bool exists = fs::exists(path_str, ec);
        ctx.write_output(std::format("exists|{}", exists ? "true" : "false"));

        if (exists) {
            if (fs::is_regular_file(path_str, ec)) {
                ctx.write_output("type|file");
                auto sz = fs::file_size(path_str, ec);
                ctx.write_output(std::format("size|{}", ec ? 0 : sz));
            } else if (fs::is_directory(path_str, ec)) {
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

        std::error_code ec;
        std::string path_str{path};

        if (!fs::is_directory(path_str, ec)) {
            ctx.write_output("error|path is not a directory or does not exist");
            return 1;
        }

        int count = 0;
        constexpr int max_entries = 1000;

        for (auto it = fs::directory_iterator(path_str, ec);
             it != fs::directory_iterator() && count < max_entries;
             it.increment(ec)) {
            if (ec) continue;

            const auto& entry = *it;
            std::string entry_name = entry.path().filename().string();
            std::string entry_type = "other";
            std::uintmax_t entry_size = 0;

            std::error_code entry_ec;
            if (entry.is_regular_file(entry_ec)) {
                entry_type = "file";
                entry_size = entry.file_size(entry_ec);
                if (entry_ec) entry_size = 0;
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

        auto algorithm = params.get("algorithm", "sha256");
        std::string algo_str{algorithm};

        // Validate algorithm
        if (algo_str != "sha256" && algo_str != "sha1") {
            ctx.write_output(std::format("error|unsupported algorithm: {}", algo_str));
            return 1;
        }

        std::string path_str{path};
        std::error_code ec;
        if (!fs::is_regular_file(path_str, ec)) {
            ctx.write_output("error|path is not a regular file or does not exist");
            return 1;
        }

        auto file_size = fs::file_size(path_str, ec);
        if (ec) file_size = 0;

#ifdef _WIN32
        auto hash = compute_hash_win(path_str, algo_str);
#else
        auto hash = compute_hash_unix(path_str, algo_str);
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
};

YUZU_PLUGIN_EXPORT(FilesystemPlugin)
