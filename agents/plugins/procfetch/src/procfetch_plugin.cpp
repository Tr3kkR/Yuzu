/**
 * procfetch_plugin.cpp — Process enumeration plugin for Yuzu
 *
 * Actions:
 *   "procfetch_fetch" — Enumerates running processes on the host,
 *                       returning PID, name, executable path, and
 *                       SHA-1 hash of each executable binary.
 *
 * Output is pipe-delimited, one process per line via write_output():
 *   pid|name|path|sha1_hex
 *
 * On non-Linux platforms the plugin returns an error string.
 */

#include <yuzu/plugin.hpp>

#include <cstdio>
#include <filesystem>
#include <format>
#include <fstream>
#include <string>
#include <string_view>
#include <vector>

#ifdef __linux__
#include <openssl/evp.h>
#endif

namespace {

#ifdef __linux__

std::string read_first_line(const std::filesystem::path& path) {
    std::ifstream f(path);
    if (!f) return {};
    std::string line;
    std::getline(f, line);
    return line;
}

std::string resolve_exe(const std::filesystem::path& link) {
    try {
        return std::filesystem::read_symlink(link).string();
    } catch (...) {
        return {};
    }
}

std::string sha1_of_file(const std::filesystem::path& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};

    auto* ctx = EVP_MD_CTX_new();
    if (!ctx) return {};

    if (EVP_DigestInit_ex(ctx, EVP_sha1(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        return {};
    }

    char buf[8192];
    while (f.read(buf, sizeof(buf)) || f.gcount() > 0) {
        if (EVP_DigestUpdate(ctx, buf, static_cast<size_t>(f.gcount())) != 1) {
            EVP_MD_CTX_free(ctx);
            return {};
        }
        if (f.gcount() < static_cast<std::streamsize>(sizeof(buf))) break;
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return {};
    }
    EVP_MD_CTX_free(ctx);

    std::string hex;
    hex.reserve(hash_len * 2);
    for (unsigned int i = 0; i < hash_len; ++i) {
        hex += std::format("{:02x}", hash[i]);
    }
    return hex;
}

// Escape pipe characters in strings so they don't break the delimiter.
std::string escape_pipes(std::string_view sv) {
    std::string out;
    out.reserve(sv.size());
    for (char c : sv) {
        if (c == '|') {
            out += "\\|";
        } else {
            out += c;
        }
    }
    return out;
}

struct ProcessInfo {
    int pid;
    std::string name;
    std::string exe_path;
    std::string sha1;
};

std::vector<ProcessInfo> enumerate_processes() {
    std::vector<ProcessInfo> result;

    std::error_code ec;
    for (const auto& entry : std::filesystem::directory_iterator("/proc", ec)) {
        if (!entry.is_directory(ec)) continue;

        auto dirname = entry.path().filename().string();
        int pid = 0;
        auto [ptr, errc] = std::from_chars(dirname.data(),
                                            dirname.data() + dirname.size(),
                                            pid);
        if (errc != std::errc{} || ptr != dirname.data() + dirname.size()) continue;
        if (pid <= 0) continue;

        ProcessInfo info;
        info.pid = pid;
        info.name = read_first_line(entry.path() / "comm");
        if (info.name.empty()) continue;

        info.exe_path = resolve_exe(entry.path() / "exe");
        if (!info.exe_path.empty()) {
            std::error_code fe;
            if (std::filesystem::exists(info.exe_path, fe)) {
                info.sha1 = sha1_of_file(info.exe_path);
            }
        }
        result.push_back(std::move(info));
    }
    return result;
}

#endif  // __linux__

}  // namespace

class ProcfetchPlugin final : public yuzu::Plugin {
public:
    std::string_view name()        const noexcept override { return "procfetch"; }
    std::string_view version()     const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Enumerates running processes with SHA-1 hashes of executables";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"procfetch_fetch", nullptr};
        return acts;
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override { return {}; }
    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx,
                std::string_view action,
                yuzu::Params /*params*/) override {
        if (action == "procfetch_fetch") {
            return do_fetch(ctx);
        }
        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }

private:
    int do_fetch(yuzu::CommandContext& ctx) {
#ifdef __linux__
        auto procs = enumerate_processes();
        for (const auto& p : procs) {
            ctx.write_output(std::format("{}|{}|{}|{}",
                p.pid,
                escape_pipes(p.name),
                escape_pipes(p.exe_path),
                p.sha1));
        }
        return 0;
#else
        ctx.write_output("error: process enumeration not supported on this platform");
        return 1;
#endif
    }
};

YUZU_PLUGIN_EXPORT(ProcfetchPlugin)
