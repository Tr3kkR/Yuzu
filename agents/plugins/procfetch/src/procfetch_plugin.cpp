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
 * Platform support:
 *   Linux  — /proc filesystem, OpenSSL EVP for SHA-1
 *   Windows — CreateToolhelp32Snapshot, BCrypt for SHA-1
 *
 * Performance notes:
 *   - SHA-1 results are cached by path to avoid re-hashing duplicate
 *     executables (e.g. svchost.exe × 20+).
 *   - Results are streamed per-process instead of collected first.
 *   - BCrypt provider (Windows) is opened once per fetch, not per file.
 *   - 64KB I/O buffer for faster reads.
 */

#include <yuzu/plugin.hpp>

#include <cstdio>
#include <filesystem>
#include <format>
#include <fstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#ifdef __linux__
#include <openssl/evp.h>
#elif defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <bcrypt.h>
#include <charconv>
#include <tlhelp32.h>
#include <windows.h>
#endif

namespace {

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

// -- Linux implementation -----------------------------------------------------
#ifdef __linux__

std::string read_first_line(const std::filesystem::path& path) {
    std::ifstream f(path);
    if (!f)
        return {};
    std::string line;
    std::getline(f, line);
    return line;
}

std::string resolve_exe(const std::filesystem::path& link) {
    try {
        return std::filesystem::read_symlink(link).string();
    } catch (const std::filesystem::filesystem_error&) {
        return {};
    }
}

std::string sha1_of_file(const std::filesystem::path& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f)
        return {};

    auto* ctx = EVP_MD_CTX_new();
    if (!ctx)
        return {};

    if (EVP_DigestInit_ex(ctx, EVP_sha1(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        return {};
    }

    char buf[65536];
    while (f.read(buf, sizeof(buf)) || f.gcount() > 0) {
        if (EVP_DigestUpdate(ctx, buf, static_cast<size_t>(f.gcount())) != 1) {
            EVP_MD_CTX_free(ctx);
            return {};
        }
        if (f.gcount() < static_cast<std::streamsize>(sizeof(buf)))
            break;
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

void enumerate_and_stream(yuzu::CommandContext& ctx) {
    std::unordered_map<std::string, std::string> sha_cache;
    std::error_code ec;

    for (const auto& entry : std::filesystem::directory_iterator("/proc", ec)) {
        if (!entry.is_directory(ec))
            continue;

        auto dirname = entry.path().filename().string();
        int pid = 0;
        auto [ptr, errc] = std::from_chars(dirname.data(), dirname.data() + dirname.size(), pid);
        if (errc != std::errc{} || ptr != dirname.data() + dirname.size())
            continue;
        if (pid <= 0)
            continue;

        std::string name = read_first_line(entry.path() / "comm");
        if (name.empty())
            continue;

        std::string exe_path = resolve_exe(entry.path() / "exe");
        std::string sha1;
        if (!exe_path.empty()) {
            std::error_code fe;
            if (std::filesystem::exists(exe_path, fe)) {
                auto it = sha_cache.find(exe_path);
                if (it != sha_cache.end()) {
                    sha1 = it->second;
                } else {
                    sha1 = sha1_of_file(exe_path);
                    sha_cache.emplace(exe_path, sha1);
                }
            }
        }

        ctx.write_output(
            std::format("{}|{}|{}|{}", pid, escape_pipes(name), escape_pipes(exe_path), sha1));
    }
}

// -- Windows implementation ---------------------------------------------------
#elif defined(_WIN32)

std::string wide_to_utf8(const wchar_t* ws) {
    if (!ws || !*ws)
        return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, ws, -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0)
        return {};
    std::string s(static_cast<size_t>(len - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, ws, -1, s.data(), len, nullptr, nullptr);
    return s;
}

std::string get_process_image_path(DWORD pid) {
    HANDLE proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!proc)
        return {};

    wchar_t path_buf[MAX_PATH];
    DWORD path_len = MAX_PATH;
    BOOL ok = QueryFullProcessImageNameW(proc, 0, path_buf, &path_len);
    CloseHandle(proc);

    if (!ok)
        return {};
    return wide_to_utf8(path_buf);
}

std::string sha1_of_file(const std::string& path, BCRYPT_ALG_HANDLE alg) {
    HANDLE file = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE)
        return {};

    BCRYPT_HASH_HANDLE hash_handle = nullptr;
    NTSTATUS status = BCryptCreateHash(alg, &hash_handle, nullptr, 0, nullptr, 0, 0);
    if (status != 0) {
        CloseHandle(file);
        return {};
    }

    char buf[65536];
    DWORD bytes_read = 0;
    while (ReadFile(file, buf, sizeof(buf), &bytes_read, nullptr) && bytes_read > 0) {
        status = BCryptHashData(hash_handle, reinterpret_cast<PUCHAR>(buf), bytes_read, 0);
        if (status != 0)
            break;
    }
    CloseHandle(file);

    unsigned char hash[20]; // SHA-1 is 20 bytes
    status = BCryptFinishHash(hash_handle, hash, sizeof(hash), 0);
    BCryptDestroyHash(hash_handle);

    if (status != 0)
        return {};

    std::string hex;
    hex.reserve(40);
    for (int i = 0; i < 20; ++i) {
        hex += std::format("{:02x}", hash[i]);
    }
    return hex;
}

void enumerate_and_stream(yuzu::CommandContext& ctx) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return;

    BCRYPT_ALG_HANDLE alg = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA1_ALGORITHM, nullptr, 0);
    if (status != 0) {
        CloseHandle(snap);
        return;
    }

    std::unordered_map<std::string, std::string> sha_cache;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);

    if (!Process32FirstW(snap, &pe)) {
        BCryptCloseAlgorithmProvider(alg, 0);
        CloseHandle(snap);
        return;
    }

    do {
        int pid = static_cast<int>(pe.th32ProcessID);
        std::string name = wide_to_utf8(pe.szExeFile);
        if (name.empty())
            continue;

        std::string exe_path = get_process_image_path(pe.th32ProcessID);
        std::string sha1;
        if (!exe_path.empty()) {
            auto it = sha_cache.find(exe_path);
            if (it != sha_cache.end()) {
                sha1 = it->second;
            } else {
                sha1 = sha1_of_file(exe_path, alg);
                sha_cache.emplace(exe_path, sha1);
            }
        }

        ctx.write_output(
            std::format("{}|{}|{}|{}", pid, escape_pipes(name), escape_pipes(exe_path), sha1));
    } while (Process32NextW(snap, &pe));

    BCryptCloseAlgorithmProvider(alg, 0);
    CloseHandle(snap);
}

#endif // platform

} // namespace

class ProcfetchPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "procfetch"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Enumerates running processes with SHA-1 hashes of executables";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"procfetch_fetch", nullptr};
        return acts;
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override { return {}; }
    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action,
                yuzu::Params /*params*/) override {
        if (action == "procfetch_fetch") {
            return do_fetch(ctx);
        }
        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }

private:
    int do_fetch(yuzu::CommandContext& ctx) {
#if defined(__linux__) || defined(_WIN32)
        enumerate_and_stream(ctx);
        return 0;
#else
        ctx.write_output("error: process enumeration not supported on this platform");
        return 1;
#endif
    }
};

YUZU_PLUGIN_EXPORT(ProcfetchPlugin)
