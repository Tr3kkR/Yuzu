/**
 * processes_plugin.cpp — Process listing plugin for Yuzu
 *
 * Actions:
 *   "list"        — List running processes: PID, name.
 *   "list_hashed" — List running processes with the SHA-256 of the on-disk
 *                   executable image + its path: proc|pid|name|sha256|path.
 *   "query"       — Filter process list by case-insensitive name match.
 *
 * Output is pipe-delimited via write_output():
 *   proc|pid|name                (list / query)
 *   proc|pid|name|sha256|path    (list_hashed; sha256/path empty if unresolved)
 */

#include <yuzu/agent/plugin_loader.hpp> // yuzu::agent::sha256_file
#include <yuzu/plugin.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <format>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <tlhelp32.h>
#endif

#ifdef __linux__
#include <dirent.h>
#include <fstream>
#include <unistd.h> // readlink
#endif

#ifdef __APPLE__
#include <libproc.h> // proc_pidpath
#endif

namespace {

struct ProcessInfo {
    unsigned long pid;
    std::string name;
};

std::string to_lower(std::string_view sv) {
    std::string result{sv};
    std::transform(result.begin(), result.end(), result.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return result;
}

// The wire format is pipe-delimited, one record per line. A process name (or any
// field) containing '|', CR, or LF would shift/split fields on the server-side
// positional parser, so neutralise those bytes to a space before emitting.
std::string sanitize_field(std::string s) {
    for (char& c : s)
        if (c == '|' || c == '\n' || c == '\r')
            c = ' ';
    return s;
}

#ifdef _WIN32
std::vector<ProcessInfo> enumerate_processes() {
    std::vector<ProcessInfo> procs;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return procs;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            ProcessInfo pi;
            pi.pid = pe.th32ProcessID;
            // Wide to narrow (ASCII process names)
            int len =
                WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, nullptr, 0, nullptr, nullptr);
            if (len > 0) {
                pi.name.resize(static_cast<size_t>(len - 1));
                WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, pi.name.data(), len, nullptr,
                                    nullptr);
            }
            procs.push_back(std::move(pi));
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return procs;
}
#elif defined(__linux__)
std::vector<ProcessInfo> enumerate_processes() {
    std::vector<ProcessInfo> procs;
    DIR* proc_dir = opendir("/proc");
    if (!proc_dir)
        return procs;

    struct dirent* entry = nullptr;
    while ((entry = readdir(proc_dir)) != nullptr) {
        // Only numeric directories
        if (entry->d_type != DT_DIR)
            continue;
        bool is_pid = true;
        for (const char* p = entry->d_name; *p; ++p) {
            if (!std::isdigit(static_cast<unsigned char>(*p))) {
                is_pid = false;
                break;
            }
        }
        if (!is_pid)
            continue;

        std::string status_path = std::string("/proc/") + entry->d_name + "/status";
        std::ifstream ifs(status_path);
        if (!ifs.is_open())
            continue;

        ProcessInfo pi;
        pi.pid = std::stoul(entry->d_name);
        std::string line;
        while (std::getline(ifs, line)) {
            if (line.starts_with("Name:")) {
                auto pos = line.find_first_not_of(" \t", 5);
                if (pos != std::string::npos) {
                    pi.name = line.substr(pos);
                }
                break;
            }
        }
        procs.push_back(std::move(pi));
    }
    closedir(proc_dir);
    return procs;
}
#elif defined(__APPLE__)
std::vector<ProcessInfo> enumerate_processes() {
    std::vector<ProcessInfo> procs;
    FILE* pipe = popen("ps -axo pid,comm", "r");
    if (!pipe)
        return procs;

    std::array<char, 512> buf{};
    // Skip header line
    if (fgets(buf.data(), static_cast<int>(buf.size()), pipe) == nullptr) {
        pclose(pipe);
        return procs;
    }

    while (fgets(buf.data(), static_cast<int>(buf.size()), pipe)) {
        std::string line{buf.data()};
        // Trim trailing newline
        while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) {
            line.pop_back();
        }
        if (line.empty())
            continue;

        // Parse: "  PID COMMAND"
        auto pos = line.find_first_not_of(' ');
        if (pos == std::string::npos)
            continue;
        auto space = line.find(' ', pos);
        if (space == std::string::npos)
            continue;

        ProcessInfo pi;
        try {
            pi.pid = std::stoul(line.substr(pos, space - pos));
        } catch (...) {
            continue;
        }
        auto cmd_start = line.find_first_not_of(' ', space);
        if (cmd_start != std::string::npos) {
            pi.name = line.substr(cmd_start);
        }
        procs.push_back(std::move(pi));
    }
    pclose(pipe);
    return procs;
}
#else
std::vector<ProcessInfo> enumerate_processes() {
    return {};
}
#endif

// Resolve a process's true on-disk executable path (NOT argv[0], which is
// spoofable) so its image can be hashed. Empty on failure — kernel threads,
// PID 0/4, access-denied, or an unsupported platform all read as "no path".
#ifdef _WIN32
// Single-owner RAII for a process HANDLE: CloseHandle runs on every scope exit,
// including an exception from a std::wstring/std::string allocation between
// acquire and release (a leak the prior manual CloseHandle could skip).
struct HandleGuard {
    HANDLE h;
    explicit HandleGuard(HANDLE handle) noexcept : h(handle) {}
    ~HandleGuard() { if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h); }
    HandleGuard(const HandleGuard&) = delete;
    HandleGuard& operator=(const HandleGuard&) = delete;
    explicit operator bool() const noexcept { return h && h != INVALID_HANDLE_VALUE; }
};

std::string resolve_exe_path(unsigned long pid) {
    HandleGuard hg(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (!hg)
        return "";
    std::wstring wbuf(4096, L'\0');
    DWORD sz = static_cast<DWORD>(wbuf.size());
    std::string path;
    if (QueryFullProcessImageNameW(hg.h, 0, wbuf.data(), &sz) && sz > 0) {
        int len = WideCharToMultiByte(CP_UTF8, 0, wbuf.data(), static_cast<int>(sz), nullptr, 0,
                                      nullptr, nullptr);
        if (len > 0) {
            path.resize(static_cast<size_t>(len));
            WideCharToMultiByte(CP_UTF8, 0, wbuf.data(), static_cast<int>(sz), path.data(), len,
                                nullptr, nullptr);
        }
    }
    return path; // ~HandleGuard closes the handle on every path
}
#elif defined(__linux__)
std::string resolve_exe_path(unsigned long pid) {
    std::string link = "/proc/" + std::to_string(pid) + "/exe";
    std::array<char, 4096> buf{};
    ssize_t n = readlink(link.c_str(), buf.data(), buf.size() - 1);
    if (n <= 0)
        return "";
    std::string path(buf.data(), static_cast<size_t>(n));
    // A replaced/removed binary reads as "<path> (deleted)" — strip the marker;
    // sha256_file then fails honestly (the on-disk image is gone).
    if (path.ends_with(" (deleted)"))
        path.erase(path.size() - 10);
    return path;
}
#elif defined(__APPLE__)
std::string resolve_exe_path(unsigned long pid) {
    std::array<char, PROC_PIDPATHINFO_MAXSIZE> buf{};
    int n = proc_pidpath(static_cast<int>(pid), buf.data(), buf.size());
    if (n <= 0)
        return "";
    return std::string(buf.data(), static_cast<size_t>(n));
}
#else
std::string resolve_exe_path(unsigned long) {
    return "";
}
#endif

} // namespace

class ProcessesPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "processes"; }
    std::string_view version() const noexcept override { return "0.1.0"; }
    std::string_view description() const noexcept override {
        return "Process listing — enumerate and query running processes";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"list", "list_hashed", "query", nullptr};
        return acts;
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override { return {}; }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action, yuzu::Params params) override {
        if (action == "list") {
            return do_list(ctx);
        }
        if (action == "list_hashed") {
            return do_list_hashed(ctx);
        }
        if (action == "query") {
            return do_query(ctx, params);
        }

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }

private:
    int do_list(yuzu::CommandContext& ctx) {
        auto procs = enumerate_processes();
        for (const auto& p : procs) {
            ctx.write_output(std::format("proc|{}|{}", p.pid, sanitize_field(p.name)));
        }
        return 0;
    }

    // proc|pid|name|sha256|path. The on-disk image is hashed (lowercase hex);
    // unique paths are hashed once (many PIDs share one executable). The hash is
    // bounded (kMaxHashBytes) so an oversized image can't turn a live query into a
    // multi-GB read. sha256/path are empty when the path can't be resolved (kernel
    // threads, access-denied) or the file is gone/too large — rendered honestly.
    int do_list_hashed(yuzu::CommandContext& ctx) {
        static constexpr std::size_t kMaxHashBytes = 512ull * 1024 * 1024; // 512 MiB cap
        auto procs = enumerate_processes();
        std::unordered_map<std::string, std::string> hash_cache; // path -> sha256
        for (const auto& p : procs) {
            std::string path = resolve_exe_path(p.pid);
            std::string hash;
            if (!path.empty()) {
                auto it = hash_cache.find(path);
                if (it != hash_cache.end()) {
                    hash = it->second;
                } else {
                    hash = yuzu::agent::sha256_file(path, kMaxHashBytes);
                    hash_cache.emplace(path, hash);
                }
            }
            ctx.write_output(std::format("proc|{}|{}|{}|{}", p.pid, sanitize_field(p.name), hash,
                                         sanitize_field(path)));
        }
        return 0;
    }

    int do_query(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto name_filter = params.get("name");
        if (name_filter.empty()) {
            ctx.write_output("error|missing required parameter: name");
            return 1;
        }

        auto filter_lower = to_lower(name_filter);
        auto procs = enumerate_processes();
        std::vector<const ProcessInfo*> matches;

        for (const auto& p : procs) {
            auto name_lower = to_lower(p.name);
            if (name_lower.find(filter_lower) != std::string::npos) {
                matches.push_back(&p);
            }
        }

        ctx.write_output(std::format("found|{}", matches.empty() ? "false" : "true"));
        for (const auto* p : matches) {
            ctx.write_output(std::format("proc|{}|{}", p->pid, p->name));
        }
        return 0;
    }
};

YUZU_PLUGIN_EXPORT(ProcessesPlugin)
