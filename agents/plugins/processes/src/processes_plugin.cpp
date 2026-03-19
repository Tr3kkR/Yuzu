/**
 * processes_plugin.cpp — Process listing plugin for Yuzu
 *
 * Actions:
 *   "list"  — List running processes: PID, name.
 *   "query" — Filter process list by case-insensitive name match.
 *
 * Output is pipe-delimited via write_output():
 *   proc|pid|name
 */

#include <yuzu/plugin.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <format>
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
#include <windows.h>
#include <tlhelp32.h>
#endif

#ifdef __linux__
#include <dirent.h>
#include <fstream>
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

} // namespace

class ProcessesPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "processes"; }
    std::string_view version() const noexcept override { return "0.1.0"; }
    std::string_view description() const noexcept override {
        return "Process listing — enumerate and query running processes";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"list", "query", nullptr};
        return acts;
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override { return {}; }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action, yuzu::Params params) override {
        if (action == "list") {
            return do_list(ctx);
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
            ctx.write_output(std::format("proc|{}|{}", p.pid, p.name));
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
