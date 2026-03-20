/**
 * agent_logging_plugin.cpp — Remote agent log access plugin for Yuzu
 *
 * Actions:
 *   "get_log"       — Return the last N lines of the agent log file.
 *   "get_key_files" — List important agent files (config, data, logs)
 *                     with sizes and modification times.
 *
 * Output is pipe-delimited, one field per line via write_output():
 *   key|value
 *
 * The agent log file path is read from agent config. Key file paths
 * are discovered from the agent's configured directories.
 */

#include <yuzu/plugin.hpp>

#include <charconv>
#include <chrono>
#include <deque>
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
#endif

namespace {

namespace fs = std::filesystem;

YuzuPluginContext* g_ctx = nullptr;

/**
 * Helper to read a config value via the raw plugin context.
 */
std::string_view cfg(std::string_view key) {
    if (!g_ctx) return {};
    const char* val = yuzu_ctx_get_config(g_ctx, std::string{key}.c_str());
    return val ? std::string_view{val} : std::string_view{};
}

/**
 * Determine the agent log file path. Checks config keys in order:
 *   1. agent.log_file — explicit log file path
 *   2. agent.data_dir + "/yuzu-agent.log" — data directory default
 *   3. Platform default paths
 */
std::string get_log_file_path() {
    // Try explicit log file config
    auto log_file = cfg("agent.log_file");
    if (!log_file.empty()) {
        return std::string{log_file};
    }

    // Try data_dir + default log name
    auto data_dir = cfg("agent.data_dir");
    if (!data_dir.empty()) {
        fs::path p = fs::path{std::string{data_dir}} / "yuzu-agent.log";
        if (fs::exists(p)) {
            return p.string();
        }
    }

    // Platform default paths
#ifdef _WIN32
    // Check ProgramData
    const char* prog_data = std::getenv("ProgramData");
    if (prog_data) {
        fs::path p = fs::path{prog_data} / "Yuzu" / "yuzu-agent.log";
        if (fs::exists(p)) return p.string();
    }
#elif defined(__APPLE__)
    {
        fs::path p = "/Library/Application Support/Yuzu/yuzu-agent.log";
        if (fs::exists(p)) return p.string();
    }
    {
        fs::path p = "/var/log/yuzu/yuzu-agent.log";
        if (fs::exists(p)) return p.string();
    }
#else // Linux
    {
        fs::path p = "/var/log/yuzu/yuzu-agent.log";
        if (fs::exists(p)) return p.string();
    }
    {
        fs::path p = "/opt/yuzu/yuzu-agent.log";
        if (fs::exists(p)) return p.string();
    }
#endif

    return {};
}

/**
 * Read the last N lines from a file using a tail-style approach.
 * Reads the file line-by-line and keeps a sliding window of the
 * last `count` lines in a deque.
 */
std::deque<std::string> tail_file(const std::string& path, int count) {
    std::deque<std::string> lines;
    std::ifstream file(path);
    if (!file.is_open()) return lines;

    std::string line;
    while (std::getline(file, line)) {
        lines.push_back(std::move(line));
        if (static_cast<int>(lines.size()) > count) {
            lines.pop_front();
        }
    }
    return lines;
}

/**
 * Format a file_time_type as an ISO-like string.
 * Uses system_clock conversion where available.
 */
std::string format_file_time(const fs::file_time_type& ft) {
    // Convert to system_clock time_point
    auto sctp = std::chrono::clock_cast<std::chrono::system_clock>(ft);
    auto epoch_s = std::chrono::duration_cast<std::chrono::seconds>(
                       sctp.time_since_epoch())
                       .count();
    return std::format("{}", epoch_s);
}

/**
 * Write a file info line: file|<path>|<size>|<modified_epoch>
 */
void emit_file_info(yuzu::CommandContext& ctx, const fs::path& path) {
    std::error_code ec;
    if (!fs::exists(path, ec) || ec) return;

    auto size = fs::file_size(path, ec);
    if (ec) size = 0;

    auto mtime = fs::last_write_time(path, ec);
    std::string mtime_str = ec ? "0" : format_file_time(mtime);

    ctx.write_output(std::format("file|{}|{}|{}", path.string(), size, mtime_str));
}

/**
 * Scan a directory (non-recursively) and emit file info for each entry.
 */
void scan_directory(yuzu::CommandContext& ctx, const fs::path& dir) {
    std::error_code ec;
    if (!fs::exists(dir, ec) || !fs::is_directory(dir, ec)) return;

    for (const auto& entry : fs::directory_iterator(dir, ec)) {
        if (ec) break;
        if (entry.is_regular_file()) {
            emit_file_info(ctx, entry.path());
        }
    }
}

} // namespace

class AgentLoggingPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "agent_logging"; }
    std::string_view version() const noexcept override { return "0.1.0"; }
    std::string_view description() const noexcept override {
        return "Remote agent log access — retrieve log tail, list key agent files";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"get_log", "get_key_files", nullptr};
        return acts;
    }

    yuzu::Result<void> init(yuzu::PluginContext& ctx) override {
        g_ctx = ctx.raw();
        return {};
    }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {
        g_ctx = nullptr;
    }

    int execute(yuzu::CommandContext& ctx, std::string_view action,
                yuzu::Params params) override {
        if (action == "get_log")
            return do_get_log(ctx, params);
        if (action == "get_key_files")
            return do_get_key_files(ctx);

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }

private:
    int do_get_log(yuzu::CommandContext& ctx, yuzu::Params params) {
        // Parse lines parameter
        int lines = 50; // default
        auto lines_param = params.get("lines");
        if (!lines_param.empty()) {
            auto [ptr, ec] = std::from_chars(
                lines_param.data(), lines_param.data() + lines_param.size(), lines);
            if (ec != std::errc{} || lines < 1) {
                ctx.write_output("status|error|invalid lines parameter: must be a positive integer");
                return 1;
            }
        }

        // Clamp to max 500
        if (lines > 500) {
            lines = 500;
        }

        // Find log file
        std::string log_path = get_log_file_path();
        if (log_path.empty()) {
            ctx.write_output("status|error|agent log file not found");
            return 1;
        }

        ctx.write_output(std::format("log_file|{}", log_path));

        // Read and output last N lines
        auto tail = tail_file(log_path, lines);
        ctx.write_output(std::format("line_count|{}", tail.size()));

        for (const auto& line : tail) {
            ctx.write_output(std::format("line|{}", line));
        }

        return 0;
    }

    int do_get_key_files(yuzu::CommandContext& ctx) {
        // Agent executable
#ifdef _WIN32
        {
            char exe_path[MAX_PATH]{};
            if (GetModuleFileNameA(nullptr, exe_path, MAX_PATH) > 0) {
                emit_file_info(ctx, fs::path{exe_path});
            }
        }
#elif defined(__linux__)
        {
            std::error_code ec;
            auto exe = fs::read_symlink("/proc/self/exe", ec);
            if (!ec) {
                emit_file_info(ctx, exe);
            }
        }
#elif defined(__APPLE__)
        // On macOS, use _NSGetExecutablePath or /proc alternative
        // Just report the standard install path
        {
            fs::path p = "/usr/local/bin/yuzu-agent";
            if (fs::exists(p)) {
                emit_file_info(ctx, p);
            }
        }
#endif

        // Agent log file
        {
            std::string log_path = get_log_file_path();
            if (!log_path.empty()) {
                emit_file_info(ctx, fs::path{log_path});
            }
        }

        // Config file(s) — check common locations
        auto data_dir_sv = cfg("agent.data_dir");
        if (!data_dir_sv.empty()) {
            fs::path data_dir{std::string{data_dir_sv}};

            // Config files
            for (const auto& name : {"yuzu-agent.cfg", "agent.cfg", "config.cfg"}) {
                fs::path p = data_dir / name;
                std::error_code ec;
                if (fs::exists(p, ec)) {
                    emit_file_info(ctx, p);
                }
            }

            // Data files — KV store, etc.
            for (const auto& name : {"kv-store.db", "agent-state.db"}) {
                fs::path p = data_dir / name;
                std::error_code ec;
                if (fs::exists(p, ec)) {
                    emit_file_info(ctx, p);
                }
            }
        }

        // Plugin directory
        auto plugin_dir_sv = cfg("agent.plugin_dir");
        if (!plugin_dir_sv.empty()) {
            scan_directory(ctx, fs::path{std::string{plugin_dir_sv}});
        }

        // TLS certificates
        yuzu::PluginContext pctx{g_ctx};
        for (const auto& key : {"tls.ca_cert", "tls.client_cert", "tls.client_key"}) {
            auto path = pctx.get_config(key);
            if (!path.empty()) {
                emit_file_info(ctx, fs::path{std::string{path}});
            }
        }

        return 0;
    }
};

YUZU_PLUGIN_EXPORT(AgentLoggingPlugin)
