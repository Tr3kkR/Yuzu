#ifdef _WIN32
#include <cstdio>
#include <io.h>
#pragma section(".CRT$XCB", read)
static void __cdecl diag_before_static_init() {
    const char msg[] = "[DIAG] EXE static-init starting (before C++ globals)\n";
    _write(2, msg, sizeof(msg) - 1);
}
__declspec(allocate(".CRT$XCB")) static void(__cdecl* p_diag_init)() = diag_before_static_init;
#endif

#include <yuzu/agent/agent.hpp>
#include <yuzu/agent/identity_store.hpp>
#include <yuzu/json_log_formatter.hpp>
#include <yuzu/version.hpp>

#include <CLI/CLI.hpp>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

#include <atomic>
#include <csignal>
#ifndef _WIN32
#include <unistd.h>
#endif
#include <cstdlib>
#include <filesystem>
#include <format>
#include <memory>
#include <string>

static std::atomic<yuzu::agent::Agent*> g_agent{nullptr};

static void on_signal(int sig) {
    // Only async-signal-safe calls allowed here.
    // write() to stderr instead of spdlog (which allocates and locks).
    const char msg[] = "Received signal, shutting down...\n";
#ifdef _WIN32
    _write(2, msg, sizeof(msg) - 1);
#else
    (void)::write(STDERR_FILENO, msg, sizeof(msg) - 1);
#endif
    (void)sig;
    if (auto* a = g_agent.load(std::memory_order_acquire))
        a->stop();
}

int main(int argc, char* argv[]) {
    fprintf(stderr, "[DIAG] main() entered\n");
    CLI::App app{"Yuzu Agent", "yuzu-agent"};
    app.set_version_flag("--version",
                         std::format("{}  ({})", yuzu::kFullVersionString, yuzu::kGitCommitHash));

    yuzu::agent::Config cfg;
    std::string log_level = "info";
    std::string log_file;
    size_t log_max_size = 50 * 1024 * 1024; // 50 MB
    int log_max_files = 5;

    app.add_option("--server", cfg.server_address, "Server address (host:port)")
        ->default_val("localhost:50051")
        ->envname("YUZU_SERVER");
    app.add_option("--agent-id", cfg.agent_id, "Stable agent UUID (auto-generated if empty)")
        ->envname("YUZU_AGENT_ID");
    app.add_option("--data-dir", cfg.data_dir, "Directory for persistent agent state")
        ->default_val(yuzu::agent::default_data_dir().string())
        ->envname("YUZU_DATA_DIR");
    // Default plugin dir: <exe_dir>/../plugins (matches meson build layout)
    auto exe_dir = std::filesystem::path(argv[0]).parent_path();
    if (exe_dir.empty())
        exe_dir = std::filesystem::current_path();
    app.add_option("--plugin-dir", cfg.plugin_dir, "Directory containing plugin shared libraries")
        ->default_val((exe_dir / ".." / "plugins").string())
        ->envname("YUZU_PLUGIN_DIR");
    app.add_option("--heartbeat", cfg.heartbeat_interval, "Heartbeat interval in seconds")
        ->default_val(30)
        ->envname("YUZU_HEARTBEAT");
    app.add_flag("--no-tls", "Disable TLS (insecure, for development only)")
        ->each([&cfg](const std::string&) { cfg.tls_enabled = false; });
    app.add_option("--ca-cert", cfg.tls_ca_cert, "PEM CA certificate for server verification")
        ->envname("YUZU_CA_CERT");
    app.add_option("--client-cert", cfg.tls_client_cert, "PEM client certificate for mTLS")
        ->envname("YUZU_CLIENT_CERT");
    app.add_option("--client-key", cfg.tls_client_key, "PEM client private key for mTLS")
        ->envname("YUZU_CLIENT_KEY");
    app.add_option("--cert-store", cfg.cert_store,
                   "Windows certificate store name (e.g. MY) for mTLS")
        ->envname("YUZU_CERT_STORE");
    app.add_option("--cert-subject", cfg.cert_subject, "Subject CN match for cert store lookup")
        ->envname("YUZU_CERT_SUBJECT");
    app.add_option("--cert-thumbprint", cfg.cert_thumbprint,
                   "SHA-1 thumbprint for cert store lookup (hex)")
        ->envname("YUZU_CERT_THUMBPRINT");
    app.add_flag("--no-cert-discovery", "Disable auto-discovery of certs from well-known paths")
        ->each([&cfg](const std::string&) { cfg.cert_auto_discovery = false; });
    app.add_option("--enrollment-token", cfg.enrollment_token,
                   "Pre-shared enrollment token for server registration")
        ->envname("YUZU_ENROLLMENT_TOKEN");
    app.add_flag("--debug", "Enable debug mode (diagnostic features)")
        ->each([&cfg](const std::string&) { cfg.debug_mode = true; });
    app.add_flag("--verbose", "Enable verbose logging")->each([&cfg](const std::string&) {
        cfg.verbose_logging = true;
    });
    std::string log_format = "text";
    app.add_option("--log-level", log_level, "Log level: trace|debug|info|warn|error")
        ->default_val("info")
        ->envname("YUZU_LOG_LEVEL");
    app.add_option("--log-format", log_format, "Log format: text|json")
        ->default_val("text")
        ->envname("YUZU_LOG_FORMAT");
    app.add_option("--log-file", log_file, "Log file path (enables file logging)")
        ->envname("YUZU_LOG_FILE");
    app.add_option("--log-max-size", log_max_size, "Max log file size in bytes (default: 50MB)")
        ->default_val(50 * 1024 * 1024)
        ->envname("YUZU_LOG_MAX_SIZE");
    app.add_option("--log-max-files", log_max_files, "Max rotated log files (default: 5)")
        ->default_val(5)
        ->envname("YUZU_LOG_MAX_FILES");
    app.add_flag("--no-auto-update", "Disable OTA auto-updates")->each([&cfg](const std::string&) {
        cfg.auto_update = false;
    });
    int update_interval_sec = 21600;
    app.add_option("--update-check-interval", update_interval_sec,
                   "Update check interval in seconds (default: 21600 = 6h)")
        ->default_val(21600)
        ->envname("YUZU_UPDATE_CHECK_INTERVAL");

    CLI11_PARSE(app, argc, argv);

    cfg.update_check_interval = std::chrono::seconds(update_interval_sec);

    cfg.log_level = log_level;
    if (cfg.verbose_logging) {
        log_level = "trace";
        cfg.log_level = "trace";
    }

    // Configure logging — stderr + optional rotating file
    spdlog::set_level(spdlog::level::from_str(log_level));
    if (!log_file.empty()) {
        auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
            log_file, log_max_size, log_max_files);
        auto stderr_sink = std::make_shared<spdlog::sinks::stderr_color_sink_mt>();
        auto logger =
            std::make_shared<spdlog::logger>("", spdlog::sinks_init_list{stderr_sink, file_sink});
        logger->set_level(spdlog::level::from_str(log_level));
        spdlog::set_default_logger(logger);
    }
    if (log_format == "json") {
        spdlog::set_formatter(std::make_unique<yuzu::JsonLogFormatter>("agent"));
    } else {
        spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] [%t] %v");
    }

    spdlog::info("Yuzu Agent v{} ({})", yuzu::kFullVersionString, yuzu::kGitCommitHash);

    // Resolve persistent agent ID
    auto id_result = yuzu::agent::resolve_agent_id(cfg.agent_id, cfg.data_dir / "agent.db");
    if (!id_result) {
        spdlog::error("Failed to resolve agent ID: {}", id_result.error().message);
        return EXIT_FAILURE;
    }
    cfg.agent_id = std::move(*id_result);
    spdlog::info("Agent ID: {}", cfg.agent_id);

    // Signal handling
    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    auto agent = yuzu::agent::Agent::create(std::move(cfg));
    g_agent.store(agent.get(), std::memory_order_release);
    agent->run();

    return EXIT_SUCCESS;
}
