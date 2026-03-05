#ifdef _WIN32
#  include <io.h>
#  include <cstdio>
#  pragma section(".CRT$XCB", read)
static void __cdecl diag_before_static_init() {
    const char msg[] = "[DIAG] EXE static-init starting (before C++ globals)\n";
    _write(2, msg, sizeof(msg) - 1);
}
__declspec(allocate(".CRT$XCB")) static void (__cdecl *p_diag_init)() = diag_before_static_init;
#endif

#include <yuzu/agent/agent.hpp>
#include <yuzu/version.hpp>

#include <CLI/CLI.hpp>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include <csignal>
#include <cstdlib>
#include <filesystem>
#include <memory>
#include <string>

static yuzu::agent::Agent* g_agent = nullptr;

static void on_signal(int sig) {
    spdlog::warn("Received signal {}, shutting down...", sig);
    if (g_agent) g_agent->stop();
}

int main(int argc, char* argv[]) {
    fprintf(stderr, "[DIAG] main() entered\n");
    CLI::App app{"Yuzu Agent", "yuzu-agent"};
    app.set_version_flag("--version", std::string{yuzu::kVersionString});

    yuzu::agent::Config cfg;
    std::string log_level = "info";

    app.add_option("--server",   cfg.server_address,  "Server address (host:port)")
       ->default_val("localhost:50051");
    app.add_option("--agent-id", cfg.agent_id,        "Stable agent UUID (auto-generated if empty)");
    app.add_option("--plugin-dir", cfg.plugin_dir,    "Directory containing plugin shared libraries")
       ->default_val(std::filesystem::current_path() / "plugins");
    app.add_option("--heartbeat", cfg.heartbeat_interval,
                   "Heartbeat interval in seconds")->default_val(30);
    app.add_flag  ("--no-tls",   "Disable TLS (insecure, for development only)")
       ->each([&cfg](const std::string&) { cfg.tls_enabled = false; });
    app.add_option("--ca-cert",  cfg.tls_ca_cert,     "PEM CA certificate for server verification");
    app.add_option("--log-level", log_level,           "Log level: trace|debug|info|warn|error")
       ->default_val("info");

    CLI11_PARSE(app, argc, argv);

    // Configure logging
    spdlog::set_level(spdlog::level::from_str(log_level));
    spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] [%t] %v");

    spdlog::info("Yuzu Agent v{}", yuzu::kVersionString);

    // Signal handling
    std::signal(SIGINT,  on_signal);
    std::signal(SIGTERM, on_signal);

    auto agent = yuzu::agent::Agent::create(std::move(cfg));
    g_agent = agent.get();
    agent->run();

    return EXIT_SUCCESS;
}
