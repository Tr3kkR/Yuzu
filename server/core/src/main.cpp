#include <yuzu/server/server.hpp>
#include <yuzu/server/auth.hpp>
#include <yuzu/version.hpp>

#include <CLI/CLI.hpp>
#include <spdlog/spdlog.h>

#include <chrono>
#include <csignal>
#include <cstdlib>
#include <format>
#include <iostream>
#include <memory>
#include <string>

static yuzu::server::Server* g_server = nullptr;

static void on_signal(int sig) {
    spdlog::warn("Received signal {}, shutting down...", sig);
    if (g_server) g_server->stop();
}

int main(int argc, char* argv[]) {
    CLI::App app{"Yuzu Server", "yuzu-server"};
    app.set_version_flag("--version", std::format("{}  ({})", yuzu::kFullVersionString, yuzu::kGitCommitHash));

    yuzu::server::Config cfg;
    std::string log_level = "info";
    std::string config_file;

    app.add_option("--config",     config_file,              "Path to yuzu-server.cfg");
    app.add_option("--listen",     cfg.listen_address,       "Agent gRPC address (host:port)")
       ->default_val("0.0.0.0:50051");
    app.add_option("--management", cfg.management_address,   "Management gRPC address (host:port)")
       ->default_val("0.0.0.0:50052");
    app.add_option("--web-address", cfg.web_address,         "Web UI bind address")
       ->default_val("0.0.0.0");
    app.add_option("--web-port",    cfg.web_port,            "Web UI port")
       ->default_val(8080);
    app.add_flag  ("--no-tls",    "Disable TLS (insecure, for development only)")
       ->each([&cfg](const std::string&) { cfg.tls_enabled = false; });
    app.add_option("--cert",       cfg.tls_server_cert,      "PEM server certificate");
    app.add_option("--key",        cfg.tls_server_key,       "PEM server private key");
    app.add_option("--ca-cert",    cfg.tls_ca_cert,          "PEM CA cert (for mTLS agent verification)");
    app.add_flag  ("--allow-one-way-tls", "Allow TLS without --ca-cert (disables mTLS)")
       ->each([&cfg](const std::string&) { cfg.allow_one_way_tls = true; });
    app.add_option("--management-cert",    cfg.mgmt_tls_server_cert, "PEM management server certificate override");
    app.add_option("--management-key",     cfg.mgmt_tls_server_key,  "PEM management server private key override");
    app.add_option("--management-ca-cert", cfg.mgmt_tls_ca_cert,     "PEM CA cert for management client cert verification");
    app.add_option("--gateway-upstream", cfg.gateway_upstream_address,
                   "Gateway upstream gRPC address (host:port); empty = disabled");
    app.add_flag  ("--gateway-mode", "Enable gateway mode (relax peer-mismatch in Subscribe)")
       ->each([&cfg](const std::string&) { cfg.gateway_mode = true; });
    app.add_option("--max-agents", cfg.max_agents,           "Maximum concurrent agent connections")
       ->default_val(10000);
    app.add_option("--log-level",  log_level,                "Log level: trace|debug|info|warn|error")
       ->default_val("info");

    // Batch token generation mode (runs and exits, no server startup)
    int generate_tokens = 0;
    std::string gen_label;
    int gen_max_uses = 1;
    int gen_ttl_hours = 0;
    app.add_option("--generate-tokens", generate_tokens,
                   "Generate N enrollment tokens and print to stdout (JSON), then exit");
    app.add_option("--token-label",     gen_label,     "Label prefix for generated tokens");
    app.add_option("--token-max-uses",  gen_max_uses,  "Max uses per token (default: 1)");
    app.add_option("--token-ttl-hours", gen_ttl_hours, "Token TTL in hours (0 = no expiry)");

    CLI11_PARSE(app, argc, argv);

    spdlog::set_level(spdlog::level::from_str(log_level));
    spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] [%t] %v");

    spdlog::info("Yuzu Server v{} ({})", yuzu::kFullVersionString, yuzu::kGitCommitHash);

    // -- Auth config loading / first-run setup --------------------------------

    namespace auth = yuzu::server::auth;

    auto cfg_path = config_file.empty()
        ? auth::default_config_path()
        : std::filesystem::path(config_file);

    auth::AuthManager auth_mgr;

    if (!auth_mgr.load_config(cfg_path)) {
        spdlog::warn("No user config found at {}", cfg_path.string());
        spdlog::info("Running first-time setup...");

        if (!auth::AuthManager::first_run_setup(cfg_path)) {
            spdlog::error("First-run setup failed — exiting");
            return EXIT_FAILURE;
        }

        // Reload after setup
        if (!auth_mgr.load_config(cfg_path)) {
            spdlog::error("Failed to load config after setup — exiting");
            return EXIT_FAILURE;
        }
    }

    cfg.auth_config_path = cfg_path;

    // -- Batch token generation mode (exits without starting server) ----------

    if (generate_tokens > 0) {
        auto ttl = gen_ttl_hours > 0
            ? std::chrono::seconds(gen_ttl_hours * 3600)
            : std::chrono::seconds(0);

        auto tokens = auth_mgr.create_enrollment_tokens_batch(
            gen_label, generate_tokens, gen_max_uses, ttl);

        // Output JSON to stdout for scripting (Ansible, etc.)
        std::cout << "{\"count\":" << tokens.size() << ",\"tokens\":[\n";
        for (size_t i = 0; i < tokens.size(); ++i) {
            if (i > 0) std::cout << ",\n";
            std::cout << "  \"" << tokens[i] << "\"";
        }
        std::cout << "\n]}\n";

        spdlog::info("Generated {} enrollment tokens", tokens.size());
        return EXIT_SUCCESS;
    }

    // -------------------------------------------------------------------------

    std::signal(SIGINT,  on_signal);
    std::signal(SIGTERM, on_signal);

    auto server = yuzu::server::Server::create(std::move(cfg), auth_mgr);
    g_server = server.get();
    server->run();

    return EXIT_SUCCESS;
}
