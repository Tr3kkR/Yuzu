#include <yuzu/server/server.hpp>
#include <yuzu/version.hpp>

#include <CLI/CLI.hpp>
#include <spdlog/spdlog.h>

#include <csignal>
#include <cstdlib>
#include <memory>
#include <string>

static yuzu::server::Server* g_server = nullptr;

static void on_signal(int sig) {
    spdlog::warn("Received signal {}, shutting down...", sig);
    if (g_server) g_server->stop();
}

int main(int argc, char* argv[]) {
    CLI::App app{"Yuzu Server", "yuzu-server"};
    app.set_version_flag("--version", std::string{yuzu::kVersionString});

    yuzu::server::Config cfg;
    std::string log_level = "info";

    app.add_option("--listen",     cfg.listen_address,     "Agent gRPC address (host:port)")
       ->default_val("0.0.0.0:50051");
    app.add_option("--management", cfg.management_address, "Management gRPC address (host:port)")
       ->default_val("0.0.0.0:50052");
    app.add_option("--web-address", cfg.web_address,      "Web UI bind address")
       ->default_val("0.0.0.0");
    app.add_option("--web-port",    cfg.web_port,          "Web UI port")
       ->default_val(8080);
    app.add_flag  ("--no-tls",    "Disable TLS (insecure, for development only)")
       ->each([&cfg](const std::string&) { cfg.tls_enabled = false; });
    app.add_option("--cert",       cfg.tls_server_cert,    "PEM server certificate");
    app.add_option("--key",        cfg.tls_server_key,     "PEM server private key");
    app.add_option("--ca-cert",    cfg.tls_ca_cert,        "PEM CA cert (for mTLS agent verification)");
    app.add_option("--max-agents", cfg.max_agents,         "Maximum concurrent agent connections")
       ->default_val(10000);
    app.add_option("--log-level",  log_level,              "Log level: trace|debug|info|warn|error")
       ->default_val("info");

    CLI11_PARSE(app, argc, argv);

    spdlog::set_level(spdlog::level::from_str(log_level));
    spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] [%t] %v");

    spdlog::info("Yuzu Server v{}", yuzu::kVersionString);

    std::signal(SIGINT,  on_signal);
    std::signal(SIGTERM, on_signal);

    auto server = yuzu::server::Server::create(std::move(cfg));
    g_server = server.get();
    server->run();

    return EXIT_SUCCESS;
}
