#include <yuzu/json_log_formatter.hpp>
#include <yuzu/server/auth.hpp>
#include <yuzu/server/server.hpp>
#include <yuzu/version.hpp>

#include <CLI/CLI.hpp>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdlib>

#ifdef _WIN32
// clang-format off
#include <winsock2.h>  // must precede windows.h to avoid redefinition
#include <windows.h>
// clang-format on
#include <crtdbg.h>
#include <io.h>
#else
#include <unistd.h>
#endif
#include <format>
#include <iostream>
#include <memory>
#include <string>

static std::atomic<yuzu::server::Server*> g_server{nullptr};

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
    if (auto* s = g_server.load(std::memory_order_acquire))
        s->stop();
}

int main(int argc, char* argv[]) {
#ifdef _WIN32
    // Suppress all CRT/abort pop-up dialogs — route to stderr instead.
    _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDERR);
    _CrtSetReportMode(_CRT_ERROR, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_ERROR, _CRTDBG_FILE_STDERR);
    _CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_WARN, _CRTDBG_FILE_STDERR);
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);

    // Winsock must be initialised before any socket work (httplib, gRPC).
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        std::cerr << "WSAStartup failed\n";
        return EXIT_FAILURE;
    }
#endif

    CLI::App app{"Yuzu Server", "yuzu-server"};
    app.set_version_flag("--version",
                         std::format("{}  ({})", yuzu::kFullVersionString, yuzu::kGitCommitHash));

    yuzu::server::Config cfg;
    std::string log_level = "info";
    std::string log_format = "text";
    std::string log_file;
    size_t log_max_size = 50 * 1024 * 1024; // 50 MB
    int log_max_files = 5;
    std::string config_file;
    int rate_limit = 100;
    int login_rate_limit = 10;

    app.add_option("--config", config_file, "Path to yuzu-server.cfg")
        ->envname("YUZU_CONFIG");
    app.add_option("--listen", cfg.listen_address, "Agent gRPC address (host:port)")
        ->default_val("0.0.0.0:50051")
        ->envname("YUZU_LISTEN_ADDRESS");
    app.add_option("--management", cfg.management_address, "Management gRPC address (host:port)")
        ->default_val("0.0.0.0:50052")
        ->envname("YUZU_MANAGEMENT_ADDRESS");
    app.add_option("--web-address", cfg.web_address, "Web UI bind address")
        ->default_val("127.0.0.1")
        ->envname("YUZU_WEB_ADDRESS");
    app.add_option("--web-port", cfg.web_port, "Web UI port")
        ->default_val(8080)
        ->envname("YUZU_WEB_PORT");
    app.add_flag("--no-tls", "Disable TLS (insecure, for development only)")
        ->each([&cfg](const std::string&) { cfg.tls_enabled = false; });
    app.add_option("--cert", cfg.tls_server_cert, "PEM server certificate")
        ->envname("YUZU_CERT");
    app.add_option("--key", cfg.tls_server_key, "PEM server private key")
        ->envname("YUZU_KEY");
    app.add_option("--ca-cert", cfg.tls_ca_cert, "PEM CA cert (for mTLS agent verification)")
        ->envname("YUZU_CA_CERT");
    app.add_flag("--allow-one-way-tls", "Allow TLS without --ca-cert (disables mTLS)")
        ->each([&cfg](const std::string&) { cfg.allow_one_way_tls = true; });
    app.add_option("--management-cert", cfg.mgmt_tls_server_cert,
                   "PEM management server certificate override");
    app.add_option("--management-key", cfg.mgmt_tls_server_key,
                   "PEM management server private key override");
    app.add_option("--management-ca-cert", cfg.mgmt_tls_ca_cert,
                   "PEM CA cert for management client cert verification");
    app.add_option("--gateway-upstream", cfg.gateway_upstream_address,
                   "Gateway upstream gRPC address (host:port); empty = disabled")
        ->envname("YUZU_GATEWAY_UPSTREAM");
    app.add_flag("--gateway-mode", "Enable gateway mode (relax peer-mismatch in Subscribe)")
        ->each([&cfg](const std::string&) { cfg.gateway_mode = true; });
    app.add_option("--max-agents", cfg.max_agents, "Maximum concurrent agent connections")
        ->default_val(10000)
        ->envname("YUZU_MAX_AGENTS");
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
    app.add_option("--rate-limit", rate_limit, "Max API requests/second per IP (default: 100)")
        ->default_val(100)
        ->envname("YUZU_RATE_LIMIT");
    app.add_option("--login-rate-limit", login_rate_limit,
                   "Max login attempts/second per IP (default: 10)")
        ->default_val(10)
        ->envname("YUZU_LOGIN_RATE_LIMIT");

    // Batch token generation mode (runs and exits, no server startup)
    int generate_tokens = 0;
    std::string gen_label;
    int gen_max_uses = 1;
    int gen_ttl_hours = 0;
    app.add_option("--generate-tokens", generate_tokens,
                   "Generate N enrollment tokens and print to stdout (JSON), then exit");
    app.add_option("--token-label", gen_label, "Label prefix for generated tokens");
    app.add_option("--token-max-uses", gen_max_uses, "Max uses per token (default: 1)");
    app.add_option("--token-ttl-hours", gen_ttl_hours, "Token TTL in hours (0 = no expiry)");

    // NVD CVE feed options
    int nvd_sync_hours = 4;
    app.add_option("--nvd-api-key", cfg.nvd_api_key, "NVD API key (for higher rate limits)")
        ->envname("YUZU_NVD_API_KEY");
    app.add_option("--nvd-proxy", cfg.nvd_proxy, "HTTP proxy for NVD API (e.g. http://proxy:8080)")
        ->envname("YUZU_NVD_PROXY");
    app.add_option("--nvd-sync-interval", nvd_sync_hours, "NVD sync interval in hours (default: 4)")
        ->default_val(4)
        ->envname("YUZU_NVD_SYNC_INTERVAL");
    app.add_flag("--no-nvd-sync", "Disable NVD CVE feed sync")->each([&cfg](const std::string&) {
        cfg.nvd_sync_enabled = false;
    });

    // OTA agent update options
    app.add_option("--update-dir", cfg.update_dir, "Directory for agent update binaries")
        ->envname("YUZU_UPDATE_DIR");
    app.add_flag("--no-ota", "Disable OTA agent updates")->each([&cfg](const std::string&) {
        cfg.ota_enabled = false;
    });

    // HTTPS web dashboard options
    app.add_flag("--https", "Enable HTTPS for the web dashboard")->each([&cfg](const std::string&) {
        cfg.https_enabled = true;
    });
    app.add_option("--https-port", cfg.https_port, "HTTPS port (default: 8443)")
        ->default_val(8443)
        ->envname("YUZU_HTTPS_PORT");
    app.add_option("--https-cert", cfg.https_cert_path, "PEM certificate for HTTPS")
        ->envname("YUZU_HTTPS_CERT");
    app.add_option("--https-key", cfg.https_key_path, "PEM private key for HTTPS")
        ->envname("YUZU_HTTPS_KEY");
    app.add_flag("--no-https-redirect", "Disable HTTP→HTTPS redirect")
        ->each([&cfg](const std::string&) { cfg.https_redirect = false; });

    // OIDC SSO options
    app.add_option("--oidc-issuer", cfg.oidc_issuer,
                   "OIDC issuer URL (e.g. https://login.microsoftonline.com/{tenant}/v2.0)")
        ->envname("YUZU_OIDC_ISSUER");
    app.add_option("--oidc-client-id", cfg.oidc_client_id, "OIDC client ID (app registration)")
        ->envname("YUZU_OIDC_CLIENT_ID");
    app.add_option("--oidc-client-secret", cfg.oidc_client_secret,
                   "OIDC client secret (required for Entra/Azure AD web apps)")
        ->envname("YUZU_OIDC_CLIENT_SECRET");
    app.add_option("--oidc-redirect-uri", cfg.oidc_redirect_uri,
                   "OIDC redirect URI (default: auto-computed from web address/port)")
        ->envname("YUZU_OIDC_REDIRECT_URI");
    app.add_option("--oidc-admin-group", cfg.oidc_admin_group,
                   "Entra group object ID that maps to admin role")
        ->envname("YUZU_OIDC_ADMIN_GROUP");

    // Data infrastructure options
    app.add_option("--response-retention-days", cfg.response_retention_days,
                   "Response retention period in days (default: 90)")
        ->default_val(90)
        ->envname("YUZU_RESPONSE_RETENTION_DAYS");
    app.add_option("--audit-retention-days", cfg.audit_retention_days,
                   "Audit log retention period in days (default: 365)")
        ->default_val(365)
        ->envname("YUZU_AUDIT_RETENTION_DAYS");

    // Analytics options
    app.add_flag("--no-analytics", "Disable analytics event collection")
        ->each([&cfg](const std::string&) { cfg.analytics_enabled = false; });
    app.add_option("--analytics-drain-interval", cfg.analytics_drain_interval_seconds,
                   "Analytics drain interval in seconds (default: 10)")
        ->default_val(10);
    app.add_option("--analytics-batch-size", cfg.analytics_batch_size,
                   "Analytics drain batch size (default: 100)")
        ->default_val(100);
    app.add_option("--analytics-jsonl", cfg.analytics_jsonl_path,
                   "Path for JSON Lines analytics output file")
        ->envname("YUZU_ANALYTICS_JSONL");
    app.add_option("--clickhouse-url", cfg.clickhouse_url,
                   "ClickHouse HTTP URL (e.g. http://localhost:8123)")
        ->envname("YUZU_CLICKHOUSE_URL");
    app.add_option("--clickhouse-database", cfg.clickhouse_database,
                   "ClickHouse database name (default: yuzu)")
        ->default_val("yuzu")
        ->envname("YUZU_CLICKHOUSE_DATABASE");
    app.add_option("--clickhouse-table", cfg.clickhouse_table,
                   "ClickHouse table name (default: yuzu_events)")
        ->default_val("yuzu_events")
        ->envname("YUZU_CLICKHOUSE_TABLE");
    app.add_option("--clickhouse-user", cfg.clickhouse_username, "ClickHouse username")
        ->envname("YUZU_CLICKHOUSE_USER");
    app.add_option("--clickhouse-password", cfg.clickhouse_password, "ClickHouse password")
        ->envname("YUZU_CLICKHOUSE_PASSWORD");

    CLI11_PARSE(app, argc, argv);

    // Auto-compute OIDC redirect URI if not explicitly set
    if (!cfg.oidc_issuer.empty() && cfg.oidc_redirect_uri.empty()) {
        auto scheme = cfg.https_enabled ? "https" : "http";
        auto port = cfg.https_enabled ? cfg.https_port : cfg.web_port;
        cfg.oidc_redirect_uri = std::format("{}://localhost:{}/auth/callback", scheme, port);
    }

    cfg.nvd_sync_interval = std::chrono::seconds(nvd_sync_hours * 3600);
    cfg.rate_limit = rate_limit;
    cfg.login_rate_limit = login_rate_limit;

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
        spdlog::set_formatter(std::make_unique<yuzu::JsonLogFormatter>("server"));
    } else {
        spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] [%t] %v");
    }

    spdlog::info("Yuzu Server v{} ({})", yuzu::kFullVersionString, yuzu::kGitCommitHash);

    // -- Auth config loading / first-run setup --------------------------------

    namespace auth = yuzu::server::auth;

    auto cfg_path =
        config_file.empty() ? auth::default_config_path() : std::filesystem::path(config_file);

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
        auto ttl = gen_ttl_hours > 0 ? std::chrono::seconds(gen_ttl_hours * 3600)
                                     : std::chrono::seconds(0);

        auto tokens =
            auth_mgr.create_enrollment_tokens_batch(gen_label, generate_tokens, gen_max_uses, ttl);

        // Output JSON to stdout for scripting (Ansible, etc.)
        std::cout << "{\"count\":" << tokens.size() << ",\"tokens\":[\n";
        for (size_t i = 0; i < tokens.size(); ++i) {
            if (i > 0)
                std::cout << ",\n";
            std::cout << "  \"" << tokens[i] << "\"";
        }
        std::cout << "\n]}\n";

        spdlog::info("Generated {} enrollment tokens", tokens.size());
        return EXIT_SUCCESS;
    }

    // -------------------------------------------------------------------------

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    try {
        auto server = yuzu::server::Server::create(std::move(cfg), auth_mgr);
        g_server.store(server.get(), std::memory_order_release);
        server->run();
    } catch (const std::exception& ex) {
        spdlog::error("Fatal exception: {}", ex.what());
#ifdef _WIN32
        WSACleanup();
#endif
        return EXIT_FAILURE;
    } catch (...) {
        spdlog::error("Fatal unknown exception");
#ifdef _WIN32
        WSACleanup();
#endif
        return EXIT_FAILURE;
    }

#ifdef _WIN32
    WSACleanup();
#endif
    return EXIT_SUCCESS;
}
