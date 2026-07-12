#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <io.h>
#pragma section(".CRT$XCB", read)
[[maybe_unused]] static void __cdecl diag_before_static_init() {
    const char msg[] = "[DIAG] EXE static-init starting (before C++ globals)\n";
    _write(2, msg, sizeof(msg) - 1);
}
__declspec(allocate(".CRT$XCB")) [[maybe_unused]] static void(__cdecl* p_diag_init)() = diag_before_static_init;
#endif

#include <yuzu/agent/agent.hpp>
#include <yuzu/agent/env_util.hpp>
#include <yuzu/agent/identity_store.hpp>
#include <yuzu/json_log_formatter.hpp>
#include <yuzu/version.hpp>

#include "service_win.hpp" // #1822: Windows SCM ServiceMain/control-handler dispatcher

#include <CLI/CLI.hpp>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

#include <atomic>
#include <csignal>
#ifdef _WIN32
#include <win_sc_handle.hpp> // shared yuzu::win SC_HANDLE RAII owner (#1822)
#else
#include <unistd.h>
#endif
#include <sqlite3.h>

#include <cstdlib>
#include <filesystem>
#include <format>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

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

// Verifies preconditions and constructs the Agent. Shared by the console path and
// the Windows service path (service_win.cpp's ServiceMain calls this on its own
// thread, after reporting SERVICE_START_PENDING) so both go through identical
// startup checks. Returns nullptr on failure; the reason is already spdlog'd.
static std::unique_ptr<yuzu::agent::Agent> make_agent(yuzu::agent::Config cfg) {
    // Verify SQLite was compiled with thread-safety (FULLMUTEX requires SQLITE_THREADSAFE != 0)
    if (sqlite3_threadsafe() == 0) {
        spdlog::critical(
            "SQLite compiled with SQLITE_THREADSAFE=0 — FULLMUTEX disabled, concurrent access unsafe");
        return nullptr;
    }

    // Resolve persistent agent ID
    auto id_result = yuzu::agent::resolve_agent_id(cfg.agent_id, cfg.data_dir / "agent.db");
    if (!id_result) {
        spdlog::error("Failed to resolve agent ID: {}", id_result.error().message);
        return nullptr;
    }
    cfg.agent_id = std::move(*id_result);
    spdlog::info("Agent ID: {}", cfg.agent_id);
    // Unconditional so a service left running against the wrong address (e.g. a
    // manual --install-service re-run that reset binPath and dropped a prior
    // --server, or a fleet upgrade script that didn't replay --server on a silent
    // reinstall) is diagnosable from the log alone -- the reconnect loop in run()
    // is otherwise silent about what it's even trying to reach (Gate 4 unhappy-
    // path finding, governance re-run).
    spdlog::info("Server address: {}", cfg.server_address);

    return yuzu::agent::Agent::create(std::move(cfg));
}

int main(int argc, char* argv[]) {
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
    // NOTE: no ->envname() here — CLI11 binds an env var as PRESENT/ABSENT and ignores
    // its value, so YUZU_TLS_SYSTEM_ROOTS=0 would still ENABLE the fallback (#1303 — a
    // footgun for a security flag). The env var is handled value-aware below (env_truthy),
    // seeded before parse so this CLI flag still wins (it can only ever opt IN, the secure
    // direction).
    app.add_flag("--tls-system-roots",
                 "Allow TLS verification against the SYSTEM trust store when no CA is pinned "
                 "(no --ca-cert and no install CA found). Use ONLY when the server certificate "
                 "chains to a public/corporate CA already in the system store — otherwise the "
                 "agent fails closed (#1303). Env: YUZU_TLS_SYSTEM_ROOTS=1/true/yes/on enables; "
                 "0/false/no/off/unset disables.")
        ->each([&cfg](const std::string&) { cfg.tls_allow_system_trust = true; });
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
    app.add_option("--cert-dir", cfg.cert_dir,
                   "Directory for the auto-provisioned per-agent mTLS credential "
                   "(default: <data-dir>/certs)")
        ->envname("YUZU_CERT_DIR");
    app.add_flag("--no-auto-provision-cert",
                 "Disable PKI auto-provisioning (do not generate a CSR / request a "
                 "per-agent client certificate at enrollment)")
        ->each([&cfg](const std::string&) { cfg.auto_provision_cert = false; });
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
    app.add_option("--plugin-allowlist", cfg.plugin_allowlist,
                   "Path to sha256sum-format allowlist file for plugin verification")
        ->envname("YUZU_PLUGIN_ALLOWLIST");
    app.add_option("--plugin-trust-bundle", cfg.plugin_trust_bundle,
                   "PEM CA bundle for plugin code-signing verification (operator-supplied "
                   "or pointing at the Yuzu self-managed CA root)")
        ->envname("YUZU_PLUGIN_TRUST_BUNDLE");
    app.add_flag("--plugin-require-signature", cfg.plugin_require_signature,
                 "Reject plugins that have no .sig sibling file (default: allow unsigned "
                 "if --plugin-trust-bundle is set, for transitional rollouts)")
        ->envname("YUZU_PLUGIN_REQUIRE_SIGNATURE");
    app.add_flag("--no-auto-update", "Disable OTA auto-updates")->each([&cfg](const std::string&) {
        cfg.auto_update = false;
    });
    int update_interval_sec = 21600;
    app.add_option("--update-check-interval", update_interval_sec,
                   "Update check interval in seconds (default: 21600 = 6h)")
        ->default_val(21600)
        ->envname("YUZU_UPDATE_CHECK_INTERVAL");
    app.add_flag("--dex-disable", cfg.dex_disable,
                 "Disable the Guardian DEX crash recorder (collect no process-crash "
                 "telemetry). Deploy-time opt-out; not a server-side runtime toggle.")
        ->envname("YUZU_AGENT_DEX_DISABLE");

    app.add_flag("--inventory-disable", cfg.inventory_disable,
                 "Disable the daily installed-software inventory sync (ADR-0016): collect "
                 "and push no installed-software inventory. Deploy-time opt-out for "
                 "jurisdictions / works-council agreements that require it off; not a "
                 "server-side runtime toggle.")
        ->envname("YUZU_AGENT_INVENTORY_DISABLE");

    app.add_flag("--spark-disable", cfg.spark_disable,
                 "Disable the SparkEngine detection engine (ADR-0021 Stage-2): do not "
                 "instantiate it and emit no spark telemetry. Deploy-time opt-out; the "
                 "enforcing legacy Guardian path is unaffected. Not a server-side runtime "
                 "toggle.")
        ->envname("YUZU_AGENT_SPARK_DISABLE");

    // Windows service management
    bool install_service = false;
    bool remove_service = false;
    bool service_mode = false;
    app.add_flag("--install-service", install_service, "Install as Windows service and exit");
    app.add_flag("--remove-service", remove_service, "Remove Windows service and exit");
    // Internal marker set by --install-service on the service binPath (and by the
    // installer) so the process knows to run under the SCM instead of as a console
    // program. Hidden from --help via the empty group; not meant for interactive use.
    app.add_flag("--service", service_mode, "Run under the Windows Service Control Manager")
        ->group("");

    // #1303: seed the security fallback from a VALUE-AWARE env var BEFORE parse so a
    // passed --tls-system-roots CLI flag still wins (it only opts in). Without this,
    // CLI11's presence-only envname would treat YUZU_TLS_SYSTEM_ROOTS=0 as "enabled" and
    // silently re-open the fail-open posture the operator believes is off.
    cfg.tls_allow_system_trust = yuzu::agent::env_truthy(std::getenv("YUZU_TLS_SYSTEM_ROOTS"));

    CLI11_PARSE(app, argc, argv);

#ifdef _WIN32
    if (install_service || remove_service) {
        yuzu::win::ScHandle scm;
        scm.reset(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS));
        if (!scm) {
            std::cerr << "Failed to open SCM (run as administrator)\n";
            return EXIT_FAILURE;
        }
        if (install_service) {
            wchar_t exe_path[MAX_PATH];
            DWORD exe_path_len = GetModuleFileNameW(nullptr, exe_path, MAX_PATH);
            if (exe_path_len == 0 || exe_path_len == MAX_PATH) {
                std::cerr << "Failed to resolve the agent's own executable path\n";
                return EXIT_FAILURE;
            }
            // #1822: quote the path (a bare path containing spaces, e.g. under
            // "Program Files", is otherwise misparsed by the SCM) and append the
            // --service marker the SCM-launched process needs to find the
            // ServiceMain dispatcher instead of running the console main().
            std::wstring bin_path = yuzu::agent::win::make_service_binpath(exe_path);

            yuzu::win::ScHandle svc;
            svc.reset(CreateServiceW(scm.get(), yuzu::agent::win::kServiceName, L"Yuzu Agent",
                                     SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                                     SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, bin_path.c_str(),
                                     nullptr, nullptr, nullptr, nullptr, nullptr));

            bool updated_existing = false;
            if (!svc) {
                DWORD create_err = GetLastError();
                if (create_err == ERROR_SERVICE_MARKED_FOR_DELETE) {
                    // 1072: the service was just deleted (e.g. a --remove-service
                    // moments earlier, or a concurrent uninstall) and stays in this
                    // state until every open handle to it closes -- typically the
                    // exiting old process's own SCM handle. Distinguished from the
                    // generic failure below so a scripted repair/reinstall doesn't
                    // read "Failed to create service" as an unrelated problem when a
                    // short retry would succeed (Gate 4 unhappy-path finding,
                    // governance re-run).
                    std::cerr << "Service is pending deletion from a recent removal -- "
                                 "wait a moment and retry --install-service\n";
                    return EXIT_FAILURE;
                }
                if (create_err != ERROR_SERVICE_EXISTS) {
                    std::cerr << "Failed to create service\n";
                    return EXIT_FAILURE;
                }
                // Idempotent re-install: heals a stale binPath from an earlier
                // (pre-#1822) install that lacks the --service marker, or one whose
                // args changed. SERVICE_NO_CHANGE preserves start type / error
                // control / everything else.
                svc.reset(OpenServiceW(scm.get(), yuzu::agent::win::kServiceName,
                                       SERVICE_CHANGE_CONFIG));
                if (!svc) {
                    std::cerr << "Service exists but could not be opened for update\n";
                    return EXIT_FAILURE;
                }
                if (!ChangeServiceConfigW(svc.get(), SERVICE_NO_CHANGE, SERVICE_NO_CHANGE,
                                          SERVICE_NO_CHANGE, bin_path.c_str(), nullptr, nullptr,
                                          nullptr, nullptr, nullptr, nullptr)) {
                    std::cerr << "Failed to update existing service configuration\n";
                    return EXIT_FAILURE;
                }
                updated_existing = true;
            }

            // Each of these is best-effort hardening on top of the core binPath fix
            // (description / delayed-start / crash-and-error recovery) -- a failure
            // here must not abort the install (the service is already usable
            // without it), but silently swallowing it would leave e.g. the
            // recovery-actions guarantee unconfigured while still printing
            // "installed successfully" (Gate-4 UP-6). Warn, don't abort.
            SERVICE_DESCRIPTIONW desc;
            desc.lpDescription = const_cast<wchar_t*>(L"Yuzu endpoint management agent");
            if (!ChangeServiceConfig2W(svc.get(), SERVICE_CONFIG_DESCRIPTION, &desc))
                std::cerr << "Warning: failed to set service description (" << GetLastError()
                          << ")\n";
            SERVICE_DELAYED_AUTO_START_INFO delayed = {TRUE};
            if (!ChangeServiceConfig2W(svc.get(), SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
                                       &delayed))
                std::cerr << "Warning: failed to set delayed auto-start (" << GetLastError()
                          << ")\n";
            SC_ACTION actions[3] = {
                {SC_ACTION_RESTART, 60000},
                {SC_ACTION_RESTART, 60000},
                {SC_ACTION_RESTART, 60000}};
            SERVICE_FAILURE_ACTIONSW failure = {};
            failure.dwResetPeriod = 86400;
            failure.cActions = 3;
            failure.lpsaActions = actions;
            if (!ChangeServiceConfig2W(svc.get(), SERVICE_CONFIG_FAILURE_ACTIONS, &failure))
                std::cerr << "Warning: failed to configure crash-recovery actions ("
                          << GetLastError() << ")\n";
            // #1822: recovery actions only fire on a crash by default -- also fire
            // them on a clean exit with an error (e.g. the #1303 fail-closed
            // startup refusal), approximating systemd's Restart=always.
            SERVICE_FAILURE_ACTIONS_FLAG flag{TRUE};
            if (!ChangeServiceConfig2W(svc.get(), SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, &flag))
                std::cerr << "Warning: failed to enable recovery-on-error-exit ("
                          << GetLastError() << ")\n";

            std::cout << (updated_existing ? "Service 'YuzuAgent' updated\n"
                                           : "Service 'YuzuAgent' installed successfully\n");
        }
        if (remove_service) {
            yuzu::win::ScHandle svc;
            svc.reset(
                OpenServiceW(scm.get(), yuzu::agent::win::kServiceName, DELETE | SERVICE_STOP));
            if (svc) {
                SERVICE_STATUS status;
                ControlService(svc.get(), SERVICE_CONTROL_STOP, &status);
                DeleteService(svc.get()) ? std::cout << "Service removed\n"
                                         : std::cerr << "Failed to delete service\n";
            } else {
                std::cerr << "Service not found\n";
                return EXIT_FAILURE;
            }
        }
        return EXIT_SUCCESS;
    }
#endif

    cfg.update_check_interval = std::chrono::seconds(update_interval_sec);

    cfg.log_level = log_level;
    if (cfg.verbose_logging) {
        log_level = "trace";
        cfg.log_level = "trace";
    }

    // Configure logging — stderr + optional rotating file
    spdlog::set_level(spdlog::level::from_str(log_level));
#ifdef _WIN32
    if (service_mode && log_file.empty()) {
        // No console under the SCM -- without --log-file the agent would log to
        // nowhere. Default alongside persistent state.
        log_file = (cfg.data_dir / "yuzu-agent.log").string();
    }
#endif
    if (!log_file.empty()) {
        try {
            std::vector<spdlog::sink_ptr> sinks;
            sinks.push_back(std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
                log_file, log_max_size, log_max_files));
#ifdef _WIN32
            if (!service_mode)
#endif
                sinks.push_back(std::make_shared<spdlog::sinks::stderr_color_sink_mt>());
            auto logger = std::make_shared<spdlog::logger>("", sinks.begin(), sinks.end());
            logger->set_level(spdlog::level::from_str(log_level));
            spdlog::set_default_logger(logger);
        } catch (const std::exception& e) {
            // A missing/unwritable log directory must not crash the process before
            // the SCM dispatcher connects (the same failure class #1822 fixes: an
            // uncaught exception here would silently reproduce error 1053).
            std::cerr << "Failed to open log file '" << log_file << "': " << e.what()
                      << " — falling back to the default logger\n";
        }
    }
    if (log_format == "json") {
        spdlog::set_formatter(std::make_unique<yuzu::JsonLogFormatter>("agent"));
    } else {
        spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] [%t] %v");
    }

    spdlog::info("Yuzu Agent v{} ({})", yuzu::kFullVersionString, yuzu::kGitCommitHash);

#ifdef _WIN32
    // #1822: hand off to the SCM ServiceMain dispatcher instead of running the
    // console path below. run_service() blocks for the lifetime of the service.
    if (service_mode) {
        return yuzu::agent::win::run_service(
            [cfg = std::move(cfg)]() mutable { return make_agent(std::move(cfg)); });
    }
#endif

    auto agent = make_agent(std::move(cfg));
    if (!agent)
        return EXIT_FAILURE;

    // Signal handling — installed only once `agent` exists (right after
    // make_agent() returns, right before g_agent is published), so on_signal
    // (which no-ops when g_agent is null) never silently swallows a Ctrl-C/
    // SIGTERM that arrives during make_agent()'s work (a SQLite open/write in
    // resolve_agent_id() plus a trivial in-memory Agent construction -- the
    // actual heavy work, plugin load and KV/TAR store open, happens later
    // inside agent->run() below, which was already covered by this
    // registration point before make_agent() existed). Installing the
    // handlers any earlier -- e.g. before calling make_agent() -- would
    // widen that pre-existing signal gap to cover make_agent()'s work too
    // (Gate 3 cpp-expert finding, governance re-run).
    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);
    g_agent.store(agent.get(), std::memory_order_release);
    agent->run();

    // #1303: a fatal STARTUP failure (e.g. the fail-closed TLS posture refused to
    // connect with no pinnable CA) must surface as a non-zero exit so systemd
    // Restart= / Docker / Windows SCM react, instead of a silent EXIT_SUCCESS.
    if (agent->startup_failed())
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
}
