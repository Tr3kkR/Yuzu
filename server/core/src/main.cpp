#include <yuzu/json_log_formatter.hpp>
#include <yuzu/server/auth.hpp>
#include <yuzu/server/auth_db.hpp>

#include "audit_store.hpp"
#include <yuzu/server/server.hpp>
#include <yuzu/version.hpp>

#include "insecure_tls_gate.hpp"
#include "security_headers.hpp"

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
#include <lmcons.h>  // UNLEN for GetUserNameA
#else
#include <pwd.h>     // getpwuid for the real OS principal
#include <unistd.h>
#endif
#include <sqlite3.h>

#include <format>
#include <iostream>
#include <memory>
#include <string>
#include <string_view>

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

// Resolve the real OS account running this process for break-glass audit
// attribution. Reads the kernel-authoritative identity (getpwuid(geteuid) /
// GetUserNameA) rather than getenv("USER"), which is inherited from the parent
// and trivially forgeable — a forged principal would poison the very evidence
// the break-glass audit row exists to provide (#1226 H-2).
static std::string resolve_os_principal() {
#ifdef _WIN32
    char name[UNLEN + 1];
    DWORD len = static_cast<DWORD>(sizeof(name));
    if (GetUserNameA(name, &len) && len > 1) {
        return std::string(name, len - 1); // len counts the trailing NUL
    }
    return "unknown";
#else
    if (struct passwd* pw = ::getpwuid(::geteuid()); pw && pw->pw_name && pw->pw_name[0] != '\0') {
        return std::string(pw->pw_name);
    }
    return "unknown";
#endif
}

// Minimal RFC 8259 string-content escaper for emitting a username inside a JSON
// status line. is_valid_username already restricts the charset so no escaping is
// strictly needed today, but output-encoding (not input validation) is the
// correct defence: this stays correct if the validator is ever relaxed (#1226 M-2).
static std::string json_escape(std::string_view s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\b': out += "\\b"; break;
        case '\f': out += "\\f"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (static_cast<unsigned char>(c) < 0x20) {
                out += std::format("\\u{:04x}", static_cast<unsigned char>(c));
            } else {
                out += c;
            }
        }
    }
    return out;
}

// Validate that the configured break-glass principal exists and carries a
// second factor. Mandatory-MFA is enforced FAIL-CLOSED: the sso-only escape
// hatch must never be a bare-password account (SOC 2 CC6.6). Shared by the
// server-start guard and the --break-glass-arm one-shot so both apply the same
// contract. Returns true on success; on failure returns false and sets `err`
// to an operator-facing reason.
static bool break_glass_user_valid(yuzu::server::AuthDB& db, const std::string& user,
                                   std::string& err) {
    if (!yuzu::server::is_valid_username(user)) {
        err = "not a valid username";
        return false;
    }
    auto exists = db.user_exists(user);
    if (!exists) {
        err = "auth store error while checking the account";
        return false;
    }
    if (!*exists) {
        err = "account does not exist";
        return false;
    }
    auto mfa = db.mfa_status(user);
    if (!mfa) {
        err = "auth store error while checking MFA enrollment";
        return false;
    }
    if (!mfa->enrolled) {
        err = "account has no MFA enrolled (a break-glass account must carry a second factor)";
        return false;
    }
    return true;
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

    app.add_option("--config", config_file, "Path to yuzu-server.cfg")->envname("YUZU_CONFIG");
    app.add_option("--data-dir", cfg.data_dir,
                   "Data directory for SQLite DBs (default: same directory as config file)")
        ->envname("YUZU_DATA_DIR");
    app.add_option("--postgres-dsn", cfg.postgres_dsn,
                   "PostgreSQL connection string (libpq conninfo or URI) for the server "
                   "storage substrate. REQUIRED — the server fails closed without a reachable "
                   "database (ADR-0006/0007). The agent stays SQLite.")
        ->envname("YUZU_POSTGRES_DSN");
    app.add_option("--postgres-pool-size", cfg.postgres_pool_size,
                   "Max concurrent PostgreSQL connections in the shared pool (default 16). "
                   "Raise for high agent counts / slow managed-PG links; tune against "
                   "yuzu_pg_pool_in_use and yuzu_pg_acquire_wait_seconds.")
        ->default_val(16)
        ->check(CLI::PositiveNumber)
        ->envname("YUZU_POSTGRES_POOL_SIZE");
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
    app.add_option("--cert", cfg.tls_server_cert, "PEM server certificate")->envname("YUZU_CERT");
    app.add_option("--key", cfg.tls_server_key, "PEM server private key")->envname("YUZU_KEY");
    app.add_flag("--no-default-certs",
                 "Do not auto-generate built-in default certificates on first boot; require "
                 "operator-provided certs instead (legacy refuse-to-start behaviour)")
        ->each([&cfg](const std::string&) { cfg.no_default_certs = true; })
        ->envname("YUZU_NO_DEFAULT_CERTS");
    app.add_option("--ca-dir", cfg.ca_dir,
                   "Directory for the built-in CA + default certs (default: platform cert dir)")
        ->envname("YUZU_CA_DIR");
    app.add_option("--cert-san", cfg.cert_sans,
                   "Extra Subject Alternative Name for the auto-generated default certs "
                   "(repeatable). Forms: 'dns:<name>', 'ip:<addr>', or a bare value "
                   "(auto-classified); a single value may be comma-separated. Added to the "
                   "https/agent/gateway default leaves so they validate for a deployment "
                   "hostname or IP (e.g. 'dns:gateway'). Ignored when operator certs are "
                   "supplied or --no-default-certs is set.")
        // #1271 cpp-expert: comma-splitting is done ONCE, in parse_extra_sans
        // (default_certs.cpp), NOT here — do NOT add CLI11 `->delimiter(',')`, or a
        // comma-separated value would be split twice (CLI11 tokens × the parser's
        // own comma loop) and mangle entries. Each CLI/env token reaches the parser
        // whole; the parser owns the comma semantics.
        ->envname("YUZU_CERT_SAN");
    app.add_option("--cert-group", cfg.cert_group,
                   "Shared POSIX group (name or gid) for the auto-generated cert volume "
                   "(PKI #1289). When set, the cert dir (0750) + default-gateway.key (0640) "
                   "are made group-readable so a gateway/agent running as a different uid in a "
                   "sibling container can read the shared CA + leaf out of /etc/yuzu/certs. "
                   "All three users must belong to this group. Empty (default) keeps tight "
                   "single-host perms (0700/0600). POSIX-only.")
        ->envname("YUZU_CERT_GROUP");
    app.add_option("--ca-cert", cfg.tls_ca_cert, "PEM CA cert (for mTLS agent verification)")
        ->envname("YUZU_CA_CERT");
    bool deprecated_allow_one_way_tls_flag = false;
    app.add_flag("--insecure-skip-client-verify",
                 "Allow TLS without --ca-cert (disables mTLS client verification). "
                 "Requires YUZU_ALLOW_INSECURE_TLS=1.")
        ->each([&cfg](const std::string&) { cfg.allow_one_way_tls = true; });
    app.add_flag("--allow-one-way-tls", "[DEPRECATED] Renamed to --insecure-skip-client-verify; "
                                        "still accepted for backward compatibility.")
        ->each([&cfg, &deprecated_allow_one_way_tls_flag](const std::string&) {
            cfg.allow_one_way_tls = true;
            deprecated_allow_one_way_tls_flag = true;
        });
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
    app.add_option("--gateway-command-addr", cfg.gateway_command_address,
                   "Gateway ManagementService address for command forwarding (host:port)")
        ->envname("YUZU_GATEWAY_COMMAND_ADDR");
    app.add_option("--trusted-nat-cidr", cfg.trusted_nat_cidrs,
                   "Multi-egress NAT/proxy CIDR(s) (e.g. 203.0.113.0/24,2001:db8::/32). A direct "
                   "agent whose Register and Subscribe source IPs both fall in one range is "
                   "tolerated instead of rejected (#1128). Repeatable or comma-separated.")
        ->delimiter(',')
        ->envname("YUZU_TRUSTED_NAT_CIDR");
    app.add_flag("--nat-trust-mtls-identity", cfg.nat_trust_mtls_identity,
                 "Also tolerate a peer-IP mismatch when the Subscribe mTLS identity matches the "
                 "Register-bound identity (#1128). SAFE ONLY WITH PER-AGENT CLIENT CERTS — a "
                 "shared fleet-wide cert makes this a session-replay bypass. Default off.")
        ->envname("YUZU_NAT_TRUST_MTLS_IDENTITY");
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

    // MFA / TOTP — SOC 2 CC6.6. See docs/auth-mfa-design.md.
    app.add_option("--mfa-enforcement", cfg.mfa_enforcement,
                   "MFA enforcement (default: optional). \"optional\" = self-service "
                   "enrollment, login never requires it. \"admin-only\" = admins must "
                   "enrol before login completes. \"required\" = every role must enrol. "
                   "Under admin-only/required an un-enrolled login is redirected through "
                   "TOTP enrollment (POST /login/mfa/enroll) before a session is minted.")
        ->default_val("optional")
        ->check(CLI::IsMember({"optional", "admin-only", "required"}))
        ->envname("YUZU_MFA_ENFORCEMENT");
    app.add_option("--mfa-step-up-window-secs", cfg.mfa_step_up_window_secs,
                   "Seconds after a TOTP proof that high-risk endpoints accept the session as "
                   "stepped-up (default: 300)")
        ->default_val(300)
        ->envname("YUZU_MFA_STEP_UP_WINDOW_SECS");
    app.add_option("--mfa-login-pending-secs", cfg.mfa_login_pending_secs,
                   "Seconds the intermediate mfa-pending token is valid between password "
                   "success and TOTP submission (default: 120)")
        ->default_val(120)
        ->envname("YUZU_MFA_LOGIN_PENDING_SECS");

    // Hardened authentication mode + break-glass — SOC 2 CC6.3/CC6.6.
    // See docs/auth-architecture.md "Hardened mode".
    app.add_option("--auth-mode", cfg.auth_mode,
                   "Local-password login policy (default: standard). \"standard\" = "
                   "password login enabled. \"sso-only\" = local-password login is "
                   "disabled fleet-wide (only OIDC SSO mints a session); the server "
                   "refuses to start without OIDC configured. A single --break-glass-user "
                   "is exempt while armed (see --break-glass-arm).")
        ->default_val("standard")
        ->check(CLI::IsMember({"standard", "sso-only"}))
        ->envname("YUZU_AUTH_MODE");
    app.add_option("--break-glass-user", cfg.break_glass_user,
                   "Username of the single local account exempt from --auth-mode=sso-only "
                   "while armed. Must exist and have MFA enrolled (enforced at boot). "
                   "Arm it out-of-band with --break-glass-arm.")
        ->envname("YUZU_BREAK_GLASS_USER");
    app.add_option("--break-glass-window-secs", cfg.break_glass_window_secs,
                   "Seconds the break-glass account stays armed after --break-glass-arm "
                   "(default: 86400 = 24h). The arm auto-expires — it is never permanent.")
        ->default_val(86400)
        ->check(CLI::PositiveNumber)
        ->envname("YUZU_BREAK_GLASS_WINDOW_SECS");

    // Account lockout — SOC 2 CC6.3. See docs/auth-architecture.md.
    app.add_option("--auth-lockout-threshold", cfg.auth_lockout_threshold,
                   "Consecutive failed local-password attempts before an account is temporarily "
                   "locked (default: 5). 0 disables lockout. The counter resets on a successful "
                   "login or an admin unlock.")
        ->default_val(5)
        // Fail fast on a negative value rather than silently treating it as
        // "disabled" (Hermes cyber-review F5 / Codex note). 0 is valid (off).
        ->check(CLI::NonNegativeNumber)
        ->envname("YUZU_AUTH_LOCKOUT_THRESHOLD");
    app.add_option("--auth-lockout-window-secs", cfg.auth_lockout_window_secs,
                   "Seconds an account stays locked after the threshold is crossed (default: 900). "
                   "The lock auto-expires after this window — it is never permanent.")
        ->default_val(900)
        // Reject 0 / negative at parse time instead of the runtime clamp-to-1s
        // surprise (Hermes cyber-review F5). A lock window must be >= 1 second.
        ->check(CLI::PositiveNumber)
        ->envname("YUZU_AUTH_LOCKOUT_WINDOW_SECS");

    // Metrics auth
    app.add_flag("--metrics-no-auth", "Allow unauthenticated /metrics access from any source")
        ->each([&cfg](const std::string&) { cfg.metrics_require_auth = false; })
        ->envname("YUZU_METRICS_NO_AUTH");

    // Security response headers (SOC2-C1)
    app.add_option("--csp-extra-sources", cfg.csp_extra_sources,
                   "Extra CSP sources appended to script-src/style-src/connect-src/img-src "
                   "(space-separated, e.g. \"https://cdn.example.com https://beacon.example.com\")")
        ->envname("YUZU_CSP_EXTRA_SOURCES");

    // MCP (Model Context Protocol) server
    app.add_flag("--mcp-disable", cfg.mcp_disable,
                 "Disable MCP endpoint entirely (rejects all /mcp/v1/ requests)")
        ->envname("YUZU_MCP_DISABLE");
    app.add_flag("--mcp-read-only", cfg.mcp_read_only,
                 "Restrict MCP to read-only tools only (no write/execute)")
        ->envname("YUZU_MCP_READ_ONLY");

    // Fleet visualization (PR 3 of feat/viz-engine ladder)
    app.add_flag("--viz-disable", cfg.viz_disable,
                 "Disable fleet visualization endpoints (/api/v1/viz/fleet/topology, "
                 "/fragments/viz/fleet/topology); both return 503")
        ->envname("YUZU_VIZ_DISABLE");

    // Product pack signature enforcement (#802 / W7.4)
    app.add_flag("--allow-unsigned-packs", cfg.allow_unsigned_packs,
                 "Accept product packs without an Ed25519 signature at install time. "
                 "DANGEROUS — exposes the fleet to arbitrary instruction/plugin execution "
                 "from any pack upload. Default off; set only for legacy environments that "
                 "have not yet adopted signing. Emits a `server.unsigned_packs_allowed` "
                 "audit event + startup warning when enabled.")
        ->envname("YUZU_ALLOW_UNSIGNED_PACKS");

    // Instruction-definition signature enforcement (#1073 / W7.4 sibling-gap)
    app.add_flag("--allow-unsigned-definitions", cfg.allow_unsigned_definitions,
                 "Accept InstructionDefinition imports without an Ed25519 signature at "
                 "import time. DANGEROUS — exposes the same fleet arbitrary-code-execution "
                 "surface that --allow-unsigned-packs covers on the ProductPack side: an "
                 "operator with InstructionDefinition:Write can publish a definition that "
                 "dispatches a malicious plugin invocation. Default off; set only for "
                 "legacy environments that have not yet adopted signing. Emits a "
                 "`server.unsigned_definitions_allowed` audit event + startup warning "
                 "when enabled.")
        ->envname("YUZU_ALLOW_UNSIGNED_DEFINITIONS");

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

    // Break-glass MFA reset mode (runs and exits, no server startup). Clears a
    // user's MFA enrollment out-of-band so an operator locked out by MFA
    // enforcement (lost device, IdP not asserting amr, sole admin who could not
    // enroll) can recover. Run on the server host as the service account. The
    // reset is audited (unlike the manual SQL break-glass it replaces). #1226.
    std::string mfa_reset_user;
    app.add_option("--mfa-reset", mfa_reset_user,
                   "Break-glass: clear MFA enrollment for the named user, then exit "
                   "(audited recovery from MFA lockout)");

    // Break-glass arm mode (runs and exits, no server startup). Arms the
    // configured --break-glass-user for --break-glass-window-secs so it can log
    // in locally under --auth-mode=sso-only. Run on the server host as the
    // service account (the IdP being down is precisely why break-glass exists,
    // so arming must NOT depend on a session). Audited. SOC 2 CC6.6.
    bool break_glass_arm = false;
    app.add_flag("--break-glass-arm", break_glass_arm,
                 "Break-glass: arm --break-glass-user for the configured window, then exit "
                 "(audited; enables local login under --auth-mode=sso-only)");

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
    app.add_flag("--no-https", "Disable HTTPS (insecure, for development only)")
        ->each([&cfg](const std::string&) { cfg.https_enabled = false; })
        ->envname("YUZU_NO_HTTPS");
    app.add_option("--https-port", cfg.https_port, "HTTPS port (default: 8443)")
        ->default_val(8443)
        ->envname("YUZU_HTTPS_PORT");
    app.add_option("--https-cert", cfg.https_cert_path, "PEM certificate for HTTPS")
        ->envname("YUZU_HTTPS_CERT");
    app.add_option("--https-key", cfg.https_key_path, "PEM private key for HTTPS")
        ->envname("YUZU_HTTPS_KEY");
    app.add_flag("--no-https-redirect", "Disable HTTP→HTTPS redirect")
        ->each([&cfg](const std::string&) { cfg.https_redirect = false; });

    // Certificate hot-reload options
    app.add_flag("--no-cert-reload", "Disable automatic certificate hot-reload")
        ->each([&cfg](const std::string&) { cfg.cert_reload_enabled = false; })
        ->envname("YUZU_NO_CERT_RELOAD");
    app.add_option("--cert-reload-interval", cfg.cert_reload_interval_seconds,
                   "Certificate reload polling interval in seconds (default: 60)")
        ->default_val(60)
        ->envname("YUZU_CERT_RELOAD_INTERVAL");

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
    app.add_flag("--oidc-skip-tls-verify", cfg.oidc_skip_tls_verify,
                 "Disable TLS certificate verification for OIDC endpoints (INSECURE, dev only)")
        ->envname("YUZU_OIDC_SKIP_TLS_VERIFY");

    // Data infrastructure options
    app.add_option("--response-retention-days", cfg.response_retention_days,
                   "Response retention period in days (default: 90)")
        ->default_val(90)
        ->envname("YUZU_RESPONSE_RETENTION_DAYS");
    app.add_option("--audit-retention-days", cfg.audit_retention_days,
                   "Audit log retention period in days (default: 365)")
        ->default_val(365)
        ->envname("YUZU_AUDIT_RETENTION_DAYS");
    app.add_option("--guardian-event-retention-days", cfg.guardian_event_retention_days,
                   "Guardian (guaranteed-state) event retention period in days (default: 30)")
        ->default_val(30)
        ->envname("YUZU_GUARDIAN_EVENT_RETENTION_DAYS");

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

    // Windows service management
    bool install_service = false;
    bool remove_service = false;
    app.add_flag("--install-service", install_service, "Install as Windows service and exit");
    app.add_flag("--remove-service", remove_service, "Remove Windows service and exit");

    CLI11_PARSE(app, argc, argv);

    // ── MFA enforcement mode advisory ──
    // Surface the active enforcement mode once at startup so an auditor
    // reading the boot log can confirm the deployment's posture (SOC 2
    // CC6.6 evidence). `admin-only` and `required` redirect an un-enrolled
    // login through TOTP enrollment before a session is minted; `optional`
    // (default) leaves enrollment self-service.
    if (cfg.mfa_enforcement != "optional") {
        spdlog::info("MFA enforcement active: mode={} — un-enrolled {} must complete TOTP "
                     "enrollment at login before a session is issued.",
                     cfg.mfa_enforcement,
                     cfg.mfa_enforcement == "required" ? "users" : "admins");
    }
    // ── Hardened auth mode guard + posture (SOC 2 CC6.3/CC6.6) ──
    // sso-only disables the local-password path, so OIDC must be configured or
    // every operator is locked out (the break-glass account is for an IdP
    // OUTAGE, not for never wiring SSO at all). Fail closed at boot with a clear
    // message rather than booting an unreachable server.
    if (cfg.auth_mode == "sso-only") {
        if (cfg.oidc_issuer.empty()) {
            spdlog::error("--auth-mode=sso-only disables local-password login but no OIDC "
                          "provider is configured (--oidc-issuer is empty). This would lock "
                          "every operator out. Configure OIDC SSO, or use --auth-mode=standard.");
            return EXIT_FAILURE;
        }
        spdlog::warn("Hardened auth mode ACTIVE (--auth-mode=sso-only): local-password login is "
                     "DISABLED fleet-wide; only OIDC SSO can mint a session.{}",
                     cfg.break_glass_user.empty()
                         ? std::string(" No break-glass account is configured.")
                         : std::format(" Break-glass account '{}' is exempt only while armed "
                                       "(--break-glass-arm).",
                                       cfg.break_glass_user));
    } else if (!cfg.break_glass_user.empty()) {
        // A break-glass user only means something under sso-only. Warn rather
        // than fail so a standard-mode deployment that pre-seeds the env var
        // (e.g. ahead of a planned hardening) still boots.
        spdlog::warn("--break-glass-user='{}' is set but --auth-mode is 'standard' — the "
                     "break-glass exemption only applies under --auth-mode=sso-only; ignoring.",
                     cfg.break_glass_user);
    }
    // Account lockout posture (SOC 2 CC6.3 evidence). Surfaced once at boot
    // so an operator/auditor can confirm the deployment's brute-force
    // protection from journald without scraping per-event logs. The posture
    // is gated on the auth.db store actually being wired (--data-dir set):
    // lockout state lives in auth.db, so in a config-file-only deployment
    // (auth_db_ == nullptr, the legacy fallback) every lockout op no-ops.
    // Claiming "active" there would overstate the deployed control
    // (governance/adversarial C4) — fail honest instead.
    if (cfg.auth_lockout_threshold > 0) {
        if (cfg.data_dir.empty()) {
            spdlog::warn("Account lockout CONFIGURED (threshold={}) but INACTIVE: failed-login "
                         "lockout requires the auth.db store, which is created only when "
                         "--data-dir is set. This config-file-only deployment has NO account "
                         "lockout. Set --data-dir to activate it.",
                         cfg.auth_lockout_threshold);
        } else {
            spdlog::info("Account lockout active: {} failed local-password attempts → locked "
                         "for {}s (auto-expiring).",
                         cfg.auth_lockout_threshold, cfg.auth_lockout_window_secs);
        }
    } else {
        spdlog::warn("Account lockout DISABLED (--auth-lockout-threshold=0) — local-password "
                     "logins have no brute-force throttle.");
    }
    // PR2 governance Gate 2 sec-M6: the step-up gate honours
    // window_secs <= 0 as an "escape hatch" that lets every request
    // through without re-prompting. The helper itself doesn't log on
    // every skip (too noisy), so we surface it once at startup so the
    // operator sees the disabled state in journald and an auditor
    // reading the boot log can spot a misconfigured deployment.
    if (cfg.mfa_step_up_window_secs <= 0) {
        spdlog::warn(
            "--mfa-step-up-window-secs={} disables the MFA step-up gate entirely. High-risk "
            "REST + Settings endpoints will NOT re-prompt for MFA proof. SOC 2 CC6.6 evidence "
            "rows (`mfa.step_up.required`) will not be emitted. Set to a positive value "
            "(default 300) to re-enable.",
            cfg.mfa_step_up_window_secs);
    }

    // ── Validate operator-supplied CSP extras (SOC2-C1, gov UP-1/UP-2) ──
    // Done immediately after CLI parse so operators see a clear startup
    // error rather than a silently-dropped CSP header on every response.
    if (auto validated = yuzu::server::security::validate_csp_extra_sources(cfg.csp_extra_sources);
        validated.has_value()) {
        cfg.csp_extra_sources = std::move(*validated);
    } else {
        std::cerr << "Invalid --csp-extra-sources: " << validated.error() << "\n";
        return EXIT_FAILURE;
    }

#ifdef _WIN32
    if (install_service || remove_service) {
        SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
        if (!scm) {
            std::cerr << "Failed to open SCM (run as administrator)\n";
            return EXIT_FAILURE;
        }
        if (install_service) {
            wchar_t exe_path[MAX_PATH];
            GetModuleFileNameW(nullptr, exe_path, MAX_PATH);
            SC_HANDLE svc =
                CreateServiceW(scm, L"YuzuServer", L"Yuzu Server", SERVICE_ALL_ACCESS,
                               SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
                               exe_path, nullptr, nullptr, nullptr, nullptr, nullptr);
            if (svc) {
                SERVICE_DESCRIPTIONW desc;
                desc.lpDescription = const_cast<wchar_t*>(L"Yuzu endpoint management server");
                ChangeServiceConfig2W(svc, SERVICE_CONFIG_DESCRIPTION, &desc);
                SERVICE_DELAYED_AUTO_START_INFO delayed = {TRUE};
                ChangeServiceConfig2W(svc, SERVICE_CONFIG_DELAYED_AUTO_START_INFO, &delayed);
                SC_ACTION actions[3] = {{SC_ACTION_RESTART, 60000},
                                        {SC_ACTION_RESTART, 60000},
                                        {SC_ACTION_RESTART, 60000}};
                SERVICE_FAILURE_ACTIONSW failure = {};
                failure.dwResetPeriod = 86400;
                failure.cActions = 3;
                failure.lpsaActions = actions;
                ChangeServiceConfig2W(svc, SERVICE_CONFIG_FAILURE_ACTIONS, &failure);
                CloseServiceHandle(svc);
                std::cout << "Service 'YuzuServer' installed successfully\n";
            } else {
                auto err = GetLastError();
                std::cerr << (err == ERROR_SERVICE_EXISTS ? "Service already exists\n"
                                                          : "Failed to create service\n");
                CloseServiceHandle(scm);
                return EXIT_FAILURE;
            }
        }
        if (remove_service) {
            SC_HANDLE svc = OpenServiceW(scm, L"YuzuServer", DELETE | SERVICE_STOP);
            if (svc) {
                SERVICE_STATUS status;
                ControlService(svc, SERVICE_CONTROL_STOP, &status);
                DeleteService(svc) ? std::cout << "Service removed\n"
                                   : std::cerr << "Failed to delete service\n";
                CloseServiceHandle(svc);
            } else {
                std::cerr << "Service not found\n";
                CloseServiceHandle(scm);
                return EXIT_FAILURE;
            }
        }
        CloseServiceHandle(scm);
        return EXIT_SUCCESS;
    }
#endif

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

    // ── Insecure-TLS gate (issue #79) ────────────────────────────────────────
    // Disabling client certificate verification requires BOTH a CLI flag AND
    // an explicit environment variable, so that no single misconfiguration
    // (typo, copy-pasted command, leaked CLI history) can silently downgrade
    // the agent listener from mTLS to one-way TLS.
    if (deprecated_allow_one_way_tls_flag) {
        spdlog::warn("--allow-one-way-tls is deprecated; use --insecure-skip-client-verify "
                     "instead (this flag will be removed in a future release).");
    }
    if (cfg.allow_one_way_tls && cfg.tls_enabled) {
        if (!yuzu::server::security::insecure_tls_env_authorized()) {
            spdlog::error("--insecure-skip-client-verify requires YUZU_ALLOW_INSECURE_TLS=1 "
                          "in the environment as a second confirmation. Refusing to start.");
            return EXIT_FAILURE;
        }
        spdlog::error("***********************************************************************");
        spdlog::error("*** CLIENT CERTIFICATE VERIFICATION DISABLED (one-way TLS)          ***");
        spdlog::error("*** Any network peer can connect to the agent listener AND the      ***");
        spdlog::error("*** management listener without an mTLS client certificate. This is ***");
        spdlog::error("*** acceptable ONLY for short-term development or migration         ***");
        spdlog::error("*** scenarios. Re-enable mTLS by supplying --ca-cert (and           ***");
        spdlog::error("*** --management-ca-cert if a management override is configured)    ***");
        spdlog::error("*** and removing --insecure-skip-client-verify.                     ***");
        spdlog::error("***********************************************************************");
    }

    // ── --no-tls warning banner ──────────────────────────────────────────────
    // --no-tls is the supported posture for UAT and customer demos until the
    // CA/CSR pipeline is automated. It is intentionally NOT gated behind an
    // env var (an operator passing --no-tls is opting in to plaintext loudly
    // and explicitly), but we make the degradation impossible to miss in logs.
    if (!cfg.tls_enabled) {
        spdlog::error("***********************************************************************");
        spdlog::error("*** --no-tls IS UNSAFE                                              ***");
        spdlog::error("*** TLS is fully disabled. The agent gRPC listener AND the          ***");
        spdlog::error("*** management gRPC listener accept plaintext connections from any  ***");
        spdlog::error("*** network peer with no encryption and no peer authentication.     ***");
        spdlog::error("*** The administrative surface is ungated. Anyone reachable on the  ***");
        spdlog::error("*** management port can issue admin RPCs.                           ***");
        spdlog::error("*** Use --no-tls ONLY for local UAT, customer demos, and dev work.  ***");
        spdlog::error("***********************************************************************");
    }

    // Verify SQLite was compiled with thread-safety (FULLMUTEX requires SQLITE_THREADSAFE != 0)
    if (sqlite3_threadsafe() == 0) {
        spdlog::critical("SQLite compiled with SQLITE_THREADSAFE=0 — FULLMUTEX disabled, "
                         "concurrent access unsafe");
        return EXIT_FAILURE;
    }

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

    // AuthDB lifetime — declared at function scope (NOT inside the
    // --data-dir block) so the unique_ptr outlives Server::create() and
    // server->run(). Storing &auth_db in AuthManager from inside the
    // else block (the previous shape) destroyed the AuthDB at the close
    // of the block, leaving AuthManager holding a dangling pointer for
    // the rest of main() — every authenticate() / upsert_user /
    // update_role / list_users call hit use-after-free in production
    // deployments with --data-dir set (governance round arch-B1
    // CRITICAL). Stays nullptr when no --data-dir is configured.
    std::unique_ptr<yuzu::server::AuthDB> auth_db;

    // If --data-dir was specified, ensure it exists and resolve to canonical path
    if (!cfg.data_dir.empty()) {
        std::error_code ec;
        std::filesystem::create_directories(cfg.data_dir, ec);
        if (ec) {
            spdlog::error("Cannot create data directory {}: {}", cfg.data_dir.string(),
                          ec.message());
            return EXIT_FAILURE;
        }
        // Resolve symlinks to prevent privileged write redirection
        auto canonical = std::filesystem::canonical(cfg.data_dir, ec);
        if (ec) {
            spdlog::error("Cannot resolve data directory {}: {}", cfg.data_dir.string(),
                          ec.message());
            return EXIT_FAILURE;
        }
        cfg.data_dir = canonical;

        // Writable probe — fail startup if directory is not writable rather than
        // deferring to the first DB open (which would leave the server running
        // but returning 503 on every store operation).
        auto probe = cfg.data_dir / ".yuzu-probe";
        {
            std::ofstream f(probe);
            if (!f.is_open()) {
                spdlog::error("Data directory {} is not writable", cfg.data_dir.string());
                return EXIT_FAILURE;
            }
        }
        std::filesystem::remove(probe, ec); // best-effort cleanup

        auth_mgr.set_data_dir(cfg.data_dir);
        // Re-load tokens and pending agents from the new data directory.
        // The initial load_config() loaded them from cfg_path_ parent (the old
        // location) because set_data_dir() hadn't been called yet.
        auth_mgr.reload_state();

        // -- Auth DB: Initialize SQLite-backed auth persistence -----------------
        // When --data-dir is specified, create and initialize the auth DB.
        // This provides persistent user/session/token storage that survives
        // container restarts (fixes GitHub issues #618, #388, #527, #391, #526).
        //
        // arch-B1 fix: assign through the function-scope unique_ptr declared
        // above. Do NOT redeclare a local AuthDB inside this block — the
        // pointer must outlive Server::create() and server->run() below.
        spdlog::info("Initializing auth DB in data directory: {}", cfg.data_dir.string());
        auth_db = std::make_unique<yuzu::server::AuthDB>(cfg.data_dir);
        auto db_result = auth_db->initialize();
        if (!db_result) {
            spdlog::error("Failed to initialize auth DB: {}", static_cast<int>(db_result.error()));
            return EXIT_FAILURE;
        }
        spdlog::info("Auth DB initialized successfully");

        // First-boot seeding: if auth DB has no users, seed admin from config file.
        // This ensures backwards compatibility — existing config-based users
        // are automatically migrated to the DB on first start.
        auto users_result = auth_db->list_users();
        if (users_result && users_result->empty()) {
            spdlog::info("Auth DB is empty — seeding admin user from config file");
            // The admin user was already loaded into auth_mgr via load_config(),
            // so we can read it back and persist to the DB.
            for (const auto& user : auth_mgr.list_users()) {
                auto seed_result =
                    auth_db->upsert_user(user.username, user.hash_hex, user.salt_hex, user.role);
                if (seed_result) {
                    spdlog::info("Seeded user '{}' (role={}) into auth DB", user.username,
                                 auth::role_to_string(user.role));
                } else {
                    spdlog::warn("Failed to seed user '{}' into auth DB", user.username);
                }
            }
        }

        spdlog::info("Data directory: {}", cfg.data_dir.string());

        // Wire AuthDB into AuthManager AFTER seeding is complete.
        // This ensures auth_mgr.list_users() reads from in-memory (config file)
        // during seeding, then delegates to AuthDB for all subsequent operations.
        // The raw pointer is safe: auth_db (the unique_ptr) lives in the outer
        // function scope and is destroyed only after server->run() returns
        // and AuthManager has gone out of scope.
        auth_mgr.set_auth_db(auth_db.get());
        spdlog::info("AuthManager configured to use AuthDB for persistence");
    }

    // -- Break-glass MFA reset mode (exits without starting server) -----------
    // Out-of-band recovery for an operator locked out by MFA enforcement.
    // Runs on the server host as the service account; clears the user's MFA
    // and writes an audit row (the manual SQL break-glass it replaces bypassed
    // the audit chain — #1226). Under enforcement the user is walked through
    // re-enrollment at their next login.
    if (!mfa_reset_user.empty()) {
        if (!auth_db) {
            spdlog::error("--mfa-reset requires the persistent auth store (auth.db); none is "
                          "configured for data dir '{}'",
                          cfg.data_dir.string());
            return EXIT_FAILURE;
        }
        // Defence-in-depth: validate the CLI arg before it touches the store
        // (governance sec-LOW-1). The SQL is parameterised and user_exists
        // would reject a non-conforming value anyway, but validating up front
        // keeps the charset guarantee local to the entry point.
        if (!yuzu::server::is_valid_username(mfa_reset_user)) {
            spdlog::error("--mfa-reset: '{}' is not a valid username", mfa_reset_user);
            std::cerr << "error: invalid username\n";
            return EXIT_FAILURE;
        }
        auto exists = auth_db->user_exists(mfa_reset_user);
        if (!exists) {
            // Distinguish a store error from a genuinely-absent user so an
            // operator mid-lockout isn't misled (governance cpp-safety SHOULD).
            spdlog::error("--mfa-reset: auth store error checking '{}': {}", mfa_reset_user,
                          static_cast<int>(exists.error()));
            std::cerr << "error: auth store unavailable\n";
            return EXIT_FAILURE;
        }
        if (!*exists) {
            spdlog::error("--mfa-reset: user '{}' not found", mfa_reset_user);
            std::cerr << "error: user '" << mfa_reset_user << "' not found\n";
            return EXIT_FAILURE;
        }
        // Audit is MANDATORY for break-glass: the whole point of #1226 is to
        // replace the manual-SQL path that left no evidence (SOC 2 CC6.6). So
        // open + verify the audit store is WRITABLE *before* mutating MFA — if
        // it isn't, refuse to proceed rather than silently clear a second factor
        // with no record (H-1). This also gives the operator an actionable error
        // instead of a buried warning during a stressful recovery.
        yuzu::server::AuditStore audit(cfg.data_dir / "audit.db");
        if (!audit.is_open()) {
            spdlog::error("--mfa-reset: audit store (audit.db in '{}') is not writable; refusing "
                          "to clear MFA without an audit record. Fix audit.db permissions/disk and "
                          "retry, or perform the reset via your documented break-glass SQL path "
                          "(which you must then record in change management).",
                          cfg.data_dir.string());
            std::cerr << "error: audit store unavailable; refusing to clear MFA without an audit "
                         "record\n";
            return EXIT_FAILURE;
        }
        if (auto r = auth_db->mfa_disable(mfa_reset_user); !r) {
            spdlog::error("--mfa-reset: failed to clear MFA for '{}'", mfa_reset_user);
            return EXIT_FAILURE;
        }
        // Attribute the break-glass to the KERNEL-AUTHORITATIVE OS identity, not
        // getenv("USER") — the env var is inherited from the parent and trivially
        // forgeable (USER=root ./yuzu-server --mfa-reset ...), which would let the
        // actor poison the very evidence this audit exists to provide (H-2).
        const std::string os_user = resolve_os_principal();
        yuzu::server::AuditEvent ev;
        ev.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                           std::chrono::system_clock::now().time_since_epoch())
                           .count();
        ev.principal = os_user;
        ev.principal_role = "break-glass";
        ev.action = "mfa.reset.breakglass";
        ev.target_type = "User";
        ev.target_id = mfa_reset_user;
        ev.result = "success";
        ev.detail = std::format("MFA enrollment cleared via --mfa-reset CLI (os_identity={})",
                                os_user);
        if (!audit.log(ev)) {
            // The pre-check passed but the write failed (e.g. disk filled mid-op).
            // MFA is already cleared; fail loudly and non-zero so automation and
            // the operator know the evidence row is missing and must be recorded.
            spdlog::error("--mfa-reset: MFA cleared for '{}' but the audit row failed to persist — "
                          "record this reset manually in your change-management system NOW",
                          mfa_reset_user);
            std::cerr << "error: MFA cleared but audit row failed to persist; record this reset "
                         "manually\n";
            return EXIT_FAILURE;
        }
        spdlog::info("Break-glass: MFA cleared for '{}'. The user can now sign in with their "
                     "password alone; under MFA enforcement they will be walked through "
                     "enrollment at next login.",
                     mfa_reset_user);
        std::cout << std::format("{{\"status\":\"ok\",\"user\":\"{}\",\"action\":\"{}\"}}\n",
                                 json_escape(mfa_reset_user), "mfa.reset.breakglass");
        return EXIT_SUCCESS;
    }

    // -- Break-glass arm mode (exits without starting server) -----------------
    // Arms the configured --break-glass-user for --break-glass-window-secs so it
    // can log in locally under --auth-mode=sso-only. Runs on the server host as
    // the service account — arming must NOT require a session, because the IdP
    // being down is exactly when you need it. The arm is audited (SOC 2 CC6.6),
    // attributed to the kernel-authoritative OS identity (not the forgeable
    // USER env var), and the audit store is verified writable BEFORE the mutate
    // so the exemption is never granted without an evidence row — mirrors the
    // --mfa-reset break-glass contract (#1226).
    if (break_glass_arm) {
        if (cfg.break_glass_user.empty()) {
            spdlog::error("--break-glass-arm requires --break-glass-user (or "
                          "YUZU_BREAK_GLASS_USER) to name the account to arm.");
            std::cerr << "error: --break-glass-arm requires --break-glass-user\n";
            return EXIT_FAILURE;
        }
        if (!auth_db) {
            spdlog::error("--break-glass-arm requires the persistent auth store (auth.db); none "
                          "is configured for data dir '{}'",
                          cfg.data_dir.string());
            return EXIT_FAILURE;
        }
        // Same fail-closed validation the running server applies: the account
        // must exist and carry a second factor before it can be armed.
        std::string why;
        if (!break_glass_user_valid(*auth_db, cfg.break_glass_user, why)) {
            spdlog::error("--break-glass-arm: refusing to arm '{}': {}", cfg.break_glass_user, why);
            std::cerr << "error: cannot arm break-glass account: " << why << "\n";
            return EXIT_FAILURE;
        }
        // Audit is MANDATORY (CC6.6): verify the audit store is WRITABLE before
        // arming, so the exemption is never granted without a record.
        yuzu::server::AuditStore audit(cfg.data_dir / "audit.db");
        if (!audit.is_open()) {
            spdlog::error("--break-glass-arm: audit store (audit.db in '{}') is not writable; "
                          "refusing to arm break-glass without an audit record.",
                          cfg.data_dir.string());
            std::cerr << "error: audit store unavailable; refusing to arm without an audit record\n";
            return EXIT_FAILURE;
        }
        auto armed = auth_db->arm_break_glass(cfg.break_glass_user, cfg.break_glass_window_secs);
        if (!armed) {
            spdlog::error("--break-glass-arm: failed to arm '{}' (auth store error {})",
                          cfg.break_glass_user, static_cast<int>(armed.error()));
            std::cerr << "error: failed to arm break-glass account\n";
            return EXIT_FAILURE;
        }
        const std::string os_user = resolve_os_principal();
        yuzu::server::AuditEvent ev;
        ev.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                           std::chrono::system_clock::now().time_since_epoch())
                           .count();
        ev.principal = os_user;
        ev.principal_role = "break-glass";
        ev.action = "auth.breakglass.armed";
        ev.target_type = "User";
        ev.target_id = cfg.break_glass_user;
        ev.result = "success";
        ev.detail = std::format("break-glass armed until {} ({}s window) via --break-glass-arm "
                                "CLI (os_identity={})",
                                armed->armed_until, cfg.break_glass_window_secs, os_user);
        if (!audit.log(ev)) {
            spdlog::error("--break-glass-arm: armed '{}' but the audit row failed to persist — "
                          "record this manually in change management NOW",
                          cfg.break_glass_user);
            std::cerr << "error: armed but audit row failed to persist; record this manually\n";
            return EXIT_FAILURE;
        }
        spdlog::warn("Break-glass account '{}' ARMED until {} ({}s). It can now sign in locally "
                     "under --auth-mode=sso-only (MFA still required). The arm auto-expires.",
                     cfg.break_glass_user, armed->armed_until, cfg.break_glass_window_secs);
        std::cout << std::format(
            "{{\"status\":\"ok\",\"user\":\"{}\",\"action\":\"auth.breakglass.armed\","
            "\"armed_until\":\"{}\"}}\n",
            json_escape(cfg.break_glass_user), json_escape(armed->armed_until));
        return EXIT_SUCCESS;
    }

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

    // ── Hardened-mode break-glass boot validation (SOC 2 CC6.6) ──
    // Under sso-only the break-glass account is the ONLY local-login path, so it
    // must exist and carry a second factor. Enforce fail-closed at boot rather
    // than discovering the misconfiguration during an IdP outage when an
    // operator is trying to break the glass. (Standard mode ignores the field;
    // it was already warned about above.)
    if (cfg.auth_mode == "sso-only" && !cfg.break_glass_user.empty()) {
        if (!auth_db) {
            spdlog::error("--auth-mode=sso-only with --break-glass-user requires the persistent "
                          "auth store (auth.db); set --data-dir.");
            return EXIT_FAILURE;
        }
        std::string why;
        if (!break_glass_user_valid(*auth_db, cfg.break_glass_user, why)) {
            spdlog::error("--break-glass-user='{}' is invalid under --auth-mode=sso-only: {}. "
                          "Fix the account (create it / enroll MFA) or correct the flag — "
                          "refusing to start with an unusable break-glass account.",
                          cfg.break_glass_user, why);
            return EXIT_FAILURE;
        }
    }

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    try {
        auto server = yuzu::server::Server::create(std::move(cfg), auth_mgr);
        g_server.store(server.get(), std::memory_order_release);
        server->run();
        if (server->startup_failed()) {
#ifdef _WIN32
            WSACleanup();
#endif
            return EXIT_FAILURE;
        }
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
