#pragma once

#include <chrono>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace yuzu::server::auth {
class AuthManager;
}

namespace yuzu::server {

struct Config {
    std::string listen_address{"0.0.0.0:50051"};     // Agent-facing gRPC
    std::string management_address{"0.0.0.0:50052"}; // Operator-facing gRPC
    std::string web_address{"127.0.0.1"};            // HTMX web UI bind address
    int web_port{8080};                              // HTMX web UI port

    bool tls_enabled{true};
    std::filesystem::path tls_server_cert; // PEM server certificate
    std::filesystem::path tls_server_key;  // PEM server private key
    std::filesystem::path tls_ca_cert;     // For mTLS agent verification
    bool allow_one_way_tls{false};         // Permit TLS without client cert verification

    // PKI default certs (PR2). With no operator cert flags and without
    // --no-default-certs, the server generates a per-install CA + server-side
    // leaves on first boot (default_certs.hpp). `ca_dir` defaults to
    // auth::default_cert_dir() when empty; `using_default_certs` is runtime state
    // the bootstrap sets to drive the notification surfaces + the
    // request-but-don't-require agent-listener posture (per-agent mTLS is PR3).
    bool no_default_certs{false};
    bool using_default_certs{false};       // any surface on default certs — drives notifications
    bool using_default_agent_certs{false}; // agent listener on default certs (don't-require posture)
    std::filesystem::path ca_dir;
    // Extra Subject Alternative Names to inject into the auto-generated default
    // leaves (--cert-san, repeatable). Each value is "dns:<name>", "ip:<addr>",
    // or a bare value auto-classified by IP-literal shape; a single value may be
    // comma-separated. Applied to every default leaf (https/server/gateway) so an
    // operator can make the built-in certs valid for a deployment hostname or IP
    // (e.g. "dns:gateway" so an agent verifying a gateway reached by that name
    // succeeds). Ignored when operator certs are supplied or --no-default-certs.
    std::vector<std::string> cert_sans;
    // Shared POSIX group (name or numeric gid) for the auto-generated cert volume
    // (--cert-group, PKI #1289). When set, the cert dir (0750) and the gateway
    // leaf key (0640) are chgrp'd to it so a gateway/agent running as a DIFFERENT
    // uid in a sibling container can read the shared CA + its leaf out of the
    // shared /etc/yuzu/certs volume. Empty (default) = tight single-host perms
    // (dir 0700, keys 0600). The server/HTTPS private keys stay 0600 regardless.
    std::string cert_group;

    // Optional management listener TLS override.
    // If left empty, management reuses the agent listener credentials.
    std::filesystem::path mgmt_tls_server_cert;
    std::filesystem::path mgmt_tls_server_key;
    std::filesystem::path mgmt_tls_ca_cert;

    // Session management
    std::chrono::seconds session_timeout{
        90}; // Agents disconnected after this many seconds without heartbeat
    std::size_t max_agents{10'000};

    // JIT admin elevation (SOC 2 CC6.3/CC6.6) — `/auth-and-authz` gap P1 #9.
    // Maximum lifetime (seconds) of a time-boxed admin elevation granted via
    // POST /api/v1/elevate; a request asking for longer is clamped to this. The
    // elevation is in-memory per-session and auto-reverts on lapse. Default
    // 3600 (1h). Wired via --jit-max-elevation-secs / YUZU_JIT_MAX_ELEVATION_SECS.
    int jit_max_elevation_secs{3600};

    // Operator dashboard idle (inactivity) session timeout — SOC 2 CC6.3.
    // Seconds of inactivity after which a cookie session is invalidated
    // server-side (a sliding window UNDER the absolute 8h session lifetime).
    // 0 (default) disables it — only the absolute lifetime applies; existing
    // deployments are unaffected. Enabling it (recommended 900 = 15 min)
    // satisfies the CC6.3 inactivity-timeout control. Wired via
    // --session-inactivity-secs / YUZU_SESSION_INACTIVITY_SECS into
    // AuthManager::set_session_inactivity. See docs/auth-architecture.md.
    int session_inactivity_secs{0};

    // Authentication
    std::filesystem::path auth_config_path; // yuzu-server.cfg path

    // Data directory (for all SQLite DBs and runtime state).
    // If empty, defaults to auth_config_path's parent directory.
    std::filesystem::path data_dir;

    /// Returns the directory where DBs and runtime state should be written.
    [[nodiscard]] std::filesystem::path db_dir() const {
        return data_dir.empty() ? auth_config_path.parent_path() : data_dir;
    }

    // PostgreSQL server storage substrate (ADR-0006/0007). libpq conninfo —
    // keyword/value or URI form — for the shared PgPool every Postgres-backed
    // server store uses. Wired via --postgres-dsn / YUZU_POSTGRES_DSN. The
    // server FAILS CLOSED (ADR-0007, no SQLite fallback) when this is empty or
    // the pool cannot reach the database: startup_failed() is set and run()
    // returns non-zero. The agent stays SQLite; this is server-only.
    std::string postgres_dsn;

    // Max concurrent PostgreSQL connections in the shared pool. Default 16.
    // Sizing guidance in docs/user-manual/server-admin.md; tuning signals are
    // yuzu_pg_pool_in_use / yuzu_pg_acquire_wait_seconds. Wired via
    // --postgres-pool-size / YUZU_POSTGRES_POOL_SIZE.
    int postgres_pool_size{16};

    // Gateway upstream (Erlang gateway → C++ server control plane)
    std::string gateway_upstream_address; // Empty = disabled; e.g. "0.0.0.0:50053"
    std::string gateway_command_address;  // Gateway ManagementService for command forwarding
    bool gateway_mode{false};             // When true, relax peer-mismatch in Subscribe

    // #1128: operator-declared multi-egress NAT/proxy ranges. When a direct-
    // connect agent's Register and Subscribe present different source IPs that
    // BOTH fall inside one of these CIDRs, the per-session peer-IP mismatch is
    // downgraded to advisory (audit + metric) instead of rejected. Empty = the
    // strict exact-match binding (default, no relaxation).
    std::vector<std::string> trusted_nat_cidrs;

    // #1128 / gov UP-2: opt-in to the mTLS-identity NAT accommodation. When
    // true, a peer-IP mismatch is also downgraded to advisory if the Subscribe
    // mTLS identity matches the one bound at Register. SAFE ONLY WITH PER-AGENT
    // CLIENT CERTS — a shared/fleet-wide cert makes every identity "match",
    // which would let an insider replay another agent's session from its own IP
    // (the IP guard is waived). Default false: identity-match never relaxes the
    // IP binding unless the operator affirms per-agent certs via this flag.
    bool nat_trust_mtls_identity{false};

    // NVD CVE feed
    std::string nvd_api_key; // Optional NVD API key for higher rate limits
    std::string nvd_proxy;   // HTTP proxy for NVD API (e.g. "http://proxy:8080")
    std::chrono::seconds nvd_sync_interval{4 * 3600}; // Default: 4 hours
    bool nvd_sync_enabled{true};

    // OTA agent updates
    std::filesystem::path
        update_dir;         // Directory for agent binaries (default: <config_dir>/agent-updates/)
    bool ota_enabled{true}; // Master switch for OTA updates

    // HTTPS for web dashboard
    bool https_enabled{true};
    int https_port{8443};
    std::filesystem::path https_cert_path;
    std::filesystem::path https_key_path;
    bool https_redirect{true}; // HTTP→HTTPS 301 redirect

    // Certificate hot-reload
    bool cert_reload_enabled{true};       // Auto-reload when cert/key files change on disk
    int cert_reload_interval_seconds{60}; // Polling interval in seconds

    // OIDC SSO
    std::string oidc_issuer;        // e.g. "https://login.microsoftonline.com/{tenant}/v2.0"
    std::string oidc_client_id;     // App registration client ID
    std::string oidc_client_secret; // Client secret (required for Entra web platform)
    std::string oidc_redirect_uri;  // Callback URL (auto-computed from web port if empty)
    std::string oidc_admin_group;   // Entra group ID that maps to admin role
    bool oidc_skip_tls_verify{
        false}; // Disable TLS cert verification for OIDC (insecure, for dev only)

    // SAML 2.0 SSO
    // Enabled when idp_sso_url + idp_cert + sp_entity_id + sp_acs_url are all non-empty
    // (mirrors OIDC's "gated on issuer && client_id" pattern).
    // Not supported on Windows builds — is_enabled() returns false (N4), and a startup
    // ERROR is logged if any flag is set.
    std::string saml_idp_entity_id; // IdP entityID (must match Issuer in assertions)
    std::string saml_idp_sso_url;   // IdP SSO URL (HTTP-Redirect binding endpoint)
    std::string saml_idp_cert;      // Filesystem path to IdP signing cert PEM (pinned key)
    std::string saml_sp_entity_id;  // SP entityID (used as AudienceRestriction)
    std::string saml_sp_acs_url;    // SP Assertion Consumer Service URL (POST binding)

    // Response persistence
    int response_retention_days{90};

    // Audit trail
    int audit_retention_days{365};

    // Guardian (Guaranteed State) event retention. Default 30d matches
    // kDefaultEventRetentionDays + the workstream-E data inventory.
    int guardian_event_retention_days{30};

    // Analytics
    bool analytics_enabled{true};
    int analytics_drain_interval_seconds{10};
    int analytics_batch_size{100};
    std::string clickhouse_url; // empty = disabled
    std::string clickhouse_database{"yuzu"};
    std::string clickhouse_table{"yuzu_events"};
    std::string clickhouse_username;
    std::string clickhouse_password;
    std::filesystem::path analytics_jsonl_path; // empty = disabled

    // Metrics
    bool metrics_require_auth{true}; // Require auth for remote /metrics access

    // Security response headers (SOC2-C1)
    // Extra source-list entries appended to script-src, style-src, connect-src,
    // and img-src CSP directives. Space-separated. Use to whitelist customer
    // CDNs, monitoring beacons, or analytics endpoints.
    std::string csp_extra_sources;

    // Rate limiting
    int rate_limit{100};      // Max API requests/second per IP
    int login_rate_limit{10}; // Max login attempts/second per IP

    // Account lockout — `/auth-and-authz` skill gap matrix P0 #2, SOC 2
    // CC6.3. After `auth_lockout_threshold` consecutive failed local-password
    // attempts the account is locked for `auth_lockout_window_secs`. The
    // counter resets on a successful login or an admin unlock. Threshold 0
    // disables the feature. The lock is temporary/auto-expiring so it cannot
    // be weaponised to permanently DoS a legitimate principal; OIDC and the
    // MFA code-verification path (which has its own rate-limit) are out of
    // scope. See docs/auth-architecture.md.
    int auth_lockout_threshold{5};     // consecutive failures before lock; 0 disables
    int auth_lockout_window_secs{900}; // lock duration, default 15 min

    // MFA / TOTP — `/auth-and-authz` skill gap matrix P0 #1, SOC 2 CC6.6.
    // See docs/auth-mfa-design.md. PR1 ships enforcement="optional" (self-
    // service enrollment, no enforcement at login). PR3 wires admin-only /
    // required by gating /login against users.mfa_enrolled_at.
    std::string mfa_enforcement{"optional"}; // "optional" | "admin-only" | "required"
    /// How long after a successful MFA proof (login or step-up) high-risk
    /// endpoints accept the session as "stepped up" without re-prompting.
    /// Default 300 s mirrors common bank/SaaS UX. Lowering to <60 s pushes
    /// every privileged click through TOTP; raising to >900 s weakens
    /// the CC6.6 evidence chain.
    int mfa_step_up_window_secs{300};
    /// How long the intermediate "mfa_pending" token is valid (window
    /// between password success and TOTP submission). Default 120 s.
    int mfa_login_pending_secs{120};

    // Hardened authentication mode + break-glass — `/auth-and-authz` skill gap
    // matrix P0 #3, SOC 2 CC6.3 (disable password fallback) + CC6.6
    // (constrained break-glass). See docs/auth-architecture.md "Hardened mode".
    //
    // "standard" (default) leaves local-password login enabled. "sso-only"
    // disables the local-password path fleet-wide — only OIDC SSO mints a
    // session — EXCEPT for a single designated break-glass account that is
    // exempt ONLY while armed (an out-of-band host operator ran
    // --break-glass-arm within the window). sso-only refuses to start without
    // OIDC configured (it would otherwise lock every operator out).
    std::string auth_mode{"standard"}; // "standard" | "sso-only"
    /// Username of the single local account exempt from sso-only while armed.
    /// Empty = no break-glass account. Must exist and have MFA enrolled
    /// (enforced fail-closed at boot under sso-only).
    std::string break_glass_user;
    /// Seconds the break-glass account stays armed after --break-glass-arm
    /// (default 86400 = 24h). The arm auto-expires (break_glass_armed_until is
    /// a future timestamp evaluated lazily at login, like locked_until) so it
    /// can never be a permanent standing exemption.
    int break_glass_window_secs{86400};

    // MCP (Model Context Protocol) server
    bool mcp_disable{false};   // Kill switch: reject all MCP requests
    bool mcp_read_only{false}; // Restrict MCP to read-only tools only

    // Fleet visualization (PR 3 of feat/viz-engine ladder)
    bool viz_disable{false}; // Kill switch: reject all /viz/fleet requests (DEP-1)

    // Product pack signature enforcement (#802 / W7.4)
    /// When true, install_pack accepts packs WITHOUT a `signature` field
    /// (legacy unsigned packs). Default false — the secure posture rejects
    /// unsigned packs to close the fleet-wide arbitrary-code-execution
    /// surface a MITM or unprivileged-uploader could otherwise exploit.
    /// Wired via --allow-unsigned-packs / YUZU_ALLOW_UNSIGNED_PACKS=1.
    /// Setting true at startup emits the `server.unsigned_packs_allowed`
    /// audit event + a startup spdlog::warn so the relaxed posture is
    /// loud in both audit log and operator-visible logs.
    bool allow_unsigned_packs{false};

    // Instruction-definition signature enforcement (#1073 / W7.4 sibling-gap)
    /// When true, `InstructionStore::import_definition_json` accepts
    /// definitions WITHOUT a `signature` field (legacy unsigned imports).
    /// Default false — the secure posture rejects unsigned imports to close
    /// the equivalent fleet-wide arbitrary-code-execution surface that #802
    /// closed for ProductPack: an operator with `InstructionDefinition:Write`
    /// can otherwise publish an arbitrary definition (carrying a plugin
    /// invocation) that executes on every targeted agent. Wired via
    /// --allow-unsigned-definitions / YUZU_ALLOW_UNSIGNED_DEFINITIONS=1.
    /// Setting true at startup emits the `server.unsigned_definitions_allowed`
    /// audit event + a startup spdlog::warn — exact parity with
    /// `--allow-unsigned-packs`.
    bool allow_unsigned_definitions{false};
};

/**
 * Server manages inbound agent connections and exposes a management gRPC API.
 */
class Server {
public:
    virtual ~Server() = default;

    [[nodiscard]] static std::unique_ptr<Server> create(Config config, auth::AuthManager& auth_mgr);

    /** Block and serve until stop() is called. */
    virtual void run() = 0;

    /** Graceful shutdown. Thread-safe. */
    virtual void stop() noexcept = 0;

    /** True when run() returned because startup failed (refuse-to-start), so the
     *  caller can exit non-zero — systemd Restart=on-failure / k8s crashloop
     *  detection need a non-zero code, not a silent clean exit. Default false. */
    [[nodiscard]] virtual bool startup_failed() const { return false; }
};

} // namespace yuzu::server
