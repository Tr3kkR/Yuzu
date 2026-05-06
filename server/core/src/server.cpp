// ServerImpl composition root — creates stores, wires route modules, manages lifecycle.
// Route handlers extracted to separate TUs (G3-ARCH-001 decomposition, 2026-03-28):
//   auth_routes, settings_routes, compliance_routes, workflow_routes,
//   notification_routes, webhook_routes, discovery_routes
// Inner classes extracted: agent_registry, agent_service_impl, gateway_service_impl, event_bus
// Pre-existing extractions: rest_api_v1, mcp_server

#include <yuzu/metrics.hpp>
#include <yuzu/secure_zero.hpp>
#include <yuzu/version.hpp>
#include "cert_reloader.hpp"
#include "file_utils.hpp"
#include "web_utils.hpp"
#include <yuzu/server/auth.hpp>
#include <yuzu/server/auto_approve.hpp>
#include <yuzu/server/server.hpp>

#include "agent.grpc.pb.h"
#include "analytics_event.hpp"
#include "store_errors.hpp"
#include "analytics_event_store.hpp"
#include "api_token_store.hpp"
#include "approval_manager.hpp"
#include "audit_store.hpp"
#include "compliance_eval.hpp"
#include "custom_properties_store.hpp"
#include "data_export.hpp"
#include "deployment_store.hpp"
#include "discovery_store.hpp"
#include "execution_event_bus.hpp"
#include "execution_tracker.hpp"
#include "gateway.grpc.pb.h"
#include "instruction_store.hpp"
#include "inventory_store.hpp"
// Visualization engine consumers live in dashboard_routes.cpp (#589) and
// rest_api_v1.cpp; server.cpp no longer references the engine directly.
#include "management.grpc.pb.h"
#include "management_group_store.hpp"
#include "notification_store.hpp"
#include "nvd_db.hpp"
#include "policy_store.hpp"
#include "guaranteed_state_store.hpp"
#include "product_pack_store.hpp"
#include "nvd_sync.hpp"
#include "oidc_provider.hpp"
#include "quarantine_store.hpp"
#include "rbac_store.hpp"
#include "response_store.hpp"
#include "mcp_jsonrpc.hpp"
#include "auth_routes.hpp"
#include "compliance_routes.hpp"
#include "dashboard_routes.hpp"
#include "discovery_routes.hpp"
#include "mcp_server.hpp"
#include "notification_routes.hpp"
#include "offload_routes.hpp"
#include "rest_api_v1.hpp"
#include "settings_routes.hpp"
#include "webhook_routes.hpp"
#include "workflow_routes.hpp"
#include "runtime_config_store.hpp"
#include "schedule_engine.hpp"
#include "scope_engine.hpp"
#include "instruction_db_pool.hpp"
#include "tag_store.hpp"
#include "update_registry.hpp"
#include "webhook_store.hpp"
#include "offload_target_store.hpp"
#include "workflow_engine.hpp"
#include "directory_sync.hpp"
#include "patch_manager.hpp"
#include "process_health.hpp"
#include "rate_limiter.hpp"
#include "security_headers.hpp"

#include "event_bus.hpp"
#include "agent_registry.hpp"
#include "agent_service_impl.hpp"
#include "gateway_service_impl.hpp"

#include <grpc/grpc_security_constants.h>
#include <grpcpp/grpcpp.h>
#include <grpcpp/health_check_service_interface.h>
#include <httplib.h>

// httplib compat: v0.18+ moved file upload helpers to req.form (MultipartFormData).
// CPPHTTPLIB_VERSION_NUM changed from int to string in v0.37+, so we detect via
// the presence of the Request::form member instead of a preprocessor version check.
#if __has_include(<httplib.h>)
// httplib 0.18+ has req.form.has_file(); older versions have req.has_file().
// We detect at compile time: if Request::form exists, use the new API.
namespace yuzu::detail {
template <typename T, typename = void> struct has_form_member : std::false_type {};
template <typename T>
struct has_form_member<T, std::void_t<decltype(std::declval<T>().form)>> : std::true_type {};
} // namespace yuzu::detail
template <typename Req> bool yuzu_req_has_file(const Req& req, const std::string& name) {
    if constexpr (yuzu::detail::has_form_member<Req>::value)
        return req.form.has_file(name);
    else
        return req.has_file(name);
}
template <typename Req> auto yuzu_req_get_file(const Req& req, const std::string& name) {
    if constexpr (yuzu::detail::has_form_member<Req>::value)
        return req.form.get_file(name);
    else
        return req.get_file_value(name);
}
#define YUZU_REQ_HAS_FILE(req, name) yuzu_req_has_file(req, name)
#define YUZU_REQ_GET_FILE(req, name) yuzu_req_get_file(req, name)
#endif

#include <nlohmann/json.hpp>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

#include <atomic>
#include <cctype>
#include <charconv>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <ctime>
#include <deque>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <ranges>
#include <set>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// Defined in dashboard_ui.cpp (separate TU to isolate MSVC raw-string issues).
extern const char* const kDashboardIndexHtml;

// Legacy UIs kept for backward compatibility (redirect to /).
extern const char* const kChargenIndexHtml;
extern const char* const kProcfetchIndexHtml;

// Login and Settings pages (separate TUs).
extern const char* const kLoginHtml;
extern const char* const kSettingsHtml;

// Help and Instruction management pages (separate TUs).
extern const char* const kHelpHtml;
extern const char* const kInstructionPageHtml;
extern const char* const kTarPageHtml;
extern const char* const kInstructionEditorHtml;
extern const char* const kInstructionEditorDeniedHtml;

// Shared design system assets (icons_svg.cpp + build-time embed targets).
extern const char* const kYuzuIconsSvg;
extern const std::string kHtmxJs;
extern const std::string kSseJs;
namespace yuzu::server {
extern const std::string kYuzuCss; // server/core/static/yuzu.css (build-time embed)
extern const std::string kYuzuChartsJs;
extern const std::string kEChartsJs; // server/core/vendor/echarts.min.js (Apache-2.0)
extern const std::string_view
    kInterVariableWoff2; // server/core/vendor/inter/InterVariable.woff2 (SIL OFL)
extern const std::vector<std::string>
    kBundledDefinitions;                            // build-time embed of content/definitions/
extern const std::vector<std::string> kBundledSets; // build-time embed of content/packs/*sets*
} // namespace yuzu::server

namespace yuzu::server {

namespace detail {

// -- Platform-specific log path -----------------------------------------------

[[nodiscard]] std::filesystem::path server_log_path() {
#ifdef _WIN32
    return R"(C:\ProgramData\Yuzu\logs\server.log)";
#elif defined(__APPLE__)
    if (const char* home = std::getenv("HOME")) {
        return std::filesystem::path(home) / "Library/Logs/Yuzu/server.log";
    }
    return "/Library/Logs/Yuzu/server.log";
#else
    return "/var/log/yuzu/server.log";
#endif
}
} // namespace detail

// -- ServerImpl ---------------------------------------------------------------

class ServerImpl final : public Server {
public:
    explicit ServerImpl(Config cfg, auth::AuthManager& auth_mgr)
        : cfg_(std::move(cfg)), auth_mgr_(auth_mgr), auto_approve_(), metrics_(), event_bus_(),
          registry_(event_bus_, metrics_),
          agent_service_(registry_, event_bus_, cfg_.tls_enabled && !cfg_.tls_ca_cert.empty(),
                         auth_mgr, auto_approve_, metrics_, cfg_.gateway_mode),
          api_rate_limiter_(cfg_.rate_limit), login_rate_limiter_(cfg_.login_rate_limit) {
        // Register metric descriptions
        metrics_.describe("yuzu_agents_connected", "Number of currently connected agents", "gauge");
        metrics_.describe("yuzu_agents_registered_total", "Total number of agent registrations",
                          "counter");
        metrics_.describe("yuzu_commands_dispatched_total",
                          "Total number of commands dispatched to agents", "counter");
        metrics_.describe("yuzu_commands_completed_total",
                          "Total number of completed commands by status", "counter");
        metrics_.describe("yuzu_command_duration_seconds", "Command execution latency in seconds",

                          "histogram");
        metrics_.describe("yuzu_grpc_requests_total", "Total gRPC requests by method and status",
                          "counter");
        metrics_.describe("yuzu_http_requests_total", "Total HTTP requests by path and status",
                          "counter");
        // Fleet health metrics (aggregated from agent heartbeat status_tags)
        metrics_.describe("yuzu_fleet_agents_healthy",
                          "Number of agents reporting healthy via heartbeat", "gauge");
        metrics_.describe("yuzu_fleet_agents_by_os", "Connected agents by operating system",
                          "gauge");
        metrics_.describe("yuzu_fleet_agents_by_arch", "Connected agents by CPU architecture",
                          "gauge");
        metrics_.describe("yuzu_fleet_agents_by_version", "Connected agents by agent version",
                          "gauge");
        metrics_.describe("yuzu_fleet_commands_executed_total",
                          "Fleet-wide commands executed (sum of agent-reported counts)", "gauge");
        metrics_.describe("yuzu_server_management_groups_total",
                          "Total number of management groups", "gauge");
        metrics_.describe("yuzu_server_group_members_total",
                          "Total members across all management groups", "gauge");
        metrics_.describe("yuzu_heartbeats_received_total", "Total heartbeats received from agents",
                          "counter");
        metrics_.describe("yuzu_server_cert_reloads_total",
                          "Total successful certificate hot-reloads", "gauge");
        metrics_.describe("yuzu_server_cert_reload_failures_total",
                          "Total failed certificate hot-reload attempts", "gauge");
        metrics_.describe("yuzu_server_token_cache_hits_total",
                          "API token validate_token calls served from in-memory cache", "counter");
        metrics_.describe("yuzu_server_token_cache_misses_total",
                          "API token validate_token calls that fell through to SQLite", "counter");
        metrics_.describe("yuzu_server_token_cache_size",
                          "Distinct API tokens currently held in the validate_token cache",
                          "gauge");
        metrics_.describe("yuzu_server_audit_events_total",
                          "Audit events written, bucketed by result", "counter");
        // Audit-pipeline observability (governance PR4 OBS-4). Increments when
        // audit_store->add_event()'s SQLite step does not return DONE — pages
        // operators that the audit chain itself is degraded.
        metrics_.describe("yuzu_server_audit_emit_failed_total",
                          "Audit events that failed to persist (sqlite3_step != DONE)", "counter");
        // Login-latency observability (governance PR4 OBS-2). Histogram of
        // PBKDF2 verify duration, labelled by result so alerts can fire on
        // success-path regressions independently of brute-force noise on
        // bad_password / unknown_user.
        metrics_.describe("yuzu_auth_login_duration_seconds",
                          "Login PBKDF2 verify latency in seconds, by method and result",
                          "histogram");
        // Guardian observability (#452 §6). Sized at zero before ingest
        // starts so Prometheus alert rules on these metric names can be
        // authored up front — e.g. events_total > 5e6 as an early-warning
        // for reaper failure or retention misconfiguration.
        metrics_.describe("yuzu_server_guardian_rules_total",
                          "Total Guaranteed-State rules persisted", "gauge");
        metrics_.describe("yuzu_server_guardian_events_total",
                          "Total Guaranteed-State events currently persisted", "gauge");
        metrics_.describe("yuzu_server_guardian_events_written_total",
                          "Cumulative Guaranteed-State events ever written (pre-reap)", "counter");
        metrics_.describe("yuzu_server_guardian_events_reaped_total",
                          "Cumulative Guaranteed-State events deleted by the retention reaper",
                          "counter");
        // Process health metrics (capability 22.1)
        metrics_.describe("yuzu_server_cpu_usage_percent", "Server process CPU usage percentage",
                          "gauge");
        metrics_.describe("yuzu_server_memory_bytes", "Server process memory usage in bytes",
                          "gauge");
        metrics_.describe("yuzu_server_open_connections", "Number of connected gRPC agent streams",
                          "gauge");
        metrics_.describe("yuzu_server_command_queue_depth",
                          "Number of in-flight command executions", "gauge");
        metrics_.describe("yuzu_server_uptime_seconds", "Server process uptime in seconds",
                          "gauge");
        // PR 5b — surface ExecutionEventBus internals so SREs can alert on
        // SSE backpressure (events_dropped non-zero rate), retention-window
        // sizing (gc_channels_total trend), and live-subscriber load
        // (subscribers_active gauge). Pairs with the bounded ring buffer
        // contract documented in CLAUDE.md "Executions-history ladder PR 3".
        metrics_.describe("yuzu_server_sse_channels_active",
                          "Per-execution SSE channels currently in the bus map", "gauge");
        metrics_.describe("yuzu_server_sse_subscribers_active",
                          "Total live SSE subscribers across all channels", "gauge");
        metrics_.describe("yuzu_server_sse_events_dropped_total",
                          "Cumulative SSE events dropped by the ring buffer "
                          "(slow-subscriber backpressure signal)",
                          "counter");
        metrics_.describe("yuzu_server_sse_gc_sweeps_total",
                          "Cumulative ExecutionEventBus GC sweeps run", "counter");
        metrics_.describe("yuzu_server_sse_gc_channels_total",
                          "Cumulative SSE channels reaped after retention "
                          "window + zero subscribers",
                          "counter");

        // Wire health store into agent service
        agent_service_.set_health_store(&health_store_);

        // Wire metrics registry into auth manager so authenticate() can
        // observe login latency. Optional in tests/CLI tools that don't
        // construct a ServerImpl (auth_mgr_.metrics_ stays nullptr there).
        auth_mgr_.set_metrics_registry(&metrics_);

        // Create gateway upstream service if configured
        if (!cfg_.gateway_upstream_address.empty()) {
            gateway_service_ = std::make_unique<detail::GatewayUpstreamServiceImpl>(
                registry_, event_bus_, auth_mgr, auto_approve_, &metrics_, &health_store_);
        }

        // Create gateway management client for command forwarding
        if (!cfg_.gateway_command_address.empty()) {
            gw_mgmt_channel_ = grpc::CreateChannel(cfg_.gateway_command_address,
                                                   grpc::InsecureChannelCredentials());
            gw_mgmt_stub_ = ::yuzu::server::v1::ManagementService::NewStub(gw_mgmt_channel_);
            spdlog::info("Gateway command forwarding enabled: {}", cfg_.gateway_command_address);
        }

        // Load auto-approve policies
        auto approve_path = cfg_.db_dir() / "auto-approve.cfg";
        auto_approve_.load(approve_path);

        // Initialize OIDC provider if configured
        if (!cfg_.oidc_issuer.empty() && !cfg_.oidc_client_id.empty()) {
            oidc::OidcConfig oidc_cfg;
            oidc_cfg.issuer = cfg_.oidc_issuer;
            oidc_cfg.client_id = cfg_.oidc_client_id;
            oidc_cfg.client_secret = cfg_.oidc_client_secret;
            oidc_cfg.redirect_uri = cfg_.oidc_redirect_uri;
            oidc_cfg.admin_group_id = cfg_.oidc_admin_group;
            oidc_cfg.skip_tls_verify = cfg_.oidc_skip_tls_verify;
            if (cfg_.oidc_skip_tls_verify)
                spdlog::warn(
                    "OIDC TLS certificate verification DISABLED — do not use in production");
            // Fallback endpoints for Entra ID — OidcProvider constructor will
            // override from the OIDC discovery document if reachable.
            // Entra v2.0 pattern: issuer is .../v2.0, endpoints are .../oauth2/v2.0/...
            auto issuer = cfg_.oidc_issuer;
            auto v2_pos = issuer.rfind("/v2.0");
            if (v2_pos != std::string::npos) {
                auto base = issuer.substr(0, v2_pos);
                oidc_cfg.authorization_endpoint = base + "/oauth2/v2.0/authorize";
                oidc_cfg.token_endpoint = base + "/oauth2/v2.0/token";
            } else {
                oidc_cfg.authorization_endpoint = issuer + "/authorize";
                oidc_cfg.token_endpoint = issuer + "/token";
            }
            // Token exchange helper script (Python subprocess workaround for
            // httplib OpenSSL client issues on Windows)
            auto script_dir =
                std::filesystem::path(cfg_.auth_config_path).parent_path().parent_path() /
                "scripts" / "oidc_token_exchange.py";
            // Try source tree location first (development), then installed location
            auto src_script =
                std::filesystem::current_path() / "scripts" / "oidc_token_exchange.py";
            if (std::filesystem::exists(src_script))
                oidc_cfg.exchange_script = src_script.string();
            else if (std::filesystem::exists(script_dir))
                oidc_cfg.exchange_script = script_dir.string();
            spdlog::info("OIDC exchange script: {}", oidc_cfg.exchange_script);

            oidc_provider_ = std::make_unique<oidc::OidcProvider>(std::move(oidc_cfg));
        }

        // Setup file logger.
        //
        // The default platform log paths (/var/log/yuzu on Linux,
        // C:\ProgramData\Yuzu\logs on Windows, ~/Library/Logs/Yuzu on macOS)
        // may not exist or be writable in containerised or rootless
        // deployments. Issue #624: when the directory cannot be created we
        // used to log a WARN + ERROR pair on every boot which made operators
        // think the server was broken. The file logger is best-effort
        // observability, not load-bearing — if the path is unwritable we
        // log a single info line and proceed. Operators who want file
        // logging can pass --log-file explicitly (handled separately in
        // main.cpp).
        auto log_path = detail::server_log_path();
        auto parent = log_path.parent_path();
        bool parent_ready = parent.empty();
        if (!parent.empty()) {
            std::error_code ec;
            std::filesystem::create_directories(parent, ec);
            parent_ready = !ec;
            if (ec) {
                // INFO not DEBUG (governance Gate 7): default loglevel is INFO,
                // so DEBUG is invisible — operators auditing the SOC 2 evidence
                // chain or troubleshooting "where did my logs go?" need a single
                // visible breadcrumb. WARN was the original UX bug (false-positive
                // scary message on every container boot when the directory simply
                // didn't exist). INFO is the canonical "single startup crumb"
                // level — appears in default operator output, no alarm semantics.
                spdlog::info("Default log directory {} not creatable ({}); "
                             "skipping default file logger. Pass --log-file to override.",
                             parent.string(), ec.message());
            }
        }
        if (parent_ready) {
            try {
                file_logger_ = spdlog::basic_logger_mt("server_file", log_path.string());
                file_logger_->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [server] %v");
                file_logger_->flush_on(spdlog::level::info);
                spdlog::info("Log file: {}", log_path.string());
            } catch (const spdlog::spdlog_ex& ex) {
                // INFO not DEBUG — see rationale on the create_directories
                // branch above.
                spdlog::info("Default file logger unavailable ({}); "
                             "pass --log-file to override.",
                             ex.what());
            }
        }

        // Initialize NVD CVE database
        auto nvd_path = cfg_.db_dir() / "nvd_cves.db";
        nvd_db_ = std::make_shared<NvdDatabase>(nvd_path);

        if (cfg_.nvd_sync_enabled && nvd_db_->is_open()) {
            nvd_sync_ = std::make_unique<NvdSyncManager>(nvd_db_, cfg_.nvd_api_key, cfg_.nvd_proxy,
                                                         cfg_.nvd_sync_interval);
            nvd_sync_->start();
        }

        // Initialize OTA update registry
        if (cfg_.ota_enabled) {
            auto update_db_path = cfg_.db_dir() / "update_packages.db";
            auto update_dir =
                cfg_.update_dir.empty() ? cfg_.db_dir() / "agent-updates" : cfg_.update_dir;
            std::error_code ec;
            std::filesystem::create_directories(update_dir, ec);
            update_registry_ = std::make_unique<UpdateRegistry>(update_db_path, update_dir);
            agent_service_.set_update_registry(update_registry_.get());
        }

        // Wire up cross-references for AgentServiceImpl
        // (done after stores are created below)

        // Initialize response store
        {
            auto resp_db = cfg_.db_dir() / "responses.db";
            response_store_ =
                std::make_unique<ResponseStore>(resp_db, cfg_.response_retention_days);
            if (response_store_->is_open()) {
                response_store_->start_cleanup();
            }
        }

        // Initialize audit store
        {
            auto audit_db = cfg_.db_dir() / "audit.db";
            audit_store_ = std::make_unique<AuditStore>(audit_db, cfg_.audit_retention_days);
            if (audit_store_->is_open()) {
                audit_store_->start_cleanup();
            }
        }

        // Initialize tag store
        {
            auto tag_db = cfg_.db_dir() / "tags.db";
            tag_store_ = std::make_unique<TagStore>(tag_db);
        }

        // Initialize analytics event store
        if (cfg_.analytics_enabled) {
            auto analytics_db = cfg_.db_dir() / "analytics.db";
            analytics_store_ = std::make_unique<AnalyticsEventStore>(
                analytics_db, cfg_.analytics_drain_interval_seconds, cfg_.analytics_batch_size);
            if (analytics_store_->is_open()) {
                if (!cfg_.analytics_jsonl_path.empty()) {
                    analytics_store_->add_sink(make_jsonlines_sink(cfg_.analytics_jsonl_path));
                }
                if (!cfg_.clickhouse_url.empty()) {
                    analytics_store_->add_sink(make_clickhouse_sink(
                        cfg_.clickhouse_url, cfg_.clickhouse_database, cfg_.clickhouse_table,
                        cfg_.clickhouse_username, cfg_.clickhouse_password));
                }
                analytics_store_->start_drain();
            }
        }

        // Wire up store pointers for AgentServiceImpl
        if (response_store_)
            agent_service_.set_response_store(response_store_.get());
        if (tag_store_)
            agent_service_.set_tag_store(tag_store_.get());
        if (analytics_store_)
            agent_service_.set_analytics_store(analytics_store_.get());
        if (notification_store_)
            agent_service_.set_notification_store(notification_store_.get());
        if (webhook_store_)
            agent_service_.set_webhook_store(webhook_store_.get());
        if (offload_target_store_)
            agent_service_.set_offload_target_store(offload_target_store_.get());
        if (inventory_store_)
            agent_service_.set_inventory_store(inventory_store_.get());

        // Initialize instruction store (Phase 2)
        {
            auto instr_db = cfg_.db_dir() / "instructions.db";
            instruction_store_ = std::make_unique<InstructionStore>(instr_db);
            if (instruction_store_ && instruction_store_->is_open()) {
                // RAII pool owns the shared connection (fixes G3-ARCH-T2-002).
                // Declare instr_db_pool_ before the consumers in the member list
                // so that consumers are destroyed before the pool closes the DB.
                instr_db_pool_ = std::make_unique<InstructionDbPool>(instr_db);
                if (instr_db_pool_->is_open()) {
                    // PR 3 — per-execution SSE event bus. Constructed
                    // before the tracker so the tracker can attach
                    // immediately and we keep the "bus outlives tracker"
                    // invariant that the member-order comment encodes.
                    execution_event_bus_ = std::make_unique<ExecutionEventBus>();
                    execution_tracker_ = std::make_unique<ExecutionTracker>(instr_db_pool_->get());
                    execution_tracker_->create_tables();
                    execution_tracker_->set_event_bus(execution_event_bus_.get());
                    // UAT 2026-05-06 #8: AgentServiceImpl notifies the
                    // tracker on every response so the per-agent KPI
                    // table populates and SSE agent-transition fires
                    // for live drawer updates.
                    agent_service_.set_execution_tracker(execution_tracker_.get());

                    approval_manager_ = std::make_unique<ApprovalManager>(instr_db_pool_->get());
                    approval_manager_->create_tables();

                    schedule_engine_ = std::make_unique<ScheduleEngine>(instr_db_pool_->get());
                    schedule_engine_->create_tables();
                }

                // Auto-import shipped content from content/definitions/ and
                // content/packs/. The build-time embed_content.py script
                // converts each YAML doc to a JSON envelope; we walk the
                // arrays and upsert. Conflicts on already-existing ids are
                // expected on second-and-later startups and silently
                // skipped — content is the source of truth at boot, not
                // override of in-place operator edits.
                //
                // Conflict detection uses is_conflict_error() against the
                // shared kConflictPrefix (Gate 4 C-B1 / arch-B1). Substring
                // matching on "already exists" was fragile to localization
                // and to error-string drift in the store layer.
                //
                // Audit emission: each successful import or skip writes one
                // audit_store entry with principal="system" — closes Gate 6
                // COMP-1 / sec-M2. Errors include the JSON envelope's `id`
                // field in both the audit detail and the spdlog warning so
                // operators can triage without reading 200+ envelopes by
                // hand (Gate 6 SRE-O2).
                {
                    auto audit_bundle = [this](std::string_view target_type,
                                               const std::string& target_id,
                                               std::string_view result, const std::string& detail) {
                        // Hardening round 1 INFO — audit_store_ is
                        // initialized at server.cpp:394, before this
                        // block at :441; the null branch is unreachable
                        // today. Guard with an error log so a future
                        // re-ordering surfaces immediately rather than
                        // silently dropping boot-content audit events.
                        if (!audit_store_) {
                            spdlog::error("bundled_content audit dropped: "
                                          "audit_store_ not initialized "
                                          "(target_type={} target_id={})",
                                          target_type, target_id);
                            return;
                        }
                        AuditEvent ev{};
                        ev.timestamp = std::time(nullptr);
                        ev.principal = "system";
                        ev.principal_role = "system";
                        ev.action = "content.bundled_import";
                        ev.target_type = std::string(target_type);
                        ev.target_id = target_id;
                        ev.detail = detail;
                        ev.result = std::string(result);
                        audit_store_->log(ev);
                    };
                    auto envelope_id = [](const std::string& env) -> std::string {
                        auto p = nlohmann::json::parse(env, nullptr, false);
                        return p.is_discarded() ? std::string{} : p.value("id", std::string{});
                    };
                    int defs_imported = 0, defs_skipped = 0, defs_errored = 0;
                    for (const auto& env : kBundledDefinitions) {
                        auto id = envelope_id(env);
                        auto r = instruction_store_->import_definition_json(env);
                        if (r) {
                            ++defs_imported;
                            audit_bundle("InstructionDefinition", *r, "success",
                                         "boot-time content embed");
                        } else if (is_conflict_error(r.error())) {
                            ++defs_skipped;
                        } else {
                            ++defs_errored;
                            spdlog::warn("bundled definition import failed: id={} error={}", id,
                                         r.error());
                            audit_bundle("InstructionDefinition", id, "error", r.error());
                        }
                    }
                    int sets_imported = 0, sets_skipped = 0, sets_errored = 0;
                    for (const auto& env : kBundledSets) {
                        auto parsed = nlohmann::json::parse(env, nullptr, false);
                        if (parsed.is_discarded()) {
                            ++sets_errored;
                            continue;
                        }
                        InstructionSet s;
                        s.id = parsed.value("id", "");
                        s.name = parsed.value("name", s.id);
                        s.description = parsed.value("description", "");
                        s.created_by = parsed.value("created_by", "system");
                        if (s.id.empty()) {
                            ++sets_errored;
                            continue;
                        }
                        auto r = instruction_store_->create_set(s);
                        if (r) {
                            ++sets_imported;
                            audit_bundle("InstructionSet", *r, "success",
                                         "boot-time content embed");
                        } else if (is_conflict_error(r.error())) {
                            ++sets_skipped;
                        } else {
                            ++sets_errored;
                            spdlog::warn("bundled set import failed: id={} error={}", s.id,
                                         r.error());
                            audit_bundle("InstructionSet", s.id, "error", r.error());
                        }
                    }
                    spdlog::info(
                        "bundled content: {} definitions imported / {} skipped / {} errored; "
                        "{} sets imported / {} skipped / {} errored",
                        defs_imported, defs_skipped, defs_errored, sets_imported, sets_skipped,
                        sets_errored);
                }
            }
        }

        // Initialize Phase 3: Security & RBAC stores
        {
            auto rbac_db = cfg_.db_dir() / "rbac.db";
            rbac_store_ = std::make_unique<RbacStore>(rbac_db);
        }
        {
            auto mgmt_db = cfg_.db_dir() / "management-groups.db";
            mgmt_group_store_ = std::make_unique<ManagementGroupStore>(mgmt_db);
            // Ensure root "All Devices" group exists
            if (mgmt_group_store_ && mgmt_group_store_->is_open()) {
                auto root = mgmt_group_store_->get_group(ManagementGroupStore::kRootGroupId);
                if (!root) {
                    ManagementGroup g;
                    g.id = ManagementGroupStore::kRootGroupId;
                    g.name = "All Devices";
                    g.description = "Root group containing all enrolled agents";
                    g.membership_type = "dynamic";
                    g.scope_expression = "*";
                    g.created_by = "system";
                    auto r = mgmt_group_store_->create_group(g);
                    if (r)
                        spdlog::info("Auto-created root management group 'All Devices'");
                }
            }
            agent_service_.set_mgmt_group_store(mgmt_group_store_.get());
            if (gateway_service_)
                gateway_service_->set_mgmt_group_store(mgmt_group_store_.get());
        }
        {
            auto token_db = cfg_.db_dir() / "api-tokens.db";
            api_token_store_ = std::make_unique<ApiTokenStore>(token_db);
        }
        {
            auto quar_db = cfg_.db_dir() / "quarantine.db";
            quarantine_store_ = std::make_unique<QuarantineStore>(quar_db);
        }

        // Phase 5: Policy Engine
        {
            auto policy_db = cfg_.db_dir() / "policies.db";
            policy_store_ = std::make_unique<PolicyStore>(policy_db);
            if (policy_store_ && policy_store_->is_open()) {
                spdlog::info("PolicyStore initialized at {}", policy_db.string());
            }
        }

        // Guardian (Guaranteed State) rule + event store. REST/dashboard/push
        // wiring lands in later PRs; this PR stands the store up with its
        // retention reaper so the schema migration runs, the database file
        // exists, and bounded growth is the default from day one (#452 §5).
        {
            auto gs_db = cfg_.db_dir() / "guaranteed-state.db";
            guaranteed_state_store_ =
                std::make_unique<GuaranteedStateStore>(gs_db, cfg_.guardian_event_retention_days);
            if (guaranteed_state_store_ && guaranteed_state_store_->is_open()) {
                guaranteed_state_store_->start_cleanup();
                spdlog::info("GuaranteedStateStore initialized at {} (retention={}d)",
                             gs_db.string(), cfg_.guardian_event_retention_days);
            }
        }

        // Phase 7: Runtime Configuration + Custom Properties
        {
            auto rtcfg_db = cfg_.db_dir() / "runtime-config.db";
            runtime_config_store_ = std::make_unique<RuntimeConfigStore>(rtcfg_db);
            if (runtime_config_store_ && runtime_config_store_->is_open()) {
                // Apply stored overrides on startup
                apply_runtime_config_overrides();
            }
        }
        {
            auto props_db = cfg_.db_dir() / "custom-properties.db";
            custom_properties_store_ = std::make_unique<CustomPropertiesStore>(props_db);
        }

        // Phase 7: Workflow Engine
        {
            auto wf_db = cfg_.db_dir() / "workflows.db";
            workflow_engine_ = std::make_unique<WorkflowEngine>(wf_db);
            if (workflow_engine_ && workflow_engine_->is_open()) {
                spdlog::info("WorkflowEngine initialized at {}", wf_db.string());
            }
        }

        // Phase 7: Product Pack Store
        {
            auto pack_db = cfg_.db_dir() / "product-packs.db";
            product_pack_store_ = std::make_unique<ProductPackStore>(pack_db);
            if (product_pack_store_ && product_pack_store_->is_open()) {
                spdlog::info("ProductPackStore initialized at {}", pack_db.string());
            }
        }

        // Notification & Webhook stores
        {
            auto notif_db = cfg_.db_dir() / "notifications.db";
            notification_store_ = std::make_unique<NotificationStore>(notif_db);
        }
        {
            auto webhook_db = cfg_.db_dir() / "webhooks.db";
            webhook_store_ = std::make_unique<WebhookStore>(webhook_db);
        }
        {
            auto offload_db = cfg_.db_dir() / "offload_targets.db";
            offload_target_store_ = std::make_unique<OffloadTargetStore>(offload_db);
        }

        // Phase 7: Inventory Store (Issue 7.17)
        {
            auto inv_db = cfg_.db_dir() / "inventory.db";
            inventory_store_ = std::make_unique<InventoryStore>(inv_db);
            if (inventory_store_ && inventory_store_->is_open()) {
                spdlog::info("InventoryStore initialized at {}", inv_db.string());
            }
            if (gateway_service_)
                gateway_service_->set_inventory_store(inventory_store_.get());
        }

        // Phase 7: Directory Sync (AD/Entra integration)
        {
            auto dirsync_db = cfg_.db_dir() / "directory-sync.db";
            directory_sync_ = std::make_unique<DirectorySync>(dirsync_db);
            if (directory_sync_ && directory_sync_->is_open()) {
                spdlog::info("DirectorySync initialized at {}", dirsync_db.string());
            }
        }

        // Phase 7: Patch Manager
        {
            auto patch_db = cfg_.db_dir() / "patches.db";
            patch_manager_ = std::make_unique<PatchManager>(patch_db);
            if (patch_manager_ && patch_manager_->is_open()) {
                spdlog::info("PatchManager initialized at {}", patch_db.string());
            }
        }

        // Phase 7: Deployment Jobs (Issue 7.7)
        {
            auto deploy_db = cfg_.db_dir() / "deployment-jobs.db";
            deployment_store_ = std::make_unique<DeploymentStore>(deploy_db);
            if (deployment_store_ && deployment_store_->is_open()) {
                spdlog::info("DeploymentStore initialized at {}", deploy_db.string());
            }
        }

        // Phase 7: Device Discovery (Issue 7.18)
        {
            auto discovery_db = cfg_.db_dir() / "discovery.db";
            discovery_store_ = std::make_unique<DiscoveryStore>(discovery_db);
            if (discovery_store_ && discovery_store_->is_open()) {
                spdlog::info("DiscoveryStore initialized at {}", discovery_db.string());
            }
        }
    }

    void run() override {
        spdlog::info("run(): entering");
        grpc::EnableDefaultHealthCheckService(true);

        std::shared_ptr<grpc::ServerCredentials> agent_creds = grpc::InsecureServerCredentials();
        std::shared_ptr<grpc::ServerCredentials> mgmt_creds = grpc::InsecureServerCredentials();
        if (cfg_.tls_enabled) {
            auto tls =
                build_tls_credentials(cfg_.tls_server_cert, cfg_.tls_server_key, cfg_.tls_ca_cert,
                                      cfg_.allow_one_way_tls, "agent listener");
            if (tls) {
                agent_creds = std::move(tls);
            } else {
                spdlog::error("TLS is enabled but credentials are invalid; refusing to start");
                return;
            }

            if (!cfg_.mgmt_tls_server_cert.empty() || !cfg_.mgmt_tls_server_key.empty() ||
                !cfg_.mgmt_tls_ca_cert.empty()) {
                // The management listener is governed by the SAME insecure-TLS gate
                // as the agent listener (issue #79 / C-79-1). An operator who supplies
                // --management-cert/--management-key without --management-ca-cert must
                // also pass --insecure-skip-client-verify (which itself requires
                // YUZU_ALLOW_INSECURE_TLS=1) — otherwise build_tls_credentials refuses.
                // Previously this was hardcoded `true`, which silently accepted any
                // unauthenticated peer on the management plane.
                auto mgmt_tls = build_tls_credentials(
                    cfg_.mgmt_tls_server_cert, cfg_.mgmt_tls_server_key, cfg_.mgmt_tls_ca_cert,
                    cfg_.allow_one_way_tls, "management listener");
                if (!mgmt_tls) {
                    spdlog::error("Management TLS credentials are invalid; refusing to start");
                    return;
                }
                mgmt_creds = std::move(mgmt_tls);
            } else {
                mgmt_creds = agent_creds;
            }
        }

        grpc::ServerBuilder builder;
        builder.AddChannelArgument(GRPC_ARG_KEEPALIVE_TIME_MS, 60000);
        builder.AddChannelArgument(GRPC_ARG_KEEPALIVE_TIMEOUT_MS, 20000);
        builder.AddChannelArgument(GRPC_ARG_KEEPALIVE_PERMIT_WITHOUT_CALLS, 1);
        builder.AddChannelArgument(GRPC_ARG_HTTP2_MAX_PINGS_WITHOUT_DATA, 0);
        builder.AddChannelArgument(GRPC_ARG_HTTP2_MIN_RECV_PING_INTERVAL_WITHOUT_DATA_MS, 30000);
        builder.AddListeningPort(cfg_.listen_address, agent_creds);
        builder.AddListeningPort(cfg_.management_address, mgmt_creds);
        builder.RegisterService(&agent_service_);
        builder.RegisterService(&mgmt_service_);

        if (gateway_service_) {
            // Gateway upstream uses the same credentials as the management listener
            // (internal traffic, typically mTLS between gateway and server).
            builder.AddListeningPort(cfg_.gateway_upstream_address, mgmt_creds);
            builder.RegisterService(gateway_service_.get());
            spdlog::info("Gateway upstream service enabled on {}", cfg_.gateway_upstream_address);
        }

        agent_server_ = builder.BuildAndStart();

        if (!agent_server_) {
            spdlog::error("Failed to start gRPC server -- check that ports {} and {} are available",
                          cfg_.listen_address, cfg_.management_address);
            return;
        }

        spdlog::info("Yuzu Server listening on {} (agents) and {} (management)",
                     cfg_.listen_address, cfg_.management_address);
        if (gateway_service_) {
            spdlog::info("Gateway upstream listening on {}", cfg_.gateway_upstream_address);
        }

        // Create AuthRoutes — must precede start_web_server which uses it
        auth_routes_ = std::make_unique<AuthRoutes>(
            cfg_, auth_mgr_, rbac_store_.get(), api_token_store_.get(), audit_store_.get(),
            mgmt_group_store_.get(), tag_store_.get(), analytics_store_.get(), oidc_mu_,
            oidc_provider_);

        start_web_server();

        // Start certificate hot-reload watcher
        if (cfg_.cert_reload_enabled && cfg_.https_enabled && web_server_) {
            CertReloader::Params reload_params;
            reload_params.cert_path = cfg_.https_cert_path;
            reload_params.key_path = cfg_.https_key_path;
            reload_params.interval = std::chrono::seconds(cfg_.cert_reload_interval_seconds);
            reload_params.web_server = web_server_.get();
            reload_params.audit_store = audit_store_ ? audit_store_.get() : nullptr;
            cert_reloader_ = std::make_unique<CertReloader>(std::move(reload_params));
            cert_reloader_->start();
            spdlog::info("Certificate hot-reload enabled (interval={}s)",
                         cfg_.cert_reload_interval_seconds);
        } else if (cfg_.https_enabled && !cfg_.cert_reload_enabled) {
            spdlog::info("Certificate hot-reload disabled via --no-cert-reload");
        }
        if (cfg_.cert_reload_enabled && cfg_.tls_enabled) {
            spdlog::warn("gRPC TLS certificate hot-reload is not yet supported; "
                         "gRPC listeners will use the certificates loaded at startup");
        }

        // Spawn fleet health recomputation thread (aggregates agent heartbeat data)
        health_recompute_thread_ = std::thread([this]() {
            spdlog::info("Fleet health recomputation thread started (interval=15s)");
            while (!stop_requested_.load(std::memory_order_acquire)) {
                // Sleep in small increments for responsive shutdown
                for (int i = 0; i < 3 && !stop_requested_.load(std::memory_order_acquire); ++i) {
                    std::this_thread::sleep_for(std::chrono::seconds{5});
                }
                if (stop_requested_.load(std::memory_order_acquire))
                    break;
                health_store_.recompute_metrics(metrics_, std::chrono::seconds{90});
                // Reap Subscribe streams for agents that missed heartbeats
                registry_.reap_stale_sessions(cfg_.session_timeout);
                // Publish cert reload counters to Prometheus
                if (cert_reloader_) {
                    metrics_.gauge("yuzu_server_cert_reloads_total")
                        .set(static_cast<double>(cert_reloader_->reload_count()));
                    metrics_.gauge("yuzu_server_cert_reload_failures_total")
                        .set(static_cast<double>(cert_reloader_->failure_count()));
                }
                // Publish token cache observability so SRE can verify cache effectiveness
                // and detect cold-cache stampedes (gate-6 SRE finding HIGH-1).
                if (api_token_store_) {
                    metrics_.gauge("yuzu_server_token_cache_hits_total")
                        .set(static_cast<double>(api_token_store_->cache_hits()));
                    metrics_.gauge("yuzu_server_token_cache_misses_total")
                        .set(static_cast<double>(api_token_store_->cache_misses()));
                    metrics_.gauge("yuzu_server_token_cache_size")
                        .set(static_cast<double>(api_token_store_->cache_size()));
                }
                // Publish audit event write rate so the audit subsystem is observable.
                if (audit_store_) {
                    metrics_.gauge("yuzu_server_audit_events_total", {{"result", "success"}})
                        .set(static_cast<double>(audit_store_->events_written("success")));
                    metrics_.gauge("yuzu_server_audit_events_total", {{"result", "failure"}})
                        .set(static_cast<double>(audit_store_->events_written("failure")));
                    metrics_.gauge("yuzu_server_audit_events_total", {{"result", "denied"}})
                        .set(static_cast<double>(audit_store_->events_written("denied")));
                    metrics_.gauge("yuzu_server_audit_events_total", {{"result", "other"}})
                        .set(static_cast<double>(audit_store_->events_written("other")));
                    // OBS-4: surface audit-pipeline persistence failures.
                    metrics_.gauge("yuzu_server_audit_emit_failed_total")
                        .set(static_cast<double>(audit_store_->emit_failed_count()));
                }
                // PR 5b — ExecutionEventBus observability. Same scrape-as-
                // gauge pattern used for AuditStore + GuaranteedStateStore
                // counters above; the bus exposes the counters via lock-
                // free atomic accessors so reading from this thread is safe.
                if (execution_event_bus_) {
                    metrics_.gauge("yuzu_server_sse_channels_active")
                        .set(static_cast<double>(execution_event_bus_->channel_count()));
                    metrics_.gauge("yuzu_server_sse_subscribers_active")
                        .set(static_cast<double>(execution_event_bus_->subscribers_total()));
                    metrics_.gauge("yuzu_server_sse_events_dropped_total")
                        .set(static_cast<double>(execution_event_bus_->events_dropped_total()));
                    metrics_.gauge("yuzu_server_sse_gc_sweeps_total")
                        .set(static_cast<double>(execution_event_bus_->gc_sweeps_total()));
                    metrics_.gauge("yuzu_server_sse_gc_channels_total")
                        .set(static_cast<double>(execution_event_bus_->gc_channels_total()));
                }
                // Guardian scalars + cumulative write/reap counters. Use
                // gauges for the count-now values (SQL COUNT(*)) and for the
                // cumulative-but-serialized-as-gauge counters exposed by
                // the store — matches the existing audit_store pattern so
                // the /metrics shape stays consistent across subsystems.
                if (guaranteed_state_store_) {
                    metrics_.gauge("yuzu_server_guardian_rules_total")
                        .set(static_cast<double>(guaranteed_state_store_->rule_count()));
                    metrics_.gauge("yuzu_server_guardian_events_total")
                        .set(static_cast<double>(guaranteed_state_store_->event_count()));
                    metrics_.gauge("yuzu_server_guardian_events_written_total")
                        .set(static_cast<double>(guaranteed_state_store_->events_written_total()));
                    metrics_.gauge("yuzu_server_guardian_events_reaped_total")
                        .set(static_cast<double>(guaranteed_state_store_->events_reaped_total()));
                }
                // Process health sampling (22.1)
                {
                    auto ph = process_health_sampler_.sample();
                    metrics_.gauge("yuzu_server_cpu_usage_percent").set(ph.cpu_percent);
                    metrics_.gauge("yuzu_server_memory_bytes", {{"type", "rss"}})
                        .set(static_cast<double>(ph.memory_rss_bytes));
                    metrics_.gauge("yuzu_server_memory_bytes", {{"type", "vss"}})
                        .set(static_cast<double>(ph.memory_vss_bytes));
                    metrics_.gauge("yuzu_server_open_connections")
                        .set(static_cast<double>(registry_.agent_count()));
                    auto queue_depth =
                        execution_tracker_
                            ? static_cast<double>(
                                  execution_tracker_->query_executions({.status = "running"})
                                      .size())
                            : 0.0;
                    metrics_.gauge("yuzu_server_command_queue_depth").set(queue_depth);
                    auto uptime_s = std::chrono::duration_cast<std::chrono::seconds>(
                                        std::chrono::steady_clock::now() - server_start_time_)
                                        .count();
                    metrics_.gauge("yuzu_server_uptime_seconds").set(static_cast<double>(uptime_s));
                }
            }
            spdlog::info("Fleet health recomputation thread stopped");
        });

        // Periodic reminder when TLS is disabled or weakened (issue #79 + C-79
        // family). Logs at ERROR level every 5 minutes AND writes an audit event
        // so SOC 2 CC7.2 evidence is collected for the duration the server runs
        // in a degraded posture (otherwise spdlog-only output would not survive
        // log rotation or land in audit.db).
        const bool insecure_skip_verify_active = cfg_.tls_enabled && cfg_.allow_one_way_tls;
        const bool no_tls_active = !cfg_.tls_enabled;
        if (insecure_skip_verify_active || no_tls_active) {
            insecure_tls_reminder_thread_ =
                std::thread([this, insecure_skip_verify_active, no_tls_active]() {
                    using namespace std::chrono_literals;
                    while (!stop_requested_.load(std::memory_order_acquire)) {
                        // Sleep in small increments for responsive shutdown (300s = 60 * 5s)
                        for (int i = 0; i < 60 && !stop_requested_.load(std::memory_order_acquire);
                             ++i) {
                            std::this_thread::sleep_for(5s);
                        }
                        if (stop_requested_.load(std::memory_order_acquire))
                            break;
                        const char* posture =
                            no_tls_active ? "--no-tls" : "--insecure-skip-client-verify";
                        const char* detail =
                            no_tls_active
                                ? "TLS is fully disabled; both agent and management gRPC "
                                  "listeners accept plaintext from any peer with no encryption "
                                  "and no peer authentication. Restart with TLS certificates "
                                  "to leave this posture."
                                : "Agent / management listener still running without client "
                                  "certificate verification. Re-enable mTLS by supplying "
                                  "--ca-cert (and --management-ca-cert if applicable).";
                        spdlog::error("[INSECURE-TLS] ({}) {}", posture, detail);
                        if (audit_store_ && audit_store_->is_open()) {
                            audit_store_->log({.timestamp = std::time(nullptr),
                                               .principal = "system",
                                               .principal_role = "system",
                                               .action = "server.tls_degraded",
                                               .target_type = "server",
                                               .target_id = posture,
                                               .detail = detail,
                                               .result = "warning"});
                        }
                    }
                });
        }

        agent_server_->Wait();
    }

    void stop() noexcept override {
        // Guard against re-entrant calls from repeated signals.
        // The signal handler calls stop() directly, so a second Ctrl+C
        // re-enters stop() on a different thread while the first is still
        // joining threads — causing "Resource deadlock avoided".
        bool expected = false;
        if (!stop_entered_.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
            return; // Another thread is already running stop()
        }

        spdlog::info("Shutting down server...");
        draining_.store(true, std::memory_order_release);

        // Graceful drain: wait for in-flight executions (up to 30s)
        if (execution_tracker_) {
            for (int i = 0; i < 30; ++i) {
                auto running = execution_tracker_->query_executions({.status = "running"});
                if (running.empty())
                    break;
                spdlog::info("Draining: {} executions in flight, waiting...", running.size());
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        }

        stop_requested_.store(true, std::memory_order_release);

        // Join the fleet health recomputation thread
        if (health_recompute_thread_.joinable()) {
            health_recompute_thread_.join();
        }

        // Join the insecure-TLS reminder thread (issue #79)
        if (insecure_tls_reminder_thread_.joinable()) {
            insecure_tls_reminder_thread_.join();
        }

        if (schedule_engine_)
            schedule_engine_->stop();
        if (nvd_sync_) {
            nvd_sync_->stop();
        }
        if (analytics_store_)
            analytics_store_->stop_drain();
        if (response_store_)
            response_store_->stop_cleanup();
        if (audit_store_)
            audit_store_->stop_cleanup();
        if (guaranteed_state_store_)
            guaranteed_state_store_->stop_cleanup();

        // Stop cert reloader before web server (it holds a pointer to web_server_)
        if (cert_reloader_) {
            cert_reloader_->stop();
            cert_reloader_.reset();
        }

        if (redirect_server_) {
            redirect_server_->stop();
        }
        if (redirect_thread_.joinable()) {
            redirect_thread_.join();
        }
        if (web_server_) {
            web_server_->stop();
        }
        if (web_thread_.joinable()) {
            web_thread_.join();
        }

        // Phase 8.3 #255 — drain offload batch buffers BEFORE the store is
        // reset further down. Detached delivery threads continue past
        // process exit's perspective but get a fair chance to finish
        // before the SQLite handle goes away. flush_all() spawns a final
        // round of detached deliveries; we don't join them, but the
        // buffer state is consistent (RESTART-1 from Gate 6 SRE).
        if (offload_target_store_) {
            offload_target_store_->flush_all();
        }

        // Release Phase 2 components before closing shared DB
        // Release Phase 2 components before closing shared DB (RAII handles close)
        execution_tracker_.reset();
        // PR 3 — bus outlives the tracker by member-order convention,
        // but in the explicit reset path we drop the tracker first
        // (it borrows `event_bus_`), then the bus.
        execution_event_bus_.reset();
        approval_manager_.reset();
        schedule_engine_.reset();
        instr_db_pool_.reset();

        // Shutdown with a deadline — without one, Shutdown() waits
        // indefinitely for all RPCs to finish.  The Subscribe RPC is a
        // long-lived bidirectional stream that never completes on its own,
        // so a bare Shutdown() hangs forever.
        auto deadline = std::chrono::system_clock::now() + std::chrono::seconds(5);
        if (agent_server_)
            agent_server_->Shutdown(deadline);
        if (mgmt_server_)
            mgmt_server_->Shutdown(deadline);
    }

private:
    // -- TLS ------------------------------------------------------------------

    [[nodiscard]] std::shared_ptr<grpc::ServerCredentials>
    build_tls_credentials(const std::filesystem::path& cert_path,
                          const std::filesystem::path& key_path,
                          const std::filesystem::path& ca_path, bool allow_one_way_tls,
                          std::string_view listener_name) const {
        if (cert_path.empty() || key_path.empty()) {
            spdlog::error("{} TLS requires certificate and key", listener_name);
            return nullptr;
        }

        if (!detail::validate_key_file_permissions(key_path, listener_name)) {
            return nullptr;
        }

        auto cert = detail::read_file_contents(cert_path);
        auto key = detail::read_file_contents(key_path);
        if (cert.empty() || key.empty()) {
            spdlog::error("Failed to read {} TLS cert/key files", listener_name);
            return nullptr;
        }

        grpc::SslServerCredentialsOptions ssl_opts;
        grpc::SslServerCredentialsOptions::PemKeyCertPair key_cert;
        key_cert.private_key = std::move(key);
        key_cert.cert_chain = std::move(cert);
        ssl_opts.pem_key_cert_pairs.push_back(std::move(key_cert));

        if (!ca_path.empty()) {
            auto ca = detail::read_file_contents(ca_path);
            if (ca.empty()) {
                spdlog::error("Failed to read {} CA cert from {}", listener_name, ca_path.string());
                return nullptr;
            }

            ssl_opts.pem_root_certs = std::move(ca);
            ssl_opts.client_certificate_request =
                GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY;
        } else {
            if (!allow_one_way_tls) {
                spdlog::error("{} TLS requires --ca-cert (or enable "
                              "--insecure-skip-client-verify with YUZU_ALLOW_INSECURE_TLS=1)",
                              listener_name);
                return nullptr;
            }
            spdlog::warn("{} TLS running without client certificate verification "
                         "(--insecure-skip-client-verify)",
                         listener_name);
        }

        auto creds = grpc::SslServerCredentials(ssl_opts);
        for (auto& kc : ssl_opts.pem_key_cert_pairs) {
            yuzu::secure_zero(kc.private_key);
        }
        return creds;
    }

    // -- Web server -----------------------------------------------------------

    // -- Base64 decode --------------------------------------------------------

    static std::string base64_decode(const std::string& in) {
        static constexpr unsigned char kTable[256] = {
            64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
            64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62,
            64, 64, 64, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64, 64, 0,
            1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
            23, 24, 25, 64, 64, 64, 64, 64, 64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38,
            39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64, 64, 64, 64, 64,
            64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
            64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
            64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
            64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
            64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
            64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64};
        std::string out;
        out.reserve(in.size() * 3 / 4);
        unsigned int val = 0;
        int bits = -8;
        for (unsigned char c : in) {
            if (kTable[c] == 64)
                continue;
            val = (val << 6) | kTable[c];
            bits += 6;
            if (bits >= 0) {
                out += static_cast<char>((val >> bits) & 0xFF);
                bits -= 8;
            }
        }
        return out;
    }

    // -- HTML helpers ---------------------------------------------------------

    static std::string html_escape(const std::string& s) {
        std::string out;
        out.reserve(s.size());
        for (char c : s) {
            switch (c) {
            case '&':
                out += "&amp;";
                break;
            case '<':
                out += "&lt;";
                break;
            case '>':
                out += "&gt;";
                break;
            case '"':
                out += "&quot;";
                break;
            case '\'':
                out += "&#39;";
                break;
            default:
                out += c;
            }
        }
        return out;
    }

    // -- Server-side YAML syntax highlighter ----------------------------------
    // Used by instruction editor routes. YAML helpers are also duplicated in
    // settings_routes.cpp (anonymous namespace) for the settings YAML preview.

    static std::string highlight_yaml_value(const std::string& val, const std::string& key = {}) {
        if (val.empty())
            return {};
        auto trimmed = val;
        auto sp = trimmed.find_first_not_of(' ');
        if (sp == std::string::npos)
            return html_escape(val);
        trimmed = trimmed.substr(sp);
        // Semantic highlighting: color specific key:value pairs to match the legend.
        if (key == "type" && (trimmed == "question" || trimmed == "\"question\""))
            return "<span class=\"yq\">" + html_escape(val) + "</span>";
        if (key == "type" && (trimmed == "action" || trimmed == "\"action\""))
            return "<span class=\"yact\">" + html_escape(val) + "</span>";
        if (key == "approval" && (trimmed == "required" || trimmed == "\"required\""))
            return "<span class=\"yar\">" + html_escape(val) + "</span>";
        if (key == "concurrency" && (trimmed == "single" || trimmed == "serial" ||
                                     trimmed == "\"single\"" || trimmed == "\"serial\""))
            return "<span class=\"ycc\">" + html_escape(val) + "</span>";
        if (trimmed == "true" || trimmed == "false" || trimmed == "True" || trimmed == "False")
            return "<span class=\"yb\">" + html_escape(val) + "</span>";
        bool is_number = !trimmed.empty();
        for (char c : trimmed) {
            if (c != '-' && c != '.' && (c < '0' || c > '9')) {
                is_number = false;
                break;
            }
        }
        if (is_number && !trimmed.empty())
            return "<span class=\"yn\">" + html_escape(val) + "</span>";
        return "<span class=\"yv\">" + html_escape(val) + "</span>";
    }

    static std::string highlight_yaml_kv(const std::string& line) {
        std::size_t i = 0;
        while (i < line.size() && line[i] == ' ')
            ++i;
        auto key_start = i;
        while (i < line.size() && (std::isalnum(static_cast<unsigned char>(line[i])) ||
                                   line[i] == '_' || line[i] == '-' || line[i] == '.'))
            ++i;
        if (i >= line.size() || line[i] != ':' || i == key_start)
            return html_escape(line);
        auto indent = line.substr(0, key_start);
        auto key = line.substr(key_start, i - key_start);
        auto rest = line.substr(i + 1);
        bool is_schema = (key == "apiVersion" || key == "kind");
        std::string key_cls = is_schema ? "ya" : "yk";
        return html_escape(indent) + "<span class=\"" + key_cls + "\">" + html_escape(key) +
               "</span>:" + highlight_yaml_value(rest, key);
    }

    static std::string highlight_yaml(std::string_view source) {
        std::string result;
        result.reserve(source.size() * 2);
        int line_num = 1;
        std::size_t pos = 0;
        while (pos <= source.size()) {
            auto nl = source.find('\n', pos);
            std::string line;
            if (nl == std::string_view::npos) {
                line = std::string(source.substr(pos));
                pos = source.size() + 1;
            } else {
                line = std::string(source.substr(pos, nl - pos));
                pos = nl + 1;
            }
            result +=
                "<div class=\"yl\"><span class=\"ln\">" + std::to_string(line_num++) + "</span>";
            auto trimmed_start = line.find_first_not_of(' ');
            if (trimmed_start == std::string::npos) {
                result += "&nbsp;";
            } else if (line[trimmed_start] == '#') {
                result += "<span class=\"yc\">" + html_escape(line) + "</span>";
            } else if (line == "---" || line == "...") {
                result += "<span class=\"yd\">" + html_escape(line) + "</span>";
            } else if (line[trimmed_start] == '-' && trimmed_start + 1 < line.size() &&
                       line[trimmed_start + 1] == ' ') {
                auto indent2 = line.substr(0, trimmed_start);
                auto after_dash = line.substr(trimmed_start + 2);
                result += html_escape(indent2) + "<span class=\"yd\">-</span> ";
                if (after_dash.find(':') != std::string::npos)
                    result += highlight_yaml_kv(after_dash);
                else
                    result += highlight_yaml_value(after_dash);
            } else if (line.find(':') != std::string::npos) {
                result += highlight_yaml_kv(line);
            } else {
                result += html_escape(line);
            }
            result += "</div>";
        }
        return result;
    }

    static std::vector<std::string> validate_yaml_source(const std::string& yaml_source) {
        std::vector<std::string> errors;
        if (yaml_source.empty())
            errors.push_back("YAML source is empty");
        if (yaml_source.find("apiVersion:") == std::string::npos)
            errors.push_back("Missing apiVersion field");
        if (yaml_source.find("kind:") == std::string::npos)
            errors.push_back("Missing kind field");
        if (yaml_source.find("plugin:") == std::string::npos)
            errors.push_back("Missing spec.plugin field");
        if (yaml_source.find("action:") == std::string::npos)
            errors.push_back("Missing spec.action field");
        return errors;
    }

    // -- Auth helpers for HTTP ------------------------------------------------

    static std::string url_decode(const std::string& s) {
        std::string out;
        out.reserve(s.size());
        for (std::size_t i = 0; i < s.size(); ++i) {
            if (s[i] == '%' && i + 2 < s.size()) {
                auto hex = s.substr(i + 1, 2);
                out += static_cast<char>(std::stoul(hex, nullptr, 16));
                i += 2;
            } else if (s[i] == '+') {
                out += ' ';
            } else {
                out += s[i];
            }
        }
        return out;
    }

    static std::string extract_form_value(const std::string& body, const std::string& key) {
        auto needle = key + "=";
        auto pos = body.find(needle);
        if (pos == std::string::npos)
            return {};
        pos += needle.size();
        auto end = body.find('&', pos);
        auto raw = body.substr(pos, end == std::string::npos ? end : end - pos);
        return url_decode(raw);
    }

    // -- Auth helpers: thin delegation wrappers to AuthRoutes -----------------

    auth::Session synthesize_token_session(const ApiToken& api_token) {
        return auth_routes_->synthesize_token_session(api_token);
    }

    std::optional<auth::Session> require_auth(const httplib::Request& req, httplib::Response& res) {
        return auth_routes_->require_auth(req, res);
    }

    bool require_admin(const httplib::Request& req, httplib::Response& res) {
        return auth_routes_->require_admin(req, res);
    }

    bool require_permission(const httplib::Request& req, httplib::Response& res,
                            const std::string& securable_type, const std::string& operation) {
        return auth_routes_->require_permission(req, res, securable_type, operation);
    }

    bool require_scoped_permission(const httplib::Request& req, httplib::Response& res,
                                   const std::string& securable_type, const std::string& operation,
                                   const std::string& agent_id) {
        return auth_routes_->require_scoped_permission(req, res, securable_type, operation,
                                                       agent_id);
    }

    /// Return the agent list as JSON, filtered by RBAC visibility for the given user.
    nlohmann::json get_visible_agents_json(const std::string& username) {
        auto agents = registry_.to_json_obj();
        if (rbac_store_ && rbac_store_->is_rbac_enabled() && mgmt_group_store_) {
            bool global_read = rbac_store_->check_permission(username, "Infrastructure", "Read");
            if (!global_read) {
                auto visible = mgmt_group_store_->get_visible_agents(username);
                std::set<std::string> visible_set(visible.begin(), visible.end());
                nlohmann::json filtered = nlohmann::json::array();
                for (const auto& a : agents) {
                    if (a.contains("agent_id") &&
                        visible_set.count(a["agent_id"].get<std::string>()))
                        filtered.push_back(a);
                }
                return filtered;
            }
        }
        return agents;
    }

    /// Auto-create a dynamic management group for a service tag value.
    void ensure_service_management_group(const std::string& service_value) {
        if (!mgmt_group_store_ || service_value.empty())
            return;

        std::string group_name = "Service: " + service_value;
        auto existing = mgmt_group_store_->find_group_by_name(group_name);
        if (existing)
            return;

        ManagementGroup g;
        g.name = group_name;
        g.description = "Auto-created for IT service: " + service_value;
        g.membership_type = "dynamic";
        g.scope_expression = "tag:service == \"" + service_value + "\"";
        g.created_by = "system";

        auto result = mgmt_group_store_->create_group(g);
        if (result) {
            // Populate with agents that have this service tag
            if (tag_store_) {
                auto agents = tag_store_->agents_with_tag("service", service_value);
                mgmt_group_store_->refresh_dynamic_membership(*result, agents);
            }
            spdlog::info("Auto-created management group '{}' for service '{}'", group_name,
                         service_value);
        }
    }

    /// Forward any commands queued for gateway-connected agents.
    void forward_gateway_pending() {
        auto gw_pending = registry_.drain_gateway_pending();
        if (!gw_pending.empty() && gw_mgmt_stub_) {
            for (auto& gp : gw_pending) {
                auto* stub = gw_mgmt_stub_.get();
                auto* svc = &agent_service_;
                auto cmd_id = gp.cmd.command_id();
                spdlog::debug("Forwarding command {} to gateway for agent {}", cmd_id, gp.agent_id);
                std::thread([stub, svc, gp = std::move(gp), cmd_id]() {
                    ::yuzu::server::v1::SendCommandRequest req;
                    req.add_agent_ids(gp.agent_id);
                    *req.mutable_command() = gp.cmd;
                    req.set_timeout_seconds(300);

                    // Retry up to 3 times on transient connection failures
                    for (int attempt = 0; attempt < 3; ++attempt) {
                        if (attempt > 0) {
                            spdlog::info("Retrying gateway SendCommand for {} (attempt {})", cmd_id,
                                         attempt + 1);
                            std::this_thread::sleep_for(std::chrono::seconds(1 << attempt));
                        }

                        grpc::ClientContext ctx;
                        ctx.set_deadline(std::chrono::system_clock::now() +
                                         std::chrono::seconds(300));
                        auto reader = stub->SendCommand(&ctx, req);

                        ::yuzu::server::v1::SendCommandResponse resp;
                        int resp_count = 0;
                        while (reader->Read(&resp)) {
                            ++resp_count;
                            svc->process_gateway_response(resp.agent_id(), resp.response());
                        }
                        auto status = reader->Finish();
                        if (status.ok()) {
                            spdlog::debug("Gateway SendCommand for {} completed: {} response(s)",
                                          cmd_id, resp_count);
                            return; // success — done
                        }
                        // Only retry on UNAVAILABLE (connection refused / not ready)
                        if (status.error_code() != grpc::StatusCode::UNAVAILABLE) {
                            spdlog::warn("Gateway SendCommand RPC for {} failed: {} ({})", cmd_id,
                                         status.error_message(),
                                         static_cast<int>(status.error_code()));
                            return; // non-transient error — don't retry
                        }
                        spdlog::warn("Gateway SendCommand for {} unavailable (attempt {}): {}",
                                     cmd_id, attempt + 1, status.error_message());
                    }
                    spdlog::error("Gateway SendCommand for {} failed after 3 attempts", cmd_id);
                }).detach();
            }
        }
    }

    /// Push structured tag state to an agent via the asset_tags plugin.
    void push_asset_tags_to_agent(const std::string& agent_id) {
        if (!tag_store_)
            return;

        // Build the sync command with all 4 structured category values
        ::yuzu::agent::v1::CommandRequest cmd;
        cmd.set_command_id("asset-tag-sync-" +
                           std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(
                                              std::chrono::system_clock::now().time_since_epoch())
                                              .count()));
        cmd.set_plugin("asset_tags");
        cmd.set_action("sync");

        auto* params = cmd.mutable_parameters();
        for (auto cat_key : kCategoryKeys) {
            std::string key_str{cat_key};
            auto val = tag_store_->get_tag(agent_id, key_str);
            (*params)[key_str] = val;
        }

        if (registry_.send_to(agent_id, cmd)) {
            spdlog::debug("Pushed asset tag sync to agent {}", agent_id);
            forward_gateway_pending();
        }
    }

    // Settings render methods moved to settings_routes.cpp
    // Compliance render methods moved to compliance_routes.cpp

    // -- Web server -----------------------------------------------------------

    // -- Cookie/audit/event helpers: thin delegation wrappers to AuthRoutes --

    std::string session_cookie_attrs() const { return auth_routes_->session_cookie_attrs(); }

    AuditEvent make_audit_event(const httplib::Request& req, const std::string& action,
                                const std::string& result) {
        return auth_routes_->make_audit_event(req, action, result);
    }

    void audit_log(const httplib::Request& req, const std::string& action,
                   const std::string& result, const std::string& target_type = {},
                   const std::string& target_id = {}, const std::string& detail = {}) {
        auth_routes_->audit_log(req, action, result, target_type, target_id, detail);
    }

    // Apply stored runtime config overrides on startup
    void apply_runtime_config_overrides() {
        if (!runtime_config_store_ || !runtime_config_store_->is_open())
            return;
        auto entries = runtime_config_store_->get_all();
        for (const auto& e : entries) {
            spdlog::info("Applying runtime config override: {} = {}", e.key, e.value);
            if (e.key == "log_level") {
                spdlog::set_level(spdlog::level::from_str(e.value));
            } else if (e.key == "heartbeat_timeout") {
                try {
                    cfg_.session_timeout = std::chrono::seconds(std::stoi(e.value));
                } catch (...) {}
            } else if (e.key == "response_retention_days") {
                try {
                    cfg_.response_retention_days = std::stoi(e.value);
                } catch (...) {}
            } else if (e.key == "audit_retention_days") {
                try {
                    cfg_.audit_retention_days = std::stoi(e.value);
                } catch (...) {}
            } else if (e.key == "guardian_event_retention_days") {
                try {
                    cfg_.guardian_event_retention_days = std::stoi(e.value);
                } catch (...) {}
            }
            // auto_approve_enabled is read dynamically, no startup action needed
            // OIDC settings — runtime-configurable via Settings UI
            else if (e.key == "oidc_issuer" && !e.value.empty())
                cfg_.oidc_issuer = e.value;
            else if (e.key == "oidc_client_id" && !e.value.empty())
                cfg_.oidc_client_id = e.value;
            else if (e.key == "oidc_client_secret" && !e.value.empty())
                cfg_.oidc_client_secret = e.value;
            else if (e.key == "oidc_redirect_uri")
                cfg_.oidc_redirect_uri = e.value;
            else if (e.key == "oidc_admin_group")
                cfg_.oidc_admin_group = e.value;
            else if (e.key == "oidc_skip_tls_verify")
                cfg_.oidc_skip_tls_verify = (e.value == "true");
        }
    }

    void emit_event(const std::string& event_type, const httplib::Request& req,
                    const nlohmann::json& attrs = {}, const nlohmann::json& payload_data = {},
                    Severity sev = Severity::kInfo) {
        auth_routes_->emit_event(event_type, req, attrs, payload_data, sev);
    }

    void start_web_server() {
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
        if (cfg_.https_enabled) {
            if (cfg_.https_cert_path.empty() || cfg_.https_key_path.empty()) {
                spdlog::error("HTTPS is enabled by default but --https-cert and --https-key "
                              "are required. Provide certificate paths or use --no-https "
                              "for development.");
                return;
            }
            if (!std::filesystem::exists(cfg_.https_cert_path)) {
                spdlog::error("HTTPS cert not found: {}", cfg_.https_cert_path.string());
                return;
            }
            if (!std::filesystem::exists(cfg_.https_key_path)) {
                spdlog::error("HTTPS key not found: {}", cfg_.https_key_path.string());
                return;
            }
            if (!detail::validate_key_file_permissions(cfg_.https_key_path, "HTTPS")) {
                spdlog::error("Fix key file permissions before starting with HTTPS");
                return;
            }
            web_server_ = std::make_unique<httplib::SSLServer>(
                cfg_.https_cert_path.string().c_str(), cfg_.https_key_path.string().c_str());
            spdlog::info("HTTPS enabled on port {} (cert: {}, key: {})", cfg_.https_port,
                         cfg_.https_cert_path.string(), cfg_.https_key_path.string());
        } else {
            spdlog::warn("HTTPS disabled via --no-https. Dashboard traffic is unencrypted.");
            web_server_ = std::make_unique<httplib::Server>();
        }
#else
        if (cfg_.https_enabled) {
            spdlog::warn(
                "HTTPS requested but OpenSSL support not compiled in; falling back to HTTP");
        }
        if (!cfg_.https_enabled) {
            spdlog::warn("HTTPS disabled via --no-https. Dashboard traffic is unencrypted.");
        }
        web_server_ = std::make_unique<httplib::Server>();
#endif

        // Disable Nagle — SSE events are small and must reach the browser
        // immediately, not wait 200ms for the TCP send buffer to coalesce.
        web_server_->set_tcp_nodelay(true);

        // SSE connections are long-lived; the default 5s keep-alive timeout
        // causes browsers to close idle EventSource connections prematurely.
        web_server_->set_keep_alive_timeout(120);
        web_server_->set_keep_alive_max_count(std::numeric_limits<size_t>::max());

        // Increase socket read/write timeouts from the 5s defaults.
        // Under load, slow responses can hit the 5s deadline and drop
        // in-progress connections; 30s gives adequate headroom.
        web_server_->set_read_timeout(30);
        web_server_->set_write_timeout(30);

        // -- Auth middleware (pre-routing) -----------------------------------
        web_server_->set_pre_routing_handler([this](const httplib::Request& req,
                                                    httplib::Response& res)
                                                 -> httplib::Server::HandlerResponse {
            // Lightweight probes — always allowed, no auth, no rate limit.
            // /health and /api/health are included here (governance Gate 7,
            // unhappy-path UP-1) so monitoring integrations behind a NAT or
            // sharing a source-IP bucket with authed REST traffic cannot
            // 429-starve the health probe. The endpoints themselves are
            // strictly read-only and documented as unauthenticated.
            if (req.path == "/livez" || req.path == "/readyz" || req.path == "/health" ||
                req.path == "/api/health") {
                return httplib::Server::HandlerResponse::Unhandled;
            }

            // Rate limiting — check before auth to protect against brute force
            bool is_login = (req.path == "/login" && req.method == "POST");
            auto& limiter = is_login ? login_rate_limiter_ : api_rate_limiter_;
            if (!limiter.allow(req.remote_addr)) {
                res.status = 429;
                res.set_header("Retry-After", "1");
                res.set_content(
                    R"({"error":{"code":429,"message":"rate limit exceeded"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return httplib::Server::HandlerResponse::Handled;
            }

            // Allow unauthenticated access to login page, health, OIDC flow, and OpenAPI spec.
            // /health and /api/health are ALSO covered by the early-return
            // exemption at the top of this lambda (which additionally skips
            // rate limiting). They are kept in this list as defense-in-depth
            // — a future contributor narrowing the early-return back to
            // /livez|/readyz alone would silently start requiring auth on
            // /health without this lower entry. Governance Gate 7, security
            // re-review LOW. Do not remove either site without updating both.
            if (req.path == "/login" || req.path == "/health" || req.path == "/api/health" ||
                req.path == "/auth/oidc/start" || req.path == "/auth/callback" ||
                req.path == "/api/v1/openapi.json" || req.path.starts_with("/static/")) {
                return httplib::Server::HandlerResponse::Unhandled;
            }

            // /metrics: localhost always unauthenticated; remote depends on config
            if (req.path == "/metrics") {
                if (req.remote_addr == "127.0.0.1" || req.remote_addr == "::1") {
                    return httplib::Server::HandlerResponse::Unhandled;
                }
                if (!cfg_.metrics_require_auth) {
                    return httplib::Server::HandlerResponse::Unhandled;
                }
                // Remote callers fall through to normal auth check below
            }

            auto session = auth_routes_->resolve_session(req);

            if (!session) {
                // API calls and MCP endpoint get 401 JSON, pages get redirect
                if (req.path.starts_with("/api/") || req.path == "/events" ||
                    req.path.starts_with("/mcp/")) {
                    res.status = 401;
                    res.set_content(
                        R"({"error":{"code":401,"message":"unauthorized"},"meta":{"api_version":"v1"}})",
                        "application/json");
                } else {
                    res.set_redirect("/login");
                }
                return httplib::Server::HandlerResponse::Handled;
            }

            return httplib::Server::HandlerResponse::Unhandled;
        });

        // -- Auth routes (login, logout, OIDC) — delegated to AuthRoutes --------
        auth_routes_->register_routes(*web_server_);

        // -- HTTP metrics + CORS + security headers (post-routing handler) -------
        // Security headers (SOC2-C1) — pre-compute the static header bundle
        // ONCE at startup and capture it by value into the lambda. The same
        // HeaderBundle code path is exercised by the unit tests in
        // tests/unit/server/test_security_headers.cpp, so a regression in the
        // bundle would be caught by CI before reaching the post-routing
        // handler.
        //
        // Pre-condition: cfg_.csp_extra_sources has already been validated by
        // main.cpp via security::validate_csp_extra_sources before
        // Server::create was called.
        const auto security_headers =
            security::HeaderBundle::make(cfg_.csp_extra_sources, cfg_.https_enabled);
        spdlog::info("Security headers active: CSP={} bytes, HSTS={}, "
                     "Referrer-Policy=\"{}\", Permissions-Policy={} bytes",
                     security_headers.csp.size(), security_headers.https_enabled ? "on" : "off",
                     security_headers.referrer_policy, security_headers.permissions_policy.size());
        spdlog::debug("Resolved Content-Security-Policy: {}", security_headers.csp);
        web_server_->set_post_routing_handler([this, security_headers](const httplib::Request& req,
                                                                       httplib::Response& res) {
            // -- Security response headers (SOC2-C1) ---------------------
            // Applied to ALL responses (dashboard, API, metrics, health,
            // error pages).
            security_headers.apply(res);

            // CORS headers for all /api/ responses (H6)
            // Only reflect Origin if it matches the server's own origin
            // to prevent credentialed cross-origin attacks.
            if (req.path.starts_with("/api/")) {
                auto origin = req.get_header_value("Origin");
                if (!origin.empty()) {
                    auto scheme = cfg_.https_enabled ? "https" : "http";
                    auto port = cfg_.https_enabled ? cfg_.https_port : cfg_.web_port;
                    auto self_origin = std::format("{}://{}:{}", scheme, cfg_.web_address, port);
                    auto localhost_origin = std::format("{}://localhost:{}", scheme, port);
                    auto loopback_origin = std::format("{}://127.0.0.1:{}", scheme, port);
                    if (origin == self_origin || origin == localhost_origin ||
                        origin == loopback_origin) {
                        res.set_header("Access-Control-Allow-Origin", origin);
                        res.set_header("Access-Control-Allow-Credentials", "true");
                    }
                }
                res.set_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
                res.set_header("Access-Control-Allow-Headers",
                               "Content-Type, Authorization, X-Yuzu-Token");
                res.set_header("Access-Control-Max-Age", "86400");
            }

            metrics_
                .counter("yuzu_http_requests_total",
                         {{"method", req.method}, {"status", std::to_string(res.status)}})
                .increment();
        });

        // -- Prometheus metrics endpoint ----------------------------------------
        web_server_->Get("/metrics", [this](const httplib::Request&, httplib::Response& res) {
            // Refresh management group gauges before serializing
            if (mgmt_group_store_ && mgmt_group_store_->is_open()) {
                metrics_.gauge("yuzu_server_management_groups_total")
                    .set(static_cast<double>(mgmt_group_store_->count_groups()));
                metrics_.gauge("yuzu_server_group_members_total")
                    .set(static_cast<double>(mgmt_group_store_->count_all_members()));
            }
            res.set_content(metrics_.serialize(), "text/plain; version=0.0.4; charset=utf-8");
        });

        // -- Health endpoint (7.2) ------------------------------------------------
        // Mounted on both /health and /api/health (issue #620). The /api alias
        // exists so monitoring integrations that prefix every REST call with
        // /api/ keep working — a side-effect of #401's move from /api/health → /health.
        auto health_handler = [this](const httplib::Request& req, httplib::Response& res) {
            // Resolve auth FIRST so we can gate expensive work on it.
            // Governance Gate 7 round 2 (security MEDIUM): /health and
            // /api/health are rate-limit-exempt for monitoring stability;
            // the bounded but non-trivial work below (SQLite scans on
            // pending-agents and execution_tracker) must only run for
            // authenticated callers, otherwise an unauth flood becomes a
            // DoS amplification primitive. Unauth callers get the cheap
            // probe response — status, uptime, agent count from in-memory
            // registry, store ok flags from is_open() (constant-time member
            // checks), and version. Authed callers additionally get
            // pending-agent count, execution stats, and process sampler.
            bool is_authenticated = static_cast<bool>(auth_routes_->resolve_session(req));

            auto now = std::chrono::steady_clock::now();
            auto uptime_sec =
                std::chrono::duration_cast<std::chrono::seconds>(now - server_start_time_).count();

            // Cheap: in-memory agent registry count.
            auto online = registry_.agent_count();

            // Store health — is_open() is a constant-time member check, no DB I/O.
            auto response_ok = response_store_ && response_store_->is_open();
            auto audit_ok = audit_store_ && audit_store_->is_open();
            auto instruction_ok = instruction_store_ && instruction_store_->is_open();
            auto policy_ok = policy_store_ && policy_store_->is_open();
            // Guardian store is load-bearing for the /api/v1/guaranteed-state/*
            // surface; prior to inclusion here /healthz reported "healthy" while
            // every Guardian endpoint returned 503. Mirrors the /readyz conjunction.
            bool guaranteed_state_ok =
                guaranteed_state_store_ && guaranteed_state_store_->is_open();
            // Phase 8.3 #255 — same pattern as Guardian above. Without
            // this row /healthz would report "healthy" while every
            // /api/v1/offload-targets endpoint and every fire_event call
            // silently no-ops on a migration failure (HC-1 from Gate 6).
            bool offload_target_ok = offload_target_store_ && offload_target_store_->is_open();

            // Determine overall status
            bool all_stores_ok = response_ok && audit_ok && instruction_ok && policy_ok &&
                                 guaranteed_state_ok && offload_target_ok;
            std::string status = all_stores_ok ? "healthy" : "degraded";

            nlohmann::json health = {
                {"status", status},
                {"uptime_seconds", uptime_sec},
                {"agents", {{"online", online}}}, // pending added below for authed callers
                {"stores",
                 {{"responses", response_ok ? "ok" : "error"},
                  {"audit", audit_ok ? "ok" : "error"},
                  {"instructions", instruction_ok ? "ok" : "error"},
                  {"policies", policy_ok ? "ok" : "error"},
                  {"guaranteed_state", guaranteed_state_ok ? "ok" : "error"},
                  {"offload_target", offload_target_ok ? "ok" : "error"}}},
                // #401: was hardcoded "0.1.0" — now derived from the
                // meson-generated yuzu/version.hpp so the health endpoint
                // tracks the actual build instead of a stale literal.
                {"version", std::string(yuzu::kVersionString)}};

            // Authenticated extension — heavier work, only run when the caller
            // has a session. Adds: agents.pending (SQLite scan), executions.*
            // (SQLite scan + 1h-window loop), system.* (process_health_sampler).
            if (is_authenticated) {
                auto pending_agents = auth_mgr_.list_pending_agents();
                int pending_count = 0;
                for (const auto& a : pending_agents) {
                    if (a.status == auth::PendingStatus::pending)
                        ++pending_count;
                }
                health["agents"]["pending"] = pending_count;

                int in_flight = 0;
                int completed_last_hour = 0;
                int failed_last_hour = 0;
                if (execution_tracker_) {
                    auto running = execution_tracker_->query_executions({.status = "running"});
                    in_flight = static_cast<int>(running.size());
                    auto now_epoch = std::chrono::duration_cast<std::chrono::seconds>(
                                         std::chrono::system_clock::now().time_since_epoch())
                                         .count();
                    auto hour_ago = now_epoch - 3600;
                    auto recent = execution_tracker_->query_executions({.limit = 1000});
                    for (const auto& e : recent) {
                        if (e.completed_at >= hour_ago) {
                            if (e.status == "completed")
                                ++completed_last_hour;
                            else if (e.status == "failed")
                                ++failed_last_hour;
                        }
                    }
                }
                health["executions"] = {{"in_flight", in_flight},
                                        {"completed_last_hour", completed_last_hour},
                                        {"failed_last_hour", failed_last_hour}};

                // Process health (22.1) — leaks process internals so
                // intentionally authenticated-only.
                auto ph = process_health_sampler_.sample();
                health["system"] = {{"cpu_percent", ph.cpu_percent},
                                    {"memory_rss_bytes", static_cast<int64_t>(ph.memory_rss_bytes)},
                                    {"memory_vss_bytes", static_cast<int64_t>(ph.memory_vss_bytes)},
                                    {"grpc_connections", static_cast<int>(online)},
                                    {"command_queue_depth", in_flight}};
            }

            res.set_content(health.dump(), "application/json");
        };
        // Both URLs MUST be served by the SAME handler instance — do not split
        // into two lambda bodies. The unauthenticated `system.*` gating above
        // is load-bearing and must run identically on both routes; forking the
        // body invites a future regression where the alias diverges in subtle
        // ways. Governance Gate 7, architect NICE-2.
        web_server_->Get("/health", health_handler);
        web_server_->Get("/api/health", health_handler);

        // -- Kubernetes probe endpoints (/livez, /readyz) -------------------------
        web_server_->Get("/livez", [](const httplib::Request&, httplib::Response& res) {
            res.set_content(R"({"status":"ok"})", "application/json");
        });

        web_server_->Get("/readyz", [this](const httplib::Request&, httplib::Response& res) {
            if (draining_.load(std::memory_order_acquire)) {
                res.status = 503;
                res.set_content(R"({"status":"draining"})", "application/json");
                return;
            }

            // Check every store that is load-bearing for request handling.
            // A store with a failed migration has had db_ closed and nullified
            // inside create_tables(), so is_open() will correctly return false.
            struct StoreCheck {
                const char* name;
                bool ok;
            };
            std::vector<StoreCheck> checks = {
                {"response_store", response_store_ && response_store_->is_open()},
                {"audit_store", audit_store_ && audit_store_->is_open()},
                {"instruction_store", instruction_store_ && instruction_store_->is_open()},
                {"api_token_store", api_token_store_ && api_token_store_->is_open()},
                {"policy_store", policy_store_ && policy_store_->is_open()},
                {"rbac_store", rbac_store_ && rbac_store_->is_open()},
                {"tag_store", tag_store_ && tag_store_->is_open()},
                {"management_group_store", mgmt_group_store_ && mgmt_group_store_->is_open()},
                {"runtime_config_store", runtime_config_store_ && runtime_config_store_->is_open()},
                {"inventory_store", inventory_store_ && inventory_store_->is_open()},
                {"workflow_engine", workflow_engine_ && workflow_engine_->is_open()},
                {"custom_properties_store",
                 custom_properties_store_ && custom_properties_store_->is_open()},
                {"guaranteed_state_store",
                 guaranteed_state_store_ && guaranteed_state_store_->is_open()},
                // PR 5b: AuthDB integrity-check coverage. Reports "ok" on
                // legacy config-file-only deployments (auth_db_ == nullptr
                // in AuthManager) and false only when an opted-in AuthDB
                // failed the integrity check or migration. SOC 2 evidence:
                // an operator can detect a corrupt auth.db without scraping
                // spdlog; pairs with docs/ops-runbooks/auth-db-recovery.md.
                {"auth_db", auth_mgr_.is_auth_db_ok()},
                // Phase 8.3 #255 — load-bearing for /api/v1/offload-targets
                // and the AgentService fan-out path. A migration failure
                // would silently no-op all offload deliveries while the
                // probe reported "ready" (HC-1 gap from Gate 6 SRE).
                {"offload_target_store", offload_target_store_ && offload_target_store_->is_open()},
            };

            std::string failed_list;
            for (const auto& c : checks) {
                if (!c.ok) {
                    if (!failed_list.empty())
                        failed_list += ",";
                    failed_list += "\"";
                    failed_list += c.name;
                    failed_list += "\"";
                }
            }

            if (failed_list.empty()) {
                res.set_content(R"({"status":"ready"})", "application/json");
            } else {
                res.status = 503;
                res.set_content("{\"status\":\"not ready\",\"failed_stores\":[" + failed_list +
                                    "]}",
                                "application/json");
            }
        });

        // -- Health summary dashboard fragment (7.2) ----------------------------
        web_server_->Get("/fragments/health/summary", [this](const httplib::Request& req,
                                                             httplib::Response& res) {
            auto session = require_auth(req, res);
            if (!session)
                return;

            auto now = std::chrono::steady_clock::now();
            auto uptime_sec =
                std::chrono::duration_cast<std::chrono::seconds>(now - server_start_time_).count();

            // Store health
            bool response_ok = response_store_ && response_store_->is_open();
            bool audit_ok = audit_store_ && audit_store_->is_open();
            bool instruction_ok = instruction_store_ && instruction_store_->is_open();
            bool policy_ok = policy_store_ && policy_store_->is_open();
            bool guaranteed_state_ok =
                guaranteed_state_store_ && guaranteed_state_store_->is_open();
            bool all_ok =
                response_ok && audit_ok && instruction_ok && policy_ok && guaranteed_state_ok;

            // Execution stats
            int in_flight = 0;
            if (execution_tracker_) {
                auto running = execution_tracker_->query_executions({.status = "running"});
                in_flight = static_cast<int>(running.size());
            }

            // Format uptime
            auto days = uptime_sec / 86400;
            auto hours = (uptime_sec % 86400) / 3600;
            auto mins = (uptime_sec % 3600) / 60;
            std::string uptime_str;
            if (days > 0)
                uptime_str = std::to_string(days) + "d " + std::to_string(hours) + "h";
            else if (hours > 0)
                uptime_str = std::to_string(hours) + "h " + std::to_string(mins) + "m";
            else
                uptime_str = std::to_string(mins) + "m";

            auto online = registry_.agent_count();

            // Process health for dashboard
            auto ph = process_health_sampler_.sample();
            auto rss_mb = ph.memory_rss_bytes / (1024 * 1024);
            char cpu_buf[16];
            std::snprintf(cpu_buf, sizeof(cpu_buf), "%.1f", ph.cpu_percent);

            // Only render the strip if there are issues
            if (all_ok && in_flight == 0) {
                // Minimal healthy summary
                std::string html =
                    "<div class=\"health-strip health-ok\" "
                    "style=\"display:flex;gap:1.5rem;align-items:center;"
                    "padding:0.4rem 1rem;background:var(--surface-1);"
                    "border-left:3px solid var(--green);border-radius:4px;"
                    "font-size:0.8rem;color:var(--text-secondary);margin-bottom:0.75rem\">"
                    "<span>Server healthy</span>"
                    "<span>Uptime: " +
                    uptime_str +
                    "</span>"
                    "<span>Agents online: " +
                    std::to_string(online) +
                    "</span>"
                    "<span>CPU: " +
                    std::string(cpu_buf) +
                    "%</span>"
                    "<span>Mem: " +
                    std::to_string(rss_mb) +
                    " MB</span>"
                    "</div>";
                res.set_content(html, "text/html; charset=utf-8");
                return;
            }

            // Degraded or busy — show warning strip
            std::string html =
                "<div class=\"health-strip health-warn\" "
                "style=\"display:flex;gap:1.5rem;align-items:center;"
                "padding:0.4rem 1rem;background:var(--surface-1);"
                "border-left:3px solid var(--yellow);border-radius:4px;"
                "font-size:0.8rem;color:var(--text-secondary);margin-bottom:0.75rem\">";

            if (!all_ok) {
                html += "<span style=\"color:var(--yellow)\">Stores degraded: ";
                if (!response_ok)
                    html += "responses ";
                if (!audit_ok)
                    html += "audit ";
                if (!instruction_ok)
                    html += "instructions ";
                if (!policy_ok)
                    html += "policies ";
                html += "</span>";
            }

            html += "<span>Uptime: " + uptime_str + "</span>";
            html += "<span>Agents: " + std::to_string(online) + "</span>";
            html += "<span>CPU: " + std::string(cpu_buf) + "%</span>";
            html += "<span>Mem: " + std::to_string(rss_mb) + " MB</span>";
            if (in_flight > 0)
                html += "<span>In-flight: " + std::to_string(in_flight) + "</span>";

            html += "</div>";
            res.set_content(html, "text/html; charset=utf-8");
        });

        // -- Runtime Configuration API (7.3) ------------------------------------
        web_server_->Get("/api/config", [this](const httplib::Request& req,
                                               httplib::Response& res) {
            if (!require_permission(req, res, "Infrastructure", "Read"))
                return;

            nlohmann::json config_obj;
            // Current effective values (from cfg_ + overrides)
            config_obj["heartbeat_timeout"] = cfg_.session_timeout.count();
            config_obj["response_retention_days"] = cfg_.response_retention_days;
            config_obj["audit_retention_days"] = cfg_.audit_retention_days;
            config_obj["guardian_event_retention_days"] = cfg_.guardian_event_retention_days;
            config_obj["auto_approve_enabled"] = !auto_approve_.list_rules().empty();
            config_obj["log_level"] =
                spdlog::level::to_string_view(spdlog::default_logger()->level()).data();

            // Overrides from store
            nlohmann::json overrides = nlohmann::json::object();
            if (runtime_config_store_ && runtime_config_store_->is_open()) {
                auto entries = runtime_config_store_->get_all();
                for (const auto& e : entries) {
                    overrides[e.key] = {{"value", e.value},
                                        {"updated_by", e.updated_by},
                                        {"updated_at", e.updated_at}};
                }
            }

            nlohmann::json allowed = nlohmann::json::array();
            for (const auto& k : RuntimeConfigStore::allowed_keys())
                allowed.push_back(k);

            res.set_content(
                nlohmann::json(
                    {{"config", config_obj}, {"overrides", overrides}, {"allowed_keys", allowed}})
                    .dump(),
                "application/json");
        });

        web_server_->Put(R"(/api/config/([a-z_]+))", [this](const httplib::Request& req,
                                                            httplib::Response& res) {
            if (!require_permission(req, res, "Infrastructure", "Write"))
                return;
            if (!runtime_config_store_ || !runtime_config_store_->is_open()) {
                res.status = 503;
                res.set_content(
                    R"({"error":{"code":503,"message":"runtime config store unavailable"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }

            auto key = req.matches[1].str();
            std::string value;
            try {
                auto j = nlohmann::json::parse(req.body);
                if (j.contains("value"))
                    value =
                        j["value"].is_string() ? j["value"].get<std::string>() : j["value"].dump();
                else {
                    res.status = 400;
                    res.set_content(
                        R"({"error":{"code":400,"message":"missing 'value' in request body"},"meta":{"api_version":"v1"}})",
                        "application/json");
                    return;
                }
            } catch (...) {
                res.status = 400;
                res.set_content(
                    R"({"error":{"code":400,"message":"invalid JSON body"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }

            // Validate integer-typed keys BEFORE persisting so a
            // non-numeric or negative value does not silently land
            // in RuntimeConfigStore while leaving cfg_ at the old
            // value (the prior `try { stoi } catch (...) {}` path
            // was a ghost-write: store persists, cfg ignores,
            // operator sees 200 with no effect). UP-R5 from the
            // Guardian PR 2 governance re-run.
            const bool is_int_key =
                key == "heartbeat_timeout" || key == "response_retention_days" ||
                key == "audit_retention_days" || key == "guardian_event_retention_days";
            int parsed_int = 0;
            if (is_int_key) {
                auto first = value.data();
                auto last = value.data() + value.size();
                auto [ptr, ec] = std::from_chars(first, last, parsed_int);
                if (ec != std::errc{} || ptr != last || parsed_int < 0) {
                    res.status = 400;
                    res.set_content(
                        R"({"error":{"code":400,"message":"value must be a non-negative integer"},"meta":{"api_version":"v1"}})",
                        "application/json");
                    return;
                }
            }

            // Get username from session
            auto session = require_auth(req, res);
            if (!session)
                return;

            auto result = runtime_config_store_->set(key, value, session->username);
            if (!result) {
                res.status = 400;
                res.set_content(nlohmann::json({{"error", result.error()}}).dump(),
                                "application/json");
                return;
            }

            // Apply the change to in-memory config. Integer keys
            // parsed above; direct assignment here means no
            // second `try { stoi }` that could swallow errors.
            if (key == "heartbeat_timeout") {
                cfg_.session_timeout = std::chrono::seconds(parsed_int);
            } else if (key == "response_retention_days") {
                cfg_.response_retention_days = parsed_int;
            } else if (key == "audit_retention_days") {
                cfg_.audit_retention_days = parsed_int;
            } else if (key == "guardian_event_retention_days") {
                cfg_.guardian_event_retention_days = parsed_int;
            }
            // log_level is applied inside RuntimeConfigStore::set()

            audit_log(req, "config.update", "success", "RuntimeConfig", key, "value=" + value);

            res.set_content(
                nlohmann::json({{"key", key}, {"value", value}, {"applied", true}}).dump(),
                "application/json");
        });

        // -- Custom Properties API (7.6) ----------------------------------------

        // GET /api/agents/:id/properties
        web_server_->Get(R"(/api/agents/([^/]+)/properties)", [this](const httplib::Request& req,
                                                                     httplib::Response& res) {
            if (!require_permission(req, res, "Infrastructure", "Read"))
                return;
            if (!custom_properties_store_ || !custom_properties_store_->is_open()) {
                res.status = 503;
                res.set_content(
                    R"({"error":{"code":503,"message":"custom properties store unavailable"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }

            auto agent_id = req.matches[1].str();
            auto props = custom_properties_store_->get_properties(agent_id);
            nlohmann::json arr = nlohmann::json::array();
            for (const auto& p : props) {
                arr.push_back({{"key", p.key},
                               {"value", p.value},
                               {"type", p.type},
                               {"updated_at", p.updated_at}});
            }
            res.set_content(nlohmann::json({{"agent_id", agent_id}, {"properties", arr}}).dump(),
                            "application/json");
        });

        // PUT /api/agents/:id/properties/:key
        web_server_->Put(R"(/api/agents/([^/]+)/properties/([a-zA-Z0-9_.:-]+))", [this](
                                                                                     const httplib::
                                                                                         Request&
                                                                                             req,
                                                                                     httplib::
                                                                                         Response&
                                                                                             res) {
            if (!require_permission(req, res, "Infrastructure", "Write"))
                return;
            if (!custom_properties_store_ || !custom_properties_store_->is_open()) {
                res.status = 503;
                res.set_content(
                    R"({"error":{"code":503,"message":"custom properties store unavailable"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }

            auto agent_id = req.matches[1].str();
            auto key = req.matches[2].str();

            std::string value;
            std::string type = "string";
            try {
                auto j = nlohmann::json::parse(req.body);
                if (j.contains("value"))
                    value =
                        j["value"].is_string() ? j["value"].get<std::string>() : j["value"].dump();
                else {
                    res.status = 400;
                    res.set_content(
                        R"({"error":{"code":400,"message":"missing 'value' in request body"},"meta":{"api_version":"v1"}})",
                        "application/json");
                    return;
                }
                if (j.contains("type") && j["type"].is_string())
                    type = j["type"].get<std::string>();
            } catch (...) {
                res.status = 400;
                res.set_content(
                    R"({"error":{"code":400,"message":"invalid JSON body"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }

            auto result = custom_properties_store_->set_property(agent_id, key, value, type);
            if (!result) {
                res.status = 400;
                res.set_content(nlohmann::json({{"error", result.error()}}).dump(),
                                "application/json");
                return;
            }

            audit_log(req, "custom_property.set", "success", "Agent", agent_id, key + "=" + value);

            res.set_content(
                nlohmann::json(
                    {{"agent_id", agent_id}, {"key", key}, {"value", value}, {"type", type}})
                    .dump(),
                "application/json");
        });

        // DELETE /api/agents/:id/properties/:key
        web_server_->Delete(R"(/api/agents/([^/]+)/properties/([a-zA-Z0-9_.:-]+))", [this](
                                                                                        const httplib::
                                                                                            Request&
                                                                                                req,
                                                                                        httplib::
                                                                                            Response&
                                                                                                res) {
            if (!require_permission(req, res, "Infrastructure", "Write"))
                return;
            if (!custom_properties_store_ || !custom_properties_store_->is_open()) {
                res.status = 503;
                res.set_content(
                    R"({"error":{"code":503,"message":"custom properties store unavailable"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }

            auto agent_id = req.matches[1].str();
            auto key = req.matches[2].str();

            bool deleted = custom_properties_store_->delete_property(agent_id, key);
            if (!deleted) {
                res.status = 404;
                res.set_content(
                    R"({"error":{"code":404,"message":"property not found"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }

            audit_log(req, "custom_property.delete", "success", "Agent", agent_id, "key=" + key);

            res.set_content(nlohmann::json({{"deleted", true}, {"key", key}}).dump(),
                            "application/json");
        });

        // GET /api/property-schemas
        web_server_->Get("/api/property-schemas", [this](const httplib::Request& req,
                                                         httplib::Response& res) {
            if (!require_permission(req, res, "Infrastructure", "Read"))
                return;
            if (!custom_properties_store_ || !custom_properties_store_->is_open()) {
                res.status = 503;
                res.set_content(
                    R"({"error":{"code":503,"message":"custom properties store unavailable"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }

            auto schemas = custom_properties_store_->list_schemas();
            nlohmann::json arr = nlohmann::json::array();
            for (const auto& s : schemas) {
                arr.push_back({{"key", s.key},
                               {"display_name", s.display_name},
                               {"type", s.type},
                               {"description", s.description},
                               {"validation_regex", s.validation_regex}});
            }
            res.set_content(nlohmann::json({{"schemas", arr}}).dump(), "application/json");
        });

        // POST /api/property-schemas
        web_server_->Post("/api/property-schemas", [this](const httplib::Request& req,
                                                          httplib::Response& res) {
            if (!require_permission(req, res, "Infrastructure", "Write"))
                return;
            if (!custom_properties_store_ || !custom_properties_store_->is_open()) {
                res.status = 503;
                res.set_content(
                    R"({"error":{"code":503,"message":"custom properties store unavailable"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }

            CustomPropertySchema schema;
            try {
                auto j = nlohmann::json::parse(req.body);
                schema.key = j.value("key", "");
                schema.display_name = j.value("display_name", "");
                schema.type = j.value("type", "string");
                schema.description = j.value("description", "");
                schema.validation_regex = j.value("validation_regex", "");
            } catch (...) {
                res.status = 400;
                res.set_content(
                    R"({"error":{"code":400,"message":"invalid JSON body"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }

            if (schema.key.empty()) {
                res.status = 400;
                res.set_content(
                    R"({"error":{"code":400,"message":"'key' is required"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }

            auto result = custom_properties_store_->upsert_schema(schema);
            if (!result) {
                res.status = 400;
                res.set_content(nlohmann::json({{"error", result.error()}}).dump(),
                                "application/json");
                return;
            }

            audit_log(req, "property_schema.create", "success", "PropertySchema", schema.key);

            res.status = 201;
            res.set_content(nlohmann::json({{"key", schema.key},
                                            {"display_name", schema.display_name},
                                            {"type", schema.type},
                                            {"description", schema.description},
                                            {"validation_regex", schema.validation_regex}})
                                .dump(),
                            "application/json");
        });

        // -- Current user info (/api/me) --------------------------------------
        web_server_->Get("/api/me", [this](const httplib::Request& req, httplib::Response& res) {
            auto session = require_auth(req, res);
            if (!session)
                return;
            auto j = nlohmann::json(
                {{"username", session->username}, {"role", auth::role_to_string(session->role)}});
            // Add RBAC role if enabled
            if (rbac_store_ && rbac_store_->is_rbac_enabled()) {
                j["rbac_enabled"] = true;
                auto roles = rbac_store_->get_principal_roles("user", session->username);
                if (!roles.empty()) {
                    j["rbac_role"] = roles[0].role_name;
                } else {
                    // Fallback: map legacy role to RBAC role name
                    j["rbac_role"] =
                        session->role == auth::Role::admin ? "Administrator" : "Viewer";
                }
            } else {
                j["rbac_enabled"] = false;
                j["rbac_role"] = session->role == auth::Role::admin ? "Administrator" : "Viewer";
            }
            res.set_content(j.dump(), "application/json");
        });

        // -- Static design-system assets ----------------------------------------
        // CSS is served with no-cache so dashboard skin iteration during
        // active dev/UAT is picked up on a normal browser reload. The bundle
        // is ~22 KB; revalidation cost is negligible. Switch back to
        // max-age + content-hashed URL for prod once the skin stabilises.
        web_server_->Get("/static/yuzu.css", [](const httplib::Request&, httplib::Response& res) {
            res.set_header("Cache-Control", "no-cache, no-store, must-revalidate");
            res.set_content(yuzu::server::kYuzuCss, "text/css; charset=utf-8");
        });
        web_server_->Get("/static/icons.svg", [](const httplib::Request&, httplib::Response& res) {
            res.set_header("Cache-Control", "public, max-age=3600");
            res.set_content(kYuzuIconsSvg, "image/svg+xml");
        });
        web_server_->Get("/static/htmx.js", [](const httplib::Request&, httplib::Response& res) {
            res.set_header("Cache-Control", "public, max-age=86400");
            res.set_content(kHtmxJs, "application/javascript; charset=utf-8");
        });
        web_server_->Get("/static/sse.js", [](const httplib::Request&, httplib::Response& res) {
            res.set_header("Cache-Control", "public, max-age=86400");
            res.set_content(kSseJs, "application/javascript; charset=utf-8");
        });
        // Issue #253: response visualization renderer.
        // /static/echarts.min.js is the vendored Apache ECharts 5 library
        // (Apache-2.0). /static/yuzu-charts.js is the thin Yuzu adapter
        // that maps our chart payload onto ECharts options and reads
        // Yuzu design-system CSS tokens for theming. Both are cached aggressively
        // because the bundle is content-addressed by binary version.
        web_server_->Get(
            "/static/echarts.min.js", [](const httplib::Request&, httplib::Response& res) {
                res.set_header("Cache-Control", "public, max-age=86400");
                res.set_content(yuzu::server::kEChartsJs, "application/javascript; charset=utf-8");
            });
        // Inter variable webfont (SIL OFL) — the Yuzu design system's
        // default family. Single woff2 covers all weights via font-
        // variation-settings on the @font-face declaration in
        // css_bundle.cpp.
        web_server_->Get("/static/fonts/InterVariable.woff2", [](const httplib::Request&,
                                                                 httplib::Response& res) {
            res.set_header("Cache-Control", "public, max-age=2592000, immutable");
            // Zero-copy: pass the byte view's data+size directly so we
            // don't allocate a 345 KB std::string per fetch. (Gate 3
            // cpp-S1.) httplib's set_content(const char*, size_t, ...)
            // copies into the response buffer once.
            res.set_content(yuzu::server::kInterVariableWoff2.data(),
                            yuzu::server::kInterVariableWoff2.size(), "font/woff2");
        });

        web_server_->Get("/static/yuzu-charts.js", [](const httplib::Request&,
                                                      httplib::Response& res) {
            res.set_header("Cache-Control", "public, max-age=86400");
            res.set_content(yuzu::server::kYuzuChartsJs, "application/javascript; charset=utf-8");
        });

        // Issue #253 fragment route lives in dashboard_routes.cpp now (#589).

        // -- Dashboard (unified UI) -------------------------------------------
        web_server_->Get("/", [](const httplib::Request&, httplib::Response& res) {
            res.set_content(kDashboardIndexHtml, "text/html; charset=utf-8");
        });

        // -- Settings routes (extracted to settings_routes.cpp) ---------------
        settings_routes_ = std::make_unique<SettingsRoutes>();
        settings_routes_->register_routes(
            *web_server_,
            [this](const httplib::Request& req, httplib::Response& res) {
                return require_auth(req, res);
            },
            [this](const httplib::Request& req, httplib::Response& res) {
                return require_admin(req, res);
            },
            [this](const httplib::Request& req, httplib::Response& res,
                   const std::string& securable_type, const std::string& operation) {
                return require_permission(req, res, securable_type, operation);
            },
            [this](const httplib::Request& req, const std::string& action,
                   const std::string& result, const std::string& target_type,
                   const std::string& target_id, const std::string& detail) {
                audit_log(req, action, result, target_type, target_id, detail);
            },
            cfg_, auth_mgr_, auto_approve_, api_token_store_.get(), mgmt_group_store_.get(),
            tag_store_.get(), update_registry_.get(), runtime_config_store_.get(),
            audit_store_.get(), gateway_service_ != nullptr,
            gateway_service_ ? SettingsRoutes::GatewaySessionCountFn([this]() -> std::size_t {
                return gateway_service_->session_count();
            })
                             : SettingsRoutes::GatewaySessionCountFn{},
            [this]() -> std::string { return registry_.to_json(); }, oidc_mu_, oidc_provider_);

        // Legacy routes — redirect to dashboard
        web_server_->Get("/chargen", [](const httplib::Request&, httplib::Response& res) {
            res.set_redirect("/");
        });
        web_server_->Get("/procfetch", [](const httplib::Request&, httplib::Response& res) {
            res.set_redirect("/");
        });

        // SSE endpoint
        web_server_->Get("/events", [this](const httplib::Request&, httplib::Response& res) {
            res.set_header("Cache-Control", "no-cache");
            res.set_header("X-Accel-Buffering", "no");

            auto sink_state = std::make_shared<detail::SseSinkState>();
            sink_state->sub_id = event_bus_.subscribe([sink_state](const detail::SseEvent& ev) {
                {
                    std::lock_guard<std::mutex> lk(sink_state->mu);
                    sink_state->queue.push_back(ev);
                }
                sink_state->cv.notify_one();
            });

            detail::EventBus* bus = &event_bus_;
            // Use chunked content provider so httplib sends each sink.write()
            // as a complete HTTP chunk in a single send() call.  The browser
            // processes each chunk eagerly (no buffering of raw streams).
            // Note: httplib's chunked loop sets data_available = (l > 0) on
            // every write.  Our provider never writes 0 bytes (always at
            // least a 14-byte keepalive), so the loop runs indefinitely.
            res.set_chunked_content_provider(
                "text/event-stream",
                [sink_state](size_t offset, httplib::DataSink& sink) -> bool {
                    return detail::sse_content_provider(sink_state, offset, sink);
                },
                [sink_state, bus](bool success) {
                    detail::sse_resource_release(sink_state, *bus, success);
                });
        });

        // -- Agent listing API ------------------------------------------------

        web_server_->Get("/api/agents", [this](const httplib::Request& req,
                                               httplib::Response& res) {
            if (!require_permission(req, res, "Infrastructure", "Read"))
                return;
            auto session = require_auth(req, res);
            if (!session)
                return;
            res.set_content(get_visible_agents_json(session->username).dump(), "application/json");
        });

        // /fragments/scope-list — moved to DashboardRoutes (with groups support)

        web_server_->Get("/api/help", [this](const httplib::Request& req, httplib::Response& res) {
            if (!require_permission(req, res, "Infrastructure", "Read"))
                return;
            res.set_content(registry_.help_json(), "application/json");
        });

        // Help table HTML fragment (HTMX)
        web_server_->Get("/api/help/html",
                         [this](const httplib::Request& req, httplib::Response& res) {
                             if (!require_permission(req, res, "Infrastructure", "Read"))
                                 return;
                             std::string filter;
                             if (req.has_param("filter"))
                                 filter = req.get_param_value("filter");
                             res.set_content(registry_.help_html(filter), "text/html");
                         });

        // Autocomplete HTML fragment (HTMX)
        web_server_->Get("/api/help/autocomplete",
                         [this](const httplib::Request& req, httplib::Response& res) {
                             if (!require_permission(req, res, "Infrastructure", "Read"))
                                 return;
                             std::string q;
                             if (req.has_param("q"))
                                 q = req.get_param_value("q");
                             if (q.empty()) {
                                 res.set_content("", "text/html");
                                 return;
                             }
                             res.set_content(registry_.autocomplete_html(q), "text/html");
                         });

        // Command palette instruction search HTML fragment (HTMX)
        web_server_->Get("/api/help/palette",
                         [this](const httplib::Request& req, httplib::Response& res) {
                             if (!require_permission(req, res, "Infrastructure", "Read"))
                                 return;
                             std::string q;
                             if (req.has_param("q"))
                                 q = req.get_param_value("q");
                             if (q.empty()) {
                                 res.set_content("", "text/html");
                                 return;
                             }
                             res.set_content(registry_.palette_html(q), "text/html");
                         });

        // -- NVD CVE feed endpoints -------------------------------------------

        web_server_->Get("/api/nvd/status",
                         [this](const httplib::Request& req, httplib::Response& res) {
                             if (!require_permission(req, res, "Infrastructure", "Read"))
                                 return;
                             if (!nvd_db_ || !nvd_db_->is_open()) {
                                 res.set_content(R"({"enabled":false})", "application/json");
                                 return;
                             }
                             nlohmann::json j;
                             j["enabled"] = true;
                             j["total_cves"] = nvd_db_->total_cve_count();
                             if (nvd_sync_) {
                                 auto st = nvd_sync_->status();
                                 j["syncing"] = st.syncing;
                                 j["last_sync_time"] = st.last_sync_time;
                                 j["last_error"] = st.last_error;
                             }
                             res.set_content(j.dump(), "application/json");
                         });

        web_server_->Post("/api/nvd/sync", [this](const httplib::Request& req,
                                                  httplib::Response& res) {
            if (!require_permission(req, res, "Infrastructure", "Execute"))
                return;
            if (!nvd_sync_) {
                res.status = 503;
                res.set_content(
                    R"({"error":{"code":503,"message":"NVD sync not enabled"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }
            // Run sync in a detached thread so we don't block the HTTP response
            std::thread([this] { nvd_sync_->sync_now(); }).detach();
            res.set_content(R"({"status":"sync_started"})", "application/json");
        });

        web_server_->Post("/api/nvd/match", [this](const httplib::Request& req,
                                                   httplib::Response& res) {
            if (!require_permission(req, res, "Infrastructure", "Read"))
                return;
            if (!nvd_db_ || !nvd_db_->is_open()) {
                res.status = 503;
                res.set_content(
                    R"({"error":{"code":503,"message":"NVD database not available"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }
            // Parse inventory: array of {name, version} or pipe-delimited lines
            std::vector<SoftwareItem> inventory;
            try {
                auto body = nlohmann::json::parse(req.body);
                if (body.contains("inventory") && body["inventory"].is_array()) {
                    for (const auto& item : body["inventory"]) {
                        SoftwareItem si;
                        si.name = item.value("name", "");
                        si.version = item.value("version", "");
                        if (!si.name.empty())
                            inventory.push_back(std::move(si));
                    }
                }
            } catch (...) {
                res.status = 400;
                res.set_content(
                    R"({"error":{"code":400,"message":"invalid JSON body"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }

            auto matches = nvd_db_->match_inventory(inventory);
            nlohmann::json arr = nlohmann::json::array();
            for (const auto& m : matches) {
                arr.push_back({{"cve_id", m.cve_id},
                               {"severity", m.severity},
                               {"description", m.description},
                               {"product", m.product},
                               {"installed_version", m.installed_version},
                               {"fixed_in", m.fixed_in},
                               {"source", m.source}});
            }
            res.set_content(nlohmann::json({{"findings", arr}, {"count", arr.size()}}).dump(),
                            "application/json");
        });

        // -- Generic command dispatch API -------------------------------------

        web_server_->Post("/api/command", [this](const httplib::Request& req,
                                                 httplib::Response& res) {
            // Parse JSON body: { "plugin": "...", "action": "...", "agent_ids": [...] }
            auto plugin = extract_json_string(req.body, "plugin");
            auto action = extract_json_string(req.body, "action");
            auto agent_ids = extract_json_string_array(req.body, "agent_ids");

            if (plugin.empty() || action.empty()) {
                res.status = 400;
                res.set_content(
                    R"({"error":{"code":400,"message":"plugin and action are required"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }

            // All commands require Execution:Execute permission
            if (!require_permission(req, res, "Execution", "Execute"))
                return;

            if (!registry_.has_any()) {
                res.status = 503;
                res.set_content(
                    R"({"error":{"code":503,"message":"no agent connected"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }

            auto command_id =
                plugin + "-" + auth::AuthManager::bytes_to_hex(auth::AuthManager::random_bytes(8));

            detail::pb::CommandRequest cmd;
            cmd.set_command_id(command_id);
            cmd.set_plugin(plugin);
            cmd.set_action(action);

            // Parameters: pass-through key-value pairs to the agent plugin
            {
                auto params_map = extract_json_string_map(req.body, "params");
                for (const auto& [k, v] : params_map) {
                    (*cmd.mutable_parameters())[k] = v;
                }
            }

            // Stagger/delay: prevent thundering herd on large-fleet dispatch
            auto stagger = extract_json_int(req.body, "stagger", 0);
            auto delay = extract_json_int(req.body, "delay", 0);
            if (stagger > 0)
                cmd.set_stagger_seconds(stagger);
            if (delay > 0)
                cmd.set_delay_seconds(delay);

            agent_service_.record_send_time(command_id);

            // Check for scope-based targeting
            auto scope_expr = extract_json_string(req.body, "scope");

            int sent = 0;
            if (!scope_expr.empty() && scope_expr.starts_with("group:")) {
                // Group-based dispatch — resolve group members
                auto group_id = scope_expr.substr(6);
                if (mgmt_group_store_) {
                    auto members = mgmt_group_store_->get_members(group_id);
                    for (const auto& m : members) {
                        if (registry_.send_to(m.agent_id, cmd))
                            ++sent;
                    }
                }
            } else if (!scope_expr.empty()) {
                // Scope expression dispatch
                auto parsed = yuzu::scope::parse(scope_expr);
                if (!parsed) {
                    res.status = 400;
                    res.set_content(
                        nlohmann::json({{"error", "invalid scope: " + parsed.error()}}).dump(),
                        "application/json");
                    return;
                }
                auto matched_ids = registry_.evaluate_scope(*parsed, tag_store_.get(),
                                                            custom_properties_store_.get());
                for (const auto& aid : matched_ids) {
                    if (registry_.send_to(aid, cmd)) {
                        ++sent;
                    }
                }
            } else if (agent_ids.empty()) {
                // Broadcast to all agents
                sent = registry_.send_to_all(cmd);
            } else {
                for (const auto& aid : agent_ids) {
                    if (registry_.send_to(aid, cmd)) {
                        ++sent;
                    }
                }
            }

            // Forward commands queued for gateway agents
            forward_gateway_pending();

            if (sent == 0) {
                res.status = 503;
                res.set_content(
                    R"({"error":{"code":503,"message":"failed to send command to any agent"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }

            metrics_.counter("yuzu_commands_dispatched_total").increment();
            event_bus_.publish("command-status", "<span id=\"status-badge\" class=\"badge-running\""
                                                 " hx-swap-oob=\"outerHTML\">RUNNING</span>");
            spdlog::info("Command dispatched: {}:{} → {} agent(s)", plugin, action, sent);
            audit_log(req, "command.dispatch", "success", "command", command_id,
                      plugin + ":" + action + " → " + std::to_string(sent) + " agent(s)");
            emit_event("command.dispatched", req, {{"target_count", sent}},
                       {{"plugin", plugin},
                        {"action", action},
                        {"command_id", command_id},
                        {"scope", scope_expr}});
            res.set_header("HX-Trigger", "{\"showToast\":{\"message\":\"Command sent to " +
                                             std::to_string(sent) +
                                             " agent(s)\",\"level\":\"success\"}}");
            res.set_content(
                nlohmann::json({{"status", "sent"},
                                {"command_id", command_id},
                                {"agents_reached", sent},
                                {"thead_html", agent_service_.thead_for_plugin(plugin)}})
                    .dump(),
                "application/json");
        });

        // -- Legacy API endpoints (still functional, delegate to generic path) --

        web_server_->Post("/api/chargen/start",
                          [this](const httplib::Request& req, httplib::Response& res) {
                              if (!require_permission(req, res, "Execution", "Execute"))
                                  return;
                              forward_legacy_command("chargen", "chargen_start", res);
                          });

        web_server_->Post("/api/chargen/stop",
                          [this](const httplib::Request& req, httplib::Response& res) {
                              if (!require_permission(req, res, "Execution", "Execute"))
                                  return;
                              forward_legacy_command("chargen", "chargen_stop", res);
                          });

        web_server_->Post("/api/procfetch/fetch",
                          [this](const httplib::Request& req, httplib::Response& res) {
                              if (!require_permission(req, res, "Execution", "Execute"))
                                  return;
                              forward_legacy_command("procfetch", "procfetch_fetch", res);
                          });

        web_server_->Get(
            "/api/chargen/status", [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_permission(req, res, "Infrastructure", "Read"))
                    return;
                res.set_content(nlohmann::json({{"agent_connected", registry_.has_any()}}).dump(),
                                "application/json");
            });

        web_server_->Get(
            "/api/procfetch/status", [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_permission(req, res, "Infrastructure", "Read"))
                    return;
                res.set_content(nlohmann::json({{"agent_connected", registry_.has_any()}}).dump(),
                                "application/json");
            });

        // -- Response API ---------------------------------------------------------

        // Aggregate endpoint — must be registered before the catch-all responses route
        web_server_->Get(R"(/api/responses/([^/]+)/aggregate)", [this](const httplib::Request& req,
                                                                       httplib::Response& res) {
            if (!require_permission(req, res, "Response", "Read"))
                return;

            auto instruction_id = req.matches[1].str();
            if (!response_store_ || !response_store_->is_open()) {
                res.status = 503;
                res.set_content(
                    R"({"error":{"code":503,"message":"response store not available"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }

            auto group_by = req.get_param_value("group_by");
            if (group_by.empty())
                group_by = "status";

            AggregateOp op = AggregateOp::Count;
            auto op_str = req.get_param_value("op");
            if (op_str == "sum")
                op = AggregateOp::Sum;
            else if (op_str == "avg")
                op = AggregateOp::Avg;
            else if (op_str == "min")
                op = AggregateOp::Min;
            else if (op_str == "max")
                op = AggregateOp::Max;

            AggregationQuery aq;
            aq.group_by = group_by;
            aq.op = op;
            aq.op_column = req.get_param_value("op_column");

            ResponseQuery filter;
            if (req.has_param("agent_id"))
                filter.agent_id = req.get_param_value("agent_id");
            try {
                if (req.has_param("status"))
                    filter.status = std::stoi(req.get_param_value("status"));
                if (req.has_param("since"))
                    filter.since = std::stoll(req.get_param_value("since"));
                if (req.has_param("until"))
                    filter.until = std::stoll(req.get_param_value("until"));
            } catch (const std::exception&) {
                res.status = 400;
                res.set_content(
                    R"({"error":{"code":400,"message":"invalid numeric query parameter"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }

            auto results = response_store_->aggregate(instruction_id, aq, filter);

            int64_t total_rows = 0;
            nlohmann::json groups = nlohmann::json::array();
            for (const auto& r : results) {
                total_rows += r.count;
                groups.push_back({{"group_value", r.group_value},
                                  {"count", r.count},
                                  {"aggregate_value", r.aggregate_value}});
            }

            res.set_content(nlohmann::json({{"instruction_id", instruction_id},
                                            {"groups", groups},
                                            {"total_groups", results.size()},
                                            {"total_rows", total_rows}})
                                .dump(),
                            "application/json");
        });

        // Export endpoint — must be registered before the catch-all responses route
        web_server_->Get(R"(/api/responses/([^/]+)/export)", [this](const httplib::Request& req,
                                                                    httplib::Response& res) {
            if (!require_permission(req, res, "Response", "Read"))
                return;

            auto instruction_id = req.matches[1].str();
            if (!response_store_ || !response_store_->is_open()) {
                res.status = 503;
                res.set_content(
                    R"({"error":{"code":503,"message":"response store not available"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }

            ResponseQuery q;
            if (req.has_param("agent_id"))
                q.agent_id = req.get_param_value("agent_id");
            try {
                if (req.has_param("status"))
                    q.status = std::stoi(req.get_param_value("status"));
                if (req.has_param("since"))
                    q.since = std::stoll(req.get_param_value("since"));
                if (req.has_param("until"))
                    q.until = std::stoll(req.get_param_value("until"));
                if (req.has_param("limit"))
                    q.limit = std::stoi(req.get_param_value("limit"));
                else
                    q.limit = 10000; // higher default for exports
            } catch (const std::exception&) {
                res.status = 400;
                res.set_content(
                    R"({"error":{"code":400,"message":"invalid numeric query parameter"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }

            auto results = response_store_->query(instruction_id, q);
            auto format = req.get_param_value("format");

            if (format == "csv") {
                std::string csv =
                    "id,instruction_id,agent_id,timestamp,status,output,error_detail\r\n";
                for (const auto& r : results) {
                    csv += std::to_string(r.id) + ",";
                    csv += data_export::csv_escape(r.instruction_id) + ",";
                    csv += data_export::csv_escape(r.agent_id) + ",";
                    csv += std::to_string(r.timestamp) + ",";
                    csv += std::to_string(r.status) + ",";
                    csv += data_export::csv_escape(r.output) + ",";
                    csv += data_export::csv_escape(r.error_detail) + "\r\n";
                }
                res.set_header("Content-Disposition",
                               "attachment; filename=\"responses-" + instruction_id + ".csv\"");
                res.set_content(csv, "text/csv; charset=utf-8");
            } else {
                nlohmann::json arr = nlohmann::json::array();
                for (const auto& r : results) {
                    arr.push_back({{"id", r.id},
                                   {"instruction_id", r.instruction_id},
                                   {"agent_id", r.agent_id},
                                   {"timestamp", r.timestamp},
                                   {"status", r.status},
                                   {"output", r.output},
                                   {"error_detail", r.error_detail}});
                }
                nlohmann::json envelope = {{"instruction_id", instruction_id},
                                           {"count", results.size()},
                                           {"responses", arr}};
                res.set_header("Content-Disposition",
                               "attachment; filename=\"responses-" + instruction_id + ".json\"");
                res.set_content(envelope.dump(2), "application/json; charset=utf-8");
            }
        });

        web_server_->Get(R"(/api/responses/(.+))", [this](const httplib::Request& req,
                                                          httplib::Response& res) {
            if (!require_permission(req, res, "Response", "Read"))
                return;

            auto instruction_id = req.matches[1].str();
            if (instruction_id.empty()) {
                res.status = 400;
                res.set_content(
                    R"({"error":{"code":400,"message":"instruction_id required"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }

            if (!response_store_ || !response_store_->is_open()) {
                res.status = 503;
                res.set_content(
                    R"({"error":{"code":503,"message":"response store not available"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }

            ResponseQuery q;
            if (req.has_param("agent_id"))
                q.agent_id = req.get_param_value("agent_id");
            try {
                if (req.has_param("status"))
                    q.status = std::stoi(req.get_param_value("status"));
                if (req.has_param("since"))
                    q.since = std::stoll(req.get_param_value("since"));
                if (req.has_param("until"))
                    q.until = std::stoll(req.get_param_value("until"));
                if (req.has_param("limit"))
                    q.limit = std::stoi(req.get_param_value("limit"));
                if (req.has_param("offset"))
                    q.offset = std::stoi(req.get_param_value("offset"));
            } catch (const std::exception&) {
                res.status = 400;
                res.set_content(
                    R"({"error":{"code":400,"message":"invalid numeric query parameter"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }

            auto results = response_store_->query(instruction_id, q);

            nlohmann::json arr = nlohmann::json::array();
            for (const auto& r : results) {
                arr.push_back({{"id", r.id},
                               {"instruction_id", r.instruction_id},
                               {"agent_id", r.agent_id},
                               {"timestamp", r.timestamp},
                               {"status", r.status},
                               {"output", r.output},
                               {"error_detail", r.error_detail}});
            }
            res.set_content(nlohmann::json({{"responses", arr}, {"count", arr.size()}}).dump(),
                            "application/json");
        });

        // -- Audit API -----------------------------------------------------------
        web_server_->Get("/api/audit", [this](const httplib::Request& req, httplib::Response& res) {
            if (!require_permission(req, res, "AuditLog", "Read"))
                return;

            if (!audit_store_ || !audit_store_->is_open()) {
                res.status = 503;
                res.set_content(
                    R"({"error":{"code":503,"message":"audit store not available"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }

            AuditQuery q;
            if (req.has_param("principal"))
                q.principal = req.get_param_value("principal");
            if (req.has_param("action"))
                q.action = req.get_param_value("action");
            if (req.has_param("target_type"))
                q.target_type = req.get_param_value("target_type");
            if (req.has_param("target_id"))
                q.target_id = req.get_param_value("target_id");
            try {
                if (req.has_param("since"))
                    q.since = std::stoll(req.get_param_value("since"));
                if (req.has_param("until"))
                    q.until = std::stoll(req.get_param_value("until"));
                if (req.has_param("limit"))
                    q.limit = std::stoi(req.get_param_value("limit"));
                if (req.has_param("offset"))
                    q.offset = std::stoi(req.get_param_value("offset"));
            } catch (const std::exception&) {
                res.status = 400;
                res.set_content(
                    R"({"error":{"code":400,"message":"invalid numeric query parameter"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }

            auto results = audit_store_->query(q);

            nlohmann::json arr = nlohmann::json::array();
            for (const auto& e : results) {
                arr.push_back({{"id", e.id},
                               {"timestamp", e.timestamp},
                               {"principal", e.principal},
                               {"principal_role", e.principal_role},
                               {"action", e.action},
                               {"target_type", e.target_type},
                               {"target_id", e.target_id},
                               {"detail", e.detail},
                               {"source_ip", e.source_ip},
                               {"result", e.result}});
            }
            res.set_content(nlohmann::json({{"events", arr},
                                            {"count", arr.size()},
                                            {"total", audit_store_->total_count()}})
                                .dump(),
                            "application/json");
        });

        // -- Tags API ---------------------------------------------------------
        web_server_->Get("/api/tags", [this](const httplib::Request& req, httplib::Response& res) {
            if (!require_permission(req, res, "Tag", "Read"))
                return;

            if (!tag_store_ || !tag_store_->is_open()) {
                res.status = 503;
                res.set_content(
                    R"({"error":{"code":503,"message":"tag store not available"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }

            auto agent_id = req.get_param_value("agent_id");
            if (agent_id.empty()) {
                res.status = 400;
                res.set_content(
                    R"({"error":{"code":400,"message":"agent_id parameter required"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }

            auto tags = tag_store_->get_all_tags(agent_id);
            nlohmann::json arr = nlohmann::json::array();
            for (const auto& t : tags) {
                arr.push_back({{"key", t.key},
                               {"value", t.value},
                               {"source", t.source},
                               {"updated_at", t.updated_at}});
            }
            res.set_content(nlohmann::json({{"agent_id", agent_id}, {"tags", arr}}).dump(),
                            "application/json");
        });

        web_server_->Post("/api/tags/set", [this](const httplib::Request& req,
                                                  httplib::Response& res) {
            if (!require_permission(req, res, "Tag", "Write"))
                return;
            if (!tag_store_) {
                res.status = 503;
                res.set_content(
                    R"({"error":{"code":503,"message":"tag store not available"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }

            auto agent_id = extract_json_string(req.body, "agent_id");
            auto key = extract_json_string(req.body, "key");
            auto value = extract_json_string(req.body, "value");

            if (agent_id.empty() || key.empty()) {
                res.status = 400;
                res.set_content(
                    R"({"error":{"code":400,"message":"agent_id and key required"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }

            if (!TagStore::validate_key(key)) {
                res.status = 400;
                res.set_content(
                    R"({"error":{"code":400,"message":"invalid tag key"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }

            tag_store_->set_tag(agent_id, key, value, "api");
            if (key == "service")
                ensure_service_management_group(value);
            // Push updated tags to agent if a structured category changed
            // Case-insensitive: API may receive "Role" but kCategoryKeys are lowercase
            {
                std::string lower_key = key;
                std::transform(lower_key.begin(), lower_key.end(), lower_key.begin(),
                               [](unsigned char c) { return std::tolower(c); });
                for (auto cat_key : kCategoryKeys) {
                    if (cat_key == lower_key) {
                        push_asset_tags_to_agent(agent_id);
                        break;
                    }
                }
            }
            audit_log(req, "tag.set", "success", "tag", agent_id + ":" + key, value);
            res.set_header("HX-Trigger",
                           R"({"showToast":{"message":"Tag updated","level":"success"}})");
            res.set_content(R"({"status":"ok"})", "application/json");
        });

        web_server_->Post("/api/tags/delete", [this](const httplib::Request& req,
                                                     httplib::Response& res) {
            if (!require_permission(req, res, "Tag", "Delete"))
                return;
            if (!tag_store_) {
                res.status = 503;
                res.set_content(
                    R"({"error":{"code":503,"message":"tag store not available"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }

            auto agent_id = extract_json_string(req.body, "agent_id");
            auto key = extract_json_string(req.body, "key");

            if (agent_id.empty() || key.empty()) {
                res.status = 400;
                res.set_content(
                    R"({"error":{"code":400,"message":"agent_id and key required"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }

            bool deleted = tag_store_->delete_tag(agent_id, key);
            audit_log(req, "tag.delete", deleted ? "success" : "not_found", "tag",
                      agent_id + ":" + key);
            if (deleted) {
                res.set_header("HX-Trigger",
                               R"({"showToast":{"message":"Tag deleted","level":"success"}})");
            }
            res.set_content(nlohmann::json({{"deleted", deleted}}).dump(), "application/json");
        });

        web_server_->Post("/api/tags/query", [this](const httplib::Request& req,
                                                    httplib::Response& res) {
            if (!require_permission(req, res, "Tag", "Read"))
                return;
            if (!tag_store_) {
                res.status = 503;
                res.set_content(
                    R"({"error":{"code":503,"message":"tag store not available"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }

            auto key = extract_json_string(req.body, "key");
            auto value = extract_json_string(req.body, "value");

            if (key.empty()) {
                res.status = 400;
                res.set_content(
                    R"({"error":{"code":400,"message":"key required"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }

            auto agents = tag_store_->agents_with_tag(key, value);
            nlohmann::json arr = nlohmann::json::array();
            for (const auto& a : agents)
                arr.push_back(a);
            res.set_content(nlohmann::json({{"agents", arr}, {"count", arr.size()}}).dump(),
                            "application/json");
        });

        // -- Help page --------------------------------------------------------
        web_server_->Get("/help", [](const httplib::Request&, httplib::Response& res) {
            res.set_content(kHelpHtml, "text/html; charset=utf-8");
        });

        // -- TAR dashboard page (Phase 15.A — issue #547) --------------------
        // Auth required because the page makes HTMX calls to retention-paused
        // and (later) SQL fragment endpoints that themselves require auth +
        // RBAC; loading the page unauthenticated would just produce a blank
        // shell that immediately redirects on first fragment request. Mirror
        // the /instructions pattern.
        web_server_->Get("/tar", [this](const httplib::Request& req, httplib::Response& res) {
            auto session = require_auth(req, res);
            if (!session) {
                res.set_redirect("/login");
                return;
            }
            res.set_content(kTarPageHtml, "text/html; charset=utf-8");
        });

        // -- Instruction management page --------------------------------------
        web_server_->Get("/instructions",
                         [this](const httplib::Request& req, httplib::Response& res) {
                             auto session = require_auth(req, res);
                             if (!session) {
                                 res.set_redirect("/login");
                                 return;
                             }
                             res.set_content(kInstructionPageHtml, "text/html; charset=utf-8");
                         });

        // -- Generic JSON-to-CSV export -----------------------------------------
        web_server_->Post("/api/export/json-to-csv", [this](const httplib::Request& req,
                                                            httplib::Response& res) {
            if (!require_permission(req, res, "Response", "Read"))
                return;

            auto csv = data_export::json_array_to_csv(req.body);
            if (csv.empty()) {
                res.status = 400;
                res.set_content(
                    R"({"error":{"code":400,"message":"invalid JSON array"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }
            res.set_header("Content-Disposition", "attachment; filename=\"export.csv\"");
            res.set_content(csv, "text/csv; charset=utf-8");
        });

        // -- Instruction Definitions API --------------------------------------

        web_server_->Get("/api/instructions", [this](const httplib::Request& req,
                                                     httplib::Response& res) {
            if (!require_permission(req, res, "InstructionDefinition", "Read"))
                return;
            if (!instruction_store_ || !instruction_store_->is_open()) {
                res.status = 503;
                res.set_content(
                    R"({"error":{"code":503,"message":"instruction store not available"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }

            InstructionQuery q;
            if (req.has_param("name"))
                q.name_filter = req.get_param_value("name");
            if (req.has_param("plugin"))
                q.plugin_filter = req.get_param_value("plugin");
            if (req.has_param("type"))
                q.type_filter = req.get_param_value("type");
            if (req.has_param("set_id"))
                q.set_id_filter = req.get_param_value("set_id");
            if (req.has_param("enabled_only"))
                q.enabled_only = true;
            try {
                if (req.has_param("limit"))
                    q.limit = std::stoi(req.get_param_value("limit"));
            } catch (const std::exception&) {
                res.status = 400;
                res.set_content(
                    R"({"error":{"code":400,"message":"invalid numeric query parameter"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }

            auto defs = instruction_store_->query_definitions(q);
            nlohmann::json arr = nlohmann::json::array();
            for (const auto& d : defs) {
                arr.push_back({{"id", d.id},
                               {"name", d.name},
                               {"version", d.version},
                               {"type", d.type},
                               {"plugin", d.plugin},
                               {"action", d.action},
                               {"description", d.description},
                               {"enabled", d.enabled},
                               {"instruction_set_id", d.instruction_set_id},
                               {"created_at", d.created_at},
                               {"updated_at", d.updated_at}});
            }
            res.set_content(nlohmann::json({{"definitions", arr}, {"count", arr.size()}}).dump(),
                            "application/json");
        });

        web_server_->Post("/api/instructions", [this](const httplib::Request& req,
                                                      httplib::Response& res) {
            if (!require_permission(req, res, "InstructionDefinition", "Write"))
                return;
            if (!instruction_store_) {
                res.status = 503;
                res.set_content(
                    R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }

            try {
                auto j = nlohmann::json::parse(req.body);
                InstructionDefinition def;
                // #402 / iter-H1: honor caller-supplied `id` so the
                // duplicate-id guard in create_definition_impl actually
                // fires from this endpoint. Prior code dropped the id on
                // the floor, leaving #402's protection store-only.
                def.id = j.value("id", "");
                def.name = j.value("name", "");
                def.version = j.value("version", "1.0");
                def.type = j.value("type", "");
                def.plugin = j.value("plugin", "");
                def.action = j.value("action", "");
                // Normalize action to lowercase — agent plugins match case-sensitively
                for (auto& c : def.action)
                    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                def.description = j.value("description", "");
                def.enabled = j.value("enabled", true);
                def.instruction_set_id = j.value("instruction_set_id", "");
                def.gather_ttl_seconds = j.value("gather_ttl_seconds", 300);
                def.response_ttl_days = j.value("response_ttl_days", 90);
                def.approval_mode = j.value("approval_mode", "auto");
                // Validate approval_mode
                if (def.approval_mode != "auto" && def.approval_mode != "role-gated" &&
                    def.approval_mode != "always") {
                    res.status = 400;
                    res.set_content(
                        nlohmann::json({{"error", "invalid approval_mode: " + def.approval_mode +
                                                      " (must be auto, role-gated, or always)"}})
                            .dump(),
                        "application/json");
                    return;
                }

                if (auto session = auth_routes_->resolve_session(req))
                    def.created_by = session->username;

                auto result = instruction_store_->create_definition(def);
                if (!result) {
                    // #402: store-level kConflictPrefix maps to HTTP 409. The
                    // prefix is an internal store↔route contract — strip it
                    // before placing the message in the operator-facing JSON
                    // body (governance enterprise-N1). Emit a denied audit
                    // event so duplicate-id probing leaves a trace
                    // (governance compliance-1, up-18).
                    bool is_conflict = is_conflict_error(result.error());
                    res.status = is_conflict ? 409 : 400;
                    if (is_conflict) {
                        audit_log(req, "instruction.create", "denied", "instruction", def.id,
                                  "duplicate_id");
                    }
                    auto body_msg = is_conflict ? std::string(strip_conflict_prefix(result.error()))
                                                : result.error();
                    res.set_content(nlohmann::json({{"error", body_msg}}).dump(),
                                    "application/json");
                    return;
                }
                audit_log(req, "instruction.create", "success", "instruction", *result, def.name);
                emit_event("instruction.created", req,
                           {{"name", def.name},
                            {"plugin", def.plugin},
                            {"action", def.action},
                            {"type", def.type}},
                           {{"instruction_id", *result}});
                res.set_header(
                    "HX-Trigger",
                    R"({"showToast":{"message":"Instruction definition created","level":"success"}})");
                res.set_content(nlohmann::json({{"id", *result}}).dump(), "application/json");
            } catch (const std::exception& e) {
                res.status = 400;
                res.set_content(nlohmann::json({{"error", e.what()}}).dump(), "application/json");
            }
        });

        web_server_->Get(R"(/api/instructions/([^/]+))", [this](const httplib::Request& req,
                                                                httplib::Response& res) {
            if (!require_permission(req, res, "InstructionDefinition", "Read"))
                return;
            if (!instruction_store_) {
                res.status = 503;
                res.set_content(
                    R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }

            auto id = req.matches[1].str();
            auto def = instruction_store_->get_definition(id);
            if (!def) {
                res.status = 404;
                res.set_content(
                    R"({"error":{"code":404,"message":"not found"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }

            res.set_content(nlohmann::json({{"id", def->id},
                                            {"name", def->name},
                                            {"version", def->version},
                                            {"type", def->type},
                                            {"plugin", def->plugin},
                                            {"action", def->action},
                                            {"description", def->description},
                                            {"enabled", def->enabled},
                                            {"instruction_set_id", def->instruction_set_id},
                                            {"gather_ttl_seconds", def->gather_ttl_seconds},
                                            {"response_ttl_days", def->response_ttl_days},
                                            {"created_by", def->created_by},
                                            {"created_at", def->created_at},
                                            {"updated_at", def->updated_at}})
                                .dump(),
                            "application/json");
        });

        web_server_->Put(R"(/api/instructions/([^/]+))", [this](const httplib::Request& req,
                                                                httplib::Response& res) {
            if (!require_permission(req, res, "InstructionDefinition", "Write"))
                return;
            if (!instruction_store_) {
                res.status = 503;
                res.set_content(
                    R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }

            auto id = req.matches[1].str();
            try {
                auto j = nlohmann::json::parse(req.body);

                // Read existing definition to preserve fields not in the update
                auto existing = instruction_store_->get_definition(id);
                if (!existing) {
                    res.status = 404;
                    res.set_content(
                        R"({"error":{"code":404,"message":"instruction definition not found"},"meta":{"api_version":"v1"}})",
                        "application/json");
                    return;
                }

                InstructionDefinition def = *existing;
                if (j.contains("name"))
                    def.name = j["name"].get<std::string>();
                if (j.contains("version"))
                    def.version = j["version"].get<std::string>();
                if (j.contains("type"))
                    def.type = j["type"].get<std::string>();
                if (j.contains("plugin"))
                    def.plugin = j["plugin"].get<std::string>();
                if (j.contains("action")) {
                    def.action = j["action"].get<std::string>();
                    // Normalize action to lowercase
                    for (auto& c : def.action)
                        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                }
                if (j.contains("description"))
                    def.description = j["description"].get<std::string>();
                if (j.contains("enabled"))
                    def.enabled = j["enabled"].get<bool>();
                if (j.contains("instruction_set_id"))
                    def.instruction_set_id = j["instruction_set_id"].get<std::string>();
                if (j.contains("approval_mode")) {
                    def.approval_mode = j["approval_mode"].get<std::string>();
                    if (def.approval_mode != "auto" && def.approval_mode != "role-gated" &&
                        def.approval_mode != "always") {
                        res.status = 400;
                        res.set_content(
                            nlohmann::json(
                                {{"error", "invalid approval_mode: " + def.approval_mode +
                                               " (must be auto, role-gated, or always)"}})
                                .dump(),
                            "application/json");
                        return;
                    }
                }

                auto result = instruction_store_->update_definition(def);
                if (!result) {
                    res.status = 400;
                    res.set_content(nlohmann::json({{"error", result.error()}}).dump(),
                                    "application/json");
                    return;
                }
                audit_log(req, "instruction.update", "success", "instruction", id);
                emit_event("instruction.updated", req, {}, {{"instruction_id", id}});
                res.set_header(
                    "HX-Trigger",
                    R"({"showToast":{"message":"Instruction definition updated","level":"success"}})");
                res.set_content(R"({"status":"ok"})", "application/json");
            } catch (const std::exception& e) {
                res.status = 400;
                res.set_content(nlohmann::json({{"error", e.what()}}).dump(), "application/json");
            }
        });

        web_server_->Delete(R"(/api/instructions/([^/]+))", [this](const httplib::Request& req,
                                                                   httplib::Response& res) {
            if (!require_permission(req, res, "InstructionDefinition", "Delete"))
                return;
            if (!instruction_store_) {
                res.status = 503;
                res.set_content(
                    R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }

            auto id = req.matches[1].str();
            bool deleted = instruction_store_->delete_definition(id);
            if (deleted) {
                audit_log(req, "instruction.delete", "success", "instruction", id);
                emit_event("instruction.deleted", req, {}, {{"instruction_id", id}});
                res.set_header(
                    "HX-Trigger",
                    R"({"showToast":{"message":"Instruction definition deleted","level":"success"}})");
            }
            res.set_content(nlohmann::json({{"deleted", deleted}}).dump(), "application/json");
        });

        web_server_->Get(R"(/api/instructions/([^/]+)/export)", [this](const httplib::Request& req,
                                                                       httplib::Response& res) {
            if (!require_permission(req, res, "InstructionDefinition", "Read"))
                return;
            if (!instruction_store_) {
                res.status = 503;
                res.set_content(
                    R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }

            auto id = req.matches[1].str();
            auto json = instruction_store_->export_definition_json(id);
            res.set_content(json, "application/json");
        });

        web_server_->Post("/api/instructions/import", [this](const httplib::Request& req,
                                                             httplib::Response& res) {
            if (!require_permission(req, res, "InstructionDefinition", "Write"))
                return;
            if (!instruction_store_) {
                res.status = 503;
                res.set_content(
                    R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }

            auto result = instruction_store_->import_definition_json(req.body);
            if (!result) {
                // iter-H2: /import shares the create_definition_impl path,
                // so it inherits the kConflictPrefix → 409 mapping that the
                // POST handler does. Without this mapping the import path
                // returns 400 with the raw "conflict:" prefix in the body
                // — defeats the prefix-stripping contract on the very
                // endpoint that exercises duplicate-id rejection most.
                bool is_conflict = is_conflict_error(result.error());
                res.status = is_conflict ? 409 : 400;
                if (is_conflict) {
                    audit_log(req, "instruction.import", "denied", "instruction", "",
                              "duplicate_id");
                }
                auto body_msg = is_conflict ? std::string(strip_conflict_prefix(result.error()))
                                            : result.error();
                res.set_content(nlohmann::json({{"error", body_msg}}).dump(), "application/json");
                return;
            }
            audit_log(req, "instruction.import", "success", "instruction", *result);
            res.set_header("HX-Trigger",
                           R"({"showToast":{"message":"Definitions imported","level":"success"}})");
            res.set_content(nlohmann::json({{"id", *result}}).dump(), "application/json");
        });

        // -- Instruction Sets API ---------------------------------------------

        web_server_->Get("/api/instruction-sets", [this](const httplib::Request& req,
                                                         httplib::Response& res) {
            if (!require_permission(req, res, "InstructionSet", "Read"))
                return;
            if (!instruction_store_) {
                res.status = 503;
                res.set_content(
                    R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }

            auto sets = instruction_store_->list_sets();
            nlohmann::json arr = nlohmann::json::array();
            for (const auto& s : sets) {
                arr.push_back({{"id", s.id},
                               {"name", s.name},
                               {"description", s.description},
                               {"created_by", s.created_by},
                               {"created_at", s.created_at}});
            }
            res.set_content(nlohmann::json({{"sets", arr}}).dump(), "application/json");
        });

        web_server_->Post("/api/instruction-sets", [this](const httplib::Request& req,
                                                          httplib::Response& res) {
            if (!require_permission(req, res, "InstructionSet", "Write"))
                return;
            if (!instruction_store_) {
                res.status = 503;
                res.set_content(
                    R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }

            auto name = extract_json_string(req.body, "name");
            auto desc = extract_json_string(req.body, "description");
            InstructionSet s;
            s.name = name;
            s.description = desc;
            auto result = instruction_store_->create_set(s);
            if (!result) {
                res.status = 400;
                res.set_content(nlohmann::json({{"error", result.error()}}).dump(),
                                "application/json");
                return;
            }
            res.set_content(nlohmann::json({{"id", *result}}).dump(), "application/json");
        });

        web_server_->Delete(R"(/api/instruction-sets/([^/]+))", [this](const httplib::Request& req,
                                                                       httplib::Response& res) {
            if (!require_permission(req, res, "InstructionSet", "Delete"))
                return;
            if (!instruction_store_) {
                res.status = 503;
                res.set_content(
                    R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }

            auto id = req.matches[1].str();
            bool deleted = instruction_store_->delete_set(id);
            res.set_content(nlohmann::json({{"deleted", deleted}}).dump(), "application/json");
        });

        // -- Execution API ----------------------------------------------------

        web_server_->Get("/api/executions", [this](const httplib::Request& req,
                                                   httplib::Response& res) {
            if (!require_permission(req, res, "Execution", "Read"))
                return;
            if (!execution_tracker_) {
                res.status = 503;
                res.set_content(
                    R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }

            ExecutionQuery q;
            if (req.has_param("definition_id"))
                q.definition_id = req.get_param_value("definition_id");
            if (req.has_param("status"))
                q.status = req.get_param_value("status");
            try {
                if (req.has_param("limit"))
                    q.limit = std::stoi(req.get_param_value("limit"));
            } catch (const std::exception&) {
                res.status = 400;
                res.set_content(
                    R"({"error":{"code":400,"message":"invalid numeric query parameter"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }

            auto execs = execution_tracker_->query_executions(q);
            nlohmann::json arr = nlohmann::json::array();
            for (const auto& e : execs) {
                arr.push_back({{"id", e.id},
                               {"definition_id", e.definition_id},
                               {"status", e.status},
                               {"dispatched_by", e.dispatched_by},
                               {"dispatched_at", e.dispatched_at},
                               {"agents_targeted", e.agents_targeted},
                               {"agents_responded", e.agents_responded},
                               {"agents_success", e.agents_success},
                               {"agents_failure", e.agents_failure},
                               {"completed_at", e.completed_at},
                               {"rerun_of", e.rerun_of}});
            }
            res.set_content(nlohmann::json({{"executions", arr}, {"count", arr.size()}}).dump(),
                            "application/json");
        });

        web_server_->Get(R"(/api/executions/([^/]+))", [this](const httplib::Request& req,
                                                              httplib::Response& res) {
            if (!require_permission(req, res, "Execution", "Read"))
                return;
            if (!execution_tracker_) {
                res.status = 503;
                res.set_content(
                    R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }

            auto id = req.matches[1].str();
            auto exec = execution_tracker_->get_execution(id);
            if (!exec) {
                res.status = 404;
                res.set_content(
                    R"({"error":{"code":404,"message":"not found"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }

            res.set_content(nlohmann::json({{"id", exec->id},
                                            {"definition_id", exec->definition_id},
                                            {"status", exec->status},
                                            {"scope_expression", exec->scope_expression},
                                            {"parameter_values", exec->parameter_values},
                                            {"dispatched_by", exec->dispatched_by},
                                            {"dispatched_at", exec->dispatched_at},
                                            {"agents_targeted", exec->agents_targeted},
                                            {"agents_responded", exec->agents_responded},
                                            {"agents_success", exec->agents_success},
                                            {"agents_failure", exec->agents_failure},
                                            {"completed_at", exec->completed_at},
                                            {"parent_id", exec->parent_id},
                                            {"rerun_of", exec->rerun_of}})
                                .dump(),
                            "application/json");
        });

        web_server_->Get(R"(/api/executions/([^/]+)/summary)", [this](const httplib::Request& req,
                                                                      httplib::Response& res) {
            if (!require_permission(req, res, "Execution", "Read"))
                return;
            if (!execution_tracker_) {
                res.status = 503;
                res.set_content(
                    R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }

            auto id = req.matches[1].str();
            auto summary = execution_tracker_->get_summary(id);
            res.set_content(nlohmann::json({{"id", summary.id},
                                            {"status", summary.status},
                                            {"agents_targeted", summary.agents_targeted},
                                            {"agents_responded", summary.agents_responded},
                                            {"agents_success", summary.agents_success},
                                            {"agents_failure", summary.agents_failure},
                                            {"progress_pct", summary.progress_pct}})
                                .dump(),
                            "application/json");
        });

        web_server_->Get(R"(/api/executions/([^/]+)/agents)", [this](const httplib::Request& req,
                                                                     httplib::Response& res) {
            if (!require_permission(req, res, "Execution", "Read"))
                return;
            if (!execution_tracker_) {
                res.status = 503;
                res.set_content(
                    R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }

            auto id = req.matches[1].str();
            auto agents = execution_tracker_->get_agent_statuses(id);
            nlohmann::json arr = nlohmann::json::array();
            for (const auto& a : agents) {
                arr.push_back({{"agent_id", a.agent_id},
                               {"status", a.status},
                               {"dispatched_at", a.dispatched_at},
                               {"first_response_at", a.first_response_at},
                               {"completed_at", a.completed_at},
                               {"exit_code", a.exit_code},
                               {"error_detail", a.error_detail}});
            }
            res.set_content(nlohmann::json({{"agents", arr}}).dump(), "application/json");
        });

        web_server_->Post(R"(/api/executions/([^/]+)/rerun)", [this](const httplib::Request& req,
                                                                     httplib::Response& res) {
            if (!require_permission(req, res, "Execution", "Execute"))
                return;
            if (!execution_tracker_) {
                res.status = 503;
                res.set_content(
                    R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }

            auto id = req.matches[1].str();
            auto scope_filter = extract_json_string(req.body, "scope");
            bool failed_only = (scope_filter == "failed_only");

            auto session = auth_routes_->resolve_session(req);
            auto user = session ? session->username : "unknown";

            auto result = execution_tracker_->create_rerun(id, user, failed_only);
            if (!result) {
                res.status = 400;
                res.set_content(nlohmann::json({{"error", result.error()}}).dump(),
                                "application/json");
                return;
            }
            audit_log(req, "execution.rerun", "success", "execution", *result, "rerun of " + id);
            emit_event("execution.created", req, {},
                       {{"execution_id", *result}, {"parent_id", id}, {"trigger", "rerun"}});
            res.set_header(
                "HX-Trigger",
                R"({"showToast":{"message":"Execution rerun initiated","level":"success"}})");
            res.set_content(nlohmann::json({{"id", *result}}).dump(), "application/json");
        });

        web_server_->Post(R"(/api/executions/([^/]+)/cancel)", [this](const httplib::Request& req,
                                                                      httplib::Response& res) {
            if (!require_permission(req, res, "Execution", "Execute"))
                return;
            if (!execution_tracker_) {
                res.status = 503;
                res.set_content(
                    R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }

            auto id = req.matches[1].str();
            auto session = auth_routes_->resolve_session(req);
            auto user = session ? session->username : "unknown";

            execution_tracker_->mark_cancelled(id, user);
            audit_log(req, "execution.cancel", "success", "execution", id);
            emit_event("execution.completed", req, {{"status", "cancelled"}},
                       {{"execution_id", id}});
            res.set_header("HX-Trigger",
                           R"({"showToast":{"message":"Execution cancelled","level":"success"}})");
            res.set_content(R"({"status":"cancelled"})", "application/json");
        });

        web_server_->Get(R"(/api/executions/([^/]+)/children)", [this](const httplib::Request& req,
                                                                       httplib::Response& res) {
            if (!require_permission(req, res, "Execution", "Read"))
                return;
            if (!execution_tracker_) {
                res.status = 503;
                res.set_content(
                    R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }

            auto id = req.matches[1].str();
            auto children = execution_tracker_->get_children(id);
            nlohmann::json arr = nlohmann::json::array();
            for (const auto& c : children) {
                arr.push_back(
                    {{"id", c.id}, {"status", c.status}, {"dispatched_at", c.dispatched_at}});
            }
            res.set_content(nlohmann::json({{"children", arr}}).dump(), "application/json");
        });

        // -- Schedule API -----------------------------------------------------

        web_server_->Get("/api/schedules", [this](const httplib::Request& req,
                                                  httplib::Response& res) {
            if (!require_permission(req, res, "Schedule", "Read"))
                return;
            if (!schedule_engine_) {
                res.status = 503;
                res.set_content(
                    R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }

            ScheduleQuery q;
            if (req.has_param("definition_id"))
                q.definition_id = req.get_param_value("definition_id");
            if (req.has_param("enabled_only"))
                q.enabled_only = true;

            auto scheds = schedule_engine_->query_schedules(q);
            nlohmann::json arr = nlohmann::json::array();
            for (const auto& s : scheds) {
                arr.push_back({{"id", s.id},
                               {"name", s.name},
                               {"definition_id", s.definition_id},
                               {"enabled", s.enabled},
                               {"frequency_type", s.frequency_type},
                               {"next_execution_at", s.next_execution_at},
                               {"last_executed_at", s.last_executed_at},
                               {"execution_count", s.execution_count}});
            }
            res.set_content(nlohmann::json({{"schedules", arr}}).dump(), "application/json");
        });

        web_server_->Post("/api/schedules", [this](const httplib::Request& req,
                                                   httplib::Response& res) {
            if (!require_permission(req, res, "Schedule", "Write"))
                return;
            if (!schedule_engine_) {
                res.status = 503;
                res.set_content(
                    R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }

            try {
                auto j = nlohmann::json::parse(req.body);
                InstructionSchedule sched;
                sched.name = j.value("name", "");
                sched.definition_id = j.value("definition_id", "");
                sched.frequency_type = j.value("frequency_type", "once");
                sched.interval_minutes = j.value("interval_minutes", 60);
                sched.time_of_day = j.value("time_of_day", "00:00");
                sched.day_of_week = j.value("day_of_week", 0);
                sched.day_of_month = j.value("day_of_month", 1);
                sched.scope_expression = j.value("scope_expression", "");
                sched.requires_approval = j.value("requires_approval", false);

                if (auto session = auth_routes_->resolve_session(req))
                    sched.created_by = session->username;

                auto result = schedule_engine_->create_schedule(sched);
                if (!result) {
                    res.status = 400;
                    res.set_content(nlohmann::json({{"error", result.error()}}).dump(),
                                    "application/json");
                    return;
                }
                audit_log(req, "schedule.create", "success", "schedule", *result, sched.name);
                res.set_header("HX-Trigger",
                               R"({"showToast":{"message":"Schedule created","level":"success"}})");
                res.set_content(nlohmann::json({{"id", *result}}).dump(), "application/json");
            } catch (const std::exception& e) {
                res.status = 400;
                res.set_content(nlohmann::json({{"error", e.what()}}).dump(), "application/json");
            }
        });

        web_server_->Delete(R"(/api/schedules/([^/]+))", [this](const httplib::Request& req,
                                                                httplib::Response& res) {
            if (!require_permission(req, res, "Schedule", "Delete"))
                return;
            if (!schedule_engine_) {
                res.status = 503;
                res.set_content(
                    R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }

            auto id = req.matches[1].str();
            bool deleted = schedule_engine_->delete_schedule(id);
            if (deleted) {
                audit_log(req, "schedule.delete", "success", "schedule", id);
                res.set_header("HX-Trigger",
                               R"({"showToast":{"message":"Schedule deleted","level":"success"}})");
            }
            res.set_content(nlohmann::json({{"deleted", deleted}}).dump(), "application/json");
        });

        web_server_->Post(R"(/api/schedules/([^/]+)/enable)", [this](const httplib::Request& req,
                                                                     httplib::Response& res) {
            if (!require_permission(req, res, "Schedule", "Write"))
                return;
            if (!schedule_engine_) {
                res.status = 503;
                res.set_content(
                    R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }

            auto id = req.matches[1].str();
            auto enabled_str = extract_json_string(req.body, "enabled");
            bool enabled = (enabled_str != "false");
            schedule_engine_->set_enabled(id, enabled);
            res.set_content(nlohmann::json({{"enabled", enabled}}).dump(), "application/json");
        });

        // -- Approval API -----------------------------------------------------

        web_server_->Get("/api/approvals", [this](const httplib::Request& req,
                                                  httplib::Response& res) {
            if (!require_permission(req, res, "Approval", "Read"))
                return;
            if (!approval_manager_) {
                res.status = 503;
                res.set_content(
                    R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }

            ApprovalQuery q;
            if (req.has_param("status"))
                q.status = req.get_param_value("status");
            if (req.has_param("submitted_by"))
                q.submitted_by = req.get_param_value("submitted_by");

            auto approvals = approval_manager_->query(q);
            nlohmann::json arr = nlohmann::json::array();
            for (const auto& a : approvals) {
                arr.push_back({{"id", a.id},
                               {"definition_id", a.definition_id},
                               {"status", a.status},
                               {"submitted_by", a.submitted_by},
                               {"submitted_at", a.submitted_at},
                               {"reviewed_by", a.reviewed_by},
                               {"reviewed_at", a.reviewed_at},
                               {"review_comment", a.review_comment},
                               {"scope_expression", a.scope_expression}});
            }
            res.set_content(nlohmann::json({{"approvals", arr}}).dump(), "application/json");
        });

        web_server_->Get("/api/approvals/pending/count", [this](const httplib::Request& req,
                                                                httplib::Response& res) {
            if (!require_permission(req, res, "Approval", "Read"))
                return;
            if (!approval_manager_) {
                res.set_content(R"({"count":0})", "application/json");
                return;
            }
            auto count = approval_manager_->pending_count();
            res.set_content(nlohmann::json({{"count", count}}).dump(), "application/json");
        });

        web_server_->Post(R"(/api/approvals/([^/]+)/approve)", [this](const httplib::Request& req,
                                                                      httplib::Response& res) {
            if (!require_permission(req, res, "Approval", "Approve"))
                return;
            if (!approval_manager_) {
                res.status = 503;
                res.set_content(
                    R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }

            auto id = req.matches[1].str();
            auto comment = extract_json_string(req.body, "comment");
            auto session = auth_routes_->resolve_session(req);
            auto reviewer = session ? session->username : "unknown";

            auto result = approval_manager_->approve(id, reviewer, comment);
            if (!result) {
                res.status = 400;
                res.set_content(nlohmann::json({{"error", result.error()}}).dump(),
                                "application/json");
                return;
            }
            audit_log(req, "approval.approve", "success", "approval", id);
            emit_event("approval.approved", req, {{"reviewer", reviewer}}, {{"approval_id", id}});
            res.set_header("HX-Trigger",
                           R"({"showToast":{"message":"Approved","level":"success"}})");
            res.set_content(R"({"status":"approved"})", "application/json");
        });

        web_server_->Post(R"(/api/approvals/([^/]+)/reject)", [this](const httplib::Request& req,
                                                                     httplib::Response& res) {
            if (!require_permission(req, res, "Approval", "Approve"))
                return;
            if (!approval_manager_) {
                res.status = 503;
                res.set_content(
                    R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }

            auto id = req.matches[1].str();
            auto comment = extract_json_string(req.body, "comment");
            auto session = auth_routes_->resolve_session(req);
            auto reviewer = session ? session->username : "unknown";

            auto result = approval_manager_->reject(id, reviewer, comment);
            if (!result) {
                res.status = 400;
                res.set_content(nlohmann::json({{"error", result.error()}}).dump(),
                                "application/json");
                return;
            }
            audit_log(req, "approval.reject", "success", "approval", id);
            emit_event("approval.rejected", req, {{"reviewer", reviewer}, {"comment", comment}},
                       {{"approval_id", id}});
            res.set_header("HX-Trigger",
                           R"({"showToast":{"message":"Rejected","level":"warning"}})");
            res.set_content(R"({"status":"rejected"})", "application/json");
        });

        // -- Analytics API ---------------------------------------------------------

        web_server_->Get("/api/analytics/status",
                         [this](const httplib::Request& req, httplib::Response& res) {
                             if (!require_permission(req, res, "Infrastructure", "Read"))
                                 return;

                             nlohmann::json j;
                             if (analytics_store_) {
                                 j["enabled"] = true;
                                 j["pending_count"] = analytics_store_->pending_count();
                                 j["total_emitted"] = analytics_store_->total_emitted();
                             } else {
                                 j["enabled"] = false;
                                 j["pending_count"] = 0;
                                 j["total_emitted"] = 0;
                             }
                             res.set_content(j.dump(), "application/json");
                         });

        web_server_->Get(
            "/api/analytics/recent", [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_permission(req, res, "Infrastructure", "Read"))
                    return;

                int limit = 50;
                if (req.has_param("limit")) {
                    try {
                        limit = std::stoi(req.get_param_value("limit"));
                    } catch (...) {}
                }
                if (!analytics_store_) {
                    res.set_content(R"({"events":[],"count":0})", "application/json");
                    return;
                }
                auto events = analytics_store_->query_recent(limit);
                nlohmann::json arr = nlohmann::json::array();
                for (const auto& e : events) {
                    arr.push_back(e);
                }
                res.set_content(nlohmann::json({{"events", arr}, {"count", arr.size()}}).dump(),
                                "application/json");
            });

        // -- HTMX Fragment Routes for Instructions UI -------------------------

        web_server_->Get(
            "/fragments/instructions", [this](const httplib::Request& req, httplib::Response& res) {
                auto session = require_auth(req, res);
                if (!session)
                    return;
                if (!instruction_store_) {
                    res.set_content("<div class=\"empty-state\">Not available</div>", "text/html");
                    return;
                }

                auto defs = instruction_store_->query_definitions();

                // Check if user has PlatformEngineer or Administrator role
                // PlatformEngineer or Administrator can author definitions.
                // When RBAC enforcement is fully wired, this will check the
                // PlatformEngineer role via RbacStore::check_permission().
                bool can_author = (session->role == auth::Role::admin);

                std::string html;
                // Toolbar with New button for Platform Engineers
                html += "<div class=\"toolbar\"><div>";
                html += "<strong>" + std::to_string(defs.size()) + "</strong> definitions";
                html += "</div><div>";
                if (can_author) {
                    html += "<button class=\"btn btn-primary\" onclick=\"openEditor()\">"
                            "New Definition</button>";
                }
                html += "</div></div>";

                if (defs.empty()) {
                    html += "<div class=\"empty-state\">No instruction definitions yet.";
                    if (can_author)
                        html += " Click <strong>New Definition</strong> to create one.";
                    html += "</div>";
                } else {
                    html += "<table><thead><tr><th>Name</th><th>Plugin:Action</th><th>Type</"
                            "th><th>Enabled</th><th>Set</th><th></th></tr></thead><tbody>";
                    for (const auto& d : defs) {
                        auto type_cls = d.type == "question" ? "status-running" : "status-pending";
                        bool is_legacy = d.id.starts_with("legacy.");
                        html += "<tr><td><strong>" + html_escape(d.name) + "</strong>";
                        if (is_legacy)
                            html += " <span class=\"legacy-badge\">legacy</span>";
                        html += "<br><span style=\"font-size:0.65rem;color:#8b949e\">" +
                                html_escape(d.id.substr(0, 12)) +
                                "</span></td>"
                                "<td><code>" +
                                html_escape(d.plugin) + ":" + html_escape(d.action) +
                                "</code></td>"
                                "<td><span class=\"status-badge " +
                                type_cls + "\">" + html_escape(d.type) +
                                "</span></td>"
                                "<td>" +
                                std::string(d.enabled ? "Yes" : "No") +
                                "</td>"
                                "<td>" +
                                html_escape(d.instruction_set_id.empty()
                                                ? "-"
                                                : d.instruction_set_id.substr(0, 8)) +
                                "</td>"
                                "<td>";
                        if (can_author) {
                            html += "<button class=\"btn btn-secondary btn-sm\" "
                                    "onclick=\"openEditor('" +
                                    d.id + "')\">Edit</button> ";
                        }
                        html += "<button class=\"btn btn-danger btn-sm\" "
                                "hx-delete=\"/api/instructions/" +
                                d.id +
                                "\" hx-target=\"#tab-definitions\" hx-swap=\"innerHTML\" "
                                "hx-confirm=\"Delete definition '" +
                                html_escape(d.name) + "'?\">Delete</button></td></tr>";
                    }
                    html += "</tbody></table>";
                }
                res.set_content(html, "text/html; charset=utf-8");
            });

        // -- Editor fragment: RBAC-gated to PlatformEngineer / Administrator --
        web_server_->Get("/fragments/instructions/editor", [this](const httplib::Request& req,
                                                                  httplib::Response& res) {
            auto session = require_auth(req, res);
            if (!session)
                return;

            // Check InstructionDefinition:Write via RBAC; falls back to admin check
            if (!require_permission(req, res, "InstructionDefinition", "Write")) {
                // Override JSON 403 with HTML denial for HTMX fragment
                res.status = 200;
                res.set_content(kInstructionEditorDeniedHtml, "text/html; charset=utf-8");
                return;
            }

            std::string tmpl(kInstructionEditorHtml);
            auto def_id = req.get_param_value("id");
            if (!def_id.empty() && instruction_store_) {
                auto def = instruction_store_->get_definition(def_id);
                if (def) {
                    auto replace = [&](const std::string& key, const std::string& val) {
                        for (auto pos = tmpl.find(key); pos != std::string::npos;
                             pos = tmpl.find(key))
                            tmpl.replace(pos, key.size(), html_escape(val));
                    };
                    replace("{{TITLE}}", "Edit Definition");
                    replace("{{DEF_ID}}", def->id);
                    replace("{{DEF_NAME}}", def->name);
                    replace("{{DEF_VERSION}}", def->version);
                    replace("{{DEF_PLUGIN}}", def->plugin);
                    replace("{{DEF_ACTION}}", def->action);
                    replace("{{DEF_DESCRIPTION}}", def->description);
                    replace("{{DEF_PLATFORMS}}", def->platforms);
                    replace("{{YAML_SOURCE}}", def->yaml_source);
                    // Set dropdowns
                    replace("{{SEL_QUESTION}}", def->type == "question" ? "selected" : "");
                    replace("{{SEL_ACTION}}", def->type == "action" ? "selected" : "");
                    replace("{{SEL_APPR_AUTO}}", def->approval_mode == "auto" ? "selected" : "");
                    replace("{{SEL_APPR_ROLE}}",
                            def->approval_mode == "role-gated" ? "selected" : "");
                    replace("{{SEL_APPR_ALWAYS}}",
                            def->approval_mode == "always" ? "selected" : "");
                    replace("{{SEL_CC_UNLIM}}",
                            def->concurrency_mode == "unlimited" ? "selected" : "");
                    replace("{{SEL_CC_DEV}}",
                            def->concurrency_mode == "per-device" ? "selected" : "");
                    replace("{{SEL_CC_DEF}}",
                            def->concurrency_mode == "per-definition" ? "selected" : "");
                    replace("{{SEL_CC_SET}}", def->concurrency_mode == "per-set" ? "selected" : "");
                }
            } else {
                // New definition — clear all placeholders
                auto clear = [&](const std::string& key) {
                    for (auto pos = tmpl.find(key); pos != std::string::npos; pos = tmpl.find(key))
                        tmpl.replace(pos, key.size(), "");
                };
                auto replace = [&](const std::string& key, const std::string& val) {
                    for (auto pos = tmpl.find(key); pos != std::string::npos; pos = tmpl.find(key))
                        tmpl.replace(pos, key.size(), val);
                };
                replace("{{TITLE}}", "New Definition");
                clear("{{DEF_ID}}");
                clear("{{DEF_NAME}}");
                clear("{{DEF_VERSION}}");
                clear("{{DEF_PLUGIN}}");
                clear("{{DEF_ACTION}}");
                clear("{{DEF_DESCRIPTION}}");
                clear("{{DEF_PLATFORMS}}");
                replace("{{YAML_SOURCE}}",
                        "apiVersion: yuzu.io/v1alpha1\nkind: InstructionDefinition\n"
                        "metadata:\n  name: \"\"\n  version: \"1.0.0\"\nspec:\n"
                        "  plugin: \"\"\n  action: \"\"\n  type: question\n"
                        "  description: \"\"\n  concurrency: unlimited\n"
                        "  approval: auto\n  parameters:\n    type: object\n"
                        "    additionalProperties:\n      type: string\n"
                        "  results:\n    - name: output\n      type: string\n");
                replace("{{SEL_QUESTION}}", "selected");
                clear("{{SEL_ACTION}}");
                replace("{{SEL_APPR_AUTO}}", "selected");
                clear("{{SEL_APPR_ROLE}}");
                clear("{{SEL_APPR_ALWAYS}}");
                replace("{{SEL_CC_UNLIM}}", "selected");
                clear("{{SEL_CC_DEV}}");
                clear("{{SEL_CC_DEF}}");
                clear("{{SEL_CC_SET}}");
            }
            res.set_content(tmpl, "text/html; charset=utf-8");
        });

        // -- YAML save endpoint (HTMX form POST from editor) --
        web_server_->Post("/api/instructions/yaml", [this](const httplib::Request& req,
                                                           httplib::Response& res) {
            if (!require_permission(req, res, "InstructionDefinition", "Write"))
                return;
            auto session = require_auth(req, res);
            if (!session)
                return;
            if (!instruction_store_) {
                res.set_content(
                    "<div class=\"alert alert-error\">Instruction store not available</div>",
                    "text/html");
                return;
            }

            auto yaml_source = req.get_param_value("yaml_source");
            auto def_id = req.get_param_value("id");

            if (yaml_source.empty()) {
                res.set_content(
                    "<div class=\"alert alert-error\">YAML source cannot be empty</div>",
                    "text/html");
                return;
            }

            // Minimal YAML field extraction (name, plugin, action from the YAML text).
            // Full yaml-cpp parsing is deferred; for now we extract fields via simple
            // line scanning — the YAML source is stored verbatim as source of truth.
            auto extract = [&](const std::string& key) -> std::string {
                auto needle = key + ": ";
                auto pos = yaml_source.find(needle);
                if (pos == std::string::npos)
                    return {};
                auto start = pos + needle.size();
                auto end = yaml_source.find('\n', start);
                auto val = yaml_source.substr(start, end - start);
                // Strip quotes
                if (val.size() >= 2 && val.front() == '"' && val.back() == '"')
                    val = val.substr(1, val.size() - 2);
                return val;
            };

            InstructionDefinition def;
            def.name = extract("name");
            def.version = extract("version");
            def.plugin = extract("plugin");
            def.action = extract("action");
            // Normalize action to lowercase — agent plugins match case-sensitively
            for (auto& c : def.action)
                c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            def.type = extract("type");
            def.description = extract("description");
            def.concurrency_mode = extract("concurrency");
            def.approval_mode = extract("approval");
            // Validate approval_mode — reject unknown values at creation time
            if (!def.approval_mode.empty() && def.approval_mode != "auto" &&
                def.approval_mode != "role-gated" && def.approval_mode != "always") {
                res.set_content("<div class=\"alert alert-error\">Invalid approval mode: &quot;" +
                                    html_escape(def.approval_mode) +
                                    "&quot;. Must be auto, role-gated, or always.</div>",
                                "text/html");
                return;
            }
            def.yaml_source = yaml_source;
            def.created_by = session->username;
            def.enabled = true;

            if (def.name.empty() || def.plugin.empty() || def.action.empty()) {
                res.set_content("<div class=\"alert alert-error\">Missing required fields: "
                                "name, plugin, action</div>",
                                "text/html");
                return;
            }

            std::string msg;
            if (!def_id.empty()) {
                def.id = def_id;
                auto result = instruction_store_->update_definition(def);
                msg = result ? "Definition updated" : "Update failed: " + result.error();
            } else {
                auto result = instruction_store_->create_definition(def);
                msg = result ? "Definition created" : "Create failed: " + result.error();
            }

            std::string cls =
                msg.find("failed") != std::string::npos ? "alert-error" : "alert-success";
            {
                auto level = msg.find("failed") == std::string::npos ? "success" : "error";
                nlohmann::json trigger = {{"showToast", {{"message", msg}, {"level", level}}}};
                res.set_header("HX-Trigger", trigger.dump());
            }
            res.set_content("<div class=\"alert " + cls + "\">" + html_escape(msg) + "</div>",
                            "text/html");
        });

        // -- YAML validate endpoint --
        web_server_->Post("/api/instructions/validate-yaml", [this](const httplib::Request& req,
                                                                    httplib::Response& res) {
            if (!require_permission(req, res, "InstructionDefinition", "Read"))
                return;

            auto yaml_source = req.get_param_value("yaml_source");
            auto errors = validate_yaml_source(yaml_source);

            if (errors.empty()) {
                res.set_content("<div class=\"alert alert-success\">YAML validation passed</div>",
                                "text/html");
            } else {
                std::string html =
                    "<div class=\"alert alert-error\"><strong>Validation errors:</strong><ul>";
                for (const auto& e : errors)
                    html += "<li>" + html_escape(e) + "</li>";
                html += "</ul></div>";
                res.set_content(html, "text/html");
            }
        });

        // -- YAML preview endpoint (server-side highlighting + validation) --
        web_server_->Post(
            "/fragments/instructions/yaml-preview",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_permission(req, res, "InstructionDefinition", "Read"))
                    return;

                auto yaml_source = req.get_param_value("yaml_source");
                auto highlighted = highlight_yaml(yaml_source);
                auto errors = validate_yaml_source(yaml_source);

                std::string html = highlighted;
                if (!errors.empty()) {
                    html += R"(<div id="yaml-errors" hx-swap-oob="innerHTML:#yaml-errors">)";
                    for (const auto& e : errors)
                        html += "<div class='err'>" + html_escape(e) + "</div>";
                    html += "</div>";
                } else {
                    html += R"(<div id="yaml-errors" hx-swap-oob="innerHTML:#yaml-errors"></div>)";
                }
                res.set_content(html, "text/html");
            });

        web_server_->Get(
            "/fragments/approvals", [this](const httplib::Request& req, httplib::Response& res) {
                auto session = require_auth(req, res);
                if (!session)
                    return;
                if (!approval_manager_) {
                    res.set_content("<div class=\"empty-state\">Not available</div>", "text/html");
                    return;
                }

                auto approvals = approval_manager_->query();
                std::string html;
                if (approvals.empty()) {
                    html = "<div class=\"empty-state\">No approval requests.</div>";
                } else {
                    html = "<table><thead><tr><th>ID</th><th>Status</th><th>Submitted "
                           "By</th><th>Scope</th><th></th></tr></thead><tbody>";
                    for (const auto& a : approvals) {
                        auto status_cls = "status-" + a.status;
                        html += "<tr><td><code style=\"font-size:0.7rem\">" +
                                html_escape(a.id.substr(0, 12)) +
                                "</code></td>"
                                "<td><span class=\"status-badge " +
                                status_cls + "\">" + html_escape(a.status) +
                                "</span></td>"
                                "<td>" +
                                html_escape(a.submitted_by) +
                                "</td>"
                                "<td><code style=\"font-size:0.7rem\">" +
                                html_escape(a.scope_expression) +
                                "</code></td>"
                                "<td>";
                        if (a.status == "pending") {
                            html += "<button class=\"btn btn-primary\" "
                                    "style=\"font-size:0.65rem;padding:0.15rem "
                                    "0.5rem;margin-right:0.3rem\" "
                                    "hx-post=\"/api/approvals/" +
                                    a.id +
                                    "/approve\" hx-target=\"#tab-approvals\" "
                                    "hx-swap=\"innerHTML\">Approve</button>"
                                    "<button class=\"btn btn-danger\" "
                                    "style=\"font-size:0.65rem;padding:0.15rem 0.5rem\" "
                                    "hx-post=\"/api/approvals/" +
                                    a.id +
                                    "/reject\" hx-target=\"#tab-approvals\" "
                                    "hx-swap=\"innerHTML\">Reject</button>";
                        }
                        html += "</td></tr>";
                    }
                    html += "</tbody></table>";
                }
                res.set_content(html, "text/html; charset=utf-8");
            });

        // -- Scope API --------------------------------------------------------
        web_server_->Post("/api/scope/validate", [this](const httplib::Request& req,
                                                        httplib::Response& res) {
            auto session = require_auth(req, res);
            if (!session)
                return;

            auto expression = extract_json_string(req.body, "expression");
            if (expression.empty()) {
                res.status = 400;
                res.set_content(
                    R"({"error":{"code":400,"message":"expression required"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }

            auto result = yuzu::scope::validate(expression);
            if (result) {
                res.set_content(R"({"valid":true})", "application/json");
            } else {
                res.set_content(
                    nlohmann::json({{"valid", false}, {"error", result.error()}}).dump(),
                    "application/json");
            }
        });

        // -- Inventory REST endpoints (Issue 7.17) --------------------------------

        // GET /api/inventory/tables — list available inventory data types
        web_server_->Get("/api/inventory/tables", [this](const httplib::Request& req,
                                                         httplib::Response& res) {
            if (!require_permission(req, res, "Inventory", "Read"))
                return;
            if (!inventory_store_ || !inventory_store_->is_open()) {
                res.status = 503;
                res.set_content(
                    R"({"error":{"code":503,"message":"inventory store not available"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }
            auto tables = inventory_store_->list_tables();
            nlohmann::json arr = nlohmann::json::array();
            for (const auto& t : tables) {
                arr.push_back({{"plugin", t.plugin},
                               {"agent_count", t.agent_count},
                               {"last_collected", t.last_collected}});
            }
            res.set_content(nlohmann::json({{"tables", arr}, {"count", arr.size()}}).dump(),
                            "application/json");
        });

        // GET /api/inventory/:agent_id/:plugin — get inventory for agent+plugin
        web_server_->Get(R"(/api/inventory/([^/]+)/([^/]+))", [this](const httplib::Request& req,
                                                                     httplib::Response& res) {
            if (!require_permission(req, res, "Inventory", "Read"))
                return;
            if (!inventory_store_ || !inventory_store_->is_open()) {
                res.status = 503;
                res.set_content(
                    R"({"error":{"code":503,"message":"inventory store not available"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }
            auto agent_id = req.matches[1].str();
            auto plugin = req.matches[2].str();
            auto record = inventory_store_->get(agent_id, plugin);
            if (!record) {
                res.status = 404;
                res.set_content(
                    R"({"error":{"code":404,"message":"no inventory data found"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }
            nlohmann::json data_obj;
            try {
                data_obj = nlohmann::json::parse(record->data_json);
            } catch (...) {
                data_obj = record->data_json;
            }
            res.set_content(nlohmann::json({{"agent_id", record->agent_id},
                                            {"plugin", record->plugin},
                                            {"data", data_obj},
                                            {"collected_at", record->collected_at}})
                                .dump(),
                            "application/json");
        });

        // POST /api/inventory/query — query inventory across agents
        web_server_->Post("/api/inventory/query", [this](const httplib::Request& req,
                                                         httplib::Response& res) {
            if (!require_permission(req, res, "Inventory", "Read"))
                return;
            if (!inventory_store_ || !inventory_store_->is_open()) {
                res.status = 503;
                res.set_content(
                    R"({"error":{"code":503,"message":"inventory store not available"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }
            auto body = nlohmann::json::parse(req.body, nullptr, false);
            if (body.is_discarded()) {
                res.status = 400;
                res.set_content(
                    R"({"error":{"code":400,"message":"invalid JSON"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }
            InventoryQuery q;
            q.agent_id = body.value("agent_id", "");
            q.plugin = body.value("plugin", "");
            q.since = body.value("since", int64_t{0});
            q.until = body.value("until", int64_t{0});
            q.limit = body.value("limit", 100);
            if (q.limit > 1000)
                q.limit = 1000;

            auto records = inventory_store_->query(q);
            nlohmann::json arr = nlohmann::json::array();
            for (const auto& r : records) {
                nlohmann::json data_obj;
                try {
                    data_obj = nlohmann::json::parse(r.data_json);
                } catch (...) {
                    data_obj = r.data_json;
                }
                arr.push_back({{"agent_id", r.agent_id},
                               {"plugin", r.plugin},
                               {"data", data_obj},
                               {"collected_at", r.collected_at}});
            }
            res.set_content(nlohmann::json({{"results", arr}, {"count", arr.size()}}).dump(),
                            "application/json");
        });

        // -- Extracted route modules ------------------------------------------------
        // Common callback lambdas shared by all extracted route modules.
        auto auth_fn = [this](const httplib::Request& req,
                              httplib::Response& res) -> std::optional<auth::Session> {
            return require_auth(req, res);
        };
        auto perm_fn = [this](const httplib::Request& req, httplib::Response& res,
                              const std::string& type, const std::string& op) -> bool {
            return require_permission(req, res, type, op);
        };
        auto audit_fn = [this](const httplib::Request& req, const std::string& action,
                               const std::string& result, const std::string& target_type,
                               const std::string& target_id, const std::string& detail) {
            audit_log(req, action, result, target_type, target_id, detail);
        };

        // ComplianceRoutes — /compliance, /fragments/compliance/*, /api/policies/*,
        // /api/compliance/*
        compliance_routes_ = std::make_unique<ComplianceRoutes>();
        compliance_routes_->register_routes(
            *web_server_, auth_fn, perm_fn, audit_fn,
            [this](const std::string& event_type, const httplib::Request& req,
                   const nlohmann::json& attrs, const nlohmann::json& payload_data) {
                emit_event(event_type, req, attrs, payload_data);
            },
            policy_store_.get(), [this]() -> std::string { return registry_.to_json(); });

        // DashboardRoutes — /fragments/results, /fragments/results/filter-bar,
        //                   /fragments/create-group-form, /api/dashboard/group-from-results
        dashboard_routes_ = std::make_unique<DashboardRoutes>();
        dashboard_routes_->register_routes(
            *web_server_, auth_fn, perm_fn, audit_fn, response_store_.get(),
            mgmt_group_store_.get(), &registry_, tag_store_.get(), &event_bus_,
            [this]() -> std::string { return registry_.to_json(); },
            // DispatchFn — reuses /api/command dispatch logic
            [this](const std::string& plugin, const std::string& action,
                   const std::vector<std::string>& agent_ids, const std::string& scope_expr,
                   const std::unordered_map<std::string, std::string>& parameters)
                -> std::pair<std::string, int> {
                auto command_id =
                    plugin + "-" +
                    auth::AuthManager::bytes_to_hex(auth::AuthManager::random_bytes(8));

                detail::pb::CommandRequest cmd;
                cmd.set_command_id(command_id);
                cmd.set_plugin(plugin);
                cmd.set_action(action);
                for (const auto& [k, v] : parameters)
                    (*cmd.mutable_parameters())[k] = v;
                agent_service_.record_send_time(command_id);

                int sent = 0;
                if (!scope_expr.empty() && scope_expr.starts_with("group:")) {
                    auto group_id = scope_expr.substr(6);
                    if (mgmt_group_store_) {
                        auto members = mgmt_group_store_->get_members(group_id);
                        for (const auto& m : members) {
                            if (registry_.send_to(m.agent_id, cmd))
                                ++sent;
                        }
                    }
                } else if (!scope_expr.empty()) {
                    auto parsed = yuzu::scope::parse(scope_expr);
                    if (parsed) {
                        auto matched = registry_.evaluate_scope(*parsed, tag_store_.get(),
                                                                custom_properties_store_.get());
                        for (const auto& aid : matched) {
                            if (registry_.send_to(aid, cmd))
                                ++sent;
                        }
                    }
                } else if (agent_ids.empty()) {
                    sent = registry_.send_to_all(cmd);
                } else {
                    for (const auto& aid : agent_ids) {
                        if (registry_.send_to(aid, cmd))
                            ++sent;
                    }
                }

                forward_gateway_pending();

                if (sent > 0) {
                    metrics_.counter("yuzu_commands_dispatched_total").increment();
                    // Publish RUNNING status + clear results via SSE.
                    // This MUST happen via SSE (not in the POST response)
                    // because the POST response races with SSE output
                    // events — fast agents respond before the browser
                    // receives the POST reply, and an innerHTML OOB in
                    // the POST response would wipe already-displayed rows.
                    //
                    // Each OOB element is published separately to avoid
                    // mixing table elements (<tbody>) with non-table
                    // elements (<span>, <strong>) in the same fragment.
                    // Browsers apply table content model rules during
                    // fragment parsing and silently discard <tbody> tags
                    // outside a <table> context (foster parenting).
                    event_bus_.publish("command-status",
                                       "<span id=\"status-badge\" class=\"badge-running\""
                                       " hx-swap-oob=\"outerHTML\">RUNNING</span>");
                    event_bus_.publish(
                        "output", "<tbody id=\"results-tbody\" hx-swap-oob=\"innerHTML\">"
                                  "<tr id=\"empty-row\"><td colspan=\"99\" class=\"empty-state\">"
                                  "Waiting for results...</td></tr></tbody>");
                    event_bus_.publish("output",
                                       "<strong id=\"row-count\" hx-swap-oob=\"true\">0</strong>");
                }
                return {command_id, sent};
            },
            // ResolveFn — resolve instruction text → (plugin, action)
            [this](const std::string& text) -> std::pair<std::string, std::string> {
                auto help = registry_.help_json();
                auto data = nlohmann::json::parse(help, nullptr, false);
                if (!data.is_object() || !data.contains("plugins"))
                    return {"", ""};
                for (const auto& p : data["plugins"]) {
                    auto pname = p.value("name", "");
                    auto& actions = p["actions"];
                    // "plugin" alone → first action
                    if (text == pname && !actions.empty()) {
                        auto aname = actions[0].is_string() ? actions[0].get<std::string>()
                                                            : actions[0].value("name", "");
                        return {pname, aname};
                    }
                    // "plugin action" → specific action
                    for (const auto& a : actions) {
                        auto aname = a.is_string() ? a.get<std::string>() : a.value("name", "");
                        if (text == pname + " " + aname)
                            return {pname, aname};
                    }
                }
                return {"", ""};
            },
            &metrics_, instruction_store_.get());

        // WorkflowRoutes — /fragments/executions, /fragments/schedules, /api/workflows/*,
        //                   /api/workflow-executions/*, /api/product-packs/*, /api/scope/estimate
        //
        // PR 2.5 (#670): deps-struct refactor. All 15 dependencies now flow
        // through `WorkflowRoutes::Deps` so PR 3's SSE event-bus addition is
        // a single new field, not a 17th parameter.
        workflow_routes_ = std::make_unique<WorkflowRoutes>();
        WorkflowRoutes::Deps wf_deps;
        wf_deps.auth_fn = auth_fn;
        wf_deps.perm_fn = perm_fn;
        wf_deps.audit_fn = audit_fn;
        wf_deps.emit_fn = [this](const std::string& event_type, const httplib::Request& req) {
            emit_event(event_type, req);
        };
        wf_deps.scope_fn =
            [this](const std::string& expression) -> std::pair<std::size_t, std::size_t> {
            auto parsed = yuzu::scope::parse(expression);
            if (!parsed)
                return {0, registry_.agent_count()};
            auto matched =
                registry_.evaluate_scope(*parsed, tag_store_.get(), custom_properties_store_.get());
            return {matched.size(), registry_.agent_count()};
        };
        wf_deps.workflow_engine = workflow_engine_.get();
        wf_deps.execution_tracker = execution_tracker_.get();
        wf_deps.schedule_engine = schedule_engine_.get();
        wf_deps.product_pack_store = product_pack_store_.get();
        wf_deps.instruction_store = instruction_store_.get();
        wf_deps.policy_store = policy_store_.get();
        wf_deps.command_dispatch_fn =
            [this](const std::string& plugin, const std::string& action,
                   const std::vector<std::string>& agent_ids, const std::string& scope_expr,
                   const std::unordered_map<std::string, std::string>& parameters,
                   const std::string& execution_id) -> std::pair<std::string, int> {
            // Normalize action to lowercase — agent plugins register actions
            // in lowercase and match case-sensitively.
            auto norm_action = action;
            for (auto& c : norm_action)
                c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            auto command_id =
                plugin + "-" + auth::AuthManager::bytes_to_hex(auth::AuthManager::random_bytes(8));
            detail::pb::CommandRequest cmd;
            cmd.set_command_id(command_id);
            cmd.set_plugin(plugin);
            cmd.set_action(norm_action);
            for (const auto& [k, v] : parameters)
                (*cmd.mutable_parameters())[k] = v;
            agent_service_.record_send_time(command_id);
            // PR 2 / UP2-4: register the command_id → execution_id
            // mapping BEFORE any RPC is sent so a sub-millisecond
            // loopback agent's response cannot win the race against
            // mapping registration. Empty execution_id (out-of-band
            // dispatch with no tracker row) skips registration —
            // record_execution_id is a no-op for empty values.
            if (!execution_id.empty()) {
                agent_service_.record_execution_id(command_id, execution_id);
            }
            int sent = 0;
            if (!scope_expr.empty() && scope_expr.starts_with("group:")) {
                auto group_id = scope_expr.substr(6);
                if (mgmt_group_store_) {
                    auto members = mgmt_group_store_->get_members(group_id);
                    for (const auto& m : members)
                        if (registry_.send_to(m.agent_id, cmd))
                            ++sent;
                }
            } else if (!scope_expr.empty()) {
                auto parsed = yuzu::scope::parse(scope_expr);
                if (parsed) {
                    auto matched = registry_.evaluate_scope(*parsed, tag_store_.get(),
                                                            custom_properties_store_.get());
                    for (const auto& aid : matched)
                        if (registry_.send_to(aid, cmd))
                            ++sent;
                }
            } else if (agent_ids.empty()) {
                sent = registry_.send_to_all(cmd);
            } else {
                for (const auto& aid : agent_ids)
                    if (registry_.send_to(aid, cmd))
                        ++sent;
            }
            forward_gateway_pending();
            if (sent > 0)
                metrics_.counter("yuzu_commands_dispatched_total").increment();
            return {command_id, sent};
        };
        wf_deps.approval_manager = approval_manager_.get();
        wf_deps.response_store = response_store_.get();
        // PR 3 — SSE event bus for live execution updates. Server owns
        // the bus; ExecutionTracker publishes onto it; SSE handler
        // subscribes per-connection.
        wf_deps.execution_event_bus = execution_event_bus_.get();
        workflow_routes_->register_routes(*web_server_, std::move(wf_deps));

        // NotificationRoutes — /api/notifications/*
        notification_routes_ = std::make_unique<NotificationRoutes>();
        notification_routes_->register_routes(*web_server_, auth_fn, perm_fn, audit_fn,
                                              notification_store_.get());

        // WebhookRoutes — /api/webhooks/*
        webhook_routes_ = std::make_unique<WebhookRoutes>();
        webhook_routes_->register_routes(
            *web_server_, auth_fn, perm_fn, audit_fn,
            [this](const std::string& event_type, const httplib::Request& req,
                   const nlohmann::json& attrs,
                   const nlohmann::json& payload) { emit_event(event_type, req, attrs, payload); },
            webhook_store_.get());

        // OffloadRoutes — /api/v1/offload-targets/* (Phase 8.3, #255)
        offload_routes_ = std::make_unique<OffloadRoutes>();
        offload_routes_->register_routes(*web_server_, auth_fn, perm_fn, audit_fn,
                                         offload_target_store_.get());

        // DiscoveryRoutes — /api/directory/*, /api/patches/*, /api/deployments/*, /api/discovery/*
        discovery_routes_ = std::make_unique<DiscoveryRoutes>();
        discovery_routes_->register_routes(*web_server_, auth_fn, perm_fn, audit_fn,
                                           directory_sync_.get(), patch_manager_.get(),
                                           deployment_store_.get(), discovery_store_.get());

        // -- Register REST API v1 routes (Phase 3) --------------------------------

        rest_api_v1_ = std::make_unique<RestApiV1>();
        rest_api_v1_->register_routes(
            *web_server_,
            [this](const httplib::Request& req, httplib::Response& res)
                -> std::optional<auth::Session> { return require_auth(req, res); },
            [this](const httplib::Request& req, httplib::Response& res, const std::string& type,
                   const std::string& op) -> bool {
                return require_permission(req, res, type, op);
            },
            [this](const httplib::Request& req, const std::string& action,
                   const std::string& result, const std::string& target_type,
                   const std::string& target_id, const std::string& detail) {
                audit_log(req, action, result, target_type, target_id, detail);
            },
            rbac_store_.get(), mgmt_group_store_.get(), api_token_store_.get(),
            quarantine_store_.get(), response_store_.get(), instruction_store_.get(),
            execution_tracker_.get(), schedule_engine_.get(), approval_manager_.get(),
            tag_store_.get(), audit_store_.get(),
            [this](const std::string& service_value) {
                ensure_service_management_group(service_value);
            },
            [this](const std::string& agent_id, const std::string& key) {
                // Push asset tags to agent when a structured category changes
                // Case-insensitive match: API may receive "Role" but kCategoryKeys are lowercase
                std::string lower_key = key;
                std::transform(lower_key.begin(), lower_key.end(), lower_key.begin(),
                               [](unsigned char c) { return std::tolower(c); });
                for (auto cat_key : kCategoryKeys) {
                    if (cat_key == lower_key) {
                        push_asset_tags_to_agent(agent_id);
                        break;
                    }
                }
            },
            inventory_store_.get(), product_pack_store_.get(),
            /*sw_deploy_store=*/nullptr,
            /*device_token_store=*/nullptr,
            /*license_store=*/nullptr, guaranteed_state_store_.get());

        // -- Register MCP server routes ----------------------------------------

        if (cfg_.mcp_disable) {
            // C8: Return a proper JSON-RPC error instead of a generic 404
            web_server_->Post("/mcp/v1/", [](const httplib::Request&, httplib::Response& res) {
                res.set_header("Content-Type", "application/json");
                res.set_content(
                    mcp::error_response_null(mcp::kMcpDisabled, "MCP is disabled on this server"),
                    "application/json");
            });
        } else {
            mcp_server_ = std::make_unique<mcp::McpServer>();
            mcp_server_->register_routes(
                *web_server_,
                [this](const httplib::Request& req, httplib::Response& res)
                    -> std::optional<auth::Session> { return require_auth(req, res); },
                [this](const httplib::Request& req, httplib::Response& res, const std::string& type,
                       const std::string& op) -> bool {
                    return require_permission(req, res, type, op);
                },
                [this](const httplib::Request& req, const std::string& action,
                       const std::string& result, const std::string& target_type,
                       const std::string& target_id, const std::string& detail) {
                    audit_log(req, action, result, target_type, target_id, detail);
                },
                [this]() { return registry_.to_json_obj(); }, rbac_store_.get(),
                instruction_store_.get(), execution_tracker_.get(), response_store_.get(),
                audit_store_.get(), tag_store_.get(), inventory_store_.get(), policy_store_.get(),
                mgmt_group_store_.get(), approval_manager_.get(), schedule_engine_.get(),
                cfg_.mcp_read_only, cfg_.mcp_disable,
                // DispatchFn — reuses /api/command dispatch logic for MCP execute_instruction
                [this](const std::string& plugin, const std::string& action,
                       const std::vector<std::string>& agent_ids, const std::string& scope_expr,
                       const std::unordered_map<std::string, std::string>& parameters)
                    -> std::pair<std::string, int> {
                    auto command_id =
                        plugin + "-" +
                        auth::AuthManager::bytes_to_hex(auth::AuthManager::random_bytes(8));

                    detail::pb::CommandRequest cmd;
                    cmd.set_command_id(command_id);
                    cmd.set_plugin(plugin);
                    cmd.set_action(action);
                    for (const auto& [k, v] : parameters)
                        (*cmd.mutable_parameters())[k] = v;
                    agent_service_.record_send_time(command_id);

                    int sent = 0;
                    if (!scope_expr.empty() && scope_expr != "__all__" &&
                        scope_expr.starts_with("group:")) {
                        auto group_id = scope_expr.substr(6);
                        if (mgmt_group_store_) {
                            for (const auto& m : mgmt_group_store_->get_members(group_id))
                                if (registry_.send_to(m.agent_id, cmd))
                                    ++sent;
                        }
                    } else if (!scope_expr.empty() && scope_expr != "__all__") {
                        auto parsed = yuzu::scope::parse(scope_expr);
                        if (parsed) {
                            for (const auto& aid : registry_.evaluate_scope(
                                     *parsed, tag_store_.get(), custom_properties_store_.get()))
                                if (registry_.send_to(aid, cmd))
                                    ++sent;
                        }
                    } else if (agent_ids.empty()) {
                        sent = registry_.send_to_all(cmd);
                    } else {
                        for (const auto& aid : agent_ids)
                            if (registry_.send_to(aid, cmd))
                                ++sent;
                    }

                    forward_gateway_pending();
                    if (sent > 0)
                        metrics_.counter("yuzu_commands_dispatched_total").increment();
                    spdlog::info("MCP execute_instruction: {}:{} → {} agent(s)", plugin, action,
                                 sent);
                    return {command_id, sent};
                });
        }

        // -- Listen -----------------------------------------------------------

        if (cfg_.web_address == "0.0.0.0" || cfg_.web_address == "::") {
            spdlog::warn("Web UI bound to all interfaces ({}). Consider restricting "
                         "to 127.0.0.1 in production.",
                         cfg_.web_address);
        }

        int listen_port = cfg_.web_port;
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
        if (cfg_.https_enabled) {
            listen_port = cfg_.https_port;

            // Start HTTP→HTTPS redirect server
            if (cfg_.https_redirect) {
                redirect_server_ = std::make_unique<httplib::Server>();
                auto https_port = cfg_.https_port;
                auto web_address = cfg_.web_address;
                redirect_server_->set_pre_routing_handler(
                    [web_address,
                     https_port](const httplib::Request& req,
                                 httplib::Response& res) -> httplib::Server::HandlerResponse {
                        auto host = req.get_header_value("Host");
                        // Strip port from host if present
                        auto colon = host.find(':');
                        if (colon != std::string::npos) {
                            host = host.substr(0, colon);
                        }
                        if (host.empty())
                            host = web_address;
                        auto location =
                            "https://" + host + ":" + std::to_string(https_port) + req.path;
                        if (!req.params.empty()) {
                            location += "?";
                            bool first = true;
                            for (const auto& [k, v] : req.params) {
                                if (!first)
                                    location += "&";
                                location += k + "=" + v;
                                first = false;
                            }
                        }
                        res.set_redirect(location, 301);
                        return httplib::Server::HandlerResponse::Handled;
                    });
                redirect_thread_ = std::thread([this] {
                    spdlog::info("HTTP→HTTPS redirect on http://{}:{}/", cfg_.web_address,
                                 cfg_.web_port);
                    redirect_server_->listen(cfg_.web_address, cfg_.web_port);
                });
            }
        }
#endif

        web_thread_ = std::thread([this, listen_port] {
            if (cfg_.https_enabled) {
                spdlog::info("Web UI available at https://{}:{}/", cfg_.web_address, listen_port);
            } else {
                spdlog::info("Web UI available at http://{}:{}/", cfg_.web_address, listen_port);
            }
            web_server_->listen(cfg_.web_address, listen_port);
        });
    }

    void forward_legacy_command(const std::string& plugin, const std::string& action,
                                httplib::Response& res) {
        if (!registry_.has_any()) {
            res.status = 503;
            res.set_content(
                R"({"error":{"code":503,"message":"no agent connected"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }

        auto command_id =
            plugin + "-" + auth::AuthManager::bytes_to_hex(auth::AuthManager::random_bytes(8));

        detail::pb::CommandRequest cmd;
        cmd.set_command_id(command_id);
        cmd.set_plugin(plugin);
        cmd.set_action(action);

        agent_service_.record_send_time(command_id);
        int sent = registry_.send_to_all(cmd);

        if (sent == 0) {
            res.status = 503;
            res.set_content(
                R"({"error":{"code":503,"message":"failed to send command"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }
        res.set_content("{\"status\":\"sent\"}", "application/json");
    }

    // -- JSON parsing helpers (using nlohmann/json) --------------------------

    static std::string extract_json_string(const std::string& body, const std::string& key) {
        try {
            auto j = nlohmann::json::parse(body);
            if (j.contains(key) && j[key].is_string()) {
                return j[key].get<std::string>();
            }
        } catch (...) {}
        return {};
    }

    static std::vector<std::string> extract_json_string_array(const std::string& body,
                                                              const std::string& key) {
        try {
            auto j = nlohmann::json::parse(body);
            if (j.contains(key) && j[key].is_array()) {
                std::vector<std::string> result;
                for (const auto& elem : j[key]) {
                    if (elem.is_string()) {
                        result.push_back(elem.get<std::string>());
                    }
                }
                return result;
            }
        } catch (...) {}
        return {};
    }

    static std::unordered_map<std::string, std::string>
    extract_json_string_map(const std::string& body, const std::string& key) {
        try {
            auto j = nlohmann::json::parse(body);
            if (j.contains(key) && j[key].is_object()) {
                std::unordered_map<std::string, std::string> result;
                for (auto& [k, v] : j[key].items()) {
                    if (v.is_string())
                        result[k] = v.get<std::string>();
                    else
                        result[k] = v.dump();
                }
                return result;
            }
        } catch (...) {}
        return {};
    }

    static int32_t extract_json_int(const std::string& body, const std::string& key,
                                    int32_t default_value = 0) {
        try {
            auto j = nlohmann::json::parse(body);
            if (j.contains(key) && j[key].is_number_integer()) {
                return j[key].get<int32_t>();
            }
        } catch (...) {}
        return default_value;
    }

    // -- Data members ---------------------------------------------------------

    Config cfg_;
    auth::AuthManager& auth_mgr_;
    auth::AutoApproveEngine auto_approve_;
    yuzu::MetricsRegistry metrics_;
    detail::EventBus event_bus_;
    detail::AgentRegistry registry_;
    detail::AgentServiceImpl agent_service_;
    detail::ManagementServiceImpl mgmt_service_;
    std::unique_ptr<detail::GatewayUpstreamServiceImpl> gateway_service_;
    std::shared_ptr<grpc::Channel> gw_mgmt_channel_;
    std::unique_ptr<::yuzu::server::v1::ManagementService::Stub> gw_mgmt_stub_;
    std::shared_ptr<spdlog::logger> file_logger_;
    std::unique_ptr<grpc::Server> agent_server_;
    std::unique_ptr<grpc::Server> mgmt_server_;
    std::unique_ptr<httplib::Server> web_server_;
    std::thread web_thread_;

    // HTTPS redirect server
    std::unique_ptr<httplib::Server> redirect_server_;
    std::thread redirect_thread_;

    // Certificate hot-reload
    std::unique_ptr<CertReloader> cert_reloader_;

    // OIDC SSO — protected by oidc_mu_ for thread-safe reinit from Settings UI
    mutable std::shared_mutex oidc_mu_;
    std::unique_ptr<oidc::OidcProvider> oidc_provider_;

    // NVD CVE feed
    std::shared_ptr<NvdDatabase> nvd_db_;
    std::unique_ptr<NvdSyncManager> nvd_sync_;

    // OTA agent updates
    std::unique_ptr<UpdateRegistry> update_registry_;

    // Analytics
    std::unique_ptr<AnalyticsEventStore> analytics_store_;

    // Phase 1: Data infrastructure
    std::unique_ptr<ResponseStore> response_store_;
    std::unique_ptr<AuditStore> audit_store_;
    std::unique_ptr<TagStore> tag_store_;

    // Phase 2: Instruction system
    std::unique_ptr<InstructionStore> instruction_store_;
    std::unique_ptr<InstructionDbPool>
        instr_db_pool_; // RAII owner — declared before consumers so it outlives them
    /// PR 3 — per-execution SSE event bus. Process-local; the tracker
    /// borrows this pointer and publishes onto it; `WorkflowRoutes`
    /// registers the SSE handler that subscribes per-connection.
    /// Declared BEFORE `execution_tracker_` so the bus outlives the
    /// tracker — members destroy in reverse declaration order, so
    /// `execution_tracker_` runs `~ExecutionTracker` first (releasing
    /// its borrowed `event_bus_` pointer) and only then the bus
    /// destructs.
    std::unique_ptr<ExecutionEventBus> execution_event_bus_;
    std::unique_ptr<ExecutionTracker> execution_tracker_;
    // [BUS-BEFORE-TRACKER] — DO NOT reorder these two members or insert
    // a new member between them. ExecutionTracker borrows a raw
    // ExecutionEventBus* via set_event_bus(); destructor order is
    // reverse-of-declaration, so the tracker must destruct FIRST
    // (releasing the borrow) and the bus must destruct LAST. Reordering
    // produces a SIGTERM-during-publish UAF that only surfaces under
    // chaos. Compile-time enforcement was tried (offsetof) but the
    // class is non-standard-layout — offsetof is conditionally
    // supported and emits warnings. This comment is the contract
    // (governance round arch-N1 / UP-A13). Code reviewers — grep
    // [BUS-BEFORE-TRACKER] before approving any change to this block.
    std::unique_ptr<ApprovalManager> approval_manager_;
    std::unique_ptr<ScheduleEngine> schedule_engine_;

    // Phase 3: Security & RBAC
    std::unique_ptr<RbacStore> rbac_store_;
    std::unique_ptr<ManagementGroupStore> mgmt_group_store_;
    std::unique_ptr<ApiTokenStore> api_token_store_;
    std::unique_ptr<QuarantineStore> quarantine_store_;
    std::unique_ptr<PolicyStore> policy_store_;
    std::unique_ptr<GuaranteedStateStore> guaranteed_state_store_;
    std::unique_ptr<AuthRoutes> auth_routes_;
    std::unique_ptr<RestApiV1> rest_api_v1_;
    std::unique_ptr<SettingsRoutes> settings_routes_;
    std::unique_ptr<mcp::McpServer> mcp_server_;
    std::unique_ptr<ComplianceRoutes> compliance_routes_;
    std::unique_ptr<DashboardRoutes> dashboard_routes_;
    std::unique_ptr<WorkflowRoutes> workflow_routes_;
    std::unique_ptr<NotificationRoutes> notification_routes_;
    std::unique_ptr<WebhookRoutes> webhook_routes_;
    std::unique_ptr<OffloadRoutes> offload_routes_;
    std::unique_ptr<DiscoveryRoutes> discovery_routes_;

    // Phase 7: Runtime config, custom properties, health monitoring, workflows, product packs
    std::unique_ptr<RuntimeConfigStore> runtime_config_store_;
    std::unique_ptr<CustomPropertiesStore> custom_properties_store_;
    std::unique_ptr<WorkflowEngine> workflow_engine_;
    std::unique_ptr<ProductPackStore> product_pack_store_;
    std::chrono::steady_clock::time_point server_start_time_{std::chrono::steady_clock::now()};
    detail::ProcessHealthSampler process_health_sampler_;

    // Notification & Webhook stores
    std::unique_ptr<NotificationStore> notification_store_;
    std::unique_ptr<WebhookStore> webhook_store_;
    std::unique_ptr<OffloadTargetStore> offload_target_store_;

    // Phase 7: Inventory Store (Issue 7.17)
    std::unique_ptr<InventoryStore> inventory_store_;

    // Phase 7: Directory Sync (AD/Entra) & Patch Manager
    std::unique_ptr<DirectorySync> directory_sync_;
    std::unique_ptr<PatchManager> patch_manager_;

    // Phase 7: Deployment Jobs (Issue 7.7) & Discovery (Issue 7.18)
    std::unique_ptr<DeploymentStore> deployment_store_;
    std::unique_ptr<DiscoveryStore> discovery_store_;

    // Fleet health aggregation
    detail::AgentHealthStore health_store_;
    std::thread health_recompute_thread_;

    // Periodic reminder when running with --insecure-skip-client-verify (issue #79)
    std::thread insecure_tls_reminder_thread_;

    std::atomic<bool> stop_requested_{false};
    std::atomic<bool> stop_entered_{false};
    std::atomic<bool> draining_{false};

    // Rate limiting
    RateLimiter api_rate_limiter_;
    RateLimiter login_rate_limiter_;
};

// -- Factory ------------------------------------------------------------------

std::unique_ptr<Server> Server::create(Config config, auth::AuthManager& auth_mgr) {
    return std::make_unique<ServerImpl>(std::move(config), auth_mgr);
}

} // namespace yuzu::server
