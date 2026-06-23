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
#include "ca_routes.hpp"
#include "ca_store.hpp"
#include "default_certs.hpp"
#include "key_provider.hpp"
#include "x509_ca.hpp"
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
#include "offline_endpoint_store.hpp"
#include "pg/pg_pool.hpp"
// Visualization engine consumers live in dashboard_routes.cpp (#589) and
// rest_api_v1.cpp; server.cpp no longer references the engine directly.
#include "management.grpc.pb.h"
#include "management_group_store.hpp"
#include "notification_store.hpp"
#include "nvd_db.hpp"
#include "policy_store.hpp"
#include "guaranteed_state_store.hpp"
#include "baseline_store.hpp"
#include "guardian_push_builder.hpp"
#include "guaranteed_state.pb.h"
#include "product_pack_store.hpp"
#include "nvd_sync.hpp"
#include "oidc_provider.hpp"
#include "quarantine_store.hpp"
#include "result_set_matcher.hpp"
#include "result_set_store.hpp"
#include "result_sets_ui.hpp"
#include "scope_yaml.hpp"
#include "rbac_store.hpp"
#include "response_store.hpp"
#include "mcp_jsonrpc.hpp"
#include "auth_routes.hpp"
#include "compliance_routes.hpp"
#include "guardian_routes.hpp"
#include "dex_alert_router.hpp"
#include "dex_blast_radius.hpp"
#include "dex_perf_rules.hpp"
#include "dex_routes.hpp"
#include "network_perf_rules.hpp"
#include "network_routes.hpp"
#include "device_routes.hpp"
#include "tar_tree_routes.hpp"
#include "policy_evaluator.hpp"
#include "dashboard_routes.hpp"
#include "discovery_routes.hpp"
#include "fleet_topology_store.hpp"
#include "heartbeat_ingestion.hpp"
#include "fleet_topology_types.hpp"
#include "mcp_server.hpp"
#include "notification_routes.hpp"
#include "offload_routes.hpp"
#include "rest_api_v1.hpp"
#include "settings_routes.hpp"
#include "viz_routes.hpp"
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
#include "cidr_match.hpp"
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
#include <optional>
#include <shared_mutex>
#include <ranges>
#include <set>
#include <string>
#include <utility>
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
extern const char* const kVizFleetPageHtml; // server/core/src/viz_page_ui.cpp (PR 5)
extern const char* const kVizHostPageHtml;  // server/core/src/viz_host_page_ui.cpp (PR 9-pre)
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
extern const std::string kThreeJs;   // server/core/vendor/three.module.min.js (MIT, three.js r168)
extern const std::string
    kThreeOrbitControlsJs; // server/core/vendor/three-orbit-controls.js (MIT, three.js r168)
extern const std::string
    kYuzuVizJs; // server/core/src/yuzu_viz_js_bundle.cpp (PR 5 fleet renderer module)
extern const std::string kYuzuVizHostJs; // server/core/src/yuzu_viz_host_js_bundle.cpp (PR 9-pre)
extern const std::string kCytoscapeJs;   // Cytoscape.js 3.33.3 ESM (MIT)
extern const std::string_view
    kInterVariableWoff2; // server/core/vendor/inter/InterVariable.woff2 (SIL OFL)
extern const std::vector<std::string>
    kBundledDefinitions;                            // build-time embed of content/definitions/
extern const std::vector<std::string> kBundledSets; // build-time embed of content/packs/*sets*
} // namespace yuzu::server

namespace yuzu::server {

namespace detail {

// RAII guard that zeroes a std::string's bytes on scope exit (incl. exception
// unwind). Used wherever a private key is transiently materialised — the CA
// signing + CRL paths — so the crown jewel is not left in freed heap. (DRYs the
// formerly-duplicated local KeyZero structs — gov cpp-expert SHOULD.)
struct ScopedKeyZero {
    std::string& s;
    ~ScopedKeyZero() { yuzu::secure_zero(s); }
};

// Neutralise a value for safe interpolation into a STRUCTURED `k=v k=v` audit
// detail string (#1290 Hermes MEDIUM). agent_id is only length-bounded at the
// Register gate — never charset-checked — and is audited verbatim. Without this,
// an agent_id like `x via=direct` could forge the very `via=` discriminator
// #1290 adds (field confusion), and a CRLF could split the audit line. The
// canonical implementation now lives in web_utils.hpp so the same neutralizer
// guards every structured-audit call site (here + tar_tree_routes.cpp) without
// the rule drifting; this `using` keeps the existing `detail::audit_token(...)`
// spellings below resolving unchanged.
using yuzu::server::audit_token;

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
        metrics_.describe("yuzu_server_default_certs_active",
                          "1 when running with built-in per-install default certificates, else 0",
                          "gauge");
        metrics_.describe("yuzu_server_cert_expiry_timestamp_seconds",
                          "Unix timestamp (seconds) at which a server certificate expires, by "
                          "cert label. The yuzu-tls alert rules fire on (value - time()) < window.",
                          "gauge");
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
        // PostgreSQL substrate pool metrics (#1320 PR 3 / #1368 observability).
        // Gauges are sampled every recompute cycle; counters/histogram are fed
        // live by the pool's observer hooks wired at pool construction.
        metrics_.describe("yuzu_pg_pool_in_use", "PostgreSQL pool connections currently leased out",
                          "gauge");
        metrics_.describe("yuzu_pg_pool_open",
                          "PostgreSQL pool connections currently open (leased + idle)", "gauge");
        metrics_.describe("yuzu_pg_pool_size", "PostgreSQL pool configured maximum size", "gauge");
        metrics_.describe("yuzu_pg_pool_waiters",
                          "Threads currently blocked waiting for a PostgreSQL pool connection — "
                          "the saturation signal between fully-leased and an acquire timeout",
                          "gauge");
        metrics_.describe("yuzu_pg_connect_failed_total",
                          "Total PostgreSQL connection attempts that failed", "counter");
        metrics_.describe("yuzu_pg_acquire_timeout_total",
                          "Total PostgreSQL pool acquires that timed out before a connection was "
                          "available",
                          "counter");
        metrics_.describe("yuzu_pg_unhealthy_discard_total",
                          "Total PostgreSQL connections discarded as unhealthy on return", "counter");
        metrics_.describe("yuzu_pg_acquire_wait_seconds",
                          "Wall time spent waiting to acquire a PostgreSQL pool connection — the "
                          "leading pool-saturation indicator",
                          "histogram");
        // Fleet health metrics (aggregated from agent heartbeat status_tags)
        metrics_.describe("yuzu_fleet_agents_healthy",
                          "Number of agents reporting healthy via heartbeat", "gauge");
        metrics_.describe("yuzu_fleet_agents_dex_observer_disarmed",
                          "Windows agents (DEX enabled) reporting their DEX signal observer is not "
                          "fully healthy (no channel armed, or a channel subscription dropped at "
                          "runtime) — >0 means reliability telemetry is off or degraded on that "
                          "many endpoints. (Per-channel partial-arm granularity is a follow-up; "
                          "today this is the agent's own health flag.)",
                          "gauge");
        metrics_.describe("yuzu_fleet_dex_observed_total",
                          "Fleet-wide DEX signals observed (crashes, hangs, service failures, "
                          "boot reports, …; sum of agent-reported counts since each agent "
                          "started)", "gauge");
        // D3 blast-radius detector observability (gov SRE OBS-1 / compliance S1).
        metrics_.describe("yuzu_server_dex_blast_radius_incidents_total",
                          "Fleet-incident alerts fired (≥min_devices distinct devices, same "
                          "obs_type+subject, within the window)", "counter");
        metrics_.describe("yuzu_server_dex_blast_radius_fires_dropped_total",
                          "Incident fires suppressed by the global per-minute fan-out rate cap",
                          "counter");
        metrics_.describe("yuzu_server_dex_blast_radius_entries_dropped_total",
                          "Sightings dropped because the global tracked-entry memory budget was "
                          "exhausted", "counter");
        metrics_.describe("yuzu_server_dex_blast_radius_pairs_evicted_total",
                          "(obs_type,subject) pairs LRU-evicted to admit a new pair at the cap",
                          "counter");
        metrics_.describe("yuzu_server_dex_blast_radius_pairs_tracked",
                          "Current count of tracked (obs_type,subject) pairs", "gauge");
        // F2a PR3: per-cohort fleet perf gauges (exported only when the operator
        // sets a cohort export tag key in Settings → DEX alerts; absent otherwise).
        metrics_.describe("yuzu_fleet_perf_cohort_cpu_pct",
                          "Per-cohort device CPU utilization % (avg/p50/p90/max by {stat}; "
                          "cohorts of the configured export tag key, ≥10 reporting devices)",
                          "gauge");
        metrics_.describe("yuzu_fleet_perf_cohort_commit_pct",
                          "Per-cohort memory commit-charge % (avg/p50/p90/max by {stat})",
                          "gauge");
        metrics_.describe("yuzu_fleet_perf_cohort_disk_lat_ms",
                          "Per-cohort disk per-IO service time ms (avg/p50/p90/max by {stat})",
                          "gauge");
        metrics_.describe("yuzu_fleet_perf_cohort_reporting",
                          "Devices contributing perf samples per exported cohort", "gauge");
        metrics_.describe("yuzu_fleet_perf_cohort_clipped",
                          "Exportable cohorts dropped by the top-50 cardinality cap this sweep "
                          "(0 = nothing clipped; absent = export disabled)", "gauge");
        // F1 alert-router observability (uniform yuzu_server_dex_alert_* prefix).
        metrics_.describe("yuzu_server_dex_alert_fired_total",
                          "Operator-routed per-signal alerts fired (notification + dex.signal "
                          "webhook event)", "counter");
        metrics_.describe("yuzu_server_dex_alert_delivery_failed_total",
                          "Routed alerts whose sink (notification/webhook) threw — fired but not "
                          "delivered; the cooldown is already armed so the alert is lost until the "
                          "next episode", "counter");
        metrics_.describe("yuzu_server_dex_alert_suppressed_total",
                          "Routed sightings silenced by the per-(type,agent) cooldown", "counter");
        metrics_.describe("yuzu_server_dex_alert_dropped_total",
                          "Routed alerts dropped by the global per-minute fan-out cap", "counter");
        metrics_.describe("yuzu_server_dex_alert_cooldowns_evicted_total",
                          "Cooldown entries evicted at the capacity bound", "counter");
        metrics_.describe("yuzu_server_dex_alert_routed_types",
                          "Number of obs_types currently routed to alerts", "gauge");
        metrics_.describe("yuzu_fleet_agents_by_os", "Connected agents by operating system",
                          "gauge");
        metrics_.describe("yuzu_fleet_agents_by_arch", "Connected agents by CPU architecture",
                          "gauge");
        metrics_.describe("yuzu_fleet_agents_by_version", "Connected agents by agent version",
                          "gauge");
        metrics_.describe("yuzu_fleet_commands_executed_total",
                          "Fleet-wide commands executed (sum of agent-reported counts)", "gauge");
        // A4 fleet device-utilization rollup (heartbeat perf tags; absent when
        // no agent reports — never a fabricated zero).
        metrics_.describe("yuzu_fleet_perf_reporting",
                          "Agents whose latest heartbeat carried at least ONE perf tag — the "
                          "same any-of-three definition the /dex Performance tab's Reporting "
                          "card uses, so the two always agree. Each per-metric gauge may cover "
                          "a SUBSET of this population (its {stat} series carry their own n via "
                          "the tab/REST; e.g. agents on virtual disks that don't answer "
                          "IOCTL_DISK_PERFORMANCE omit the disk-latency tag)", "gauge");
        metrics_.describe("yuzu_fleet_perf_cpu_pct",
                          "Fleet device CPU busy % over each agent's last heartbeat interval, "
                          "by {stat}: avg / nearest-rank p50 / p90 / max", "gauge");
        metrics_.describe("yuzu_fleet_perf_commit_pct",
                          "Fleet commit-charge % of limit (memory pressure), by {stat}: "
                          "avg / p50 / p90 / max", "gauge");
        metrics_.describe("yuzu_fleet_perf_disk_lat_ms",
                          "Fleet per-IO disk service time in ms, by {stat}: avg / p50 / p90 / max",
                          "gauge");
        // Network rollup (slice 3; heartbeat net facts, absent when no agent
        // reports — never a fabricated zero). Same shared validators as the
        // /network read model (per-device parity); the gauges are split per `os`
        // while the page is OS-blended, so a mixed-fleet aggregate differs by
        // design (Windows + Linux retransmit rates are not comparable).
        metrics_.describe("yuzu_fleet_net_reporting",
                          "Agents (per `os`) whose latest heartbeat carried at least ONE network "
                          "fact — the same any-of definition the /network Overview's Reporting card "
                          "uses", "gauge");
        metrics_.describe("yuzu_fleet_net_retrans_reporting",
                          "Agents (per `os`) that contributed an interval retransmit RATE to the "
                          "gauge this cycle (a subset of net_reporting{os}). Denominator for "
                          "net_retrans_pct{stat,os}. Loss-validated OSes only (Linux today) — a "
                          "Windows device reports a retransmit fact but it is withheld from the "
                          "gauge (#1465), so Windows is absent here", "gauge");
        metrics_.describe("yuzu_fleet_net_degraded",
                          "DORMANT (measurement-first), per `os`: absent unless an agent still emits "
                          "the retired net_degraded tag (e.g. mid rolling-upgrade). A degraded "
                          "classification needs real-fleet baseline calibration (a later slice) — "
                          "treat ABSENT as 'not classified', never 0 as 'healthy'", "gauge");
        metrics_.describe("yuzu_fleet_net_rtt_ms",
                          "Fleet smoothed round-trip time in ms, by {stat,os}: avg / p50 / p90 / max "
                          "(reported by Linux only today, so os=\"linux\" is the only series)",
                          "gauge");
        metrics_.describe("yuzu_fleet_net_retrans_pct",
                          "Fleet TCP retransmit rate %, by {stat,os}: avg / p50 / p90 / max. INTERVAL "
                          "rate (interval delta of retransmits / segments over recent heartbeats), "
                          "not the lifetime ratio. Loss-validated OSes only: Linux (netem-validated). "
                          "The Windows rate is system-wide (loopback-inclusive, biased low, "
                          "unvalidated #1465) and is WITHHELD here — it shows on the /network page + "
                          "REST until validated. Never alert on a cross-OS aggregate", "gauge");
        metrics_.describe("yuzu_fleet_net_throughput_bps",
                          "Fleet device network throughput in bytes/s, by {stat,os}: avg / p50 / p90 "
                          "/ max", "gauge");
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
        // gov PR-E OBS-2: a from_result_set: scope ref resolved to an
        // absent/expired/not-owned set at dispatch. Audit rows are not
        // Prometheus-alertable; this counter makes the failure mode (silent
        // under-scope to zero targets) visible to an on-call SRE.
        metrics_.describe("yuzu_scope_resolution_failed_total",
                          "from_result_set: scope references that failed owner-checked "
                          "resolution at dispatch (set absent, expired, or not owned)",
                          "counter");
        // Audit-pipeline observability (governance PR4 OBS-4). Increments when
        // audit_store->add_event()'s SQLite step does not return DONE — pages
        // operators that the audit chain itself is degraded.
        metrics_.describe("yuzu_server_audit_emit_failed_total",
                          "Audit events that failed to persist (sqlite3_step != DONE)", "counter");
        // PR W1.1 sre-1 (gov Gate 6, sre): CSPRNG-failure paging signal.
        // Increments in the token-create handlers (api_token, device_token)
        // when `secure_random::fill_random` returns prng_failure (entropy
        // exhaustion). Operators wire a Prometheus rule like
        //   rate(yuzu_secure_random_failure_total[5m]) > 0
        // to page on-call short of grepping audit logs.
        metrics_.describe("yuzu_secure_random_failure_total",
                          "CSPRNG (RAND_bytes / BCryptGenRandom) failures during token "
                          "issuance, labelled by reason and call site",
                          "counter");
        // W1.3 (#826 + #1052 + #1053): device-token rejection counters.
        // Three high-signal variants each get their own counter so SRE
        // can alert directly without a labels selector. The remaining
        // variants bucket under yuzu_device_token_rejected_total{variant=...}
        // so they're still visible without flooding paging surface.
        // Alert recipes:
        //   rate(yuzu_device_token_binding_mismatch_total[5m]) > 0
        //     — stolen-token impersonation attempt in progress (#826)
        //   rate(yuzu_device_token_unbound_legacy_total[5m]) > 0
        //     — legacy any-device token is being presented; rotate
        //   rate(yuzu_device_token_revoked_attempt_total[5m]) > 0
        //     — revoked token replay; investigate originating IP
        metrics_.describe("yuzu_device_token_binding_mismatch_total",
                          "Device-token presenter did not match the bound device_id "
                          "(#826 stolen-token impersonation attempt)",
                          "counter");
        metrics_.describe("yuzu_device_token_unbound_legacy_total",
                          "Device-token validation refused because the stored row has "
                          "empty device_id (W1.2 R2 HIGH-1/HIGH-2 — pre-#824 legacy)",
                          "counter");
        metrics_.describe("yuzu_device_token_revoked_attempt_total",
                          "Replay attempt against a revoked device token", "counter");
        metrics_.describe("yuzu_device_token_rejected_total",
                          "Low-signal device-token validation rejections (not_found, "
                          "expired, invalid_input, internal_error), labelled by variant",
                          "counter");
        // W1.4 / #827: enrollment-token race-loss counter. Fires when two
        // agents concurrently presented the same one-time enrollment token
        // and the second consumer lost the atomic-claim race. Each
        // increment is one credential-leak signal — a non-zero rate over
        // 5 min means a leaked enrollment token is in active use by more
        // than one party. Alert recipe:
        //   rate(yuzu_enrollment_token_race_lost_total[5m]) > 0
        // Audit row with `variant=already_consumed already_consumed_by=
        // <agent_id>` accompanies each increment.
        metrics_.describe("yuzu_enrollment_token_race_lost_total",
                          "Enrollment-token consume lost the atomic-claim race "
                          "(#827 — leaked token presented by a second agent)",
                          "counter");
        // Low-signal enrollment-token rejection bucket. Variants are
        // `not_found`, `revoked`, `expired`, `invalid_input`,
        // `invalid_input_length`, `internal_error`. The high-signal
        // `already_consumed` variant has its own dedicated counter above
        // so SRE can page on race-loss without a label selector.
        metrics_.describe("yuzu_enrollment_token_rejected_total",
                          "Low-signal enrollment-token validation rejections "
                          "(not_found, revoked, expired, invalid_input, "
                          "invalid_input_length, internal_error), labelled by variant",
                          "counter");
        // #826 sec-S1: Subscribe peer-mismatch rejections, labelled by
        // gateway_mode so an operator can distinguish "agent reconnected
        // from a new IP" (steady state in gateway deployments) from
        // "stolen session_id in non-gateway deployment" (active attack).
        metrics_.describe("yuzu_grpc_subscribe_peer_mismatch_total",
                          "Subscribe RPC rejected because the peer IP differs from the "
                          "Register peer IP and is not a trusted gateway (stolen-session "
                          "signal, #1059). Labelled event=security (SIEM-routing tag — "
                          "Splunk et al. ingest via their Prometheus receiver and filter "
                          "on event) and gateway_mode (true|false)",
                          "counter");
        metrics_.describe("yuzu_grpc_subscribe_identity_mismatch_total",
                          "Subscribe RPC rejected because the mTLS client identity does not "
                          "match the identity bound at Register time (stolen-session signal, "
                          "#1118). Labelled event=security (SIEM-routing tag)",
                          "counter");
        // PKI PR3: an agent-initiated RPC rejected because the presented client
        // leaf's serial is on the internal CA's revocation list (ca.db). A revoked
        // agent that keeps calling is a decommissioned/compromised-credential
        // signal. Labelled by rpc (subscribe|heartbeat|download_update) so an
        // operator can see a revoked agent trying every surface, not just the
        // command channel.
        metrics_.describe("yuzu_grpc_revoked_cert_total",
                          "Agent RPC rejected because the presented client certificate has been "
                          "revoked against the internal CA (PKI PR3). Labelled event=security "
                          "(SIEM-routing tag) and rpc (subscribe|heartbeat|download_update)",
                          "counter");
        // PKI PR3: per-agent client certificates signed at enrollment. A spike is
        // an enrollment storm (mass deploy) or, if sustained, a CSR-flood signal.
        metrics_.describe("yuzu_server_ca_cert_issued_total",
                          "Per-agent client certificates issued by the internal CA at agent "
                          "enrollment (PKI PR3). Labelled purpose (agent)",
                          "counter");
        // PKI PR4 (gov sre/unhappy SHOULD): the CRL could not be (re)built/signed —
        // the public CRL is stale relative to ca.db. Alert on >0 since a revocation,
        // since server-side enforcement is live but external consumers are not
        // seeing the revocation. The audit row (ca.crl.published failure) is the
        // forensic pair; this counter is the real-time alert source.
        metrics_.describe("yuzu_server_ca_crl_publish_failures_total",
                          "Internal-CA CRL (re)publish failures (key load / build / record). A "
                          "non-zero value since a revocation means the public CRL is stale (PKI PR4)",
                          "counter");
        // #1128: a peer-IP mismatch that was TOLERATED (not rejected) because a
        // NAT-aware accommodation applied. Paired with _peer_mismatch_total
        // (rejects): a spike here without a matching reject spike is benign
        // multi-egress churn; a spike in BOTH is worth investigating. reason
        // distinguishes the accommodation that fired.
        metrics_.describe("yuzu_grpc_subscribe_peer_advisory_total",
                          "Subscribe RPC peer-IP mismatch tolerated under a NAT-aware "
                          "accommodation instead of rejected (#1128). Labelled event=security "
                          "(SIEM-routing tag) and reason (mtls_identity_match|trusted_nat_cidr)",
                          "counter");
        metrics_.describe("yuzu_register_denied_total",
                          "Register/ProxyRegister rejected an admin-denied agent before "
                          "consuming its enrollment token (#1067). Labelled source "
                          "(direct|gateway_proxy) and event=security (SIEM-routing tag) — a "
                          "persistently-denied identity hammering Register is a "
                          "credential-abuse signal",
                          "counter");
        // Login-latency observability (governance PR4 OBS-2). Histogram of
        // PBKDF2 verify duration, labelled by result so alerts can fire on
        // success-path regressions independently of brute-force noise on
        // bad_password / unknown_user.
        metrics_.describe("yuzu_auth_login_duration_seconds",
                          "Login PBKDF2 verify latency in seconds, by method and result",
                          "histogram");
        // Session-revocation observability (CC7.2 anomaly-detection +
        // capacity planning). Counter labels: caller=admin|self,
        // result=success|partial|denied, scope=cookies|all (all = /me's
        // "Sign out everywhere" which also revokes API tokens).
        metrics_.describe("yuzu_auth_sessions_revoked_total",
                          "Total session revocations, by caller, result, and scope", "counter");
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
        metrics_.describe("yuzu_server_guardian_events_dropped_total",
                          "Cumulative Guaranteed-State events dropped at ingest on an event_id "
                          "PK/UNIQUE conflict (redelivery, agent event_seq_ reset, clock skew, or "
                          "a forged-id pre-claim #1360). >0 distinguishes 'no drift' from 'drift "
                          "silently discarded' (CC7.3 evidence gap #1414).",
                          "counter");
        metrics_.describe("yuzu_server_guardian_events_reaped_total",
                          "Cumulative Guaranteed-State events deleted by the retention reaper",
                          "counter");
        metrics_.describe("yuzu_server_guardian_proj_failures_total",
                          "DEX observation projection failures. The source event is preserved "
                          "(degrade-don't-destroy); only the derived guardian_observations read "
                          "model row is lost. >0 means /dex is under-counting — investigate "
                          "(commonly a stale-schema dev DB; see docs/user-manual/dex.md).",
                          "counter");
        metrics_.describe("yuzu_server_guardian_observations_reaped_total",
                          "Cumulative DEX observation rows deleted by the retention reaper "
                          "(disposal evidence for the behavioral-PII projection, WS-E)", "counter");
        metrics_.describe("yuzu_server_guardian_baselines_total",
                          "Total Guardian Baselines persisted", "gauge");
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
        // W5.1 — endpoint-scoped agentic SSE metrics. Distinct from the
        // bus-level yuzu_server_sse_* family above: those measure the
        // ExecutionEventBus regardless of consumer, these measure the
        // /api/v1/events handler specifically (label `route="events"`).
        // governance R2 fix for consistency-MED (missing describe()
        // calls left /metrics output without # HELP / # TYPE).
        metrics_.describe("yuzu_server_sse_api_subscriptions_total",
                          "Cumulative successful subscribes on /api/v1/events "
                          "(labelled by route)",
                          "counter");
        metrics_.describe("yuzu_server_sse_api_active",
                          "Live /api/v1/events subscriptions currently held by "
                          "httplib worker threads (labelled by route). Alert on "
                          "saturation of the configured worker pool size.",
                          "gauge");
        metrics_.describe("yuzu_server_sse_api_queue_overflow_total",
                          "Cumulative events dropped from per-connection /api/v1/events "
                          "queues (kPerConnectionQueueCapDefault overflow; slow-consumer "
                          "backpressure on the route-side queue, distinct from the "
                          "bus-level yuzu_server_sse_events_dropped_total).",
                          "counter");
        metrics_.describe("yuzu_server_sse_api_replay_gap_total",
                          "Cumulative /api/v1/events connections that received a "
                          "synthetic replay-gap envelope because the bus ring buffer "
                          "had already evicted events the client requested via ?since "
                          "or Last-Event-ID.",
                          "counter");
        // Fleet visualization observability (PR 3 + PR 6 of feat/viz-engine).
        // gov R6 SRE OBS-1: every metric has a describe() so /metrics
        // includes # HELP and # TYPE lines for Prometheus / Grafana scrapers.
        metrics_.describe("yuzu_viz_topology_request_seconds",
                          "End-to-end /api/v1/viz/fleet/topology request latency", "histogram");
        metrics_.describe("yuzu_viz_topology_fetch_duration_seconds",
                          "Inner agent-dispatch (tar.fleet_snapshot fan-out) duration "
                          "on cache-miss refills only; observed even on fetcher exception",
                          "histogram");
        metrics_.describe("yuzu_viz_cache_hit_total",
                          "Fleet topology requests served from the FleetTopologyStore cache",
                          "counter");
        metrics_.describe("yuzu_viz_cache_miss_total",
                          "Fleet topology requests that triggered a cache refill", "counter");
        metrics_.describe("yuzu_viz_oversize_response_total",
                          "Fleet topology requests rejected with HTTP 413 (machines_max breached)",
                          "counter");
        metrics_.describe("yuzu_viz_offline_hosts_total",
                          "Stale-flagged offline hosts merged into /viz/fleet from the durable "
                          "OfflineEndpointStore (hosts that aged out of the in-memory snapshot)",
                          "counter");
        metrics_.describe("yuzu_viz_agent_dispatch_timeout_total",
                          "Per-agent timeouts during tar.fleet_snapshot fan-out", "counter");
        metrics_.describe("yuzu_viz_refill_oversize_drops_total",
                          "Refills exceeding max_snapshot_bytes (returned to caller, not cached)",
                          "gauge");
        metrics_.describe("yuzu_viz_refill_wait_timeouts_total",
                          "Single-flight waiters that timed out before the refill completed",
                          "gauge");
        metrics_.describe("yuzu_viz_refill_waiters_total",
                          "Fetch waiters that piggybacked on an in-flight refill", "gauge");
        // PR 10 hardening — push-ingestion metrics. `via` label
        // distinguishes the direct HeartbeatRequest path from the
        // gateway BatchHeartbeat path; sum across the label set to
        // get fleet-wide push volume.
        metrics_.describe("yuzu_viz_topology_pushed_total",
                          "Agent-pushed fleet_snapshot.v1 payloads accepted into the "
                          "FleetTopologyStore via heartbeat. Labelled by via=direct|gateway.",
                          "counter");
        metrics_.describe("yuzu_viz_topology_push_parse_errors_total",
                          "Agent-pushed fleet_snapshot.v1 payloads rejected by the shared "
                          "parser (oversized, row-cap exceeded, malformed JSON). Labelled "
                          "by via=direct|gateway.",
                          "counter");
        metrics_.describe("yuzu_viz_local_edges_dropped_total",
                          "EdgeScope::Local connection edges dropped from the snapshot "
                          "before serialisation because no reciprocal half was visible in "
                          "the same agent payload (PR 8). Non-zero under normal churn; a "
                          "spike vs steady-state indicates systematic loss (kernel race, "
                          "agent connection-cap truncation, half-open sockets).",
                          "gauge");
        // Gate 7 sre OBS-1/OBS-2/OBS-3 — push-ingestion failure modes were
        // previously dark (no Prometheus exposure). A non-zero rate on the
        // first two is operator-actionable: a rejection spike means an
        // IP-spoof campaign or a NAT/DHCP misconfiguration; a cap-eviction
        // spike means the fleet outgrew kPushedMapHardCap (or a cap-flood
        // attack). pushed_map_size is the memory-pressure gauge to alert on
        // before evictions begin.
        metrics_.describe("yuzu_viz_topology_push_rejected_total",
                          "Agent fleet_snapshot pushes rejected by the UP-1 IP-spoof guard "
                          "(claimed local_ip owned by a live agent). Non-zero signals a "
                          "spoofing campaign or NAT/DHCP misconfiguration.",
                          "gauge");
        metrics_.describe("yuzu_viz_pushed_cap_evictions_total",
                          "FleetTopologyStore pushed_ entries evicted because the map was at "
                          "kPushedMapHardCap when a new agent pushed (CAP-1 LRU). Non-zero "
                          "means the fleet outgrew the cap or a cap-flood attack is evicting "
                          "legitimate agents.",
                          "gauge");
        metrics_.describe("yuzu_viz_pushed_map_size",
                          "Current occupancy of the FleetTopologyStore pushed_ map. Primary "
                          "memory-pressure signal — alert before it approaches "
                          "kPushedMapHardCap (100000).",
                          "gauge");

        // Wire health store into agent service
        agent_service_.set_health_store(&health_store_);

        // #1128: NAT-aware Subscribe binding — operator-declared multi-egress
        // CIDRs. Empty (default) keeps the strict exact-match peer binding.
        // gov UP-9: fail-loud on a mistyped CIDR rather than silently treating
        // it as a range that matches nothing (operator would believe the
        // relaxation is active when it isn't).
        if (!cfg_.trusted_nat_cidrs.empty()) {
            std::size_t valid_cidrs = 0;
            for (const auto& cidr : cfg_.trusted_nat_cidrs) {
                if (yuzu::server::detail::is_valid_cidr(cidr))
                    ++valid_cidrs;
                else
                    spdlog::warn("--trusted-nat-cidr: ignoring malformed CIDR '{}' (not a valid "
                                 "IPv4/IPv6 network) — agents will NOT be matched against it",
                                 cidr);
            }
            spdlog::info("--trusted-nat-cidr: {} valid, {} invalid of {} configured range(s)",
                         valid_cidrs, cfg_.trusted_nat_cidrs.size() - valid_cidrs,
                         cfg_.trusted_nat_cidrs.size());
        }
        if (cfg_.nat_trust_mtls_identity)
            // warn-level (gov chaos CH-3 / UP-2): this flag intentionally
            // relaxes a security control, so the visibility budget is the same
            // as --no-tls's ERROR banner — info-level would lose the line in a
            // multi-thousand-line boot log piped to a file, exactly the path
            // most production operators use.
            spdlog::warn("--nat-trust-mtls-identity enabled: mTLS-identity match will relax the "
                         "Subscribe peer-IP binding. Ensure client certs are PER-AGENT (a shared "
                         "fleet-wide cert makes this a session-replay bypass — gov UP-2).");
        agent_service_.set_trusted_nat_cidrs(cfg_.trusted_nat_cidrs);
        agent_service_.set_nat_trust_mtls_identity(cfg_.nat_trust_mtls_identity);

        // Wire metrics registry into auth manager so authenticate() can
        // observe login latency. Optional in tests/CLI tools that don't
        // construct a ServerImpl (auth_mgr_.metrics_ stays nullptr there).
        auth_mgr_.set_metrics_registry(&metrics_);

        // Create gateway upstream service if configured
        if (!cfg_.gateway_upstream_address.empty()) {
            gateway_service_ = std::make_unique<detail::GatewayUpstreamServiceImpl>(
                registry_, event_bus_, auth_mgr, auto_approve_, &metrics_, &health_store_);
        }

        // Gateway command-forwarding client (gw_mgmt_channel_/gw_mgmt_stub_) is
        // built in run(), AFTER bootstrap_default_certs() — for a default-cert
        // install the client cert/key paths are empty here and only populated by
        // the bootstrap, and the mutual-TLS dial (HIGH-2 #1314) needs them. Same
        // pre-bootstrap-empty reason the per-agent mTLS wiring is deferred to run().

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

        // PostgreSQL substrate (ADR-0006/0007): one shared pool, constructed
        // BEFORE any Postgres-backed store and validated by a probe checkout so
        // the server FAILS CLOSED — no SQLite fallback — when the DSN is empty
        // or the database is unreachable. The observer hooks feed the pool's
        // saturation/health metrics and capture &metrics_, which outlives the
        // pool (declaration order). A distinct "[PG] Refusing to start" log
        // token separates a substrate failure from other startup failures.
        {
            if (cfg_.postgres_dsn.empty()) {
                spdlog::error("[PG] Refusing to start: no PostgreSQL DSN. Set --postgres-dsn / "
                              "YUZU_POSTGRES_DSN (ADR-0006/0007 — the server requires Postgres; "
                              "the agent stays SQLite).");
                startup_failed_ = true;
            } else {
                pg::PgPool::Options opts;
                opts.conninfo = cfg_.postgres_dsn;
                opts.size = cfg_.postgres_pool_size > 0
                                ? static_cast<std::size_t>(cfg_.postgres_pool_size)
                                : 16;
                opts.observer.on_connect_failure = [this] {
                    metrics_.counter("yuzu_pg_connect_failed_total").increment();
                };
                opts.observer.on_acquire_timeout = [this] {
                    metrics_.counter("yuzu_pg_acquire_timeout_total").increment();
                };
                opts.observer.on_unhealthy_discard = [this] {
                    metrics_.counter("yuzu_pg_unhealthy_discard_total").increment();
                };
                opts.observer.on_acquire_wait_seconds = [this](double s) {
                    metrics_.histogram("yuzu_pg_acquire_wait_seconds").observe(s);
                };
                pg_pool_ = std::make_unique<pg::PgPool>(std::move(opts));
                // Probe: a live checkout proves reachability and warms one
                // connection. Bounded by connect_timeout_s; an empty lease means
                // an invalid DSN or an unreachable database — fail closed.
                if (auto probe = pg_pool_->acquire(); !probe) {
                    spdlog::error("[PG] Refusing to start: cannot reach PostgreSQL substrate: {}",
                                  pg_pool_->last_error());
                    startup_failed_ = true;
                } else {
                    spdlog::info("[PG] PostgreSQL substrate connected (pool size {})",
                                 pg_pool_->size());
                }
            }
        }

        // First born-on-Postgres store (#1320 PR 3): last-known endpoint state,
        // so offline hosts render stale-flagged on /viz/fleet. Only built when
        // the substrate probe above succeeded (an unreachable database already
        // set startup_failed_ and run() refuses to serve). FAIL CLOSED on a
        // migration/open failure too (ADR-0007 + the ADR-0008 per-store
        // migration invariant): a reachable database whose schema migration
        // fails — schema conflict, missing CREATE privilege, advisory-lock
        // contention — must NOT serve degraded. This is the template every
        // future Postgres-backed store inherits, so the contract is uniform:
        // a Postgres-backed store that cannot open is a fatal startup error.
        if (pg_pool_ && !startup_failed_) {
            offline_endpoint_store_ = std::make_unique<OfflineEndpointStore>(*pg_pool_);
            if (!offline_endpoint_store_->is_open()) {
                spdlog::error("[PG] Refusing to start: offline-endpoint store migration/open "
                              "failed (database reachable but the endpoint_state schema could "
                              "not be created/opened)");
                startup_failed_ = true;
            }
        }

        // Initialize response store
        {
            auto resp_db = cfg_.db_dir() / "responses.db";
            response_store_ =
                std::make_unique<ResponseStore>(resp_db, cfg_.response_retention_days);
            if (response_store_->is_open()) {
                response_store_->start_cleanup();
            }
        }

        // Seed kill-switch from cfg_; runtime flip path can land later.
        viz_disabled_.store(cfg_.viz_disable, std::memory_order_release);
        if (cfg_.viz_disable) {
            // gov R3 F-1 (compliance): the per-request audit row only fires
            // when a request hits the disabled endpoint. Operators deploying
            // with --viz-disable from boot need a startup-time evidence line
            // confirming the kill-switch took effect. Mirrors the MCP
            // precedent at server.cpp:5161 below.
            spdlog::warn("[VIZ] viz endpoint disabled by configuration "
                         "(--viz-disable / YUZU_VIZ_DISABLE)");
        }

        // Initialize fleet topology store (PR 3 of feat/viz-engine).
        //
        // The fetcher dispatches `tar.fleet_snapshot` to every connected
        // agent on cache miss, polls the response_store for matches keyed
        // on the synthesised command_id, and returns whatever arrived
        // before the deadline. Missing agents come back as stale=true rows
        // so the renderer dims their cubes rather than disappearing them.
        //
        // Notes on integration choices:
        //  * No execution_id is recorded for the fetcher dispatch. The
        //    executions tracker is operator-facing; an automated cache
        //    refill happening every 60s would otherwise spam its history
        //    pane. record_send_time stays so the standard latency
        //    histogram still observes these dispatches (sec-INFO-10:
        //    intentionally opted-out of cmd_execution_ids_).
        //  * forward_gateway_pending() drains commands queued for
        //    gateway-proxied agents so a fleet that mixes direct and
        //    gateway-connected hosts gets uniform dispatch.
        //  * The poll loop sleeps in 100ms increments; a future PR can
        //    swap in the response-arrival event bus when one exists.
        if (response_store_) {
            auto fetcher =
                [this](std::chrono::milliseconds deadline) -> std::vector<RawAgentSnapshot> {
                std::vector<RawAgentSnapshot> out;
                if (!response_store_ || !response_store_->is_open())
                    return out;

                auto agent_ids = registry_.all_ids();
                if (agent_ids.empty())
                    return out;

                // Sibling dispatchers use `<plugin>-<hex>` (server.cpp:2820,
                // 4879, 5014). Stick to that shape so anyone grepping
                // response_store for `tar-` finds viz fetcher dispatches too,
                // and so the `<plugin>-` prefix doesn't lie about the actual
                // wire plugin (gov R3 C-3).
                const auto command_id =
                    "tar-" + auth::AuthManager::bytes_to_hex(auth::AuthManager::random_bytes(8));

                detail::pb::CommandRequest cmd;
                cmd.set_command_id(command_id);
                cmd.set_plugin("tar");
                cmd.set_action("fleet_snapshot");

                agent_service_.record_send_time(command_id);

                std::unordered_set<std::string> dispatched;
                dispatched.reserve(agent_ids.size());
                for (const auto& aid : agent_ids) {
                    if (registry_.send_to(aid, cmd))
                        dispatched.insert(aid);
                }
                forward_gateway_pending();

                if (dispatched.empty())
                    return out;

                // Poll response_store for matching responses until we have
                // one per dispatched agent OR the deadline elapses. Each
                // response carries `instruction_id == command_id` (set by
                // agent_service when the frame arrives -- naming overload
                // we live with).
                const auto t_deadline = std::chrono::steady_clock::now() + deadline;
                std::vector<StoredResponse> matched;
                std::unordered_set<std::string> seen;
                while (std::chrono::steady_clock::now() < t_deadline &&
                       seen.size() < dispatched.size()) {
                    ResponseQuery q;
                    q.limit = static_cast<int>(dispatched.size()) + 16;
                    auto rows = response_store_->query(command_id, q);
                    for (const auto& r : rows) {
                        if (seen.insert(r.agent_id).second)
                            matched.push_back(r);
                    }
                    if (seen.size() >= dispatched.size())
                        break;
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                }

                // Deduplicate by agent_id (one response per agent expected;
                // duplicates ignored).
                std::unordered_set<std::string> have;
                out.reserve(dispatched.size());
                for (const auto& r : matched) {
                    if (!have.insert(r.agent_id).second)
                        continue;
                    // CommandResponse::Status enum: 1 == SUCCESS. Anything
                    // else (FAILURE / TIMEOUT / REJECTED / RUNNING-only-row)
                    // is treated as a stale snapshot for renderer purposes.
                    if (r.status != 1) {
                        RawAgentSnapshot rs;
                        rs.agent_id = r.agent_id;
                        rs.stale = true;
                        if (auto sess = registry_.get_session(r.agent_id)) {
                            rs.os = sess->os;
                            rs.hostname = sess->hostname;
                        }
                        out.push_back(std::move(rs));
                        continue;
                    }
                    // PR 10 hardening — share the parser with the push
                    // ingestion sites so caps + sanitisation + field
                    // set stay in lock-step (arch-B3 / cons-S1).
                    std::string os_from_session, hostname_fallback, parse_err;
                    if (auto sess = registry_.get_session(r.agent_id)) {
                        os_from_session = sess->os;
                        hostname_fallback = sess->hostname;
                    }
                    auto parsed = FleetTopologyStore::parse_fleet_snapshot_json(
                        r.output, r.agent_id, os_from_session, &parse_err);
                    if (parsed.has_value()) {
                        out.push_back(std::move(*parsed));
                    } else {
                        spdlog::warn("FleetTopologyStore fetcher: rejected "
                                     "fleet_snapshot.v1 from {} ({})",
                                     r.agent_id, parse_err);
                        RawAgentSnapshot rs;
                        rs.agent_id = r.agent_id;
                        rs.os = std::move(os_from_session);
                        rs.hostname = std::move(hostname_fallback);
                        rs.stale = true;
                        out.push_back(std::move(rs));
                    }
                }

                // Agents that were dispatched but never responded -> stale
                // entries so the aggregate snapshot still shows them.
                int dispatch_timeouts = 0;
                for (const auto& aid : dispatched) {
                    if (have.contains(aid))
                        continue;
                    RawAgentSnapshot rs;
                    rs.agent_id = aid;
                    rs.stale = true;
                    if (auto sess = registry_.get_session(aid)) {
                        rs.hostname = sess->hostname;
                        rs.os = sess->os;
                    }
                    out.push_back(std::move(rs));
                    ++dispatch_timeouts;
                }
                if (dispatch_timeouts > 0) {
                    metrics_.counter("yuzu_viz_agent_dispatch_timeout_total")
                        .increment(static_cast<double>(dispatch_timeouts));
                }

                return out;
            };

            // 60s TTL, 5s fetch deadline, 256 MiB max snapshot bytes from
            // PR 2 defaults. nvd_db_ may be null if NVD store failed to open;
            // the store handles that gracefully (vuln overlay becomes inert).
            fleet_topology_store_ = std::make_unique<FleetTopologyStore>(
                std::move(fetcher), nvd_db_ ? nvd_db_.get() : nullptr);

            // PR 6 / OBS-2: wire the agent-dispatch duration histogram.
            // Distinguishes "agent dispatch is slow" from "the rest of
            // the request is slow" -- viz_routes.cpp already times the
            // whole HTTP path via yuzu_viz_topology_request_seconds.
            // Captures only on cache miss / refill (warm requests skip
            // the fetcher entirely).
            fleet_topology_store_->set_fetch_duration_observer(
                [this](std::chrono::duration<double> elapsed) {
                    metrics_.histogram("yuzu_viz_topology_fetch_duration_seconds")
                        .observe(elapsed.count());
                });
            // gov R6 SRE OBS-2: log so a future refactor that silently
            // skips the wire-up (re-ordered init, conditional metrics-off
            // mode, etc.) leaves a positive trace operators can grep for
            // when the histogram count fails to increment.
            spdlog::debug("FleetTopologyStore: fetch-duration observer wired "
                          "(yuzu_viz_topology_fetch_duration_seconds)");

            // Gate 7 UP-9 / hp-S1 — roster provider. The push path skips
            // the dispatch fetcher, so a registered agent that has not
            // pushed (legacy build mid rolling-upgrade, TAR plugin off,
            // wedged first-cycle pump) would silently vanish from the
            // topology. The store consults this to emit a stale placeholder
            // cube for every registered-but-unpushed agent. Session-sourced
            // identity only — no agent-controlled JSON.
            fleet_topology_store_->set_roster_provider(
                [this]() -> std::vector<FleetTopologyStore::RosterEntry> {
                    std::vector<FleetTopologyStore::RosterEntry> roster;
                    auto ids = registry_.all_ids();
                    roster.reserve(ids.size());
                    for (const auto& aid : ids) {
                        FleetTopologyStore::RosterEntry e;
                        e.agent_id = aid;
                        if (auto sess = registry_.get_session(aid)) {
                            e.hostname = sess->hostname;
                            e.os = sess->os;
                        }
                        roster.push_back(std::move(e));
                    }
                    return roster;
                });

            // UAT 2026-05-12: wire the store into AgentServiceImpl so a
            // fresh Register() drops both cache slots — eliminates the
            // up-to-60 s "stale ghost cube" window operators saw after
            // server restarts.
            agent_service_.set_fleet_topology_store(fleet_topology_store_.get());
            // PR 10: also wire into the gateway upstream service so
            // BatchHeartbeat ingests pushed snapshots from
            // gateway-routed agents (the path 100% of viz-UAT traffic
            // takes today).
            if (gateway_service_)
                gateway_service_->set_fleet_topology_store(fleet_topology_store_.get());
        }

        // Initialize audit store
        {
            auto audit_db = cfg_.db_dir() / "audit.db";
            audit_store_ = std::make_unique<AuditStore>(audit_db, cfg_.audit_retention_days);
            if (audit_store_->is_open()) {
                audit_store_->start_cleanup();
            }
            // Internal-CA store (ca.db) — cert inventory + CRL versions. The CA
            // root key itself is a 0600 file via default_certs, never in this DB.
            ca_store_ = std::make_unique<CaStore>(cfg_.db_dir() / "ca.db");
            // PR 10 hardening — wire AuditStore into FleetTopologyStore
            // so push success (first-per-agent) and rejections emit
            // AuditEvents (F-1 / CC6.1 / CC7.3 evidence chain). Must
            // run after fleet_topology_store_ AND audit_store_ are
            // both initialised; that ordering is fixed here.
            if (fleet_topology_store_ && audit_store_ && audit_store_->is_open())
                fleet_topology_store_->set_audit_store(audit_store_.get());

            // Gate 7 compliance F-1 — durable evidence that the viz
            // kill-switch took effect. The per-request `kill_switch` audit
            // row in VizRoutes only fires when a request actually hits a
            // disabled endpoint; a cold deployment with --viz-disable and
            // no viz traffic would leave zero audit rows despite the
            // feature being off. Emit one startup AuditEvent so an auditor
            // asking "was viz disabled during window X?" can answer it from
            // the audit store, not just process logs. Emitted here (rather
            // than at the viz_disabled_ seed above) because audit_store_ is
            // only constructed now.
            if (cfg_.viz_disable && audit_store_ && audit_store_->is_open()) {
                AuditEvent ev;
                ev.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                                   std::chrono::system_clock::now().time_since_epoch())
                                   .count();
                ev.principal = "system";
                ev.action = "server.viz_disabled";
                ev.target_type = "FleetTopology";
                ev.target_id = "viz";
                ev.detail = "fleet visualization endpoints disabled at startup "
                            "(--viz-disable / YUZU_VIZ_DISABLE)";
                ev.result = "success";
                (void)audit_store_->log(ev);
            }

            // #802 / W7.4 — mirror the viz-disable audit emission pattern:
            // when the operator has opted out of signed-pack enforcement,
            // emit a startup-time audit row so the relaxed posture is
            // recoverable from the audit store, not only from process logs.
            // Auditors and incident-response queries asking "was unsigned
            // pack acceptance enabled during window X?" can answer from
            // the audit log. The matching `--allow-unsigned-packs` startup
            // warn fires earlier at the ProductPackStore construction
            // site; the audit row fires here because audit_store_ is only
            // constructed at this phase.
            if (cfg_.allow_unsigned_packs && audit_store_ && audit_store_->is_open()) {
                AuditEvent ev;
                ev.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                                   std::chrono::system_clock::now().time_since_epoch())
                                   .count();
                ev.principal = "system";
                ev.action = "server.unsigned_packs_allowed";
                ev.target_type = "ProductPack";
                // gov R1 CONS-BLOCKING-1: use a feature-name scope label
                // rather than "*" wildcard. The audit_store query planner
                // uses `WHERE target_id = ?` (audit_store.cpp:191) — "*"
                // would only match this exact row, not "all packs". Mirrors
                // the sibling `server.viz_disabled` row which uses
                // `target_id="viz"`. Future startup-posture audit rows
                // should follow `target_id=<feature_name>` (see
                // docs/observability-conventions.md startup-posture pattern).
                ev.target_id = "signature_enforcement";
                ev.detail = "product pack signature enforcement disabled at startup "
                            "(--allow-unsigned-packs / YUZU_ALLOW_UNSIGNED_PACKS) — "
                            "unsigned packs will be accepted at install";
                ev.result = "success";
                (void)audit_store_->log(ev);
            }

            // #1073 / W7.4 sibling-gap — same startup-posture audit emission
            // as the unsigned_packs row above, but for instruction-import.
            // Auditors querying "was unsigned definition acceptance enabled
            // during window X?" answer from the audit log, not from process
            // logs. Mirrors the unsigned_packs target_id convention
            // (`signature_enforcement` is the feature scope).
            if (cfg_.allow_unsigned_definitions && audit_store_ && audit_store_->is_open()) {
                AuditEvent ev;
                ev.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                                   std::chrono::system_clock::now().time_since_epoch())
                                   .count();
                ev.principal = "system";
                ev.action = "server.unsigned_definitions_allowed";
                ev.target_type = "InstructionDefinition";
                ev.target_id = "signature_enforcement";
                ev.detail = "instruction-definition signature enforcement disabled at startup "
                            "(--allow-unsigned-definitions / YUZU_ALLOW_UNSIGNED_DEFINITIONS) "
                            "— unsigned definitions will be accepted at import";
                ev.result = "success";
                (void)audit_store_->log(ev);
            }

            // CAP-1 (#1002) — bound the pushed_ map so a churning fleet or
            // a session-management bug that leaves evict_pushed un-called
            // can't grow the map unbounded. Cap at the same hard ceiling
            // as the /viz machines_max DoS guard.
            if (fleet_topology_store_)
                fleet_topology_store_->set_pushed_map_cap(FleetTopologyStore::kPushedMapHardCap);

            // #1000 / arch-S2 — construct the shared HeartbeatIngestion now
            // that fleet_topology_store_ and health_store_ are wired, then
            // inject into both ingestion paths so they cannot drift.
            heartbeat_ingestion_ = std::make_unique<HeartbeatIngestion>(
                registry_, &health_store_, fleet_topology_store_.get(), &metrics_,
                offline_endpoint_store_.get());
            agent_service_.set_heartbeat_ingestion(heartbeat_ingestion_.get());
            if (gateway_service_)
                gateway_service_->set_heartbeat_ingestion(heartbeat_ingestion_.get());

            // Guardian heartbeat reconcile (M5 / #1209). The agent reports its
            // applied policy generation on every heartbeat; if it trails the
            // current generation it missed a push (was offline when the push fired,
            // or has just reconnected — sync_with_server is a no-op pull), so
            // re-push its applicable rules. Reads the generation, never bumps it, so
            // catching one lagging agent up does not make the rest of the fleet look
            // stale (the cascade M6's monotonic counter is designed to avoid).
            heartbeat_ingestion_->set_guardian_reconcile_fn(
                [this](std::string_view agent_id_sv, std::uint64_t agent_gen) {
                    if (!guaranteed_state_store_)
                        return;
                    const std::uint64_t current =
                        guaranteed_state_store_->current_policy_generation();
                    if (agent_gen >= current)
                        return;  // agent already at or ahead of current policy
                    const std::string agent_id(agent_id_sv);

                    // Per-agent rate limit (#1209 hardening: sec-MED1/perf-S1/S2).
                    // Claim the slot under the lock BEFORE any work so concurrent
                    // heartbeats from the same agent can't both reconcile, and a
                    // stuck/hostile agent can't turn every heartbeat into a registry
                    // scan. Wall-clock based so it self-heals a re-registered/wiped
                    // agent after the interval (no generation-keyed dedupe hole).
                    constexpr auto kGuardianReconcileMinInterval = std::chrono::seconds(25);
                    const auto reconcile_now = std::chrono::steady_clock::now();
                    {
                        std::lock_guard lk(guardian_reconcile_mu_);
                        auto last = guardian_last_reconcile_.find(agent_id);
                        if (last != guardian_last_reconcile_.end() &&
                            (reconcile_now - last->second) < kGuardianReconcileMinInterval) {
                            metrics_
                                .counter("yuzu_server_guardian_reconciles_total",
                                         {{"result", "rate_limited"}})
                                .increment();
                            return;
                        }
                        guardian_last_reconcile_[agent_id] = reconcile_now;  // claim
                    }

                    auto sess = registry_.get_session(agent_id);
                    if (!sess) {
                        metrics_
                            .counter("yuzu_server_guardian_reconciles_total",
                                     {{"result", "no_session"}})
                            .increment();
                        return;
                    }
                    // Per-agent filtering as the fan-out (M4): only rules that target
                    // this agent's OS and name it in scope. Cache scope membership
                    // across rules sharing a scope_expr within this one reconcile.
                    // Baseline gate (docs/guardian-baseline-model.md): the rule source
                    // is the union of member Guards of *deployed* Baselines, so an
                    // enabled-but-undeployed Guard is never reconciled onto an agent.
                    const auto rules = guardian::filter_deployed_members(
                        guaranteed_state_store_->list_rules(), deployed_member_rule_ids());
                    std::unordered_map<std::string, bool> scope_member;
                    auto push = guardian::build_agent_push(
                        rules, sess->os,
                        [&](const std::string& expr) {
                            auto cached = scope_member.find(expr);
                            if (cached != scope_member.end())
                                return cached->second;
                            bool member = false;
                            if (auto parsed = yuzu::scope::parse(expr)) {
                                for (const auto& id : registry_.evaluate_scope(
                                         *parsed, tag_store_.get(),
                                         custom_properties_store_.get()))
                                    if (id == agent_id) {
                                        member = true;
                                        break;
                                    }
                            }
                            scope_member.emplace(expr, member);
                            return member;
                        },
                        /*full_sync=*/true, current);
                    ::yuzu::agent::v1::CommandRequest cmd;
                    // Unique per re-push (random suffix) so a same-generation reconcile
                    // can't collide with the agent's replay-dedup set (hp-F2/cons-S1).
                    cmd.set_command_id(
                        "__guard__-reconcile-" + std::to_string(current) + "-" +
                        auth::AuthManager::bytes_to_hex(auth::AuthManager::random_bytes(8)));
                    cmd.set_plugin("__guard__");
                    cmd.set_action("push_rules");
                    cmd.set_payload(push.SerializeAsString());
                    if (registry_.send_to(agent_id, cmd)) {
                        forward_gateway_pending();
                        metrics_
                            .counter("yuzu_server_guardian_reconciles_total",
                                     {{"result", "sent"}})
                            .increment();
                        metrics_
                            .counter("yuzu_server_guardian_pushes_dispatched_total",
                                     {{"reason", "reconcile"}})
                            .increment();
                        metrics_.gauge("yuzu_server_guardian_policy_generation")
                            .set(static_cast<double>(current));
                        // Durable audit of a system-initiated enforcement re-deploy
                        // (SOC2 CC7.2/CC7.4 — comp-F1). Deduped above → at most one
                        // row per agent per interval, not per heartbeat.
                        if (audit_store_ && audit_store_->is_open()) {
                            AuditEvent ev;
                            ev.timestamp =
                                std::chrono::duration_cast<std::chrono::seconds>(
                                    std::chrono::system_clock::now().time_since_epoch())
                                    .count();
                            ev.principal = "system";
                            ev.action = "guaranteed_state.reconcile";
                            ev.target_type = "GuaranteedState";
                            ev.target_id = agent_id;
                            ev.detail = "heartbeat reconcile re-push (generation " +
                                        std::to_string(agent_gen) + " -> " +
                                        std::to_string(current) + ")";
                            ev.result = "success";
                            (void)audit_store_->log(ev);
                        }
                        spdlog::info("Guardian: reconciled agent {} (generation {} -> {})",
                                     agent_id, agent_gen, current);
                    }
                });
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
        // W1.4 / #827: AuditStore for enrollment-token consume rows.
        // Direct path (AgentServiceImpl) AND gateway path
        // (GatewayUpstreamServiceImpl) both get the same store so the
        // success+failure audit trail is uniform regardless of how the
        // agent reached us.
        if (audit_store_ && audit_store_->is_open()) {
            agent_service_.set_audit_store(audit_store_.get());
            if (gateway_service_) {
                gateway_service_->set_audit_store(audit_store_.get());
            }
        }
        if (analytics_store_ && gateway_service_) {
            gateway_service_->set_analytics_store(analytics_store_.get());
        }
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
            // #1073 / W7.4 sibling-gap: InstructionStore ctor sets
            // require_signed_definitions_=true. Wire the operator opt-out
            // immediately after construction, before any import path can
            // execute, so legacy unsigned imports are accepted iff the
            // operator explicitly enabled --allow-unsigned-definitions.
            if (instruction_store_) {
                instruction_store_->set_require_signed_definitions(
                    !cfg_.allow_unsigned_definitions);
                if (cfg_.allow_unsigned_definitions) {
                    spdlog::warn("InstructionStore: signature enforcement DISABLED "
                                 "by configuration (--allow-unsigned-definitions / "
                                 "YUZU_ALLOW_UNSIGNED_DEFINITIONS) — unsigned "
                                 "instruction imports will be accepted");
                }
            }
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
                        (void)audit_store_->log(ev);
                    };
                    auto envelope_id = [](const std::string& env) -> std::string {
                        auto p = nlohmann::json::parse(env, nullptr, false);
                        return p.is_discarded() ? std::string{} : p.value("id", std::string{});
                    };
                    int defs_imported = 0, defs_skipped = 0, defs_errored = 0;
                    for (const auto& env : kBundledDefinitions) {
                        auto id = envelope_id(env);
                        // #1073 / W7.4 sibling-gap: bundled content is
                        // authenticated by build-time binary linkage; route
                        // through the trusted variant so the runtime
                        // signature gate doesn't reject definitions baked
                        // into yuzu-server at compile time. The public
                        // `import_definition_json` is reserved for
                        // operator/network-supplied input.
                        auto r = instruction_store_->import_definition_json_trusted(env);
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
            // #1453 — make device visibility honor the RBAC-disabled posture.
            // When RBAC is globally off there are no per-user
            // management_group_roles rows, so get_visible_agents would return an
            // empty set and the legacy-admin superuser would see no agents (TAR
            // fleet scan, /api/me visible-agents). The probe lets the store
            // return the full enrolled set in that case; when RBAC is enabled it
            // reports true and the exact role-scoped join is preserved. Reads the
            // live RbacStore flag at request time, so wiring order vs rbac_store_
            // does not matter.
            //
            // #1498 — the predicate fails CLOSED on a missing or load-failed
            // store (open/migration failure leaves db_ null), so a corrupt
            // rbac.db can never widen TAR fleet-scan visibility to the whole
            // fleet; see rbac_enforcement_in_effect (rbac_store.hpp) for the
            // full policy and its unit tests.
            mgmt_group_store_->set_rbac_enabled_probe(
                [this]() { return rbac_enforcement_in_effect(rbac_store_.get()); });
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
        {
            // Scope-walking result sets (capability §30).
            auto rs_db = cfg_.db_dir() / "result_sets.db";
            result_set_store_ = std::make_unique<ResultSetStore>(rs_db);
            if (result_set_store_ && result_set_store_->is_open())
                spdlog::info("ResultSetStore initialized at {}", rs_db.string());
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
                // Step 5: ingest agent `__guard__` events arriving on the Subscribe
                // stream → guaranteed_state_events. See docs/guardian-mvp-contract.md.
                agent_service_.set_guaranteed_state_store(guaranteed_state_store_.get());
                // Guardian Half B: gateway-connected agents' drift events arrive
                // via GatewayUpstream.ForwardGuardianMessage, not the direct
                // Subscribe loop — wire the same store so they ingest through the
                // shared path. Gateway service exists only in gateway mode.
                if (gateway_service_)
                    gateway_service_->set_guaranteed_state_store(guaranteed_state_store_.get());

                // D3 fleet-incident alerting (docs/dex-brd-coverage.md): N
                // distinct devices reporting the same (obs_type, subject)
                // inside the window → one operator notification + one
                // webhook/offload event per cooldown. Wired before traffic
                // (set-before-traffic contract on the detector).
                blast_radius_detector_.set_on_incident([this](const BlastRadiusIncident& inc) {
                    const std::string what = inc.subject.empty()
                                                 ? inc.obs_type
                                                 : inc.obs_type + " '" + inc.subject + "'";
                    const std::string title = "Fleet incident: " + what + " on " +
                                              std::to_string(inc.device_count) + " devices";
                    const std::string message =
                        std::to_string(inc.device_count) + " distinct devices reported " +
                        what + " within the last " + std::to_string(inc.window_seconds / 60) +
                        " minutes. See /dex for the drill-down.";
                    spdlog::warn("BlastRadius: {}", title);
                    if (notification_store_)
                        notification_store_->create("warn", title, message);
                    // Same dual-sink discipline as agent.registered (HP-1/UP-6):
                    // build the body once, guard each sink separately.
                    if ((webhook_store_ && webhook_store_->is_open()) ||
                        (offload_target_store_ && offload_target_store_->is_open())) {
                        nlohmann::json payload = {{"event", "dex.blast_radius"},
                                                  {"obs_type", inc.obs_type},
                                                  {"subject", inc.subject},
                                                  {"device_count", inc.device_count},
                                                  {"window_seconds", inc.window_seconds}};
                        const auto body = payload.dump();
                        if (webhook_store_ && webhook_store_->is_open())
                            webhook_store_->fire_event("dex.blast_radius", body);
                        if (offload_target_store_ && offload_target_store_->is_open())
                            offload_target_store_->fire_event("dex.blast_radius", body);
                    }
                });
                blast_radius_detector_.set_metrics(&metrics_);
                agent_service_.set_blast_radius_detector(&blast_radius_detector_);
                if (gateway_service_)
                    gateway_service_->set_blast_radius_detector(&blast_radius_detector_);

                // F1 operator-routed per-signal alerts (Settings → DEX alerts):
                // a routed obs_type raises one notification + one `dex.signal`
                // webhook/offload event per (type, agent) cooldown. Routes load
                // from runtime config after the store opens (apply_dex_alert_
                // config); default = nothing routed.
                dex_alert_router_.set_on_alert([this](const RoutedSignalAlert& a) {
                    const std::string what =
                        a.subject.empty() ? a.obs_type : a.obs_type + " '" + a.subject + "'";
                    const std::string title = "DEX alert: " + what;
                    const std::string message = "Device " + a.agent_id + " reported " + what +
                                                " (operator-routed signal). See /dex for the "
                                                "drill-down.";
                    spdlog::info("DexAlertRouter: {} on {}", what, a.agent_id);
                    if (notification_store_)
                        notification_store_->create("warn", title, message);
                    // Dual-sink discipline, same as the blast-radius incident.
                    if ((webhook_store_ && webhook_store_->is_open()) ||
                        (offload_target_store_ && offload_target_store_->is_open())) {
                        nlohmann::json payload = {{"event", "dex.signal"},
                                                  {"obs_type", a.obs_type},
                                                  {"subject", a.subject},
                                                  {"agent_id", a.agent_id}};
                        const auto body = payload.dump();
                        if (webhook_store_ && webhook_store_->is_open())
                            webhook_store_->fire_event("dex.signal", body);
                        if (offload_target_store_ && offload_target_store_->is_open())
                            offload_target_store_->fire_event("dex.signal", body);
                    }
                });
                dex_alert_router_.set_metrics(&metrics_);
                agent_service_.set_dex_alert_router(&dex_alert_router_);
                if (gateway_service_)
                    gateway_service_->set_dex_alert_router(&dex_alert_router_);
            }
        }

        // Guardian Baselines — the deployable collection of Guards (M:N members +
        // included/excluded management-group assignment). Control-plane only; the
        // agent never hears the word "Baseline". See docs/guardian-baseline-model.md.
        {
            auto bl_db = cfg_.db_dir() / "guardian-baselines.db";
            baseline_store_ = std::make_unique<BaselineStore>(bl_db);
            if (baseline_store_ && baseline_store_->is_open())
                spdlog::info("BaselineStore initialized at {}", bl_db.string());
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
                // #802 / W7.4: enforce signed-pack-by-default. Default
                // ProductPackStore ctor sets require_signed_packs_=true; we
                // invert only when the operator opts in via the flag, and
                // make the relaxed posture loud in operator logs + audit
                // (audit emission deferred to post-audit_store_-construction
                // block below to mirror the viz_disable pattern).
                product_pack_store_->set_require_signed_packs(!cfg_.allow_unsigned_packs);
                if (cfg_.allow_unsigned_packs) {
                    spdlog::warn("[SECURITY] product pack signature enforcement DISABLED "
                                 "by configuration (--allow-unsigned-packs / "
                                 "YUZU_ALLOW_UNSIGNED_PACKS). Unsigned packs will be "
                                 "accepted at install — this exposes the fleet to "
                                 "arbitrary instruction/plugin execution. Sign packs and "
                                 "remove the flag as soon as feasible.");
                }
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

    // Destruction must guarantee every background thread is joined before its
    // captured members are torn down. stop() does that join and is idempotent
    // (guarded by the stop_entered_ CAS), so calling it here is safe even when
    // the normal shutdown path already ran. Without this, a destruction that
    // skips stop() — run() early-returning on a TLS/bind failure after the
    // policy-eval / health threads were spawned, or an exception during late
    // construction — would destroy a still-joinable std::thread and call
    // std::terminate, or free borrowed stores out from under a live thread.
    // PKI: generate + wire per-install default certs on first boot when the
    // operator supplied no certs (and --no-default-certs is unset). Fills the
    // per-surface cfg_ paths, flips cfg_.using_default_certs, and emits the
    // one-shot audit + startup banner + Prometheus gauge. Sets
    // default_certs_failed_ when generation was required but failed, so run()
    // can refuse to start rather than serve without the certs it expected.
    void bootstrap_default_certs() {
        // Always publish the gauge (0) so dashboards can alert on ==1 and clear
        // on ==0 within one process lifetime; flipped to 1 below if defaults are
        // actually active.
        metrics_.gauge("yuzu_server_default_certs_active").set(0);
        if (cfg_.no_default_certs)
            return;
        // A surface is "operator-supplied" only when BOTH its cert and key are
        // present. Exactly one present is a misconfiguration — refuse rather than
        // silently mix operator + generated material (otherwise a half-supplied
        // --cert would be clobbered, or — worse — a strict operator agent
        // listener would be downgraded to don't-require).
        auto half_supplied = [](const std::filesystem::path& cert,
                                const std::filesystem::path& key) {
            return cert.empty() != key.empty();
        };
        if ((cfg_.https_enabled && half_supplied(cfg_.https_cert_path, cfg_.https_key_path)) ||
            (cfg_.tls_enabled && half_supplied(cfg_.tls_server_cert, cfg_.tls_server_key))) {
            spdlog::error("A TLS surface has a certificate without its key (or vice versa). "
                          "Supply both, or neither (to use default certs). Refusing to start.");
            default_certs_failed_ = true;
            return;
        }
        const bool https_needs =
            cfg_.https_enabled && cfg_.https_cert_path.empty() && cfg_.https_key_path.empty();
        const bool agent_needs =
            cfg_.tls_enabled && cfg_.tls_server_cert.empty() && cfg_.tls_server_key.empty();
        if (!https_needs && !agent_needs)
            return; // operator supplied certs for every active surface (or TLS/HTTPS off)

        const std::filesystem::path dir =
            cfg_.ca_dir.empty() ? auth::default_cert_dir() : cfg_.ca_dir;
        if (!ca_store_ || !ca_store_->is_open())
            spdlog::warn("default_certs: ca.db is not open — cert-inventory recording will fail and "
                         "generation will refuse (surfacing the DB-open failure)");
        if (!ensure_default_certs(dir, detect_hostname(), ca_store_.get(), default_cert_set_,
                                  cfg_.cert_sans, cfg_.cert_group)) {
            spdlog::error("default certificates were required but generation failed");
            default_certs_failed_ = true;
            return;
        }
        cfg_.using_default_certs = true; // any surface on defaults — drives the notifications
        // Per-surface fill — only where the operator left BOTH paths empty, so an
        // explicit operator surface is never clobbered or downgraded.
        if (https_needs) {
            cfg_.https_cert_path = default_cert_set_.https_cert;
            cfg_.https_key_path = default_cert_set_.https_key;
        }
        if (agent_needs) {
            cfg_.tls_server_cert = default_cert_set_.server_cert;
            cfg_.tls_server_key = default_cert_set_.server_key;
            if (cfg_.tls_ca_cert.empty())
                cfg_.tls_ca_cert = default_cert_set_.ca_cert;
            // This flag relaxes ONLY the agent listener to request-but-don't-
            // require on default certs, so an unenrolled agent can bootstrap before
            // PR3 mints per-agent client certs. It does NOT relax the higher-
            // privilege management or gateway-upstream planes — those stay STRICT
            // even in default mode (see run() #1238 H-1). An operator-supplied
            // agent surface keeps the strict REQUIRE posture.
            // INVARIANT: using_default_agent_certs ⟹ using_default_certs (it is set
            // inside this `if (https_needs/agent_needs)` block, only after
            // using_default_certs is set above). The /healthz ca-store check keys on
            // the broader using_default_certs (ca.db is needed whenever ANY default
            // surface is active); the listener relaxation keys on the agent-specific
            // flag. Keep them in sync if a future mixed-mode is introduced.
            cfg_.using_default_agent_certs = true;
        }
        metrics_.gauge("yuzu_server_default_certs_active").set(1);
        // B-4 (#1238): the default CA + leaves are 10-year with NO auto-renewal,
        // so their eventual expiry is otherwise a silent outage. Publish the
        // absolute notAfter as a timestamp gauge so the yuzu-tls alert rules
        // (warn @7d / crit @1d) fire ahead of it. The leaves are sized to the CA's
        // notAfter, so cert="default-ca" is the binding expiry for the whole set.
        if (default_cert_set_.ca_expires_at.time_since_epoch().count() != 0) {
            const auto exp_ts = std::chrono::duration_cast<std::chrono::seconds>(
                                    default_cert_set_.ca_expires_at.time_since_epoch())
                                    .count();
            metrics_.gauge("yuzu_server_cert_expiry_timestamp_seconds", {{"cert", "default-ca"}})
                .set(static_cast<double>(exp_ts));
        }
        if (default_cert_set_.freshly_generated && audit_store_ && audit_store_->is_open()) {
            (void)audit_store_->log({.timestamp = std::time(nullptr),
                                     .principal = "system",
                                     .principal_role = "system",
                                     .action = "server.default_certs_generated",
                                     .target_type = "server",
                                     // #1238 should-fix: startup-posture rows key
                                     // target_id on the feature, not a value, to
                                     // match sibling rows; fingerprint goes in detail.
                                     .target_id = "default-certs",
                                     .detail = "Generated per-install default CA + server leaves; "
                                               "ca_fingerprint=" +
                                               default_cert_set_.ca_fingerprint_sha256,
                                     .result = "warning"});
        }
        const std::time_t exp =
            std::chrono::system_clock::to_time_t(default_cert_set_.ca_expires_at);
        // std::ctime returns nullptr on an out-of-range time_t (reachable with a
        // 10-year expiry on a 32-bit time_t build) — constructing a std::string
        // from nullptr is UB and would crash AFTER certs are generated. Guard it.
        // (The banner runs once at startup, single-threaded, so ctime's shared
        // static buffer is not a reentrancy concern here.)
        const char* exp_c = std::ctime(&exp);
        std::string exp_str = exp_c ? exp_c : "unknown";
        if (!exp_str.empty() && exp_str.back() == '\n')
            exp_str.pop_back();
        spdlog::error("**********************************************************************");
        spdlog::error("*** Yuzu is running with BUILT-IN DEFAULT CERTIFICATES.");
        spdlog::error("*** CA SHA-256 : {}", default_cert_set_.ca_fingerprint_sha256);
        spdlog::error("*** CA key     : {} — anyone who reads it can MITM agent traffic",
                      (dir / "default-ca.key").string());
        spdlog::error("*** Expires    : {}", exp_str);
        spdlog::error("*** Replace with --cert/--key/--https-cert (or via Settings) ASAP.");
        spdlog::error("**********************************************************************");
    }

    ~ServerImpl() override { stop(); }

    [[nodiscard]] bool startup_failed() const override { return startup_failed_; }

    void run() override {
        spdlog::info("run(): entering");

        // Fail closed if construction already determined the server cannot
        // start — e.g. the PostgreSQL substrate (ADR-0007) was absent or
        // unreachable in the ctor. main() exits non-zero on startup_failed().
        if (startup_failed_) {
            spdlog::error("run(): refusing to serve — startup failed during construction");
            return;
        }

        // PKI: generate + wire per-install default certs before building TLS
        // credentials (fills cfg_ cert paths + cfg_.using_default_certs).
        bootstrap_default_certs();
        if (default_certs_failed_) {
            spdlog::error("Refusing to start: default certificates were required but could not be "
                          "generated. Provide --cert/--key/--https-cert, or pass "
                          "--no-default-certs to opt out.");
            startup_failed_ = true;
            return;
        }

        // Gateway command-forwarding client — built HERE (post-bootstrap) so the
        // mutual-TLS dial sees the now-populated server leaf + CA (HIGH-2 #1314).
        // When TLS is on, dial the gateway's privileged command plane over MUTUAL
        // TLS (server presents its leaf, verifies the gateway against the install
        // CA). The gateway's mgmt listener requires the client cert, so an
        // unauthenticated container — including a compromised agent with no
        // CA-issued cert — can no longer push commands to the fleet. Only a
        // plaintext stack (--no-tls, dev/demo) keeps insecure credentials.
        if (!cfg_.gateway_command_address.empty()) {
            std::shared_ptr<grpc::ChannelCredentials> gw_creds;
            if (cfg_.tls_enabled) {
                gw_creds = build_gateway_command_credentials();
                if (!gw_creds)
                    // fail-closed: leave gw_mgmt_stub_ null → command forwarding off.
                    spdlog::error("Gateway command forwarding NOT enabled for {} — could not "
                                  "build mutual-TLS credentials.",
                                  cfg_.gateway_command_address);
            } else {
                spdlog::warn("Gateway command plane to {} is PLAINTEXT (--no-tls): the command "
                             "fan-out plane is unauthenticated — keep it on a trusted network.",
                             cfg_.gateway_command_address);
                gw_creds = grpc::InsecureChannelCredentials();
            }
            if (gw_creds) {
                gw_mgmt_channel_ = grpc::CreateChannel(cfg_.gateway_command_address, gw_creds);
                gw_mgmt_stub_ = ::yuzu::server::v1::ManagementService::NewStub(gw_mgmt_channel_);
                spdlog::info("Gateway command forwarding enabled: {} ({})",
                             cfg_.gateway_command_address,
                             cfg_.tls_enabled ? "mutual TLS" : "plaintext");
            }
        }

        // PKI PR3: per-agent mTLS issuance + enforcement, wired AFTER the
        // bootstrap so it sees the live CA. require_client_identity_ was baked at
        // ctor from cfg_.tls_ca_cert (empty pre-bootstrap when relying on
        // defaults) — recompute it now from the post-bootstrap config so the app
        // layer enforces mTLS identity whenever a CA bundle is in play (default
        // OR operator-supplied). Register stays bootstrap-exempt (it issues the
        // first cert); every other RPC requires a verified, non-revoked identity.
        agent_service_.set_require_client_identity(cfg_.tls_enabled && !cfg_.tls_ca_cert.empty());
        // Only an install with our OWN issuing CA (built-in defaults today,
        // subordinate in PR6) signs agent CSRs. When the operator brought their
        // own certs there is no root in ca.db → no signer, and agents must carry
        // operator-minted client certs (the pre-PKI contract). The revocation
        // checker is wired whenever a CA root exists so a revoked leaf is refused
        // even on an operator-supplied-cert install that still uses our CA.
        if (ca_store_ && ca_store_->is_open() && ca_store_->has_root()) {
            // LIFETIME: these [this]-capturing lambdas are invoked from gRPC worker
            // threads and dereference ca_store_/agent_ca_cert_pem_/csr_issue_*. That
            // is safe only because stop() (run from ~ServerImpl) calls
            // agent_server_->Shutdown(deadline) — draining/cancelling all in-flight
            // RPCs — BEFORE any member is destroyed, even though ca_store_ is
            // declared after agent_service_/agent_server_ (destructs first). Same
            // shutdown-before-destruct contract as execution_tracker_. agent_ca_cert_pem_
            // is written ONCE here, before BuildAndStart accepts traffic (publish-
            // before-start), so the worker-thread reads are race-free; do not re-wire
            // the CA at runtime without adding synchronisation.
            // Cache the issuing-CA cert PEM so is_yuzu_issued() can signature-verify
            // a presented client leaf against OUR CA specifically (Hermes CRITICAL-1
            // / LOW-5 — a foreign cert in a multi-CA trust bundle must not be
            // mistaken for a Yuzu agent identity or a revoked Yuzu serial).
            if (auto r = ca_store_->get_root())
                agent_ca_cert_pem_ = r->cert_pem;
            // ONE guarded signer, shared by the direct (AgentServiceImpl) and
            // gateway-proxied (GatewayUpstreamServiceImpl::ProxyRegister, PR5d)
            // Register paths — so an agent enrolling through the gateway receives a
            // per-agent client cert too, with the SAME CA / rate-limit / ca_issued
            // recording / CSR-size cap (one chokepoint, cannot drift). The
            // try/catch enforces sign_agent_csr's documented "nullopt on any
            // failure" contract even if it throws (e.g. bad_alloc) — an uncaught
            // exception out of a sync gRPC handler on the exposed one-way-TLS agent
            // edge would otherwise terminate the server (Hermes pass-2 MEDIUM).
            std::function<std::optional<std::pair<std::string, std::string>>(
                const std::string&, const std::string&, CertIssuanceSource)>
                cert_signer = [this](const std::string& csr_pem, const std::string& agent_id,
                                     CertIssuanceSource src)
                -> std::optional<std::pair<std::string, std::string>> {
                try {
                    return sign_agent_csr(csr_pem, agent_id, src);
                } catch (const std::exception& e) {
                    spdlog::error("PKI: agent CSR signing threw ({}) for {} — non-fatal", e.what(),
                                  agent_id);
                    return std::nullopt;
                } catch (...) {
                    spdlog::error("PKI: agent CSR signing threw (unknown) for {} — non-fatal",
                                  agent_id);
                    return std::nullopt;
                }
            };
            agent_service_.set_agent_cert_signer(cert_signer);
            if (gateway_service_)
                gateway_service_->set_agent_cert_signer(cert_signer);
            agent_service_.set_revocation_checker(
                [this](const std::string& peer_cert_pem) { return is_peer_cert_revoked(peer_cert_pem); });
            // Recognizer: lets the Register re-auth gate treat ONLY Yuzu-issued
            // certs as agent identities (foreign certs fall through to bootstrap).
            agent_service_.set_peer_cert_recognizer(
                [this](const std::string& peer_cert_pem) { return is_yuzu_issued(peer_cert_pem); });
            spdlog::info("PKI: per-agent mTLS issuance active (CA {})",
                         default_cert_set_.ca_fingerprint_sha256.empty()
                             ? std::string("operator-supplied")
                             : default_cert_set_.ca_fingerprint_sha256);
            // Hermes M1: pre-publish the CRL at startup so the PUBLIC GET
            // /api/v1/ca/crl serves a cached, already-signed CRL and never loads
            // the CA key for an anonymous caller (the public handler is
            // serve-or-503, it does NOT build). Best-effort: a failure just means
            // /ca/crl returns 503 until the next revoke republishes.
            if (!publish_crl())
                spdlog::warn("PKI: initial CRL publish failed; GET /api/v1/ca/crl will 503 until "
                             "the next revocation republishes");
        }

        grpc::EnableDefaultHealthCheckService(true);

        std::shared_ptr<grpc::ServerCredentials> agent_creds = grpc::InsecureServerCredentials();
        std::shared_ptr<grpc::ServerCredentials> mgmt_creds = grpc::InsecureServerCredentials();
        if (cfg_.tls_enabled) {
            auto tls = build_tls_credentials(cfg_.tls_server_cert, cfg_.tls_server_key,
                                             cfg_.tls_ca_cert, cfg_.allow_one_way_tls,
                                             /*require_client_cert=*/!cfg_.using_default_agent_certs,
                                             "agent listener");
            if (tls) {
                agent_creds = std::move(tls);
            } else {
                spdlog::error("TLS is enabled but credentials are invalid; refusing to start");
                startup_failed_ = true;
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
                    cfg_.allow_one_way_tls, /*require_client_cert=*/true, "management listener");
                if (!mgmt_tls) {
                    spdlog::error("Management TLS credentials are invalid; refusing to start");
                    startup_failed_ = true;
                    return;
                }
                mgmt_creds = std::move(mgmt_tls);
            } else if (cfg_.using_default_agent_certs) {
                // H-1 (#1238 review): on default certs the AGENT listener relaxes
                // to request-but-don't-require so an unenrolled agent can bootstrap
                // before PR3 mints per-agent client certs. The management and
                // gateway-upstream planes are higher-privilege — do NOT inherit
                // that relaxation. Build a STRICT (require-client-cert) credential
                // from the same default server cert/key/CA. In M1 the gRPC mgmt
                // service is a placeholder so this locks out no real workflow; it
                // stops the privileged plane silently accepting unauthenticated
                // peers. A gateway (PR5) presents the default-gateway client leaf,
                // so the gateway-upstream listener still connects.
                auto mgmt_tls = build_tls_credentials(
                    cfg_.tls_server_cert, cfg_.tls_server_key, cfg_.tls_ca_cert,
                    cfg_.allow_one_way_tls, /*require_client_cert=*/true, "management listener");
                if (!mgmt_tls) {
                    spdlog::error("Management TLS credentials (strict, default certs) are invalid; "
                                  "refusing to start");
                    startup_failed_ = true;
                    return;
                }
                mgmt_creds = std::move(mgmt_tls);
            } else {
                // Operator-supplied agent certs: agent_creds is already strict
                // (require_client_cert = !using_default_agent_certs = true), so the
                // management plane safely reuses it.
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
            startup_failed_ = true;
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
                // G6 SRE: the sweep body is a serial budget shared with the
                // SECURITY-relevant revocation sweep below — a stall here (e.g.
                // a locked tags.db inside the cohort gauge publish) delays
                // revoked-agent teardown by the same amount. Make it visible.
                const auto sweep_start = std::chrono::steady_clock::now();
                health_store_.recompute_metrics(metrics_, std::chrono::seconds{90});
                // PostgreSQL pool gauges (#1368): sampled on the same cadence as
                // the fleet families. Counters/histogram are fed live by the
                // pool's observer hooks, so only the level gauges are polled here.
                if (pg_pool_) {
                    metrics_.gauge("yuzu_pg_pool_in_use")
                        .set(static_cast<double>(pg_pool_->in_use()));
                    metrics_.gauge("yuzu_pg_pool_open").set(static_cast<double>(pg_pool_->open()));
                    metrics_.gauge("yuzu_pg_pool_size").set(static_cast<double>(pg_pool_->size()));
                    metrics_.gauge("yuzu_pg_pool_waiters")
                        .set(static_cast<double>(pg_pool_->waiters()));
                }
                // F2a PR3: per-cohort fleet perf gauges — same cycle, same
                // staleness window as the fleet families above.
                publish_cohort_perf_gauges();
                // Reap Subscribe streams for agents that missed heartbeats
                registry_.reap_stale_sessions(cfg_.session_timeout);
                // PR3 H-1: tear down any live Subscribe stream whose agent leaf
                // has since been revoked. The Subscribe establishment gate runs
                // once; without this sweep a revoked/compromised agent keeps
                // receiving dispatched commands until it voluntarily reconnects.
                // ~15s cadence (this thread) is well inside CRL validity windows;
                // PR4's operator-revoke handler calls the same sweep immediately
                // for prompt teardown. No-op unless the internal CA is active.
                // PR4 (architect S1 / UP-3): keep the published CRL fresh. A fleet
                // with no revocations would otherwise never re-publish, so /ca/crl
                // eventually serves a CRL past its nextUpdate (external validators
                // reject an expired CRL), and a failed startup pre-publish would
                // leave /ca/crl 503 with no self-heal. Re-publish when the latest
                // CRL is missing or within 24h of nextUpdate. publish_crl()
                // serialises + bumps the crlNumber; once it runs, nextUpdate jumps
                // 7 days out so this fires at most ~once/6 days in steady state.
                if (ca_store_ && ca_store_->is_open() && ca_store_->has_root()) {
                    // Backoff (steady_clock — immune to NTP jumps): after a failed
                    // freshness publish, don't retry every tick — wait 5 min so a
                    // persistent failure (bad CA key) doesn't spam logs + the
                    // failure counter (gov L1/L5).
                    const auto now_steady = std::chrono::steady_clock::now();
                    if (now_steady >= crl_freshness_retry_after_) {
                        // nextUpdate is a wall-clock epoch → compare with wall time.
                        const auto now_epoch = static_cast<int64_t>(std::time(nullptr));
                        auto latest = ca_store_->latest_crl();
                        const bool stale =
                            !latest || (latest->next_update - now_epoch) < 24 * 3600;
                        if (stale) {
                            if (publish_crl())
                                spdlog::info(
                                    "PKI: CRL re-published for freshness (nextUpdate window)");
                            else
                                crl_freshness_retry_after_ = now_steady + std::chrono::minutes(5);
                        }
                    }
                }
                if (ca_store_ && ca_store_->is_open()) {
                    const auto swept = registry_.sweep_revoked(
                        [this](const std::string& pem) { return is_peer_cert_revoked(pem); });
                    if (!swept.empty()) {
                        spdlog::warn("Revocation sweep cancelled {} Subscribe stream(s)",
                                     swept.size());
                        // HIGH-1 (#1239 Hermes): a revocation-driven access termination
                        // is a durable SOC 2 CC6.3/CC7.2 event, not just a metric/log.
                        // The sweep is low-frequency (fires only on actual revocations),
                        // so a WAL row per cancelled stream is not a flood risk.
                        if (audit_store_ && audit_store_->is_open()) {
                            for (const auto& aid : swept) {
                                (void)audit_store_->log(
                                    {.timestamp = std::time(nullptr),
                                     .principal = "agent:" + aid,
                                     .principal_role = "agent",
                                     .action = "session.cert_revoked",
                                     .target_type = "Session",
                                     .target_id = aid,
                                     .detail = "reason=revoked_client_cert source=stream_sweep",
                                     .result = "denied"});
                            }
                        }
                    }
                }
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
                // Publish FleetTopologyStore internals so the 256 MiB store-
                // level oversize cap and single-flight refill timeouts are
                // observable -- the route-level yuzu_viz_oversize_response_total
                // only fires on the machines_max gate, not on the byte cap
                // (gov R3 OBS-1).
                if (fleet_topology_store_) {
                    metrics_.gauge("yuzu_viz_refill_oversize_drops_total")
                        .set(static_cast<double>(fleet_topology_store_->refill_oversize_drops()));
                    metrics_.gauge("yuzu_viz_refill_wait_timeouts_total")
                        .set(static_cast<double>(fleet_topology_store_->refill_wait_timeouts()));
                    metrics_.gauge("yuzu_viz_refill_waiters_total")
                        .set(static_cast<double>(fleet_topology_store_->refill_waiters()));
                    metrics_.gauge("yuzu_viz_local_edges_dropped_total")
                        .set(static_cast<double>(fleet_topology_store_->local_edges_dropped()));
                    // Gate 7 sre OBS-1/OBS-2/OBS-3 — push-ingestion failure-mode
                    // counters, previously unscraped.
                    metrics_.gauge("yuzu_viz_topology_push_rejected_total")
                        .set(static_cast<double>(fleet_topology_store_->pushed_rejected_count()));
                    metrics_.gauge("yuzu_viz_pushed_cap_evictions_total")
                        .set(static_cast<double>(fleet_topology_store_->pushed_evicted_for_cap()));
                    metrics_.gauge("yuzu_viz_pushed_map_size")
                        .set(static_cast<double>(fleet_topology_store_->pushed_map_size()));
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
                    metrics_.gauge("yuzu_server_guardian_events_dropped_total")
                        .set(static_cast<double>(guaranteed_state_store_->events_dropped_total()));
                    metrics_.gauge("yuzu_server_guardian_events_reaped_total")
                        .set(static_cast<double>(guaranteed_state_store_->events_reaped_total()));
                    metrics_.gauge("yuzu_server_guardian_proj_failures_total")
                        .set(static_cast<double>(
                            guaranteed_state_store_->observations_proj_failures_total()));
                    metrics_.gauge("yuzu_server_guardian_observations_reaped_total")
                        .set(static_cast<double>(
                            guaranteed_state_store_->observations_reaped_total()));
                }
                if (baseline_store_) {
                    metrics_.gauge("yuzu_server_guardian_baselines_total")
                        .set(static_cast<double>(baseline_store_->baseline_count()));
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
                // G6 SRE: sweep-body duration (excludes the sleep) — the
                // revocation sweep above shares this serial budget, so a stall
                // (locked tags.db, slow fleet walk) is a security-relevant
                // delay, not just stale metrics.
                metrics_
                    .histogram("yuzu_server_reaper_sweep_duration_seconds")
                    .observe(std::chrono::duration<double>(std::chrono::steady_clock::now() -
                                                           sweep_start)
                                 .count());
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
        const bool default_certs_active = cfg_.using_default_certs;
        if (insecure_skip_verify_active || no_tls_active || default_certs_active) {
            // Compose the default-certs detail once (carries the CA fingerprint).
            const std::string default_certs_detail =
                default_certs_active
                    ? "Running with built-in per-install default certificates (CA " +
                          default_cert_set_.ca_fingerprint_sha256 +
                          "). Anyone who can read the local CA key can MITM agent traffic. "
                          "Replace with operator-provided certs (--cert/--https-cert) or via "
                          "Settings as soon as possible."
                    : std::string();
            insecure_tls_reminder_thread_ = std::thread(
                [this, insecure_skip_verify_active, no_tls_active, default_certs_active,
                 default_certs_detail]() {
                    using namespace std::chrono_literals;
                    while (!stop_requested_.load(std::memory_order_acquire)) {
                        // Sleep in small increments for responsive shutdown (300s = 60 * 5s)
                        for (int i = 0; i < 60 && !stop_requested_.load(std::memory_order_acquire);
                             ++i) {
                            std::this_thread::sleep_for(5s);
                        }
                        if (stop_requested_.load(std::memory_order_acquire))
                            break;
                        auto emit = [this](const char* posture, const std::string& detail,
                                           const char* action) {
                            spdlog::error("[INSECURE-TLS] ({}) {}", posture, detail);
                            if (audit_store_ && audit_store_->is_open()) {
                                (void)audit_store_->log({.timestamp = std::time(nullptr),
                                                         .principal = "system",
                                                         .principal_role = "system",
                                                         .action = action,
                                                         .target_type = "server",
                                                         .target_id = posture,
                                                         .detail = detail,
                                                         .result = "warning"});
                            }
                        };
                        if (no_tls_active)
                            emit("--no-tls",
                                 "TLS is fully disabled; both agent and management gRPC listeners "
                                 "accept plaintext from any peer with no encryption and no peer "
                                 "authentication. Restart with TLS certificates to leave this "
                                 "posture.",
                                 "server.tls_degraded");
                        if (insecure_skip_verify_active)
                            emit("--insecure-skip-client-verify",
                                 "Agent / management listener still running without client "
                                 "certificate verification. Re-enable mTLS by supplying --ca-cert "
                                 "(and --management-ca-cert if applicable).",
                                 "server.tls_degraded");
                        if (default_certs_active)
                            emit("default-certs", default_certs_detail,
                                 "server.default_certs_in_use");
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

        // Join the policy evaluation thread (uses policy_evaluator_ + stores,
        // so it must stop before any of them are torn down)
        if (policy_eval_thread_.joinable()) {
            policy_eval_thread_.join();
        }

        // Join the result-set maintenance thread (borrows result_set_store_,
        // execution_tracker_, response_store_ — must stop before teardown)
        if (result_set_maint_thread_.joinable()) {
            result_set_maint_thread_.join();
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

        // Shutdown gRPC with a deadline FIRST so in-flight Subscribe and
        // ManagementService streams drain before we drop the stores they
        // reference. Without a deadline, Shutdown() waits indefinitely for
        // all RPCs to finish, and the Subscribe RPC is a long-lived
        // bidirectional stream that never completes on its own. With a
        // deadline, RPCs are forcibly cancelled at expiry.
        //
        // Governance round (UAT 2026-05-06 architect Gate 3 B-1):
        // AgentServiceImpl borrows execution_tracker_ via a raw pointer
        // (set_execution_tracker), and Subscribe/process_gateway_response
        // call notify_exec_tracker -> update_agent_status on every
        // CommandResponse frame. Resetting execution_tracker_ before the
        // gRPC drain race-windowed a use-after-free during graceful
        // shutdown. Drain producers first, null the borrowed pointer
        // explicitly, then release the tracker.
        auto deadline = std::chrono::system_clock::now() + std::chrono::seconds(5);
        if (agent_server_)
            agent_server_->Shutdown(deadline);
        if (mgmt_server_)
            mgmt_server_->Shutdown(deadline);

        // Now safe: gRPC streams have either completed or been cancelled,
        // so no thread is inside notify_exec_tracker holding the borrowed
        // pointer. Null it before reset for belt-and-braces.
        agent_service_.set_execution_tracker(nullptr);

        // Same contract for the blast-radius detector: both service impls
        // borrow it by raw pointer and call observe() from the ingest path the
        // drain above quiesced. Null before any member teardown (gov
        // cpp-safety/architect/consistency — the detector destructs early by
        // member-decl order, so this removes the only reliance on drain timing).
        agent_service_.set_blast_radius_detector(nullptr);
        if (gateway_service_)
            gateway_service_->set_blast_radius_detector(nullptr);
        // F1: the alert router has the identical borrow contract.
        agent_service_.set_dex_alert_router(nullptr);
        if (gateway_service_)
            gateway_service_->set_dex_alert_router(nullptr);

        // PR3 cpp-safety: the PKI trust callbacks capture `this` and are invoked
        // from Register/Subscribe/Heartbeat/CheckForUpdate/DownloadUpdate. The
        // drain above guarantees no handler is mid-invocation; null them for the
        // same belt-and-braces reason as the tracker so a stray late call cannot
        // touch released CA state.
        agent_service_.set_agent_cert_signer(nullptr);
        agent_service_.set_revocation_checker(nullptr);
        agent_service_.set_peer_cert_recognizer(nullptr);

        // Release Phase 2 components (RAII handles close).
        execution_tracker_.reset();
        // PR 3 — bus outlives the tracker by member-order convention,
        // but in the explicit reset path we drop the tracker first
        // (it borrows `event_bus_`), then the bus.
        execution_event_bus_.reset();
        approval_manager_.reset();
        schedule_engine_.reset();
        instr_db_pool_.reset();

        // PostgreSQL substrate teardown (ADR-0007). The gRPC drain above has
        // quiesced every handler thread that could hold a pool lease through a
        // Postgres-backed store (the heartbeat ingest path's borrowed
        // offline-store pointer was nulled before this), so it is now safe to
        // drop the stores that borrow the pool, then the pool itself — LAST, so
        // no lease outlives it. The pool dtor blocks on outstanding leases; a
        // still-leased thread destroying the pool would self-deadlock (see
        // pg_pool.hpp). Reset is idempotent, so a startup_failed() server that
        // never built these tears down cleanly too.
        if (heartbeat_ingestion_)
            heartbeat_ingestion_->set_offline_endpoint_store(nullptr);
        offline_endpoint_store_.reset();
        pg_pool_.reset();
    }

private:
    // -- TLS ------------------------------------------------------------------

    [[nodiscard]] std::shared_ptr<grpc::ServerCredentials>
    build_tls_credentials(const std::filesystem::path& cert_path,
                          const std::filesystem::path& key_path,
                          const std::filesystem::path& ca_path, bool allow_one_way_tls,
                          bool require_client_cert, std::string_view listener_name) const {
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
            // Under built-in default certs the agent has no client cert yet
            // (per-agent issuance is PR3): REQUEST + VERIFY if presented, but do
            // NOT REQUIRE — otherwise no agent could connect. Operator-provided
            // certs keep the strict REQUIRE posture.
            ssl_opts.client_certificate_request =
                require_client_cert ? GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY
                                    : GRPC_SSL_REQUEST_CLIENT_CERTIFICATE_AND_VERIFY;
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

    // HIGH-2 (#1314): mutual-TLS client credentials for the server→gateway command
    // plane (ManagementService at --gateway-command-addr). The gateway's mgmt
    // listener is the PRIVILEGED command-fan-out plane; without mTLS it is an
    // unauthenticated fleet-RCE surface reachable by any container that can route
    // to it (incl. a compromised agent). Here the server PRESENTS its own leaf as
    // the client cert and VERIFIES the gateway against the install CA, so the
    // gateway can require a client cert (strict mTLS) and reject anyone who can't
    // present a CA-issued cert. Returns nullptr (fail-closed — caller disables
    // command forwarding) if the required cert material is missing/unreadable.
    //
    // The two directions are NOT symmetric. Server→gateway (here): grpc verifies
    // the gateway's identity by SNI/SAN against the dialled host, so the server
    // talks only to the real gateway. Gateway→server (the listener's acceptance
    // policy): verify_peer authenticates to the CA, NOT to a specific identity.
    //
    // Residual (tracked, PKI-ladder): because the gateway side authenticates to
    // the CA only, ANY holder of ANY CA-issued cert+key passes — an enrolled
    // agent's stolen per-agent leaf, or the default-server/default-gateway leaves
    // (0600, need filesystem compromise to extract). There is also no CRL/OCSP
    // check on this path yet, so a revoked-but-stolen leaf still passes. Pinning
    // the mgmt peer to the server's identity (CN/SAN or a dedicated EKU) + mgmt
    // revocation is the cryptographic-identity-binding item that lands with the
    // QUIC-era rework; through-gateway identity stays app-layer until then. mTLS
    // still closes the far larger hole: the plaintext, no-cert-required plane.
    [[nodiscard]] std::shared_ptr<grpc::ChannelCredentials>
    build_gateway_command_credentials() const {
        if (cfg_.tls_server_cert.empty() || cfg_.tls_server_key.empty()) {
            spdlog::error("Gateway command plane: TLS is enabled but the server has no "
                          "client cert/key to present for mutual TLS — command forwarding "
                          "DISABLED (fail-closed). Provide server certs or --no-tls.");
            return nullptr;
        }
        if (cfg_.tls_ca_cert.empty()) {
            spdlog::error("Gateway command plane: TLS is enabled but no CA cert is configured "
                          "to verify the gateway — command forwarding DISABLED (fail-closed).");
            return nullptr;
        }
        if (!detail::validate_key_file_permissions(cfg_.tls_server_key, "Gateway command plane")) {
            return nullptr;
        }
        grpc::SslCredentialsOptions ssl_opts;
        ssl_opts.pem_root_certs = detail::read_file_contents(cfg_.tls_ca_cert);
        ssl_opts.pem_cert_chain = detail::read_file_contents(cfg_.tls_server_cert);
        ssl_opts.pem_private_key = detail::read_file_contents(cfg_.tls_server_key);
        if (ssl_opts.pem_root_certs.empty() || ssl_opts.pem_cert_chain.empty() ||
            ssl_opts.pem_private_key.empty()) {
            spdlog::error("Gateway command plane: failed to read CA/cert/key for mutual TLS — "
                          "command forwarding DISABLED (fail-closed).");
            yuzu::secure_zero(ssl_opts.pem_private_key);
            return nullptr;
        }
        auto creds = grpc::SslCredentials(ssl_opts);
        // Scrub all three PEM buffers from the local copy (#1314 L-1): the private
        // key is the sensitive one, the CA/cert are public, but zeroing all three
        // matches the KeyZeroGuard hygiene used elsewhere and leaves no cert
        // metadata resident longer than needed.
        yuzu::secure_zero(ssl_opts.pem_private_key);
        yuzu::secure_zero(ssl_opts.pem_cert_chain);
        yuzu::secure_zero(ssl_opts.pem_root_certs);
        return creds;
    }

    // -- PKI PR3: per-agent client-cert issuance + revocation ------------------

    /// Percent-encode a single URI path segment per RFC 3986 (Hermes LOW-6).
    /// agent_id arrives from protobuf with only length validation, so it may carry
    /// characters that are invalid raw in a URI (spaces, `/`, `%`, control bytes);
    /// the issued leaf's URI SAN must stay well-formed for downstream parsers.
    static std::string uri_encode_segment(std::string_view s) {
        static constexpr char kHex[] = "0123456789ABCDEF";
        std::string out;
        out.reserve(s.size());
        for (unsigned char c : s) {
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                c == '-' || c == '.' || c == '_' || c == '~') {
                out.push_back(static_cast<char>(c));
            } else {
                out.push_back('%');
                out.push_back(kHex[c >> 4]);
                out.push_back(kHex[c & 0x0F]);
            }
        }
        return out;
    }

    /// True iff `peer_cert_pem` chains to OUR issuing CA (signature-verified, not a
    /// mere issuer-DN string match). In a multi-CA trust bundle this is what
    /// distinguishes a Yuzu-issued agent leaf from a foreign (e.g. corporate-CA)
    /// client cert that merely carries a matching CN — so a foreign cert is never
    /// conflated with a Yuzu agent identity (Hermes CRITICAL-1) nor with a revoked
    /// Yuzu serial (Hermes LOW-5). `agent_ca_cert_pem_` is cached at wiring time.
    /// NOTE: verify_chain is validity-sensitive — a genuine-but-EXPIRED Yuzu leaf
    /// returns false here. Benign on the call paths today (gRPC rejects an expired
    /// client cert at the TLS handshake, so it never reaches these gates, and
    /// Register then falls through to a clean re-enrollment). A future caller that
    /// inspects a cert OFF the handshake-validated path must not read false as
    /// "not ours".
    bool is_yuzu_issued(const std::string& peer_cert_pem) {
        if (peer_cert_pem.empty() || agent_ca_cert_pem_.empty())
            return false;
        // gov UP-7 / sre: cache the verify_chain result so the per-heartbeat
        // revocation gate doesn't pay an ECDSA chain verify on every call
        // fleet-wide. The result is immutable for a given (cert, CA) pair — a cert
        // either chains to our CA or never will — and agent_ca_cert_pem_ is set
        // once before traffic, so no TTL is needed (re-wiring the CA at runtime,
        // a PR6 concern, must clear this cache). Keyed by the full PEM so there is
        // no hash-collision trust risk.
        {
            std::lock_guard<std::mutex> lk(yuzu_issued_cache_mu_);
            auto it = yuzu_issued_cache_.find(peer_cert_pem);
            if (it != yuzu_issued_cache_.end())
                return it->second;
        }
        const bool ok = pki::verify_chain(peer_cert_pem, agent_ca_cert_pem_);
        {
            std::lock_guard<std::mutex> lk(yuzu_issued_cache_mu_);
            if (yuzu_issued_cache_.size() > 16384)
                yuzu_issued_cache_.clear(); // crude bound; certs are stable → low churn
            yuzu_issued_cache_[peer_cert_pem] = ok;
        }
        return ok;
    }

    /// Sign a per-agent client leaf from the agent's CSR, bound to agent_id.
    /// Returns {leaf_pem, ca_chain_pem} or nullopt on any failure (the Register
    /// handler treats nullopt as "stay on the bootstrap posture, retry later").
    ///
    /// SECURITY: the CSR contributes ONLY its public key (proof-of-possession is
    /// verified inside pki::sign_csr). Identity is set HERE from the authenticated
    /// agent_id — CN=agent_id (matched by the #1118 peer-identity gate) plus an
    /// install-scoped URI SAN — never from CSR-controlled fields. The CA private
    /// key is loaded transiently and zeroed before return (incl. exception
    /// unwind) so the crown jewel is not resident for the process lifetime.
    std::optional<std::pair<std::string, std::string>>
    sign_agent_csr(const std::string& csr_pem, const std::string& agent_id,
                   CertIssuanceSource src) {
        // #1290: forensic discriminator on the issuance audit — was this minted on a
        // direct agent connection or relayed by a (potentially compromised) gateway?
        // The exact population an incident responder scopes when bulk-revoking after
        // a gateway compromise (the PR5 R-5 confused-deputy compensating control).
        const char* const via = to_audit_via(src);
        if (!ca_store_ || !ca_store_->is_open())
            return std::nullopt;
        auto root = ca_store_->get_root();
        if (!root) {
            spdlog::warn("PKI: agent CSR signing requested but ca.db has no root");
            return std::nullopt;
        }
        // PR5d / Hermes LOW: bound the attacker-supplied CSR before any parse or
        // sign. A PEM CSR is well under 2 KiB (EC P-256 ~0.6 KiB, RSA-4096
        // ~1.7 KiB); 16 KiB is generous slack. This is the SINGLE chokepoint for
        // BOTH the direct Register and the gateway ProxyRegister signing paths, so
        // the now-gateway-reachable signer cannot be fed a multi-MB blob (gRPC's
        // 4 MiB message cap is the outer bound — this is defence-in-depth on the
        // exposed one-way-TLS agent edge).
        constexpr std::size_t kMaxCsrPemBytes = 16 * 1024;
        if (csr_pem.size() > kMaxCsrPemBytes) {
            spdlog::warn("PKI: rejecting oversize CSR ({} bytes > {}) for agent {}",
                         csr_pem.size(), kMaxCsrPemBytes, agent_id);
            return std::nullopt;
        }

        // HIGH-2 (#1239 Hermes): block revocation bypass via re-enrollment. A
        // compromised endpoint whose leaf was revoked could otherwise delete its
        // local key, reconnect, and trigger this CSR flow to obtain a FRESH leaf
        // with a new serial — silently resurrecting a revoked identity. If this
        // agent_id has a revoked, non-expired cert on record, refuse to auto-issue:
        // clearing a revocation must be a deliberate operator action, not an
        // automatic side effect of the agent dropping its key. A non-revoked
        // orphan (benign key loss) is unaffected — only an ACTIVE revocation
        // blocks re-provisioning. (sign_agent_csr is rate-limited and only runs at
        // enrollment/renewal, so the list_revoked scan is off the hot path.)
        //
        // CONTRACT: ca_issued.subject for an agent cert is the BARE agent_id (set
        // below at `rec.subject = agent_id`), NOT a "CN=..." DN — so the bare-vs-bare
        // compare below is correct. Do NOT "fix" this into a DN parse without also
        // changing the issuance site. Residuals (tracked, narrow): a revoke landing
        // between this scan and signing still issues (TOCTOU — operator re-revokes;
        // the sweep then tears it down), and list_revoked() is an O(revoked) scan
        // (fine at realistic revocation counts; a subject-indexed query is the
        // follow-up if it ever grows).
        {
            const auto now_epoch = static_cast<int64_t>(std::time(nullptr));
            for (const auto& rev : ca_store_->list_revoked()) {
                if (rev.subject == agent_id && rev.not_after > now_epoch) {
                    spdlog::warn("PKI: refusing to re-issue for agent {} — a revoked, "
                                 "non-expired cert (serial {}) exists; an operator must clear "
                                 "the revocation before this agent can re-provision",
                                 agent_id, rev.serial_hex);
                    metrics_
                        .counter("yuzu_server_ca_reissue_blocked_total",
                                 {{"reason", "revoked_identity"}})
                        .increment();
                    if (audit_store_ && audit_store_->is_open()) {
                        (void)audit_store_->log({.timestamp = std::time(nullptr),
                                                 .principal = "agent:" + agent_id,
                                                 .principal_role = "agent",
                                                 .action = "ca.cert.reissue_blocked",
                                                 .target_type = "AgentCertificate",
                                                 .target_id = rev.serial_hex,
                                                 .detail = "reason=revoked_identity cn=" +
                                                           detail::audit_token(agent_id) +
                                                           " via=" + via,
                                                 .result = "denied"});
                    }
                    return std::nullopt;
                }
            }
        }
        // Hermes MEDIUM-4: per-agent issuance rate-limit. A holder of a valid
        // enrollment credential could otherwise spam Register-with-CSR, each call
        // burning an ECDSA sign + a ca.db row. A legitimate agent issues once per
        // provisioning (it then re-Registers WITHOUT a CSR) and again only at the
        // ~8-month renewal, so this floor never affects the happy path; it also
        // bounds the ca.db rows a bounded agent retry (Hermes HIGH-2) can create.
        {
            // gov UP-1: CHECK only here; the timestamp is recorded AFTER a
            // successful issuance (below), so a transient server-side failure
            // (key-load glitch, record_issued contention) does NOT throttle the
            // agent's legitimate retry for 30s. A successful issuance still blocks
            // a re-issue for the window.
            constexpr auto kCsrIssueMinInterval = std::chrono::seconds(30);
            std::lock_guard<std::mutex> rl(csr_issue_mu_);
            const auto now_s = std::chrono::steady_clock::now();
            // Opportunistic prune so the map can't grow unbounded over uptime.
            if (csr_issue_last_.size() > 4096) {
                for (auto it = csr_issue_last_.begin(); it != csr_issue_last_.end();) {
                    if (now_s - it->second > kCsrIssueMinInterval)
                        it = csr_issue_last_.erase(it);
                    else
                        ++it;
                }
            }
            auto it = csr_issue_last_.find(agent_id);
            if (it != csr_issue_last_.end() && now_s - it->second < kCsrIssueMinInterval) {
                spdlog::warn("PKI: throttling agent CSR for {} (one issuance per {}s)", agent_id,
                             kCsrIssueMinInterval.count());
                return std::nullopt;
            }
        }
        const std::filesystem::path dir =
            cfg_.ca_dir.empty() ? auth::default_cert_dir() : cfg_.ca_dir;
        FileKeyProvider kp(dir);
        auto ca_key = kp.load_key(root->key_ref);
        if (!ca_key) {
            spdlog::error("PKI: cannot load CA issuing key — agent cert not issued");
            return std::nullopt;
        }
        // Zero the CA key on every exit path, including exception unwind.
        detail::ScopedKeyZero ca_key_zero{*ca_key};

        // Leaf validity: ~1y (the agent auto-renews at 2/3 life), clamped so it
        // can never outlive the issuing CA (x509_ca rejects a leaf beyond the CA).
        const auto now = std::chrono::system_clock::now();
        auto not_after = now + std::chrono::hours(24 * 365);
        const auto ca_not_after =
            std::chrono::system_clock::time_point{std::chrono::seconds{root->not_after}};
        if (not_after > ca_not_after)
            not_after = ca_not_after;

        pki::LeafParams lp;
        lp.subject = {agent_id, "Yuzu"}; // CN=agent_id → #1118 identity match
        // H-2: backdate not_before by the clock-skew allowance so an agent whose
        // clock lags the server can still present this leaf on its immediate
        // reconnect (a not-yet-valid leaf fails the handshake and the agent does
        // not recover from clock skew). Mirrors the validity_* helpers.
        lp.validity = {now - pki::kClockSkewBackdate, not_after};
        lp.usage = pki::LeafUsage{.client_auth = true};
        // Install-scoped URI SAN (defence in depth + forensic identity). The CA
        // fingerprint (colon-stripped → a valid URI authority) is the per-install
        // id; fall back to the ca.db root fingerprint on an operator-supplied set.
        std::string install = default_cert_set_.ca_fingerprint_sha256.empty()
                                  ? root->fingerprint_sha256
                                  : default_cert_set_.ca_fingerprint_sha256;
        std::erase(install, ':');
        if (!install.empty())
            lp.san.uris.push_back("yuzu://" + install + "/agent/" + uri_encode_segment(agent_id));

        auto issued = pki::sign_csr(csr_pem, root->cert_pem, *ca_key, lp);
        if (!issued) {
            spdlog::warn("PKI: sign_csr failed for agent {}", agent_id);
            return std::nullopt;
        }

        // Record the issued leaf so it can be revoked / inventoried (ca.db).
        IssuedCertRecord rec;
        rec.serial_hex = issued->serial_hex;
        rec.subject = agent_id;
        rec.san = lp.san.uris.empty() ? std::string{} : lp.san.uris.front();
        rec.purpose = "agent";
        rec.not_after =
            std::chrono::duration_cast<std::chrono::seconds>(not_after.time_since_epoch()).count();
        rec.cert_pem = issued->cert_pem;
        rec.issued_by = "agent:" + agent_id;
        rec.enrollment_request_id = agent_id;
        // #1296: stamp the STABLE key-based CA identity (and the issuance-time cert
        // fingerprint, which agent rows previously left blank) so an "issued by this
        // CA" inventory query survives a subordinate re-key. issuer_key_id hashes the
        // root's public key (invariant across the re-key); both are best-effort
        // forensic metadata — a derivation miss does not block issuance.
        if (auto kid = pki::issuer_key_id(root->cert_pem))
            rec.issuer_key_id = *kid;
        rec.issuer_fingerprint = root->fingerprint_sha256;
        if (!ca_store_->record_issued(rec)) {
            // Fail closed: an unrecorded cert can't be revoked, so don't hand it
            // out — the agent stays on the bootstrap posture and retries.
            spdlog::error("PKI: failed to record issued agent cert for {} — not issuing", agent_id);
            return std::nullopt;
        }

        // gov UP-1: record the rate-limit timestamp only now (issuance succeeded),
        // so a failed attempt above never throttles a legitimate retry.
        {
            std::lock_guard<std::mutex> rl(csr_issue_mu_);
            csr_issue_last_[agent_id] = std::chrono::steady_clock::now();
        }
        // gov (sre SHOULD): real-time issuance signal for alerting on enrollment
        // storms / CSR floods (the audit row below is the forensic record).
        metrics_.counter("yuzu_server_ca_cert_issued_total", {{"purpose", "agent"}, {"via", via}})
            .increment();

        if (audit_store_ && audit_store_->is_open()) {
            (void)audit_store_->log({.timestamp = std::time(nullptr),
                                     .principal = "agent:" + agent_id,
                                     .principal_role = "agent",
                                     .action = "ca.cert.issued",
                                     .target_type = "AgentCertificate",
                                     .target_id = issued->serial_hex,
                                     .detail =
                                         "purpose=agent cn=" + detail::audit_token(agent_id) +
                                         " via=" + via,
                                     // gov consistency: "success" (not "ok") so a
                                     // SIEM filter on ca.% AND result=success
                                     // catches issuance alongside revoke/publish.
                                     .result = "success"});
        }
        // The issued chain is our issuing cert PLUS, in subordinate mode (PR6),
        // the parent chain above it — so the agent receives a full path to the
        // corporate trust anchor. chain_pem is empty in Builtin mode, leaving the
        // M1 single-cert behaviour unchanged.
        return std::make_pair(issued->cert_pem, root->cert_pem + root->chain_pem);
    }

    /// PR6 subordinate-CA: export the install CA's CSR (PKCS#10 PEM) over its
    /// EXISTING key, with the CA's own subject, for an enterprise root to sign
    /// into a subordinate-CA intermediate. Returns nullopt on no-CA / key-load /
    /// CSR-build failure. The CA key is loaded transiently and zeroed on every
    /// exit path (same custody discipline as sign_agent_csr).
    std::optional<std::string> export_ca_csr() {
        if (!ca_store_ || !ca_store_->is_open())
            return std::nullopt;
        auto root = ca_store_->get_root();
        if (!root) {
            spdlog::warn("PKI: CA CSR export requested but ca.db has no root");
            return std::nullopt;
        }
        const std::filesystem::path dir =
            cfg_.ca_dir.empty() ? auth::default_cert_dir() : cfg_.ca_dir;
        FileKeyProvider kp(dir);
        auto ca_key = kp.load_key(root->key_ref);
        if (!ca_key) {
            spdlog::error("PKI: cannot load CA issuing key — CSR not exported");
            return std::nullopt;
        }
        struct KeyZero {
            std::string& s;
            ~KeyZero() { yuzu::secure_zero(s); }
        } ca_key_zero{*ca_key};

        // Subject = our CA's existing subject so the signed intermediate keeps the
        // same DN (authorityKeyIdentifier on previously-issued leaves is derived
        // from the issuer KEY, which is unchanged, so they keep validating; the
        // matching DN keeps the human-facing identity stable too).
        auto details = pki::parse_certificate(root->cert_pem);
        pki::CsrParams cp;
        cp.subject = details ? details->subject
                             : pki::DistinguishedName{"Yuzu Internal CA", "Yuzu"};
        return pki::make_csr(*ca_key, cp);
    }

    /// PR6 subordinate-CA: validate an enterprise-signed intermediate and, on
    /// success, switch the issuing identity to subordinate mode. The validation is
    /// the security crux — an operator could otherwise re-root the install at an
    /// attacker-chosen hierarchy or an issuing cert whose key we don't hold:
    ///   1. parseable cert,
    ///   2. is a CA (basicConstraints CA:TRUE) — else it cannot sign leaves,
    ///   3. carries OUR CA public key — proof the enterprise signed the CSR we
    ///      exported, and that we still hold the matching private key, and
    ///   4. verifies up to the uploaded parent chain.
    /// Only then does it set_root (cert=intermediate, chain=parent, mode=
    /// Subordinate); the issuing KEY (key_ref) is unchanged.
    CaRoutes::ImportOutcome import_subordinate_chain(const std::string& intermediate_pem,
                                                     const std::string& parent_chain_pem) {
        if (!ca_store_ || !ca_store_->is_open())
            return CaRoutes::ImportOutcome::StoreError;
        auto root = ca_store_->get_root();
        if (!root)
            return CaRoutes::ImportOutcome::NoRoot;

        auto details = pki::parse_certificate(intermediate_pem);
        if (!details)
            return CaRoutes::ImportOutcome::BadIntermediate;
        if (!pki::cert_is_ca(intermediate_pem))
            return CaRoutes::ImportOutcome::NotCa;

        // Load the CA key transiently (zeroed on exit) to prove the intermediate
        // carries our public key.
        const std::filesystem::path dir =
            cfg_.ca_dir.empty() ? auth::default_cert_dir() : cfg_.ca_dir;
        FileKeyProvider kp(dir);
        auto ca_key = kp.load_key(root->key_ref);
        if (!ca_key) {
            spdlog::error("PKI: cannot load CA issuing key — subordinate import refused");
            return CaRoutes::ImportOutcome::StoreError;
        }
        struct KeyZero {
            std::string& s;
            ~KeyZero() { yuzu::secure_zero(s); }
        } ca_key_zero{*ca_key};

        if (!pki::cert_matches_key(intermediate_pem, *ca_key))
            return CaRoutes::ImportOutcome::KeyMismatch;
        if (!pki::verify_chain_to_bundle(intermediate_pem, parent_chain_pem))
            return CaRoutes::ImportOutcome::ChainInvalid;

        auto fp = pki::fingerprint_sha256(intermediate_pem);
        if (!fp)
            return CaRoutes::ImportOutcome::BadIntermediate;

        // Switch the issuing identity. Keep key_ref + algo (the key is unchanged);
        // adopt the intermediate's validity window and our new parent chain.
        //
        // H1 (PR6 Hermes): the issuing KEY is unchanged, only the issuer cert (and
        // the current root fingerprint) changes. Leaves issued BEFORE this switch
        // keep validating — admission verifies by key+DN, not by fingerprint — and
        // their ca_issued.issuer_fingerprint deliberately retains the issuance-time
        // (builtin) value (forensic accuracy: that cert did mint them). We do NOT
        // bulk-rewrite the inventory: issuer_fingerprint is forensic metadata, never
        // an admission/filter key (see IssuedCertRecord::issuer_fingerprint).
        //
        // #1296 resolves the "issued by this CA" query landmine: ca_issued.issuer_key_id
        // is the STABLE key-based identity (pki::issuer_key_id — a hash of the public
        // key). Because THIS import keeps the key, that id is unchanged across the
        // switch, so leaves issued before AND after share one issuer_key_id and
        // CaStore::list_issued_by_key_id returns the whole population with NO rewrite
        // here. (issuer_fingerprint stays split two-for-one-key, by design.)
        CaRoot updated = *root;
        updated.cert_pem = intermediate_pem;
        updated.chain_pem = parent_chain_pem;
        updated.mode = CaMode::Subordinate;
        updated.fingerprint_sha256 = *fp;
        updated.not_before = std::chrono::duration_cast<std::chrono::seconds>(
                                 details->not_before.time_since_epoch())
                                 .count();
        updated.not_after = std::chrono::duration_cast<std::chrono::seconds>(
                                details->not_after.time_since_epoch())
                                .count();
        if (!ca_store_->set_root(updated)) {
            spdlog::error("PKI: subordinate import validated but set_root failed");
            return CaRoutes::ImportOutcome::StoreError;
        }
        spdlog::warn("PKI: issuing identity switched to SUBORDINATE — intermediate {} now chains "
                     "to an enterprise root",
                     *fp);
        metrics_.counter("yuzu_server_ca_subordinate_imported_total", {}).increment();
        return CaRoutes::ImportOutcome::Ok;
    }

    /// True iff the presented client leaf is one of OURS and its serial is revoked
    /// in ca.db. Issuer-scoped (is_yuzu_issued) so a foreign cert whose serial
    /// happens to collide with a revoked Yuzu serial is not falsely rejected
    /// (Hermes LOW-5). Reads only the CA store (its own mutex) — safe off the
    /// agent-plane lock.
    bool is_peer_cert_revoked(const std::string& peer_cert_pem) {
        if (!ca_store_ || !ca_store_->is_open() || !is_yuzu_issued(peer_cert_pem))
            return false;
        // gov/sre: the serial is IMMUTABLE for a given leaf PEM, so cache the
        // PEM→serial parse (mirrors yuzu_issued_cache_) — the per-heartbeat
        // revocation gate would otherwise pay an X509 PEM parse on every call,
        // fleet-wide. CRITICAL: the is_revoked() lookup below stays LIVE — caching
        // the revocation *result* would let a revoked agent keep talking until the
        // cache expired (a security bug). Only the parse is memoised.
        std::string serial;
        {
            std::lock_guard<std::mutex> lk(peer_serial_cache_mu_);
            if (auto it = peer_serial_cache_.find(peer_cert_pem);
                it != peer_serial_cache_.end())
                serial = it->second;
        }
        if (serial.empty()) {
            auto details = pki::parse_certificate(peer_cert_pem);
            if (!details || details->serial_hex.empty())
                return false; // unparseable → not our cert; the identity gate handles it
            serial = details->serial_hex;
            std::lock_guard<std::mutex> lk(peer_serial_cache_mu_);
            if (peer_serial_cache_.size() > 16384)
                peer_serial_cache_.clear(); // crude bound; certs are stable → low churn
            peer_serial_cache_[peer_cert_pem] = serial;
        }
        return ca_store_->is_revoked(serial);
    }

    /// PKI PR4: build + record a new CRL version over the current revoked set,
    /// signed by the CA, and return its DER. Backs GET /api/v1/ca/crl (served from
    /// the recorded latest, DoS-safe) and is called by POST /api/v1/ca/revoke to
    /// republish. Loads the CA key transiently + zeroes it (RAII). nullopt on no
    /// CA / load / sign failure.
    std::optional<std::vector<std::uint8_t>> publish_crl() {
        // Serialise number-allocation + record so the crlNumber stays monotonic
        // under concurrent publishers (gov architect SHOULD).
        std::lock_guard<std::mutex> publish_lock(crl_publish_mu_);
        if (!ca_store_ || !ca_store_->is_open())
            return std::nullopt;
        auto root = ca_store_->get_root();
        if (!root)
            return std::nullopt;
        const std::filesystem::path dir =
            cfg_.ca_dir.empty() ? auth::default_cert_dir() : cfg_.ca_dir;
        FileKeyProvider kp(dir);
        auto ca_key = kp.load_key(root->key_ref);
        if (!ca_key) {
            spdlog::error("PKI: cannot load CA issuing key — CRL not published");
            metrics_.counter("yuzu_server_ca_crl_publish_failures_total").increment();
            return std::nullopt;
        }
        detail::ScopedKeyZero ca_key_zero{*ca_key};

        std::vector<pki::CrlRevocation> revoked;
        for (const auto& r : ca_store_->list_revoked()) {
            revoked.push_back(
                {r.serial_hex,
                 std::chrono::system_clock::time_point{std::chrono::seconds{r.revoked_at}}});
        }
        const auto now = std::chrono::system_clock::now();
        const pki::Validity validity{now, now + std::chrono::hours(24 * 7)}; // 7-day nextUpdate
        const std::uint64_t number = ca_store_->next_crl_number();
        auto der = pki::build_crl(root->cert_pem, *ca_key, revoked, validity, number);
        if (!der) {
            spdlog::error("PKI: build_crl failed");
            metrics_.counter("yuzu_server_ca_crl_publish_failures_total").increment();
            return std::nullopt;
        }
        CrlVersionRecord rec;
        rec.version = static_cast<int64_t>(number);
        rec.der = *der;
        rec.this_update =
            std::chrono::duration_cast<std::chrono::seconds>(validity.not_before.time_since_epoch())
                .count();
        rec.next_update =
            std::chrono::duration_cast<std::chrono::seconds>(validity.not_after.time_since_epoch())
                .count();
        // #1296: stamp the signing CA's identity on the CRL row — the issuance-time
        // cert fingerprint plus the STABLE key id (invariant across a subordinate
        // re-key) so the CRL history is attributable to the key, not just a cert.
        rec.issuer_fingerprint = root->fingerprint_sha256;
        if (auto kid = pki::issuer_key_id(root->cert_pem))
            rec.issuer_key_id = *kid;
        if (!ca_store_->record_crl(rec)) {
            // B-1 (#1240): do NOT report success on a persistence failure. Returning
            // the freshly-built DER here would make the revoke handler audit
            // ca.crl.published/success and set crl_republished:true while /ca/crl
            // keeps serving the PREVIOUS CRL (missing the just-revoked serial) — a
            // false success that also evades the stale-CRL alert. Fail honestly so
            // the caller reports crl_republished:false and the failure audit fires.
            spdlog::error("PKI: failed to record CRL v{} — reporting publish failure", number);
            metrics_.counter("yuzu_server_ca_crl_publish_failures_total").increment();
            return std::nullopt;
        }
        return der;
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
        // #1498 — restrict whenever RBAC enforcement is in effect, which includes
        // a missing/load-failed store (fail closed); only a loaded-and-explicitly-
        // disabled store skips filtering and returns the full fleet. Shares the
        // rbac_enforcement_in_effect predicate with the get_visible_agents probe
        // so /api/agents and the TAR fleet scan can never disagree.
        if (mgmt_group_store_ && rbac_enforcement_in_effect(rbac_store_.get())) {
            // A global Infrastructure:Read grant sees the whole fleet even under
            // RBAC-on. On a load-failed store check_permission is unavailable
            // (is_open()==false), so this is false and visibility falls to the
            // role-scoped join, which itself fails closed.
            bool global_read = rbac_store_ && rbac_store_->is_open() &&
                               rbac_store_->check_permission(username, "Infrastructure", "Read");
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

    // `[[nodiscard]]` per #1073 R2 governance / PR #883 SOC 2 CC7.2 pattern:
    // callers on security-relevant paths MUST inspect the return and signal
    // audit-write failure to the operator (e.g. `Sec-Audit-Failed: true`
    // header). Silently discarding the return on a denied/success path
    // re-opens the evidence-chain gap whose closure was the whole point of
    // PR #883 and which Gate 4 unhappy-path UP-1/UP-11 re-flagged on the
    // import handler. Non-security audits (config.update, custom_property.*,
    // tag.*, etc.) may still discard with explicit `(void)` cast.
    [[nodiscard]] bool audit_log(const httplib::Request& req, const std::string& action,
                                 const std::string& result, const std::string& target_type = {},
                                 const std::string& target_id = {},
                                 const std::string& detail = {}) {
        return auth_routes_->audit_log(req, action, result, target_type, target_id, detail);
    }

    // PR-E: emit the invocation-time scope-resolution-failure audit row (design
    // §7 rule 3) when a from_result_set: ref resolves to an absent/expired or
    // not-owned set. Req-less so every dispatch path (REST, tracked, MCP) emits
    // uniformly. Carries the dispatch/instruction correlation id (command_id),
    // the result-set ref, principal + role, and reason — the forensic chain the
    // design §10 walkthrough requires (gov C-B1/F1). Also increments a
    // Prometheus counter so the failure is alertable rather than buried in
    // audit.db (gov OBS-2), and logs at warn so a signal survives even when the
    // audit write itself fails (gov OBS-3 / F3 / UP-2).
    void audit_scope_resolution_failed(const std::string& principal,
                                       const std::string& principal_role,
                                       const std::string& command_id, const std::string& ref) {
        metrics_.counter("yuzu_scope_resolution_failed_total").increment();
        spdlog::warn("scope resolution failed: command={} principal={} ref={} "
                     "(result set absent, expired, or not owned)",
                     command_id, principal.empty() ? "unknown" : principal, ref);
        if (!audit_store_)
            return;
        AuditEvent ev{};
        ev.timestamp = std::time(nullptr);
        ev.principal = principal.empty() ? "unknown" : principal;
        ev.principal_role = principal_role;
        ev.action = "instruction.scope_resolution_failed";
        ev.target_type = "result_set";
        ev.target_id = ref;
        ev.detail = "INSTRUCTION_SCOPE_RESOLUTION_FAILED command=" + command_id + " ref=" + ref +
                    " reason=result set not found, expired, or not owned by principal";
        ev.result = "failure";
        if (!audit_store_->log(ev))
            spdlog::error("audit write failed: instruction.scope_resolution_failed "
                          "(command={} ref={})",
                          command_id, ref);
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
        // F1 DEX alerting config — both consumers accept live updates, so the
        // same call applies at boot and from the settings POST handlers.
        apply_dex_alert_config();
    }

    /// F1: push the persisted DEX alerting config into the alert router and
    /// the blast-radius detector. Safe to call any time (both take their own
    /// locks); called at boot via apply_runtime_config_overrides and from the
    /// Settings → DEX alerts POST handlers after a write.
    void apply_dex_alert_config() {
        if (!runtime_config_store_ || !runtime_config_store_->is_open())
            return;
        dex_alert_router_.set_routes(
            parse_routed_types(runtime_config_store_->get_value("dex_alert_routing")));
        const auto get_int = [&](const char* key, int fallback) {
            try {
                const auto v = runtime_config_store_->get_value(key);
                if (!v.empty())
                    return std::stoi(v);
            } catch (...) {}
            return fallback;
        };
        const BlastRadiusConfig defaults{};
        blast_radius_detector_.update_alert_shape(
            get_int("dex_blast_min_devices", defaults.min_devices),
            get_int("dex_blast_window_seconds", defaults.window_seconds),
            get_int("dex_blast_cooldown_seconds", defaults.cooldown_seconds));
        // F2a PR3: cohort metrics export key — read+validated here, consumed by
        // the reaper-thread gauge sweep. Invalid stored values disable the
        // export (fail closed) rather than reaching the snapshot provider.
        {
            std::string key = runtime_config_store_->get_value("dex_cohort_export_key");
            if (!key.empty() && !TagStore::validate_key(key))
                key.clear();
            std::lock_guard lk(dex_cohort_export_mu_);
            dex_cohort_export_key_ = std::move(key);
        }
    }

    /// F2a PR3: publish the per-cohort fleet perf gauges for the configured
    /// export tag key. Runs on the reaper thread each sweep, right after
    /// recompute_metrics (same cycle, same staleness window → the cohort
    /// gauges can never disagree with the fleet families). The export logic
    /// (clear-first absent-not-stale, floor, top-N cap + visible clipped
    /// count, "(untagged)" residual label) lives in dex_perf_model so the
    /// gauges are pinned by unit tests against the same cohort rows the tab
    /// and REST render.
    void publish_cohort_perf_gauges() {
        std::string key;
        DexPerfFn perf;
        {
            std::lock_guard lk(dex_cohort_export_mu_);
            key = dex_cohort_export_key_;
            perf = dex_perf_fn_;
        }
        if (key.empty() || !perf) {
            dex_perf_clear_cohort_gauges(metrics_); // export disabled — absent
            return;
        }
        dex_perf_export_cohort_gauges(metrics_, dex_perf_cohorts(perf(key)));
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

            // Rate limiting — check before auth to protect against brute force.
            // Both /login and /login/mfa share the tighter login-rate bucket;
            // the MFA challenge is part of the same per-IP credential-brute
            // surface and must not fall through to the looser api_rate_limiter_
            // (Hermes Agent red-team finding LOW #6, 2026-05-29). The per-
            // pending-token 5-attempt cap on /login/mfa is the second layer of
            // this defence and remains in place at AuthRoutes::POST /login/mfa.
            // `/login/mfa/stepup` joins this bucket (PR2): the endpoint
            // accepts the same TOTP / recovery code space as `/login/mfa`
            // so a malicious operator with a stolen valid session could
            // pound the space to brute-force the secret. Step-up has no
            // per-pending-token attempts cap (the session IS the
            // credential), so the per-IP rate limit is the only brake.
            // `/login/mfa/enroll` joins it too (PR3): it confirms the first
            // code against a provisional TOTP secret during enforced
            // enrollment, so it is the same online-guessing surface and
            // must not fall through to the looser bucket.
            bool is_login = (req.path == "/login" || req.path == "/login/mfa" ||
                             req.path == "/login/mfa/stepup" ||
                             req.path == "/login/mfa/enroll") &&
                            req.method == "POST";
            auto& limiter = is_login ? login_rate_limiter_ : api_rate_limiter_;
            if (!limiter.allow(req.remote_addr)) {
                res.status = 429;
                res.set_header("Retry-After", "1");
                res.set_content(
                    R"({"error":{"code":429,"message":"rate limit exceeded"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return httplib::Server::HandlerResponse::Handled;
            }

            // Allow unauthenticated access to login pages, health, OIDC flow, and OpenAPI spec.
            // /health and /api/health are ALSO covered by the early-return
            // exemption at the top of this lambda (which additionally skips
            // rate limiting). They are kept in this list as defense-in-depth
            // — a future contributor narrowing the early-return back to
            // /livez|/readyz alone would silently start requiring auth on
            // /health without this lower entry. Governance Gate 7, security
            // re-review LOW. Do not remove either site without updating both.
            //
            // `/login/mfa` MUST be unauthenticated for the same reason `/login`
            // is: the MFA challenge completes the login. The pending token is
            // the only credential the caller has at this point — they have no
            // session cookie yet. Hermes Agent's red-team review (2026-05-29)
            // caught the omission; without it, MFA-enrolled users are locked
            // out because every POST /login/mfa redirects to /login before the
            // route handler runs.
            // `/login/mfa/enroll` (PR3) is also pre-session: it completes
            // an enforced login for an un-enrolled user who has only the
            // enrollment-pending token, not a cookie. (`/login/mfa/stepup`
            // is deliberately NOT here — it requires an existing session.)
            if (req.path == "/login" || req.path == "/login/mfa" ||
                req.path == "/login/mfa/enroll" || req.path == "/health" ||
                req.path == "/api/health" || req.path == "/auth/oidc/start" ||
                req.path == "/auth/callback" || req.path == "/api/v1/openapi.json" ||
                // PKI PR4: the CA root cert + CRL are public by design — clients
                // and browsers need them to establish trust / check revocation
                // before they have any session. Exact-match only; /api/v1/ca/issued
                // and /api/v1/ca/revoke remain Security-gated below.
                req.path == "/api/v1/ca/root" || req.path == "/api/v1/ca/crl" ||
                req.path.starts_with("/static/")) {
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
            // Guardian Baselines store — load-bearing for the Baseline dashboard +
            // deploy surface; same rationale as the Guard store row above.
            bool baseline_ok = baseline_store_ && baseline_store_->is_open();
            // Phase 8.3 #255 — same pattern as Guardian above. Without
            // this row /healthz would report "healthy" while every
            // /api/v1/offload-targets endpoint and every fire_event call
            // silently no-ops on a migration failure (HC-1 from Gate 6).
            bool offload_target_ok = offload_target_store_ && offload_target_store_->is_open();
            // #1238 B-3: ca.db is load-bearing whenever default certs are active
            // (issuance / revocation / CRL). It was wired into /readyz but missing
            // here, so /healthz could report "healthy" with a dead ca.db. Mirrors
            // the /readyz conjunction; trivially true when not on default certs
            // (the operator brought their own, so ca.db isn't required).
            bool ca_ok = !cfg_.using_default_certs || (ca_store_ && ca_store_->is_open());

            // Determine overall status
            bool all_stores_ok = response_ok && audit_ok && instruction_ok && policy_ok &&
                                 guaranteed_state_ok && baseline_ok && offload_target_ok && ca_ok;
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
                  {"baselines", baseline_ok ? "ok" : "error"},
                  {"offload_target", offload_target_ok ? "ok" : "error"},
                  {"ca", ca_ok ? "ok" : "error"}}},
                // #401: was hardcoded "0.1.0" — now derived from the
                // meson-generated yuzu/version.hpp so the health endpoint
                // tracks the actual build instead of a stale literal.
                {"version", std::string(yuzu::kVersionString)}};

            // TLS posture — intentionally UNAUTHENTICATED: operators and
            // monitoring MUST be able to see when the install is on built-in
            // default certs. The CA fingerprint is public.
            health["tls"] = {
                {"default_certs_active", cfg_.using_default_certs},
                {"ca_fingerprint", default_cert_set_.ca_fingerprint_sha256},
                {"ca_expires_at",
                 cfg_.using_default_certs ? static_cast<int64_t>(std::chrono::system_clock::to_time_t(
                                                default_cert_set_.ca_expires_at))
                                          : int64_t{0}}};

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
                {"baseline_store", baseline_store_ && baseline_store_->is_open()},
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
                // Governance UAT 2026-05-06 SRE-1: ExecutionTracker became
                // load-bearing in this batch — AgentServiceImpl's
                // notify_exec_tracker calls update_agent_status on every
                // CommandResponse frame. The tracker has no is_open() of
                // its own; it shares the instructions DB pool. We probe
                // the pointer (nullptr means the pool failed to construct)
                // AND the underlying instr_db_pool_ explicitly, so a
                // pool-open failure surfaces as /readyz=503 rather than a
                // silent no-op on every response.
                {"execution_tracker",
                 execution_tracker_ != nullptr && instr_db_pool_ && instr_db_pool_->is_open()},
                // gov R3 HC-1: FleetTopologyStore became load-bearing for
                // /api/v1/viz/fleet/topology + /fragments/viz/fleet/topology.
                // Pure in-memory store with no is_open(); pointer-not-null is
                // the right probe. Without this, a store-construction failure
                // would leave /readyz "ready" while every viz request 503s.
                {"fleet_topology_store", fleet_topology_store_ != nullptr},
                // #1320 PR 3 (#1368 Pattern E): the Postgres substrate is
                // load-bearing — without it every Postgres-backed store is
                // dead. Cheap, NON-lease-consuming signal: valid() (conninfo
                // parsed) AND the connect breaker is closed. The breaker arms
                // on real connect failures (PG unreachable) but NOT on pool
                // saturation, so this reflects runtime reachability without the
                // false-negative a lease-consuming probe would hit under load
                // (gov UP-2 — a busy-but-healthy server must NOT be evicted
                // from the LB). Saturation is surfaced via the acquire-wait
                // histogram + pool gauges + their alert rules, not /readyz.
                {"pg_pool", pg_pool_ != nullptr && pg_pool_->valid() &&
                                !pg_pool_->connect_breaker_open()},
                // First migrated store (#1368). The server fails closed without
                // Postgres, so this is true whenever it serves; a false here is
                // the loud signal that the migration path is broken even though
                // the pool answered.
                {"offline_endpoint_store",
                 offline_endpoint_store_ && offline_endpoint_store_->is_open()},
                // gov W7.4 R1 sre-B1: ProductPackStore became more load-bearing
                // post-#802. UP-2 from the W7.4 Gate 4 risk register: a store
                // that fails to open AND `--allow-unsigned-packs` set produces
                // a silent half-state — the audit row at startup says "unsigned
                // packs allowed" but every install returns 503 because the
                // store is dead. Without this readyz entry, an LB or operator
                // dashboard would not detect the half-state. Pairs with the
                // workflow_routes.cpp install handler's `is_open()` guard.
                {"product_pack_store", product_pack_store_ && product_pack_store_->is_open()},
                // gov PR-E OBS-1: ResultSetStore became load-bearing — every
                // scoped command dispatch and the /api/scope/estimate preview
                // resolve from_result_set: aliases and owner-check membership
                // against it. A failed migration / corrupt result_sets.db would
                // silently degrade every scoped dispatch to zero targets while
                // /readyz reported "ready".
                {"result_set_store", result_set_store_ && result_set_store_->is_open()},
                // PKI PR2: ca.db is load-bearing only when the install is on
                // built-in default certs (PR3+ make it load-bearing for mTLS
                // issuance/revocation). When the operator brought their own certs
                // it is not on the request path, so report ok.
                {"ca_store", !cfg_.using_default_certs || (ca_store_ && ca_store_->is_open())},
                {"ca_root", !cfg_.using_default_certs || (ca_store_ && ca_store_->has_root())},
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
            bool baseline_ok = baseline_store_ && baseline_store_->is_open();
            bool all_ok = response_ok && audit_ok && instruction_ok && policy_ok &&
                          guaranteed_state_ok && baseline_ok;

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

            (void)audit_log(req, "config.update", "success", "RuntimeConfig", key,
                            "value=" + value);

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

            (void)audit_log(req, "custom_property.set", "success", "Agent", agent_id,
                            key + "=" + value);

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

            (void)audit_log(req, "custom_property.delete", "success", "Agent", agent_id,
                            "key=" + key);

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

            (void)audit_log(req, "property_schema.create", "success", "PropertySchema", schema.key);

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

        // PR 4 of feat/viz-engine: vendored Three.js r168 (MIT) + OrbitControls
        // (MIT, ES module). Modern Three.js (r150+) ships only as ES modules,
        // so PR 5's page scaffold loads these via `<script type="importmap">`
        // mapping `"three"` to `/static/three.module.min.js` and
        // `"three/addons/controls/OrbitControls.js"` to
        // `/static/three-orbit-controls.js`. Cache-Control matches the
        // ECharts pattern: public, max-age=86400, content-addressed by
        // server binary version.
        web_server_->Get(
            "/static/three.module.min.js", [](const httplib::Request&, httplib::Response& res) {
                res.set_header("Cache-Control", "public, max-age=86400");
                res.set_content(yuzu::server::kThreeJs, "application/javascript; charset=utf-8");
            });
        web_server_->Get("/static/three-orbit-controls.js",
                         [](const httplib::Request&, httplib::Response& res) {
                             res.set_header("Cache-Control", "public, max-age=86400");
                             res.set_content(yuzu::server::kThreeOrbitControlsJs,
                                             "application/javascript; charset=utf-8");
                         });
        // PR 5 of feat/viz-engine: yuzu-viz.js renderer module. Loaded as
        // type="module" so it can resolve the `import 'three'` bare
        // specifier through the importmap declared in viz_page_ui.cpp.
        //
        // Cache-Control: no-cache, no-store, must-revalidate -- matches the
        // /viz/fleet page shell. The renderer bundles change on every
        // feat/viz-engine PR; a `max-age` here means operators serve a
        // stale renderer (wrong tier classification, missing features,
        // outdated layout code) for up to the max-age window after a
        // server upgrade, with no signal that anything is wrong. The page
        // shell already revalidates; the bundle it pulls must too, or the
        // skew window just moves from the HTML to the JS. ~88 KB of
        // revalidated body per page load is cheap next to a silently-stale
        // renderer. Vendored libs below (cytoscape, three) keep max-age --
        // they're content-stable and only change on a deliberate refresh.
        web_server_->Get(
            "/static/yuzu-viz.js", [](const httplib::Request&, httplib::Response& res) {
                res.set_header("Cache-Control", "no-cache, no-store, must-revalidate");
                res.set_content(yuzu::server::kYuzuVizJs, "application/javascript; charset=utf-8");
            });

        // PR 9-pre: per-host renderer + vendored Cytoscape.js 3.33.3 (MIT).
        // yuzu-viz-host.js is the ES module entry; cytoscape.min.js is the
        // ESM minified Cytoscape bundle resolved via the importmap in
        // viz_host_page_ui.cpp. The renderer uses cytoscape's built-in
        // `cose` layout — no layout-extension asset is served.
        //
        // yuzu-viz-host.js gets the same no-cache treatment as yuzu-viz.js
        // (it's our renderer code, changes every viz PR); cytoscape.min.js
        // keeps max-age (vendored, content-stable).
        web_server_->Get("/static/yuzu-viz-host.js", [](const httplib::Request&,
                                                        httplib::Response& res) {
            res.set_header("Cache-Control", "no-cache, no-store, must-revalidate");
            res.set_content(yuzu::server::kYuzuVizHostJs, "application/javascript; charset=utf-8");
        });
        web_server_->Get("/static/cytoscape.min.js", [](const httplib::Request&,
                                                        httplib::Response& res) {
            res.set_header("Cache-Control", "public, max-age=86400");
            res.set_content(yuzu::server::kCytoscapeJs, "application/javascript; charset=utf-8");
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

        // PR2 — MFA step-up gate. Single shared closure (governance Gate 2
        // sec-M5: was duplicated at the SettingsRoutes and RestApiV1
        // register_routes sites; DRY'd up here so a future change updates
        // both surfaces atomically). Hoisted to the top of start_web_server
        // because SettingsRoutes::register_routes (called just below) and
        // RestApiV1::register_routes (called later in this same function)
        // both consume it. The closure captures cfg_ + auth_mgr_ + audit_log
        // and dispatches into `require_mfa_step_up`. `std::function` copies
        // it into each call site.
        StepUpFn step_up_fn = [this](const httplib::Request& req, httplib::Response& res,
                                     const auth::Session& session,
                                     const std::string& action_label) -> bool {
            if (!auth_mgr_.auth_db_ptr())
                return true; // defensive — auth_db is always non-null in production
            return require_mfa_step_up(
                req, res, session, *auth_mgr_.auth_db_ptr(), cfg_.mfa_step_up_window_secs,
                [this](const httplib::Request& r, const std::string& a, const std::string& rs,
                       const std::string& tt, const std::string& ti, const std::string& d) {
                    return audit_log(r, a, rs, tt, ti, d);
                },
                action_label, cfg_.mfa_enforcement);
        };

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
                (void)audit_log(req, action, result, target_type, target_id, detail);
            },
            cfg_, auth_mgr_, auto_approve_, api_token_store_.get(), mgmt_group_store_.get(),
            tag_store_.get(), update_registry_.get(), runtime_config_store_.get(),
            audit_store_.get(), gateway_service_ != nullptr,
            gateway_service_ ? SettingsRoutes::GatewaySessionCountFn([this]() -> std::size_t {
                return gateway_service_->session_count();
            })
                             : SettingsRoutes::GatewaySessionCountFn{},
            [this]() -> std::string { return registry_.to_json(); }, oidc_mu_, oidc_provider_,
            /*metrics_registry=*/&metrics_, step_up_fn);
        // F1: live-apply hook for the DEX alerts settings (wired before the
        // listener starts, so no request races the set).
        settings_routes_->set_dex_alert_apply_fn([this]() { apply_dex_alert_config(); });

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
                // Scope expression dispatch.
                // Owner principal for from_result_set: resolution (review B1).
                // This raw path is untracked (no execution row), so read the
                // session directly; auth already passed require_permission above.
                std::string principal, principal_role;
                if (auto s = require_auth(req, res)) {
                    principal = s->username;
                    principal_role = auth::role_to_string(s->role);
                }
                // Resolve from_result_set: aliases against the operator's owned
                // sets before parsing (PR-E): the scope resolver does not.
                auto resolved_scope =
                    resolve_scope_aliases(scope_expr, principal, result_set_store_.get());
                // Forensic row when a referenced set is absent/expired/unowned
                // (design §7 rule 3); does not abort dispatch.
                for (const auto& ref : scope_refs_failing_owner_check(
                         resolved_scope, principal, result_set_store_.get()))
                    audit_scope_resolution_failed(principal, principal_role, command_id, ref);
                auto parsed = yuzu::scope::parse(resolved_scope);
                if (!parsed) {
                    res.status = 400;
                    res.set_content(
                        nlohmann::json({{"error", "invalid scope: " + parsed.error()}}).dump(),
                        "application/json");
                    return;
                }
                auto matched_ids = registry_.evaluate_scope(*parsed, tag_store_.get(),
                                                            custom_properties_store_.get(),
                                                            result_set_store_.get(), principal);
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
            (void)audit_log(req, "command.dispatch", "success", "command", command_id,
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
            (void)audit_log(req, "tag.set", "success", "tag", agent_id + ":" + key, value);
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
            (void)audit_log(req, "tag.delete", deleted ? "success" : "not_found", "tag",
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

        // ── Result Sets (scope walking — capability §30) ─────────────────
        // Page shell + HTML fragment routes. Per-operator, owner-scoped: every
        // fragment authenticates and filters/loads by the session principal.
        // Rendering lives in result_sets_ui.cpp; store I/O happens here.
        web_server_->Get("/result-sets",
                         [this](const httplib::Request& req, httplib::Response& res) {
                             auto session = require_auth(req, res);
                             if (!session) {
                                 res.set_redirect("/login");
                                 return;
                             }
                             res.set_content(kResultSetsPageHtml, "text/html; charset=utf-8");
                         });

        // Owner-scoped sidebar list.
        web_server_->Get(
            "/fragments/result-sets/sidebar",
            [this](const httplib::Request& req, httplib::Response& res) {
                auto session = require_auth(req, res);
                if (!session)
                    return;
                if (!result_set_store_) {
                    res.set_content("", "text/html; charset=utf-8");
                    return;
                }
                std::string next;
                std::string selected =
                    req.has_param("selected") ? req.get_param_value("selected") : "";
                auto sets = result_set_store_->list_by_owner(session->username, "", 200, next);
                res.set_content(render_result_sets_sidebar(sets, selected),
                                "text/html; charset=utf-8");
            });

        // Detail pane for one set (owner-checked).
        web_server_->Get(
            R"(/fragments/result-sets/(rs_[0-9a-f]+)/detail)",
            [this](const httplib::Request& req, httplib::Response& res) {
                auto session = require_auth(req, res);
                if (!session)
                    return;
                auto id = req.matches[1].str();
                auto row = result_set_store_ ? result_set_store_->get(id) : std::nullopt;
                if (!row || row->owner_principal != session->username) {
                    res.set_content(render_result_set_detail_empty(),
                                    "text/html; charset=utf-8");
                    return;
                }
                auto chain = result_set_store_->lineage(id, session->username);
                res.set_content(render_result_set_detail(*row, chain),
                                "text/html; charset=utf-8");
            });

        // Pin / unpin — return the refreshed detail and trigger a sidebar reload.
        auto rs_detail_after = [this](const std::string& id, const std::string& owner,
                                      httplib::Response& res) {
            auto row = result_set_store_->get(id);
            if (!row || row->owner_principal != owner) {
                res.set_content(render_result_set_detail_empty(), "text/html; charset=utf-8");
                return;
            }
            auto chain = result_set_store_->lineage(id, owner);
            res.set_header("HX-Trigger", "resultSetsChanged");
            res.set_content(render_result_set_detail(*row, chain), "text/html; charset=utf-8");
        };

        web_server_->Post(
            R"(/fragments/result-sets/(rs_[0-9a-f]+)/pin)",
            [this, rs_detail_after](const httplib::Request& req, httplib::Response& res) {
                auto session = require_auth(req, res);
                if (!session || !result_set_store_)
                    return;
                auto id = req.matches[1].str();
                auto row = result_set_store_->get(id);
                if (!row || row->owner_principal != session->username) {
                    res.set_content(render_result_set_detail_empty(), "text/html; charset=utf-8");
                    return;
                }
                auto pinned = result_set_store_->pin(id);
                if (!pinned) {
                    // Don't audit a success that didn't happen, and tell the
                    // operator why (review merged_bug_009). PinLimit is the
                    // 50-pin cap; otherwise a transient store error.
                    audit_log(req, "result_set.pin",
                              pinned.error() == ResultSetError::PinLimit ? "denied" : "failure",
                              "ResultSet", id, to_string(pinned.error()));
                    res.set_header(
                        "HX-Trigger",
                        nlohmann::json{{"showToast",
                                        {{"level", "error"}, {"message", to_string(pinned.error())}}}}
                            .dump());
                    auto chain = result_set_store_->lineage(id, session->username);
                    res.set_content(render_result_set_detail(*row, chain),
                                    "text/html; charset=utf-8");
                    return;
                }
                audit_log(req, "result_set.pin", "success", "ResultSet", id, "");
                rs_detail_after(id, session->username, res);
            });

        web_server_->Post(
            R"(/fragments/result-sets/(rs_[0-9a-f]+)/unpin)",
            [this, rs_detail_after](const httplib::Request& req, httplib::Response& res) {
                auto session = require_auth(req, res);
                if (!session || !result_set_store_)
                    return;
                auto id = req.matches[1].str();
                auto row = result_set_store_->get(id);
                if (!row || row->owner_principal != session->username) {
                    res.set_content(render_result_set_detail_empty(), "text/html; charset=utf-8");
                    return;
                }
                auto unpinned = result_set_store_->unpin(id);
                if (!unpinned) {
                    audit_log(req, "result_set.unpin", "failure", "ResultSet", id,
                              to_string(unpinned.error()));
                    res.set_header("HX-Trigger",
                                   nlohmann::json{{"showToast",
                                                   {{"level", "error"},
                                                    {"message", to_string(unpinned.error())}}}}
                                       .dump());
                    auto chain = result_set_store_->lineage(id, session->username);
                    res.set_content(render_result_set_detail(*row, chain),
                                    "text/html; charset=utf-8");
                    return;
                }
                audit_log(req, "result_set.unpin", "success", "ResultSet", id, "");
                rs_detail_after(id, session->username, res);
            });

        web_server_->Post(
            R"(/fragments/result-sets/(rs_[0-9a-f]+)/delete)",
            [this](const httplib::Request& req, httplib::Response& res) {
                auto session = require_auth(req, res);
                if (!session || !result_set_store_)
                    return;
                auto id = req.matches[1].str();
                auto row = result_set_store_->get(id);
                if (!row || row->owner_principal != session->username) {
                    res.set_content(render_result_set_detail_empty(), "text/html; charset=utf-8");
                    return;
                }
                auto del = result_set_store_->delete_set(id);
                if (!del) {
                    // Pinned sets must be unpinned first — re-render the detail
                    // so the operator sees why nothing was deleted.
                    auto chain = result_set_store_->lineage(id, session->username);
                    res.set_content(render_result_set_detail(*row, chain),
                                    "text/html; charset=utf-8");
                    return;
                }
                audit_log(req, "result_set.delete", "success", "ResultSet", id, "");
                res.set_header("HX-Trigger", "resultSetsChanged");
                res.set_content(render_result_set_detail_empty(), "text/html; charset=utf-8");
            });

        // Create from pasted device IDs (CSV import) — returns refreshed sidebar.
        web_server_->Post(
            "/fragments/result-sets/create",
            [this](const httplib::Request& req, httplib::Response& res) {
                auto session = require_auth(req, res);
                if (!session || !result_set_store_)
                    return;
                CreateRequest cr;
                cr.owner_principal = session->username;
                cr.name = req.has_param("name") ? req.get_param_value("name") : "";
                cr.source_kind = std::string(source_kind::kManualCurate);
                cr.source_payload = R"({"note":"dashboard CSV import"})";

                std::vector<std::string> members;
                if (req.has_param("device_ids")) {
                    std::string raw = req.get_param_value("device_ids");
                    std::string cur;
                    auto flush = [&]() {
                        // trim whitespace
                        std::size_t a = cur.find_first_not_of(" \t\r\n");
                        std::size_t b = cur.find_last_not_of(" \t\r\n");
                        if (a != std::string::npos)
                            members.push_back(cur.substr(a, b - a + 1));
                        cur.clear();
                    };
                    for (char c : raw) {
                        if (c == '\n' || c == ',')
                            flush();
                        else
                            cur += c;
                    }
                    flush();
                }
                auto created = result_set_store_->create_materialized(cr, members);
                if (!created) {
                    // Surface quota / too-many-members / store errors instead of
                    // silently re-rendering as if the create succeeded (review
                    // merged_bug_009). The store enforces kMaxMembersPerSet, so an
                    // oversized pasted CSV lands here as TooManyMembers (B4).
                    if (created.error() == ResultSetError::QuotaExceeded ||
                        created.error() == ResultSetError::TooManyMembers)
                        metrics_.counter("yuzu_result_set_quota_rejected").increment();
                    audit_log(req, "result_set.create", "denied", "ResultSet", "",
                              to_string(created.error()));
                    res.set_header("HX-Trigger",
                                   nlohmann::json{{"showToast",
                                                   {{"level", "error"},
                                                    {"message", to_string(created.error())}}}}
                                       .dump());
                    std::string next;
                    auto sets = result_set_store_->list_by_owner(session->username, "", 200, next);
                    res.set_content(render_result_sets_sidebar(sets, ""),
                                    "text/html; charset=utf-8");
                    return;
                }
                audit_log(req, "result_set.create", "success", "ResultSet", created->id,
                          cr.source_kind);
                std::string next;
                auto sets = result_set_store_->list_by_owner(session->username, "", 200, next);
                res.set_header("HX-Trigger", "resultSetsChanged");
                res.set_content(render_result_sets_sidebar(sets, created->id),
                                "text/html; charset=utf-8");
            });

        // PR 5 of feat/viz-engine: Fleet visualization page. Auth-gated
        // (same posture as /tar) but the per-request RBAC check happens
        // inside VizRoutes when the page's JS hits /api/v1/viz/fleet/topology.
        // The page itself is just the renderer scaffold + nav chrome -- no
        // per-machine data is rendered server-side; the JSON fetch on the
        // client is what enforces Response.Read.
        //
        // Cache-Control: no-cache, no-store, must-revalidate forces the
        // browser to revalidate the page HTML on every navigation. This
        // closes the gov R4 UP-10 / DEP-1 / CHAOS-C3 "stale page + new
        // bundle" skew window: the page references a hard-coded importmap
        // for `/static/three.module.min.js` etc. that are themselves
        // cached for 24 hours. Without revalidation, a heuristically-
        // cached stale page after a server upgrade pairs with new asset
        // bytes (or vice versa), producing a silent blank canvas with a
        // module-resolution console error.
        //
        // Future-PR ordering note (gov R4 arch-S1): if a future PR
        // introduces a regex route like `R"(/viz/([^/]+))"` for per-
        // machine drill-in, register it AFTER this literal route or the
        // first-match-wins routing in cpp-httplib would swallow `fleet`
        // as a path parameter.
        web_server_->Get("/viz/fleet", [this](const httplib::Request& req, httplib::Response& res) {
            auto session = require_auth(req, res);
            if (!session) {
                res.set_redirect("/login");
                return;
            }
            // Gate 7 sec-L1 / cons-N1 — honour the kill switch on the page
            // shell, not just the REST/fragment endpoints. Previously the
            // shell rendered and only the JSON fetch 503'd, leaving the
            // operator with a half-working page and a console error. 503
            // here matches the VizRoutes posture and the invariant doc's
            // "a disabled viz surface returns 503".
            if (viz_disabled_.load(std::memory_order_acquire)) {
                res.status = 503;
                res.set_content("fleet visualization is disabled by an administrator "
                                "(--viz-disable / YUZU_VIZ_DISABLE)",
                                "text/plain; charset=utf-8");
                return;
            }
            res.set_header("Cache-Control", "no-cache, no-store, must-revalidate");
            res.set_content(kVizFleetPageHtml, "text/html; charset=utf-8");
        });

        // PR 9-pre: per-host drill-down page. Opened by the 3D viz's
        // dblclick handler in a new tab. Must be registered AFTER
        // /viz/fleet (literal match wins; the regex below would otherwise
        // swallow `fleet` as a parameter — gov R4 arch-S1 ordering).
        // Agent_id is URL-decoded by httplib (req.matches[1]); we replace
        // `{{AGENT_ID}}` in the static HTML with the sanitised id so the
        // renderer can read it from data-agent-id without parsing the URL.
        // Allow-list: a-z A-Z 0-9 dash underscore dot — anything else is
        // 400 (the agent_id schema is hexadecimal-uuid-ish; nothing else
        // should reach this route).
        web_server_->Get(
            R"(/viz/host/([^/]+))", [this](const httplib::Request& req, httplib::Response& res) {
                auto session = require_auth(req, res);
                if (!session) {
                    res.set_redirect("/login");
                    return;
                }
                // Gate 7 sec-L1 / cons-N1 — kill switch on the host
                // drill-down page shell too (cons-N1 confirmed the gap
                // spans both viz page routes, not just /viz/fleet).
                if (viz_disabled_.load(std::memory_order_acquire)) {
                    res.status = 503;
                    res.set_content("fleet visualization is disabled by an administrator "
                                    "(--viz-disable / YUZU_VIZ_DISABLE)",
                                    "text/plain; charset=utf-8");
                    return;
                }
                const std::string raw_id = req.matches.size() > 1 ? req.matches[1].str() : "";
                for (char c : raw_id) {
                    const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                                    (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.';
                    if (!ok) {
                        res.status = 400;
                        res.set_content("invalid agent_id", "text/plain");
                        return;
                    }
                }
                std::string html(kVizHostPageHtml);
                const std::string token = "{{AGENT_ID}}";
                for (auto pos = html.find(token); pos != std::string::npos;
                     pos = html.find(token, pos + raw_id.size())) {
                    html.replace(pos, token.size(), raw_id);
                }
                res.set_header("Cache-Control", "no-cache, no-store, must-revalidate");
                res.set_content(std::move(html), "text/html; charset=utf-8");
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
                        (void)audit_log(req, "instruction.create", "denied",
                                        "InstructionDefinition", def.id, "duplicate_id");
                    }
                    auto body_msg = is_conflict ? std::string(strip_conflict_prefix(result.error()))
                                                : result.error();
                    res.set_content(nlohmann::json({{"error", body_msg}}).dump(),
                                    "application/json");
                    return;
                }
                (void)audit_log(req, "instruction.create", "success", "InstructionDefinition",
                                *result, def.name);
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
                (void)audit_log(req, "instruction.update", "success", "InstructionDefinition", id);
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
                (void)audit_log(req, "instruction.delete", "success", "InstructionDefinition", id);
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
                // R4 (gov R1 unhappy/security HIGH): audit EVERY rejection
                // path, not just conflicts. The #1073 signature gate adds
                // five new rejection branches (signature_invalid,
                // signature_incomplete, signature_wrong_length, signature_
                // missing_content, unsigned_rejected); each is an access
                // decision the SOC 2 CC6.7 audit trail must reflect. The
                // detail is the store-returned error message classified
                // either as "duplicate_id" (the legacy contract) or the
                // raw error text (which begins with a stable token like
                // "signature verification failed" / "instruction-import
                // is unsigned" / etc. that SIEM rules can key on).
                std::string detail = is_conflict ? "duplicate_id" : result.error();
                // R2 / Gate 4 unhappy UP-1 + compliance CO-1: capture the
                // audit_log return and surface failure to the operator via
                // Sec-Audit-Failed header (PR #883 / SOC 2 CC7.2 pattern at
                // rest_api_v1.cpp:1129). Silently discarding the bool on a
                // security-decision audit row re-opens the evidence-chain
                // gap whose closure was the whole point of R4's hoist.
                // R2 / Gate 4 consistency CONS-BLOCKING-1: target_type is
                // now the RBAC-securable PascalCase "InstructionDefinition"
                // matching ProductPack's W7.4 R2 normalisation, NOT the
                // legacy lowercase "instruction" string.
                const bool audit_ok = audit_log(req, "instruction.import", "denied",
                                                "InstructionDefinition", "", detail);
                if (!audit_ok)
                    res.set_header("Sec-Audit-Failed", "true");
                auto body_msg = is_conflict ? std::string(strip_conflict_prefix(result.error()))
                                            : result.error();
                // R3 governance security MEDIUM-1: body field mirrors the
                // captured bool, NOT a hardcoded `false`. On the rare
                // happy-rejection path (request denied AND audit row
                // persisted successfully) the operator sees
                // `audit_emitted: true`. Symmetric with the success branch
                // below.
                res.set_content(
                    nlohmann::json({{"error", body_msg}, {"audit_emitted", audit_ok}}).dump(),
                    "application/json");
                return;
            }
            // R2 success-branch: same Sec-Audit-Failed treatment so a wedged
            // audit-store on a successful import surfaces to the operator —
            // SOC 2 CC7.2 requires the evidence row, and silently landing a
            // definition in the DB without the row is a half-broken chain.
            const bool audit_ok =
                audit_log(req, "instruction.import", "success", "InstructionDefinition", *result);
            if (!audit_ok)
                res.set_header("Sec-Audit-Failed", "true");
            res.set_header("HX-Trigger",
                           R"({"showToast":{"message":"Definitions imported","level":"success"}})");
            res.set_content(nlohmann::json({{"id", *result}, {"audit_emitted", audit_ok}}).dump(),
                            "application/json");
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
            (void)audit_log(req, "execution.rerun", "success", "execution", *result,
                            "rerun of " + id);
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
            (void)audit_log(req, "execution.cancel", "success", "execution", id);
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
                (void)audit_log(req, "schedule.create", "success", "schedule", *result, sched.name);
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
                (void)audit_log(req, "schedule.delete", "success", "schedule", id);
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
            (void)audit_log(req, "approval.approve", "success", "approval", id);
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
            (void)audit_log(req, "approval.reject", "success", "approval", id);
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
        // Per-device tier + management-group scope gate (wraps
        // require_scoped_permission). Used by DeviceRoutes' per-device routes so an
        // operator can only open / read / live-query a device inside their scope.
        auto scoped_perm_fn = [this](const httplib::Request& req, httplib::Response& res,
                                     const std::string& type, const std::string& op,
                                     const std::string& agent_id) -> bool {
            return require_scoped_permission(req, res, type, op, agent_id);
        };
        // Visible-agent SET resolver for filtering device-id-rendering lists (DEX
        // device drills). SAME policy as get_visible_agents_json / the /devices list:
        // nullopt = caller sees the whole fleet (global Infrastructure:Read OR RBAC
        // off); else the caller's management-group members. The global-read branch is
        // load-bearing — a bare get_visible_agents would blank an admin in no group.
        auto visible_set_fn =
            [this](const std::string& username) -> std::optional<std::set<std::string>> {
            if (rbac_store_ && rbac_store_->is_rbac_enabled() && mgmt_group_store_) {
                if (!rbac_store_->check_permission(username, "Infrastructure", "Read")) {
                    auto v = mgmt_group_store_->get_visible_agents(username);
                    return std::set<std::string>(v.begin(), v.end());
                }
            }
            return std::nullopt; // global read or RBAC disabled → sees all
        };
        auto audit_fn = [this](const httplib::Request& req, const std::string& action,
                               const std::string& result, const std::string& target_type,
                               const std::string& target_id, const std::string& detail) -> bool {
            return audit_log(req, action, result, target_type, target_id, detail);
        };

        // Shared command-dispatch closure — sends a CommandRequest to agents via
        // gRPC. Hoisted here (was inline in the WorkflowRoutes block) so the
        // PolicyEvaluator and WorkflowRoutes drive the EXACT same dispatch path.
        auto command_dispatch_fn =
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
            // PR 2 / UP2-4: register command_id -> execution_id BEFORE any RPC.
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
                // from_result_set: is owner-scoped; recover the dispatching
                // operator from the execution row (run_async / workflow /
                // scheduled all create it with dispatched_by before dispatch).
                // This is how owner-checked result-set resolution reaches the
                // tracked dispatch paths without threading a param through the
                // shared CommandDispatchFn (review finding B1).
                std::string principal;
                if (scope_expr.find("from_result_set:") != std::string::npos &&
                    !execution_id.empty() && execution_tracker_) {
                    if (auto ex = execution_tracker_->get_execution(execution_id))
                        principal = ex->dispatched_by;
                }
                // Resolve from_result_set: aliases at the dispatch layer (PR-E).
                auto resolved_scope =
                    resolve_scope_aliases(scope_expr, principal, result_set_store_.get());
                // Role is not available on the tracked path (principal recovered
                // from the execution row, no live session); principal + command
                // id still identify the actor for the forensic chain.
                for (const auto& ref : scope_refs_failing_owner_check(
                         resolved_scope, principal, result_set_store_.get()))
                    audit_scope_resolution_failed(principal, /*role=*/"", command_id, ref);
                auto parsed = yuzu::scope::parse(resolved_scope);
                if (parsed) {
                    auto matched = registry_.evaluate_scope(*parsed, tag_store_.get(),
                                                            custom_properties_store_.get(),
                                                            result_set_store_.get(), principal);
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

        // PolicyEvaluator — drives the compliance check -> verdict pipeline.
        // A background thread ticks it: dispatch due policies' check
        // instructions, collect responses, evaluate the CEL, write status.
        policy_evaluator_ = std::make_unique<PolicyEvaluator>(PolicyEvaluator::Deps{
            .policy_store = policy_store_.get(),
            .instruction_store = instruction_store_.get(),
            .response_store = response_store_.get(),
            .registry = &registry_,
            .tag_store = tag_store_.get(),
            .custom_properties_store = custom_properties_store_.get(),
            .mgmt_group_store = mgmt_group_store_.get(),
            .metrics = &metrics_,
            .dispatch_fn = command_dispatch_fn,
        });
        policy_eval_thread_ = std::thread([this]() {
            spdlog::info("Policy evaluation thread started (cadence=10s, grace=15s)");
            while (!stop_requested_.load(std::memory_order_acquire)) {
                for (int i = 0; i < 2 && !stop_requested_.load(std::memory_order_acquire); ++i)
                    std::this_thread::sleep_for(std::chrono::seconds{5});
                if (stop_requested_.load(std::memory_order_acquire))
                    break;
                if (policy_evaluator_) {
                    // tick() touches JSON parsing, the CEL evaluator and SQLite —
                    // any of which can throw on a malformed policy/result. An
                    // exception escaping a std::thread entry calls std::terminate,
                    // so a single bad policy must not take the process (or silently
                    // kill compliance evaluation). Catch, log, and keep ticking.
                    try {
                        policy_evaluator_->tick();
                    } catch (const std::exception& e) {
                        spdlog::error("policy_eval: tick threw ({}) — thread continuing", e.what());
                    } catch (...) {
                        spdlog::error("policy_eval: tick threw unknown exception — thread continuing");
                    }
                }
            }
        });

        // Result-set maintenance thread (capability §30) — materialises pending
        // result sets once their producing execution reaches a terminal state,
        // runs the GC sweep on a ~5-minute cadence, and refreshes the alive
        // gauges. Borrows result_set_store_, execution_tracker_, response_store_
        // and metrics_, so it MUST be joined before any of them are torn down
        // (join sits next to the policy-eval join in stop()).
        if (result_set_store_ && result_set_store_->is_open()) {
            result_set_maint_thread_ = std::thread([this]() {
                spdlog::info("Result-set maintenance thread started (cadence=2s, GC=5m)");
                constexpr int kGcEveryNTicks = 150;            // ~5 minutes at 2s/tick
                constexpr int64_t kPendingTimeoutSeconds = 300; // give up waiting after 5m
                int tick = 0;
                while (!stop_requested_.load(std::memory_order_acquire)) {
                    for (int i = 0; i < 2 && !stop_requested_.load(std::memory_order_acquire); ++i)
                        std::this_thread::sleep_for(std::chrono::seconds{1});
                    if (stop_requested_.load(std::memory_order_acquire))
                        break;
                    try {
                        const int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
                                                std::chrono::system_clock::now().time_since_epoch())
                                                .count();

                        // 1) Materialise terminal pending sets.
                        for (const auto& p : result_set_store_->list_pending()) {
                            if (p.source_execution_id.empty())
                                continue;
                            bool terminal = false;
                            if (execution_tracker_) {
                                auto sum = execution_tracker_->get_summary(p.source_execution_id);
                                terminal = sum.agents_targeted > 0 &&
                                           sum.agents_responded >= sum.agents_targeted;
                            }
                            const bool timed_out = now - p.created_at > kPendingTimeoutSeconds;
                            if (!terminal && !timed_out)
                                continue;

                            // Membership: every responder whose (status,
                            // output) satisfies the pending row's matcher.
                            // rs_matcher centralises the per-producer rule —
                            // empty matcher = SUCCESS responders; tar_rows_ge
                            // = SUCCESS with ≥N rows; column/op/value = a
                            // matching output row (PR-D, design §3.3).
                            std::vector<std::string> members;
                            std::unordered_set<std::string> seen;
                            if (response_store_) {
                                for (const auto& r :
                                     response_store_->query_by_execution(p.source_execution_id)) {
                                    if (!rs_matcher::response_matches(p.matcher, r.status, r.output))
                                        continue;
                                    if (seen.insert(r.agent_id).second)
                                        members.push_back(r.agent_id);
                                }
                            }
                            if (result_set_store_->materialize(p.id, members)) {
                                metrics_
                                    .counter("yuzu_result_sets_total",
                                             {{"source_kind", p.source_kind},
                                              {"result", "materialized"}})
                                    .increment();
                            } else {
                                // Don't count a materialization that didn't happen
                                // (review finding bug_008); surface the failure so
                                // SRE can alert on a stuck pending row.
                                metrics_
                                    .counter("yuzu_result_sets_total",
                                             {{"source_kind", p.source_kind},
                                              {"result", "materialize_failed"}})
                                    .increment();
                            }
                        }

                        // 2) GC sweep on the slow cadence.
                        if (++tick % kGcEveryNTicks == 0) {
                            int swept = result_set_store_->gc_sweep();
                            if (swept > 0) {
                                metrics_.counter("yuzu_result_set_gc_total")
                                    .increment(static_cast<double>(swept));
                                spdlog::info("result-set GC swept {} expired set(s)", swept);
                            }
                        }

                        // 3) Refresh alive gauges.
                        auto c = result_set_store_->counts();
                        metrics_.gauge("yuzu_result_sets_alive", {{"pinned", "true"}})
                            .set(static_cast<double>(c.pinned));
                        metrics_.gauge("yuzu_result_sets_alive", {{"pinned", "false"}})
                            .set(static_cast<double>(c.total - c.pinned));
                    } catch (const std::exception& e) {
                        spdlog::error("result_set_maint: tick threw ({}) — thread continuing",
                                      e.what());
                    } catch (...) {
                        spdlog::error("result_set_maint: tick threw unknown — thread continuing");
                    }
                }
            });
        }

        // ComplianceRoutes — /compliance, /fragments/compliance/*, /api/policies/*,
        // /api/compliance/*
        compliance_routes_ = std::make_unique<ComplianceRoutes>();
        compliance_routes_->register_routes(
            *web_server_, auth_fn, perm_fn, audit_fn,
            [this](const std::string& event_type, const httplib::Request& req,
                   const nlohmann::json& attrs, const nlohmann::json& payload_data) {
                emit_event(event_type, req, attrs, payload_data);
            },
            policy_store_.get(), [this]() -> std::string { return registry_.to_json(); },
            policy_evaluator_.get());

        // GuardianRoutes — /guardian + /fragments/guardian/* (Guaranteed State
        // dashboard; docs/guardian-mvp-contract.md §8). Fragment renderers are
        // mock-backed (contract-shaped) until the parallel backend on
        // feat/guardian-mvp lands; live data is used where it already exists
        // (rule CRUD + event query on GuaranteedStateStore).
        guardian_routes_ = std::make_unique<GuardianRoutes>();
        guardian_routes_->register_routes(
            *web_server_, auth_fn, perm_fn, audit_fn,
            [this](const std::string& event_type, const httplib::Request& req,
                   const nlohmann::json& attrs, const nlohmann::json& payload_data) {
                emit_event(event_type, req, attrs, payload_data);
            },
            guaranteed_state_store_.get(),
            baseline_store_.get(),
            [this]() -> std::string { return registry_.to_json(); },
            // Dashboard enforcement toggle deploys via the same push fan-out the
            // REST endpoint uses. guardian_push_fn_ is assigned just below during
            // REST wiring; this lambda reads it at toggle-time (runtime), never at
            // registration time, so the ordering is fine.
            [this](const std::string& scope, bool full_sync) -> int {
                return guardian_push_fn_ ? guardian_push_fn_(scope, full_sync) : -2;
            });

        // F2a: the fleet perf snapshot provider — joins AgentHealthStore heartbeat
        // perf tags (validated through the SAME dex_perf_rules the Prometheus
        // gauges use), AgentRegistry sessions (OS + agent-reported tags) and the
        // TagStore (operator tags, ONE bulk query per render — not N point
        // lookups). Cohort precedence mirrors evaluate_scope: agent scopable_tags
        // first, then the tag store. Shared by the /dex Performance fragments,
        // the /api/v1/dex/perf/* REST surface and the MCP perf tools so all
        // three can never disagree.
        auto dex_perf_uncached = [this](const std::string& cohort_key) -> DexPerfSnapshot {
            DexPerfSnapshot snap;
            snap.cohort_key = cohort_key;
            std::unordered_map<std::string, std::string> cohort_values;
            if (tag_store_ && !cohort_key.empty()) {
                // available_keys feed the tab's key picker and the cohorts
                // REST response — both always pass a key. Key-less callers
                // (the pollable fleet endpoint, the disabled gauge sweep)
                // don't pay the extra query (grill NFR fix).
                snap.available_keys = tag_store_->get_distinct_keys();
                cohort_values = tag_store_->get_values_for_key(cohort_key);
            }
            // Same staleness the recompute_metrics sweep prunes by — the tab and
            // the yuzu_fleet_perf_* gauges see the same population. perf_snapshot
            // copies ONLY the perf tags (G3 performance S1 — the copy runs under
            // the heartbeat-upsert mutex).
            const auto health = health_store_.perf_snapshot(std::chrono::seconds{90});
            std::unordered_map<std::string, const detail::AgentHealthSnapshot*> by_id;
            by_id.reserve(health.size());
            for (const auto& h : health)
                by_id[h.agent_id] = &h;
            for (const auto& id : registry_.all_ids()) {
                auto s = registry_.get_session(id);
                if (!s)
                    continue;
                DexPerfDevice d;
                d.agent_id = id;
                std::string os = s->os;
                for (auto& c : os)
                    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                // starts_with, NOT find: "darwin" CONTAINS "win" — a substring
                // match classifies every macOS agent as Windows (G4 UP-1
                // BLOCKING). Agents report "windows" / "darwin" / "linux"
                // (agents/core/src/agent.cpp kAgentOs).
                d.is_windows = os.starts_with("win");
                if (auto it = by_id.find(id); it != by_id.end()) {
                    const auto& tags = it->second->status_tags;
                    auto get = [&](const char* k) -> std::string {
                        auto t = tags.find(k);
                        return t != tags.end() ? t->second : std::string{};
                    };
                    d.cpu_pct = detail::parse_perf_cpu_pct(get(detail::kPerfTagCpuPct));
                    d.commit_pct = detail::parse_perf_commit_pct(get(detail::kPerfTagCommitPct));
                    d.disk_lat_ms =
                        detail::parse_perf_disk_lat_ms(get(detail::kPerfTagDiskLatMs));
                }
                if (!cohort_key.empty()) {
                    // STORE-FIRST precedence — deliberately the OPPOSITE of
                    // evaluate_scope's agent-first order: a benchmark cohort is
                    // an operator-declared comparison population, so a rogue
                    // agent must not self-assign into "executive-laptops" and
                    // drag its p90 (G4 UP-5). The store already carries honest
                    // agents' tags via sync_agent_tags, so store-first loses
                    // nothing; the in-memory fallback only covers a tag not yet
                    // synced, and it is value-validated (G2 sec-L2: scopable_tags
                    // are unvalidated at session ingest) so oversized/garbage
                    // bytes never become a cohort label.
                    if (auto cv = cohort_values.find(id); cv != cohort_values.end()) {
                        d.cohort = cv->second;
                    } else if (auto it = s->scopable_tags.find(cohort_key);
                               it != s->scopable_tags.end() &&
                               TagStore::validate_value(it->second)) {
                        d.cohort = it->second;
                    }
                }
                snap.devices.push_back(std::move(d));
            }
            // C-S1 (consistency): the fleet yuzu_fleet_perf_* gauges aggregate
            // EVERY fresh health snapshot; an agent whose Subscribe session was
            // reaped while its heartbeat is still <90s old must therefore also
            // appear here, or the tab and the gauges disagree about the same
            // sweep. Session-less devices carry values but no OS/cohort context
            // (is_windows=false keeps them out of the Windows denominator;
            // store-side cohort still resolves).
            std::unordered_set<std::string> seen;
            seen.reserve(snap.devices.size());
            for (const auto& d : snap.devices)
                seen.insert(d.agent_id);
            for (const auto& h : health) {
                if (seen.contains(h.agent_id))
                    continue;
                DexPerfDevice d;
                d.agent_id = h.agent_id;
                auto get = [&](const char* k) -> std::string {
                    auto t = h.status_tags.find(k);
                    return t != h.status_tags.end() ? t->second : std::string{};
                };
                d.cpu_pct = detail::parse_perf_cpu_pct(get(detail::kPerfTagCpuPct));
                d.commit_pct = detail::parse_perf_commit_pct(get(detail::kPerfTagCommitPct));
                d.disk_lat_ms = detail::parse_perf_disk_lat_ms(get(detail::kPerfTagDiskLatMs));
                if (!cohort_key.empty())
                    if (auto cv = cohort_values.find(h.agent_id); cv != cohort_values.end())
                        d.cohort = cv->second;
                snap.devices.push_back(std::move(d));
            }
            return snap;
        };
        // G3 performance S2: a 5s TTL memo keyed by cohort key. Heartbeat data
        // changes on a ~30s cadence, so every consumer (operator clicks, agentic
        // pollers, per-device drills, the 15s gauge sweep) can share one build
        // per key per 5s — bounding the fleet-walk + tag-query cost no matter
        // how hard the REST surface is polled. Consumers may therefore see a
        // snapshot up to 5s stale; that is well inside the heartbeat cadence.
        struct DexPerfMemo {
            std::mutex mu;
            struct Entry {
                std::chrono::steady_clock::time_point at;
                DexPerfSnapshot snap;
            };
            std::unordered_map<std::string, Entry> by_key;
        };
        auto dex_perf_memo = std::make_shared<DexPerfMemo>();
        auto dex_perf_fn = [memo = dex_perf_memo,
                            dex_perf_uncached](const std::string& cohort_key) -> DexPerfSnapshot {
            constexpr auto kTtl = std::chrono::seconds{5};
            constexpr std::size_t kMaxMemoEntries = 8; // "", default key, export key, picker keys
            const auto now = std::chrono::steady_clock::now();
            {
                std::lock_guard lk(memo->mu);
                if (auto it = memo->by_key.find(cohort_key);
                    it != memo->by_key.end() && now - it->second.at < kTtl)
                    return it->second.snap;
            }
            auto snap = dex_perf_uncached(cohort_key);
            {
                std::lock_guard lk(memo->mu);
                if (memo->by_key.size() >= kMaxMemoEntries &&
                    !memo->by_key.contains(cohort_key)) {
                    auto oldest = memo->by_key.begin();
                    for (auto it = memo->by_key.begin(); it != memo->by_key.end(); ++it)
                        if (it->second.at < oldest->second.at)
                            oldest = it;
                    memo->by_key.erase(oldest);
                }
                memo->by_key[cohort_key] = {now, snap};
            }
            return snap;
        };
        // PR3: the reaper-thread cohort gauge sweep uses the same provider.
        {
            std::lock_guard lk(dex_cohort_export_mu_);
            dex_perf_fn_ = dex_perf_fn;
        }

        // DexRoutes — /dex + /fragments/dex/overview (DEX reliability read model
        // over the crash-observation projection). Read-only; NO mock data — real
        // aggregations or a "no data" placeholder. Gates on GuaranteedState:Read.
        dex_routes_ = std::make_unique<DexRoutes>();
        dex_routes_->register_routes(
            *web_server_, auth_fn, perm_fn, guaranteed_state_store_.get(),
            // Cross-store fleet denominator for the DEX rates: count online agents,
            // and of those the Windows ones (the only OS with a crash collector
            // today — the coverage-honest crash-free denominator). Real data; an
            // empty fleet degrades the rates to the "no data" tile, never a fake number.
            //
            // SCOPING NOTE (PR #1522 re-review): this provider is intentionally
            // fleet-wide and is NOT an enumeration vector — it renders NO agent_ids.
            // It feeds only fleet AGGREGATES (the crash-free rate denominator + the
            // score-distribution histogram). The device-id LISTS the re-review flagged
            // get their ids from the per-OBSERVATION store queries (dex_top_devices /
            // dex_signal_devices / dex_app_devices / dex_perf_devices), which ARE
            // scoped to the caller's management groups (VisibleSetFn). So the
            // enumeration is closed independent of this provider. True per-TENANT
            // aggregate RATES would also need the store-side crash/signal NUMERATORS
            // (dex_crash_summary / dex_signal_summary) scoped — a tracked follow-up;
            // scoping the denominator here without them would ship a misleading rate.
            [this]() -> DexFleet {
                DexFleet f;
                const auto ids = registry_.all_ids();
                f.total_online = static_cast<int64_t>(ids.size());
                for (const auto& id : ids) {
                    if (auto s = registry_.get_session(id)) {
                        std::string os = s->os;
                        for (auto& c : os)
                            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                        // starts_with, NOT find — "darwin" contains "win"
                        // (G4 UP-1; pre-existing here, fixed with the sibling).
                        if (os.starts_with("win"))
                            ++f.windows_online;
                        // Distinct connected OS tokens → the Catalogue's "All
                        // connected" coverage scope (render normalises darwin→macos).
                        if (!os.empty() && std::find(f.connected_os.begin(),
                                                     f.connected_os.end(), os) ==
                                               f.connected_os.end())
                            f.connected_os.push_back(os);
                        // Normalized (id, os) for the Overview score distribution +
                        // the segment breakdown.
                        const std::string nos = os.starts_with("win")            ? "windows"
                                                : os.starts_with("lin")          ? "linux"
                                                : (os == "darwin" || os == "macos") ? "macos"
                                                                                    : os;
                        f.connected_agents.emplace_back(id, nos);
                    }
                }
                return f;
            },
            audit_fn,
            // A4 device perf panel: canned tar.sql dispatch through the shared
            // chokepoint (untracked path — empty execution_id, same posture as
            // the dashboard TAR SQL surface).
            [command_dispatch_fn](const std::string& plugin, const std::string& action,
                                  const std::vector<std::string>& agent_ids,
                                  const std::string& scope_expr,
                                  const std::unordered_map<std::string, std::string>& parameters)
                -> std::pair<std::string, int> {
                return command_dispatch_fn(plugin, action, agent_ids, scope_expr, parameters,
                                           /*execution_id=*/"");
            },
            // Narrow ResponseStore seam for the result poll.
            [this](const std::string& command_id) -> std::vector<DexAgentResponse> {
                std::vector<DexAgentResponse> out;
                if (!response_store_)
                    return out;
                for (const auto& r : response_store_->query(command_id))
                    out.push_back({r.agent_id, r.status, r.output, r.error_detail});
                return out;
            },
            // F2a: the shared fleet perf snapshot provider (defined above).
            dex_perf_fn,
            // Per-device scope gate (same require_scoped_permission the /device routes
            // use) + the visible-agent set resolver — so the per-device DEX drills are
            // scoped and the device-id lists never enumerate out-of-scope agents.
            scoped_perm_fn, visible_set_fn);

        // NetworkRoutes — /network (page shell) + /fragments/network/* (the
        // network-quality lens + net/device/app co-occurrence evidence).
        //
        // Provider: assemble a NetPerfSnapshot from the health store's network
        // facts (net_snapshot — SAME 90s staleness as recompute_metrics, so the
        // page and the yuzu_fleet_net_* gauges see the same population) joined
        // with session OS + cohort tags. Mirrors dex_perf_uncached. app_unstable
        // is wired with the per-connection collector slice (the co-occurrence
        // "also app" band stays empty until net_degraded facts exist).
        auto net_perf_uncached = [this](const std::string& cohort_key) -> NetPerfSnapshot {
            NetPerfSnapshot snap;
            snap.cohort_key = cohort_key;
            std::unordered_map<std::string, std::string> cohort_values;
            if (tag_store_ && !cohort_key.empty()) {
                snap.available_keys = tag_store_->get_distinct_keys();
                cohort_values = tag_store_->get_values_for_key(cohort_key);
            }
            const auto health = health_store_.net_snapshot(std::chrono::seconds{90});
            std::unordered_map<std::string, const detail::AgentHealthSnapshot*> by_id;
            by_id.reserve(health.size());
            for (const auto& h : health)
                by_id[h.agent_id] = &h;

            auto fill_facts = [](NetPerfDevice& d,
                                 const std::unordered_map<std::string, std::string>& tags) {
                auto get = [&](const char* k) -> std::string {
                    auto t = tags.find(k);
                    return t != tags.end() ? t->second : std::string{};
                };
                d.rtt_ms = detail::parse_net_rtt_ms(get(detail::kNetTagRttP50Ms));
                d.retrans_pct = detail::parse_net_retrans_pct(get(detail::kNetTagRetransPct));
                d.throughput_bps =
                    detail::parse_net_throughput_bps(get(detail::kNetTagThroughputBps));
                if (auto deg = detail::parse_net_degraded(get(detail::kNetTagDegraded)))
                    d.net_degraded = *deg;
                d.cpu_pct = detail::parse_perf_cpu_pct(get(detail::kPerfTagCpuPct));
                d.commit_pct = detail::parse_perf_commit_pct(get(detail::kPerfTagCommitPct));
                d.disk_lat_ms = detail::parse_perf_disk_lat_ms(get(detail::kPerfTagDiskLatMs));
                d.app_unstable = false; // wired with the per-connection collector slice
            };

            std::unordered_set<std::string> seen;
            for (const auto& id : registry_.all_ids()) {
                auto s = registry_.get_session(id);
                if (!s)
                    continue;
                NetPerfDevice d;
                d.agent_id = id;
                std::string os = s->os;
                for (auto& c : os)
                    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                d.platform = os; // "windows" / "linux" / "darwin"
                if (auto it = by_id.find(id); it != by_id.end())
                    fill_facts(d, it->second->status_tags);
                if (!cohort_key.empty()) {
                    // STORE-FIRST precedence (operator-declared cohort wins over
                    // a self-reported tag) — same posture as dex_perf_uncached.
                    if (auto cv = cohort_values.find(id); cv != cohort_values.end())
                        d.cohort = cv->second;
                    else if (auto it = s->scopable_tags.find(cohort_key);
                             it != s->scopable_tags.end() &&
                             TagStore::validate_value(it->second))
                        d.cohort = it->second;
                }
                snap.devices.push_back(std::move(d));
                seen.insert(id);
            }
            // C-S1: health-only devices (session reaped, heartbeat still fresh)
            // must also appear so the page and the gauges agree.
            for (const auto& h : health) {
                if (seen.contains(h.agent_id))
                    continue;
                NetPerfDevice d;
                d.agent_id = h.agent_id;
                fill_facts(d, h.status_tags);
                if (!cohort_key.empty())
                    if (auto cv = cohort_values.find(h.agent_id); cv != cohort_values.end())
                        d.cohort = cv->second;
                snap.devices.push_back(std::move(d));
            }
            return snap;
        };
        // 5s TTL memo keyed by cohort key (mirrors the dex_perf_fn memo) —
        // heartbeat data changes on a ~30s cadence, so this bounds the per-request
        // fleet walk (all_ids + per-id get_session + net_snapshot copy-under-mutex)
        // under hard operator polling and the future REST surface.
        struct NetPerfMemo {
            std::mutex mu;
            struct Entry {
                std::chrono::steady_clock::time_point at;
                NetPerfSnapshot snap;
            };
            std::unordered_map<std::string, Entry> by_key;
        };
        auto net_memo = std::make_shared<NetPerfMemo>();
        auto net_perf_fn = [memo = net_memo,
                            net_perf_uncached](const std::string& cohort_key) -> NetPerfSnapshot {
            constexpr auto kTtl = std::chrono::seconds{5};
            constexpr std::size_t kMaxMemoEntries = 8;
            const auto now = std::chrono::steady_clock::now();
            {
                std::lock_guard lk(memo->mu);
                if (auto it = memo->by_key.find(cohort_key);
                    it != memo->by_key.end() && now - it->second.at < kTtl)
                    return it->second.snap;
            }
            auto snap = net_perf_uncached(cohort_key);
            {
                std::lock_guard lk(memo->mu);
                if (memo->by_key.size() >= kMaxMemoEntries && !memo->by_key.contains(cohort_key)) {
                    auto oldest = memo->by_key.begin();
                    for (auto it = memo->by_key.begin(); it != memo->by_key.end(); ++it)
                        if (it->second.at < oldest->second.at)
                            oldest = it;
                    memo->by_key.erase(oldest);
                }
                memo->by_key[cohort_key] = {now, snap};
            }
            return snap;
        };

        network_routes_ = std::make_unique<NetworkRoutes>();
        network_routes_->register_routes(*web_server_, auth_fn, perm_fn, net_perf_fn);

        // DeviceRoutes — /devices (fleet list) + /device?id= (the shared device
        // page; Device-info lens). Sourced from the live registry (the CONNECTED
        // agents) → identity + tags, online=true. The DEX/Guardian lenses + the
        // live pull are gated per-device by scoped_perm_fn (management-group scope).
        // Provider is PER-OPERATOR SCOPED via get_visible_agents_json — the SAME
        // path /api/agents uses, so a scope-limited operator never enumerates the
        // whole fleet. Identity-only — deliberately does NOT score (dex_score stays
        // -1); scoring is per-device in DeviceRoutes at the render sites (the single
        // device on a page open; only the filtered rows on the list), so opening one
        // device's page never pays an N-device GROUP-BY cost. (Governance Gate-3
        // architect finding; 400k-scale + NFR.)
        // Shared json-agent → DeviceRow identity mapping (used by both the scoped
        // list provider and the unscoped single-device lookup).
        auto make_device_row = [this](const nlohmann::json& a) -> DeviceRow {
            DeviceRow d;
            d.agent_id = a.value("agent_id", "");
            d.hostname = a.value("hostname", "");
            d.os = a.value("os", "");
            d.arch = a.value("arch", "");
            d.agent_version = a.value("agent_version", "");
            d.online = true; // the registry holds connected sessions
            d.last_seen = "now";
            if (auto s = registry_.get_session(d.agent_id)) {
                for (const auto& [k, v] : s->scopable_tags)
                    d.tags.push_back(v.empty() ? k : (k + "=" + v));
            }
            return d;
        };
        auto devices_fn =
            [this, make_device_row](const std::string& username) -> std::vector<DeviceRow> {
            std::vector<DeviceRow> out;
            auto arr = get_visible_agents_json(username);
            out.reserve(arr.size());
            for (const auto& a : arr)
                out.push_back(make_device_row(a));
            return out;
        };
        // UNSCOPED single-device resolver (the `get_one(id)` the list scan was meant
        // to become). Authz is the scoped_perm_fn gate the per-device routes run
        // FIRST; this only fetches the identity row. It must NOT re-scope: the list
        // filter (get_visible_agents) is a flat group-member JOIN with no ancestor
        // walk, while require_scoped_permission IS ancestor-aware — re-scoping here
        // would 404 a device a parent-group role legitimately authorizes.
        auto lookup_fn =
            [this, make_device_row](const std::string& agent_id) -> std::optional<DeviceRow> {
            if (agent_id.empty())
                return std::nullopt;
            for (const auto& a : registry_.to_json_obj())
                if (a.value("agent_id", "") == agent_id)
                    return make_device_row(a);
            return std::nullopt;
        };
        device_routes_ = std::make_unique<DeviceRoutes>();
        device_routes_->register_routes(
            *web_server_, auth_fn, perm_fn, scoped_perm_fn, devices_fn, lookup_fn,
            guaranteed_state_store_.get(),
            // "Get live info" dispatches real plugin instructions (os_info/uptime,
            // processes/list_hashed) through the shared chokepoint. DELIBERATELY an
            // UNTRACKED dispatch (empty execution_id → no ExecutionTracker row, not in
            // the executions drawer): the live shell auto-fires one panel per kind on
            // every device-page open, so tracking would flood the drawer with two
            // executions per view. This matches the already-shipped DEX device-perf
            // panel (also execution_id="") and the compliance polchk- skip — the same
            // high-frequency-read rationale. Agentic-first parity (a machine-readable
            // MCP/REST equivalent + discovery) for live-info AND the DEX-perf sibling
            // is a tracked cross-cutting follow-up, not this PR (PR #1522 review #3).
            [command_dispatch_fn](const std::string& plugin, const std::string& action,
                                  const std::vector<std::string>& agent_ids,
                                  const std::string& scope_expr,
                                  const std::unordered_map<std::string, std::string>& parameters)
                -> std::pair<std::string, int> {
                return command_dispatch_fn(plugin, action, agent_ids, scope_expr, parameters,
                                           /*execution_id=*/"");
            },
            // Narrow ResponseStore seam for the result poll.
            [this](const std::string& command_id) -> std::vector<DexAgentResponse> {
                std::vector<DexAgentResponse> out;
                if (!response_store_)
                    return out;
                for (const auto& r : response_store_->query(command_id))
                    out.push_back({r.agent_id, r.status, r.output, r.error_detail});
                return out;
            },
            audit_fn);

        // TarTreeRoutes — /tar Frame 3 process tree viewer. Reuses DeviceRoutes'
        // scoped device picker (devices_fn) + identity lookup (lookup_fn) + the SAME
        // untracked dispatch (execution_id="" → not in the executions drawer, like the
        // device live-info + DEX-perf reads) and the narrow ResponseStore seam. It
        // dispatches two canned read-only tar.sql ($Process_Live + $TCP_Live) to ONE
        // host and reconstructs the tree server-side (recursive CTEs are blocked on the
        // agent). Per-host only; data from the agent's local tar.db only.
        tar_tree_routes_ = std::make_unique<TarTreeRoutes>();
        tar_tree_routes_->register_routes(
            *web_server_, auth_fn, perm_fn, scoped_perm_fn, devices_fn, lookup_fn,
            [command_dispatch_fn](const std::string& plugin, const std::string& action,
                                  const std::vector<std::string>& agent_ids,
                                  const std::string& scope_expr,
                                  const std::unordered_map<std::string, std::string>& parameters)
                -> std::pair<std::string, int> {
                return command_dispatch_fn(plugin, action, agent_ids, scope_expr, parameters,
                                           /*execution_id=*/"");
            },
            [this](const std::string& command_id) -> std::vector<DexAgentResponse> {
                std::vector<DexAgentResponse> out;
                if (!response_store_)
                    return out;
                for (const auto& r : response_store_->query(command_id))
                    out.push_back({r.agent_id, r.status, r.output, r.error_detail});
                return out;
            },
            audit_fn);

        // VizRoutes — /api/v1/viz/fleet/topology + /fragments/viz/fleet/topology
        // (PR 3 of feat/viz-engine ladder)
        viz_routes_ = std::make_unique<VizRoutes>();
        viz_routes_->register_routes(*web_server_, auth_fn, perm_fn, audit_fn,
                                     fleet_topology_store_.get(), &metrics_, &viz_disabled_,
                                     offline_endpoint_store_.get());

        // DashboardRoutes — /fragments/results, /fragments/results/filter-bar,
        //                   /fragments/create-group-form, /api/dashboard/group-from-results
        dashboard_routes_ = std::make_unique<DashboardRoutes>();
        dashboard_routes_->register_routes(
            *web_server_, auth_fn, perm_fn, audit_fn, response_store_.get(),
            mgmt_group_store_.get(), &registry_, tag_store_.get(), &event_bus_,
            [this]() -> std::string { return registry_.to_json(); },
            // DispatchFn — reuses /api/command dispatch logic
            //
            // Fed into DashboardRoutes (legacy /api/command UI surface);
            // signature MUST stay at 5 parameters. The MCP and REST
            // execute-instruction surfaces have their own 6-parameter
            // dispatch closures (see server.cpp ~5812 for WorkflowRoutes
            // and ~6032 for McpServer) with `execution_id` threaded
            // through for the ExecutionTracker mapping (PR 2 UP2-4
            // race close + #1088 agentic-first bridging).
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
                                                                custom_properties_store_.get(),
                                                                result_set_store_.get());
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
            [this](const std::string& expression,
                   const std::string& principal) -> std::pair<std::size_t, std::size_t> {
            // Resolve from_result_set: aliases for the estimate too (PR-E).
            auto resolved = resolve_scope_aliases(expression, principal, result_set_store_.get());
            auto parsed = yuzu::scope::parse(resolved);
            if (!parsed)
                return {0, registry_.agent_count()};
            auto matched =
                registry_.evaluate_scope(*parsed, tag_store_.get(), custom_properties_store_.get(),
                                         result_set_store_.get(), principal);
            return {matched.size(), registry_.agent_count()};
        };
        wf_deps.workflow_engine = workflow_engine_.get();
        wf_deps.execution_tracker = execution_tracker_.get();
        wf_deps.schedule_engine = schedule_engine_.get();
        wf_deps.product_pack_store = product_pack_store_.get();
        wf_deps.instruction_store = instruction_store_.get();
        wf_deps.policy_store = policy_store_.get();
        wf_deps.command_dispatch_fn = command_dispatch_fn;
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

        // -- PKI PR4: internal-CA REST surface (/api/v1/ca/*) ---------------------
        // The publish-CRL callback captures `this`; like the agent-cert signer it
        // relies on the gRPC/web drain in stop() running before members destruct.
        ca_routes_ = std::make_unique<CaRoutes>();
        ca_routes_->register_routes(
            *web_server_, auth_fn, perm_fn, audit_fn, ca_store_.get(),
            [this]() -> std::optional<std::vector<std::uint8_t>> { return publish_crl(); },
            // PR6 subordinate-CA: export our CA CSR / import an enterprise-signed
            // intermediate. Both need the CA key + dir, so they live in ServerImpl.
            [this]() -> std::optional<std::string> { return export_ca_csr(); },
            [this](const std::string& intermediate_pem,
                   const std::string& parent_chain_pem) -> CaRoutes::ImportOutcome {
                return import_subordinate_chain(intermediate_pem, parent_chain_pem);
            });

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
                   const std::string& target_id, const std::string& detail) -> bool {
                return audit_log(req, action, result, target_type, target_id, detail);
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
            /*license_store=*/nullptr, guaranteed_state_store_.get(),
            /*metrics_registry=*/&metrics_,
            // session_revoke_fn — composes the cookie-session wipe
            // (AuthManager dual-write) with optional API-token revocation
            // when called from /me's "Sign out everywhere" flow. Exposes
            // the dual-write outcome (db_persisted) so the REST handler
            // can audit a partial failure honestly (CC6.6 evidence).
            [this](const std::string& username,
                   bool revoke_api_tokens) -> RestApiV1::SessionRevokeResult {
                const auto revoke = auth_mgr_.invalidate_user_sessions(username);
                std::size_t tokens = 0;
                if (revoke_api_tokens && api_token_store_ && api_token_store_->is_open()) {
                    tokens = api_token_store_->revoke_for_principal(username);
                }
                // CC7.2 anomaly-detection signal: a spike in this counter
                // is the operator's automated alert for compromised-account
                // response or rogue automation calling /me in a loop.
                // Caller dimension is inferred from the api-tokens flag:
                // /me passes true (self full-credential revoke), admin
                // path passes false (cookies only, automation tokens
                // intact). Result dimension carries db_persisted so SOC 2
                // partial-failure rows are filterable.
                metrics_
                    .counter("yuzu_auth_sessions_revoked_total",
                             {{"caller", revoke_api_tokens ? "self" : "admin"},
                              {"result", revoke.db_persisted ? "success" : "partial"},
                              {"scope", revoke_api_tokens ? "all" : "cookies"}})
                    .increment();
                return RestApiV1::SessionRevokeResult{
                    revoke.count,
                    tokens,
                    revoke.db_persisted,
                };
            },
            // W5.1 — pass the per-execution event bus into the REST
            // layer so `GET /api/v1/events` can subscribe agentic
            // workers to live execution transitions. Same bus the
            // dashboard SSE handler uses; nullptr leaves the new
            // route registered but returning 503.
            execution_event_bus_.get(),
            // Scope-walking result-set store (capability §30). nullptr leaves
            // the /api/v1/result-sets routes unregistered.
            result_set_store_.get(),
            // Same hoisted dispatch closure the workflow + policy engines use,
            // so the async result-set producers (from-tar-query /
            // from-instruction-result / re-eval) drive the exact dispatch path
            // (PR-D). Empty closure would 503 those routes.
            command_dispatch_fn,
            // PR2 MFA step-up gate for the high-risk REST handlers; empty
            // closure disables the gate (preserves pre-PR2 behaviour).
            step_up_fn,
            // Step 3 — Guardian push fan-out. Resolve scope → in-scope agents, build the
            // GuaranteedStatePush from the store's enabled rules (typed
            // spark/assertion/remediation from spec_json) and deliver as a
            // `__guard__`/push_rules CommandRequest via the agent dispatch path (reuses
            // the instruction-dispatch scope→send_to idiom). Returns the agent count, or
            // -1 on an unparseable scope. See docs/guardian-mvp-contract.md (step 3/G12).
            // Also stored into guardian_push_fn_ (member) so the dashboard enforcement
            // toggle deploys via this exact fan-out. The parenthesised assignment yields
            // the assigned std::function, which is what gets passed here by value.
            (guardian_push_fn_ = [this](const std::string& scope, bool full_sync) -> int {
                if (!guaranteed_state_store_)
                    return 0;
                const auto now_s = std::chrono::duration_cast<std::chrono::seconds>(
                                       std::chrono::system_clock::now().time_since_epoch())
                                       .count();
                // Read (never bump) the monotonic generation: a reconcile re-push
                // (M5) must carry the SAME generation as the policy-change push that
                // minted it, otherwise catching one lagging agent up would make the
                // rest of the fleet look stale and trigger a reconcile storm. The
                // store bumps the counter on rule mutations; we only read it here.
                // Replaces wall-clock seconds, which could repeat or step backwards
                // and wedge the heartbeat reconcile. (M6 / #1209.)
                const std::uint64_t generation =
                    guaranteed_state_store_->current_policy_generation();
                // Baseline gate: push only Guards that are members of a *deployed*
                // Baseline (docs/guardian-baseline-model.md). With nothing deployed
                // the set is empty and a full_sync converges agents to zero guards.
                const auto rules = guardian::filter_deployed_members(
                    guaranteed_state_store_->list_rules(), deployed_member_rule_ids());

                // Resolve the agent set this push is ADDRESSED to. H1 scopes a single
                // toggle to the affected rule's scope_expr (was the whole fleet); an
                // empty scope still means fleet-wide.
                std::vector<std::string> targets;
                if (scope.empty()) {
                    targets = registry_.all_ids();
                } else if (scope.starts_with("group:") && mgmt_group_store_) {
                    for (const auto& m : mgmt_group_store_->get_members(scope.substr(6)))
                        targets.push_back(m.agent_id);
                } else {
                    auto parsed = yuzu::scope::parse(scope);
                    if (!parsed)
                        return -1;
                    targets = registry_.evaluate_scope(*parsed, tag_store_.get(),
                                                       custom_properties_store_.get());
                }

                // Per-rule scope membership, evaluated once per distinct scope_expr
                // and cached, so the fan-out is O(agents + distinct_scopes) rather
                // than O(agents × rules).
                std::unordered_map<std::string, std::unordered_set<std::string>> scope_cache;
                auto agent_in_scope = [&](const std::string& aid,
                                          const std::string& expr) -> bool {
                    auto it = scope_cache.find(expr);
                    if (it == scope_cache.end()) {
                        std::unordered_set<std::string> ids;
                        if (auto parsed = yuzu::scope::parse(expr)) {
                            auto v = registry_.evaluate_scope(*parsed, tag_store_.get(),
                                                              custom_properties_store_.get());
                            ids.insert(v.begin(), v.end());
                        }
                        it = scope_cache.emplace(expr, std::move(ids)).first;
                    }
                    return it->second.contains(aid);
                };

                // Build and send a per-agent FILTERED push (M4 / #1209): each agent
                // receives only the enabled rules that target its OS and name it in
                // scope, so a Linux box is no longer handed Windows registry guards.
                int sent = 0;
                for (const auto& aid : targets) {
                    auto sess = registry_.get_session(aid);
                    const std::string agent_os = sess ? sess->os : std::string{};
                    auto push = guardian::build_agent_push(
                        rules, agent_os,
                        [&](const std::string& expr) { return agent_in_scope(aid, expr); },
                        full_sync, generation);

                    ::yuzu::agent::v1::CommandRequest cmd;
                    // Unique per push (random suffix) so two pushes in the same second
                    // can't collide on the agent's replay-dedup set (hp-F2/cons-S1).
                    cmd.set_command_id(
                        "__guard__-push-" + std::to_string(now_s) + "-" +
                        auth::AuthManager::bytes_to_hex(auth::AuthManager::random_bytes(8)));
                    cmd.set_plugin("__guard__");
                    cmd.set_action("push_rules");
                    // Binary serialized proto rides in the `payload` bytes field, not the
                    // `parameters` string map: proto3 string values must be valid UTF-8, and
                    // raw GuaranteedStatePush bytes are not. See agent.proto CommandRequest.payload.
                    cmd.set_payload(push.SerializeAsString());
                    if (registry_.send_to(aid, cmd)) {
                        ++sent;
                        metrics_
                            .counter("yuzu_server_guardian_pushes_dispatched_total",
                                     {{"reason", "policy_change"}})
                            .increment();
                    }
                }
                metrics_.gauge("yuzu_server_guardian_policy_generation")
                    .set(static_cast<double>(generation));
                // Drain gw_pending_ so the push reaches gateway-connected agents.
                // send_to only QUEUES for a gateway agent (it has no local Subscribe
                // stream — the gateway holds it); direct agents already got the inline
                // write. Every other dispatch site drains here; the Guardian push
                // omitted it, so over a gateway the push silently never arrived and no
                // guard armed (works in direct mode, breaks via gateway). See
                // forward_gateway_pending() and docs/guardian-mvp-contract.md G12.
                forward_gateway_pending();
                return sent;
            }),
            // F2a: the shared fleet perf snapshot provider — the same closure
            // the /dex Performance fragments and the MCP perf tools use, so
            // REST, dashboard and MCP can never disagree.
            dex_perf_fn,
            // N1: the shared network-quality snapshot provider — the same closure
            // the /network fragments use, so the /api/v1/network/* siblings and
            // MCP tools can never disagree with the dashboard.
            net_perf_fn,
            // Baseline-anchored per-device Guardian status route (trailing optional deps).
            baseline_store_.get(),
            // Per-device-scoped permission (management-group aware) for that route —
            // the SAME named closure DeviceRoutes already uses for the dashboard
            // Guardian device lens (defined once above), not a re-inlined duplicate
            // that two copies would have to keep in sync.
            scoped_perm_fn);

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
                       const std::string& target_id, const std::string& detail) -> bool {
                    return audit_log(req, action, result, target_type, target_id, detail);
                },
                [this]() { return registry_.to_json_obj(); }, rbac_store_.get(),
                instruction_store_.get(), execution_tracker_.get(), response_store_.get(),
                audit_store_.get(), tag_store_.get(), inventory_store_.get(), policy_store_.get(),
                mgmt_group_store_.get(), approval_manager_.get(), schedule_engine_.get(),
                cfg_.mcp_read_only, cfg_.mcp_disable,
                // DispatchFn — reuses /api/command dispatch logic for MCP execute_instruction.
                // #1088 — execution_id parameter added so the MCP tool's
                // pre-created execution row is bridged into
                // AgentServiceImpl's cmd_execution_ids_ map BEFORE any
                // RPC fires (UP2-4 race close from PR 2). Empty
                // execution_id is the legacy untracked path.
                [this](const std::string& plugin, const std::string& action,
                       const std::vector<std::string>& agent_ids, const std::string& scope_expr,
                       const std::unordered_map<std::string, std::string>& parameters,
                       const std::string& execution_id) -> std::pair<std::string, int> {
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
                    if (!execution_id.empty()) {
                        agent_service_.record_execution_id(command_id, execution_id);
                    }

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
                        // Owner-scoped from_result_set: recover the principal
                        // from the MCP-created execution row (review B1).
                        std::string principal;
                        if (scope_expr.find("from_result_set:") != std::string::npos &&
                            !execution_id.empty() && execution_tracker_) {
                            if (auto ex = execution_tracker_->get_execution(execution_id))
                                principal = ex->dispatched_by;
                        }
                        // Resolve from_result_set: aliases at the dispatch layer (PR-E).
                        auto resolved_scope = resolve_scope_aliases(scope_expr, principal,
                                                                    result_set_store_.get());
                        // Role unavailable on the MCP path (principal recovered
                        // from the MCP-created execution row); principal + command
                        // id identify the actor for the forensic chain.
                        for (const auto& ref : scope_refs_failing_owner_check(
                                 resolved_scope, principal, result_set_store_.get()))
                            audit_scope_resolution_failed(principal, /*role=*/"", command_id, ref);
                        auto parsed = yuzu::scope::parse(resolved_scope);
                        if (parsed) {
                            for (const auto& aid : registry_.evaluate_scope(
                                     *parsed, tag_store_.get(), custom_properties_store_.get(),
                                     result_set_store_.get(), principal))
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
                },
                // PR4 B-2: CA inventory + revoke MCP tools (parity with /api/v1/ca/*).
                ca_store_.get(), [this]() { return publish_crl(); },
                // ar-S1: DEX read tools (parity with /api/v1/dex/*).
                guaranteed_state_store_.get(),
                // F2a: the shared fleet perf snapshot provider (one closure,
                // three surfaces — fragments, REST, MCP).
                dex_perf_fn,
                // N1: the shared network-quality provider (fragments + REST + MCP).
                net_perf_fn,
                // ADR-0011: metrics sink for the MCP-surface bundle orchestrator
                // (yuzu_bundle_*{surface="mcp"}). REST passes its own registry.
                &metrics_);
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

    // Scope-walking dispatch helpers (resolve_scope_aliases /
    // scope_refs_failing_owner_check) live in scope_yaml.{hpp,cpp} as free
    // functions in yuzu::server, so the dispatch call sites below bind to them
    // unqualified and they are unit-testable.

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
    /// Shared Postgres connection pool — the server storage substrate (ADR-0006/
    /// 0007). Constructed in the ctor BEFORE any Postgres-backed store (fail
    /// closed if the DSN is empty or unreachable), reset in stop() AFTER the
    /// gRPC drain so no handler thread still holds a lease. DECLARED right after
    /// metrics_ on purpose: its observer hooks capture &metrics_, so the pool
    /// must destruct before metrics_ (reverse-declaration order) — and before it,
    /// every Postgres-backed store (declared later) releases its PgPool& and
    /// every ingest thread (agent_service_, declared later) has already stopped.
    std::unique_ptr<pg::PgPool> pg_pool_;
    detail::EventBus event_bus_;
    detail::AgentRegistry registry_;
    /// D3 fleet-incident detector — fed by the shared Guardian ingest (both the
    /// direct Subscribe path via agent_service_ and the gateway path via
    /// gateway_service_). Its on_incident sink fans out to notification +
    /// webhook + offload. Plain member (no heap): in-memory derived state only.
    /// DECLARED BEFORE its borrowers (agent_service_ / gateway_service_ /
    /// agent_server_) so it destructs AFTER them — the detector must outlive any
    /// ingest thread that holds its raw pointer (gov cpp-safety/architect). stop()
    /// also nulls the borrowed pointers after the gRPC drain, belt-and-braces.
    BlastRadiusDetector blast_radius_detector_;
    DexAlertRouter dex_alert_router_;
    /// F2a PR3: cohort metrics export — written by apply_dex_alert_config
    /// (boot + settings POST) and start_web_server (the provider closure),
    /// read by the reaper-thread gauge sweep. One mutex guards both.
    std::mutex dex_cohort_export_mu_;
    std::string dex_cohort_export_key_;
    DexPerfFn dex_perf_fn_;
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
    /// Born-on-Postgres last-known endpoint store (#1320 PR 3). Borrows pg_pool_
    /// (declared earlier, destructs later) and is borrowed by the heartbeat
    /// ingest path; declared here among the stores so it destructs AFTER the
    /// ingest services + BEFORE the pool.
    std::unique_ptr<OfflineEndpointStore> offline_endpoint_store_;
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
    // ORDER IS LOAD-BEARING (#1453): rbac_store_ MUST be declared before
    // mgmt_group_store_. The latter holds a `this`-capturing RBAC-enabled probe
    // (set_rbac_enabled_probe) that reads rbac_store_; members destruct in
    // reverse declaration order, so mgmt_group_store_ (and its probe) are torn
    // down BEFORE rbac_store_, ensuring the probe can never read a freed store
    // during shutdown. Do not reorder these two.
    std::unique_ptr<RbacStore> rbac_store_;
    std::unique_ptr<ManagementGroupStore> mgmt_group_store_;
    std::unique_ptr<ApiTokenStore> api_token_store_;
    std::unique_ptr<QuarantineStore> quarantine_store_;
    std::unique_ptr<ResultSetStore> result_set_store_;
    std::unique_ptr<PolicyStore> policy_store_;
    std::unique_ptr<PolicyEvaluator> policy_evaluator_;
    std::unique_ptr<GuaranteedStateStore> guaranteed_state_store_;
    std::unique_ptr<BaselineStore> baseline_store_;
    std::unique_ptr<CaStore> ca_store_;
    DefaultCertSet default_cert_set_;
    bool default_certs_failed_{false};
    // PR4: backoff for the reaper's CRL freshness re-publish — on a persistent
    // publish failure (e.g. unreadable CA key) skip retries until this point so
    // the ~15s reaper doesn't spam logs/metrics. steady_clock (NTP-jump-safe,
    // gov L5). ACCESSED ONLY by the single reaper thread (health_recompute_thread_)
    // — not atomic by design; do NOT read/write it from another thread without
    // converting to std::atomic first (gov L1).
    std::chrono::steady_clock::time_point crl_freshness_retry_after_{};
    // atomic so a future background-thread read can never be UB; today it is
    // written/read only on the main thread (ctor → run() → main()), so the
    // default seq_cst on the implicit load/store is free on this cold path
    // (gov fjarvis L2).
    std::atomic<bool> startup_failed_{false}; // run() refused to start — main() exits non-zero
    // PKI PR3: cached issuing-CA cert PEM (for is_yuzu_issued's verify_chain) +
    // per-agent CSR-issuance rate-limit state (sign_agent_csr). Set at wiring time.
    std::string agent_ca_cert_pem_;
    std::mutex csr_issue_mu_;
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> csr_issue_last_;
    // Serialises publish_crl() so next_crl_number()+record_crl() are atomic across
    // concurrent publishers (startup pre-publish vs a revoke, or two revokes) —
    // otherwise both could read the same number and last-writer-wins overwrites,
    // breaking RFC 5280 monotonic crlNumber (gov architect SHOULD).
    std::mutex crl_publish_mu_;
    // Cache of is_yuzu_issued (immutable per cert) — avoids a per-heartbeat
    // verify_chain fleet-wide (gov UP-7). Keyed by full leaf PEM.
    std::mutex yuzu_issued_cache_mu_;
    std::unordered_map<std::string, bool> yuzu_issued_cache_;
    // Cache of the immutable PEM→serial parse for the per-heartbeat revocation
    // gate (is_peer_cert_revoked) — avoids an X509 parse per call fleet-wide. The
    // revocation status itself is deliberately NOT cached (it is mutable). Keyed
    // by full leaf PEM; same crude size bound as yuzu_issued_cache_.
    std::mutex peer_serial_cache_mu_;
    std::unordered_map<std::string, std::string> peer_serial_cache_;
    std::unique_ptr<AuthRoutes> auth_routes_;
    std::unique_ptr<RestApiV1> rest_api_v1_;
    std::unique_ptr<SettingsRoutes> settings_routes_;
    std::unique_ptr<mcp::McpServer> mcp_server_;
    std::unique_ptr<ComplianceRoutes> compliance_routes_;
    std::unique_ptr<GuardianRoutes> guardian_routes_;
    std::unique_ptr<DexRoutes> dex_routes_;
    std::unique_ptr<NetworkRoutes> network_routes_;
    std::unique_ptr<DeviceRoutes> device_routes_;
    std::unique_ptr<TarTreeRoutes> tar_tree_routes_;
    // Guardian push fan-out, shared by the REST /push endpoint and the dashboard
    // enforcement toggle. Assigned during REST wiring (the `(guardian_push_fn_ =
    // ...)` site); GuardianRoutes captures `this` and reads it at toggle-time, by
    // which point it is set.
    std::function<int(const std::string&, bool)> guardian_push_fn_;

    // Guardian heartbeat-reconcile per-agent rate limit (#1209 hardening:
    // sec-MED1 / perf-S1 / perf-S2). Without it, a lagging — or hostile, tight-
    // looping — agent turns EVERY heartbeat into a full reconcile (list_rules +
    // per-rule registry-mutex scope scan), an asymmetric CPU amplifier. We allow
    // at most one reconcile re-push per agent per kGuardianReconcileMinInterval;
    // a genuinely-once-lagging agent still converges on its first heartbeat. Map
    // is agent_id -> last reconcile time, guarded by its own mutex.
    std::mutex guardian_reconcile_mu_;
    std::unordered_map<std::string, std::chrono::steady_clock::time_point>
        guardian_last_reconcile_;

    // The Baseline gate's input: the union of member-Guard rule_ids across all
    // *deployed* Baselines, sourced from each Baseline's deployed_snapshot (what
    // was deployed) — NOT its live member set. A Guard reaches an agent only as a
    // member of a deployed Baseline (docs/guardian-baseline-model.md), so the push
    // fan-out and the heartbeat reconcile filter their rule source through this via
    // guardian::filter_deployed_members. Empty when nothing is deployed — a
    // full_sync push then converges agents to zero guards (correct by model).
    // Delegates to BaselineStore (one shared lock; the store owns the snapshot
    // format) so an edit to a deployed Baseline's members does not change what the
    // fleet enforces until a Push-gated re-deploy rewrites the snapshot.
    std::unordered_set<std::string> deployed_member_rule_ids() const {
        if (!baseline_store_)
            return {};
        return baseline_store_->deployed_member_rule_ids();
    }

    std::unique_ptr<DashboardRoutes> dashboard_routes_;
    std::unique_ptr<WorkflowRoutes> workflow_routes_;
    std::unique_ptr<NotificationRoutes> notification_routes_;
    std::unique_ptr<WebhookRoutes> webhook_routes_;
    std::unique_ptr<OffloadRoutes> offload_routes_;
    std::unique_ptr<DiscoveryRoutes> discovery_routes_;
    std::unique_ptr<CaRoutes> ca_routes_; // PKI PR4: /api/v1/ca/*

    // Fleet visualization (PR 3 of feat/viz-engine ladder)
    std::unique_ptr<FleetTopologyStore> fleet_topology_store_;
    /// #1000 / arch-S2: shared heartbeat-ingestion pipeline. Constructed
    /// after fleet_topology_store_ + health_store_ + metrics are wired;
    /// injected into AgentServiceImpl and GatewayUpstreamServiceImpl so
    /// both ingestion paths funnel through one entry point.
    std::unique_ptr<HeartbeatIngestion> heartbeat_ingestion_;
    std::unique_ptr<VizRoutes> viz_routes_;
    /// Atomic kill-switch consulted by VizRoutes on every request. Defaults
    /// to cfg_.viz_disable; runtime config could expose a flip path later.
    std::atomic<bool> viz_disabled_{false};

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
    std::thread policy_eval_thread_;
    std::thread result_set_maint_thread_;

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
